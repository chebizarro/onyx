import { wrap, type DBSchema, type IDBPDatabase, type IDBPTransaction } from 'idb';
import { assertRecoveryPassphrase, decryptNcryptsec, encryptNcryptsec, parseNcryptsec, RECOVERY_EXPORT_LOGN, RECOVERY_MAX_LOGN } from './recovery';
import type { SecretStore } from '../../platform/types';
import { VaultError } from './errors';
import { PROTOCOL_ID, UINT64_MAX } from './protocol';
import type {
  Address, JournalStage, Persisted, Pubkey, StoredAccount, StoredConflict,
  StoredInvitation, StoredOperation, StoredRecord, StoredVault, VaultId,
  VaultRecoveryPackage, VaultRecoveryPayload,
} from './types';

export const VAULT_DATABASE_NAME = 'onyx-shared-vaults';
/** v2 adds the unencrypted `meta` (cache totals, durable pin rows, committed journal order)
 * and `objectIndex` (size + LRU clock per cached address) stores. */
export const VAULT_DATABASE_VERSION = 2;
export const DEFAULT_CACHE_LIMIT = 512 * 1024 * 1024;
/** Committed publish/materialize journals without delivery or resolution intents kept per vault. */
export const COMMITTED_JOURNALS_KEPT = 8;
export const STORAGE_KEY_PREFIX = 'onyx:vault-store:v1:';
export const ENCRYPTED_STORES = ['accounts', 'vaults', 'invitations', 'records', 'operations', 'conflicts'] as const;
export type EncryptedStore = typeof ENCRYPTED_STORES[number];
export interface StoreValues {
  accounts: StoredAccount;
  vaults: StoredVault;
  invitations: StoredInvitation;
  records: StoredRecord;
  operations: StoredOperation;
  conflicts: StoredConflict;
}
export interface StoreKeys {
  accounts: readonly [];
  vaults: readonly [VaultId];
  invitations: readonly [VaultId, string];
  records: readonly [VaultId, string];
  operations: readonly [VaultId, string];
  conflicts: readonly [VaultId, string];
}
type DatabaseKey = string[];
interface Envelope {
  schemaVersion: 1;
  protocolId: typeof PROTOCOL_ID;
  revision: number;
  keyId: string;
  nonce: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
}
interface Quarantine {
  quarantined: true;
  original: unknown;
}
interface CachedObject {
  bytes: Uint8Array<ArrayBuffer>;
  lastUsed: number;
}
/** Small per-address accounting row; addresses are already plaintext keys of `objects`. */
interface CacheIndexRow { account: string; size: number; lastUsed: number }
interface CacheMeta { totalBytes: number; count: number; clock: number }
interface PinRow { addresses: string[] }
interface CommittedRow { ids: string[] }
type MetaRow = CacheMeta | PinRow | CommittedRow;
type Row = Envelope | Quarantine;
interface VaultDB extends DBSchema {
  accounts: { key: DatabaseKey; value: Row };
  vaults: { key: DatabaseKey; value: Row };
  invitations: { key: DatabaseKey; value: Row };
  records: { key: DatabaseKey; value: Row };
  operations: { key: DatabaseKey; value: Row };
  conflicts: { key: DatabaseKey; value: Row };
  objects: { key: DatabaseKey; value: CachedObject | Quarantine };
  objectIndex: { key: DatabaseKey; value: CacheIndexRow; indexes: { byUse: [string, number] } };
  meta: { key: DatabaseKey; value: MetaRow };
}
const AUXILIARY_STORES = ['objects', 'objectIndex', 'meta'] as const;
type JournalTx = IDBPTransaction<VaultDB, (EncryptedStore | 'meta')[], 'readwrite'>;
type CacheTx = IDBPTransaction<VaultDB, ('objects' | 'objectIndex' | 'meta')[], 'readwrite'>;
const PIN_STORES = ['vaults', 'operations'] as const;
type PinStore = typeof PIN_STORES[number];
/** Durable pins come from pending journals (pinned/pending addresses) and vault rows
 * (reseal progress, local candidate). Committed journals pin nothing. */
function pinsOf(store: PinStore, value: StoreValues[PinStore]): string[] {
  if (store === 'operations') {
    const operation = value as StoredOperation;
    return operation.stage === 'committed' ? [] : [...new Set([...operation.pinnedAddresses, ...(operation.pendingAddress ? [operation.pendingAddress] : [])])].sort();
  }
  const vault = value as StoredVault;
  return [...new Set([...(vault.resealProgress?.pendingAddress ? [vault.resealProgress.pendingAddress] : []), ...(vault.localCandidate?.addresses ?? [])])].sort();
}
/** Journals still consulted after commitment (deliveries, resolution, ledgers) are never compacted. */
function compactable(operation: StoredOperation): boolean {
  const deliveries = operation.candidate.deliveries;
  return (operation.kind === 'publish' || operation.kind === 'materialize') && !(Array.isArray(deliveries) && deliveries.length)
    && !operation.candidate.materialization && !operation.candidate.epochLedger;
}
export interface Versioned<T> { readonly value: T; readonly revision: number }
export interface JournalRevisions { readonly vault: number; readonly operation: number }
export type StoreState =
  | { readonly condition: 'stopped' | 'ready' }
  | { readonly condition: 'needs-key'; readonly reason: 'locked' | 'missing' | 'wrong' | 'unavailable' }
  | { readonly condition: 'paused'; readonly reason: 'quota' | 'corrupt' };
export interface QuarantineNotice {
  readonly store: EncryptedStore | 'objects';
  readonly key: readonly string[];
}
export interface VaultStoreOptions {
  readonly accountPubkey: Pubkey;
  readonly secrets: SecretStore;
  readonly databaseName?: string;
  readonly idbFactory?: IDBFactory;
  readonly cacheLimitBytes?: number;
  readonly requestPersistence?: () => Promise<boolean>;
  readonly onQuarantine?: (notice: QuarantineNotice) => void;
}
interface WriteRow {
  store: EncryptedStore;
  key: readonly string[];
  value: StoreValues[EncryptedStore];
  expected: number;
}
interface SnapshotRow { store: EncryptedStore; key: DatabaseKey; row: Row }
const uint64Fields = new Set([
  'epoch', 'childEpoch', 'chunkKeyId', 'seq', 'grantsRev', 'mtimeNs', 'sizePlain',
  'sizeSealed', 'writtenAt', 'issuedAt', 'lastOwnSeq', 'lastOwnWrittenAt', 'attachedAt', 'since',
]);
const stages: readonly JournalStage[] = [
  'prepared', 'uploading', 'ready-to-publish', 'awaiting-ack', 'committed', 'needs-recovery',
];
const kinds = ['create', 'publish', 'policy', 'revoke', 'reseal', 'materialize'];
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const keyLocks = new Map<string, Promise<unknown>>();

export function uint64FromDecimal(value: string): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || value.length > 20) {
    throw new VaultError('ARG');
  }
  const integer = BigInt(value);
  if (integer > UINT64_MAX) throw new VaultError('ARG');
  return integer;
}
export function uint64ToDecimal(value: bigint): string {
  if (typeof value !== 'bigint' || value < 0n || value > UINT64_MAX) throw new VaultError('ARG');
  return value.toString(10);
}
function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
function unhex(value: string, length?: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(value) || (length !== undefined && value.length !== length * 2)) {
    throw new VaultError('ARG');
  }
  return Uint8Array.from(value.match(/../g)!, part => parseInt(part, 16));
}
/** A later unknown/refusal cannot undo a positive receipt for the exact event. */
export function mergeRelayOutcomes(current: StoredOperation['relayOutcomes'], incoming: StoredOperation['relayOutcomes']): StoredOperation['relayOutcomes'] {
  const map = (value: unknown): value is StoredOperation['relayOutcomes'] => !!value && typeof value === 'object' && !Array.isArray(value);
  const result = { ...current };
  for (const [key, value] of Object.entries(incoming)) {
    const previous = result[key];
    result[key] = previous === 'accepted' || previous === true ? previous
      : map(previous) && map(value) ? mergeRelayOutcomes(previous, value) : value;
  }
  return result;
}

/** Explicit serialization boundary: bigint -> decimal, bytes -> hex, maps -> objects. */
export function toStorage<T>(value: T): Persisted<T> {
  return JSON.parse(storageJson(value)) as Persisted<T>;
}
function storageJson(value: unknown): string {
  function convert(item: unknown, field = ''): unknown {
    if (item === null) return null;
    if (typeof item === 'bigint') return uint64ToDecimal(item);
    if (uint64Fields.has(field)) {
      if (typeof item !== 'string') throw new VaultError('ARG');
      uint64FromDecimal(item);
    }
    if (typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'number' && Number.isSafeInteger(item)) return item;
    if (item instanceof Uint8Array) return hex(item);
    if (Array.isArray(item)) return item.map(part => convert(part));
    if (item instanceof Map) return convert(Object.fromEntries(item));
    if (typeof item === 'object' && item !== null && (Object.getPrototypeOf(item) === Object.prototype || Object.getPrototypeOf(item) === null)) {
      return Object.fromEntries(Object.keys(item).sort().map(key => [key, convert((item as Record<string, unknown>)[key], key)]));
    }
    throw new VaultError('ARG');
  }
  return JSON.stringify(convert(value));
}
function version(value: unknown): asserts value is { schemaVersion: 1; protocolId: typeof PROTOCOL_ID } {
  if (!value || typeof value !== 'object' || !('schemaVersion' in value) || !('protocolId' in value)) throw new VaultError('ARG');
  if (value.schemaVersion !== 1 || value.protocolId !== PROTOCOL_ID) throw new VaultError('VERSION');
}
function checkKey(store: EncryptedStore, key: readonly string[]): void {
  const size = store === 'accounts' ? 0 : store === 'vaults' ? 1 : 2;
  if (key.length !== size || key.some(part => typeof part !== 'string' || !part)) throw new VaultError('ARG');
  if (size && !/^[0-9a-f]{64}$/.test(key[0])) throw new VaultError('ARG');
}
function validateValue(store: EncryptedStore, key: readonly string[], value: StoreValues[EncryptedStore]): void {
  version(value);
  storageJson(value);
  if (store !== 'accounts' && (!('vaultId' in value) || value.vaultId !== key[0])) throw new VaultError('ARG');
  if (store === 'operations') {
    const operation = value as StoredOperation;
    if (operation.operationId !== key[1] || !kinds.includes(operation.kind) || !stages.includes(operation.stage)
      || !Array.isArray(operation.pinnedAddresses) || !operation.candidate) throw new VaultError('ARG');
  }
  if (store === 'vaults') {
    const vault = value as StoredVault;
    uint64FromDecimal(vault.lastOwnSeq);
    uint64FromDecimal(vault.lastOwnWrittenAt);
    if (!vault.nodeRings || !vault.network || !vault.baseline || vault.retainedRoots !== null && !Array.isArray(vault.retainedRoots)) throw new VaultError('ARG');
  }
}
function isQuarantined(row: unknown): row is Quarantine {
  return !!row && typeof row === 'object' && 'quarantined' in row && row.quarantined === true;
}
function accountRange(account: string): IDBKeyRange {
  return IDBKeyRange.bound([account], [account, []]);
}
function revision(row: Row | undefined): number {
  if (!row) return 0;
  if (isQuarantined(row)) throw new VaultError('STORAGE');
  return row.revision;
}
function isQuota(error: unknown): boolean {
  return error instanceof Error && error.name === 'QuotaExceededError';
}
async function keyLock<T>(name: string, action: () => Promise<T>): Promise<T> {
  const previous = keyLocks.get(name) ?? Promise.resolve();
  const result = previous.catch(() => undefined).then(async () => {
    if (typeof navigator !== 'undefined' && navigator.locks) return await navigator.locks.request(name, action);
    return await action();
  });
  keyLocks.set(name, result);
  try { return await result; }
  finally { if (keyLocks.get(name) === result) keyLocks.delete(name); }
}
function samePointers(left: StoredVault, right: StoredVault, includePending: boolean): boolean {
  const fields = ['ownerCheckpointId', 'materializedViewId', 'lastOwnSeq', 'lastOwnWrittenAt', 'baseline'] as const;
  return fields.every(field => storageJson(left[field]) === storageJson(right[field]))
    && (!includePending || left.pendingCandidateId === right.pendingCandidateId);
}

export class VaultStore {
  private db?: IDBPDatabase<VaultDB>;
  private key?: CryptoKey;
  private keyId = '';
  private generation = 0;
  private starting?: Promise<StoreState>;
  private readonly listeners = new Set<(state: StoreState) => void>();
  private readonly pins = new Map<string, ReadonlySet<Address>>();
  private currentState: StoreState = { condition: 'stopped' };
  private readonly cacheLimit: number;
  private recovered: readonly StoredOperation[] = [];
  private persistenceRequested = false;

  constructor(private readonly options: VaultStoreOptions) {
    if (!/^[0-9a-f]{64}$/.test(options.accountPubkey)) throw new VaultError('ARG');
    this.cacheLimit = options.cacheLimitBytes ?? DEFAULT_CACHE_LIMIT;
    if (!Number.isSafeInteger(this.cacheLimit) || this.cacheLimit < 0) throw new VaultError('ARG');
  }
  get state(): StoreState { return this.currentState; }
  /** Pending journals are returned intact; I/O recovery belongs to the engine. */
  get recoveryOperations(): readonly StoredOperation[] { return this.recovered; }
  subscribe(listener: (state: StoreState) => void): () => void {
    this.listeners.add(listener);
    listener(this.state);
    return () => { this.listeners.delete(listener); };
  }
  private setState(state: StoreState): StoreState {
    this.currentState = state;
    for (const listener of this.listeners) listener(state);
    return state;
  }
  async start(): Promise<StoreState> {
    if (this.state.condition === 'ready') return this.state;
    if (this.starting) return this.starting;
    const generation = this.generation;
    const start = this.startSession(generation);
    this.starting = start;
    try { return await start; }
    finally { if (this.starting === start) this.starting = undefined; }
  }
  private async startSession(generation: number): Promise<StoreState> {
    if (!this.db) {
      const db = await new Promise<IDBPDatabase<VaultDB>>((resolve, reject) => {
        let expired = false;
        const fail = (message: string) => {
          expired = true; clearTimeout(timer);
          const error = new VaultError('STORAGE', { operation: 'start' }); error.message = message; reject(error);
        };
        const timer = setTimeout(() => fail('IndexedDB did not open within 5 seconds. Close other Onyx windows and retry.'), 5000);
        let request: IDBOpenDBRequest;
        try { request = (this.options.idbFactory ?? globalThis.indexedDB).open(this.options.databaseName ?? VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION); }
        catch { fail('IndexedDB is unavailable in this webview. Check storage permissions and retry.'); return; }
        request.onupgradeneeded = () => {
          if (expired || generation !== this.generation) { request.transaction?.abort(); return; }
          const names = request.result.objectStoreNames;
          for (const store of [...ENCRYPTED_STORES, 'objects', 'meta'] as const) if (!names.contains(store)) request.result.createObjectStore(store);
          if (!names.contains('objectIndex')) request.result.createObjectStore('objectIndex').createIndex('byUse', ['account', 'lastUsed']);
        };
        request.onblocked = () => fail('IndexedDB upgrade is blocked by another Onyx window. Close it and retry.');
        request.onerror = () => fail(`IndexedDB could not open (${request.error?.name ?? 'storage error'}). Check storage permissions/schema and retry.`);
        request.onsuccess = () => {
          clearTimeout(timer);
          if (expired || generation !== this.generation) { request.result.close(); reject(new VaultError('CANCELLED')); return; }
          if ([...ENCRYPTED_STORES, ...AUXILIARY_STORES].some(store => !request.result.objectStoreNames.contains(store))) {
            request.result.close(); fail('Shared vault IndexedDB schema is incomplete. Restore the local database before retrying.'); return;
          }
          request.result.onversionchange = () => this.stop();
          resolve(wrap(request.result) as IDBPDatabase<VaultDB>);
        };
      });
      if (generation !== this.generation) { db.close(); throw new VaultError('CANCELLED'); }
      this.db = db;
    }
    return keyLock(`${this.options.databaseName ?? VAULT_DATABASE_NAME}:${this.options.accountPubkey}`, async () => {
      this.assertGeneration(generation);
      this.key = undefined;
      this.recovered = [];
      if (this.options.secrets.isLocked?.()) return this.setState({ condition: 'needs-key', reason: 'locked' });
      let storedKey: string | null;
      try { storedKey = await this.options.secrets.get(STORAGE_KEY_PREFIX + this.options.accountPubkey); }
      catch { this.assertGeneration(generation); return this.setState({ condition: 'needs-key', reason: 'unavailable' }); }
      this.assertGeneration(generation);
      const existing = await this.snapshot(ENCRYPTED_STORES);
      this.assertGeneration(generation);
      if (storedKey === null) {
        if (existing.length) return this.setState({ condition: 'needs-key', reason: 'missing' });
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        storedKey = hex(bytes);
        bytes.fill(0);
        try { await this.options.secrets.set(STORAGE_KEY_PREFIX + this.options.accountPubkey, storedKey); }
        catch { this.assertGeneration(generation); return this.setState({ condition: 'needs-key', reason: 'unavailable' }); }
      }
      this.assertGeneration(generation);
      let bytes: Uint8Array<ArrayBuffer>;
      try { bytes = unhex(storedKey, 32); }
      catch { return this.setState({ condition: 'needs-key', reason: 'wrong' }); }
      try {
        const keyId = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
        this.assertGeneration(generation);
        this.keyId = keyId;
        for (const { row } of existing) {
          const original = isQuarantined(row) ? row.original : row;
          if (original && typeof original === 'object' && 'keyId' in original && original.keyId !== this.keyId) {
            return this.setState({ condition: 'needs-key', reason: 'wrong' });
          }
        }
        const key = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
        this.assertGeneration(generation);
        this.key = key;
      } finally { bytes.fill(0); }
      this.assertGeneration(generation);
      this.setState({ condition: 'ready' });
      try {
        if (!await this.read('accounts', [])) {
          await this.commitRows([{
            store: 'accounts', key: [], expected: 0,
            value: { schemaVersion: 1, protocolId: PROTOCOL_ID, deviceId: crypto.randomUUID(), deviceLabel: '', deviceKeyHistory: [], config: {} },
          }]);
        }
        await this.ensureCacheIndex();
        this.recovered = await this.pendingOperations();
      } catch (error) {
        if (this.state.condition === 'ready' && error instanceof VaultError && error.code === 'STORAGE') {
          this.setState({ condition: 'paused', reason: 'corrupt' });
        }
        throw error;
      }
      return this.state;
    });
  }
  /** Use this boundary when unlocking through the vault session; no platform mutation. */
  async unlock(passphrase: string): Promise<StoreState> {
    if (!this.options.secrets.unlock) throw new VaultError('UNSUPPORTED');
    await this.options.secrets.unlock(passphrase);
    return this.start();
  }
  stop(): void {
    this.generation++;
    this.starting = undefined;
    this.key = undefined;
    this.keyId = '';
    this.recovered = [];
    this.pins.clear();
    this.db?.close();
    this.db = undefined;
    this.setState({ condition: 'stopped' });
  }
  private assertGeneration(generation: number): void {
    if (generation !== this.generation) throw new VaultError('CANCELLED');
  }
  private session(write = false): { db: IDBPDatabase<VaultDB>; key: CryptoKey; generation: number } {
    if (!this.db || !this.key || (this.state.condition !== 'ready' && !(this.state.condition === 'paused' && !write))) {
      throw new VaultError('STORAGE');
    }
    return { db: this.db, key: this.key, generation: this.generation };
  }
  private fullKey(key: readonly string[]): DatabaseKey { return [this.options.accountPubkey, ...key]; }
  private aad(store: EncryptedStore, key: readonly string[], envelope: Envelope): Uint8Array<ArrayBuffer> {
    return encoder.encode(JSON.stringify([
      VAULT_DATABASE_NAME, this.options.accountPubkey, store, key,
      envelope.schemaVersion, envelope.protocolId, envelope.revision, envelope.keyId,
    ]));
  }
  private async seal(store: EncryptedStore, key: readonly string[], value: StoreValues[EncryptedStore], nextRevision: number): Promise<Envelope> {
    const session = this.session(true);
    validateValue(store, key, value);
    const envelope: Envelope = {
      schemaVersion: 1, protocolId: PROTOCOL_ID, revision: nextRevision, keyId: this.keyId,
      nonce: crypto.getRandomValues(new Uint8Array(12)), ciphertext: new ArrayBuffer(0),
    };
    const plaintext = encoder.encode(storageJson(value));
    try {
      envelope.ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: envelope.nonce, additionalData: this.aad(store, key, envelope) }, session.key, plaintext);
    } finally { plaintext.fill(0); }
    this.assertGeneration(session.generation);
    return envelope;
  }
  private async open<S extends EncryptedStore>(store: S, key: readonly string[], row: Row): Promise<Versioned<StoreValues[S]>> {
    const session = this.session();
    if (isQuarantined(row)) throw new VaultError('STORAGE');
    try {
      version(row);
      if (row.keyId !== this.keyId || !Number.isSafeInteger(row.revision) || row.revision < 1 || row.nonce?.byteLength !== 12) throw new VaultError('CRYPTO');
      const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: row.nonce, additionalData: this.aad(store, key, row) }, session.key, row.ciphertext));
      try {
        const value = JSON.parse(decoder.decode(plaintext)) as StoreValues[S];
        validateValue(store, key, value);
        this.assertGeneration(session.generation);
        return { value, revision: row.revision };
      } finally { plaintext.fill(0); }
    } catch (error) {
      if (error instanceof VaultError && (error.code === 'VERSION' || error.code === 'CANCELLED')) throw error;
      this.assertGeneration(session.generation);
      await this.quarantine(store, key, row);
      throw new VaultError('STORAGE', { operation: 'store' });
    }
  }
  private async snapshot(stores: readonly EncryptedStore[]): Promise<SnapshotRow[]> {
    if (!this.db) throw new VaultError('STORAGE');
    const tx = this.db.transaction([...stores], 'readonly');
    const result: SnapshotRow[] = [];
    for (const store of stores) {
      const keys = await tx.objectStore(store).getAllKeys(accountRange(this.options.accountPubkey));
      const values = await tx.objectStore(store).getAll(accountRange(this.options.accountPubkey));
      keys.forEach((key, index) => result.push({ store, key, row: values[index] }));
    }
    await tx.done;
    return result;
  }
  async read<S extends EncryptedStore>(store: S, key: StoreKeys[S]): Promise<Versioned<StoreValues[S]> | null> {
    checkKey(store, key);
    const { db } = this.session();
    const row = await db.get(store, this.fullKey(key));
    return row === undefined ? null : this.open(store, key, row);
  }
  async list<S extends EncryptedStore>(store: S): Promise<readonly (Versioned<StoreValues[S]> & { readonly key: StoreKeys[S] })[]> {
    this.session();
    const rows = await this.snapshot([store]);
    return Promise.all(rows.map(async ({ key, row }) => ({
      key: key.slice(1) as unknown as StoreKeys[S], ...await this.open(store, key.slice(1), row),
    })));
  }
  /**
   * Like `list`, but a row that cannot be opened (quarantined, unsupported version,
   * failed validation) is reported in `failed` instead of failing the whole listing,
   * so one bad row can never hide every other vault (SEC-G). The original bytes of a
   * quarantined row stay in place for repair.
   */
  async listTolerant<S extends EncryptedStore>(store: S): Promise<{
    rows: readonly (Versioned<StoreValues[S]> & { readonly key: StoreKeys[S] })[];
    failed: readonly { readonly key: StoreKeys[S]; readonly error: VaultError }[];
  }> {
    this.session();
    const rows: (Versioned<StoreValues[S]> & { readonly key: StoreKeys[S] })[] = [];
    const failed: { key: StoreKeys[S]; error: VaultError }[] = [];
    for (const { key, row } of await this.snapshot([store])) {
      const logical = key.slice(1) as unknown as StoreKeys[S];
      try { rows.push({ key: logical, ...await this.open(store, key.slice(1), row) }); }
      catch (error) {
        if (error instanceof VaultError && error.code === 'CANCELLED') throw error;
        failed.push({ key: logical, error: error instanceof VaultError ? error : new VaultError('STORAGE', { operation: 'store' }) });
      }
    }
    return { rows, failed };
  }
  private storageFailure(error: unknown): never {
    if (isQuota(error)) this.setState({ condition: 'paused', reason: 'quota' });
    if (error instanceof VaultError) throw error;
    throw new VaultError('STORAGE', { operation: 'store' });
  }
  private async commitRows(rows: readonly WriteRow[]): Promise<void> {
    const session = this.session(true);
    const sealed = await Promise.all(rows.map(async row => {
      checkKey(row.store, row.key);
      if (!Number.isSafeInteger(row.expected) || row.expected < 0) throw new VaultError('ARG');
      return { ...row, envelope: await this.seal(row.store, row.key, row.value, row.expected + 1) };
    }));
    this.assertGeneration(session.generation);
    const journal = rows.some(row => row.store === 'vaults' || row.store === 'operations');
    const stores: (EncryptedStore | 'meta')[] = [...new Set(rows.map(row => row.store))];
    if (journal) stores.push('meta');
    const tx = session.db.transaction(stores, 'readwrite');
    const done = tx.done;
    void done.catch(() => undefined);
    try {
      for (const row of sealed) {
        const current = await tx.objectStore(row.store).get(this.fullKey(row.key));
        if (current && !isQuarantined(current)) version(current);
        if (revision(current) !== row.expected) throw new VaultError('CONFLICT');
      }
      await Promise.all(sealed.map(async row => await tx.objectStore(row.store).put(row.envelope, this.fullKey(row.key))));
      // Pin rows and committed-journal order live in the same transaction as the ciphertext.
      for (const row of sealed) {
        if (row.store !== 'vaults' && row.store !== 'operations') continue;
        await this.syncPins(tx as JournalTx, row.store, row.key, row.value as StoreValues[PinStore]);
        if (row.store === 'operations' && (row.value as StoredOperation).stage === 'committed') await this.compactCommitted(tx as JournalTx, row.value as StoredOperation);
      }
      await done;
    } catch (error) {
      try { tx.abort(); } catch { /* Already aborted or committed. */ }
      await done.catch(() => undefined);
      this.storageFailure(error);
    }
  }
  async put<S extends Exclude<EncryptedStore, 'vaults' | 'operations'>>(store: S, key: StoreKeys[S], value: StoreValues[S], expectedRevision?: number): Promise<number> {
    const expected = expectedRevision ?? (await this.read(store, key))?.revision ?? 0;
    await this.commitRows([{ store, key, value, expected }]);
    return expected + 1;
  }
  async createVault(vault: StoredVault): Promise<number> {
    if (vault.pendingCandidateId !== null || vault.ownerCheckpointId !== null || vault.materializedViewId !== null
      || vault.lastOwnSeq !== '0' || vault.lastOwnWrittenAt !== '0' || Object.keys(vault.baseline).length) throw new VaultError('ARG');
    await this.commitRows([{ store: 'vaults', key: [vault.vaultId], value: vault, expected: 0 }]);
    await this.requestPersistence();
    return 1;
  }
  private pinKey(store: PinStore, key: readonly string[]): DatabaseKey { return this.fullKey(['pins', store, ...key]); }
  private pinsRange(): IDBKeyRange { return IDBKeyRange.bound([this.options.accountPubkey, 'pins'], [this.options.accountPubkey, 'pins', []]); }
  private async syncPins(tx: JournalTx, store: PinStore, key: readonly string[], value: StoreValues[PinStore]): Promise<void> {
    const meta = tx.objectStore('meta'), pinKey = this.pinKey(store, key), addresses = pinsOf(store, value);
    const current = await meta.get(pinKey) as PinRow | undefined;
    if (!addresses.length) { if (current) await meta.delete(pinKey); return; }
    if (current && current.addresses.length === addresses.length && current.addresses.every((address, i) => address === addresses[i])) return;
    await meta.put({ addresses }, pinKey);
  }
  /** Keeps the last COMMITTED_JOURNALS_KEPT compactable journals per vault for diagnostics. */
  private async compactCommitted(tx: JournalTx, operation: StoredOperation): Promise<void> {
    if (!compactable(operation)) return;
    const meta = tx.objectStore('meta'), key = this.fullKey(['committed', operation.vaultId]);
    const row = await meta.get(key) as CommittedRow | undefined;
    const ids = (row?.ids ?? []).filter(id => id !== operation.operationId);
    ids.push(operation.operationId);
    while (ids.length > COMMITTED_JOURNALS_KEPT) {
      const old = ids.shift()!;
      await tx.objectStore('operations').delete(this.fullKey([operation.vaultId, old]));
      await meta.delete(this.pinKey('operations', [operation.vaultId, old]));
    }
    await meta.put({ ids }, key);
  }
  /** Settings-only update. Journal/pointer updates must use saveJournal. */
  async updateVault(vault: StoredVault, expectedRevision: number): Promise<number> {
    const previous = await this.read('vaults', [vault.vaultId]);
    if (!previous || previous.revision !== expectedRevision || !samePointers(previous.value, vault, true)) throw new VaultError('CONFLICT');
    await this.commitRows([{ store: 'vaults', key: [vault.vaultId], value: vault, expected: expectedRevision }]);
    return expectedRevision + 1;
  }
  /** Crypto is completed before this atomic, revision-checked journal + pointer write. */
  async saveJournal(operation: StoredOperation, vault: StoredVault, expected: JournalRevisions): Promise<JournalRevisions> {
    if (operation.vaultId !== vault.vaultId) throw new VaultError('ARG');
    const oldVault = await this.read('vaults', [vault.vaultId]);
    const oldOperation = await this.read('operations', [vault.vaultId, operation.operationId]);
    if ((oldVault?.revision ?? 0) !== expected.vault || (oldOperation?.revision ?? 0) !== expected.operation) throw new VaultError('CONFLICT');
    if (oldOperation) {
      const old = oldOperation.value;
      if (old.kind !== operation.kind || old.stage === 'committed'
        || storageJson(old.candidate) !== storageJson(operation.candidate)
        || (old.signedEvent !== null && storageJson(old.signedEvent) !== storageJson(operation.signedEvent))
        || (old.stage !== 'needs-recovery' && operation.stage !== 'needs-recovery' && stages.indexOf(operation.stage) < stages.indexOf(old.stage))
        || old.pinnedAddresses.some(address => !operation.pinnedAddresses.includes(address))) throw new VaultError('CONFLICT');
    } else if (operation.stage !== 'prepared') throw new VaultError('ARG');
    if (oldVault) {
      if (oldVault.value.pendingCandidateId !== null && oldVault.value.pendingCandidateId !== operation.operationId) throw new VaultError('CONFLICT');
      if (operation.stage !== 'committed' && !samePointers(oldVault.value, vault, false)) throw new VaultError('CONFLICT');
    } else if (operation.kind !== 'create' || operation.stage !== 'prepared' || vault.lastOwnSeq !== '0'
      || vault.lastOwnWrittenAt !== '0' || vault.ownerCheckpointId !== null || vault.materializedViewId !== null
      || Object.keys(vault.baseline).length) throw new VaultError('ARG');
    if (vault.pendingCandidateId !== (operation.stage === 'committed' ? null : operation.operationId)) throw new VaultError('ARG');
    await this.commitRows([
      { store: 'operations', key: [vault.vaultId, operation.operationId], value: operation, expected: expected.operation },
      { store: 'vaults', key: [vault.vaultId], value: vault, expected: expected.vault },
    ]);
    if (!oldVault) await this.requestPersistence();
    return { vault: expected.vault + 1, operation: expected.operation + 1 };
  }
  /** Late relay receipts may update redundancy after commitment, never the
   * immutable candidate/event, journal phase, or any vault pointer. */
  async recordRelayOutcomes(vaultId: VaultId, operationId: string, outcomes: StoredOperation['relayOutcomes']): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      const row = await this.read('operations', [vaultId, operationId]);
      // SV-28 may compact old committed journals while a replica OK is in flight.
      // A missing row is terminal for receipt bookkeeping; never recreate it.
      if (!row) return;
      const relayOutcomes = mergeRelayOutcomes(row.value.relayOutcomes, outcomes);
      try {
        await this.commitRows([{ store: 'operations', key: [vaultId, operationId], value: { ...row.value, relayOutcomes }, expected: row.revision }]);
        return;
      } catch (error) { if (!(error instanceof VaultError) || error.code !== 'CONFLICT' || attempt >= 7) throw error; }
    }
  }
  /** Quarantine an incomplete operation without changing committed or pending pointers. */
  async markNeedsRecovery(vaultId: VaultId, operationId: string): Promise<void> {
    const row = await this.read('operations', [vaultId, operationId]);
    if (!row || row.value.stage === 'committed' || row.value.stage === 'needs-recovery') return;
    await this.commitRows([{ store: 'operations', key: [vaultId, operationId], value: { ...row.value, stage: 'needs-recovery', recoveryStage: row.value.stage }, expected: row.revision }]);
  }
  async pendingOperations(): Promise<readonly StoredOperation[]> {
    return (await this.list('operations')).map(row => row.value).filter(operation => operation.stage !== 'committed');
  }
  private async requestPersistence(): Promise<void> {
    try {
      if (this.persistenceRequested || !this.db || await this.db.count('vaults', accountRange(this.options.accountPubkey)) !== 1) return;
      this.persistenceRequested = true;
      const request = this.options.requestPersistence
        ?? (typeof navigator !== 'undefined' && navigator.storage?.persist ? () => navigator.storage.persist() : undefined);
      await request?.();
    } catch { /* Persistence may be denied; encrypted DB remains usable. */ }
  }
  private async quarantine(store: EncryptedStore | 'objects', key: readonly string[], original: unknown): Promise<void> {
    const { db } = this.session();
    const tx = db.transaction((store === 'objects' ? ['objects', 'objectIndex', 'meta'] : [store]) as (EncryptedStore | 'objects' | 'objectIndex' | 'meta')[], 'readwrite');
    const done = tx.done;
    void done.catch(() => undefined);
    try {
      // Do not overwrite a repair or a concurrent revision with stale corrupt bytes.
      const rows = tx.objectStore(store);
      const current = await rows.get(this.fullKey(key));
      const fingerprint = (value: unknown) => JSON.stringify(value, (_key, part: unknown) =>
        part instanceof ArrayBuffer ? hex(new Uint8Array(part)) : part);
      if (fingerprint(current) === fingerprint(original)) {
        await rows.put({ quarantined: true, original } as Row & Quarantine, this.fullKey(key));
        if (store === 'objects') await this.forgetIndexed(tx as unknown as CacheTx, this.fullKey(key));
      }
      await done;
    } catch (error) {
      try { tx.abort(); } catch { /* Already aborted. */ }
      await done.catch(() => undefined);
      this.storageFailure(error);
    }
    this.options.onQuarantine?.({ store, key: [...key] });
  }
  async quarantinedRecords(): Promise<readonly QuarantineNotice[]> {
    const { db } = this.session();
    const result: QuarantineNotice[] = [];
    for (const store of [...ENCRYPTED_STORES, 'objects'] as const) {
      const tx = db.transaction(store, 'readonly');
      const keys = await tx.store.getAllKeys(accountRange(this.options.accountPubkey));
      const values = await tx.store.getAll(accountRange(this.options.accountPubkey));
      keys.forEach((key, index) => { if (isQuarantined(values[index])) result.push({ store, key: key.slice(1) }); });
      await tx.done;
    }
    return result;
  }
  /** Extra live pins supplement (never replace) durable pending-journal pins. */
  setPins(owner: string, addresses: readonly Address[]): void {
    if (addresses.length) this.pins.set(owner, new Set(addresses));
    else this.pins.delete(owner);
  }
  private cacheKey(): DatabaseKey { return this.fullKey(['cache']); }
  private async cacheMeta(tx: CacheTx): Promise<CacheMeta> {
    return { totalBytes: 0, count: 0, clock: 0, ...(await tx.objectStore('meta').get(this.cacheKey()) as CacheMeta | undefined) };
  }
  /** Bytes that vanished behind the store's back (e.g. a cleared `objects` store) must not keep counting. */
  private async healIndex(address: Address): Promise<void> {
    const { db } = this.session();
    const key = this.fullKey([address]);
    if (!await db.get('objectIndex', key)) return;
    const tx = db.transaction(['objects', 'objectIndex', 'meta'], 'readwrite');
    const done = tx.done;
    void done.catch(() => undefined);
    try { if (!await tx.objectStore('objects').get(key)) await this.forgetIndexed(tx, key); await done; }
    catch (error) { try { tx.abort(); } catch { /* Already aborted. */ } await done.catch(() => undefined); this.storageFailure(error); }
  }
  /** Removes an index row and its size from the totals (eviction races, quarantine, healing). */
  private async forgetIndexed(tx: CacheTx, key: DatabaseKey): Promise<void> {
    const index = tx.objectStore('objectIndex'), row = await index.get(key);
    if (!row) return;
    const totals = await this.cacheMeta(tx);
    totals.totalBytes -= row.size; totals.count--;
    await index.delete(key);
    await tx.objectStore('meta').put(totals, this.cacheKey());
  }
  /** One-time migration from the scan-everything cache: size/LRU index and durable pin rows. */
  private async ensureCacheIndex(): Promise<void> {
    const { db } = this.session(true);
    if (await db.get('meta', this.cacheKey())) return;
    const operations = await this.list('operations'), vaults = await this.list('vaults');
    const tx = db.transaction(['objects', 'objectIndex', 'meta'], 'readwrite');
    const done = tx.done;
    void done.catch(() => undefined);
    try {
      const meta: CacheMeta = { totalBytes: 0, count: 0, clock: 0 };
      let cursor = await tx.objectStore('objects').openCursor(accountRange(this.options.accountPubkey));
      while (cursor) {
        const value = cursor.value;
        if (!isQuarantined(value)) {
          meta.totalBytes += value.bytes.byteLength; meta.count++; meta.clock = Math.max(meta.clock, value.lastUsed);
          await tx.objectStore('objectIndex').put({ account: this.options.accountPubkey, size: value.bytes.byteLength, lastUsed: value.lastUsed }, cursor.primaryKey);
        }
        cursor = await cursor.continue();
      }
      for (const row of operations) await this.syncPins(tx as unknown as JournalTx, 'operations', row.key, row.value);
      for (const row of vaults) await this.syncPins(tx as unknown as JournalTx, 'vaults', row.key, row.value);
      await tx.objectStore('meta').put(meta, this.cacheKey());
      await done;
    } catch (error) {
      try { tx.abort(); } catch { /* Already aborted. */ }
      await done.catch(() => undefined);
      this.storageFailure(error);
    }
  }
  /** O(1) accounting plus O(evicted) work: reads the pin rows, the totals row and one index
   * row; never scans `objects` or decrypts a journal. Eviction walks the LRU index oldest-first. */
  async cacheObject(address: Address, bytes: Uint8Array): Promise<void> {
    const owned = new Uint8Array(bytes);
    if (hex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned))) !== address) throw new VaultError('HASH_MISMATCH');
    const session = this.session(true);
    const tx = session.db.transaction(['objects', 'objectIndex', 'meta'], 'readwrite');
    const done = tx.done;
    void done.catch(() => undefined);
    try {
      const meta = tx.objectStore('meta'), index = tx.objectStore('objectIndex'), objects = tx.objectStore('objects');
      const key = this.fullKey([address]);
      const pinned = new Set<string>();
      for (const row of await meta.getAll(this.pinsRange()) as PinRow[]) for (const pin of row.addresses) pinned.add(pin);
      const totals = await this.cacheMeta(tx);
      const existing = await index.get(key);
      if (existing) { totals.totalBytes -= existing.size; totals.count--; }
      totals.totalBytes += owned.byteLength; totals.count++;
      totals.clock = Math.max(totals.clock + 1, Date.now());
      if (totals.totalBytes > this.cacheLimit) {
        let cursor = await index.index('byUse').openCursor(IDBKeyRange.bound([this.options.accountPubkey], [this.options.accountPubkey, []]));
        while (cursor && totals.totalBytes > this.cacheLimit) {
          const candidate = cursor.primaryKey[1] as Address;
          // Live pins are re-read per candidate: they may change between IDB awaits.
          if (candidate !== address && !pinned.has(candidate) && ![...this.pins.values()].some(set => set.has(candidate))) {
            totals.totalBytes -= cursor.value.size; totals.count--;
            await objects.delete(cursor.primaryKey); await cursor.delete();
          }
          cursor = await cursor.continue();
        }
        if (totals.totalBytes > this.cacheLimit) throw new DOMException('Cache is pinned or full', 'QuotaExceededError');
      }
      await objects.put({ bytes: owned, lastUsed: totals.clock }, key);
      await index.put({ account: this.options.accountPubkey, size: owned.byteLength, lastUsed: totals.clock }, key);
      await meta.put(totals, this.cacheKey());
      await done;
    } catch (error) {
      try { tx.abort(); } catch { /* Already aborted. */ }
      await done.catch(() => undefined);
      this.storageFailure(error);
    }
  }
  async cachedObject(address: Address): Promise<Uint8Array<ArrayBuffer> | null> {
    const { db, generation } = this.session();
    const row = await db.get('objects', this.fullKey([address]));
    if (!row) { await this.healIndex(address); return null; }
    if (isQuarantined(row)) throw new VaultError('STORAGE');
    const owned = new Uint8Array(row.bytes);
    if (hex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned))) !== address) {
      await this.quarantine('objects', [address], row);
      throw new VaultError('HASH_MISMATCH');
    }
    this.assertGeneration(generation);
    // LRU touch: the index row and clock move; the bytes are not rewritten. The object is
    // re-read in the transaction so a concurrent eviction never leaves a phantom index row.
    const tx = db.transaction(['objects', 'objectIndex', 'meta'], 'readwrite');
    const done = tx.done;
    void done.catch(() => undefined);
    try {
      const key = this.fullKey([address]), present = await tx.objectStore('objects').get(key);
      if (!present || isQuarantined(present)) await this.forgetIndexed(tx, key);
      else {
        const totals = await this.cacheMeta(tx), current = await tx.objectStore('objectIndex').get(key);
        totals.clock = Math.max(totals.clock + 1, Date.now());
        if (!current) { totals.totalBytes += owned.byteLength; totals.count++; }
        await tx.objectStore('objectIndex').put({ account: this.options.accountPubkey, size: current?.size ?? owned.byteLength, lastUsed: totals.clock }, key);
        await tx.objectStore('meta').put(totals, this.cacheKey());
      }
      await done;
    } catch (error) {
      try { tx.abort(); } catch { /* Already aborted. */ }
      await done.catch(() => undefined);
      this.storageFailure(error);
    }
    return owned;
  }
  /**
   * Vault-scoped package only (SV-34/G2): account device-key history is never included, so a
   * guessed package cannot open wraps for other vaults. `logn` must be within
   * [RECOVERY_EXPORT_LOGN, RECOVERY_MAX_LOGN]; the engine calibrates it per device.
   */
  async exportRecovery(vaultId: VaultId, passphrase: string, options: { logn?: number } = {}): Promise<{ filename: string; package: VaultRecoveryPackage }> {
    if (!passphrase) throw new VaultError('ARG');
    assertRecoveryPassphrase(passphrase);
    const logn = options.logn ?? RECOVERY_EXPORT_LOGN;
    if (!Number.isInteger(logn) || logn < RECOVERY_EXPORT_LOGN || logn > RECOVERY_MAX_LOGN) throw new VaultError('ARG', { operation: 'recover' });
    const vault = await this.read('vaults', [vaultId]);
    if (!vault) throw new VaultError('INCOMPLETE');
    const payload: VaultRecoveryPayload = {
      schemaVersion: 1, protocolId: PROTOCOL_ID, vaultId,
      nodeRings: vault.value.nodeRings, grant: vault.value.grant, network: vault.value.network,
    };
    const packageKey = crypto.getRandomValues(new Uint8Array(32));
    const plaintext = encoder.encode(storageJson(payload));
    try {
      const ncryptsec = await encryptNcryptsec(packageKey, passphrase, logn);
      const key = await crypto.subtle.importKey('raw', packageKey, 'AES-GCM', false, ['encrypt']);
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: recoveryAAD() }, key, plaintext);
      return {
        filename: `onyx-vault-recovery-${vaultId.slice(0, 12)}.json`,
        package: { format: 'onyx-vault-recovery', version: 1, ncryptsec, payload: { nonce: hex(nonce), ciphertext: hex(new Uint8Array(ciphertext)) } },
      };
    } finally { packageKey.fill(0); plaintext.fill(0); }
  }
}
function recoveryAAD(): Uint8Array<ArrayBuffer> {
  return encoder.encode(JSON.stringify(['onyx-vault-recovery', 1]));
}
/** Encrypted payload bound: rings/grant/network for one vault are far below this. */
export const RECOVERY_MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024;
/**
 * Returns storage DTOs, not authority to import or overwrite an existing vault.
 *
 * Order matters (SV-34/7B/7C): outer format, payload size bounds and the NIP-49 wrapper cost
 * are checked before any key derivation (`UNSUPPORTED` reason `kdf-cost` for a cost above the
 * 256 MiB ceiling); the authenticated vault id must equal `expected.vaultId` (`POLICY` reason
 * `recovery-vault-mismatch`) so a substituted package can never be mistaken for the vault the
 * caller intends to restore. Legacy payloads that carried `deviceKeyHistory` open, but that
 * field is dropped rather than returned.
 */
export async function openRecovery(recovery: VaultRecoveryPackage, passphrase: string, expected: { readonly vaultId: VaultId }): Promise<VaultRecoveryPayload> {
  if (!recovery || recovery.format !== 'onyx-vault-recovery' || recovery.version !== 1) throw new VaultError('VERSION');
  if (!expected || !/^[0-9a-f]{64}$/.test(expected.vaultId)) throw new VaultError('ARG', { operation: 'recover' });
  if (typeof recovery.payload?.ciphertext !== 'string' || typeof recovery.payload.nonce !== 'string' || typeof recovery.ncryptsec !== 'string') throw new VaultError('ARG', { operation: 'recover' });
  if (recovery.payload.ciphertext.length > RECOVERY_MAX_CIPHERTEXT_BYTES * 2) throw new VaultError('TOO_LARGE', { operation: 'recover' });
  parseNcryptsec(recovery.ncryptsec); // structure + cost ceiling, no derivation yet
  const nonce = unhex(recovery.payload.nonce, 12), ciphertext = unhex(recovery.payload.ciphertext);
  let packageKey: Uint8Array | undefined;
  try {
    packageKey = await decryptNcryptsec(recovery.ncryptsec, passphrase);
    const key = await crypto.subtle.importKey('raw', new Uint8Array(packageKey), 'AES-GCM', false, ['decrypt']);
    const plaintext = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: nonce, additionalData: recoveryAAD(),
    }, key, ciphertext));
    try {
      const parsed = JSON.parse(decoder.decode(plaintext)) as VaultRecoveryPayload & { deviceKeyHistory?: unknown };
      version(parsed);
      storageJson(parsed);
      const { deviceKeyHistory: _legacyHistory, ...payload } = parsed;
      if (!/^[0-9a-f]{64}$/.test(payload.vaultId) || !payload.nodeRings || !payload.network) throw new VaultError('ARG');
      if (payload.vaultId !== expected.vaultId) throw new VaultError('POLICY', { operation: 'recover', reason: 'recovery-vault-mismatch', retryable: false });
      return payload;
    } finally { plaintext.fill(0); }
  } catch (error) {
    if (error instanceof VaultError && ['VERSION', 'UNSUPPORTED', 'POLICY', 'TOO_LARGE'].includes(error.code)) throw error;
    throw new VaultError('CRYPTO', { operation: 'recover', retryable: false });
  } finally { packageKey?.fill(0); }
}
