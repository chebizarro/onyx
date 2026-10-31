import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { deleteDB, openDB, type IDBPDatabase } from 'idb';
import type { SecretStore } from '../../../platform/types';
import { PROTOCOL_ID, UINT64_MAX } from '../protocol';
import {
  COMMITTED_JOURNALS_KEPT, DEFAULT_CACHE_LIMIT, ENCRYPTED_STORES, STORAGE_KEY_PREFIX, VAULT_DATABASE_VERSION, VaultStore,
  openRecovery, toStorage, uint64FromDecimal, uint64ToDecimal,
} from '../store';
import type { EncryptedStore, VaultStoreOptions } from '../store';
import type { Address, JournalStage, NodeId, Pubkey, StoredOperation, StoredVault, VaultId } from '../types';
import { parseNcryptsec, RECOVERY_EXPORT_LOGN } from '../recovery';

const account = 'a'.repeat(64) as Pubkey;
const vaultId = 'b'.repeat(64) as VaultId;
const otherVaultId = 'c'.repeat(64) as VaultId;
const nodeId = 'd'.repeat(64) as NodeId;
const version = { schemaVersion: 1, protocolId: PROTOCOL_ID } as const;
function vault(id = vaultId): StoredVault {
  return {
    ...version, vaultId: id, rootNodeId: nodeId, owner: account,
    mount: { notebookPath: '/private/notebook', relativePath: 'Private vault' }, label: 'Private label',
    publisher: null, attachedAt: null, grant: null,
    nodeRings: { [nodeId]: { entries: [{ epoch: '1', nodeKey: 'e'.repeat(64) }] } },
    network: { readRelays: [], writeRelays: [], readBlossom: [], writeBlossom: [] }, enabled: true,
    lastOwnSeq: '0', lastOwnWrittenAt: '0', ownerCheckpointId: null, materializedViewId: null,
    baseline: {}, pendingCandidateId: null, retainedRoots: [], deliveryLedger: [], resealProgress: null,
  };
}
function operation(stage: JournalStage = 'prepared'): StoredOperation {
  return {
    ...version, vaultId, operationId: 'candidate-1', kind: 'publish', stage,
    candidate: { root: 'immutable-root', seq: '1' }, signedEvent: null,
    pinnedAddresses: [], pendingAddress: null, uploadOutcomes: {}, relayOutcomes: {},
  };
}
class Secrets implements SecretStore {
  readonly values = new Map<string, string>();
  locked = false;
  get = vi.fn(async (key: string) => { if (this.locked) throw new Error('locked'); return this.values.get(key) ?? null; });
  set = vi.fn(async (key: string, value: string) => { if (this.locked) throw new Error('locked'); this.values.set(key, value); });
  delete = vi.fn(async (key: string) => { this.values.delete(key); });
  isLocked = () => this.locked;
  unlock = vi.fn(async (_passphrase: string) => { this.locked = false; });
}
let databaseName: string;
let secrets: Secrets;
let stores: VaultStore[];
let raw: IDBPDatabase | undefined;
function session(options: Partial<VaultStoreOptions> = {}): VaultStore {
  const store = new VaultStore({ accountPubkey: account, databaseName, secrets, ...options });
  stores.push(store);
  return store;
}
async function db(): Promise<IDBPDatabase> { return raw ??= await openDB(databaseName); }
async function stored(store: EncryptedStore, key: string[]) { return (await db()).get(store, [account, ...key]); }
async function blob(value: number): Promise<{ address: Address; bytes: Uint8Array<ArrayBuffer> }> {
  const bytes = Uint8Array.of(value);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return { bytes, address: Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('') as Address };
}
async function cache(store: VaultStore, item: Awaited<ReturnType<typeof blob>>) { await store.cacheObject(item.address, item.bytes); }

beforeEach(() => {
  databaseName = `vault-test-${crypto.randomUUID()}`;
  secrets = new Secrets();
  stores = [];
  raw = undefined;
});
afterEach(async () => {
  vi.restoreAllMocks();
  stores.forEach(store => store.stop());
  raw?.close();
  await deleteDB(databaseName);
});

describe('encrypted vault store', () => {
  it('creates the nine v2 stores and an account key before writing encrypted state', async () => {
    const store = session();
    expect(DEFAULT_CACHE_LIMIT).toBe(512 * 1024 * 1024);
    expect(await store.start()).toEqual({ condition: 'ready' });
    expect((await db()).version).toBe(VAULT_DATABASE_VERSION);
    expect(Array.from((await db()).objectStoreNames).sort()).toEqual([...ENCRYPTED_STORES, 'objects', 'objectIndex', 'meta'].sort());
    expect(secrets.values.get(STORAGE_KEY_PREFIX + account)).toMatch(/^[0-9a-f]{64}$/);
    const accountRow = await store.read('accounts', []);
    expect(accountRow?.value.deviceId).toBeTruthy();
    const persist = vi.fn(async () => true);
    const second = session({ requestPersistence: persist });
    await second.start();
    await second.createVault(vault());
    expect(persist).toHaveBeenCalledOnce();
    await second.createVault(vault(otherVaultId));
    expect(persist).toHaveBeenCalledOnce();
    const row = await stored('vaults', [vaultId]);
    expect(row.nonce.byteLength).toBe(12);
    expect(row.ciphertext.byteLength).toBeGreaterThan(16);
    expect(new TextDecoder().decode(row.ciphertext)).not.toContain('Private label');
    expect(JSON.stringify(row)).not.toContain('/private/notebook');
    expect((await second.read('vaults', [vaultId]))?.value).toEqual(vault());
  });

  it('uses fresh AES-GCM nonces, keeps keys out of metadata, and preserves data on logout', async () => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    const first = await stored('vaults', [vaultId]);
    await store.updateVault({ ...vault(), label: 'Changed' }, 1);
    const next = await stored('vaults', [vaultId]);
    expect(next.nonce).not.toEqual(first.nonce);
    expect(JSON.stringify(next)).not.toContain('e'.repeat(64));
    store.stop();
    expect(store.state).toEqual({ condition: 'stopped' });
    await expect(store.read('vaults', [vaultId])).rejects.toMatchObject({ code: 'STORAGE' });
    await store.start();
    expect((await store.read('vaults', [vaultId]))?.value.label).toBe('Changed');
    expect(secrets.set).toHaveBeenCalledOnce();
  });

  it('never generates a replacement key for an existing encrypted account', async () => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    const row = await stored('vaults', [vaultId]);
    const key = secrets.values.get(STORAGE_KEY_PREFIX + account)!;
    store.stop();
    await secrets.delete(STORAGE_KEY_PREFIX + account);
    expect(await store.start()).toEqual({ condition: 'needs-key', reason: 'missing' });
    expect(secrets.set).toHaveBeenCalledOnce();
    expect(await stored('vaults', [vaultId])).toEqual(row);
    secrets.values.set(STORAGE_KEY_PREFIX + account, key);
    expect(await store.start()).toEqual({ condition: 'ready' });
    expect((await store.read('vaults', [vaultId]))?.value).toEqual(vault());
  });

  it('wrong or malformed keys pause without quarantining valid records', async () => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    const row = await stored('vaults', [vaultId]);
    store.stop();
    secrets.values.set(STORAGE_KEY_PREFIX + account, 'f'.repeat(64));
    expect(await store.start()).toEqual({ condition: 'needs-key', reason: 'wrong' });
    expect(await stored('vaults', [vaultId])).toEqual(row);
    secrets.values.set(STORAGE_KEY_PREFIX + account, 'bad-key');
    expect(await store.start()).toEqual({ condition: 'needs-key', reason: 'wrong' });
    expect(secrets.set).toHaveBeenCalledOnce();
  });

  it('does not recover journals while locked and resumes through unlock()', async () => {
    const first = session();
    await first.start();
    await first.createVault(vault());
    const candidate = operation();
    await first.saveJournal(candidate, { ...vault(), pendingCandidateId: candidate.operationId }, { vault: 1, operation: 0 });
    first.stop();
    secrets.locked = true;
    const store = session();
    expect(await store.start()).toEqual({ condition: 'needs-key', reason: 'locked' });
    await expect(store.list('operations')).rejects.toMatchObject({ code: 'STORAGE' });
    expect(store.recoveryOperations).toEqual([]);
    expect(await store.unlock('master-passphrase')).toEqual({ condition: 'ready' });
    expect(store.recoveryOperations).toEqual([candidate]);
  });

  it('an unavailable secret service cannot create state or replace a key', async () => {
    secrets.get.mockRejectedValue(new Error('keyring unavailable'));
    const store = session();
    expect(await store.start()).toEqual({ condition: 'needs-key', reason: 'unavailable' });
    expect(secrets.set).not.toHaveBeenCalled();
    expect(await (await db()).count('accounts')).toBe(0);
    await expect(store.createVault(vault())).rejects.toMatchObject({ code: 'STORAGE' });
  });

  it('stopping during key retrieval prevents late key creation or session resurrection', async () => {
    let entered!: () => void;
    let release!: (value: string | null) => void;
    const called = new Promise<void>(resolve => { entered = resolve; });
    const held = new Promise<string | null>(resolve => { release = resolve; });
    secrets.get.mockImplementationOnce(async () => { entered(); return held; });
    const store = session();
    const starting = store.start();
    await called;
    store.stop();
    release(null);
    await expect(starting).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(store.state).toEqual({ condition: 'stopped' });
    expect(secrets.set).not.toHaveBeenCalled();
    expect(await (await db()).count('accounts')).toBe(0);
    expect(await store.start()).toEqual({ condition: 'ready' });
  });

  it('serializes concurrent first starts onto the same account storage key', async () => {
    const first = session();
    const second = session();
    await Promise.all([first.start(), second.start()]);
    expect(secrets.set).toHaveBeenCalledOnce();
    expect((await first.read('accounts', []))?.value).toEqual((await second.read('accounts', []))?.value);
  });

  it('isolates accounts and binds encrypted records to the account, store, and record key', async () => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    await store.createVault(vault(otherVaultId));
    const row = await stored('vaults', [vaultId]);
    // The IDB primary key is outside the ciphertext; swapping it must fail authentication.
    await (await db()).put('vaults', row, [account, otherVaultId]);
    await expect(store.read('vaults', [otherVaultId])).rejects.toMatchObject({ code: 'STORAGE' });
    await (await db()).put('conflicts', row, [account, vaultId, 'copied']);
    await expect(store.read('conflicts', [vaultId, 'copied'])).rejects.toMatchObject({ code: 'STORAGE' });
    const other = '1'.repeat(64) as Pubkey;
    // Even sharing the same storage key does not remove the account AAD binding.
    secrets.values.set(STORAGE_KEY_PREFIX + other, secrets.values.get(STORAGE_KEY_PREFIX + account)!);
    const second = session({ accountPubkey: other });
    await second.start();
    expect(await second.read('vaults', [vaultId])).toBeNull();
    await (await db()).put('vaults', row, [other, vaultId]);
    await expect(second.read('vaults', [vaultId])).rejects.toMatchObject({ code: 'STORAGE' });
    expect((await store.read('vaults', [vaultId]))?.value).toEqual(vault());
  });

  it('quarantines corrupt bytes in place and surfaces them without resetting other vaults', async () => {
    const onQuarantine = vi.fn();
    const store = session({ onQuarantine });
    await store.start();
    await store.createVault(vault());
    await store.createVault(vault(otherVaultId));
    const row = await stored('vaults', [vaultId]);
    new Uint8Array(row.ciphertext)[0] ^= 1;
    await (await db()).put('vaults', row, [account, vaultId]);
    await expect(store.read('vaults', [vaultId])).rejects.toMatchObject({ code: 'STORAGE' });
    expect(await stored('vaults', [vaultId])).toEqual({ quarantined: true, original: row });
    expect(await store.quarantinedRecords()).toEqual([{ store: 'vaults', key: [vaultId] }]);
    expect(onQuarantine).toHaveBeenCalledWith({ store: 'vaults', key: [vaultId] });
    expect((await store.read('vaults', [otherVaultId]))?.value).toEqual(vault(otherVaultId));
    await expect(store.updateVault(vault(), 1)).rejects.toMatchObject({ code: 'STORAGE' });
  });

  it.each(['schemaVersion', 'protocolId'] as const)('rejects unsupported %s without rewriting it', async field => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    const row = { ...await stored('vaults', [vaultId]), [field]: field === 'schemaVersion' ? 2 : 'future/v3' };
    await (await db()).put('vaults', row, [account, vaultId]);
    await expect(store.read('vaults', [vaultId])).rejects.toMatchObject({ code: 'VERSION' });
    expect(await stored('vaults', [vaultId])).toEqual(row);
    expect(await store.quarantinedRecords()).toEqual([]);
    const accountValue = (await store.read('accounts', []))!;
    const accountRow = { ...await stored('accounts', []), [field]: row[field] };
    await (await db()).put('accounts', accountRow, [account]);
    // Supplying a CAS revision must not bypass unsupported-version protection.
    await expect(store.put('accounts', [], accountValue.value, accountValue.revision)).rejects.toMatchObject({ code: 'VERSION' });
    expect(await stored('accounts', [])).toEqual(accountRow);
  });

  it('preserves uint64 max and historical keys as canonical decimal/hex storage DTOs', async () => {
    const store = session();
    await store.start();
    const entry = toStorage({ epoch: UINT64_MAX, nodeKey: new Uint8Array(32).fill(7) });
    expect(entry).toEqual({ epoch: '18446744073709551615', nodeKey: '07'.repeat(32) });
    const value = { ...vault(), nodeRings: { [nodeId]: { entries: [entry] } } };
    await store.createVault(value);
    const restored = (await store.read('vaults', [vaultId]))!.value.nodeRings[nodeId].entries[0];
    expect(uint64FromDecimal(restored.epoch)).toBe(UINT64_MAX);
    expect(uint64ToDecimal(UINT64_MAX)).toBe(restored.epoch);
    expect(toStorage(new Map([[nodeId, { epoch: 1n }]]))).toEqual({ [nodeId]: { epoch: '1' } });
  });

  it.each(['01', '-1', '1e3', '1.0', '18446744073709551616', '', '+1'])('rejects noncanonical uint64 %j', value => {
    expect(() => uint64FromDecimal(value)).toThrow();
  });
  it('rejects numeric protocol uint64s instead of accepting precision loss', () => {
    expect(() => toStorage({ seq: 1 })).toThrow();
    expect(() => toStorage({ epoch: -1n })).toThrow();
    expect(() => toStorage({ sizePlain: UINT64_MAX + 1n })).toThrow();
  });
});

describe('durable operations and pointer transactions', () => {
  it.each(['prepared', 'uploading', 'ready-to-publish', 'awaiting-ack', 'needs-recovery', 'committed'] as const)(
    'recovers a restart at %s without advancing pointers or recreating the candidate', async stage => {
      const store = session();
      await store.start();
      await store.createVault(vault());
      let op = operation();
      let state: StoredVault = { ...vault(), pendingCandidateId: op.operationId };
      let revisions = await store.saveJournal(op, state, { vault: 1, operation: 0 });
      if (stage !== 'prepared') {
        op = { ...op, stage };
        state = { ...state, pendingCandidateId: stage === 'committed' ? null : op.operationId, lastOwnSeq: stage === 'committed' ? '1' : '0' };
        revisions = await store.saveJournal(op, state, revisions);
      }
      store.stop();
      const restarted = session();
      await restarted.start();
      expect(restarted.recoveryOperations).toEqual(stage === 'committed' ? [] : [op]);
      expect(await restarted.read('vaults', [vaultId])).toEqual({ value: state, revision: revisions.vault });
      expect(await restarted.read('operations', [vaultId, op.operationId])).toEqual({ value: op, revision: revisions.operation });
    },
  );

  it('prepares creation and its vault pending pointer in one transaction', async () => {
    const store = session();
    await store.start();
    const op = { ...operation(), kind: 'create' } as const;
    const state = { ...vault(), pendingCandidateId: op.operationId };
    await store.saveJournal(op, state, { vault: 0, operation: 0 });
    expect((await store.read('vaults', [vaultId]))?.value.pendingCandidateId).toBe(op.operationId);
    expect((await store.read('operations', [vaultId, op.operationId]))?.value).toEqual(op);
  });

  it('quota failure aborts the journal and pointer together, and pauses future commits', async () => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    const op = operation();
    const state = { ...vault(), pendingCandidateId: op.operationId };
    const revisions = await store.saveJournal(op, state, { vault: 1, operation: 0 });
    const put = IDBObjectStore.prototype.put;
    const failure = vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(function (this: IDBObjectStore, value: unknown, key?: IDBValidKey) {
      if (this.name === 'vaults') throw new DOMException('disk full', 'QuotaExceededError');
      return put.call(this, value, key);
    });
    await expect(store.saveJournal({ ...op, stage: 'committed' }, { ...state, pendingCandidateId: null, lastOwnSeq: '1' }, revisions)).rejects.toMatchObject({ code: 'STORAGE' });
    expect(store.state).toEqual({ condition: 'paused', reason: 'quota' });
    expect(await store.read('operations', [vaultId, op.operationId])).toEqual({ value: op, revision: 1 });
    expect(await store.read('vaults', [vaultId])).toEqual({ value: state, revision: 2 });
    failure.mockRestore();
    await expect(store.saveJournal({ ...op, stage: 'committed' }, { ...state, pendingCandidateId: null, lastOwnSeq: '1' }, revisions)).rejects.toMatchObject({ code: 'STORAGE' });
    await store.start();
    await store.saveJournal({ ...op, stage: 'committed' }, { ...state, pendingCandidateId: null, lastOwnSeq: '1' }, revisions);
    expect((await store.read('vaults', [vaultId]))?.value.lastOwnSeq).toBe('1');
    expect(await store.pendingOperations()).toEqual([]);
  });

  it('refuses stale revisions, candidate mutation, early pointer changes, and stage regression', async () => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    const op = operation();
    const state = { ...vault(), pendingCandidateId: op.operationId };
    const revisions = await store.saveJournal(op, state, { vault: 1, operation: 0 });
    await expect(store.saveJournal(op, state, { vault: 1, operation: 0 })).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(store.saveJournal({ ...op, candidate: { root: 'different' } }, state, revisions)).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(store.saveJournal(op, { ...state, lastOwnSeq: '1' }, revisions)).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(store.updateVault({ ...state, lastOwnSeq: '1' }, revisions.vault)).rejects.toMatchObject({ code: 'CONFLICT' });
    const advanced = await store.saveJournal({ ...op, stage: 'awaiting-ack' }, state, revisions);
    await expect(store.saveJournal(op, state, advanced)).rejects.toMatchObject({ code: 'CONFLICT' });
    expect((await store.read('vaults', [vaultId]))?.value.lastOwnSeq).toBe('0');
  });
});

describe('verified ciphertext LRU', () => {
  it('evicts the least recently read unpinned address, including when timestamps tie', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1000);
    const store = session({ cacheLimitBytes: 3 });
    await store.start();
    const [a, b, c, d] = await Promise.all([1, 2, 3, 4].map(blob));
    await cache(store, a); await cache(store, b); await cache(store, c);
    expect(await store.cachedObject(a.address)).toEqual(a.bytes);
    await cache(store, d);
    expect(await store.cachedObject(b.address)).toBeNull();
    expect(await store.cachedObject(a.address)).toEqual(a.bytes);
    expect(await store.cachedObject(c.address)).toEqual(c.bytes);
    expect(await store.cachedObject(d.address)).toEqual(d.bytes);
  });

  it('never evicts live pins, durable candidate refs, pendingAddress or materialization pins', async () => {
    const store = session({ cacheLimitBytes: 4 });
    await store.start();
    await store.createVault(vault());
    const [a, b, c, d, e] = await Promise.all([1, 2, 3, 4, 5].map(blob));
    await cache(store, a); await cache(store, b); await cache(store, c); await cache(store, d);
    const op: StoredOperation = { ...operation(), kind: 'materialize', pinnedAddresses: [a.address], pendingAddress: b.address };
    const state = { ...vault(), pendingCandidateId: op.operationId, resealProgress: { remaining: ['item'], pendingAddress: c.address } };
    await store.saveJournal(op, state, { vault: 1, operation: 0 });
    store.setPins('active-materialization', [d.address]);
    await expect(cache(store, e)).rejects.toMatchObject({ code: 'STORAGE' });
    for (const item of [a, b, c, d]) expect(await store.cachedObject(item.address)).toEqual(item.bytes);
    expect(await store.cachedObject(e.address)).toBeNull();
    store.stop();
    const restarted = session({ cacheLimitBytes: 4 });
    await restarted.start();
    await cache(restarted, e);
    // The transient pin is gone; the durable operation/pending addresses survived restart.
    expect(await restarted.cachedObject(d.address)).toBeNull();
    for (const item of [a, b, c]) expect(await restarted.cachedObject(item.address)).toEqual(item.bytes);
    expect((await restarted.read('vaults', [vaultId]))?.value.pendingCandidateId).toBe(op.operationId);
  });

  it('refuses unverified inserts and quarantines ciphertext corrupted in the cache', async () => {
    const store = session();
    await store.start();
    const a = await blob(1);
    await expect(store.cacheObject(a.address, Uint8Array.of(2))).rejects.toMatchObject({ code: 'HASH_MISMATCH' });
    expect(await store.cachedObject(a.address)).toBeNull();
    await cache(store, a);
    await (await db()).put('objects', { bytes: Uint8Array.of(2), lastUsed: 1 }, [account, a.address]);
    await expect(store.cachedObject(a.address)).rejects.toMatchObject({ code: 'HASH_MISMATCH' });
    expect(await store.quarantinedRecords()).toEqual([{ store: 'objects', key: [a.address] }]);
  });
});

describe('cache accounting and journal compaction', () => {
  async function object(i: number): Promise<{ address: Address; bytes: Uint8Array<ArrayBuffer> }> {
    const bytes = new Uint8Array(16); new DataView(bytes.buffer).setUint32(0, i);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return { bytes, address: Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('') as Address };
  }
  it('cache writes and reads cost the same IndexedDB requests with 50 or 5,000 cached objects', async () => {
    const store = session(); await store.start();
    let requests = 0; const restore: (() => void)[] = [];
    const count = (proto: object, methods: readonly string[]) => {
      for (const method of methods) {
        const target = proto as Record<string, (...args: unknown[]) => unknown>, original = target[method];
        target[method] = function (this: unknown, ...args: unknown[]) { requests++; return original.apply(this, args); };
        restore.push(() => { target[method] = original; });
      }
    };
    count(IDBObjectStore.prototype, ['get', 'getAll', 'getAllKeys', 'put', 'delete', 'openCursor', 'openKeyCursor', 'count', 'clear']);
    count(IDBIndex.prototype, ['get', 'getAll', 'getAllKeys', 'openCursor', 'openKeyCursor', 'count']);
    count(IDBCursor.prototype, ['continue', 'advance', 'delete', 'update']);
    try {
      const fill = async (from: number, to: number) => { for (let i = from; i < to; i++) { const o = await object(i); await store.cacheObject(o.address, o.bytes); } };
      const cost = async (i: number) => { const o = await object(i); requests = 0; await store.cacheObject(o.address, o.bytes); const write = requests; requests = 0; expect(await store.cachedObject(o.address)).toEqual(o.bytes); return { write, read: requests }; };
      await fill(0, 50); const small = await cost(50);
      await fill(51, 5000); const large = await cost(5000);
      expect(large).toEqual(small);
      expect(small.write).toBeLessThanOrEqual(10); expect(small.read).toBeLessThanOrEqual(6);
    } finally { restore.forEach(fn => fn()); }
  }, 60000);
  it('compacts committed publish journals beyond the retained window but keeps journals with delivery intents', async () => {
    const store = session(); await store.start(); await store.createVault(vault());
    let vaultRevision = 1;
    const commit = async (operationId: string, candidate: StoredOperation['candidate']) => {
      const op = { ...operation(), operationId, candidate };
      const prepared = await store.saveJournal(op, { ...vault(), pendingCandidateId: operationId }, { vault: vaultRevision, operation: 0 });
      vaultRevision = (await store.saveJournal({ ...op, stage: 'committed' }, vault(), prepared)).vault;
    };
    await commit('with-deliveries', { root: 'r', deliveries: [{ recipient: account, cap: 'read' }] });
    for (let i = 0; i < COMMITTED_JOURNALS_KEPT + 3; i++) await commit(`plain-${i}`, { root: `r${i}` });
    const ids = (await store.list('operations')).map(row => row.value.operationId).sort();
    expect(ids).toEqual(['with-deliveries', ...Array.from({ length: COMMITTED_JOURNALS_KEPT }, (_, i) => `plain-${i + 3}`)].sort());
    expect(await store.pendingOperations()).toEqual([]);
  });
});

describe('recovery packages', () => {
  it('wraps a fresh package key with real NIP-49 and authenticates the AES-GCM payload', async () => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    const exported = await store.exportRecovery(vaultId, 'recovery passphrase');
    expect(exported.filename).toBe(`onyx-vault-recovery-${vaultId.slice(0, 12)}.json`);
    expect(exported.package).toMatchObject({ format: 'onyx-vault-recovery', version: 1 });
    expect(exported.package.ncryptsec).toMatch(/^ncryptsec1/);
    expect(JSON.stringify(exported.package)).not.toContain('e'.repeat(64));
    // SV-34: cost pinned at or above the OWASP scrypt floor; the payload is vault-scoped (no account key history).
    expect(parseNcryptsec(exported.package.ncryptsec).logn).toBeGreaterThanOrEqual(RECOVERY_EXPORT_LOGN);
    const opened = await openRecovery(exported.package, 'recovery passphrase', { vaultId });
    expect(opened).toEqual({ ...version, vaultId, nodeRings: vault().nodeRings, grant: null, network: vault().network });
    expect(opened).not.toHaveProperty('deviceKeyHistory');
    await expect(openRecovery(exported.package, 'wrong passphrase', { vaultId })).rejects.toMatchObject({ code: 'CRYPTO' });
    await expect(openRecovery(exported.package, 'recovery passphrase', { vaultId: otherVaultId })).rejects.toMatchObject({ code: 'POLICY', message: expect.stringContaining('different vault') });
    const ciphertext = exported.package.payload.ciphertext;
    const modified = { ...exported.package, payload: { ...exported.package.payload, ciphertext: (ciphertext.startsWith('00') ? '01' : '00') + ciphertext.slice(2) } };
    await expect(openRecovery(modified, 'recovery passphrase', { vaultId })).rejects.toMatchObject({ code: 'CRYPTO' });
    await expect(openRecovery({ ...exported.package, version: 2 } as unknown as typeof exported.package, 'recovery passphrase', { vaultId })).rejects.toMatchObject({ code: 'VERSION' });
  }, 30000);

  it('rejects weak passphrases and out-of-range costs before touching vault data', async () => {
    const store = session();
    await store.start();
    await store.createVault(vault());
    for (const weak of ['', 'short', 'aaaaaaaaaaaaaaaa', 'abcdefghijklmnop', 'password1234', 'abcabcabcabcabc']) {
      await expect(store.exportRecovery(vaultId, weak)).rejects.toMatchObject({ code: 'ARG' });
    }
    await expect(store.exportRecovery(vaultId, 'recovery passphrase', { logn: 16 })).rejects.toMatchObject({ code: 'ARG' });
    await expect(store.exportRecovery(vaultId, 'recovery passphrase', { logn: 19 })).rejects.toMatchObject({ code: 'ARG' });
  });
});
