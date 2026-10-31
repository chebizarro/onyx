import { verifyEvent, type Event, type Filter } from 'nostr-tools';
import type { NostrSigner } from '../nostr/signer';
import { BlossomError, VaultBlossom } from './blossom';
import { assertGrantWrapFits, buildGrantWrap, grantWrapPlaintextSizes, openGrantWrap, type OpenedGrant } from './carrier';
import { bytes32, bytesToHex, deriveChildNodeKey, deriveRootNodeKey, encodeUtf8, equalBytes, hashAddress, hex32, hexToBytes, selectEpochKey, verifyAddress } from './crypto';
import { advanceDeviceAnnouncementPin, buildDeviceAnnouncement, fetchDeviceAnnouncement, generateDeviceKey, importDeviceKey, latestDeviceAnnouncement, loadDeviceSigners, recipientKeyStatus, selectGrantRecipient, type AnnouncementEvidence, type DeviceAnnouncementObservation, type GrantRecipient } from './device-keys';
import { assertRecoveryPassphrase, calibrateRecoveryLogn, generateRecoveryPassphrase, RECOVERY_MIN_PASSPHRASE_LENGTH, RECOVERY_NOTES } from './recovery';
import { openDirectoryNode, sealDirectoryNode } from './dir-node';
import { VaultError, type VaultErrorDisplay, type VaultOperation } from './errors';
import { buildEpochLedgerEvent, decodeEpochLedger, encodeEpochLedger, historyDTag, ledgerWithHeads, openEpochLedgerEvent, type EpochLedger } from './epoch-ledger';
import { registerVaultEngineFactory, type VaultEngine, type VaultSession, type VaultEngineDeps, type VaultEngineSnapshot, type VaultHistoryState, type VaultEndpointStatus, type VaultCreateOptions, type VaultMountOptions, type VaultCapability, type VaultDeliveryOptions, type VaultConflictResolution, type VaultResealMode, type VaultConflictSummary, type VaultDeliverySummary, type VaultDeviceKeysSummary, type VaultDeviceKeysController, type VaultDeviceAnnouncementOutcome, type VaultRecipientKeyState } from './engine-api';
import { isManagedPath, intersectsManagedMount } from './legacy-exclusion';
import { absolutePath, isReservedPath, CaptureCoalescer, checkAbort, ExpectedHashes, readStableFile, traverseMount, validateArtifactRoots, validateMount, validateRelativePath, type DiskObservation, type StableFile } from './filesystem';
import { buildGrantRumor } from './grant';
import { boundedEvent } from './ingress';
import { assertInboxReplayCapacity, inboxReplayCapacityError, inboxReplayFull, partitionInboxReplay, replayIds, TransientReplay, VAULT_INBOX_DURABLE_CAPACITY } from './inbox-replay';
import { foldCurrentHeads, selectFoldInputs, type FoldLimits } from './fold';
import { DEFAULT_VAULT_BUDGETS, conflictRowBytes, type VaultBudgets } from './budgets';
import { EMPTY_FRESHNESS, acceptCheckpoint, grantedFloor, grantedHeadSeq, headPosition, noteHead, publishedCheckpoint, withGrant } from './freshness';
import { buildHeadEvent, encodeHead, headDTag, openHeadEvent } from './head';
import { coverHead, memberHeadParents } from './parents';
import { baselineHash, cleanStagingOrphans, ensureDirectory, materialize, persistLocalConflict, resumeMaterialization, type MaterializeContext, type MaterializeTarget } from './materialize';
import { PROTOCOL_ID, PORTHOME_HEAD_KIND, VAULT_GIFT_WRAP_KIND, UINT64_MAX, VAULT_MAX_OBJECTS, VAULT_MAX_MANIFEST_RECEPTION_BYTES, ONYX_VAULT_PUBLISHER_D_PREFIX, ONYX_VAULT_PUBLISHER_KIND, ONYX_VAULT_PUBLISHER_VERSION, NIP59_MAX_PLAINTEXT, NIP4E_ANNOUNCEMENT_KIND, NIP65_RELAY_LIST_KIND, VAULT_INGRESS_MAX_QUEUED_BYTES, VAULT_INGRESS_MAX_QUEUED_ITEMS } from './protocol';
import { entryDigest, fetchRecord, recordId } from './record';
import { ResealTask, resealCost, treeResealItems } from './reseal';
import { retainRootEvidence } from './retained-roots';
import { appendRing, initRing, mergeRings, resolveChildRing, validateKeyRing } from './ring';
import { VaultRelay, combineRelays, firstSufficient, validatePublicEndpoint, type VaultRelaySubscription, type RelayPublishResult, type RelayPublishOutcome } from './relay';
import { mergeRelayOutcomes, toStorage, VaultStore } from './store';
import { captureTree, createTree, newOwnerHead, revokeTree, sealTree, type CaptureDirectory, type CaptureEntry } from './tree';
import type { Address, Bytes32, DirectoryNode, EventId, FoldResult, KeyRing, NodeEntry, NodeId, Persisted, PathConflict, Pubkey, RecordId, RecordPath, RetainedRoot, StoredRetainedRoot, StorageJson, StoredAccount, StoredBaselineEntry, StoredConflict, StoredDeviceAnnouncement, StoredFoldQuarantine, StoredFreshness, StoredInvitation, StoredNetwork, StoredOperation, StoredVault, VaultGrant, VaultHead, VaultId, VaultMount, VaultTree, VerifiedRecord } from './types';
import { VaultWorkerClient } from './worker-client';

export { getVaultEngine, resetVaultEngine } from './engine-api';
const version = { schemaVersion: 1, protocolId: PROTOCOL_ID } as const;
function freezePublic<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freezePublic(child); Object.freeze(value); } return value;
}
const last = <T>(items: readonly T[]): T => items[items.length - 1];
/** Session teardown must still propagate; every other startup failure is per-vault or a notice. */
const cancelled = (error: unknown): boolean => error instanceof VaultError && error.code === 'CANCELLED';
/** Mount registry match tolerant of a trailing separator in either spelling. */
function sameNotebook(stored: string, session: string): boolean {
  const trim = (path: string) => path.length > 1 ? path.replace(/[\\/]+$/, '') : path;
  return stored === session || trim(stored) === trim(session);
}
/** Key-free projection of one recipient pin (SV-33). */
function recipientState(identity: Pubkey, pin: StoredDeviceAnnouncement | null): VaultRecipientKeyState {
  return { identity, status: recipientKeyStatus(pin),
    observed: pin ? { eventId: pin.eventId as EventId, createdAt: pin.createdAt, encryptionKey: pin.encryptionKey } : null,
    approvedKey: pin?.approvedKey ?? null, observedAt: pin?.observedAt ?? null };
}
function recipientStates(account: StoredAccount | undefined): VaultRecipientKeyState[] {
  return Object.entries(account?.deviceAnnouncements ?? {}).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([identity, pin]) => recipientState(identity as Pubkey, pin));
}
const AUTO_RESEAL_BUDGET = 8n * 1024n * 1024n;
function foldConflictId(vaultId: VaultId, conflict: PathConflict | Persisted<PathConflict>): string {
  const { pathEnc, otherRecordId, inView, inOther, writer, seq, rootManifest } = conflict;
  return hashAddress(encodeUtf8(JSON.stringify(toStorage({ vaultId, pathEnc, otherRecordId, inView, inOther, writer, seq, rootManifest }))));
}
// Private application metadata, never a nostrc head or grant extension.
const publisherD = (id: VaultId) => `${ONYX_VAULT_PUBLISHER_D_PREFIX}${id}`;
type RelayAdapter = Pick<VaultRelay, keyof VaultRelay>;
type BlossomAdapter = Pick<VaultBlossom, keyof VaultBlossom>;
export function hydrateRing(value: Persisted<KeyRing>): KeyRing {
  const ring = { entries: value.entries.map(e => ({ epoch: BigInt(e.epoch), nodeKey: bytes32(hexToBytes(e.nodeKey)) })) };
  validateKeyRing(ring); return ring;
}
function hydrateGrant(g: Persisted<VaultGrant>): VaultGrant {
  return { ...g, issuedAt: BigInt(g.issuedAt), ring: hydrateRing(g.ring) };
}
function hydrateEntry(e: Persisted<NodeEntry>): NodeEntry {
  const meta = { namePlain: e.namePlain, nameEnc: e.nameEnc, mode: e.mode, mtimeNs: BigInt(e.mtimeNs), sizePlain: BigInt(e.sizePlain) };
  if (e.kind === 'file') return { ...meta, kind: 'file', chunks: e.chunks.map(c => ({ ...c, sizePlain: BigInt(c.sizePlain), sizeSealed: BigInt(c.sizeSealed), chunkKeyId: BigInt(c.chunkKeyId) })) };
  if (e.kind === 'directory') return { ...meta, kind: 'directory', childNodeId: e.childNodeId, manifestAddress: e.manifestAddress, childEpoch: BigInt(e.childEpoch), ...(e.keyOverride ? { keyOverride: bytes32(hexToBytes(e.keyOverride)) } : {}) };
  return { ...meta, kind: 'symlink', target: e.target };
}
function hydrateTree(value: Persisted<VaultTree>): VaultTree {
  return createTree(value.nodes.map(item => ({ ring: hydrateRing(item.ring), node: { version: 2, nodeId: item.node.nodeId, epoch: BigInt(item.node.epoch),
    entries: item.node.entries.map(hydrateEntry), ...(item.node.vault ? { vault: { ...item.node.vault, grantsRev: BigInt(item.node.vault.grantsRev) } } : {}) } })));
}
function treeRings(tree: VaultTree): StoredVault['nodeRings'] {
  return Object.fromEntries(tree.nodes.map(v => [v.node.nodeId, toStorage(v.ring)]));
}
function wipeTree(tree: VaultTree): void {
  for (const item of tree.nodes) {
    for (const e of item.ring.entries) e.nodeKey.fill(0);
    for (const e of item.node.entries) if (e.kind === 'directory') e.keyOverride?.fill(0);
  }
}
function validateNetwork(network: StoredNetwork): StoredNetwork {
  for (const url of [...network.readRelays, ...network.writeRelays]) validatePublicEndpoint(url, 'wss:');
  for (const url of [...network.readBlossom, ...network.writeBlossom]) validatePublicEndpoint(url, 'https:');
  if (!network.readRelays.length || !network.writeRelays.length || !network.readBlossom.length || !network.writeBlossom.length) {
    const error = new VaultError('UNSUPPORTED', { operation: 'validate', retryable: true });
    error.message = 'Configure at least one read/write relay and one read/write Blossom server in shared vault settings, then retry.'; throw error;
  }
  return { readRelays: [...new Set(network.readRelays.map(url => validatePublicEndpoint(url, 'wss:')))], writeRelays: [...new Set(network.writeRelays.map(url => validatePublicEndpoint(url, 'wss:')))],
    readBlossom: [...new Set(network.readBlossom.map(url => validatePublicEndpoint(url, 'https:')))], writeBlossom: [...new Set(network.writeBlossom.map(url => validatePublicEndpoint(url, 'https:')))] };
}
function includeUploadConfirmations(confirmed: Record<string, readonly string[]>, outcomes: StoredOperation['uploadOutcomes']): void {
  for (const [address, value] of Object.entries(outcomes)) {
    if (!/^[0-9a-f]{64}$/.test(address) || !value || typeof value !== 'object' || Array.isArray(value)) continue;
    const servers = 'servers' in value ? value.servers : value;
    if (!servers || typeof servers !== 'object' || Array.isArray(servers)) continue;
    const accepted = Object.entries(servers).flatMap(([url, status]) => {
      if (status !== 'accepted') return [];
      try { return [validatePublicEndpoint(url, 'https:')]; } catch { return []; }
    });
    if (accepted.length) confirmed[address] = [...new Set([...(confirmed[address] ?? []), ...accepted])];
  }
}
function pathsOf(tree: VaultTree): Map<string, { node: DirectoryNode; entry: NodeEntry; ring: KeyRing }> {
  const nodes = new Map(tree.nodes.map(n => [n.node.nodeId, n]));
  const paths = new Map<string, { node: DirectoryNode; entry: NodeEntry; ring: KeyRing }>();
  const walk = (id: NodeId, prefix: string) => {
    const item = nodes.get(id)!;
    for (const entry of item.node.entries) {
      const path = prefix ? `${prefix}/${entry.namePlain}` : entry.namePlain;
      paths.set(path, { node: item.node, entry, ring: item.ring });
      if (entry.kind === 'directory') walk(entry.childNodeId, path);
    }
  };
  walk(tree.nodes[0].node.nodeId, ''); return paths;
}
type TreeItem = { node: DirectoryNode; entry: NodeEntry; ring: KeyRing };
interface TreeIndex { readonly byPath: Map<string, TreeItem>; readonly byEntry: Map<string, readonly [string, TreeItem]> }
const entryKey = (nodeId: NodeId, index: number): string => `${nodeId}:${index}`;
/** One walk per tree per reconciliation (SV-30/G1): decoded path → entry and
 * (node, entry index) → decoded path, replacing per-conflict `pathsOf` spreads. */
const treePathIndexes = new WeakMap<VaultTree, TreeIndex>();
const recordPathIndexes = new WeakMap<VerifiedRecord, Map<string, RecordPath>>();
const decodedRecordPaths = new WeakMap<VerifiedRecord, Map<string, RecordPath>>();
const candidatePathIndexes = new WeakMap<Readonly<Record<string, StoredBaselineEntry>>, { owner?: EventId; paths: ReadonlySet<string> }>();
function indexRecord(record: VerifiedRecord): Map<string, RecordPath> {
  let index = recordPathIndexes.get(record);
  if (!index) { index = new Map(record.paths.map(p => [p.pathEnc, p])); recordPathIndexes.set(record, index); }
  return index;
}
function indexTree(tree: VaultTree): TreeIndex {
  const cached = treePathIndexes.get(tree); if (cached) return cached;
  const nodes = new Map(tree.nodes.map(n => [n.node.nodeId, n]));
  const byPath = new Map<string, TreeItem>(), byEntry = new Map<string, readonly [string, TreeItem]>();
  const walk = (id: NodeId, prefix: string) => {
    const item = nodes.get(id)!;
    item.node.entries.forEach((entry, index) => {
      const path = prefix ? `${prefix}/${entry.namePlain}` : entry.namePlain;
      const located: TreeItem = { node: item.node, entry, ring: item.ring };
      byPath.set(path, located); byEntry.set(entryKey(item.node.nodeId, index), [path, located]);
      if (entry.kind === 'directory') walk(entry.childNodeId, path);
    });
  };
  walk(tree.nodes[0].node.nodeId, '');
  const index = { byPath, byEntry }; treePathIndexes.set(tree, index); return index;
}

/** Open each historical manifest exactly once at its authenticated epoch. Child
 * epochs and overrides come only from that same authenticated parent manifest. */
export async function reconstructHistoricalRings(tree: VaultTree, rootRing: KeyRing, retainedRoots: readonly StoredRetainedRoot[] | null,
  read: (address: Address) => Promise<Uint8Array>, check: () => void = () => {}, open = openDirectoryNode): Promise<VaultTree> {
  const held = new Map(tree.nodes.map(v => [v.node.nodeId, v.ring]));
  const missing = () => tree.nodes.some(v => v.node.entries.some(e => e.kind === 'file' && e.chunks.some(c => !held.get(v.node.nodeId)?.entries.some(k => k.epoch === c.chunkKeyId))));
  if (!missing()) return createTree(tree.nodes);
  const roots = retainRootEvidence(retainedRoots);
  for (const { address, epoch } of roots.filter(root => root.epoch !== null)) {
    check();
    const selected = BigInt(epoch!);
    // Selection precedes I/O and never falls back to another ring key.
    const key = selectEpochKey(rootRing, selected);
    const ring = initRing(selected, key); key.fill(0);
    let sealed: Uint8Array;
    try { sealed = await read(address); verifyAddress(sealed, address); }
    catch (error) {
      if (!(error instanceof VaultError) || !['INCOMPLETE', 'NETWORK', 'IO'].includes(error.code)) throw error;
      continue;
    }
    const root = open(ring, selected, sealed);
    if (root.nodeId !== tree.nodes[0].node.nodeId || root.epoch !== selected || root.vault?.vaultId !== tree.nodes[0].node.vault?.vaultId || root.vault?.owner !== tree.nodes[0].node.vault?.owner) throw new VaultError('POLICY');
    const seen = new Set<Address>(); let total = 0;
    async function walk(node: DirectoryNode, keys: KeyRing, source: Address, depth: number): Promise<void> {
      check();
      if (depth > 128 || seen.size >= VAULT_MAX_OBJECTS || seen.has(source)) throw new VaultError('CONFLICT');
      seen.add(source);
      const old = held.get(node.nodeId);
      held.set(node.nodeId, old ? mergeRings(old, keys) : keys);
      for (const e of node.entries) if (e.kind === 'directory') {
        const childRing = resolveChildRing(keys, node.epoch, e);
        const bytes = await read(e.manifestAddress); check(); verifyAddress(bytes, e.manifestAddress);
        total += bytes.length;
        if (total > VAULT_MAX_MANIFEST_RECEPTION_BYTES) throw new VaultError('TOO_LARGE');
        const child = open(childRing, e.childEpoch, bytes);
        if (child.nodeId !== e.childNodeId) throw new VaultError('POLICY');
        await walk(child, childRing, e.manifestAddress, depth + 1);
      }
    }
    try { await walk(root, ring, address, 0); }
    catch (error) { if (!(error instanceof VaultError) || !['INCOMPLETE', 'NETWORK', 'IO'].includes(error.code)) throw error; }
    if (!missing()) break;
  }
  if (missing()) throw new VaultError('EPOCH', { operation: 'recover' });
  return createTree(tree.nodes.map(v => ({ node: v.node, ring: held.get(v.node.nodeId)! })));
}

class Semaphore {
  private active = 0;
  private readonly waiting: (() => void)[] = [];
  constructor(private readonly limit: number) {}
  async run<T>(signal: AbortSignal, work: () => Promise<T>): Promise<T> {
    checkAbort(signal);
    if (this.active >= this.limit) await new Promise<void>(resolve => this.waiting.push(resolve));
    else this.active++;
    try { checkAbort(signal); return await work(); }
    finally { const next = this.waiting.shift(); if (next) next(); else this.active--; }
  }
}
/** A live REQ is an authority fence only after a real EOSE. Losing every
 * caught-up source invalidates the fence until historical replay completes. */
class AuthorityCatchup {
  private readonly active = new Set<string>();
  private readonly failed = new Set<string>();
  private promise!: Promise<void>;
  private resolve!: () => void;
  private reject!: (error: VaultError) => void;
  private timer?: ReturnType<typeof setTimeout>;
  private pending = false;
  private closed = false;
  constructor(private readonly endpoints: readonly string[], private readonly signal: AbortSignal) {
    this.begin(); signal.addEventListener('abort', this.close, { once: true });
    if (signal.aborted) this.close();
  }
  private begin(): void {
    clearTimeout(this.timer); this.pending = true;
    this.promise = new Promise<void>((resolve, reject) => { this.resolve = resolve; this.reject = reject; });
    void this.promise.catch(() => {});
    this.timer = setTimeout(() => this.refuse(new VaultError('NETWORK', { operation: 'publish' })), 15000);
  }
  private refuse(error: VaultError): void {
    if (!this.pending) return;
    clearTimeout(this.timer); this.pending = false; this.reject(error);
  }
  complete(endpoint: string): void {
    if (this.closed) return;
    if (!this.pending && !this.active.size) this.begin();
    this.active.add(endpoint); this.failed.delete(endpoint);
    clearTimeout(this.timer); this.pending = false; this.resolve();
  }
  fail(endpoint: string, error: VaultError): void {
    if (this.closed) return;
    const lost = this.active.delete(endpoint); this.failed.add(endpoint);
    if (lost && !this.active.size) this.begin();
    if (!this.active.size && this.failed.size >= this.endpoints.length) this.refuse(error);
  }
  get sufficient(): boolean { return this.active.size > 0; }
  wait(): Promise<void> { return this.closed ? Promise.reject(new VaultError('CANCELLED')) : this.promise; }
  close = (): void => {
    this.closed = true; this.active.clear(); this.refuse(new VaultError('CANCELLED'));
    clearTimeout(this.timer); this.signal.removeEventListener('abort', this.close);
  };
}

interface RuntimeVault {
  value: StoredVault;
  records: Map<EventId, VerifiedRecord>;
  trees: Map<EventId, VaultTree>;
  subscription?: VaultRelaySubscription;
  publisherSub?: VaultRelaySubscription;
  ledgerSub?: VaultRelaySubscription;
  headCatchup?: AuthorityCatchup;
  ledgerCatchup?: AuthorityCatchup;
  publisherCatchup?: AuthorityCatchup;
  subscriptionKey?: string;
  auxiliaryKey?: string;
  publisherVerifiedId?: string;
  ledger?: { eventId: string; body: EpochLedger };
  readConfirmations?: Map<Address, Set<string>>;
  headEvents?: Map<string, Event>;
  publisherEvents?: Map<string, Event>;
  ledgerEvents?: Map<string, Event>;
  seenHeads?: Set<string>;
  seenPublisher?: Set<string>;
  seenLedger?: Set<string>;
  caughtUp?: boolean;
  remoteQueued?: boolean;
  /** Per-path disk stat → hash observed by this session's captures (SV-28 fast path). */
  disk?: Map<string, DiskObservation>;
  provisionalPaths: readonly string[];
  provisionalOtherPaths: readonly string[];
  provisionalCount: number;
  ownUnfolded: Set<string>;
  otherUnfolded: Set<string>;
  error: VaultError | null;
  /** SV-36: ledger state relative to the newest held ring epoch, per session. */
  history?: VaultHistoryState;
}

export class HeadlessVaultEngine implements VaultEngine {
  private deps: VaultEngineDeps;
  private session?: VaultSession;
  private store?: VaultStore;
  private worker?: VaultWorkerClient;
  private account?: StoredAccount;
  private generation = 0;
  private abort = new AbortController();
  private releaseLock?: () => void;
  private lockTask?: Promise<unknown>;
  private startTask?: Promise<void>;
  private stopTask?: Promise<void>;
  private readonly lanes = new Map<string, Promise<unknown>>();
  private cpu = new Semaphore(1);
  private network = new Semaphore(4);
  private readonly relays = new Map<string, RelayAdapter>();
  private readonly blossoms = new Map<string, BlossomAdapter>();
  private readonly endpointStates = new Map<string, VaultEndpointStatus>();
  private readonly vaults = new Map<VaultId, RuntimeVault>();
  private readonly invitations = new Map<EventId, StoredInvitation>();
  private readonly echoes = new ExpectedHashes();
  private readonly viewPins = new Map<VaultId, readonly Address[]>();
  private inboxSub?: VaultRelaySubscription;
  private readonly startupInbox = new Map<string, Event>();
  private readonly queuedWraps = new Map<string, number>();
  private queuedWrapBytes = 0;
  private inboxError?: VaultError;
  private inboxAbort = new AbortController();
  private readonly startupLate: (() => void)[] = [];
  private devices: NostrSigner[] = [];
  private coalescer?: CaptureCoalescer;
  private readonly dirtyVaults = new Set<VaultId>();
  /** Durable tier: wrap IDs that opened to a valid grant (see inbox-replay.ts). */
  private readonly seenWraps = new Set<string>();
  /** Transient tier: terminally rejected / non-grant wrap IDs. Memory-only LRU. */
  private readonly rejectedWraps = new TransientReplay();
  private inboxAtCapacity = false;
  /** Invitation rows that could not be opened; while non-zero the replay tiers fail closed. */
  private unreadableInvitations = 0;
  /** Stored vault rows that could not be opened; listed, never silently dropped. */
  private readonly unavailableVaults = new Map<string, VaultErrorDisplay>();
  private readonly openingWraps = new Set<string>();
  private readonly inboxExtra = new Map<string, VaultRelaySubscription>();
  private inboxPubkeys: readonly string[] = [];
  private readonly recipientRoutes = new Map<Pubkey, Set<string>>();
  private readonly recipientRecords = new Map<Pubkey, Event>();
  private inboxEndpoints: readonly string[] = [];
  private readonly recipientCache = new Map<string, Promise<readonly string[]>>();
  private readonly listeners = new Set<(snapshot: VaultEngineSnapshot) => void>();
  private snapshot: VaultEngineSnapshot = freezePublic({ lifecycle: 'stopped', activity: 'idle', condition: 'ready', vaults: [], invitations: [], lastError: null });
  constructor(deps: VaultEngineDeps = {}) { this.deps = deps; }
  private now(): number { const n = this.deps.clock?.() ?? Math.floor(Date.now() / 1000); if (!Number.isSafeInteger(n) || n < 0) throw new VaultError('ARG'); return n; }
  private random(n: number): Uint8Array { const b = this.deps.rng?.(n) ?? crypto.getRandomValues(new Uint8Array(n)); if (b.length !== n) throw new VaultError('CRYPTO'); return new Uint8Array(b); }
  private id(): string { return bytesToHex(this.random(32)); }
  private check(generation = this.generation): void { if (generation !== this.generation || !this.session) throw new VaultError('CANCELLED'); checkAbort(this.abort.signal); }
  private emit(patch: Partial<VaultEngineSnapshot> = {}): void {
    this.snapshot = freezePublic({ ...this.snapshot, ...patch, endpoints: structuredClone([...this.endpointStates.values()]), deviceKeys: structuredClone(this.deviceSummary), networkDefaults: this.session ? structuredClone(this.session.networkDefaults) : undefined,
      vaults: Object.freeze([...this.vaults.values()].map(v => Object.freeze({ vaultId: v.value.vaultId, owner: v.value.owner, label: v.value.label,
        authority: v.value.owner === this.session?.accountPubkey ? 'owner' as const : this.policy(v)?.writers.includes(this.session!.accountPubkey) ? 'writer' as const : 'reader' as const,
        enabled: v.value.enabled, provisional: v.provisionalCount > 0, provisionalPaths: v.provisionalPaths, provisionalCount: v.provisionalCount,
        provisionalOtherPaths: v.provisionalOtherPaths, conflictCount: this.conflictCounts.get(v.value.vaultId) ?? 0,
        freshness: v.value.freshness ? v.value.freshness.verified ? 'verified' as const : 'unverified' as const : v.value.owner === this.session?.accountPubkey ? 'verified' as const : 'unverified' as const,
        checkpoint: v.value.freshness?.checkpoint ? Object.freeze({ seq: BigInt(v.value.freshness.checkpoint.seq), epoch: BigInt(v.value.freshness.checkpoint.epoch), grantsRev: BigInt(v.value.freshness.checkpoint.grantsRev) }) : null,
        history: v.history ?? (v.value.epochLedgerEvent ? 'incomplete' as const : 'unavailable' as const),
        foldQuarantine: v.value.foldQuarantine ? Object.freeze({ reason: v.value.foldQuarantine.reason, rows: v.value.foldQuarantine.rows, bytes: v.value.foldQuarantine.bytes }) : null,
        pendingDeliveryCount: this.deliveries(v).filter(d => d.state !== 'acknowledged').length, resealRemainingBytes: this.remainingBytes(v),
        resealTotalBytes: v.value.resealTotalBytes == null ? undefined : BigInt(v.value.resealTotalBytes),
        publisher: v.value.publisher ? Object.freeze({ ...v.value.publisher, since: BigInt(v.value.publisher.since), isCurrentDevice: v.value.publisher.deviceId === this.account?.deviceId }) : null,
        fileErrors: (v.value.captureErrors ?? []).map(e => ({ path: e.path, error: new VaultError(e.code, { operation: 'capture' }).toDisplay() })),
        members: this.members(v), deliveries: this.deliveries(v), conflicts: this.conflicts(v), regrantHeadroomBytes: this.regrantHeadroom(v), network: structuredClone(v.value.network),
        mount: v.value.attachedAt === null ? null : Object.freeze({ vaultId: v.value.vaultId, ...v.value.mount }), lastError: v.error?.toDisplay() ?? null }))),
      inbox: Object.freeze({ state: this.inboxAtCapacity ? 'at-capacity' as const : this.inboxError ? 'stopped' as const : 'active' as const,
        durableIds: this.seenWraps.size, capacity: VAULT_INBOX_DURABLE_CAPACITY, message: this.inboxError?.message ?? null }),
      unavailableVaults: Object.freeze([...this.unavailableVaults].map(([vaultId, error]) => Object.freeze({ vaultId, state: 'needs-repair' as const, error }))),
      invitations: Object.freeze([...this.invitations.entries()].filter(([, i]) => i.grant.owner !== this.session?.accountPubkey).map(([invitationId, i]) => Object.freeze({ invitationId, vaultId: i.vaultId, owner: i.grant.owner, cap: i.grant.cap, read: i.read, dismissed: i.dismissed, accepted: i.accepted,
        endpointHints: { readRelays: [...i.grant.hints.relays], writeRelays: [...i.grant.hints.relays], readBlossom: [...i.grant.hints.blossom], writeBlossom: [...i.grant.hints.blossom] } }))) });
    for (const listener of this.listeners) { try { listener(this.snapshot); } catch { /* A UI observer cannot interrupt a commit. */ } }
  }
  private conflictCounts = new Map<VaultId, number>();
  private conflictRows = new Map<VaultId, readonly StoredConflict[]>();
  private deliveryIntents = new Map<VaultId, { recipient: Pubkey; cap: VaultCapability; rumorId: EventId; issuedAt: bigint }[]>();
  private deviceSummary: VaultDeviceKeysSummary = { enabled: false, allowIdentityFallback: false, announcedPubkey: null, retainedKeyCount: 0, current: null, retained: [], lastAnnouncement: null, recipients: [] };
  // NIP-4E settings controller. Account rows (including key history) stay encrypted.
  readonly deviceKeys: VaultDeviceKeysController = {
    getState: () => freezePublic(structuredClone(this.deviceSummary)),
    observeRecipient: identity => this.lane('device-keys', 'share', async () => {
      const pubkey = hex32<Pubkey>(identity);
      const endpoints = await this.recipientRelays(pubkey, this.session!.networkDefaults.readRelays); this.check();
      const observation = await this.network.run(this.abort.signal, () => fetchDeviceAnnouncement(pubkey, this.relay(endpoints))); this.check();
      const { pin } = await this.advanceRecipientPin(pubkey, observation);
      return recipientState(pubkey, pin);
    }),
    approveRecipientKey: (identity, encryptionKey) => this.lane('device-keys', 'store', async () => {
      const pubkey = hex32<Pubkey>(identity), key = hex32<Pubkey>(encryptionKey);
      // Fingerprint-bound inside the serialised account transaction: a stale UI value cannot approve a different key.
      return this.accountWrite(account => {
        const pins = account.deviceAnnouncements ?? {}, pin = pins[pubkey];
        if (!pin || pin.encryptionKey !== key) throw new VaultError('ARG', { operation: 'share' });
        const next = { ...pin, approvedKey: key };
        return { account: { ...account, deviceAnnouncements: { ...pins, [pubkey]: next } }, result: recipientState(pubkey, next) };
      });
    }),
    resetRecipientPin: identity => this.lane('device-keys', 'store', async () => {
      const pubkey = hex32<Pubkey>(identity);
      await this.accountWrite(account => {
        if (!account.deviceAnnouncements?.[pubkey]) return { account, result: undefined };
        const pins = { ...account.deviceAnnouncements }; delete pins[pubkey];
        return { account: { ...account, deviceAnnouncements: pins }, result: undefined };
      });
    }),
    setEnabled: enabled => this.lane('device-keys', 'store', () => this.storeDeviceSettings({ enabled })),
    useIdentityFallback: allow => this.lane('device-keys', 'store', () => this.storeDeviceSettings({ allowIdentityFallback: allow })),
    generate: () => this.lane('device-keys', 'store', async () => {
      const pubkey = await generateDeviceKey(this.store!); this.check();
      await this.refreshDeviceKeys(); return pubkey;
    }),
    import: secret => this.lane('device-keys', 'store', async () => {
      const pubkey = await importDeviceKey(this.store!, secret); this.check();
      await this.refreshDeviceKeys(); return pubkey;
    }),
    announce: () => this.lane('device-keys', 'publish', async () => {
      const pubkey = this.deviceSummary.current?.pubkey;
      if (!pubkey) throw new VaultError('INCOMPLETE');
      const config = this.account!.config.deviceKeys as { signedAnnouncement?: Event } | undefined;
      const createdAt = Math.max(this.now(), (config?.signedAnnouncement?.created_at ?? -1) + 1);
      const event = await buildDeviceAnnouncement(this.session!.signer, pubkey, () => createdAt); this.check();
      const pending: VaultDeviceAnnouncementOutcome = { eventId: event.id as EventId, pubkey, state: 'pending', relayOutcomes: [] };
      // Persist the signed event before network I/O, including a crash-visible pending outcome.
      await this.storeDeviceSettings({ signedAnnouncement: toStorage(event), lastAnnouncement: toStorage(pending) });
      const result = await this.publishEvent(this.session!.networkDefaults.writeRelays, event); this.check();
      await this.storeDeviceSettings({ lastAnnouncement: toStorage({ ...pending,
        state: result.durable ? 'acknowledged' : 'failed',
        relayOutcomes: result.outcomes.map(({ relay, status }) => ({ relay, status })),
      }) });
      if (!result.durable) throw new VaultError('NETWORK', { operation: 'publish' });
      this.deviceSummary = { ...this.deviceSummary, announcedPubkey: pubkey, current: { pubkey, announced: true } };
      this.emit();
    }),
  };
  private async storeDeviceSettings(patch: Record<string, StorageJson>): Promise<void> {
    const config = await this.accountWrite(row => {
      const config = { ...(row.config.deviceKeys as Record<string, StorageJson> | undefined), ...patch };
      return { account: { ...row, config: { ...row.config, deviceKeys: config } }, result: config };
    });
    this.deviceSummary = { ...this.deviceSummary, enabled: config.enabled === true, allowIdentityFallback: config.allowIdentityFallback === true,
      lastAnnouncement: (config as { lastAnnouncement?: VaultDeviceAnnouncementOutcome }).lastAnnouncement ?? null };
    this.emit();
  }
  private accountChain: Promise<unknown> = Promise.resolve();
  /**
   * Serialised read-modify-write of the encrypted account row. Vault lanes run concurrently, so
   * pin advances and approvals must re-read the authoritative row rather than trust a snapshot;
   * the mutation sees the committed record and its result is what callers gate on.
   */
  private accountWrite<T>(mutate: (account: StoredAccount) => { account: StoredAccount; result: T }): Promise<T> {
    const task = this.accountChain.catch(() => {}).then(async () => {
      const row = await this.store!.read('accounts', []); this.check();
      if (!row) throw new VaultError('STORAGE');
      const { account, result } = mutate(row.value);
      if (account !== row.value) { await this.store!.put('accounts', [], account, row.revision); this.check(); }
      this.account = account;
      this.deviceSummary = { ...this.deviceSummary, recipients: recipientStates(account) };
      this.emit();
      return result;
    });
    this.accountChain = task;
    return task;
  }
  /** Monotonic pin advance against the committed row; older observations are refused (SV-33). */
  private advanceRecipientPin(identity: Pubkey, observation: DeviceAnnouncementObservation | null) {
    return this.accountWrite(account => {
      const pins = account.deviceAnnouncements ?? {}, previous = pins[identity] ?? null;
      const advanced = advanceDeviceAnnouncementPin(previous, observation, this.now());
      if (!advanced.pin || advanced.pin === previous) return { account, result: advanced };
      return { account: { ...account, deviceAnnouncements: { ...pins, [identity]: advanced.pin } }, result: advanced };
    });
  }
  /**
   * SV-33 delivery gate: observe, advance the committed pin, then select against the committed
   * record. Device delivery additionally requires that the committed approval equals the chosen
   * key, independently of the selector, so no code path can wrap a grant to an unapproved key.
   */
  private async selectRecipient(identity: Pubkey, endpoints: readonly string[], options: VaultDeliveryOptions): Promise<GrantRecipient & { evidence: AnnouncementEvidence }> {
    if (!options.enabled) return { identity, encryptionKey: identity, mode: 'identity', evidence: 'none' };
    const observation = await this.network.run(this.abort.signal, () => fetchDeviceAnnouncement(identity, this.relay(endpoints))); this.check();
    const { pin, evidence } = await this.advanceRecipientPin(identity, observation);
    const selected = selectGrantRecipient(identity, pin, options);
    if (selected.mode === 'device' && (!pin || pin.approvedKey === null || pin.approvedKey !== selected.encryptionKey || pin.encryptionKey !== pin.approvedKey || recipientKeyStatus(pin) !== 'approved')) {
      throw new VaultError('POLICY', { operation: 'share', reason: 'key-approval-required' });
    }
    return { ...selected, evidence };
  }
  private async refreshDeviceKeys(): Promise<void> {
    const previousCount = this.devices.length;
    const devices = await loadDeviceSigners(this.store!);
    try {
      this.check();
      const known = new Set(await Promise.all(this.devices.map(d => d.getPublicKey())));
      for (const device of devices) if (!known.has(await device.getPublicKey())) this.devices.push(device);
    } finally {
      for (const device of devices) if (!this.devices.includes(device)) (device as NostrSigner & { close?: () => void }).close?.();
    }
    const pubkeys = await Promise.all(this.devices.map(async d => hex32<Pubkey>(await d.getPublicKey()))); this.check();
    this.deviceSummary = { ...this.deviceSummary, retainedKeyCount: pubkeys.length, retained: pubkeys.slice(0, -1),
      current: pubkeys.length ? { pubkey: last(pubkeys), announced: last(pubkeys) === this.deviceSummary.announcedPubkey } : null };
    this.emit();
    if (this.devices.length > previousCount) {
      // A relay checkpoint proves completeness only for the old recipient set.
      const row = (await this.store!.read('accounts', []))!; this.check();
      const value = { ...row.value, config: { ...row.value.config, inboxWatermarks: {} } };
      await this.store!.put('accounts', [], value, row.revision); this.check(); this.account = value;
    }
    this.closeInbox(); await this.startInbox(); this.check();
    void this.refreshInbox().catch(() => {});
  }
  // End NIP-4E settings controller.

  private members(v: RuntimeVault) {
    const p = this.policy(v);
    return [{ pubkey: v.value.owner, role: 'owner' as const, informational: false },
      ...(p?.writers ?? []).filter(k => k !== v.value.owner).map(pubkey => ({ pubkey, role: 'writer' as const, informational: false })),
      ...(p?.readers ?? []).filter(k => k !== v.value.owner && !p?.writers.includes(k)).map(pubkey => ({ pubkey, role: 'reader' as const, informational: true }))];
  }
  private deliveries(v: RuntimeVault): readonly VaultDeliverySummary[] {
    const p = this.policy(v), latest = new Map<Pubkey, StoredVault['deliveryLedger'][number]>();
    for (const d of v.value.deliveryLedger) {
      if (p && d.recipient !== p.owner && !p.writers.includes(d.recipient) && !p.readers.includes(d.recipient)) continue;
      if (BigInt(d.issuedAt ?? '0') >= BigInt(latest.get(d.recipient)?.issuedAt ?? '0')) latest.set(d.recipient, d);
    }
    const summaries: VaultDeliverySummary[] = [...latest.values()].map(d => {
      const outcomes = d.relayOutcomes ?? [...d.acknowledged.map(relay => ({ relay, status: 'accepted' as const })), ...d.pending.map(relay => ({ relay, status: 'unknown' as const }))];
      return { recipient: d.recipient, envelopeKey: d.envelopeKey, cap: d.cap ?? (this.policy(v)?.writers.includes(d.recipient) ? 'write' as const : 'read' as const),
        state: !d.pending.length ? 'acknowledged' as const : outcomes.length && outcomes.every(o => o.status === 'rejected') ? 'failed' as const : 'pending' as const,
        acknowledged: [...d.acknowledged], pending: [...d.pending], relayOutcomes: structuredClone(outcomes),
        ...(d.notice ? { notice: d.notice } : {}), ...(d.evidence ? { evidence: d.evidence } : {}) };
    });
    for (const intent of this.deliveryIntents.get(v.value.vaultId) ?? []) {
      const d = latest.get(intent.recipient);
      if (d && (d.rumorId === intent.rumorId || BigInt(d.issuedAt ?? '0') >= intent.issuedAt)) continue;
      const index = summaries.findIndex(d => d.recipient === intent.recipient); if (index >= 0) summaries.splice(index, 1);
      summaries.push({ recipient: intent.recipient, cap: intent.cap, envelopeKey: null, state: 'pending', acknowledged: [], pending: [...v.value.network.writeRelays], relayOutcomes: v.value.network.writeRelays.map(relay => ({ relay, status: 'unknown' })) });
    }
    return summaries;
  }
  private conflicts(v: RuntimeVault): readonly VaultConflictSummary[] {
    return (this.conflictRows.get(v.value.vaultId) ?? []).map(row => {
      const c = row.conflict, record = v.records.get(c.otherRecordId as unknown as EventId), tree = record && v.trees.get(record.eventId);
      const indexed = record?.paths.find(p => p.pathEnc === c.pathEnc);
      const known = tree && indexed ? [...pathsOf(tree)].find(([, item]) => item.node.nodeId === indexed.nodeId && item.entry === item.node.entries[indexed.entryIndex]) : undefined;
      const displayPath = row.displayPath ?? known?.[0], entry = known?.[1].entry;
      return { conflictId: row.conflictId, pathEnc: c.pathEnc, path: displayPath ?? c.pathEnc, ...(displayPath ? { displayPath } : {}),
        kind: row.kind ?? (entry?.kind === 'directory' ? 'directory' : !c.inOther ? 'deletion-only' : 'file'), inView: c.inView, inOther: c.inOther,
        writer: c.writer, seq: BigInt(c.seq), alternatePath: row.artifactRefs[0] ?? null, hashedStorage: displayPath === undefined };
    });
  }
  private regrantHeadroom(v: RuntimeVault): number {
    if (!v.value.grant || v.value.owner !== this.session?.accountPubkey) return NIP59_MAX_PLAINTEXT;
    try {
      const grant = hydrateGrant(v.value.grant);
      let sample: Uint8Array, n = 0;
      do { sample = hexToBytes(hashAddress(encodeUtf8(`headroom:${n++}`))); } while (grant.ring.entries.some(e => bytesToHex(e.nodeKey) === bytesToHex(sample)));
      const ring = appendRing(grant.ring, sample);
      const sizes = grantWrapPlaintextSizes({ ...grant, cap: 'write', ring, issuedAt: BigInt(this.now()) }, this.now());
      return NIP59_MAX_PLAINTEXT - Math.max(sizes.rumorBytes, sizes.sealBytes);
    } catch { return 0; }
  }
  private policy(v: RuntimeVault) { return v.records.get(v.value.ownerCheckpointId!)?.root.vault; }
  private remainingBytes(v: RuntimeVault, tree = v.trees.get(v.value.ownerCheckpointId!)): bigint {
    if (!tree) return 0n;
    return treeResealItems(tree).reduce((n, i) => { const e = i.node.entries[i.entry]; return n + (e.kind === 'file' && e.chunks[i.chunk].chunkKeyId !== i.node.epoch ? resealCost(e.chunks[i.chunk]) : 0n); }, 0n);
  }
  subscribe(listener: (snapshot: VaultEngineSnapshot) => void): () => void { this.listeners.add(listener); listener(this.snapshot); return () => { this.listeners.delete(listener); }; }
  private fail(error: unknown, operation: VaultOperation, v?: RuntimeVault): VaultError {
    const e = error instanceof VaultError ? error : new VaultError('IO', { operation });
    if (v) v.error = e;
    // A refused creation override or pinned service is not an account failure.
    // The caller gets the error; endpoint diagnostics and per-vault errors remain.
    if (['AUTH', 'UNSUPPORTED'].includes(e.code) && e.operation && ['validate', 'fetch', 'subscribe', 'upload'].includes(e.operation) && ['starting', 'running'].includes(this.snapshot.lifecycle) && this.session &&
        Object.entries(this.session.networkDefaults).every(([key, urls]) => urls.some((url: string) => this.endpointUsable(key.includes('Relays') ? 'relay' : 'blossom', url)))) {
      this.emit(); return e;
    }
    if (e.code !== 'CANCELLED') this.emit({ condition: ['POLICY', 'CONFLICT', 'UNSUPPORTED'].includes(e.code) ? 'blocked' : e.code === 'EPOCH' ? 'needs-key' : e.code === 'NETWORK' ? 'offline' : 'error', lastError: e.toDisplay() });
    return e;
  }
  private lane<T>(key: string, operation: VaultOperation, work: () => Promise<T>): Promise<T> {
    const generation = this.generation;
    if (this.snapshot.lifecycle !== 'running') return Promise.reject(new VaultError('CANCELLED'));
    const previous = this.lanes.get(key) ?? Promise.resolve();
    const task = previous.catch(() => {}).then(async () => { this.check(generation); try { return await work(); } catch (e) { throw this.fail(e, operation, this.vaults.get(key as VaultId)); } finally { if (generation === this.generation) {
      const id = key as VaultId; this.store?.setPins(`materialize:${id}`, []); this.viewPins.delete(id);
      this.emit({ activity: 'idle' });
    } } });
    this.lanes.set(key, task); void task.finally(() => { if (this.lanes.get(key) === task) this.lanes.delete(key); }).catch(() => {});
    return task;
  }
  start(session: VaultSession, deps?: VaultEngineDeps): Promise<void> {
    if (this.stopTask) return this.stopTask.then(() => this.start(session, deps));
    if (this.startTask || this.snapshot.lifecycle === 'running') {
      if (this.session?.accountPubkey !== session.accountPubkey || this.session.notebookPath !== session.notebookPath) {
        const error = new VaultError('CONFLICT', { operation: 'start' }); error.message = 'Stop the current shared-vault session before changing identity or notebook.';
        return Promise.reject(this.fail(error, 'start'));
      }
      return this.startTask ?? Promise.resolve();
    }
    this.startTask = this.startSession(session, deps).finally(() => { this.startTask = undefined; });
    return this.startTask;
  }
  private async startSession(session: VaultSession, deps?: VaultEngineDeps): Promise<void> {
    this.deps = { ...this.deps, ...deps }; this.session = session; this.abort = new AbortController(); const generation = ++this.generation;
    this.endpointStates.clear();
    this.emit({ lifecycle: 'starting', condition: 'ready', lastError: null });
    try {
      if (!session.notebookPath) { const error = new VaultError('ARG', { operation: 'start' }); error.message = 'Open a notebook to start shared vaults.'; throw error; }
      if (await session.signer.getPublicKey() !== session.accountPubkey) { const error = new VaultError('AUTH', { operation: 'start' }); error.message = 'The signer does not match the signed-in identity. Sign in again.'; throw error; }
      this.check(generation); this.session = { ...session, networkDefaults: validateNetwork(session.networkDefaults) };
      const locks = this.deps.lockProvider ?? globalThis.navigator?.locks;
      if (!locks) { const error = new VaultError('UNSUPPORTED', { operation: 'start' }); error.message = 'Web Locks are unavailable in this webview. Update the system WebKit/browser and retry.'; throw error; }
      this.emit({ lastError: { code: 'CONFLICT', operation: 'start', retryable: true, message: 'Waiting for the shared-vault Web Lock.' } });
      let held!: () => void, refused!: (e: unknown) => void;
      const acquired = new Promise<void>((resolve, reject) => { held = resolve; refused = reject; });
      this.lockTask = locks.request(`onyx-vault-engine:${session.accountPubkey}`, { ifAvailable: true, mode: 'exclusive' }, async lock => {
        if (!lock || generation !== this.generation || this.abort.signal.aborted) {
          const error = new VaultError(!lock ? 'CONFLICT' : 'CANCELLED', { operation: 'start' });
          if (!lock) error.message = 'Vault engine active in another window';
          refused(error); return;
        }
        await new Promise<void>(resolve => { this.releaseLock = resolve; held(); });
      });
      void this.lockTask.catch(refused);
      let lockTimer: ReturnType<typeof setTimeout> | undefined;
      const cancelLock = () => refused(new VaultError('CANCELLED', { operation: 'start' }));
      this.abort.signal.addEventListener('abort', cancelLock, { once: true });
      try {
        await Promise.race([acquired, new Promise<never>((_, reject) => {
          lockTimer = setTimeout(() => { const error = new VaultError('CONFLICT', { operation: 'start', retryable: true }); error.message = 'Timed out waiting for the shared-vault Web Lock. Close other Onyx windows and retry.'; reject(error); }, 5000);
        })]);
      } catch (error) {
        // A broken webview may never settle request(). Do not hang cleanup;
        // a late callback is refused by the generation/abort guard above.
        this.lockTask = undefined;
        throw error;
      } finally { clearTimeout(lockTimer); this.abort.signal.removeEventListener('abort', cancelLock); }
      this.check(generation); this.emit({ lastError: null });
      this.store = new VaultStore({ accountPubkey: session.accountPubkey, secrets: session.secrets, idbFactory: this.deps.idbFactory?.() });
      const state = await this.store.start(); this.check(generation);
      if (state.condition === 'needs-key') {
        this.invalidate(); await this.clearSession();
        this.emit({ condition: 'needs-key', lifecycle: 'stopped', lastError: {
          code: 'EPOCH', operation: 'start', retryable: true,
          message: 'Unlock the secret store, then call start() again to resume shared vaults.',
        } }); return;
      }
      const networkProbe = this.probeNetwork(this.session!.networkDefaults); void networkProbe.catch(() => {});
      this.account = (await this.store.read('accounts', []))!.value;
      this.worker = new VaultWorkerClient(this.deps.workerFactory);
      this.devices = await loadDeviceSigners(this.store);
      const retained = await Promise.all(this.devices.map(async d => hex32<Pubkey>(await d.getPublicKey())));
      const config = this.account.config.deviceKeys as { enabled?: boolean; allowIdentityFallback?: boolean; lastAnnouncement?: VaultDeviceAnnouncementOutcome } | undefined;
      const announcementTask = retained.length ? this.events(this.session!.networkDefaults.readRelays, [{ kinds: [NIP4E_ANNOUNCEMENT_KIND], authors: [session.accountPubkey] }]).then(events => latestDeviceAnnouncement(events, session.accountPubkey)) : Promise.resolve(null);
      void announcementTask.catch(() => {});
      const localAnnouncement = null;
      this.deviceSummary = { enabled: config?.enabled === true, allowIdentityFallback: config?.allowIdentityFallback === true, announcedPubkey: localAnnouncement,
        lastAnnouncement: config?.lastAnnouncement ?? null, retainedKeyCount: retained.length, current: retained.length ? { pubkey: last(retained), announced: last(retained) === localAnnouncement } : null, retained: retained.slice(0, -1),
        recipients: recipientStates(this.account) };
      // SEC-G: a stored vault is either loaded or listed as unavailable with its
      // reason. Nothing on this path may abort start() and hide every vault.
      const vaultRows = await this.store.listTolerant('vaults'); this.check(generation);
      for (const row of vaultRows.rows) if (sameNotebook(row.value.mount.notebookPath, session.notebookPath)) this.vaults.set(row.value.vaultId, this.runtimeVault(row.value));
      for (const failed of vaultRows.failed) this.unavailableVaults.set(failed.key[0], failed.error.toDisplay());
      const invitationRows = await this.store.listTolerant('invitations'); this.check(generation);
      for (const row of invitationRows.rows) this.invitations.set(row.value.rumorId, row.value);
      this.unreadableInvitations = invitationRows.failed.length;
      await this.restoreInboxReplay(this.account.config.inboxSeen, this.account.config.inboxRejected); this.check(generation);
      for (const row of invitationRows.rows) if (row.value.grant.owner === session.accountPubkey) {
        try { await this.rememberSelfGrant(row.value); }
        catch (error) { if (cancelled(error)) throw error; this.fail(error, 'accept', this.vaults.get(row.value.vaultId)); }
      }
      const legacy = [...this.vaults.values()].filter(v => v.value.confirmedObjects === undefined);
      if (legacy.length) {
        const operations = await this.store.list('operations').catch(error => { if (cancelled(error)) throw error; return []; });
        for (const v of legacy) {
          const confirmedObjects: Record<string, readonly string[]> = {};
          for (const row of operations) if (row.value.vaultId === v.value.vaultId) includeUploadConfirmations(confirmedObjects, row.value.uploadOutcomes);
          try { await this.settings(v, { confirmedObjects }); }
          catch (error) { if (cancelled(error)) throw error; this.fail(error, 'recover', v); }
        }
      }
      this.emit();
      for (const v of this.vaults.values()) this.subscribeVault(v);
      const inboxTask = this.startInbox(); void inboxTask.catch(() => {});
      await Promise.all([...this.vaults.values()].map(async v => {
        if (!v.value.enabled || v.value.attachedAt === null) return;
        // Any per-vault failure marks that vault (lastError) and leaves it listed.
        try {
        try { await this.loadRecords(v); }
        catch (error) {
          if (cancelled(error)) throw error;
          for (const op of this.store!.recoveryOperations.filter(op => op.vaultId === v.value.vaultId)) await this.store!.markNeedsRecovery(op.vaultId, op.operationId);
          this.fail(error, 'recover', v); return;
        }
        await this.settings(v, { retainedRoots: retainRootEvidence(v.value.retainedRoots, [...v.records.values()].map(r => r.head)) });
        await cleanStagingOrphans(this.materializeContext(), v.value, this.store!.recoveryOperations);
        const operations = (await this.store!.pendingOperations()).filter(op => op.vaultId === v.value.vaultId);
        // Recover the linked candidate first, then every remaining journal. Never
        // replace a still-pending candidate just to recover an unlinked journal.
        operations.sort((a, b) => Number(b.operationId === v.value.pendingCandidateId) - Number(a.operationId === v.value.pendingCandidateId));
        if (v.value.pendingCandidateId && !operations.some(op => op.operationId === v.value.pendingCandidateId)) throw new VaultError('STORAGE');
        for (const op of operations) {
          try {
            if (v.value.pendingCandidateId && v.value.pendingCandidateId !== op.operationId) throw new VaultError('CONFLICT');
            if (op.kind === 'materialize' && !op.candidate.attachOnly) await resumeMaterialization(this.materializeContext(), op);
            else await this.resumePublication(v, op);
          } catch (e) {
            await this.store!.markNeedsRecovery(op.vaultId, op.operationId);
            this.fail(e, 'recover', v);
          }
          await this.reload(v);
        }
        } catch (error) { if (cancelled(error)) throw error; this.fail(error, 'recover', v); }
      }));
      this.check(generation);
      this.coalescer = new CaptureCoalescer(async () => {
        const ids = [...this.dirtyVaults]; this.dirtyVaults.clear();
        await Promise.all(ids.map(id => this.lane(id, 'capture', () => this.captureLocal(this.requireVault(id))).catch(() => {})));
      });
      // The grant inbox is account-level; its failure is a notice, not a start failure.
      await inboxTask.catch(error => { if (cancelled(error)) throw error; this.fail(error, 'accept'); });
      this.session = { ...this.session!, networkDefaults: await networkProbe };
      const announcement = await announcementTask;
      const announced = announcement?.tags.find(t => t[0] === 'n')?.[1] as Pubkey | undefined;
      const currentAnnouncement = announced && retained.includes(announced) ? announced : null;
      this.deviceSummary = { ...this.deviceSummary, announcedPubkey: currentAnnouncement, current: this.deviceSummary.current ? { ...this.deviceSummary.current, announced: this.deviceSummary.current.pubkey === currentAnnouncement } : null };
      for (const row of (await this.store.listTolerant('operations')).rows) {
        const v = this.vaults.get(row.value.vaultId);
        if (v?.value.enabled && v.value.attachedAt !== null && row.value.stage === 'committed') {
          try { await this.finishResolution(v, row.value); }
          catch (error) { if (cancelled(error)) throw error; this.fail(error, 'resolve', v); }
        }
      }
      await this.refreshCounts(); this.check(generation);
      for (const id of this.viewPins.keys()) this.store.setPins(`materialize:${id}`, []); this.viewPins.clear();
      this.emit({ lifecycle: 'running' });
      for (const run of this.startupLate.splice(0)) run();
      const inbox = [...this.startupInbox.values()]; this.startupInbox.clear();
      await Promise.all(inbox.map(event => this.runQueuedWrap(event).catch(() => {})));
      this.check(generation);
      for (const v of this.vaults.values()) { this.subscribeVault(v); this.queueRemote(v); }
      for (const v of this.vaults.values()) if (v.value.enabled && v.value.attachedAt !== null) void this.lane(v.value.vaultId, 'recover', async () => {
        for (const row of await this.store!.list('operations')) if (row.value.vaultId === v.value.vaultId && row.value.stage === 'committed') {
          await this.finishResolution(v, row.value); await this.finishDeliveries(v, row.value);
        }
      }).catch(() => {});
      void this.refreshInbox().catch(() => {});
    } catch (error) {
      this.invalidate(); await Promise.allSettled([...this.lanes.values()]); await this.clearSession();
      this.fail(error, 'start'); this.emit({ lifecycle: 'stopped', activity: 'idle' }); throw error;
    }
  }
  stop(): Promise<void> {
    if (this.stopTask) return this.stopTask;
    this.stopTask = this.stopSession().finally(() => { this.stopTask = undefined; }); return this.stopTask;
  }
  private async stopSession(): Promise<void> {
    if (!this.session && this.snapshot.lifecycle === 'stopped') { this.endpointStates.clear(); this.emit({ condition: 'ready', lastError: null }); return; }
    this.emit({ lifecycle: 'stopping' }); this.invalidate();
    if (this.startTask) await this.startTask.catch(() => {});
    await Promise.allSettled([...this.lanes.values()]);
    await this.clearSession(); this.endpointStates.clear();
    this.emit({ lifecycle: 'stopped', activity: 'idle', condition: 'ready', lastError: null });
  }
  private invalidate(): void {
    ++this.generation; this.abort.abort(); this.coalescer?.stop(); this.closeInbox(); this.startupInbox.clear(); this.startupLate.length = 0;
    for (const v of this.vaults.values()) { v.subscription?.close(); v.publisherSub?.close(); v.ledgerSub?.close(); }
    for (const relay of this.relays.values()) relay.stop(); for (const blossom of this.blossoms.values()) blossom.stop(); this.worker?.dispose();
  }
  private async clearSession(): Promise<void> {
    for (const v of this.vaults.values()) for (const t of v.trees.values()) wipeTree(t);
    for (const device of this.devices) (device as NostrSigner & { close?: () => void }).close?.();
    this.devices = []; this.store?.stop(); this.releaseLock?.(); await this.lockTask?.catch(() => {});
    this.releaseLock = undefined; this.lockTask = undefined; this.session = undefined; this.worker = undefined; this.store = undefined; this.account = undefined;
    this.relays.clear(); this.blossoms.clear(); this.vaults.clear(); this.invitations.clear(); this.conflictCounts.clear(); this.conflictRows.clear(); this.deliveryIntents.clear(); this.echoes.clear(); this.capturePins.clear(); this.viewPins.clear();
    this.deviceSummary = { enabled: false, allowIdentityFallback: false, announcedPubkey: null, retainedKeyCount: 0, current: null, retained: [], lastAnnouncement: null, recipients: [] };
    this.accountChain = Promise.resolve();
    this.cpu = new Semaphore(1); this.network = new Semaphore(4); this.captureLane = Promise.resolve();
    this.queuedWraps.clear(); this.queuedWrapBytes = 0; this.inboxError = undefined; this.inboxAtCapacity = false; this.inboxAbort = new AbortController();
    this.rejectedWraps.clear(); this.unavailableVaults.clear(); this.unreadableInvitations = 0;
    this.dirtyVaults.clear(); this.seenWraps.clear(); this.openingWraps.clear(); this.recipientCache.clear(); this.recipientRoutes.clear(); this.recipientRecords.clear(); this.inboxEndpoints = []; this.inboxPubkeys = [];
  }
  private endpointUsable(kind: VaultEndpointStatus['kind'], url: string): boolean {
    const status = this.endpointStates.get(`${kind}:${url}`)?.status;
    return status === 'usable' || status === 'authenticated';
  }
  private endpointAuthenticated(kind: VaultEndpointStatus['kind'], url: string): void {
    if (this.excluded(kind, url)) return;
    this.endpointResult(kind, url);
    const previous = this.endpointStates.get(`${kind}:${url}`)!;
    this.endpointStates.set(`${kind}:${url}`, { ...previous, status: 'authenticated', message: 'Authenticated — available for shared vaults.' });
    this.emit();
  }
  private endpointResult(kind: VaultEndpointStatus['kind'], url: string, error?: unknown): void {
    // Auth refusal is sticky until session retry; concurrent EOSE/OK cannot undo it.
    if (this.excluded(kind, url)) return;
    // Missing/corrupt/oversized objects are operation failures, not service health.
    if (error instanceof VaultError && !['AUTH', 'UNSUPPORTED', 'NETWORK', 'IO'].includes(error.code)) return;
    const unsupported = error instanceof VaultError && error.code === 'UNSUPPORTED' || error instanceof BlossomError && [402, 403].includes(error.status);
    const previous = this.endpointStates.get(`${kind}:${url}`);
    const authenticated = previous?.status === 'authenticated';
    this.endpointStates.set(`${kind}:${url}`, { kind, url, ...(previous?.service ? { service: previous.service } : {}),
      status: error ? unsupported ? 'unsupported' : 'offline' : authenticated ? 'authenticated' : 'usable',
      message: error ? unsupported ? error instanceof BlossomError && error.status === 402
        ? 'Server requires payment/authorisation for this pubkey — ask the operator; not used for shared vaults.'
        : 'Not allowlisted — ask the operator; not used for shared vaults.'
        : error instanceof VaultError && error.code === 'AUTH' ? 'Authentication failed — check the signer or ask the operator.'
        : 'Could not be reached — not currently used for shared vaults.'
        : authenticated ? 'Authenticated — available for shared vaults.' : 'Available for shared vaults.' });
    const network = this.session?.networkDefaults;
    if (network && this.snapshot.lifecycle === 'running' && Object.entries(network).some(([key, urls]) => !urls.some((endpoint: string) => this.endpointUsable(key.includes('Relays') ? 'relay' : 'blossom', endpoint)))) {
      this.emit({ condition: 'blocked', lastError: this.networkUnavailable(network).toDisplay() });
    } else if (this.snapshot.condition === 'blocked' && this.snapshot.lastError?.operation === 'validate') this.emit({ condition: 'ready', lastError: null });
    else this.emit();
  }
  private excluded(kind: VaultEndpointStatus['kind'], url: string): boolean {
    return this.endpointStates.get(`${kind}:${url}`)?.status === 'unsupported';
  }
  private networkUnavailable(network: StoredNetwork): VaultError {
    const error = new VaultError('UNSUPPORTED', { operation: 'validate', retryable: true });
    const missing = (Object.keys(network) as (keyof StoredNetwork)[]).filter(key => !network[key].some(url => this.endpointUsable(key.includes('Relays') ? 'relay' : 'blossom', url)));
    const labels = { readRelays: 'read relay', writeRelays: 'write relay', readBlossom: 'read Blossom server', writeBlossom: 'write Blossom server' };
    error.message = `Shared vaults need usable read/write relays and Blossom servers. Unavailable: ${missing.map(key => labels[key]).join(', ')}. Check shared vault settings or replace these endpoints: ${[...new Set(missing.flatMap(key => network[key]))].join(', ')}.`;
    return error;
  }
  private async probeNetwork(config: StoredNetwork): Promise<StoredNetwork> {
    const network = validateNetwork(config);
    const probes = new Map<string, Promise<void>>(), finished = new Set<string>();
    for (const url of [...new Set([...network.readRelays, ...network.writeRelays])]) probes.set(`relay:${url}`, (async () => {
        if (this.excluded('relay', url)) return;
        try { await this.recipientRelays(this.session!.accountPubkey, [url]); this.check(); this.endpointResult('relay', url); }
        catch (error) { this.check(); this.endpointResult('relay', url, error); throw error; }
      })());
    for (const url of [...new Set([...network.readBlossom, ...network.writeBlossom])]) probes.set(`blossom:${url}`, this.network.run(this.abort.signal, async () => {
        if (this.excluded('blossom', url)) return;
        // HEAD is read-only; sign only if challenged. An authorised 404 is usable.
        try { await this.blossom(url).head('0'.repeat(64), this.abort.signal); this.check(); this.endpointResult('blossom', url); }
        catch (error) { this.check(); this.endpointResult('blossom', url, error); throw error; }
      }));
    for (const [key, task] of probes) void task.finally(() => finished.add(key)).catch(() => {});
    // A failed/slow replica cannot hold the healthy service categories hostage.
    const category = (kind: 'relay' | 'blossom', urls: readonly string[]) => firstSufficient(urls.map(url => probes.get(`${kind}:${url}`)!.then(() => {
      if (!this.endpointUsable(kind, url)) throw new VaultError('UNSUPPORTED');
    })));
    try { await Promise.all([category('relay', network.readRelays), category('relay', network.writeRelays), category('blossom', network.readBlossom), category('blossom', network.writeBlossom)]); }
    catch { this.check(); throw this.networkUnavailable(network); }
    this.check();
    const usable = (kind: VaultEndpointStatus['kind'], urls: readonly string[]) => urls.filter(url => !this.excluded(kind, url) && (!finished.has(`${kind}:${url}`) || this.endpointUsable(kind, url)));
    const selected = { readRelays: usable('relay', network.readRelays), writeRelays: usable('relay', network.writeRelays), readBlossom: usable('blossom', network.readBlossom), writeBlossom: usable('blossom', network.writeBlossom) };
    if (Object.values(selected).some(urls => !urls.length)) throw this.networkUnavailable(network);
    return selected;
  }
  private relay(endpoints: readonly string[]): RelayAdapter {
    endpoints = [...new Set(endpoints)].filter(url => !this.excluded('relay', url));
    if (!endpoints.length) throw new VaultError('UNSUPPORTED', { operation: 'subscribe' });
    if (endpoints.length > 1) return combineRelays(endpoints.map(endpoint => this.relay([endpoint])));
    const key = endpoints[0];
    let relay = this.relays.get(key);
    if (!relay) {
      const options = { signer: this.session!.signer, accountPubkey: this.session!.accountPubkey,
        onAuthenticated: (url: string) => this.endpointAuthenticated('relay', url),
        onPrivateVaultService: (url: string) => {
          const previous = this.endpointStates.get(`relay:${url}`) ?? { kind: 'relay' as const, url, status: 'offline' as const, message: 'Checking availability.' };
          this.endpointStates.set(`relay:${url}`, { ...previous, service: 'private vault service' });
          this.emit();
        } };
      relay = this.deps.relayFactory?.(endpoints, options) ?? new VaultRelay(endpoints, options);
      this.relays.set(key, relay);
    }
    return relay;
  }
  private blossom(endpoint: string): BlossomAdapter {
    let client = this.blossoms.get(endpoint);
    if (!client) {
      const options = { now: () => this.now(), signer: this.session!.signer, accountPubkey: this.session!.accountPubkey,
        onAuthenticated: () => this.endpointAuthenticated('blossom', endpoint) };
      client = this.deps.blossomFactory?.(endpoint, options) ?? new VaultBlossom(endpoint, options);
      this.blossoms.set(endpoint, client);
    }
    return client;
  }
  private async publishEvent(endpoints: readonly string[], event: Event, late?: (outcomes: readonly RelayPublishOutcome[]) => Promise<void>): Promise<RelayPublishResult> {
    const generation = this.generation;
    const report = (outcomes: readonly RelayPublishOutcome[]) => {
      if (generation !== this.generation || this.abort.signal.aborted) return;
      for (const outcome of outcomes) {
        if (outcome.status === 'accepted') this.endpointResult('relay', outcome.relay);
        else if (outcome.error || outcome.status === 'rejected' && /^restricted:/.test(outcome.reason)) this.endpointResult('relay', outcome.relay, outcome.error ?? new VaultError('UNSUPPORTED'));
      }
    };
    let result: RelayPublishResult;
    try { result = await this.relay(endpoints).publish(event); }
    catch (error) {
      this.check(generation);
      result = { event, durable: false, degraded: true, outcomes: endpoints.map(relay => ({ relay, status: 'unknown' as const, error: error instanceof VaultError ? error : new VaultError('NETWORK') })) };
    }
    this.check(generation);
    const skipped = endpoints.filter(url => this.excluded('relay', url) && !result.outcomes.some(outcome => outcome.relay === url)).map(relay => ({ relay, status: 'unknown' as const, error: new VaultError('UNSUPPORTED', { operation: 'publish' }) }));
    if (skipped.length) result = { ...result, outcomes: [...result.outcomes, ...skipped], degraded: true, ...(result.settled ? { settled: result.settled.then(outcomes => [...outcomes, ...skipped]) } : {}) };
    report(result.outcomes);
    if (result.settled) void result.settled.then(async outcomes => {
      if (generation !== this.generation || this.abort.signal.aborted) return;
      report(outcomes); await late?.(outcomes);
    }).catch(() => {});
    return result;
  }
  private async events(endpoints: readonly string[], filters: readonly Filter[], late?: (event: Event) => void, complete?: (endpoint: string, late: boolean) => void): Promise<Event[]> {
    const generation = this.generation, result = new Map<string, Event>();
    let returned = false;
    await this.relay(endpoints).backfill(filters, {
      onevent: event => {
        if (generation !== this.generation || this.abort.signal.aborted || result.has(event.id)) return;
        result.set(event.id, event); if (returned) late?.(event);
      },
      oneose: endpoint => { if (generation === this.generation && !this.abort.signal.aborted) { this.endpointResult('relay', endpoint); complete?.(endpoint, returned); } },
      onerror: (endpoint, error) => { if (generation === this.generation && !this.abort.signal.aborted) this.endpointResult('relay', endpoint, error); },
    }, this.abort.signal);
    this.check(generation); returned = true; return [...result.values()];
  }
  private lateInLane(v: RuntimeVault, work: () => Promise<void>): Promise<void> {
    const generation = this.generation;
    const run = () => { if (generation === this.generation && !this.abort.signal.aborted) void this.lane(v.value.vaultId, 'publish', work).catch(() => {}); };
    if (this.snapshot.lifecycle === 'starting') this.startupLate.push(run); else run();
    return Promise.resolve();
  }
  private async recordPublicationResult(v: RuntimeVault, operationId: string, outcomes: readonly RelayPublishOutcome[], ledger = false): Promise<void> {
    const statuses = Object.fromEntries(outcomes.map(outcome => [outcome.relay, outcome.status]));
    await this.store!.recordRelayOutcomes(v.value.vaultId, operationId, ledger ? { epochLedger: statuses } : statuses); this.check();
    if (v.error?.code === 'NETWORK' && v.error.operation === 'publish' && v.value.network.writeRelays.every(url => statuses[url] === 'accepted')) {
      const row = await this.store!.read('operations', [v.value.vaultId, operationId]); this.check();
      if (!row) return; // A late OK for a compacted journal carries no current-view authority.
      const op = row.value;
      const uploadsComplete = Object.values(op.uploadOutcomes).every(value => !value || typeof value !== 'object' || Array.isArray(value) || !('servers' in value) || !value.servers || typeof value.servers !== 'object' || Object.values(value.servers).every(status => status === 'accepted'));
      const head = op.candidate.head as unknown as Persisted<VaultHead>;
      const ledger = op.relayOutcomes.epochLedger;
      const headsComplete = v.value.network.writeRelays.every(url => op.relayOutcomes[url] === 'accepted');
      const ledgerComplete = !op.signedEpochLedgerEvent || ledger && typeof ledger === 'object' && !Array.isArray(ledger) && v.value.network.writeRelays.every(url => new Map(Object.entries(ledger)).get(url) === 'accepted');
      if (uploadsComplete && headsComplete && ledgerComplete && head?.seq === v.value.lastOwnSeq) v.error = null;
    }
    this.emit();
  }
  private async recordDeliveryResult(v: RuntimeVault, recipient: Pubkey, rumorId: EventId, outcomes: readonly RelayPublishOutcome[]): Promise<void> {
    const entry = v.value.deliveryLedger.find(d => d.recipient === recipient && d.rumorId === rumorId);
    if (!entry) return;
    const acknowledged = [...new Set([...entry.acknowledged, ...outcomes.filter(o => o.status === 'accepted').map(o => o.relay)])];
    const receipts = new Map(entry.relayOutcomes?.map(o => [o.relay, o]));
    for (const o of outcomes) if (receipts.get(o.relay)?.status !== 'accepted') receipts.set(o.relay, { relay: o.relay, status: o.status, ...('reason' in o ? { reason: o.reason } : {}) });
    await this.settings(v, { deliveryLedger: v.value.deliveryLedger.map(d => d.recipient === recipient && d.rumorId === rumorId ? { ...d, acknowledged, pending: d.pending.filter(url => !acknowledged.includes(url)), relayOutcomes: [...receipts.values()] } : d) });
    await this.refreshCounts(); this.emit();
  }
  private async cacheBlob(address: Address, bytes: Uint8Array): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      this.check();
      try { await this.store!.cacheObject(address, bytes); this.check(); return; }
      catch (error) { if (!(error instanceof VaultError) || error.code !== 'CONFLICT' || attempt >= 7) throw error; }
    }
  }
  private async flushReadConfirmations(v: RuntimeVault): Promise<void> {
    if (!v.readConfirmations?.size) return;
    const confirmedObjects = { ...v.value.confirmedObjects };
    for (const [address, urls] of v.readConfirmations) confirmedObjects[address] = [...new Set([...(confirmedObjects[address] ?? []), ...urls])];
    await this.settings(v, { confirmedObjects }); v.readConfirmations.clear();
  }
  private async readBlob(v: RuntimeVault, address: Address): Promise<Uint8Array> {
    this.check(); let cached: Uint8Array | null = null;
    try { cached = await this.store!.cachedObject(address); }
    catch (error) {
      const quarantined = error instanceof VaultError && error.code === 'HASH_MISMATCH' || error instanceof VaultError && error.code === 'STORAGE' && this.store!.state.condition === 'ready' && (await this.store!.quarantinedRecords()).some(row => row.store === 'objects' && row.key[0] === address);
      if (!quarantined) throw error;
      if (!v.value.objectWarnings?.some(w => w.address === address)) await this.settings(v, { objectWarnings: [...(v.value.objectWarnings ?? []), { address, code: 'HASH_MISMATCH' }] });
    }
    this.check(); if (cached) return cached;
    let failure: unknown = new VaultError('INCOMPLETE');
    if (v.value.network.readBlossom.every(url => this.excluded('blossom', url))) {
      const error = new VaultError('UNSUPPORTED', { operation: 'fetch', retryable: true });
      error.message = `No usable Blossom server remains for this vault: ${v.value.network.readBlossom.join(', ')}. Edit its endpoints or retry.`; throw error;
    }
    for (const endpoint of v.value.network.readBlossom) {
      if (this.excluded('blossom', endpoint)) continue;
      try { const bytes = await this.network.run(this.abort.signal, () => this.blossom(endpoint).get(address, undefined, this.abort.signal)); this.check(); verifyAddress(bytes, address); await this.cacheBlob(address, bytes); this.check();
        // A necessary, hash-verified download also proves this exact server has
        // the object. Seed write confirmations without any extra GET or HEAD.
        if (v.value.network.writeBlossom.includes(endpoint) && !v.value.confirmedObjects?.[address]?.includes(endpoint)) {
          const confirmations = v.readConfirmations ??= new Map<Address, Set<string>>();
          const urls = confirmations.get(address) ?? new Set<string>(); urls.add(endpoint); confirmations.set(address, urls);
        }
        return bytes; }
      catch (error) { this.check(); this.endpointResult('blossom', endpoint, error); failure = this.excluded('blossom', endpoint) ? new VaultError('UNSUPPORTED', { operation: 'fetch' }) : error; }
    }
    throw failure;
  }
  private async putBlob(v: RuntimeVault, address: Address, read: () => Promise<Uint8Array>, expectedSize?: number): Promise<{ outcomes: Record<string, StorageJson>; durable: boolean; refusal?: VaultError }> {
    let shared = false; const outcomes: Record<string, StorageJson> = {}; let refusal: VaultError | undefined;
    const hinted = v.value.grant?.hints.blossom ?? v.value.network.writeBlossom;
    let bytes: Uint8Array | undefined;
    for (const endpoint of v.value.network.writeBlossom) {
      if (v.value.confirmedObjects?.[address]?.includes(endpoint)) {
        outcomes[endpoint] = 'accepted'; if (hinted.some(h => validatePublicEndpoint(h, 'https:') === endpoint)) shared = true; continue;
      }
      if (this.excluded('blossom', endpoint)) {
        outcomes[endpoint] = 'UNSUPPORTED'; refusal = new VaultError('UNSUPPORTED', { operation: 'upload', retryable: true });
        refusal.message = `Blossom server ${endpoint}: ${this.endpointStates.get(`blossom:${endpoint}`)?.message} Edit this vault's endpoints or retry.`; continue;
      }
      try {
        const client = this.blossom(endpoint);
        const state = await this.network.run(this.abort.signal, () => client.head(address, this.abort.signal)); this.check();
        if (state.exists) {
          if (expectedSize !== undefined && state.size !== undefined && state.size !== expectedSize) throw new VaultError('HASH_MISMATCH');
        } else {
          bytes ??= await read(); this.check();
          await this.network.run(this.abort.signal, () => client.put(bytes!, address, this.session!.signer, this.abort.signal));
        }
        this.check(); this.endpointResult('blossom', endpoint); outcomes[endpoint] = 'accepted'; if (hinted.some(h => validatePublicEndpoint(h, 'https:') === validatePublicEndpoint(endpoint, 'https:'))) shared = true;
      } catch (error) { this.check(); this.endpointResult('blossom', endpoint, error); outcomes[endpoint] = this.excluded('blossom', endpoint) ? 'UNSUPPORTED' : error instanceof VaultError ? error.code : 'unknown'; if (error instanceof VaultError && ['AUTH', 'TOO_LARGE', 'UNSUPPORTED'].includes(error.code)) refusal = this.excluded('blossom', endpoint) ? new VaultError('UNSUPPORTED', { operation: 'upload' }) : error; }
    }
    return { outcomes, durable: shared, ...(refusal ? { refusal } : {}) };
  }
  private runtimeVault(value: StoredVault): RuntimeVault {
    // Persisted designation bodies live in authenticated encrypted account state.
    // A known id need not ask a remote signer to decrypt the same record again.
    return { value, records: new Map(), trees: new Map(), provisionalPaths: [], provisionalOtherPaths: [], provisionalCount: 0,
      ownUnfolded: new Set(), otherUnfolded: new Set(), error: null,
      publisherVerifiedId: value.publisher && !value.publisherPending ? value.publisherEvent?.id : undefined };
  }
  private requireVault(id: VaultId): RuntimeVault { this.check(); const v = this.vaults.get(id); if (!v) throw new VaultError('ARG'); return v; }
  private async reload(v: RuntimeVault): Promise<void> { this.check(); const row = await this.store!.read('vaults', [v.value.vaultId]); this.check(); if (!row) throw new VaultError('STORAGE'); v.value = row.value; }
  private async settings(v: RuntimeVault, change: Partial<StoredVault>): Promise<void> {
    const row = await this.store!.read('vaults', [v.value.vaultId]); this.check();
    if (!row) throw new VaultError('STORAGE'); const value = { ...row.value, ...change };
    await this.store!.updateVault(value, row.revision); this.check(); v.value = value; this.emit();
  }
  private mounts(): VaultMount[] { return [...this.vaults.values()].filter(v => v.value.attachedAt !== null).map(v => ({ vaultId: v.value.vaultId, ...v.value.mount })); }
  private materializeContext(vaultId?: VaultId): MaterializeContext {
    const generation = this.generation, pins = this.viewPins;
    return { get pinnedAddresses() { return vaultId ? pins.get(vaultId) ?? [] : []; }, fs: this.session!.fs, store: this.store!, barrier: this.session!.editorBarrier, echoes: this.echoes, signal: this.abort.signal, check: () => this.check(generation), operationId: () => this.id(), hash: bytes => this.hashBytes(bytes), localWriter: this.session!.accountPubkey };
  }
  private async refreshCounts(): Promise<void> {
    const counts = new Map<VaultId, number>();
    const rows = new Map<VaultId, StoredConflict[]>();
    for (const row of await this.store!.list('conflicts')) if (row.value.resolution === 'unresolved') {
      counts.set(row.value.vaultId, (counts.get(row.value.vaultId) ?? 0) + 1);
      rows.set(row.value.vaultId, [...(rows.get(row.value.vaultId) ?? []), row.value]);
    }
    const intents = new Map<VaultId, { recipient: Pubkey; cap: VaultCapability; rumorId: EventId; issuedAt: bigint }[]>();
    for (const row of await this.store!.list('operations')) {
      const op = row.value, v = this.vaults.get(op.vaultId);
      if (!v || op.stage !== 'committed' || op.uploadOutcomes.localOnly || !op.candidate.deliveries || !op.candidate.grant) continue;
      const grant = hydrateGrant(op.candidate.grant as unknown as Persisted<VaultGrant>), policy = this.policy(v);
      if (last(grant.ring.entries).epoch < last(this.rootRing(v).entries).epoch) continue;
      for (const d of op.candidate.deliveries as unknown as { recipient: Pubkey; cap: VaultCapability }[]) {
        if (policy && d.recipient !== policy.owner && !policy.writers.includes(d.recipient) && !policy.readers.includes(d.recipient)) continue;
        const entries = intents.get(op.vaultId) ?? [], previous = entries.find(i => i.recipient === d.recipient);
        if (previous && previous.issuedAt >= grant.issuedAt) continue;
        const intent = { ...d, issuedAt: grant.issuedAt, rumorId: buildGrantRumor({ ...grant, cap: d.cap }).id as EventId };
        intents.set(op.vaultId, [...entries.filter(i => i.recipient !== d.recipient), intent]);
      }
    }
    this.check(); this.conflictCounts = counts; this.conflictRows = rows; this.deliveryIntents = intents;
  }
  async updateNetworkDefaults(config: StoredNetwork): Promise<void> { this.check(); this.recipientCache.clear(); this.session = { ...this.session!, networkDefaults: await this.probeNetwork(config) }; this.emit({ condition: 'ready', lastError: null }); }
  private async readEpochLedger(v: RuntimeVault, observed?: readonly Event[]): Promise<void> {
    const events = observed ?? await this.events(v.value.network.readRelays, [{ kinds: [PORTHOME_HEAD_KIND], authors: [v.value.owner], '#d': [historyDTag(v.value.vaultId)] }], event => this.observeAuxiliary(v, 'ledger', event));
    const ring = this.rootRing(v), newest = last(ring.entries).epoch, cached = v.value.epochLedgerEvent;
    const declared = (e: Event): bigint | null => {
      const tags = Array.isArray(e.tags) ? e.tags.filter(t => Array.isArray(t) && t[0] === 'epoch') : [];
      const value = tags.length === 1 && typeof tags[0][1] === 'string' ? tags[0][1] : '';
      return /^[1-9][0-9]*$/.test(value) && value.length <= 20 ? BigInt(value) : null;
    };
    // SV-36: the durable epoch high-water, not relay ordering, bounds selection from
    // below; cached signed evidence keeps an older relay response from rolling back.
    const floor = [BigInt(v.value.ledgerHighWater?.epoch ?? '0'), cached ? declared(cached) ?? 0n : 0n].reduce((a, b) => a > b ? a : b);
    const candidates = [...events, ...(cached ? [cached] : [])].flatMap(e => { const epoch = declared(e); return epoch === null || epoch < floor ? [] : [{ e, epoch }]; });
    // A declared epoch beyond the held ring is unreadable evidence of a later
    // rotation, never current history. Among readable ledgers the newest declared
    // epoch wins; timestamps only order equal epochs.
    const readable = candidates.filter(c => c.epoch <= newest).sort((a, b) => a.epoch > b.epoch ? -1 : a.epoch < b.epoch ? 1 : b.e.created_at - a.e.created_at || (a.e.id < b.e.id ? -1 : 1));
    if (!readable.length) { v.history = cached || candidates.length || floor > 0n ? 'incomplete' : 'unavailable'; return; } // Non-Onyx owners need not publish this private record.
    const { e: event, epoch } = readable[0];
    if (v.ledger?.eventId !== event.id) {
      let ledger: EpochLedger;
      try { ledger = openEpochLedgerEvent(event, v.value.vaultId, v.value.owner, ring); }
      catch (error) {
        // A signed ledger for an unavailable epoch is not yet readable. Leave
        // cached evidence/view intact and let head verification quarantine new
        // ciphertext as CRYPTO; observing it alone does not establish revocation.
        if (error instanceof VaultError && error.code === 'EPOCH' && !ring.entries.some(e => e.epoch === epoch)) { v.history = 'incomplete'; return; }
        throw error;
      }
      this.check(); v.ledger = { eventId: event.id, body: ledger };
      const evidence = ledger.epochs.map(e => ({ address: e.rootManifest, epoch: String(e.epoch) }));
      const retainedRoots = retainRootEvidence([...(v.value.retainedRoots ?? []), ...evidence]);
      const ledgerHighWater = { epoch: String(epoch), eventId: event.id as EventId };
      if (event.id !== cached?.id || JSON.stringify(retainedRoots) !== JSON.stringify(v.value.retainedRoots) || v.value.ledgerHighWater?.epoch !== ledgerHighWater.epoch)
        await this.settings(v, { epochLedgerEvent: event, retainedRoots, ledgerHighWater });
    }
    // A ledger behind the ring (including our own not-yet-published rotation
    // ledger) is incomplete history, not verified freshness.
    v.history = epoch === newest ? 'verified' : 'incomplete';
  }
  private proposedEpochLedger(v: RuntimeVault, heads: readonly VaultHead[]): EpochLedger {
    const previous = v.value.epochLedgerEvent ? v.ledger?.eventId === v.value.epochLedgerEvent.id ? v.ledger.body : openEpochLedgerEvent(v.value.epochLedgerEvent, v.value.vaultId, v.value.owner, this.rootRing(v)) : undefined;
    return ledgerWithHeads(v.value.vaultId, previous, [...v.records.values()].filter(r => r.writer === v.value.owner).map(r => r.head).concat(heads));
  }
  private async reconstructHistory(v: RuntimeVault, tree: VaultTree): Promise<VaultTree> {
    // Startup/manual backfill and the live ledger REQ maintain this evidence.
    await this.readEpochLedger(v, [...(v.ledgerEvents?.values() ?? [])]); v.ledgerEvents?.clear();
    try { return await reconstructHistoricalRings(tree, this.rootRing(v), v.value.retainedRoots, a => this.readBlob(v, a), () => this.check()); }
    catch (error) {
      if (error instanceof VaultError && error.code === 'EPOCH') {
        if (!v.value.epochLedgerEvent) throw new VaultError('EPOCH', { operation: 'recover', reason: 'history-unavailable' });
        // Fail closed as incomplete history, never as success, while the held ledger trails the ring.
        if (v.history !== 'verified') throw new VaultError('EPOCH', { operation: 'recover', reason: 'history-incomplete' });
      }
      throw error;
    }
  }
  private async readPublisher(v: RuntimeVault, events?: readonly Event[]): Promise<void> {
    if (v.value.owner !== this.session!.accountPubkey) return;
    const candidates = events ?? await this.events(v.value.network.readRelays, [{ kinds: [PORTHOME_HEAD_KIND], authors: [v.value.owner], '#d': [publisherD(v.value.vaultId)] }], event => this.observeAuxiliary(v, 'publisher', event));
    const unique = new Map([...candidates, ...(v.value.publisherEvent && !v.value.publisherPending ? [v.value.publisherEvent] : [])].map(e => [e.id, e]));
    const valid = [...unique.values()].filter(e => e.id === v.publisherVerifiedId || Number.isSafeInteger(e.created_at) && e.created_at >= 0 && e.pubkey === v.value.owner && e.kind === PORTHOME_HEAD_KIND && e.tags.length === 1 && e.tags[0].length === 2 && e.tags[0][0] === 'd' && e.tags[0][1] === publisherD(v.value.vaultId) && verifyEvent(JSON.parse(JSON.stringify(e))));
    // Include cached evidence so an older relay response cannot roll back handover.
    valid.sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1));
    if (!valid.length) throw new VaultError('INCOMPLETE', { operation: 'handover' });
    const event = valid[0];
    if (event.id === v.publisherVerifiedId) return;
    if (!this.session!.signer.nip44) throw new VaultError('UNSUPPORTED');
    const body: unknown = JSON.parse(await this.session!.signer.nip44.decrypt(v.value.owner, event.content)); this.check();
    if (!body || typeof body !== 'object') throw new VaultError('POLICY');
    const p = body as Record<string, unknown>;
    if (Object.keys(p).sort().join(',') !== 'device_id,device_label,since,v,vault_id' || p.v !== ONYX_VAULT_PUBLISHER_VERSION || p.vault_id !== v.value.vaultId || typeof p.device_id !== 'string' || !p.device_id || typeof p.device_label !== 'string' || typeof p.since !== 'number' || p.since !== event.created_at) throw new VaultError('POLICY');
    await this.settings(v, { publisher: { deviceId: p.device_id, deviceLabel: p.device_label, since: String(p.since) }, publisherEvent: event, publisherPending: false });
    v.publisherVerifiedId = event.id;
  }
  private async awaitAuthority(v: RuntimeVault): Promise<void> {
    this.subscribeVault(v);
    for (;;) {
      const fences = [v.headCatchup, v.ledgerCatchup, ...(v.value.owner === this.session!.accountPubkey ? [v.publisherCatchup] : [])];
      if (fences.some(fence => !fence)) throw new VaultError('NETWORK', { operation: 'publish' });
      await Promise.all(fences.map(fence => fence!.wait())); this.check();
      if (fences[0] === v.headCatchup && fences[1] === v.ledgerCatchup && fences.every(fence => fence!.sufficient)) break;
    }
    const ledger = [...(v.ledgerEvents?.values() ?? [])]; v.ledgerEvents?.clear();
    if (ledger.length) await this.readEpochLedger(v, ledger);
  }
  private async assertPublisher(v: RuntimeVault): Promise<void> {
    if (v.value.owner !== this.session!.accountPubkey) throw new VaultError('POLICY');
    await this.awaitAuthority(v);
    if (v.value.publisherPending && v.value.publisherEvent) {
      const result = await this.publishEvent(v.value.network.writeRelays, v.value.publisherEvent!); this.check();
      if (!result.durable) throw new VaultError('NETWORK', { operation: 'handover' });
      await this.settings(v, { publisherPending: false });
    }
    if (v.publisherEvents?.size) { const observed = [...v.publisherEvents.values()]; v.publisherEvents.clear(); await this.readPublisher(v, observed); }
    if (!v.publisherVerifiedId) await this.readPublisher(v, v.value.publisher && v.value.publisherEvent && !v.value.publisherPending ? [] : undefined);
    this.check();
    if (v.value.publisher?.deviceId !== this.account!.deviceId) throw new VaultError('POLICY', { operation: 'publish' });
  }
  private async designate(v: RuntimeVault): Promise<void> {
    if (v.value.owner !== this.session!.accountPubkey) throw new VaultError('POLICY');
    if (!this.session!.signer.nip44) throw new VaultError('UNSUPPORTED');
    const previous = await this.events(v.value.network.readRelays, [{ kinds: [PORTHOME_HEAD_KIND], authors: [v.value.owner], '#d': [publisherD(v.value.vaultId)] }]);
    if (previous.length) await this.readPublisher(v, previous);
    const now = Math.max(this.now(), Number(v.value.publisher?.since ?? '0') + 1);
    if (now > this.now() + 60) throw new VaultError('NETWORK', { operation: 'handover', retryable: true });
    const event = await this.session!.signer.signEvent({ kind: ONYX_VAULT_PUBLISHER_KIND, tags: [['d', publisherD(v.value.vaultId)]], created_at: now,
      content: await this.session!.signer.nip44.encrypt(v.value.owner, JSON.stringify({ v: ONYX_VAULT_PUBLISHER_VERSION, vault_id: v.value.vaultId,
        device_id: this.account!.deviceId, device_label: this.account!.deviceLabel, since: now })) });
    this.check();
    if (!verifyEvent(JSON.parse(JSON.stringify(event))) || event.pubkey !== v.value.owner || event.kind !== ONYX_VAULT_PUBLISHER_KIND || event.created_at !== now || event.tags.length !== 1 || event.tags[0].length !== 2 || event.tags[0][0] !== 'd' || event.tags[0][1] !== publisherD(v.value.vaultId)) throw new VaultError('AUTH');
    await this.settings(v, { publisher: { deviceId: this.account!.deviceId, deviceLabel: this.account!.deviceLabel, since: String(now) }, publisherEvent: event, publisherPending: true });
    const result = await this.publishEvent(v.value.network.writeRelays, event); this.check();
    if (!result.durable) throw new VaultError('NETWORK', { operation: 'handover' });
    await this.settings(v, { publisherPending: false });
    await this.readPublisher(v, [event]); await this.assertPublisher(v);
  }
  takeOverPublishing(id: VaultId): Promise<void> { return this.lane(id, 'handover', () => this.designate(this.requireVault(id))); }

  create(folder: string, options: VaultCreateOptions): Promise<VaultId> {
    return this.lane('mounts', 'create', async () => {
      const session = this.session!, relativePath = validateMount(session.notebookPath, folder, this.mounts());
      const rootPath = absolutePath(session.notebookPath, relativePath);
      if (!await session.fs.exists(rootPath)) throw new VaultError('ARG');
      await validateArtifactRoots(session.fs, rootPath); this.check();
      const network = await this.probeNetwork(options.network ?? session.networkDefaults); this.check();
      const vaultId = hex32<VaultId>(this.id()), rootNodeId = hex32<NodeId>(this.id()), seed = this.random(32);
      let key: Bytes32; try { key = deriveRootNodeKey(seed); } finally { seed.fill(0); }
      const ring = initRing(1n, key); key.fill(0);
      const value: StoredVault = { ...version, vaultId, rootNodeId, owner: session.accountPubkey,
        mount: { notebookPath: session.notebookPath, relativePath }, label: options.label ?? last(relativePath.split('/')), publisher: null, attachedAt: String(this.now()),
        grant: null, nodeRings: { [rootNodeId]: toStorage(ring) }, network, enabled: true,
        lastOwnSeq: '0', lastOwnWrittenAt: '0', ownerCheckpointId: null, materializedViewId: null, baseline: {}, pendingCandidateId: null, retainedRoots: [], deliveryLedger: [], resealProgress: null };
      await this.store!.createVault(value); this.check();
      const v: RuntimeVault = this.runtimeVault(value);
      this.vaults.set(vaultId, v); this.subscribeVault(v);
      return this.lane(vaultId, 'create', async () => { this.emit();
      // Mount exclusion and encrypted keys exist before designation or object I/O.
      await this.designate(v);
      await this.captureAndPublish(v, 'create', [{ recipient: value.owner, cap: 'write' }]);
      this.subscribeVault(v); return vaultId;
      });
    });
  }
  private checkpoint(v: RuntimeVault): VerifiedRecord | undefined {
    return v.records.get(v.value.ownerCheckpointId!);
  }
  private budgets(): VaultBudgets { return { ...DEFAULT_VAULT_BUDGETS, ...this.deps.budgets }; }
  private foldLimits(): FoldLimits { return { maxConflicts: this.budgets().conflictRows }; }
  /** Rows written before SV-35 carry no floors: the account's own trust at that
   * time stands, the current grant becomes the floor a newer grant re-arms. */
  private freshnessOf(v: RuntimeVault): StoredFreshness {
    if (v.value.freshness) return v.value.freshness;
    let f: StoredFreshness = EMPTY_FRESHNESS;
    for (const record of v.records.values()) f = noteHead(f, record);
    const grant = v.value.owner !== this.session!.accountPubkey && v.value.grant ? hydrateGrant(v.value.grant) : null;
    return { ...f, granted: grant ? grantedFloor(grant, null) : null, verified: true };
  }
  /** SV-35: floor check and granted-root binding, persisted before the checkpoint is used. */
  private async noteCheckpoint(v: RuntimeVault, owner: VerifiedRecord): Promise<void> {
    const current = this.freshnessOf(v);
    const freshness = acceptCheckpoint(current, owner, grantedHeadSeq(current.granted, v.value.owner, v.records.values()));
    if (JSON.stringify(freshness) !== JSON.stringify(v.value.freshness)) await this.settings(v, { freshness });
  }
  /** SV-30: nothing from the over-budget fold is persisted or chosen; the previous
   * materialised view stands until explicit repair (resolution or revocation). */
  private async quarantineFold(v: RuntimeVault, reason: StoredFoldQuarantine['reason'], rows: number, bytes: number, viewRecordId: RecordId | null): Promise<never> {
    await this.settings(v, { foldQuarantine: { reason, rows, bytes, viewRecordId } });
    throw new VaultError('TOO_LARGE', { operation: 'fold', reason: 'conflict-budget' });
  }
  private viewTree(v: RuntimeVault): VaultTree | undefined {
    return v.trees.get(v.value.materializedViewId as unknown as EventId) ?? v.trees.get(v.value.ownerCheckpointId!);
  }
  private rootRing(v: RuntimeVault): KeyRing { const ring = v.value.nodeRings[v.value.rootNodeId]; if (!ring) throw new VaultError('EPOCH'); return hydrateRing(ring); }
  private grantFor(v: RuntimeVault, cap: VaultCapability, tree: VaultTree, root: Address, issuedAt = this.now()): VaultGrant {
    return { vaultId: v.value.vaultId, nodeId: v.value.rootNodeId, owner: v.value.owner, ring: tree.nodes[0].ring, cap, rootManifest: root,
      hints: v.value.grant?.hints ?? { relays: v.value.network.writeRelays, blossom: v.value.network.writeBlossom }, issuedAt: BigInt(issuedAt) };
  }
  private decodedPaths(v: RuntimeVault, record: VerifiedRecord): Map<string, RecordPath> {
    let paths = decodedRecordPaths.get(record);
    if (!paths) {
      const tree = indexTree(v.trees.get(record.eventId)!); paths = new Map();
      for (const path of record.paths) {
        const decoded = tree.byEntry.get(entryKey(path.nodeId, path.entryIndex))![0];
        paths.set(decoded, path);
      }
      decodedRecordPaths.set(record, paths);
    }
    return paths;
  }
  /** Projection is O(differing paths); full path-table walks stay in the fold
   * and capture indexing passes, never in emit() or a row renderer. */
  private projectProvisional(v: RuntimeVault): void {
    const paths = new Set([...v.ownUnfolded, ...v.otherUnfolded]);
    const notebookPath = (path: string) => `${v.value.mount.relativePath}/${path}`;
    const listed = [...paths].slice(0, 2000);
    v.provisionalCount = paths.size;
    v.provisionalPaths = Object.freeze(listed.map(notebookPath));
    v.provisionalOtherPaths = Object.freeze(listed.filter(path => !v.ownUnfolded.has(path)).map(notebookPath));
  }
  private pendingProvisional(v: RuntimeVault, baseline: Readonly<Record<string, StoredBaselineEntry>>, owner = this.checkpoint(v)): void {
    const ownerPaths = owner ? this.decodedPaths(v, owner) : new Map<string, RecordPath>();
    const view = v.records.get(v.value.materializedViewId as unknown as EventId);
    const viewPaths = view ? this.decodedPaths(v, view) : ownerPaths;
    let indexed = candidatePathIndexes.get(baseline);
    if (!indexed || indexed.owner !== owner?.eventId) {
      // Cold journal/local-candidate restore: index its stored digest table once.
      // Live captures populate this delta during their existing path-table walk.
      const paths = new Set<string>();
      for (const [path, entry] of Object.entries(baseline)) if (ownerPaths.get(path)?.entryDigest !== entry.entryDigest) paths.add(path);
      for (const path of ownerPaths.keys()) if (!baseline[path]) paths.add(path);
      indexed = { owner: owner?.eventId, paths }; candidatePathIndexes.set(baseline, indexed);
    }
    const own = new Set(indexed.paths);
    // An unchanged inherited member version is still that writer's edit, not
    // a new local edit merely because capture observed it on disk.
    for (const path of v.otherUnfolded) if (baseline[path]?.entryDigest === viewPaths.get(path)?.entryDigest) own.delete(path);
    v.ownUnfolded = own; this.projectProvisional(v);
  }
  private foldProvisional(v: RuntimeVault, changes: readonly { record: VerifiedRecord; pathEnc: string }[], owner = this.checkpoint(v)!): void {
    v.ownUnfolded = new Set(); v.otherUnfolded = new Set();
    for (const { record, pathEnc } of changes) {
      const path = indexRecord(record).get(pathEnc) ?? indexRecord(owner).get(pathEnc)!;
      const source = indexRecord(record).has(pathEnc) ? record : owner;
      const decoded = indexTree(v.trees.get(source.eventId)!).byEntry.get(entryKey(path.nodeId, path.entryIndex))![0];
      (record.writer === this.session!.accountPubkey ? v.ownUnfolded : v.otherUnfolded).add(decoded);
    }
    if (v.value.localCandidate) this.pendingProvisional(v, v.value.localCandidate.baseline, owner);
    else this.projectProvisional(v);
  }
  private async capture(v: RuntimeVault): Promise<{ tree: VaultTree; baseline: Readonly<Record<string, StoredBaselineEntry>> }> {
    this.emit({ activity: 'capturing' });
    const session = this.session!, root = absolutePath(session.notebookPath, v.value.mount.relativePath), old = this.viewTree(v), previous = old ? pathsOf(old) : new Map();
    const entries = await traverseMount(session.fs, root, v.value.baseline, this.abort.signal); this.check();
    const rootRing = this.rootRing(v), rootKey = last(rootRing.entries);
    const policy = this.checkpoint(v)?.root.vault ?? { vaultId: v.value.vaultId, owner: v.value.owner, writers: [v.value.owner], readers: [], grantsRev: 1n };
    const baseline: Record<string, StoredBaselineEntry> = {};
    const captureErrors: { path: string; code: 'TOO_LARGE' }[] = [];
    const directories = new Map<string, { id: NodeId; ring: KeyRing; entries: CaptureEntry[]; mtimeNs?: bigint }>([['', { id: v.value.rootNodeId, ring: rootRing, entries: [] }]]);
    for (const entry of entries) {
      this.check();
      const slash = entry.path.lastIndexOf('/'), parentPath = slash < 0 ? '' : entry.path.slice(0, slash), name = entry.path.slice(slash + 1), parent = directories.get(parentPath)!;
      const prior = previous.get(entry.path), meta = { namePlain: name, mode: entry.kind === 'directory' ? 0o755 : 0o644, mtimeNs: 0n };
      if (entry.kind === 'directory') {
        const id = prior?.entry.kind === 'directory' ? prior.entry.childNodeId : hex32<NodeId>(this.id());
        const held = old?.nodes.find(n => n.node.nodeId === id)?.ring;
        const key = deriveChildNodeKey(last(parent.ring.entries).nodeKey, id);
        const ring = held ?? initRing(last(parent.ring.entries).epoch, key); key.fill(0);
        const mtime = prior?.entry.mtimeNs ?? BigInt(Math.max(0, Math.floor(await session.fs.modifiedTime(absolutePath(root, entry.path))))) * 1000000000n;
        this.check(); directories.set(entry.path, { id, ring, entries: [], mtimeNs: mtime });
        continue;
      }
      // Stat first: bytes are read only when the stat differs from every known
      // observation, or when prior chunks cannot be reused for the known hash.
      const held = v.value.baseline[entry.path], reusable = prior?.entry.kind === 'file' && held?.byteHash ? held.byteHash : null;
      const known = reusable ? [v.disk?.get(entry.path), held?.disk ? { stat: held.disk, hash: reusable } : undefined].filter(o => o?.hash === reusable) : [];
      let file: StableFile;
      try { file = await readStableFile(session.fs, session.notebookPath, absolutePath(root, entry.path), this.abort.signal, bytes => this.hashBytes(bytes), known); }
      catch (error) {
        if (!(error instanceof VaultError) || error.code !== 'TOO_LARGE') { if (error instanceof VaultError && error.code === 'CONFLICT') { this.dirtyVaults.add(v.value.vaultId); this.coalescer?.notify(); } throw error; }
        captureErrors.push({ path: entry.path, code: 'TOO_LARGE' });
        if (prior?.entry.kind === 'file') {
          parent.entries.push(prior.entry);
          if (v.value.baseline[entry.path]) baseline[entry.path] = v.value.baseline[entry.path];
        }
        continue;
      }
      this.check();
      (v.disk ??= new Map()).set(entry.path, { stat: file.stat, hash: file.hash });
      this.echoes.acknowledge(absolutePath(root, entry.path), file.hash);
      let chunks;
      if (prior?.entry.kind === 'file' && held?.byteHash === file.hash) {
        chunks = prior.entry.chunks; meta.mtimeNs = prior.entry.mtimeNs; meta.mode = prior.entry.mode;
      } else {
        const bytes = file.bytes; if (!bytes) throw new VaultError('IO', { operation: 'capture' });
        chunks = await this.cpu.run(this.abort.signal, async () => {
          const key = last(parent.ring.entries);
          const job = this.worker!.sealChunks({ buffer: bytes.buffer, nodeKey: key.nodeKey, epoch: key.epoch }, { signal: this.abort.signal });
          const refs = [];
          for await (const chunk of job.chunks) {
            this.check(); this.pinCapture(v, chunk.address);
            await this.cacheBlob(chunk.address, chunk.sealed); this.check();
            refs.push({ address: chunk.address, sizeSealed: chunk.sizeSealed, chunkKeyId: chunk.chunkKeyId, sizePlain: chunk.sizePlain });
          }
          await job.result; return refs;
        });
        meta.mtimeNs = file.mtimeNs;
      }
      parent.entries.push({ ...meta, kind: 'file', chunks });
      // Metadata/digest is filled after captureTree has made the actual entry.
      baseline[entry.path] = { nodeId: parent.id, entryDigest: hex32('00'.repeat(32)), byteHash: file.hash, kind: 'file', metadata: toStorage({ ...meta, nameEnc: '' as never, sizePlain: BigInt(file.stat.size) }), disk: file.stat };
    }
    for (const [path, dir] of [...directories].reverse()) {
      if (!path) continue;
      const slash = path.lastIndexOf('/'), parent = directories.get(slash < 0 ? '' : path.slice(0, slash))!;
      const prior = previous.get(path)?.entry;
      parent.entries.push({ namePlain: path.slice(slash + 1), mode: prior?.mode ?? 0o755, mtimeNs: dir.mtimeNs ?? 0n, kind: 'directory',
        ...(prior?.kind === 'directory' && prior.keyOverride ? { keyOverride: bytes32(prior.keyOverride) } : {}),
        child: { nodeId: dir.id, epoch: last(dir.ring.entries).epoch, ring: dir.ring, entries: dir.entries } });
    }
    // Imported symlinks are preserved as protocol entries, never followed/created.
    if (old) for (const [path, prior] of previous) if (prior.entry.kind === 'symlink') {
      const slash = path.lastIndexOf('/'), parent = directories.get(slash < 0 ? '' : path.slice(0, slash));
      if (parent) parent.entries.push(prior.entry);
    }
    const tree = this.preserveNodeOrder(captureTree({ nodeId: v.value.rootNodeId, epoch: rootKey.epoch, entries: directories.get('')!.entries, vault: policy }, rootRing), old);
    const owner = this.checkpoint(v), ownerPaths = owner ? this.decodedPaths(v, owner) : new Map<string, RecordPath>();
    const missingOwner = new Set(ownerPaths.keys()), pending = new Set<string>();
    let changed = false, pathCount = 0;
    for (const [path, { node, entry }] of pathsOf(tree)) {
      const digest = entryDigest(entry); pathCount++;
      changed ||= digest !== v.value.baseline[path]?.entryDigest;
      if (digest !== ownerPaths.get(path)?.entryDigest) pending.add(path);
      missingOwner.delete(path);
      baseline[path] = { nodeId: node.nodeId, entryDigest: digest, byteHash: baseline[path]?.byteHash ?? null, kind: entry.kind,
        metadata: toStorage({ nameEnc: entry.nameEnc, namePlain: entry.namePlain, mode: entry.mode, mtimeNs: entry.mtimeNs, sizePlain: entry.sizePlain }), ...(baseline[path]?.disk ? { disk: baseline[path].disk } : {}) };
    }
    for (const path of missingOwner) pending.add(path);
    candidatePathIndexes.set(baseline, { owner: owner?.eventId, paths: pending });
    // An unchanged pass must not rewrite the encrypted vault row.
    if (JSON.stringify(captureErrors) !== JSON.stringify(v.value.captureErrors ?? [])) await this.settings(v, { captureErrors });
    if (changed || pathCount !== Object.keys(v.value.baseline).length) this.pendingProvisional(v, baseline);
    return { tree, baseline };
  }
  private preserveNodeOrder(tree: VaultTree, previous?: VaultTree): VaultTree {
    if (!previous) return tree;
    const byId = new Map(tree.nodes.map(n => [n.node.nodeId, n])), old = new Map(previous.nodes.map(n => [n.node.nodeId, n.node]));
    const updated = new Map<NodeId, DirectoryNode>();
    const visit = (id: NodeId): Address => {
      const item = byId.get(id)!;
      const entries = item.node.entries.map(entry => entry.kind === 'directory' ? { ...entry, manifestAddress: visit(entry.childNodeId) } : entry);
      let node: DirectoryNode = { ...item.node, entries };
      const held = old.get(id), candidates = new Map(entries.map(e => [e.namePlain, entryDigest(e)]));
      if (held && held.epoch === node.epoch && JSON.stringify(toStorage(held.vault ?? null)) === JSON.stringify(toStorage(node.vault ?? null)) && held.entries.length === entries.length && held.entries.every(e => candidates.get(e.namePlain) === entryDigest(e))) node = held;
      updated.set(id, node); return sealDirectoryNode(node, last(item.ring.entries).nodeKey).address;
    };
    visit(tree.nodes[0].node.nodeId); return createTree(tree.nodes.map(n => ({ ...n, node: updated.get(n.node.nodeId)! })));
  }
  private readonly capturePins = new Map<VaultId, Set<Address>>();
  private pinCapture(v: RuntimeVault, address: Address): void {
    const pins = this.capturePins.get(v.value.vaultId) ?? new Set<Address>(); pins.add(address); this.capturePins.set(v.value.vaultId, pins);
    this.store!.setPins(`capture:${v.value.vaultId}`, [...pins]);
  }
  private clearCapture(v: RuntimeVault): void { this.capturePins.delete(v.value.vaultId); this.store?.setPins(`capture:${v.value.vaultId}`, []); }
  private async captureAndPublish(v: RuntimeVault, kind: StoredOperation['kind'] = 'publish', deliveries: readonly { recipient: Pubkey; cap: VaultCapability }[] = []): Promise<void> {
    const captured = await this.cpuCapture(v);
    try {
    if (this.conflictRows.get(v.value.vaultId)?.some(c => c.blockedMaterialization)) {
      await this.preserveCandidate(v, captured.tree, captured.baseline);
      throw new VaultError('CONFLICT', { operation: 'capture' });
    }
    const old = v.records.get(v.value.materializedViewId as unknown as EventId) ?? this.checkpoint(v);
    const oldPaths = old && this.decodedPaths(v, old);
    if (oldPaths && oldPaths.size === Object.keys(captured.baseline).length && Object.entries(captured.baseline).every(([path, entry]) => oldPaths.get(path)?.entryDigest === entry.entryDigest)) { wipeTree(captured.tree); return; }
    const policy = this.policy(v);
    if (v.value.owner === this.session!.accountPubkey) {
      try { await this.assertPublisher(v); } catch (error) {
        if (error instanceof VaultError && error.code === 'POLICY') { await this.preserveCandidate(v, captured.tree, captured.baseline); return; } throw error;
      }
    } else if (!policy?.writers.includes(this.session!.accountPubkey)) { await this.preserveCandidate(v, captured.tree, captured.baseline); return; }
    await this.publishTree(v, captured.tree, kind, captured.baseline, [], deliveries);
    } finally { wipeTree(captured.tree); }
  }
  private captureLane = Promise.resolve();
  private cpuCapture(v: RuntimeVault) {
    // One active capture file globally. Worker jobs also share the CPU semaphore.
    const task = this.captureLane.then(() => this.capture(v)); this.captureLane = task.then(() => {}, () => {}); return task;
  }
  private async preserveLocalChanges(v: RuntimeVault): Promise<void> {
    const local = await this.cpuCapture(v);
    const paths = Object.keys(local.baseline), baseline = v.value.baseline;
    const changed = paths.length !== Object.keys(baseline).length || paths.some(path => local.baseline[path].byteHash !== baseline[path]?.byteHash || local.baseline[path].kind !== baseline[path]?.kind);
    if (changed || v.provisionalCount > 0) await this.preserveCandidate(v, local.tree, local.baseline);
    if (v.provisionalCount > 0) {
      const checkpoint = this.checkpoint(v)!;
      const ownerTree = await this.reconstructHistory(v, v.trees.get(checkpoint.eventId)!);
      const targets = new Map((await this.targets(v, ownerTree)).map(target => [target.path, target]));
      for (const path of new Set([...paths, ...targets.keys()])) {
        const localHash = baselineHash(local.baseline[path]), remote = targets.get(path);
        if (localHash !== baselineHash(remote?.baseline)) await persistLocalConflict(this.materializeContext(), v.value, path, localHash, remote, recordId(checkpoint));
      }
      await this.refreshCounts();
    }
    if (!changed && !v.provisionalCount) { wipeTree(local.tree); this.clearCapture(v); }
  }
  private async preserveCandidate(v: RuntimeVault, tree: VaultTree, baseline: Readonly<Record<string, StoredBaselineEntry>>): Promise<void> {
    // Local-only data is encrypted and pins its ciphertext, but is never a pending
    // publication journal: it cannot block future remote materialisation.
    const addresses = [...new Set(tree.nodes.flatMap(n => n.node.entries.flatMap(e => e.kind === 'file' ? e.chunks.map(c => c.address) : [])))];
    await this.settings(v, { localCandidate: { tree: toStorage(tree), baseline, addresses } });
    this.clearCapture(v);
    this.pendingProvisional(v, baseline); this.emit();
  }
  private async publishTree(v: RuntimeVault, tree: VaultTree, kind: StoredOperation['kind'], baseline: StoredVault['baseline'] = v.value.baseline,
    incorporated: readonly VerifiedRecord[] = [], deliveries: readonly { recipient: Pubkey; cap: VaultCapability }[] = [], deliveryOptions: VaultDeliveryOptions = {}, materialization?: { readonly resolvedPaths: readonly string[]; readonly conflictIds: readonly string[] }): Promise<void> {
    this.check();
    if (v.value.pendingCandidateId) throw new VaultError('CONFLICT');
    await this.flushReadConfirmations(v);
    const objects = new Map<Address, Uint8Array>();
    const sealed = await sealTree(tree, { put: (bytes, address) => { objects.set(address, bytes); } });
    const all = new Set<Address>(objects.keys());
    for (const item of tree.nodes) for (const entry of item.node.entries) if (entry.kind === 'file') for (const chunk of entry.chunks) all.add(chunk.address);
    const pin = `candidate:${v.value.vaultId}`; this.store!.setPins(pin, [...all]);
    try {
      for (const [address, bytes] of objects) { this.check(); await this.cacheBlob(address, bytes); }
      const own = [...v.records.values()].filter(r => r.writer === this.session!.accountPubkey).sort((a, b) => a.head.seq > b.head.seq ? -1 : 1)[0];
      const lastWritten = [BigInt(v.value.lastOwnWrittenAt), own?.head.writtenAt ?? 0n].reduce((a, b) => a > b ? a : b);
      const writtenAt = BigInt(this.now()) > lastWritten ? BigInt(this.now()) : lastWritten + 1n;
      if (writtenAt > BigInt(this.now() + 60)) throw new VaultError('NETWORK', { operation: 'publish', retryable: true });
      let head: VaultHead;
      if (v.value.owner === this.session!.accountPubkey) {
        head = newOwnerHead(sealed.tree, own?.head ?? null, this.session!.accountPubkey, sealed.rootManifest, writtenAt);
        const allocated = BigInt(v.value.lastOwnSeq);
        if (head.seq <= allocated) {
          if (allocated === UINT64_MAX) throw new VaultError('TOO_LARGE');
          head = { ...head, seq: allocated + 1n };
        }
      }
      else {
        const checkpoint = this.checkpoint(v); if (!checkpoint || !checkpoint.root.vault!.writers.includes(this.session!.accountPubkey)) throw new VaultError('POLICY');
        const seq = (own?.head.seq ?? BigInt(v.value.lastOwnSeq)) + 1n; if (seq > UINT64_MAX) throw new VaultError('TOO_LARGE');
        head = { vaultId: v.value.vaultId, epoch: sealed.tree.nodes[0].node.epoch, rootManifest: sealed.rootManifest, seq,
          grantsRev: checkpoint.head.grantsRev, writtenAt, parents: memberHeadParents(this.session!.accountPubkey, own?.head ?? null, checkpoint),
          ...(checkpoint.head.keyOverride ? { keyOverride: bytes32(last(sealed.tree.nodes[0].ring.entries).nodeKey) } : {}) };
      }
      if (incorporated.length) head = coverHead(head, incorporated);
      const epochLedger = (kind === 'create' || kind === 'revoke') && v.value.owner === this.session!.accountPubkey ? encodeEpochLedger(this.proposedEpochLedger(v, [head])) : undefined;
      const updatedGrant = this.grantFor(v, 'write', sealed.tree, sealed.rootManifest, Number(writtenAt));
      for (const d of deliveries) assertGrantWrapFits({ ...updatedGrant, cap: d.cap }, this.now());
      const operation: StoredOperation = { ...version, vaultId: v.value.vaultId, operationId: this.id(), kind, stage: 'prepared',
        candidate: { tree: toStorage(sealed.tree), head: toStorage(head), baseline: toStorage(baseline), ...(epochLedger ? { epochLedger } : {}),
          diskEstablished: !materialization && (kind === 'create' || kind === 'publish' || v.value.materializedViewId === v.value.ownerCheckpointId as unknown as RecordId), grant: toStorage(updatedGrant), deliveries: toStorage(deliveries), deliveryOptions: toStorage(deliveryOptions), ...(materialization ? { materialization: toStorage(materialization) } : {}) },
        signedEvent: null, pinnedAddresses: [...all], pendingAddress: null, uploadOutcomes: {}, relayOutcomes: {} };
      const row = (await this.store!.read('vaults', [v.value.vaultId]))!; this.check();
      await this.store!.saveJournal(operation, { ...row.value, pendingCandidateId: operation.operationId }, { vault: row.revision, operation: 0 });
      await this.reload(v); await this.resumePublication(v, operation);
    } finally { wipeTree(sealed.tree); this.store?.setPins(pin, []); this.clearCapture(v); }
  }
  private async resumePublication(v: RuntimeVault, initial: StoredOperation): Promise<void> {
    if (initial.candidate.checkpointOnly === true || initial.candidate.attachOnly === true) {
      const row = (await this.store!.read('vaults', [v.value.vaultId]))!;
      const op = (await this.store!.read('operations', [v.value.vaultId, initial.operationId]))!; this.check();
      const change: Partial<StoredVault> = initial.candidate.checkpointOnly === true ? { ownerCheckpointId: initial.candidate.ownerId as EventId, retainedRoots: retainRootEvidence(initial.candidate.retained as unknown as readonly StoredRetainedRoot[]) } :
        { baseline: {}, materializedViewId: null, attachedAt: String(this.now()), mount: { ...row.value.mount, relativePath: initial.candidate.relativePath as string } };
      await this.store!.saveJournal({ ...op.value, stage: 'committed' }, { ...row.value, ...change, pendingCandidateId: null }, { vault: row.revision, operation: op.revision });
      await this.reload(v); return;
    }
    let operation = (await this.store!.read('operations', [initial.vaultId, initial.operationId]))!;
    const tree = hydrateTree(initial.candidate.tree as unknown as Persisted<VaultTree>);
    this.pendingProvisional(v, initial.candidate.baseline as unknown as StoredVault['baseline']);
    try {
    const grant = hydrateGrant(initial.candidate.grant as unknown as Persisted<VaultGrant>);
    const h = initial.candidate.head as unknown as Persisted<VaultHead>;
    const head: VaultHead = { vaultId: h.vaultId, rootManifest: h.rootManifest, ...(h.refState ? { refState: h.refState } : {}), epoch: BigInt(h.epoch), seq: BigInt(h.seq), grantsRev: BigInt(h.grantsRev), writtenAt: BigInt(h.writtenAt),
      parents: h.parents.map(p => ({ ...p, seq: BigInt(p.seq) })), ...(h.keyOverride ? { keyOverride: bytes32(hexToBytes(h.keyOverride)) } : {}) };
    const save = async (patch: Partial<StoredOperation>, commit?: Partial<StoredVault>) => {
      const row = (await this.store!.read('vaults', [v.value.vaultId]))!; this.check();
      const next = { ...operation.value, ...patch, ...(patch.relayOutcomes ? { relayOutcomes: mergeRelayOutcomes(operation.value.relayOutcomes, patch.relayOutcomes) } : {}) };
      const revisions = await this.store!.saveJournal(next, { ...row.value, ...commit, pendingCandidateId: next.stage === 'committed' ? null : next.operationId }, { vault: row.revision, operation: operation.revision });
      operation = { value: next, revision: revisions.operation }; await this.reload(v);
    };
    const suspend = async () => {
      await save({ stage: 'committed', uploadOutcomes: { ...operation.value.uploadOutcomes, localOnly: true } }, {
        localCandidate: { tree: toStorage(tree), baseline: initial.candidate.baseline as unknown as StoredVault['baseline'], addresses: initial.pinnedAddresses },
      });
      this.pendingProvisional(v, initial.candidate.baseline as unknown as StoredVault['baseline']); this.emit();
    };
    const authority = async () => {
      await this.awaitAuthority(v);
      if (v.value.owner === this.session!.accountPubkey) {
        try {
          await this.assertPublisher(v);
          const events = [...(v.headEvents?.values() ?? [])]; v.headEvents?.clear();
          for (const event of events) {
            if (event.id === operation.value.signedEvent?.id || v.records.has(event.id as EventId)) continue;
            const known = await this.store!.read('records', [v.value.vaultId, event.id]); this.check();
            await this.ingest(v, event, known ? BigInt(known.value.record.head.epoch) : head.epoch, tree.nodes[0].ring);
          }
          if ([...v.records.values()].some(r => r.writer === v.value.owner && (r.head.seq > head.seq || r.head.seq === head.seq && encodeHead(r.head) !== encodeHead(head)))) throw new VaultError('CONFLICT');
          if (v.records.size) foldCurrentHeads(grant, [...v.records.values()]);
          await this.assertPublisher(v);
        } catch (error) { if (error instanceof VaultError && ['POLICY', 'CONFLICT'].includes(error.code)) await suspend(); throw error; }
      } else {
        await this.ingestObservedHeads(v);
        const selected = selectFoldInputs(grant, [...v.records.values()]);
        const checkpoint = selected.records[selected.ownerIndex];
        if (!checkpoint.root.vault!.writers.includes(this.session!.accountPubkey) || checkpoint.head.grantsRev !== head.grantsRev) {
          await suspend(); throw new VaultError('POLICY');
        }
      }
    };
    await authority(); await this.flushReadConfirmations(v);
    if (operation.value.stage === 'prepared' || operation.value.stage === 'uploading' || operation.value.stage === 'needs-recovery') {
      await save({ stage: 'uploading' }); this.emit({ activity: 'uploading' });
      // The prepared journal pins the complete graph. Only unknown server/address
      // pairs need traffic; confirmations outlive both journals and cached bytes.
      const manifests = new Map<Address, number>(), order: Address[] = [];
      const sealed = await sealTree(tree, { put: (bytes, address) => { manifests.set(address, bytes.length); order.push(address); } });
      const sizes = new Map(manifests);
      const addresses = new Map<NodeId, Address>([[tree.nodes[0].node.nodeId, head.rootManifest]]);
      for (const item of tree.nodes) for (const entry of item.node.entries) {
        if (entry.kind === 'directory') addresses.set(entry.childNodeId, entry.manifestAddress);
        if (entry.kind === 'file') for (const chunk of entry.chunks) sizes.set(chunk.address, Number(chunk.sizeSealed));
      }
      const children = new Map(tree.nodes.map(item => [addresses.get(item.node.nodeId)!, item.node.entries.flatMap(e => e.kind === 'directory' ? [e.manifestAddress] : [])]));
      const heights = new Map<Address, number>();
      const height = (address: Address): number => {
        if (!heights.has(address)) heights.set(address, children.get(address)!.reduce((max, child) => Math.max(max, height(child)), -1) + 1);
        return heights.get(address)!;
      };
      const levels = new Map<number, Address[]>();
      for (const address of order) { const h = height(address); levels.set(h, [...(levels.get(h) ?? []), address]); }
      const phases = [operation.value.pinnedAddresses.filter(a => !manifests.has(a)), ...[...levels].sort((a, b) => a[0] - b[0]).map(([, a]) => a)];
      const confirmed: Record<string, readonly string[]> = { ...v.value.confirmedObjects };
      // Migrate exact server outcomes from pre-tracking journals, including a
      // successful replica in a partially failed/uncertain upload batch.
      includeUploadConfirmations(confirmed, operation.value.uploadOutcomes);
      await save({}, { confirmedObjects: confirmed });
      for (const phase of phases) {
        const hinted = (v.value.grant?.hints.blossom ?? v.value.network.writeBlossom).map(url => validatePublicEndpoint(url, 'https:'));
        const unknown = [...new Set(phase)].filter(address => v.value.network.writeBlossom.some(url => !confirmed[address]?.includes(url)) || !hinted.some(url => confirmed[address]?.includes(url)));
        for (let i = 0; i < unknown.length; i += 4) {
          const batch = unknown.slice(i, i + 4);
          const results = await Promise.all(batch.map(async address => ({ address,
            uploaded: await this.putBlob(v, address, () => this.readBlob(v, address), sizes.get(address)) })));
          this.check();
          const uploadOutcomes = { ...operation.value.uploadOutcomes };
          for (const { address, uploaded } of results) {
            confirmed[address] = [...new Set([...(confirmed[address] ?? []), ...Object.entries(uploaded.outcomes).filter(([, status]) => status === 'accepted').map(([url]) => url)])];
            uploadOutcomes[address] = { durable: uploaded.durable, servers: uploaded.outcomes };
          }
          const failed = results.find(result => !result.uploaded.durable);
          // One atomic outcome/confirmation write per batch, never concurrent
          // journal mutations. A crash before it makes these HEAD-unknown again.
          await save({ pendingAddress: failed?.address ?? null, uploadOutcomes }, { confirmedObjects: { ...confirmed } });
          if (failed) throw failed.uploaded.refusal ?? new VaultError('INCOMPLETE', { operation: 'upload' });
        }
      }
      if (sealed.rootManifest !== head.rootManifest) throw new VaultError('HASH_MISMATCH');
      const event = operation.value.signedEvent ?? await this.session!.signer.signEvent(buildHeadEvent(head, last(tree.nodes[0].ring.entries).nodeKey, this.session!.accountPubkey));
      this.check();
      // Verification catches signer substitutions before retaining or publishing.
      await fetchRecord(event, grant, tree.nodes[0].ring, head.epoch, { read: address => this.readBlob(v, address) });
      let ledgerEvent = operation.value.signedEpochLedgerEvent;
      if (operation.value.candidate.epochLedger && !ledgerEvent) {
        const ledger = decodeEpochLedger(operation.value.candidate.epochLedger as string);
        ledgerEvent = await this.session!.signer.signEvent(buildEpochLedgerEvent(ledger, tree.nodes[0].ring, v.value.owner, head.writtenAt));
        this.check();
        if (encodeEpochLedger(openEpochLedgerEvent(ledgerEvent, v.value.vaultId, v.value.owner, tree.nodes[0].ring)) !== encodeEpochLedger(ledger) || ledgerEvent.created_at !== Number(head.writtenAt)) throw new VaultError('AUTH');
      }
      await save({ stage: 'ready-to-publish', signedEvent: event, ...(ledgerEvent ? { signedEpochLedgerEvent: ledgerEvent } : {}) });
    }
    const event = operation.value.signedEvent; if (!event) throw new VaultError('STORAGE');
    await authority();
    (v.seenHeads ??= new Set()).add(event.id);
    this.emit({ activity: 'publishing' });
    await save({ stage: 'awaiting-ack' });
    try {
    const result = await this.publishEvent(v.value.network.writeRelays, event, outcomes => this.lateInLane(v, () => this.recordPublicationResult(v, initial.operationId, outcomes))); this.check();
    await save({ relayOutcomes: { ...operation.value.relayOutcomes, ...Object.fromEntries(result.outcomes.map(o => [o.relay, o.status])) } });
    if (!result.durable) throw new VaultError('NETWORK', { operation: 'publish' });
    // Publish the exact journaled ledger only after the new-epoch head has an OK.
    const ledgerEvent = operation.value.signedEpochLedgerEvent;
    if (ledgerEvent && operation.value.relayOutcomes.epochLedgerAcknowledged !== true) {
      const ledgerResult = await this.publishEvent(v.value.network.writeRelays, ledgerEvent, outcomes => this.lateInLane(v, () => this.recordPublicationResult(v, initial.operationId, outcomes, true))); this.check();
      await save({ relayOutcomes: { ...operation.value.relayOutcomes, epochLedgerAcknowledged: ledgerResult.durable, epochLedger: Object.fromEntries(ledgerResult.outcomes.map(o => [o.relay, o.status])) } });
      if (!ledgerResult.durable) throw new VaultError('NETWORK', { operation: 'publish' });
    }
    const { record, tree: verified } = await fetchRecord(event, grant, tree.nodes[0].ring, head.epoch, { read: a => this.readBlob(v, a) }, (id) => tree.nodes.find(n => n.node.nodeId === id)?.ring);
    this.check(); await this.store!.put('records', [v.value.vaultId, record.eventId], { ...version, vaultId: v.value.vaultId, record: toStorage(record) });
    const isOwner = record.writer === v.value.owner;
    const retainedRoots = retainRootEvidence(v.value.retainedRoots, [...v.records.values()].map(r => r.head).concat(head));
    const freshness = isOwner ? publishedCheckpoint(this.freshnessOf(v), record) : noteHead(this.freshnessOf(v), record);
    await save({ stage: 'committed' }, { nodeRings: treeRings(tree), grant: toStorage(grant), retainedRoots, freshness,
      ...(initial.kind === 'revoke' ? { resealTotalBytes: String(this.remainingBytes(v, tree)), resealProgress: null } : {}), ...(ledgerEvent ? { epochLedgerEvent: ledgerEvent } : {}),
      lastOwnSeq: String(head.seq), lastOwnWrittenAt: String(head.writtenAt), baseline: initial.candidate.baseline as unknown as StoredVault['baseline'],
      ...(!initial.candidate.materialization && initial.candidate.diskEstablished !== false ? { localCandidate: null } : {}),
      ...(!initial.candidate.materialization && initial.candidate.diskEstablished !== false ? { materializedViewId: recordId(record) } : {}), ...(isOwner ? { ownerCheckpointId: record.eventId } : {}) });
    v.records.set(record.eventId, record); v.trees.set(record.eventId, verified);
    const changes: { record: VerifiedRecord; pathEnc: string }[] = [];
    foldCurrentHeads(grant, [...v.records.values()], { ...this.foldLimits(), onCheckpointDifference: (record, pathEnc) => changes.push({ record, pathEnc }) });
    const selected = selectFoldInputs(grant, [...v.records.values()]);
    this.foldProvisional(v, changes, selected.records[selected.ownerIndex]);
    this.subscribeVault(v);
    const degraded = result.degraded || Object.values(operation.value.uploadOutcomes).some(value => value && typeof value === 'object' && !Array.isArray(value) && 'servers' in value && value.servers && typeof value.servers === 'object' && Object.values(value.servers).some(status => status !== 'accepted'));
    v.error = v.value.captureErrors?.length ? new VaultError('TOO_LARGE', { operation: 'capture' }) : degraded ? new VaultError('NETWORK', { operation: 'publish', retryable: true }) : null;
    // Durability is established. Replica refusals remain on this vault and the
    // endpoint list, not an account-wide error while healthy services still work.
    this.emit({ condition: v.value.captureErrors?.length ? 'error' : 'ready', lastError: v.value.captureErrors?.length ? v.error!.toDisplay() : null });
    await this.finishResolution(v, operation.value);
    await this.finishDeliveries(v, operation.value);
    } catch (error) {
      if (error instanceof VaultError && error.code === 'CANCELLED') throw new VaultError('NETWORK', { operation: 'publish', retryable: true });
      throw error;
    }
    } finally { wipeTree(tree); }
  }
  private async finishResolution(v: RuntimeVault, operation: StoredOperation): Promise<void> {
    if (!operation.candidate.materialization || operation.uploadOutcomes.localOnly === true) return;
    const intent = operation.candidate.materialization as unknown as { resolvedPaths: readonly string[]; conflictIds: readonly string[] };
    const conflicts = await Promise.all(intent.conflictIds.map(id => this.store!.read('conflicts', [v.value.vaultId, id]))); this.check();
    if (conflicts.every(row => row?.value.resolution === 'resolved')) return;
    if (!operation.signedEvent) throw new VaultError('STORAGE');
    const eventId = operation.signedEvent.id as EventId;
    if (!v.records.has(eventId)) await this.ingest(v, operation.signedEvent, BigInt((operation.candidate.head as unknown as Persisted<VaultHead>).epoch));
    if (v.value.materializedViewId !== eventId as unknown as RecordId) {
      const tree = v.trees.get(eventId)!;
      await materialize(this.materializeContext(v.value.vaultId), v.value, await this.targets(v, tree), recordId(v.records.get(eventId)!), { resolvedPaths: intent.resolvedPaths });
      await this.reload(v);
    }
    for (const conflictId of intent.conflictIds) {
      const row = await this.store!.read('conflicts', [v.value.vaultId, conflictId]); this.check();
      if (row && row.value.resolution !== 'resolved') await this.store!.put('conflicts', [v.value.vaultId, conflictId], { ...row.value, resolution: 'resolved' }, row.revision);
    }
    await this.refreshCounts(); this.emit();
  }
  private async recipientRelays(identity: Pubkey, configured: readonly string[]): Promise<readonly string[]> {
    const generation = this.generation;
    const tasks = configured.map(endpoint => {
      const key = JSON.stringify([identity, endpoint]);
      let task = this.recipientCache.get(key);
      if (!task) {
        task = this.events([endpoint], [{ kinds: [NIP65_RELAY_LIST_KIND], authors: [identity] }]).then(events => {
          const event = events.filter(e => e.pubkey === identity && verifyEvent(JSON.parse(JSON.stringify(e)))).sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1))[0];
          const urls = new Set<string>();
          for (const tag of event?.tags ?? []) if (tag[0] === 'r' && (tag.length === 2 || tag[2] === 'read')) {
            try { urls.add(validatePublicEndpoint(tag[1], 'wss:')); } catch { /* Untrusted endpoint is not contacted. */ }
          }
          this.check(generation); if (event) this.learnRecipientRelays(identity, event, [...urls]); return [...urls];
        });
        this.recipientCache.set(key, task);
        void task.catch(() => { if (this.recipientCache.get(key) === task) this.recipientCache.delete(key); });
      }
      return task;
    });
    const advertised = await firstSufficient(tasks);
    return [...new Set([...configured, ...(this.recipientRoutes.get(identity) ?? advertised)])];
  }
  private learnRecipientRelays(identity: Pubkey, event: Event, urls: readonly string[]): void {
    const previous = this.recipientRecords.get(identity);
    if (previous && (previous.created_at > event.created_at || previous.created_at === event.created_at && previous.id <= event.id)) return;
    this.recipientRecords.set(identity, event);
    const known = this.recipientRoutes.get(identity) ?? new Set<string>();
    const added = urls.filter(url => !known.has(url));
    this.recipientRoutes.set(identity, new Set(urls));
    if (!added.length) return;
    if (identity === this.session!.accountPubkey && this.inboxSub) {
      const extra = added.filter(url => !this.inboxEndpoints.includes(url));
      if (extra.length) {
        this.inboxEndpoints = [...this.inboxEndpoints, ...extra];
        this.inboxExtra.set(JSON.stringify(extra), this.subscribeInbox(extra, this.inboxPubkeys));
        void this.refreshInboxFrom(extra).catch(() => {});
      }
    }
    for (const v of this.vaults.values()) if (v.value.owner === this.session!.accountPubkey) void this.lateInLane(v, async () => {
      for (const entry of v.value.deliveryLedger.filter(d => d.recipient === identity && d.signedWrap)) {
        const pending = added.filter(url => !entry.acknowledged.includes(url));
        if (!pending.length) continue;
        await this.settings(v, { deliveryLedger: v.value.deliveryLedger.map(d => d.rumorId === entry.rumorId && d.recipient === identity ? { ...d, pending: [...new Set([...d.pending, ...pending])] } : d) });
        if (v.value.publisher?.deviceId !== this.account!.deviceId) continue;
        await this.assertPublisher(v);
        const result = await this.publishEvent(pending, entry.signedWrap!, outcomes => this.lateInLane(v, () => this.recordDeliveryResult(v, identity, entry.rumorId, outcomes)));
        await this.recordDeliveryResult(v, identity, entry.rumorId, result.outcomes);
      }
    });
  }
  private async finishDeliveries(v: RuntimeVault, operation: StoredOperation): Promise<void> {
    const recipients = operation.candidate.deliveries as unknown as readonly { recipient: Pubkey; cap: VaultCapability }[] | undefined;
    if (operation.uploadOutcomes.localOnly === true || !recipients?.length || v.value.owner !== this.session!.accountPubkey || v.value.publisher?.deviceId !== this.account!.deviceId) return;
    const grant = hydrateGrant(operation.candidate.grant as unknown as Persisted<VaultGrant>);
    if (last(grant.ring.entries).epoch < last(this.rootRing(v).entries).epoch) return;
    for (const d of recipients) {
      const policy = this.policy(v);
      if (d.recipient !== v.value.owner && !policy?.writers.includes(d.recipient) && !policy?.readers.includes(d.recipient)) continue;
      try { await this.deliver(v, { ...grant, cap: d.cap }, d.recipient, operation.candidate.deliveryOptions as VaultDeliveryOptions ?? {}); }
      catch (error) { this.fail(error, 'share', v); }
    }
    await this.refreshCounts(); this.emit();
  }
  private async deliver(v: RuntimeVault, grant: VaultGrant, recipient: Pubkey, options: VaultDeliveryOptions): Promise<void> {
    let endpoints: readonly string[] | undefined;
    // Grant rumor id is stable across retries (issuedAt belongs to the journal).
    const rumorId = buildGrantRumor(grant).id as EventId;
    let entry = v.value.deliveryLedger.find(d => d.recipient === recipient && d.rumorId === rumorId);
    if (entry && !entry.pending.length) return;
    await this.assertPublisher(v);
    if (!entry) {
      if (options.enabled) endpoints = await this.recipientRelays(recipient, v.value.network.writeRelays);
      // The pin is committed before the wrap exists: a crash leaves an observed pin and no delivery, never the reverse.
      const selected = await this.selectRecipient(recipient, endpoints ?? v.value.network.writeRelays, options); this.check();
      const prepared = await buildGrantWrap(grant, this.session!.signer, selected.encryptionKey, { clock: () => this.now(), rng: n => this.random(n) }); this.check();
      entry = { recipient, cap: grant.cap, issuedAt: String(grant.issuedAt), envelopeKey: selected.encryptionKey, rumorId: prepared.rumorId as EventId, wrapIds: [prepared.wrap.id as EventId], acknowledged: [], pending: endpoints ?? v.value.network.writeRelays, signedWrap: prepared.wrap,
        ...(selected.notice ? { notice: selected.notice } : {}), ...(options.enabled ? { evidence: selected.evidence } : {}) };
      await this.settings(v, { deliveryLedger: [...v.value.deliveryLedger, entry] });
    }
    if (!entry.pending.length) return;
    if (!entry.signedWrap) throw new VaultError('STORAGE');
    endpoints ??= await this.recipientRelays(recipient, v.value.network.writeRelays);
    const pending = [...new Set([...entry.pending, ...endpoints])].filter(url => !entry!.acknowledged.includes(url));
    await this.settings(v, { deliveryLedger: v.value.deliveryLedger.map(d => d.recipient === recipient && d.rumorId === rumorId ? { ...d, pending } : d) });
    entry = v.value.deliveryLedger.find(d => d.recipient === recipient && d.rumorId === rumorId)!;
    await this.assertPublisher(v);
    if (!entry.signedWrap) throw new VaultError('STORAGE');
    const result = await this.publishEvent(entry.pending, entry.signedWrap, outcomes => this.lateInLane(v, () => this.recordDeliveryResult(v, recipient, rumorId, outcomes))); this.check();
    await this.recordDeliveryResult(v, recipient, rumorId, result.outcomes);
    if (!result.durable) throw new VaultError('NETWORK', { operation: 'share' });
  }
  private async loadRecords(v: RuntimeVault): Promise<void> {
    for (const row of await this.store!.list('records')) if (row.value.vaultId === v.value.vaultId) {
      const saved = row.value.record;
      if (!this.rootRing(v).entries.some(e => e.epoch === BigInt(saved.head.epoch))) continue;
      const event = JSON.parse(JSON.stringify(saved.signedEvent)) as Event;
      // Persisted epoch associations are re-authenticated, not trusted as labels.
      const head = openHeadEvent(event, v.value.vaultId, this.rootRing(v), BigInt(saved.head.epoch));
      await this.settings(v, { retainedRoots: retainRootEvidence(v.value.retainedRoots, [head]) });
      try { await this.ingest(v, event, head.epoch, undefined, false); }
      catch (error) {
        if (!(error instanceof VaultError) || !['INCOMPLETE', 'NETWORK', 'IO'].includes(error.code)) throw error;
      }
    }
  }
  /** Returns true when a new record was admitted. `gate` is off only for the
   * re-authentication of previously verified persisted records. */
  private async ingest(v: RuntimeVault, event: Event, explicitEpoch?: bigint, rootOverride?: KeyRing, gate = true): Promise<boolean> {
    if (v.records.has(event.id as EventId)) return false;
    this.check();
    const ring = rootOverride ?? this.rootRing(v), epoch = explicitEpoch ?? last(ring.entries).epoch;
    if (gate) {
      // SV-30/SV-35 admission gate: one cheap authenticated head decode decides
      // before any manifest fetch or persistence. Admitted records then fold
      // exactly as before; the gate never alters a disposition.
      const head = openHeadEvent(event, v.value.vaultId, ring, epoch), writer = hex32<Pubkey>(event.pubkey);
      // Below a member's durable high-water a head can never be a frontier
      // candidate. Owner heads stay admissible as audit evidence, but a replayed
      // owner history is bounded cumulatively before any manifest fetch.
      const freshness = this.freshnessOf(v);
      if (headPosition(freshness, writer, head.seq) === 'behind') {
        if (writer !== v.value.owner) return false;
        const high = BigInt(freshness.authors[writer].seq); let audit = 0;
        for (const r of v.records.values()) if (r.writer === writer && r.head.seq < high) audit++;
        if (audit >= this.budgets().ownerAuditRecords) return false;
      }
      let held = 0;
      for (const r of v.records.values()) if (r.writer === writer && r.head.seq === head.seq) held++;
      if (held >= this.budgets().recordsPerAuthorSeq) throw new VaultError('TOO_LARGE', { operation: 'fold', reason: 'fork-budget' });
    }
    const result = await fetchRecord(event, { vaultId: v.value.vaultId, nodeId: v.value.rootNodeId, owner: v.value.owner }, ring, epoch,
      { read: address => this.readBlob(v, address) }, id => v.value.nodeRings[id] ? hydrateRing(v.value.nodeRings[id]) : undefined);
    this.check();
    await this.store!.put('records', [v.value.vaultId, result.record.eventId], { ...version, vaultId: v.value.vaultId, record: toStorage(result.record) });
    v.records.set(result.record.eventId, result.record); v.trees.set(result.record.eventId, result.tree);
    await this.settings(v, { retainedRoots: retainRootEvidence(v.value.retainedRoots, [result.record.head]), freshness: noteHead(this.freshnessOf(v), result.record) });
    if (v.value.quarantinedHeads?.[event.id]) {
      const held = { ...v.value.quarantinedHeads }; delete held[event.id]; await this.settings(v, { quarantinedHeads: held });
      if (!Object.keys(held).length) v.error = null;
    }
    return true;
  }
  private async quarantineHead(v: RuntimeVault, event: Event, error: unknown): Promise<void> {
    if (!(error instanceof VaultError) || ['NETWORK', 'INCOMPLETE', 'IO', 'CANCELLED', 'STORAGE'].includes(error.code)) return;
    const known = v.value.quarantinedHeads ?? {};
    if (known[event.id] || Object.keys(known).length >= 256) return;
    await this.settings(v, { quarantinedHeads: { ...known, [event.id]: { code: error.code, signedEvent: event } } });
  }
  private async backfill(v: RuntimeVault): Promise<void> {
    this.emit({ activity: 'fetching' });
    await this.readEpochLedger(v);
    const ownerEvents = await this.events(v.value.network.readRelays, [{ kinds: [PORTHOME_HEAD_KIND], authors: [v.value.owner], '#d': [headDTag(v.value.vaultId)] }], event => this.observeHead(v, event));
    for (const event of ownerEvents) {
      try { await this.ingest(v, event); }
      catch (error) { this.check(); await this.quarantineHead(v, event, error); this.fail(error, 'open', v); }
    }
    const owner = selectFoldInputs({ vaultId: v.value.vaultId, nodeId: v.value.rootNodeId, owner: v.value.owner }, [...v.records.values()]);
    const checkpoint = owner.records[owner.ownerIndex];
    const events = await this.events(v.value.network.readRelays, [{ kinds: [PORTHOME_HEAD_KIND], authors: [...new Set([v.value.owner, ...checkpoint.root.vault!.writers])], '#d': [headDTag(v.value.vaultId)] }], event => this.observeHead(v, event));
    for (const event of events) {
      try { await this.ingest(v, event); }
      catch (error) { this.check(); await this.quarantineHead(v, event, error); this.fail(error, 'open', v); }
    }
  }
  private observeHead(v: RuntimeVault, event: Event): void {
    if (v.records.has(event.id as EventId) || v.seenHeads?.has(event.id)) return;
    (v.seenHeads ??= new Set()).add(event.id);
    (v.headEvents ??= new Map()).set(event.id, event);
    this.queueRemote(v);
  }
  private observeAuxiliary(v: RuntimeVault, kind: 'publisher' | 'ledger', event: Event): void {
    const seen = kind === 'publisher' ? v.seenPublisher ??= new Set() : v.seenLedger ??= new Set();
    if (seen.has(event.id) || (kind === 'publisher' ? v.publisherVerifiedId : v.ledger?.eventId) === event.id) return;
    seen.add(event.id);
    (kind === 'publisher' ? v.publisherEvents ??= new Map() : v.ledgerEvents ??= new Map()).set(event.id, event);
    this.queueRemote(v);
  }
  private async ingestObservedHeads(v: RuntimeVault): Promise<boolean> {
    const events = [...(v.headEvents?.values() ?? [])]; v.headEvents?.clear();
    let changed = false;
    for (const event of events) {
      if (v.records.has(event.id as EventId)) continue;
      try { if (await this.ingest(v, event)) changed = true; }
      catch (error) { await this.quarantineHead(v, event, error); this.fail(error, 'open', v); }
    }
    return changed;
  }
  private queueRemote(v: RuntimeVault): void {
    if (this.snapshot.lifecycle !== 'running' || !v.value.enabled || v.value.attachedAt === null || !v.caughtUp || v.remoteQueued) return;
    v.remoteQueued = true;
    void this.lane(v.value.vaultId, 'sync', async () => {
      try {
        if (!v.value.enabled || v.value.attachedAt === null) return;
        const ledger = [...(v.ledgerEvents?.values() ?? [])]; v.ledgerEvents?.clear();
        if (ledger.length) await this.readEpochLedger(v, ledger);
        const publisher = [...(v.publisherEvents?.values() ?? [])]; v.publisherEvents?.clear();
        if (publisher.length) await this.readPublisher(v, publisher);
        const changed = await this.ingestObservedHeads(v);
        if ((changed || ledger.length) && v.records.size) await this.reconcile(v);
      } finally { v.remoteQueued = false; }
    }).catch(() => {}).finally(() => {
      if (v.headEvents?.size || v.publisherEvents?.size || v.ledgerEvents?.size) this.queueRemote(v);
    });
  }
  private subscribeVault(v: RuntimeVault): void {
    if (!v.value.enabled || v.value.attachedAt === null) {
      v.subscription?.close(); v.publisherSub?.close(); v.ledgerSub?.close();
      v.headCatchup?.close(); v.ledgerCatchup?.close(); v.publisherCatchup?.close();
      v.headCatchup = v.ledgerCatchup = v.publisherCatchup = undefined;
      v.subscription = v.publisherSub = v.ledgerSub = undefined;
      v.subscriptionKey = v.auxiliaryKey = undefined; return;
    }
    const generation = this.generation;
    const valid = () => generation === this.generation && !this.abort.signal.aborted;
    const endpoints = v.value.network.readRelays.filter(url => !this.excluded('relay', url));
    if (!endpoints.length) return;
    const relay = this.relay(endpoints), endpointKey = JSON.stringify([...v.value.network.readRelays].sort());
    const authors = [...new Set([v.value.owner, ...(this.policy(v)?.writers ?? [])])].sort();
    const key = JSON.stringify([endpointKey, authors]);
    const onerror = (endpoint: string, error: VaultError) => { if (valid()) this.endpointResult('relay', endpoint, error); };
    if (v.subscriptionKey !== key) {
      v.subscription?.close(); v.headCatchup?.close(); v.subscriptionKey = key; v.caughtUp = false;
      const catchup = v.headCatchup = new AuthorityCatchup(endpoints, this.abort.signal);
      // Only a verified owner-policy/writer-set change replaces this historical REQ.
      v.subscription = relay.subscribe([{ kinds: [PORTHOME_HEAD_KIND], authors, '#d': [headDTag(v.value.vaultId)] }], {
        onevent: event => { if (valid()) this.observeHead(v, event); },
        oneose: endpoint => { if (valid()) { catchup.complete(endpoint); v.caughtUp = true; this.queueRemote(v); } },
        onerror: (endpoint, error) => { if (valid()) catchup.fail(endpoint, error); onerror(endpoint, error); },
      });
    }
    if (v.auxiliaryKey !== endpointKey) {
      v.publisherSub?.close(); v.ledgerSub?.close(); v.publisherCatchup?.close(); v.ledgerCatchup?.close(); v.auxiliaryKey = endpointKey;
      const ledgerCatchup = v.ledgerCatchup = new AuthorityCatchup(endpoints, this.abort.signal);
      const publisherCatchup = v.value.owner === this.session!.accountPubkey ? v.publisherCatchup = new AuthorityCatchup(endpoints, this.abort.signal) : undefined;
      v.ledgerSub = relay.subscribe([{ kinds: [PORTHOME_HEAD_KIND], authors: [v.value.owner], '#d': [historyDTag(v.value.vaultId)] }], {
        onevent: event => { if (valid()) this.observeAuxiliary(v, 'ledger', event); },
        oneose: endpoint => { if (valid()) ledgerCatchup.complete(endpoint); },
        onerror: (endpoint, error) => { if (valid()) ledgerCatchup.fail(endpoint, error); onerror(endpoint, error); },
      });
      if (v.value.owner === this.session!.accountPubkey) v.publisherSub = relay.subscribe([{ kinds: [ONYX_VAULT_PUBLISHER_KIND], authors: [v.value.owner], '#d': [publisherD(v.value.vaultId)] }], {
        onevent: event => { if (valid()) this.observeAuxiliary(v, 'publisher', event); },
        oneose: endpoint => { if (valid()) publisherCatchup!.complete(endpoint); },
        onerror: (endpoint, error) => { if (valid()) publisherCatchup!.fail(endpoint, error); onerror(endpoint, error); },
      });
    }
  }
  private async hashBytes(bytes: Uint8Array): Promise<Address> {
    return this.cpu.run(this.abort.signal, async () => {
      const job = this.worker!.run('hash', { parameters: {}, buffers: [new Uint8Array(bytes).buffer] }, { signal: this.abort.signal });
      let digest: Address | undefined;
      for await (const chunk of job.chunks) { this.check(); digest = hex32<Address>(bytesToHex(chunk)); }
      await job.result; this.check(); if (!digest) throw new VaultError('CRYPTO'); return digest;
    });
  }
  private async targetBytes(v: RuntimeVault, entry: Extract<NodeEntry, { kind: 'file' }>, ring: KeyRing): Promise<Uint8Array> {
    if (entry.sizePlain > 128n * 1024n * 1024n) throw new VaultError('TOO_LARGE', { operation: 'materialize' });
    const bytes = new Uint8Array(Number(entry.sizePlain)); let offset = 0;
    for (const chunk of entry.chunks) {
      const key = selectEpochKey(ring, chunk.chunkKeyId);
      try {
        const sealed = await this.readBlob(v, chunk.address); this.check();
        if (BigInt(sealed.length) !== chunk.sizeSealed) throw new VaultError('HASH_MISMATCH');
        await this.cpu.run(this.abort.signal, async () => {
          const job = this.worker!.openChunk({ sealed: new Uint8Array(sealed).buffer, nodeKey: key, epoch: chunk.chunkKeyId, expectedAddress: chunk.address, sizePlain: chunk.sizePlain }, { signal: this.abort.signal });
          for await (const plain of job.chunks) { this.check(); bytes.set(plain, offset); offset += plain.length; }
          await job.result;
        });
      } finally { key.fill(0); }
    }
    if (BigInt(offset) !== entry.sizePlain) throw new VaultError('IO'); return bytes;
  }
  private async targets(v: RuntimeVault, tree: VaultTree): Promise<readonly MaterializeTarget[]> {
    const root = tree.nodes[0];
    const addresses = [...new Set([sealDirectoryNode(root.node, last(root.ring.entries).nodeKey).address,
      ...tree.nodes.flatMap(n => n.node.entries.flatMap(e => e.kind === 'file' ? e.chunks.map(c => c.address) : e.kind === 'directory' ? [e.manifestAddress] : []))])];
    this.viewPins.set(v.value.vaultId, addresses); this.store!.setPins(`materialize:${v.value.vaultId}`, addresses);
    const result: MaterializeTarget[] = [];
    for (const [path, { node, entry, ring }] of pathsOf(tree)) {
      this.check();
      const digest = entryDigest(entry), held = v.value.baseline[path];
      const metadata = toStorage({ namePlain: entry.namePlain, nameEnc: entry.nameEnc, mode: entry.mode, mtimeNs: entry.mtimeNs, sizePlain: entry.sizePlain });
      // Same entry digest as the baseline: chunks, bytes and metadata are unchanged.
      // Nothing is downloaded, opened or hashed; bytes load lazily for conflict artifacts.
      if (held && held.kind === entry.kind && held.entryDigest === digest && entry.kind !== 'symlink' && (entry.kind !== 'file' || held.byteHash)) {
        result.push({ path, unchanged: true, baseline: { nodeId: node.nodeId, entryDigest: digest, byteHash: held.byteHash, kind: entry.kind, metadata, ...(held.disk ? { disk: held.disk } : {}) },
          ...(entry.kind === 'file' ? { load: () => this.targetBytes(v, entry, ring) } : {}) });
        continue;
      }
      const bytes = entry.kind === 'file' ? await this.targetBytes(v, entry, ring) : undefined;
      const byteHash = bytes ? await this.hashBytes(bytes) : null;
      result.push({ path, ...(bytes ? { bytes } : {}), baseline: { nodeId: node.nodeId, entryDigest: digest, byteHash, kind: entry.kind, metadata } });
    }
    return result;
  }
  /** Pointer-only changes still use a committed journal, never updateVault. */
  private async checkpointPointers(v: RuntimeVault, owner: VerifiedRecord, retained: readonly RetainedRoot[]): Promise<void> {
    const row = (await this.store!.read('vaults', [v.value.vaultId]))!; this.check();
    const op: StoredOperation = { ...version, vaultId: v.value.vaultId, operationId: this.id(), kind: 'publish', stage: 'prepared', candidate: { checkpointOnly: true, ownerId: owner.eventId, retained: toStorage(retained) }, signedEvent: null, pinnedAddresses: [], pendingAddress: null, uploadOutcomes: {}, relayOutcomes: {} };
    const rev = await this.store!.saveJournal(op, { ...row.value, pendingCandidateId: op.operationId }, { vault: row.revision, operation: 0 });
    this.check();
    await this.store!.saveJournal({ ...op, stage: 'committed' }, { ...row.value, ownerCheckpointId: owner.eventId, retainedRoots: retained, pendingCandidateId: null }, rev);
    await this.reload(v);
  }
  private async reconcile(v: RuntimeVault, preserveExisting = false, autoPublish = true): Promise<void> {
    this.emit({ activity: 'folding' });
    const identity = { vaultId: v.value.vaultId, nodeId: v.value.rootNodeId, owner: v.value.owner };
    const history = [...v.records.values()];
    const selected = selectFoldInputs(identity, history), owner = selected.records[selected.ownerIndex];
    // SV-35: floor and granted-root binding are settled before this checkpoint is used for anything.
    await this.noteCheckpoint(v, owner);
    const retained = retainRootEvidence(v.value.retainedRoots, history.map(r => r.head));
    const pointers = async () => { if (v.value.ownerCheckpointId !== owner.eventId || JSON.stringify(retained) !== JSON.stringify(v.value.retainedRoots)) await this.checkpointPointers(v, owner, retained); };
    const budgets = this.budgets();
    const checkpointChanges: { record: VerifiedRecord; pathEnc: string }[] = [];
    let folded: FoldResult;
    try { folded = foldCurrentHeads(identity, history, { ...this.foldLimits(),
      onCheckpointDifference: (record, pathEnc) => checkpointChanges.push({ record, pathEnc }) }); }
    catch (error) {
      if (error instanceof VaultError && error.code === 'TOO_LARGE') {
        // Dispositions, owner ambiguity and the checkpoint are settled before conflict
        // enumeration; keep the checkpoint pointer current so revoke can repair.
        await pointers(); await this.quarantineFold(v, 'conflict-rows', budgets.conflictRows, 0, null);
      }
      throw error;
    }
    if (!folded.viewRecordId) throw new VaultError('CONFLICT', { operation: 'fold' });
    await pointers();
    const view = v.records.get(folded.viewRecordId as unknown as EventId)!;
    let tree = v.trees.get(view.eventId)!;
    tree = await this.reconstructHistory(v, tree);
    v.trees.set(view.eventId, tree);
    await this.settings(v, { nodeRings: { ...v.value.nodeRings, ...treeRings(tree) } });
    const differences: PathConflict[] = [...folded.conflicts];
    if (view.writer !== v.value.owner && folded.frontier.length === 1) {
      const ownPaths = indexRecord(owner), selectedPaths = indexRecord(view);
      for (const { record, pathEnc } of checkpointChanges) if (record === view)
        differences.push({ pathEnc, otherRecordId: recordId(owner), inView: selectedPaths.has(pathEnc), inOther: ownPaths.has(pathEnc), writer: owner.writer, seq: owner.head.seq, rootManifest: owner.head.rootManifest });
    }
    const activeConflicts = new Set(differences.map(conflict => foldConflictId(v.value.vaultId, conflict)));
    const ownerAccepted = folded.dispositions.some(row => row.recordId === recordId(owner) && row.disposition === 'ACCEPTED');
    // SV-30/G1: every tree and record path list is indexed once per reconciliation.
    const indexOf = (_id: EventId, t: VaultTree): TreeIndex => indexTree(t);
    const pathsIndex = indexRecord;
    const viewIndex = indexOf(view.eventId, tree), viewPaths = pathsIndex(view);
    const vaultRows = (await this.store!.list('conflicts')).filter(row => row.value.vaultId === v.value.vaultId);
    const rowsById = new Map(vaultRows.map(row => [row.value.conflictId, { value: row.value, revision: row.revision }]));
    for (const row of vaultRows) {
      const held = row.value;
      // This id domain identifies fold rows, including pre-SV-20 rows. Local
      // divergence and blocked-materialization rows have independent identities.
      if (held.resolution === 'unresolved' && held.conflictId === foldConflictId(held.vaultId, held.conflict) && !activeConflicts.has(held.conflictId)) {
        const other = v.records.get(held.conflict.otherRecordId as unknown as EventId);
        const covered = ownerAccepted && owner.head.parents.some(parent => parent.writer === held.conflict.writer && BigInt(held.conflict.seq) <= parent.seq);
        const currentPath = viewPaths.get(held.conflict.pathEnc);
        const otherPath = other && pathsIndex(other).get(held.conflict.pathEnc);
        let pathsEqual = !!other && !!(currentPath || otherPath) && currentPath?.entryDigest === otherPath?.entryDigest;
        if (other && !currentPath && !otherPath && held.displayPath !== undefined) {
          // Rekeying changes path_enc even for a surviving file. Two missing
          // encrypted paths prove deletion only if both decoded paths are absent.
          const otherTree = v.trees.get(other.eventId);
          pathsEqual = !!otherTree && !viewIndex.byPath.has(held.displayPath) && !indexOf(other.eventId, otherTree).byPath.has(held.displayPath);
        }
        // A policy change can remove an unincorporated alternate from the fold.
        // Keep that unresolved choice until coverage or path equality retires it.
        if (covered || pathsEqual) {
          const retired: StoredConflict = { ...held, resolution: 'resolved', retiredByFold: true };
          const revision = await this.store!.put('conflicts', row.key, retired, row.revision);
          rowsById.set(held.conflictId, { value: retired, revision });
        }
      }
    }
    // SV-30: both persistence budgets are checked before any new row or artifact
    // exists. Overflow quarantines the fold; it never picks a winner or drops rows.
    const fresh = differences.filter(conflict => !rowsById.has(foldConflictId(v.value.vaultId, conflict)));
    let unresolved = 0, rowBytes = 0, artifactBytes = 0;
    for (const { value } of rowsById.values()) {
      rowBytes += conflictRowBytes(value); artifactBytes += value.artifactBytes ?? 0;
      if (value.resolution === 'unresolved' || value.retiredByFold && activeConflicts.has(value.conflictId)) unresolved++;
    }
    if (unresolved + fresh.length > budgets.conflictRows) await this.quarantineFold(v, 'conflict-rows', unresolved + fresh.length, rowBytes, folded.viewRecordId);
    const prepared: { id: string; value: StoredConflict; located: readonly [string, TreeItem] | undefined }[] = [];
    for (const conflict of fresh) {
      const id = foldConflictId(v.value.vaultId, conflict);
      const other = v.records.get(conflict.otherRecordId as unknown as EventId)!, otherTree = v.trees.get(other.eventId)!;
      const indexed = pathsIndex(other).get(conflict.pathEnc);
      const located = indexed ? indexOf(other.eventId, otherTree).byEntry.get(entryKey(indexed.nodeId, indexed.entryIndex)) : undefined;
      const viewIndexed = viewPaths.get(conflict.pathEnc);
      const viewLocation = viewIndexed ? viewIndex.byEntry.get(entryKey(viewIndexed.nodeId, viewIndexed.entryIndex)) : undefined;
      const displayPath = located?.[0] ?? viewLocation?.[0];
      const value: StoredConflict = { ...version, vaultId: v.value.vaultId, conflictId: id, conflict: toStorage(conflict), retainedVersions: retained.map(root => root.address), artifactRefs: [], resolution: 'unresolved',
        ...(displayPath ? { displayPath } : {}), kind: located?.[1].entry.kind === 'directory' ? 'directory' : !conflict.inOther ? 'deletion-only' : 'file' };
      rowBytes += conflictRowBytes(value); prepared.push({ id, value, located });
    }
    if (rowBytes > budgets.conflictBytes) await this.quarantineFold(v, 'conflict-bytes', unresolved + fresh.length, rowBytes, folded.viewRecordId);
    if (v.value.foldQuarantine) await this.settings(v, { foldQuarantine: null });
    for (const conflict of differences) {
      const held = rowsById.get(foldConflictId(v.value.vaultId, conflict));
      if (held && held.value.resolution === 'resolved' && held.value.retiredByFold) await this.store!.put('conflicts', [v.value.vaultId, held.value.conflictId], { ...held.value, resolution: 'unresolved', retiredByFold: false }, held.revision);
    }
    for (const { id, value, located } of prepared) {
      await this.store!.put('conflicts', [v.value.vaultId, id], value);
      const entry = located?.[1].entry;
      if (entry?.kind !== 'file') continue;
      const size = Number(entry.sizePlain);
      // The row stays resolvable from the record tree; only the readable sibling
      // copy is deferred once the aggregate artifact budget is reached.
      if (artifactBytes + size > budgets.conflictArtifactBytes) { await this.store!.put('conflicts', [v.value.vaultId, id], { ...value, artifactDeferred: true }); continue; }
      const artifactRoot = absolutePath(absolutePath(v.value.mount.notebookPath, v.value.mount.relativePath), `.onyx-vault-conflicts/${id}`);
      await ensureDirectory(this.session!.fs, this.session!.notebookPath, artifactRoot); this.check();
      const content = await this.targetBytes(v, entry, located![1].ring); this.check();
      let name = entry.namePlain; try { validateRelativePath(name); } catch { name = 'other'; }
      const artifact = `${artifactRoot}/${name}`;
      await this.session!.fs.writeBinary(artifact, content, this.session!.notebookPath); this.check();
      artifactBytes += size;
      await this.store!.put('conflicts', [v.value.vaultId, id], { ...value, artifactRefs: [artifact], artifactBytes: size });
    }
    this.foldProvisional(v, checkpointChanges, owner);
    if (v.value.materializedViewId !== folded.viewRecordId || preserveExisting) {
      this.emit({ activity: 'materializing' });
      const target = await this.targets(v, tree); this.check();
      await materialize(this.materializeContext(v.value.vaultId), v.value, target, folded.viewRecordId, { preserveExisting }); await this.reload(v);
    }
    await this.flushReadConfirmations(v);
    await this.refreshCounts(); this.subscribeVault(v); this.emit();
    if (autoPublish && v.value.owner === this.session!.accountPubkey && !folded.conflicts.length && !this.conflictCounts.get(v.value.vaultId)) {
      const ownPaths = pathsOf(v.trees.get(owner.eventId)!), viewPaths = pathsOf(tree);
      const identical = ownPaths.size === viewPaths.size && [...ownPaths].every(([p, n]) => viewPaths.has(p) && entryDigest(n.entry) === entryDigest(viewPaths.get(p)!.entry));
      if (identical && folded.frontier.some(id => id !== recordId(owner)) && v.value.publisher?.deviceId === this.account!.deviceId) {
        await this.assertPublisher(v);
        await this.publishTree(v, tree, 'publish', v.value.baseline, folded.frontier.map(id => v.records.get(id as unknown as EventId)!));
      }
    }
  }
  sync(id?: VaultId): Promise<void> {
    if (id) return this.lane(id, 'sync', () => this.syncVault(this.requireVault(id)));
    this.check(); return Promise.all([...this.vaults.keys()].map(id => this.sync(id))).then(() => {});
  }
  private async syncVault(v: RuntimeVault): Promise<void> {
    if (!v.value.enabled || v.value.attachedAt === null) return;
    if (!await this.session!.fs.exists(absolutePath(this.session!.notebookPath, v.value.mount.relativePath))) { await this.settings(v, { enabled: false }); throw new VaultError('IO', { operation: 'capture' }); }
    if (v.value.pendingCandidateId) {
      const op = (await this.store!.read('operations', [v.value.vaultId, v.value.pendingCandidateId]))!.value;
      if (op.kind === 'materialize' && !op.candidate.attachOnly) await resumeMaterialization(this.materializeContext(), op); else await this.resumePublication(v, op);
      await this.reload(v);
    }
    for (const row of await this.store!.list('operations')) if (row.value.vaultId === v.value.vaultId && row.value.stage === 'committed') await this.finishResolution(v, row.value);
    if (v.value.ownerCheckpointId === null && !v.records.size && v.value.grant === null) {
      if (v.value.owner !== this.session!.accountPubkey) throw new VaultError('INCOMPLETE');
      if (!v.value.publisherEvent) await this.designate(v);
      await this.captureAndPublish(v, 'create', [{ recipient: v.value.owner, cap: 'write' }]);
    } else {
      if (v.value.owner === this.session!.accountPubkey) await this.readPublisher(v);
      await this.backfill(v); await this.reconcile(v); await this.captureAndPublish(v);
    }
    // Committed head/delivery intents survive a crash in the post-OK gap.
    for (const row of await this.store!.list('operations')) if (row.value.vaultId === v.value.vaultId && row.value.stage === 'committed') { await this.finishResolution(v, row.value); await this.finishDeliveries(v, row.value); }
    if (v.value.owner === this.session!.accountPubkey && v.value.publisher?.deviceId === this.account!.deviceId && this.remainingBytes(v)) await this.resealPass(v, AUTO_RESEAL_BUDGET, 'lazy');
    this.emit();
  }
  private async captureLocal(v: RuntimeVault): Promise<void> {
    if (!v.value.enabled || v.value.attachedAt === null) return;
    if (!await this.session!.fs.exists(absolutePath(v.value.mount.notebookPath, v.value.mount.relativePath))) {
      await this.settings(v, { enabled: false }); this.subscribeVault(v); throw new VaultError('IO', { operation: 'capture' });
    }
    if (v.value.pendingCandidateId) {
      const op = (await this.store!.read('operations', [v.value.vaultId, v.value.pendingCandidateId]))!.value;
      if (op.kind === 'materialize' && !op.candidate.attachOnly) await resumeMaterialization(this.materializeContext(), op);
      else await this.resumePublication(v, op);
      await this.reload(v);
    }
    await this.captureAndPublish(v);
  }
  notifyFilesChanged(paths?: readonly string[]): void {
    if (this.snapshot.lifecycle !== 'running') return;
    const notebook = this.session!.notebookPath;
    const qualified = paths?.filter(path => !isReservedPath(path.replace(/\\/g, '/'))).map(path =>
      /^(?:[a-z]:[\\/]|[\\/])/i.test(path) || path === notebook || path.startsWith(notebook + '/') ? path : absolutePath(notebook, path));
    for (const mount of this.mounts()) {
      const registry = { getMounts: () => [mount] };
      if (!qualified || qualified.some(path => isManagedPath(path, registry) || intersectsManagedMount(path, registry))) this.dirtyVaults.add(mount.vaultId);
    }
    // No network or immediate I/O. ExpectedHashes are acknowledged during capture,
    // before deciding whether any candidate changed (including deletion echoes).
    if (this.dirtyVaults.size) this.coalescer?.notify();
  }
  private async startInbox(): Promise<void> {
    let endpoints: readonly string[];
    try { endpoints = await this.recipientRelays(this.session!.accountPubkey, this.session!.networkDefaults.readRelays); }
    catch (error) {
      if (!(error instanceof VaultError) || !['NETWORK', 'INCOMPLETE', 'UNSUPPORTED', 'AUTH'].includes(error.code)) throw error;
      endpoints = this.session!.networkDefaults.readRelays;
    }
    endpoints = [...new Set([...endpoints, ...this.session!.networkDefaults.readRelays])];
    const pubkeys = [this.session!.accountPubkey, ...await Promise.all(this.devices.map(d => d.getPublicKey()))];
    endpoints = [...new Set([...endpoints, ...(this.recipientRoutes.get(this.session!.accountPubkey) ?? [])])];
    this.inboxEndpoints = endpoints; this.inboxPubkeys = pubkeys;
    if (!this.inboxError) this.inboxSub = this.subscribeInbox(endpoints, pubkeys);
  }
  private closeInbox(): void {
    this.inboxSub?.close(); this.inboxSub = undefined;
    for (const sub of this.inboxExtra.values()) sub.close(); this.inboxExtra.clear();
  }
  /**
   * Rebuilds the replay tiers from the invitations store plus the stored list and,
   * if the stored list is not exactly the durable set (e.g. the unbounded pre-SEC-A
   * list of every kind-1059 ID), rewrites it once. Never throws for capacity: a full
   * durable tier latches an inbox notice while vaults keep loading and syncing.
   */
  private async restoreInboxReplay(stored: unknown, rejected: unknown): Promise<void> {
    if (this.unreadableInvitations) {
      // Fail closed: an unreadable invitation row's wrap IDs are indistinguishable
      // from legacy non-grant IDs, so keep every stored ID durable, do not rewrite
      // the list, and pause ingestion. Vaults keep loading and syncing.
      this.seenWraps.clear();
      for (const id of [...this.invitations.values()].flatMap(i => i.wrapIds)) this.seenWraps.add(id);
      for (const id of replayIds(stored)) this.seenWraps.add(id);
      for (const id of replayIds(rejected)) if (!this.seenWraps.has(id)) this.rejectedWraps.add(id);
      const error = new VaultError('STORAGE', { operation: 'accept', retryable: true });
      error.message = `${this.unreadableInvitations} stored invitation record${this.unreadableInvitations === 1 ? '' : 's'} could not be read. The invitation inbox is paused so no invitation decision is lost; shared vaults keep syncing. Use "Repair invitation inbox" to retry.`;
      this.stopInbox(error); return;
    }
    const { durable, transient, migrated } = partitionInboxReplay(stored, [...this.invitations.values()].flatMap(i => i.wrapIds), rejected);
    this.seenWraps.clear(); for (const id of durable) this.seenWraps.add(id);
    for (const id of transient) this.rejectedWraps.add(id);
    if (migrated) {
      try { await this.writeInbox(); }
      catch (error) { if (cancelled(error)) throw error; this.fail(error, 'accept'); }
    }
    if (inboxReplayFull(this.seenWraps.size)) this.latchInboxCapacity();
  }
  private latchInboxCapacity(): VaultError {
    this.inboxAtCapacity = true;
    return this.stopInbox(inboxReplayCapacityError());
  }
  private wrapSeen(id: string): boolean { return this.seenWraps.has(id) || this.rejectedWraps.has(id); }
  /**
   * Repair action for an inbox at capacity: recompute the durable tier from the
   * invitation rows (dropping legacy non-grant IDs into the transient tier), persist
   * it, and resume ingestion if there is room. Never evicts a grant decision.
   */
  repairInbox(): Promise<void> {
    return this.lane('inbox', 'accept', async () => {
      const row = await this.store!.read('accounts', []); this.check();
      const invitations = await this.store!.listTolerant('invitations'); this.check();
      for (const invitation of invitations.rows) this.invitations.set(invitation.value.rumorId, invitation.value);
      this.unreadableInvitations = invitations.failed.length;
      const stopped = this.inboxError;
      this.inboxError = undefined; this.inboxAtCapacity = false;
      try { await this.restoreInboxReplay(row?.value.config.inboxSeen, row?.value.config.inboxRejected); }
      catch (error) { this.inboxError ??= stopped; throw error; }
      if (this.inboxError) { this.emit(); return false; }
      this.inboxAbort = new AbortController();
      await this.startInbox(); this.check();
      this.emit({ condition: 'ready', lastError: null }); return true;
    }).then(resumed => resumed ? this.refreshInbox() : undefined);
  }
  private stopInbox(error: VaultError): VaultError {
    this.inboxError ??= error;
    this.inboxAbort.abort(); this.closeInbox(); this.fail(this.inboxError, 'accept');
    return this.inboxError;
  }
  private queueInbox(event: Event): Promise<void> {
    if (this.inboxError) return Promise.reject(this.inboxError);
    if (this.wrapSeen(event.id) || this.queuedWraps.has(event.id)) return Promise.resolve();
    let owned: Event, bytes: number;
    try { ({ event: owned, bytes } = boundedEvent(event)); }
    catch (error) { return Promise.reject(this.stopInbox(error instanceof VaultError ? error : new VaultError('AUTH'))); }
    if (this.queuedWraps.size >= VAULT_INGRESS_MAX_QUEUED_ITEMS || this.queuedWrapBytes + bytes > VAULT_INGRESS_MAX_QUEUED_BYTES) {
      return Promise.reject(this.stopInbox(new VaultError('BUDGET', { operation: 'accept' })));
    }
    this.queuedWraps.set(owned.id, bytes); this.queuedWrapBytes += bytes;
    // Startup retains at most the same budget as the running, serial inbox lane.
    if (this.snapshot.lifecycle === 'starting') { this.startupInbox.set(owned.id, owned); return Promise.resolve(); }
    return this.runQueuedWrap(owned);
  }
  private runQueuedWrap(event: Event): Promise<void> {
    const generation = this.generation;
    return this.lane('inbox', 'accept', () => this.receiveGrant(event)).finally(() => {
      if (generation !== this.generation) return;
      this.queuedWrapBytes -= this.queuedWraps.get(event.id) ?? 0; this.queuedWraps.delete(event.id);
    });
  }
  private subscribeInbox(endpoints: readonly string[], pubkeys: readonly string[]): VaultRelaySubscription {
    const generation = this.generation;
    return this.relay(endpoints).subscribe([this.inboxFilter(endpoints, pubkeys)], {
      onevent: event => {
        if (generation !== this.generation || this.abort.signal.aborted || this.wrapSeen(event.id)) return;
        void this.queueInbox(event).catch(() => {});
      },
      onerror: (endpoint, error) => { if (generation === this.generation && !this.abort.signal.aborted) this.endpointResult('relay', endpoint, error); },
    });
  }
  private async rememberSelfGrant(invitation: StoredInvitation): Promise<void> {
    const incoming = hydrateGrant(invitation.grant), session = this.session!;
    if (incoming.owner !== session.accountPubkey) throw new VaultError('POLICY');
    let v = this.vaults.get(incoming.vaultId);
    if (!v) {
      const stored = await this.store!.read('vaults', [incoming.vaultId]); this.check();
      if (stored) v = this.runtimeVault(stored.value);
    }
    if (v) {
      if (v.value.owner !== incoming.owner || v.value.rootNodeId !== incoming.nodeId) throw new VaultError('POLICY');
      const ring = mergeRings(this.rootRing(v), incoming.ring), held = v.value.grant && hydrateGrant(v.value.grant);
      const newest = !held || last(incoming.ring.entries).epoch > last(held.ring.entries).epoch ||
        last(incoming.ring.entries).epoch === last(held.ring.entries).epoch && incoming.issuedAt > held.issuedAt;
      await this.settings(v, { grant: toStorage({ ...(newest ? incoming : held!), ring }),
        ...(last(ring.entries).epoch > last(this.rootRing(v).entries).epoch ? { resealTotalBytes: null, resealProgress: null } : {}),
        nodeRings: { ...v.value.nodeRings, [incoming.nodeId]: toStorage(ring) },
        retainedRoots: retainRootEvidence([...(v.value.retainedRoots ?? []), incoming.rootManifest]) });
    } else {
      // Discovery stores keys only. No endpoint reads, filesystem writes, mount
      // attachment or epoch authority is inferred from a self-grant's root hint.
      const relays = incoming.hints.relays.length ? incoming.hints.relays : session.networkDefaults.readRelays;
      const blossom = incoming.hints.blossom.length ? incoming.hints.blossom : session.networkDefaults.readBlossom;
      const value: StoredVault = { ...version, vaultId: incoming.vaultId, rootNodeId: incoming.nodeId, owner: incoming.owner,
        mount: { notebookPath: session.notebookPath, relativePath: `Shared Vaults/${incoming.vaultId.slice(0, 12)}` }, label: incoming.vaultId.slice(0, 12),
        publisher: null, attachedAt: null, grant: toStorage(incoming), nodeRings: { [incoming.nodeId]: toStorage(incoming.ring) },
        network: validateNetwork({ readRelays: relays, writeRelays: relays, readBlossom: blossom, writeBlossom: blossom }), enabled: true,
        lastOwnSeq: '0', lastOwnWrittenAt: '0', ownerCheckpointId: null, materializedViewId: null, baseline: {}, pendingCandidateId: null,
        retainedRoots: retainRootEvidence([incoming.rootManifest]), deliveryLedger: [], resealProgress: null };
      await this.store!.createVault(value); this.check();
      this.vaults.set(value.vaultId, this.runtimeVault(value));
    }
    const accepted = { ...invitation, accepted: true, read: true };
    await this.store!.put('invitations', [incoming.vaultId, invitation.rumorId], accepted); this.check();
    this.invitations.set(invitation.rumorId, accepted);
  }
  private async receiveGrant(event: Event): Promise<void> {
    if (this.inboxError) throw this.inboxError;
    // The kind-1059 inbox is shared with DMs, other NIP-59 applications and
    // spam. A wrap that cannot be opened or validated is that event's defect,
    // not an account or endpoint condition; only a signer without NIP-44 is.
    if (this.wrapSeen(event.id) || this.openingWraps.has(event.id)) return;
    // Reserve durable capacity before verification/decryption or invitation writes:
    // any wrap might be a grant. The inbox lane has exactly one opener.
    if (inboxReplayFull(this.seenWraps.size)) throw this.latchInboxCapacity();
    this.openingWraps.add(event.id);
    try {
    let opened: OpenedGrant | null;
    try { opened = await openGrantWrap(event, this.session!.signer, this.devices); }
    catch (error) {
      this.check(); if (this.inboxError) throw this.inboxError;
      // Terminally invalid: rejected the same way on every sight, so only the
      // transient tier remembers it. It never consumes durable replay budget.
      if (error instanceof VaultError && !['UNSUPPORTED', 'CANCELLED'].includes(error.code)) { await this.rejectWrap(event.id); return; }
      throw error;
    }
    this.check(); if (this.inboxError) throw this.inboxError;
    if (!opened) { await this.rejectWrap(event.id); return; }
    const id = opened.rumor.id as EventId, previous = this.invitations.get(id);
    const value: StoredInvitation = previous ? { ...previous, wrapIds: [...new Set([...previous.wrapIds, event.id as EventId])] } : { ...version, vaultId: opened.grant.vaultId, grant: toStorage(opened.grant), rumorId: id, wrapIds: [event.id as EventId], read: false, dismissed: false, accepted: false };
    await this.store!.put('invitations', [value.vaultId, id], value); this.check(); this.invitations.set(id, value);
    if (opened.grant.owner === this.session!.accountPubkey) await this.lane(value.vaultId, 'accept', () => this.rememberSelfGrant(value));
    await this.completeWrap(event.id); this.emit();
    } finally { this.openingWraps.delete(event.id); }
  }
  private async rejectWrap(id: string): Promise<void> {
    this.rejectedWraps.add(id);
    await this.persistInbox();
  }
  private async completeWrap(id: string): Promise<void> {
    try { assertInboxReplayCapacity(this.seenWraps.size + Number(!this.seenWraps.has(id))); }
    catch { throw this.latchInboxCapacity(); }
    this.seenWraps.add(id); this.rejectedWraps.delete(id);
    try { await this.persistInbox(); } catch (error) { this.seenWraps.delete(id); throw error; }
  }
  share(id: VaultId, recipients: readonly Pubkey[], cap: VaultCapability, delivery: VaultDeliveryOptions): Promise<void> {
    return this.lane(id, 'share', async () => {
      const v = this.requireVault(id); await this.assertPublisher(v);
      if (cap !== 'read' && cap !== 'write') throw new VaultError('ARG');
      // Journal only the two known flags: callers may pass `undefined` fields or a wider summary.
      const options: VaultDeliveryOptions = { enabled: delivery?.enabled === true, allowIdentityFallback: delivery?.allowIdentityFallback === true };
      const members = [...new Set(recipients.map(p => hex32<Pubkey>(p)))];
      await this.backfill(v); await this.reconcile(v);
      await this.preserveLocalChanges(v);
      const checkpoint = this.checkpoint(v)!, old = v.trees.get(checkpoint.eventId)!, policy = checkpoint.root.vault!;
      const writers = new Set(policy.writers), readers = new Set(policy.readers);
      for (const member of members) {
        if (member === v.value.owner) continue;
        if (cap === 'write') { writers.add(member); readers.delete(member); }
        else { readers.add(member); writers.delete(member); }
      }
      const changed = [...writers].sort().join() !== [...policy.writers].sort().join() || [...readers].sort().join() !== [...policy.readers].sort().join();
      if (changed) {
        if (policy.grantsRev === UINT64_MAX) throw new VaultError('TOO_LARGE');
        const tree = createTree(old.nodes.map((n, i) => i ? n : { ...n, node: { ...n.node, vault: { ...policy, writers: [...writers], readers: [...readers], grantsRev: policy.grantsRev + 1n } } }));
        if (members.length) assertGrantWrapFits(this.grantFor(v, cap, tree, checkpoint.head.rootManifest), this.now());
        await this.publishTree(v, tree, 'policy', v.value.baseline, [], members.map(recipient => ({ recipient, cap })), options);
      } else for (const recipient of members) await this.deliver(v, this.grantFor(v, cap, old, checkpoint.head.rootManifest, Number(checkpoint.head.writtenAt)), recipient, options);
    });
  }
  private async mountInvitation(invitationId: EventId, relativePath: string, network: StoredNetwork, label: string | undefined, attach: boolean): Promise<VaultMount> {
    const invitation = this.invitations.get(invitationId); if (!invitation) throw new VaultError('ARG');
    const incoming = hydrateGrant(invitation.grant), session = this.session!;
    // Grant hints alone carry no verified historical-head epoch evidence.
    const invitationRoots = [...this.invitations.values()].filter(i => i.grant.owner === incoming.owner && i.grant.vaultId === incoming.vaultId && i.grant.nodeId === incoming.nodeId).map(i => i.grant.rootManifest);
    if (attach && incoming.owner !== session.accountPubkey) throw new VaultError('POLICY');
    let v = this.vaults.get(incoming.vaultId);
    const alreadyAttached = v?.value.attachedAt !== null && v !== undefined;
    const folder = validateMount(session.notebookPath, alreadyAttached && !attach ? v!.value.mount.relativePath : relativePath, this.mounts(), incoming.vaultId);
    const root = absolutePath(session.notebookPath, folder);
    if (alreadyAttached && !await session.fs.exists(root)) throw new VaultError('IO', { operation: 'attach' });
    if (await session.fs.exists(root) && !alreadyAttached) {
      await validateArtifactRoots(session.fs, root);
      if (!attach && (await session.fs.listAll(root)).length) throw new VaultError('CONFLICT');
    }
    let rearm = true;
    if (v) {
      if (v.value.owner !== incoming.owner || v.value.rootNodeId !== incoming.nodeId) throw new VaultError('POLICY');
      const ring = mergeRings(this.rootRing(v), incoming.ring);
      const latest = last(ring.entries).epoch;
      if (latest > last(incoming.ring.entries).epoch) throw new VaultError('EPOCH');
      const heldGrant = v.value.grant && hydrateGrant(v.value.grant);
      rearm = !heldGrant || heldGrant.issuedAt <= incoming.issuedAt;
      await this.settings(v, { grant: toStorage({ ...(heldGrant && heldGrant.issuedAt > incoming.issuedAt ? heldGrant : incoming), ring }),
        ...(latest > last(this.rootRing(v).entries).epoch ? { resealTotalBytes: null, resealProgress: null } : {}), nodeRings: { ...v.value.nodeRings, [incoming.nodeId]: toStorage(ring) }, retainedRoots: retainRootEvidence([...(v.value.retainedRoots ?? []), ...invitationRoots]) });
    } else {
      const value: StoredVault = { ...version, vaultId: incoming.vaultId, rootNodeId: incoming.nodeId, owner: incoming.owner,
        mount: { notebookPath: session.notebookPath, relativePath: folder }, label: label ?? last(folder.split('/')), publisher: null, attachedAt: null,
        grant: toStorage(incoming), nodeRings: { [incoming.nodeId]: toStorage(incoming.ring) }, network: validateNetwork(network), enabled: true,
        lastOwnSeq: '0', lastOwnWrittenAt: '0', ownerCheckpointId: null, materializedViewId: null, baseline: {}, pendingCandidateId: null,
        retainedRoots: retainRootEvidence([incoming.rootManifest, ...invitationRoots]), deliveryLedger: [], resealProgress: null };
      await this.store!.createVault(value); this.check();
      v = this.runtimeVault(value); this.vaults.set(value.vaultId, v); this.emit();
    }
    // The bootstrap is independently bound to the granted root and identity.
    const rootBytes = await this.readBlob(v, incoming.rootManifest);
    const rootNode = openDirectoryNode(incoming.ring, last(incoming.ring.entries).epoch, rootBytes);
    if (rootNode.nodeId !== incoming.nodeId || rootNode.vault?.owner !== incoming.owner || rootNode.vault?.vaultId !== incoming.vaultId) throw new VaultError('POLICY');
    // SV-35: the owner-authenticated granted root (address, epoch, grants_rev) is
    // the bootstrap freshness floor; plan §6.7 states the binding rule.
    if (rearm) await this.settings(v, { freshness: withGrant(this.freshnessOf(v), grantedFloor(incoming, rootNode.vault!.grantsRev)) });
    await this.loadRecords(v);
    await this.backfill(v);
    // Preflight all selected bytes before attaching the mount or writing notes.
    const bootstrap = [...v.records.values()], inputs = selectFoldInputs(incoming, bootstrap);
    await this.noteCheckpoint(v, inputs.records[inputs.ownerIndex]);
    const fold = foldCurrentHeads(incoming, bootstrap, this.foldLimits());
    if (!fold.viewRecordId) throw new VaultError('CONFLICT');
    const record = v.records.get(fold.viewRecordId as unknown as EventId)!;
    const recovered = await this.reconstructHistory(v, v.trees.get(record.eventId)!);
    v.trees.set(record.eventId, recovered); await this.targets(v, recovered);
    if (v.value.owner === session.accountPubkey) await this.readPublisher(v);
    await ensureDirectory(session.fs, session.notebookPath, root); this.check();
    if (!alreadyAttached && Object.keys(v.value.baseline).length || attach && v.value.mount.relativePath !== folder) await this.resetMount(v, folder);
    await this.settings(v, { mount: { notebookPath: session.notebookPath, relativePath: folder }, attachedAt: String(this.now()), enabled: true, ...(label ? { label } : {}) });
    await this.reconcile(v, attach);
    const accepted = { ...invitation, accepted: true, read: true };
    await this.store!.put('invitations', [incoming.vaultId, invitationId], accepted); this.check(); this.invitations.set(invitationId, accepted); this.emit();
    return { vaultId: incoming.vaultId, ...v.value.mount };
  }
  accept(invitationId: EventId, options: VaultMountOptions): Promise<VaultMount> {
    return this.lane('mounts', 'accept', async () => {
      if (options.trustConfirmed !== true || options.endpointsConfirmed !== true) throw new VaultError('POLICY');
      const invitation = this.invitations.get(invitationId); if (!invitation) throw new VaultError('ARG');
      const network = validateNetwork(options.network);
      // Approved fallback endpoints never replace the grant-hinted durability set.
      for (const hint of invitation.grant.hints.relays) validatePublicEndpoint(hint, 'wss:');
      for (const hint of invitation.grant.hints.blossom) validatePublicEndpoint(hint, 'https:');
      const existing = this.vaults.get(invitation.vaultId);
      let relative = existing?.value.attachedAt !== null && existing ? existing.value.mount.relativePath : options.relativePath;
      if (!relative) {
        const base = `Shared Vaults/${invitation.vaultId.slice(0, 12)}`; relative = base;
        let suffix = 1;
        while (await this.session!.fs.exists(absolutePath(this.session!.notebookPath, relative))) relative = `${base}-${suffix++}`;
      }
      return this.lane(invitation.vaultId, 'accept', () => this.mountInvitation(invitationId, relative!, network, options.label, false));
    });
  }
  private async resetMount(v: RuntimeVault, relativePath: string): Promise<void> {
    const row = (await this.store!.read('vaults', [v.value.vaultId]))!; this.check();
    const op: StoredOperation = { ...version, vaultId: v.value.vaultId, operationId: this.id(), kind: 'materialize', stage: 'prepared',
      candidate: { attachOnly: true, relativePath }, signedEvent: null, pinnedAddresses: [], pendingAddress: null, uploadOutcomes: {}, relayOutcomes: {} };
    const rev = await this.store!.saveJournal(op, { ...row.value, pendingCandidateId: op.operationId }, { vault: row.revision, operation: 0 }); this.check();
    await this.store!.saveJournal({ ...op, stage: 'committed' }, { ...row.value, baseline: {}, materializedViewId: null, attachedAt: String(this.now()), mount: { ...row.value.mount, relativePath }, pendingCandidateId: null }, rev);
    await this.reload(v);
  }
  attach(id: EventId | VaultId, folder: string): Promise<VaultMount> {
    return this.lane('mounts', 'attach', async () => {
      const v = this.vaults.get(id as VaultId);
      if (!v) {
        const invitation = this.invitations.get(id as EventId); if (!invitation) throw new VaultError('ARG');
        return this.lane(invitation.vaultId, 'attach', () => this.mountInvitation(id as EventId, folder, { readRelays: invitation.grant.hints.relays, writeRelays: invitation.grant.hints.relays,
          readBlossom: invitation.grant.hints.blossom, writeBlossom: invitation.grant.hints.blossom }, undefined, true));
      }
      return this.lane(v.value.vaultId, 'attach', async () => {
      if (v.value.owner !== this.session!.accountPubkey || v.value.pendingCandidateId) throw new VaultError('POLICY');
      const relativePath = validateMount(this.session!.notebookPath, folder, this.mounts(), v.value.vaultId);
      await this.readPublisher(v); await this.backfill(v);
      // Resetting the baseline is a journaled, explicit attach operation.
      const row = (await this.store!.read('vaults', [v.value.vaultId]))!;
      const op: StoredOperation = { ...version, vaultId: v.value.vaultId, operationId: this.id(), kind: 'materialize', stage: 'prepared',
        candidate: { attachOnly: true, relativePath }, signedEvent: null, pinnedAddresses: [], pendingAddress: null, uploadOutcomes: {}, relayOutcomes: {} };
      const rev = await this.store!.saveJournal(op, { ...row.value, pendingCandidateId: op.operationId }, { vault: row.revision, operation: 0 }); this.check();
      await this.store!.saveJournal({ ...op, stage: 'committed' }, { ...row.value, baseline: {}, materializedViewId: null, attachedAt: String(this.now()), mount: { ...row.value.mount, relativePath }, pendingCandidateId: null }, rev);
      await this.reload(v); await this.reconcile(v, true);
      return { vaultId: v.value.vaultId, ...v.value.mount };
      });
    });
  }
  revoke(id: VaultId, member: Pubkey): Promise<void> {
    return this.lane(id, 'revoke', async () => {
      const v = this.requireVault(id); await this.assertPublisher(v); hex32<Pubkey>(member);
      if (member === v.value.owner) throw new VaultError('POLICY');
      if (v.value.pendingCandidateId) {
        const pending = (await this.store!.read('operations', [id, v.value.pendingCandidateId]))!;
        if (pending.value.kind === 'reseal') {
          const row = (await this.store!.read('vaults', [id]))!;
          const allocated = pending.value.candidate.head as unknown as Persisted<VaultHead>;
          // An uncertain signed reseal may still arrive at a relay. Invalidate
          // its retry, but reserve its sequence/time so rotation cannot equivocate
          // or lose replaceable ordering to that late old-epoch publication.
          const seq = BigInt(allocated.seq), writtenAt = BigInt(allocated.writtenAt);
          await this.store!.saveJournal({ ...pending.value, stage: 'committed', relayOutcomes: { ...pending.value.relayOutcomes, invalidatedByRevoke: true } },
            { ...row.value, pendingCandidateId: null, resealProgress: null,
              lastOwnSeq: String(seq > BigInt(row.value.lastOwnSeq) ? seq : BigInt(row.value.lastOwnSeq)),
              lastOwnWrittenAt: String(writtenAt > BigInt(row.value.lastOwnWrittenAt) ? writtenAt : BigInt(row.value.lastOwnWrittenAt)) },
            { vault: row.revision, operation: pending.revision });
          await this.reload(v);
        } else {
          await this.resumePublication(v, pending.value); if (pending.value.kind === 'revoke') return;
        }
      }
      await this.backfill(v);
      // A conflict-budget quarantine must not block the repair it asks for.
      try { await this.reconcile(v); }
      catch (error) { if (!(error instanceof VaultError) || error.code !== 'TOO_LARGE' || error.operation !== 'fold') throw error; }
      const checkpoint = this.checkpoint(v)!, policy = checkpoint.root.vault!;
      if (!policy.writers.includes(member) && !policy.readers.includes(member)) return;
      const old = await this.reconstructHistory(v, v.trees.get(checkpoint.eventId)!);
      const rotated = revokeTree(old, checkpoint.head, this.session!.accountPubkey, member, BigInt(this.now()), () => this.random(32));
      const deliveries = [...new Set([...policy.writers, ...policy.readers])].filter(p => p !== member && p !== v.value.owner).map(recipient => ({ recipient, cap: policy.writers.includes(recipient) ? 'write' as const : 'read' as const }));
      deliveries.push({ recipient: v.value.owner, cap: 'write' });
      // Entire nested carrier is checked before rotation intent or network I/O.
      for (const d of deliveries) assertGrantWrapFits(this.grantFor(v, d.cap, rotated, checkpoint.head.rootManifest), this.now());
      await this.preserveLocalChanges(v);
      this.emit({ activity: 'revoking' });
      await this.publishTree(v, rotated, 'revoke', v.value.baseline, [], deliveries);
    });
  }
  reseal(id: VaultId, budget: bigint, mode: VaultResealMode): Promise<void> { return this.lane(id, 'reseal', () => this.resealPass(this.requireVault(id), budget, mode)); }
  private async resealPass(v: RuntimeVault, budget: bigint, mode: VaultResealMode): Promise<void> {
    if (mode !== 'lazy' && mode !== 'eager') throw new VaultError('ARG');
    await this.assertPublisher(v);
    const checkpoint = this.checkpoint(v); if (!checkpoint) throw new VaultError('INCOMPLETE');
    const tree = await this.reconstructHistory(v, v.trees.get(checkpoint.eventId)!);
    if (v.value.resealTotalBytes == null) await this.settings(v, { resealTotalBytes: String(this.remainingBytes(v, tree)) });
    const task = new ResealTask(treeResealItems(tree), mode === 'eager');
    this.emit({ activity: 'resealing' });
    try {
      try { await task.run(budget, { read: a => this.readBlob(v, a), put: async (bytes, address) => {
        // No externally visible PUT before publication's immutable candidate is journaled.
        this.check(); this.pinCapture(v, address); await this.cacheBlob(address, bytes);
      } }); } catch (error) { if (!(error instanceof VaultError) || error.code !== 'BUDGET') throw error; }
      if (!task.completed) { if (task.remaining && mode === 'eager') throw new VaultError('BUDGET'); return; }
      const candidates = new Map(task.snapshot().candidateNodes.map(n => [n.nodeId, n]));
      const next = createTree(tree.nodes.map(n => ({ ...n, node: candidates.get(n.node.nodeId) ?? n.node })));
      await this.publishTree(v, next, 'reseal');
      await this.settings(v, { resealProgress: task.remaining ? { remaining: treeResealItems(next).filter(i => { const e = i.node.entries[i.entry]; return e.kind === 'file' && e.chunks[i.chunk].chunkKeyId !== i.node.epoch; }).map(i => `${i.node.nodeId}:${i.entry}:${i.chunk}`), pendingAddress: task.pendingAddress } : null });
    } finally { task.dispose(); }
  }
  pause(id: VaultId): Promise<void> { return this.lane(id, 'sync', async () => { const v = this.requireVault(id); await this.settings(v, { enabled: false }); this.subscribeVault(v); }); }
  resume(id: VaultId): Promise<void> { return this.lane(id, 'sync', async () => { const v = this.requireVault(id); await this.settings(v, { enabled: true }); this.subscribeVault(v); await this.syncVault(v); }); }
  detach(id: VaultId): Promise<void> { return this.lane(id, 'detach', async () => { const v = this.requireVault(id); await this.settings(v, { enabled: false, attachedAt: null }); this.subscribeVault(v); }); }
  exportRecovery(id: VaultId) { return this.lane(id, 'recover', async () => {
    this.requireVault(id);
    if (!this.deps.requestRecoveryPassphrase) throw new VaultError('UNSUPPORTED', { operation: 'recover' });
    // Calibrate before prompting so the prompt can state the cost; derivation itself yields to the event loop.
    const logn = await calibrateRecoveryLogn(); this.check();
    const passphrase = await this.deps.requestRecoveryPassphrase({ suggested: generateRecoveryPassphrase(n => this.random(n)), minimumLength: RECOVERY_MIN_PASSPHRASE_LENGTH, logn, notes: RECOVERY_NOTES }); this.check();
    if (!passphrase) throw new VaultError('CANCELLED', { operation: 'recover' });
    assertRecoveryPassphrase(passphrase);
    const result = await this.store!.exportRecovery(id, passphrase, { logn }); this.check(); return result.package;
  }); }
  resolveConflicts(id: VaultId, resolutions: readonly VaultConflictResolution[]): Promise<void> {
    // Bind the command at invocation, before a queued live reconciliation can
    // replace the reviewed view while this mutation waits for the vault lane.
    const reviewedView = this.vaults.get(id)?.value.materializedViewId;
    const reviewedConflicts = (this.conflictRows.get(id) ?? []).map(c => c.conflictId).sort().join();
    return this.lane(id, 'resolve', async () => {
      const v = this.requireVault(id); await this.assertPublisher(v);
      if (!resolutions.length) throw new VaultError('ARG');
      for (const row of await this.store!.list('operations')) if (row.value.vaultId === id && row.value.stage === 'committed') await this.finishResolution(v, row.value);
      await this.backfill(v); await this.reconcile(v, false, false);
      if (v.value.materializedViewId !== reviewedView || (this.conflictRows.get(id) ?? []).map(c => c.conflictId).sort().join() !== reviewedConflicts) throw new VaultError('CONFLICT', { operation: 'resolve', retryable: true });
      const current = this.viewTree(v); if (!current) throw new VaultError('INCOMPLETE');
      type Model = Omit<CaptureDirectory, 'entries'> & { entries: Item[] };
      type Item = Exclude<CaptureEntry, { kind: 'directory' }> | (Omit<Extract<CaptureEntry, { kind: 'directory' }>, 'child'> & { child: Model });
      const modelFor = (tree: VaultTree, nodeId = tree.nodes[0].node.nodeId): Model => {
        const item = tree.nodes.find(n => n.node.nodeId === nodeId)!;
        return { nodeId, epoch: item.node.epoch, ring: item.ring, ...(item.node.vault ? { vault: item.node.vault } : {}), entries: item.node.entries.map((e): Item =>
          e.kind === 'directory' ? { ...e, child: modelFor(tree, e.childNodeId) } : { ...e }) };
      };
      const root = modelFor(current);
      const adoptDirectory = async (sourceTree: VaultTree, nodeId: NodeId, destination: Model | undefined, parent: Model): Promise<Model> => {
        const source = sourceTree.nodes.find(n => n.node.nodeId === nodeId)!;
        if (source.node.vault) throw new VaultError('UNSUPPORTED');
        let target = destination;
        if (!target) {
          const id = hex32<NodeId>(this.id()), key = deriveChildNodeKey(last(parent.ring!.entries).nodeKey, id);
          target = { nodeId: id, epoch: parent.epoch, ring: initRing(parent.epoch, key), entries: [] }; key.fill(0);
        }
        const previous = new Map(target.entries.map(entry => [entry.namePlain, entry])), entries: Item[] = [];
        for (const entry of source.node.entries) {
          if (entry.kind === 'directory') {
            const old = previous.get(entry.namePlain);
            const child = await adoptDirectory(sourceTree, entry.childNodeId, old?.kind === 'directory' ? old.child : undefined, target);
            entries.push({ ...entry, child, keyOverride: bytes32(last(child.ring!.entries).nodeKey) });
          } else if (entry.kind === 'file') {
            const reusable = entry.chunks.every(chunk => {
              const old = source.ring.entries.find(e => e.epoch === chunk.chunkKeyId), current = target!.ring!.entries.find(e => e.epoch === chunk.chunkKeyId);
              return old && current && equalBytes(old.nodeKey, current.nodeKey);
            });
            entries.push(reusable ? { ...entry } : await this.resolutionFile(v, target, entry.namePlain, await this.targetBytes(v, entry, source.ring)));
          } else entries.push({ ...entry });
        }
        target.entries = entries; return target;
      };
      const rows = (await this.store!.list('conflicts')).filter(r => r.value.vaultId === id && r.value.resolution === 'unresolved');
      const chosen = new Map(resolutions.map(r => [r.conflictId, r]));
      if (chosen.size !== resolutions.length || resolutions.some(r => !rows.some(row => row.value.conflictId === r.conflictId))) throw new VaultError('ARG');
      const pathOf = (row: typeof rows[number]): string => {
        if (row.value.displayPath) return row.value.displayPath;
        const c = row.value.conflict;
        const record = v.records.get(c.otherRecordId as unknown as EventId);
        const match = record?.paths.find(p => p.pathEnc === c.pathEnc);
        if (match && record) {
          const tree = v.trees.get(record.eventId)!;
          const found = [...pathsOf(tree)].find(([, item]) => item.node.nodeId === match.nodeId && item.node.entries[match.entryIndex] === item.entry);
          if (found) return found[0];
        }
        return validateRelativePath(c.pathEnc);
      };
      const selected = rows.filter(row => chosen.has(row.value.conflictId)).map(row => ({ row, path: pathOf(row), choice: chosen.get(row.value.conflictId)! })).sort((a, b) => a.path.length - b.path.length);
      const directoryChoices: string[] = [], applied: string[] = [];
      for (const { row, path, choice } of selected) {
        if (directoryChoices.some(p => path.startsWith(p + '/'))) continue;
        const parts = validateRelativePath(path).split('/'); const name = parts.pop()!;
        let parent = root;
        for (const part of parts) { const dir = parent.entries.find(e => e.namePlain === part); if (!dir || dir.kind !== 'directory') throw new VaultError('CONFLICT'); parent = dir.child; }
        const index = parent.entries.findIndex(e => e.namePlain === name), old = parent.entries[index];
        let replacement: Item | undefined = old;
        if (choice.action === 'delete') replacement = undefined;
        else if (choice.action === 'use-other' || choice.action === 'keep-both') {
          const otherTree = v.trees.get(row.value.conflict.otherRecordId as unknown as EventId);
          const other = otherTree && pathsOf(otherTree).get(path);
          const localSibling = row.value.artifactRefs.find(p => p.endsWith('/local'));
          if (localSibling) {
            const bytes = await this.session!.fs.readBinary(localSibling, this.session!.notebookPath);
            replacement = await this.resolutionFile(v, parent, name, bytes);
          } else if (!other) replacement = undefined;
          else if (other.entry.kind === 'directory') {
            const child = await adoptDirectory(otherTree!, other.entry.childNodeId, choice.action !== 'keep-both' && old?.kind === 'directory' ? old.child : undefined, parent);
            replacement = { ...other.entry, child, keyOverride: bytes32(last(child.ring!.entries).nodeKey) };
          } else replacement = { ...other.entry };
          if (replacement?.kind === 'file' && other) {
            const destination = parent.ring!;
            const reusable = replacement.chunks.every(chunk => {
              const source = other.ring.entries.find(e => e.epoch === chunk.chunkKeyId), target = destination.entries.find(e => e.epoch === chunk.chunkKeyId);
              return source && target && equalBytes(source.nodeKey, target.nodeKey);
            });
            if (!reusable) replacement = await this.resolutionFile(v, parent, name, await this.targetBytes(v, other.entry as Extract<NodeEntry, { kind: 'file' }>, other.ring));
          }
          if (choice.action === 'keep-both') {
            validateRelativePath(choice.newBasename);
            if (choice.newBasename.includes('/') || parent.entries.some(e => e.namePlain === choice.newBasename) || !replacement) throw new VaultError('CONFLICT');
            parent.entries.push({ ...replacement, namePlain: choice.newBasename }); applied.push(path); continue;
          }
        } else if (choice.action === 'manual-merge') replacement = await this.resolutionFile(v, parent, name, choice.bytes);
        if (old?.kind === 'directory' || replacement?.kind === 'directory') directoryChoices.push(path);
        if (index >= 0) parent.entries.splice(index, 1);
        if (replacement) parent.entries.push(replacement);
        applied.push(path);
      }
      const resolvedIds = new Set(selected.map(s => s.row.value.conflictId));
      for (const row of rows) if (directoryChoices.some(dir => pathOf(row).startsWith(dir + '/'))) resolvedIds.add(row.value.conflictId);
      const otherIds = [...new Set(selected.map(s => s.row.value.conflict.otherRecordId))].filter(other => rows.filter(r => r.value.conflict.otherRecordId === other).every(r => resolvedIds.has(r.value.conflictId)));
      if (rows.every(row => resolvedIds.has(row.value.conflictId))) {
        const fold = foldCurrentHeads({ vaultId: id, nodeId: v.value.rootNodeId, owner: v.value.owner }, [...v.records.values()]);
        otherIds.push(...fold.frontier.filter(id => !otherIds.includes(id)));
      }
      const eligible = new Set(foldCurrentHeads({ vaultId: id, nodeId: v.value.rootNodeId, owner: v.value.owner }, [...v.records.values()]).dispositions.filter(d => d.disposition === 'ACCEPTED').map(d => d.recordId));
      const incorporated = otherIds.filter(id => eligible.has(id)).map(id => v.records.get(id as unknown as EventId)).filter((r): r is VerifiedRecord => !!r);
      const tree = captureTree(root, current.nodes[0].ring);
      await this.publishTree(v, tree, 'publish', v.value.baseline, incorporated, [], {}, { resolvedPaths: applied, conflictIds: [...resolvedIds] });
    });
  }
  private async resolutionFile(v: RuntimeVault, parent: CaptureDirectory, name: string, bytes: Uint8Array): Promise<Extract<CaptureEntry, { kind: 'file' }>> {
    const ring = parent.ring!; const key = last(ring.entries);
    const chunks = await this.cpu.run(this.abort.signal, async () => {
      const job = this.worker!.sealChunks({ buffer: new Uint8Array(bytes).buffer, nodeKey: key.nodeKey, epoch: key.epoch }, { signal: this.abort.signal });
      const chunks = [];
      for await (const c of job.chunks) {
        this.check(); this.pinCapture(v, c.address); await this.cacheBlob(c.address, c.sealed);
        chunks.push({ address: c.address, sizeSealed: c.sizeSealed, chunkKeyId: c.chunkKeyId, sizePlain: c.sizePlain });
      }
      await job.result; return chunks;
    });
    return { kind: 'file', namePlain: name, mode: 0o644, mtimeNs: BigInt(this.now()) * 1000000000n, chunks };
  }
  private inboxFilter(endpoints: readonly string[], pubkeys: readonly string[]): Filter {
    const watermarks = this.account?.config.inboxWatermarks as Record<string, number> | undefined;
    const since = Math.min(...endpoints.map(endpoint => watermarks?.[endpoint] ?? 0));
    // NIP-59 timestamps are randomised up to two days into the past. New
    // endpoints have no watermark and must first complete historical paging.
    return { kinds: [VAULT_GIFT_WRAP_KIND], '#p': [...pubkeys], ...(since ? { since: Math.max(0, since - 2 * 86400) } : {}) };
  }
  private persistInbox(completed: readonly string[] = [], checkpoint = 0): Promise<void> {
    return this.lane('device-keys', 'store', () => this.writeInbox(completed, checkpoint));
  }
  /** Revision-checked account write; also used during startup, before lanes open. */
  private async writeInbox(completed: readonly string[] = [], checkpoint = 0): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      if (this.inboxError) throw this.inboxError;
      const row = (await this.store!.read('accounts', []))!; this.check();
      if (this.inboxError) throw this.inboxError;
      const watermarks = { ...(row.value.config.inboxWatermarks as Record<string, number> | undefined) };
      for (const endpoint of completed) watermarks[endpoint] = Math.max(watermarks[endpoint] ?? 0, checkpoint);
      // Durable tier only. Every ID here is also in an invitation row; a legacy
      // over-capacity set of grant IDs is written whole rather than evicted.
      const inboxSeen = [...this.seenWraps], inboxRejected = this.rejectedWraps.values();
      const value = { ...row.value, config: { ...row.value.config, inboxSeen, inboxRejected, inboxWatermarks: watermarks } };
      try {
        await this.store!.put('accounts', [], value, row.revision); this.check(); this.account = value;
        // The final available decision is durable before the capacity latch.
        // Do not throw here: completeWrap must not undo its in-memory marker.
        if (inboxReplayFull(inboxSeen.length)) this.latchInboxCapacity();
        return;
      }
      catch (error) { if (!(error instanceof VaultError) || error.code !== 'CONFLICT' || attempt >= 7) throw error; }
    }
  }
  refreshInbox(): Promise<void> { return this.refreshInboxFrom(); }
  private refreshInboxFrom(selected?: readonly string[]): Promise<void> {
    // The network wave must not hold the opener lane. Stream primary and late
    // history through the very same admission budget as live frames.
    return this.lane('inbox-backfill', 'accept', async () => {
      if (this.inboxError) throw this.inboxError;
      const generation = this.generation;
      const endpoints = selected ?? (this.inboxEndpoints.length ? this.inboxEndpoints : await this.recipientRelays(this.session!.accountPubkey, this.session!.networkDefaults.readRelays));
      const pubkeys = [this.session!.accountPubkey, ...await Promise.all(this.devices.map(d => d.getPublicKey()))];
      const checkpoint = this.now(), completed: string[] = [], pending = new Set<Promise<void>>();
      let returned = false, failure: unknown;
      const check = () => { this.check(generation); if (this.inboxError) throw this.inboxError; if (failure) throw failure; };
      const finish = async (sources: readonly string[]) => {
        await Promise.all([...pending]); check(); await this.persistInbox(sources, checkpoint); check();
      };
      try {
        await this.relay(endpoints).backfill([this.inboxFilter(endpoints, pubkeys)], {
          onevent: event => {
            if (generation !== this.generation || this.abort.signal.aborted || this.inboxError || this.wrapSeen(event.id) || this.queuedWraps.has(event.id)) return;
            const task = this.queueInbox(event); pending.add(task);
            void task.then(() => pending.delete(task), error => { pending.delete(task); failure ??= error; });
          },
          oneose: endpoint => {
            if (generation !== this.generation || this.abort.signal.aborted) return;
            this.endpointResult('relay', endpoint);
            if (returned) void finish([endpoint]).catch(error => { if (generation === this.generation) this.fail(error, 'accept'); });
            else completed.push(endpoint);
          },
          onerror: (endpoint, error) => { if (generation === this.generation && !this.abort.signal.aborted) this.endpointResult('relay', endpoint, error); },
        }, this.inboxAbort.signal);
      } catch (error) { check(); throw error; }
      returned = true; await finish(completed);
    });
  }
}

registerVaultEngineFactory(deps => new HeadlessVaultEngine(deps));
