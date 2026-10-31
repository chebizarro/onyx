import type { Event as NostrEvent } from 'nostr-tools';

declare const hexBrand: unique symbol;
declare const bytes32Brand: unique symbol;
/** Only validation boundaries may construct these lowercase-hex brands. */
type Hex<Purpose extends string> = string & { readonly [hexBrand]: Purpose };
export type VaultId = Hex<'VaultId'>;
export type NodeId = Hex<'NodeId'>;
export type Pubkey = Hex<'Pubkey'>;
export type Address = Hex<'Address'>;
export type EventId = Hex<'EventId'>;
export type RecordId = Hex<'RecordId'>;
export type HeadHash = Hex<'HeadHash'>;
export type RefState = Hex<'RefState'>;
export type EntryDigest = Hex<'EntryDigest'>;
/** A 24-byte keyed name index, represented as 48 lowercase hex characters. */
export type NameEnc = Hex<'NameEnc'>;
/** Owned, validated 32-byte buffer; callers must copy at ownership boundaries. */
export type Bytes32 = Uint8Array & { readonly [bytes32Brand]: true };
/** Range is validated by codecs; never round-trip through a JS number. */
export type Uint64 = bigint;

export interface EpochKey {
  readonly epoch: Uint64;
  readonly nodeKey: Bytes32;
}
export interface KeyRing {
  readonly entries: readonly EpochKey[];
}
export interface VaultPolicy {
  readonly vaultId: VaultId;
  readonly owner: Pubkey;
  readonly writers: readonly Pubkey[];
  readonly readers: readonly Pubkey[];
  readonly grantsRev: Uint64;
}
export interface ChunkRef {
  readonly address: Address;
  readonly sizeSealed: Uint64;
  readonly chunkKeyId: Uint64;
  readonly sizePlain: Uint64;
}
export interface EntryMeta {
  readonly nameEnc: NameEnc;
  readonly namePlain: string;
  /** Validated unsigned 32-bit number. */
  readonly mode: number;
  readonly mtimeNs: Uint64;
  readonly sizePlain: Uint64;
}
export type NodeEntry = EntryMeta & (
  | { readonly kind: 'file'; readonly chunks: readonly ChunkRef[] }
  | {
      readonly kind: 'directory';
      readonly childNodeId: NodeId;
      readonly childEpoch: Uint64;
      readonly manifestAddress: Address;
      readonly keyOverride?: Bytes32;
    }
  | { readonly kind: 'symlink'; readonly target: string }
);
export interface DirectoryNode {
  readonly version: 2;
  readonly nodeId: NodeId;
  readonly epoch: Uint64;
  /** Supplied order is wire-significant; do not sort imported entries. */
  readonly entries: readonly NodeEntry[];
  readonly vault?: VaultPolicy;
}
export interface HeadParent {
  readonly writer: Pubkey;
  readonly seq: Uint64;
  readonly rootManifest: Address;
}
export interface VaultHead {
  readonly vaultId: VaultId;
  readonly epoch: Uint64;
  readonly rootManifest: Address;
  readonly refState?: RefState;
  readonly keyOverride?: Bytes32;
  readonly seq: Uint64;
  readonly parents: readonly HeadParent[];
  readonly grantsRev: Uint64;
  readonly writtenAt: Uint64;
}
export interface VaultGrant {
  readonly vaultId: VaultId;
  readonly nodeId: NodeId;
  readonly ring: KeyRing;
  readonly cap: 'read' | 'write';
  readonly owner: Pubkey;
  readonly rootManifest: Address;
  readonly hints: {
    readonly relays: readonly string[];
    readonly blossom: readonly string[];
  };
  readonly issuedAt: Uint64;
}
/** Unsigned Nostr rumor. A nonempty signature is invalid for a grant. */
export type GrantRumor = Omit<NostrEvent, 'sig'> & { readonly sig?: string };

/** Caller-owned addressed I/O. A resolved put means durable, hash-verified acceptance. */
export interface VaultBlobIO {
  read(address: Address): Uint8Array | Promise<Uint8Array>;
  put(sealed: Uint8Array, address: Address): void | Promise<void>;
}
export interface ManifestObject {
  readonly sealed: Uint8Array;
  readonly ring: KeyRing;
  readonly epoch: Uint64;
  /** When supplied, verify this requested address before opening. */
  readonly address?: Address;
}
export interface VaultTreeNode {
  readonly node: DirectoryNode;
  readonly ring: KeyRing;
}
/** Closed rooted graph, root at index zero; buffers are owned by this candidate. */
export interface VaultTree {
  readonly nodes: readonly VaultTreeNode[];
}

export interface RecordPath {
  readonly pathEnc: string;
  readonly entryDigest: EntryDigest;
  readonly nodeId: NodeId;
  readonly entryIndex: number;
}
export interface VerifiedRecord {
  readonly eventId: EventId;
  readonly signedEvent: NostrEvent;
  readonly writer: Pubkey;
  readonly head: VaultHead;
  readonly canonicalHeadHash: HeadHash;
  readonly root: DirectoryNode;
  readonly nodesById: ReadonlyMap<NodeId, DirectoryNode>;
  /** Sorted by encrypted path. */
  readonly paths: readonly RecordPath[];
}
export type Disposition = 'ACCEPTED' | 'NONWRITER' | 'STALE' | 'POLICY' | 'DUPLICATE';
export interface PathConflict {
  readonly pathEnc: string;
  readonly otherRecordId: RecordId;
  /** C in_owner; the selected view is not necessarily owner-authored. */
  readonly inView: boolean;
  readonly inOther: boolean;
  readonly writer: Pubkey;
  readonly seq: Uint64;
  readonly rootManifest: Address;
}
export interface FoldResult {
  readonly viewRecordId: RecordId | null;
  readonly frontier: readonly RecordId[];
  readonly dispositions: readonly { readonly recordId: RecordId; readonly disposition: Disposition }[];
  readonly conflicts: readonly PathConflict[];
  readonly retainedRoots: readonly Address[];
}

/** Public, key-free mount information for legacy exclusion and UI integration. */
export interface VaultMount {
  readonly vaultId: VaultId;
  readonly notebookPath: string;
  readonly relativePath: string;
}
export interface MountRegistry {
  getMounts(): readonly VaultMount[];
}

/** Storage DTOs deliberately do not hydrate integers or key buffers implicitly. */
export type Persisted<T> = T extends string | number | boolean | null ? T
  : T extends bigint ? string
  : T extends Uint8Array ? string
  : T extends ReadonlyMap<infer K, infer V> ? Record<Extract<K, string>, Persisted<V>>
  : T extends readonly (infer V)[] ? readonly Persisted<V>[]
  : T extends object ? { readonly [K in keyof T]: Persisted<T[K]> }
  : T;
export type StorageJson = null | boolean | number | string | readonly StorageJson[]
  | { readonly [key: string]: StorageJson };
export interface StoredVersion {
  readonly schemaVersion: 1;
  readonly protocolId: 'porthome/v2';
}
/**
 * Per-recipient NIP-4E announcement pin. Rollback protection only: it refuses observations
 * older than what this account already saw and records which fingerprint the user approved.
 * It cannot prove that the recipient has not rotated since (relay omission is not evidence).
 */
export interface StoredDeviceAnnouncement {
  /** Newest identity-signed kind-10044 observed, by replaceable ordering (created_at desc, id asc). */
  readonly eventId: string;
  readonly createdAt: number;
  /** Key announced by that event; null when the newest signed announcement withdrew/invalidated it. */
  readonly encryptionKey: Pubkey | null;
  /** Fingerprint explicitly approved for delivery; null until the user approves one. */
  readonly approvedKey: Pubkey | null;
  /** Local unix seconds of the last observation. */
  readonly observedAt: number;
}
export interface StoredAccount extends StoredVersion {
  readonly deviceId: string;
  readonly deviceLabel: string;
  readonly deviceKeyHistory: readonly StorageJson[];
  readonly config: Readonly<Record<string, StorageJson>>;
  /** Recipient identity pubkey → announcement pin (SV-33). Absent on rows written before pins existed. */
  readonly deviceAnnouncements?: Readonly<Record<string, StoredDeviceAnnouncement>>;
}
export interface StoredNetwork {
  readonly readRelays: readonly string[];
  readonly writeRelays: readonly string[];
  readonly readBlossom: readonly string[];
  readonly writeBlossom: readonly string[];
}
/** Disk stat observed when `byteHash` was last computed. `modified` is the
 * platform's whole-second mtime as a decimal string; `observedAt` is the wall
 * clock second of the hash. A stat is only trusted when it is strictly older
 * than its observation (git's racy-mtime rule), so a same-second edit re-hashes. */
export interface StoredDiskStat {
  readonly size: number;
  readonly modified: string;
  readonly observedAt: number;
}
export interface StoredBaselineEntry {
  readonly nodeId: NodeId;
  readonly entryDigest: EntryDigest;
  readonly byteHash: Address | null;
  readonly kind: NodeEntry['kind'];
  readonly metadata: Persisted<EntryMeta>;
  /** Present for files whose bytes were hashed from disk; absent for directories/symlinks. */
  readonly disk?: StoredDiskStat;
}
export interface StoredDelivery {
  readonly cap?: VaultGrant['cap'];
  readonly issuedAt?: string;
  readonly relayOutcomes?: readonly { readonly relay: string; readonly status: 'accepted' | 'rejected' | 'unknown'; readonly reason?: string }[];
  readonly recipient: Pubkey;
  readonly envelopeKey: Pubkey;
  readonly rumorId: EventId;
  readonly wrapIds: readonly EventId[];
  readonly acknowledged: readonly string[];
  readonly pending: readonly string[];
  /** Exact prepared envelope retained for retry after an unknown outcome. */
  readonly signedWrap?: NostrEvent;
  /** Why the identity key was used although device delivery was requested (SV-33). */
  readonly notice?: 'no-announcement' | 'unapproved' | 'key-changed' | 'withdrawn';
  /** What the relay view showed relative to the pinned announcement at delivery time. */
  readonly evidence?: 'none' | 'stale' | 'current' | 'fresh';
}
/** SV-35: durable sequence high-water per author with canonical-body evidence
 * at that sequence (several hashes = equivocation evidence), independent of
 * retained record blobs. */
export interface StoredAuthorHighWater {
  readonly seq: string;
  readonly hashes: readonly string[];
}
/** Granted-root floor: one owner-authenticated root address plus the (epoch,
 * grants_rev) it was issued at. A root address is an identity, not an ordinal. */
export interface StoredFreshnessGrant {
  readonly rootManifest: Address;
  readonly epoch: string;
  /** Revision read from the authenticated granted root node; null when unknown (migration). */
  readonly grantsRev: string | null;
}
export interface StoredFreshness {
  readonly authors: Readonly<Record<string, StoredAuthorHighWater>>;
  /** Last accepted owner checkpoint; a hard floor for every later fold. */
  readonly checkpoint: { readonly seq: string; readonly epoch: string; readonly grantsRev: string; readonly rootManifest: Address; readonly headHash: string } | null;
  readonly granted: StoredFreshnessGrant | null;
  /** False until a checkpoint is shown to be, or follow, the granted root (`freshness-unverified`). */
  readonly verified: boolean;
}
/** SV-30: a fold whose conflict output exceeded a local budget. The previous
 * materialised view is kept; nothing from this fold was persisted or chosen. */
export interface StoredFoldQuarantine {
  readonly reason: 'conflict-rows' | 'conflict-bytes';
  readonly rows: number;
  readonly bytes: number;
  readonly viewRecordId: RecordId | null;
}
/** Legacy addresses have no epoch authority and may not be opened. */
export type RetainedRoot = { readonly address: Address; readonly epoch: string | null };
export type StoredRetainedRoot = RetainedRoot | Address;

export interface StoredVault extends StoredVersion {
  readonly vaultId: VaultId;
  readonly rootNodeId: NodeId;
  readonly owner: Pubkey;
  readonly mount: { readonly notebookPath: string; readonly relativePath: string };
  readonly label: string;
  readonly publisher: { readonly deviceId: string; readonly deviceLabel: string; readonly since: string } | null;
  readonly attachedAt: string | null;
  /** Exact local designation evidence, retained across uncertain publication. */
  readonly publisherEvent?: NostrEvent;
  readonly publisherPending?: boolean;
  readonly grant: Persisted<VaultGrant> | null;
  readonly nodeRings: Readonly<Record<string, Persisted<KeyRing>>>;
  readonly network: StoredNetwork;
  readonly enabled: boolean;
  readonly lastOwnSeq: string;
  readonly lastOwnWrittenAt: string;
  readonly ownerCheckpointId: EventId | null;
  readonly materializedViewId: RecordId | null;
  readonly baseline: Readonly<Record<string, StoredBaselineEntry>>;
  readonly pendingCandidateId: string | null;
  /** Durable local-only proposal, separate from an externally committed journal. */
  readonly captureErrors?: readonly { readonly path: string; readonly code: 'TOO_LARGE' }[];
  readonly objectWarnings?: readonly { readonly address: Address; readonly code: 'HASH_MISMATCH' }[];
  /** Per-address write-server confirmations from positive HEAD/PUT; independent of cache eviction. */
  readonly confirmedObjects?: Readonly<Record<string, readonly string[]>>;
  readonly quarantinedHeads?: Readonly<Record<string, { readonly code: import('./errors').VaultErrorCode; readonly signedEvent: NostrEvent }>>;
  readonly localCandidate?: { readonly tree: Persisted<VaultTree>; readonly baseline: Readonly<Record<string, StoredBaselineEntry>>; readonly addresses: readonly Address[] } | null;
  /** Last authenticated owner ledger; encrypted with a vault head key, not identity keys. */
  readonly epochLedgerEvent?: NostrEvent;
  /** SV-36: highest authenticated ledger epoch; older ledgers are never reselected. */
  readonly ledgerHighWater?: { readonly epoch: string; readonly eventId: EventId } | null;
  /** SV-35 freshness floors; absent on rows written before the field existed. */
  readonly freshness?: StoredFreshness;
  readonly foldQuarantine?: StoredFoldQuarantine | null;
  readonly retainedRoots: readonly StoredRetainedRoot[] | null;
  readonly deliveryLedger: readonly StoredDelivery[];
  /** Decimal reservation total; absent in records created before progress totals. */
  readonly resealTotalBytes?: string | null;
  readonly resealProgress: {
    readonly remaining: readonly string[];
    readonly pendingAddress: Address | null;
  } | null;
}
export interface StoredInvitation extends StoredVersion {
  readonly vaultId: VaultId;
  readonly grant: Persisted<VaultGrant>;
  readonly rumorId: EventId;
  readonly wrapIds: readonly EventId[];
  readonly read: boolean;
  readonly dismissed: boolean;
  readonly accepted: boolean;
}
export interface StoredRecord extends StoredVersion {
  readonly vaultId: VaultId;
  readonly record: Persisted<VerifiedRecord>;
}
export type JournalKind = 'create' | 'publish' | 'policy' | 'revoke' | 'reseal' | 'materialize';
export type JournalStage = 'prepared' | 'uploading' | 'ready-to-publish' | 'awaiting-ack'
  | 'committed' | 'needs-recovery';
export interface StoredOperation extends StoredVersion {
  readonly vaultId: VaultId;
  readonly operationId: string;
  readonly kind: JournalKind;
  readonly stage: JournalStage;
  /** Resumable phase preserved when a recovery attempt fails. */
  readonly recoveryStage?: Exclude<JournalStage, 'needs-recovery' | 'committed'>;
  /** Immutable identities/refs; a retry must reuse the existing candidate. */
  readonly candidate: Readonly<Record<string, StorageJson>>;
  readonly signedEvent: NostrEvent | null;
  /** Exact owner history publication, retried only after the head receives OK. */
  readonly signedEpochLedgerEvent?: NostrEvent;
  /** Complete reachable cache addresses, not only manifest roots. */
  readonly pinnedAddresses: readonly Address[];
  readonly pendingAddress: Address | null;
  readonly uploadOutcomes: Readonly<Record<string, StorageJson>>;
  readonly relayOutcomes: Readonly<Record<string, StorageJson>>;
}
export interface StoredConflict extends StoredVersion {
  readonly displayPath?: string;
  readonly blockedMaterialization?: boolean;
  /** Fold retirement is reversible; an explicit user resolution is not. */
  readonly retiredByFold?: boolean;
  readonly kind?: 'file' | 'directory' | 'deletion-only';
  readonly vaultId: VaultId;
  readonly conflictId: string;
  readonly conflict: Persisted<PathConflict>;
  readonly retainedVersions: readonly Address[];
  readonly artifactRefs: readonly string[];
  /** Plaintext bytes of the alternate artifact written for this row (SV-30 aggregate budget). */
  readonly artifactBytes?: number;
  /** The alternate exists in the record tree but its sibling copy was deferred by the artifact budget. */
  readonly artifactDeferred?: boolean;
  readonly resolution: 'unresolved' | 'resolved';
}
/**
 * Vault-scoped recovery payload. Account-wide device-key history is deliberately excluded
 * (SV-34/G2): a guessed package must not expose keys that open wraps for other vaults.
 */
export interface VaultRecoveryPayload extends StoredVersion {
  readonly vaultId: VaultId;
  readonly nodeRings: StoredVault['nodeRings'];
  readonly grant: StoredVault['grant'];
  readonly network: StoredNetwork;
  /** Trusted minimum carried through recovery (SV-35); absent packages fall back to the grant floor. */
  readonly freshness?: StoredFreshness;
}
export interface VaultRecoveryPackage {
  readonly format: 'onyx-vault-recovery';
  readonly version: 1;
  readonly ncryptsec: string;
  readonly payload: { readonly nonce: string; readonly ciphertext: string };
}
