import type { NostrSigner } from '../nostr/signer';
import type { SecretStore, VaultFS } from '../../platform/types';
import type { BlossomOptions, VaultBlossom } from './blossom';
import type { AnnouncementEvidence, DeviceDeliveryOptions, IdentityFallbackNotice, RecipientKeyStatus } from './device-keys';
import { VaultError, type VaultErrorDisplay } from './errors';
import type { VaultRelay, VaultRelayOptions } from './relay';
import type { Address, EventId, Pubkey, StoredNetwork, Uint64, VaultGrant, VaultId,
  VaultMount, VaultRecoveryPackage } from './types';
import type { WorkerTransport } from './worker-client';

export type VaultNetworkDefaults = StoredNetwork;
export type VaultCapability = VaultGrant['cap'];
export type VaultDeliveryOptions = Readonly<DeviceDeliveryOptions>;

export interface VaultEditorBarrier {
  /** Paths are notebook-relative. Failed flushes become local-divergence conflicts.
   * Editors stay read-only until release; the default 5 s hold defers unfinished paths.
   * Replacements preserve cursors where possible and reset only that document's undo.
   */
  enter(paths: readonly string[], signal: AbortSignal): Promise<{
    readonly flushedHashes: ReadonlyMap<string, Address>;
    release(): void;
  }>;
}

export interface VaultSession {
  readonly accountPubkey: Pubkey;
  readonly signer: NostrSigner;
  readonly notebookPath: string;
  readonly fs: VaultFS;
  readonly secrets: SecretStore;
  readonly networkDefaults: VaultNetworkDefaults;
  readonly editorBarrier: VaultEditorBarrier;
}

/** Public adapter surfaces permit headless substitutes without private class state. */
export interface VaultEngineDeps {
  readonly relayFactory?: (endpoints: readonly string[], options?: VaultRelayOptions) => Pick<VaultRelay, keyof VaultRelay>;
  readonly blossomFactory?: (endpoint: string, options?: BlossomOptions) => Pick<VaultBlossom, keyof VaultBlossom>;
  /** Unix seconds. */
  readonly clock?: () => number;
  readonly rng?: (length: number) => Uint8Array;
  /** Exclusive account ownership; unavailable locks must fail closed. */
  readonly lockProvider?: Pick<LockManager, 'request'>;
  readonly workerFactory?: () => WorkerTransport;
  readonly idbFactory?: () => IDBFactory;
  /**
   * UI-owned passphrase prompt; null cancels. Never persisted by the engine. The optional
   * request carries a generated high-entropy suggestion and the policy the engine enforces;
   * implementations that ignore it keep working, but weak input is rejected afterwards.
   */
  readonly requestRecoveryPassphrase?: (request?: VaultRecoveryPassphraseRequest) => Promise<string | null>;
  /** SV-30 resource budgets; defaults in `budgets.ts`. Tests lower them. */
  readonly budgets?: Partial<import('./budgets').VaultBudgets>;
}

export interface VaultRecoveryPassphraseRequest {
  /** Freshly generated high-entropy passphrase the user may accept verbatim. */
  readonly suggested: string;
  /** Minimum accepted length in Unicode code points after NFKC normalisation. */
  readonly minimumLength: number;
  /** scrypt log2(N) the export will use after local calibration. */
  readonly logn: number;
  /** Fixed caveats the prompt should show. */
  readonly notes: readonly string[];
}

export interface VaultCreateOptions {
  readonly label?: string;
  /** Explicit endpoint override; otherwise snapshot the session defaults. */
  readonly network?: VaultNetworkDefaults;
}

export interface VaultMountOptions {
  /** Notebook-relative new/empty folder; omitted uses Shared Vaults/<id-prefix>/. */
  readonly relativePath?: string;
  readonly label?: string;
  readonly trustConfirmed: true;
  readonly endpointsConfirmed: true;
  /** Explicitly approved endpoints, including any fallbacks. */
  readonly network: VaultNetworkDefaults;
}

export type VaultConflictResolution = { readonly conflictId: string } & (
  | { readonly action: 'keep-view' }
  | { readonly action: 'use-other' }
  | { readonly action: 'delete' }
  | { readonly action: 'keep-both'; readonly newBasename: string }
  | { readonly action: 'manual-merge'; readonly bytes: Uint8Array }
);
export type VaultResealMode = 'lazy' | 'eager';
/** Complete old-read plus padded-new-write byte reservation, not plaintext size. */
export type VaultResealBudget = Uint64;

export type VaultEngineLifecycle = 'stopped' | 'starting' | 'running' | 'stopping';
export type VaultEngineActivity = 'idle' | 'capturing' | 'uploading' | 'publishing' | 'fetching'
  | 'folding' | 'materializing' | 'revoking' | 'resealing';
export type VaultEngineCondition = 'ready' | 'offline' | 'needs-key' | 'blocked' | 'error';
export type VaultAuthority = 'owner' | 'writer' | 'reader';
/** SV-35: whether the selected owner checkpoint is shown to be, or follow, the
 * granted root / a previously verified checkpoint. `verified` means verified
 * against known owner-authenticated anchors, never "up to date": a relay can
 * still withhold a newer checkpoint. `unverified` (freshness-unverified) is an
 * admitted checkpoint that cannot yet be linked to the granted root; known
 * rollbacks are never surfaced here, they fail closed (`INCOMPLETE`). */
export type VaultFreshness = 'verified' | 'unverified';
/** SV-36: owner epoch-ledger state relative to the newest held ring epoch.
 * `incomplete` covers behind-ring ledgers and expected-missing during rotation. */
export type VaultHistoryState = 'verified' | 'incomplete' | 'unavailable';

export interface VaultPublisherSummary {
  readonly deviceId: string;
  readonly deviceLabel: string;
  readonly since: Uint64;
  readonly isCurrentDevice: boolean;
}

export interface VaultMemberSummary {
  readonly pubkey: Pubkey;
  readonly role: VaultAuthority;
  readonly informational: boolean;
}
export interface VaultDeliverySummary {
  readonly recipient: Pubkey;
  /** Null until envelope routing/preparation succeeds. */
  readonly envelopeKey: Pubkey | null;
  readonly cap: VaultCapability;
  readonly state: 'pending' | 'acknowledged' | 'failed';
  readonly acknowledged: readonly string[];
  readonly pending: readonly string[];
  readonly relayOutcomes: readonly { readonly relay: string; readonly status: 'accepted' | 'rejected' | 'unknown'; readonly reason?: string }[];
  /** Set when the identity key was used although device delivery was requested. */
  readonly notice?: IdentityFallbackNotice;
  readonly evidence?: AnnouncementEvidence;
}
export interface VaultConflictSummary {
  readonly conflictId: string;
  readonly pathEnc: string;
  /** Display fallback is pathEnc when no decoded path is known. */
  readonly path: string;
  readonly displayPath?: string;
  readonly kind: 'file' | 'directory' | 'deletion-only';
  readonly inView: boolean;
  readonly inOther: boolean;
  readonly writer: Pubkey;
  readonly seq: Uint64;
  readonly alternatePath?: string | null;
  readonly hashedStorage?: boolean;
}
export interface VaultDeviceAnnouncementOutcome {
  readonly eventId: EventId;
  readonly pubkey: Pubkey;
  readonly state: 'pending' | 'acknowledged' | 'failed';
  readonly relayOutcomes: readonly { readonly relay: string; readonly status: 'accepted' | 'rejected' | 'unknown' }[];
}

/**
 * Pinned view of one recipient's NIP-4E announcement (SV-33). Pins stop rollback below what this
 * account already observed and record the fingerprint the user approved; they do not prove the
 * recipient has not rotated since. Device delivery happens only while `status === 'approved'`.
 */
export interface VaultRecipientKeyState {
  readonly identity: Pubkey;
  readonly status: RecipientKeyStatus;
  /** Newest observed announcement; `encryptionKey` null means it withdrew the key. */
  readonly observed: { readonly eventId: EventId; readonly createdAt: number; readonly encryptionKey: Pubkey | null } | null;
  readonly approvedKey: Pubkey | null;
  readonly observedAt: number | null;
}

export interface VaultDeviceKeysController {
  /** Public, immutable metadata only; never returns device secrets. */
  getState(): VaultDeviceKeysSummary;
  setEnabled(enabled: boolean): Promise<void>;
  generate(): Promise<Pubkey>;
  import(secret: string): Promise<Pubkey>;
  announce(): Promise<void>;
  useIdentityFallback(allow: boolean): Promise<void>;
  /** Fetches and pins the recipient's current announcement without delivering anything. */
  observeRecipient(identity: Pubkey): Promise<VaultRecipientKeyState>;
  /** Fingerprint-bound: `encryptionKey` must equal the currently pinned key or the call fails with ARG. */
  approveRecipientKey(identity: Pubkey, encryptionKey: Pubkey): Promise<VaultRecipientKeyState>;
  /** Discards the pin and approval; the next delivery falls back to the identity key with a notice. */
  resetRecipientPin(identity: Pubkey): Promise<void>;
}

export interface VaultDeviceKeysSummary {
  readonly enabled: boolean;
  readonly announcedPubkey: Pubkey | null;
  readonly retainedKeyCount: number;
  readonly lastAnnouncement?: VaultDeviceAnnouncementOutcome | null;
  readonly allowIdentityFallback: boolean;
  readonly current: { readonly pubkey: Pubkey; readonly announced: boolean } | null;
  readonly retained: readonly Pubkey[];
  /** Per-recipient announcement pins; empty until a share or observeRecipient() ran. */
  readonly recipients?: readonly VaultRecipientKeyState[];
}

/** Deliberately not a StoredVault projection: no grant, ring or secret fields. */
export interface VaultSummary {
  readonly vaultId: VaultId;
  readonly owner: Pubkey;
  readonly label: string;
  readonly authority: VaultAuthority;
  readonly enabled: boolean;
  readonly provisional: boolean;
  /** Notebook-relative decoded paths differing from the owner checkpoint.
   * At most 2,000 entries; provisionalCount includes the complete set. */
  readonly provisionalPaths: readonly string[];
  readonly provisionalCount: number;
  /** Subset of provisionalPaths belonging only to other writers (own wins on overlap). */
  readonly provisionalOtherPaths: readonly string[];
  readonly freshness?: VaultFreshness;
  /** Last accepted owner checkpoint floor (SV-35); null before the first fold. */
  readonly checkpoint?: { readonly seq: Uint64; readonly epoch: Uint64; readonly grantsRev: Uint64 } | null;
  readonly history?: VaultHistoryState;
  /** Non-null while the last fold's conflict output exceeded a local budget (SV-30). */
  readonly foldQuarantine?: { readonly reason: 'conflict-rows' | 'conflict-bytes'; readonly rows: number; readonly bytes: number } | null;
  readonly conflictCount: number;
  readonly pendingDeliveryCount: number;
  readonly resealRemainingBytes: Uint64;
  /** Total reserved old-read plus new-write bytes at the start of this re-seal. */
  readonly resealTotalBytes?: Uint64;
  readonly publisher: VaultPublisherSummary | null;
  readonly mount: VaultMount | null;
  readonly lastError: VaultErrorDisplay | null;
  readonly fileErrors?: readonly { readonly path: string; readonly error: VaultErrorDisplay }[];
  readonly members?: readonly VaultMemberSummary[];
  readonly deliveries?: readonly VaultDeliverySummary[];
  readonly conflicts?: readonly VaultConflictSummary[];
  readonly regrantHeadroomBytes?: number;
  readonly network?: VaultNetworkDefaults;
}

export interface VaultInvitationSummary {
  readonly invitationId: EventId;
  readonly vaultId: VaultId;
  readonly owner: Pubkey;
  readonly cap: VaultCapability;
  readonly read: boolean;
  readonly dismissed: boolean;
  readonly accepted: boolean;
  /** Key-free grant hints for explicit endpoint approval before acceptance. */
  readonly endpointHints?: VaultNetworkDefaults;
}

export interface VaultEndpointStatus {
  readonly kind: 'relay' | 'blossom';
  readonly url: string;
  readonly status: 'usable' | 'authenticated' | 'unsupported' | 'offline';
  /** Informational NIP-11 VSP-01 marker, not proof of access. */
  readonly service?: 'private vault service';
  readonly message: string;
}

/** Immutable main-thread replacement; never exposes decrypted grants or secrets. */
/** Account-level grant inbox state (SEC-G). `at-capacity` stops ingesting *new*
 * invitations only; vaults keep loading and syncing. */
export interface VaultInboxSummary {
  readonly state: 'active' | 'at-capacity' | 'stopped';
  /** Durable replay IDs held (wraps that opened to a valid grant). */
  readonly durableIds: number;
  readonly capacity: number;
  readonly message: string | null;
}
/** A stored vault row that could not be opened. Listed so it never disappears;
 * its encrypted original is retained for repair. */
export interface VaultUnavailableSummary {
  readonly vaultId: string;
  readonly state: 'needs-repair';
  readonly error: VaultErrorDisplay;
}

export interface VaultEngineSnapshot {
  readonly lifecycle: VaultEngineLifecycle;
  readonly activity: VaultEngineActivity;
  readonly condition: VaultEngineCondition;
  readonly vaults: readonly VaultSummary[];
  readonly invitations: readonly VaultInvitationSummary[];
  /** Configured user endpoints, also used by vault UI profile lookups. */
  readonly networkDefaults?: VaultNetworkDefaults;
  readonly deviceKeys?: VaultDeviceKeysSummary;
  readonly endpoints?: readonly VaultEndpointStatus[];
  readonly inbox?: VaultInboxSummary;
  readonly unavailableVaults?: readonly VaultUnavailableSummary[];
  readonly lastError: VaultErrorDisplay | null;
}

export interface VaultEngine {
  readonly deviceKeys: VaultDeviceKeysController;
  start(session: VaultSession, deps?: VaultEngineDeps): Promise<void>;
  /** Idempotent; aborts work, releases ownership and wipes owned key buffers. */
  stop(): Promise<void>;
  /** Immediately emits the current immutable snapshot. */
  subscribe(listener: (snapshot: VaultEngineSnapshot) => void): () => void;
  updateNetworkDefaults(config: VaultNetworkDefaults): Promise<void>;
  create(folder: string, options: VaultCreateOptions): Promise<VaultId>;
  share(vaultId: VaultId, recipients: readonly Pubkey[], cap: VaultCapability, delivery: VaultDeliveryOptions): Promise<void>;
  /** Owner-only empty-baseline reconciliation; existing files are never overwritten. */
  attach(invitationIdOrVaultId: EventId | VaultId, existingFolder: string): Promise<VaultMount>;
  takeOverPublishing(vaultId: VaultId): Promise<void>;
  accept(invitationId: EventId, mountOptions: VaultMountOptions): Promise<VaultMount>;
  sync(vaultId?: VaultId): Promise<void>;
  revoke(vaultId: VaultId, pubkey: Pubkey): Promise<void>;
  /** Owner-only; directory choices supersede descendants; reject inconsistent sets. */
  resolveConflicts(vaultId: VaultId, resolutions: readonly VaultConflictResolution[]): Promise<void>;
  /** Eager mode requires explicit confirmation by the caller before invocation. */
  reseal(vaultId: VaultId, budget: VaultResealBudget, mode: VaultResealMode): Promise<void>;
  pause(vaultId: VaultId): Promise<void>;
  resume(vaultId: VaultId): Promise<void>;
  detach(vaultId: VaultId): Promise<void>;
  /** Coalesced invalidation only; no immediate I/O. */
  notifyFilesChanged(paths?: readonly string[]): void;
  refreshInbox(): Promise<void>;
  /** Compacts grant-inbox replay storage to grant decisions and resumes ingestion if there is room. */
  repairInbox(): Promise<void>;
  /** Caller must obtain explicit confirmation before requesting encrypted recovery. */
  exportRecovery(vaultId: VaultId): Promise<VaultRecoveryPackage>;
}

export type VaultEngineFactory = (deps?: VaultEngineDeps) => VaultEngine;

let factory: VaultEngineFactory | undefined;
let instance: VaultEngine | undefined;

/** Registration is lazy and does not replace an existing instance; reset it first. */
export function registerVaultEngineFactory(value: VaultEngineFactory): void {
  factory = value;
}

export function getVaultEngine(deps?: VaultEngineDeps): VaultEngine {
  if (!instance) {
    if (!factory) {
      const error = new VaultError('UNSUPPORTED', { operation: 'start' });
      error.message = 'engine not registered';
      throw error;
    }
    instance = factory(deps);
  }
  return instance;
}

/** Keeps registration, but only discards the instance after stop completes. */
export async function resetVaultEngine(): Promise<void> {
  if (instance) {
    await instance.stop();
    instance = undefined;
  }
}
