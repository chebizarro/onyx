/**
 * Shared helpers and UI-only view types for the shared-vault components.
 *
 * Components consume key-free data only: the engine snapshot plus the
 * optional view models below, which App derives from engine/store state.
 * Nothing here ever carries ring keys, grants, secrets or private keys.
 */

import { createEffect, createSignal, onCleanup, type Accessor } from 'solid-js';
import { fetchUserProfile } from '../lib/nostr/login';
import { DEFAULT_SYNC_CONFIG, type NostrProfile } from '../lib/nostr/types';
import type {
  VaultAuthority, VaultCapability, VaultEngine, VaultEngineSnapshot, VaultSummary,
} from '../lib/vault/engine-api';
import { VaultError } from '../lib/vault/errors';
import { NIP59_MAX_PLAINTEXT, PORTHOME_NAME_PLAIN_MAX_BYTES } from '../lib/vault/protocol';
import type { Pubkey, VaultId } from '../lib/vault/types';

// ---------------------------------------------------------------------------
// View models not carried by VaultEngineSnapshot
// ---------------------------------------------------------------------------

export type VaultMemberRole = 'owner' | 'writer' | 'reader';

export interface VaultMemberView {
  readonly pubkey: Pubkey;
  /** `reader` entries come from the informational `readers[]` list. */
  readonly role: VaultMemberRole;
}

/** One recipient's grant delivery, derived from the vault's delivery ledger. */
export interface VaultDeliveryView extends Pick<import('../lib/vault/engine-api').VaultDeliverySummary, 'notice' | 'evidence'> {
  readonly recipient: Pubkey;
  readonly cap: VaultCapability;
  /** Relay URLs that acknowledged the wrap with a positive OK. */
  readonly acknowledged: readonly string[];
  /** Relay URLs still awaiting a positive OK. */
  readonly pending: readonly string[];
}

/** Result of the revoke pre-flight grant-size check (§6.12 step 2b). */
export interface VaultRegrantHeadroom {
  /** Largest post-revoke NIP-59 plaintext across remaining members. */
  readonly largestSealBytes: number;
  /** Ceiling for either NIP-59 plaintext; defaults to 65535. */
  readonly limitBytes?: number;
  /** Approximate number of further revocations that would still fit. */
  readonly remainingRevocations?: number;
}

export type VaultConflictKind = 'file' | 'directory';

export interface VaultConflictView {
  readonly conflictId: string;
  /** Vault-relative display path using `/` separators. */
  readonly path: string;
  readonly kind: VaultConflictKind;
  /** Present in the selected view. */
  readonly inView: boolean;
  /** Present in the other version. */
  readonly inOther: boolean;
  readonly writer: Pubkey;
  readonly seq: bigint;
  /** Local sibling under `.onyx-vault-conflicts/`, when bytes were materialised. */
  readonly alternatePath?: string | null;
  /** The path could not be represented locally; stored under a hashed name. */
  readonly hashedStorage?: boolean;
}

/** Key-free sidebar projection of a mounted vault. */
export interface SharedVaultMountInfo {
  readonly vaultId: VaultId;
  /** Notebook-relative mount folder. */
  readonly relativePath: string;
  readonly label: string;
  readonly authority: VaultAuthority;
  readonly provisional: boolean;
  readonly provisionalPaths: readonly string[];
  readonly provisionalCount: number;
  readonly provisionalOtherPaths: readonly string[];
  readonly enabled: boolean;
  readonly conflictCount: number;
}

export type VaultPathOperation = 'create' | 'rename' | 'move' | 'delete';

export interface DeviceKeyInfo {
  readonly pubkey: Pubkey;
  readonly announced: boolean;
}

/** State for the experimental NIP-4E device-key settings. Never holds private keys. */
export interface DeviceKeySettingsState {
  readonly enabled: boolean;
  readonly allowIdentityFallback: boolean;
  readonly current: DeviceKeyInfo | null;
  /** Earlier device keys kept to decrypt old wraps; never auto-deleted. */
  readonly retained: readonly Pubkey[];
  readonly recipients?: readonly import('../lib/vault/engine-api').VaultRecipientKeyState[];
}

export interface DeviceKeySettingsController {
  readonly state: DeviceKeySettingsState;
  setEnabled(enabled: boolean): Promise<void> | void;
  setAllowIdentityFallback(allow: boolean): Promise<void> | void;
  generate(): Promise<Pubkey>;
  /** Accepts an nsec or 64-char hex secret; the value is not retained by the UI. */
  import(secret: string): Promise<Pubkey>;
  announce(): Promise<void>;
  approveRecipientKey?: import('../lib/vault/engine-api').VaultDeviceKeysController['approveRecipientKey'];
  resetRecipientPin?: import('../lib/vault/engine-api').VaultDeviceKeysController['resetRecipientPin'];
}

// ---------------------------------------------------------------------------
// Snapshot hook
// ---------------------------------------------------------------------------

export const EMPTY_VAULT_SNAPSHOT: VaultEngineSnapshot = Object.freeze({
  lifecycle: 'stopped',
  activity: 'idle',
  condition: 'ready',
  vaults: Object.freeze([]) as readonly VaultSummary[],
  invitations: Object.freeze([]),
  lastError: null,
}) as VaultEngineSnapshot;

/** Thin Solid subscription: immutable snapshot replacement, unsubscribed on cleanup. */
export function createVaultSnapshot(engine: Pick<VaultEngine, 'subscribe'>): Accessor<VaultEngineSnapshot> {
  const [snapshot, setSnapshot] = createSignal<VaultEngineSnapshot>(EMPTY_VAULT_SNAPSHOT);
  const unsubscribe = engine.subscribe((next) => setSnapshot(() => next));
  onCleanup(unsubscribe);
  return snapshot;
}

/** Use the supplied snapshot when given, otherwise subscribe to the engine. */
export function useSnapshot(
  engine: Pick<VaultEngine, 'subscribe'>,
  provided: () => VaultEngineSnapshot | undefined,
): Accessor<VaultEngineSnapshot> {
  if (provided()) return () => provided() ?? EMPTY_VAULT_SNAPSHOT;
  return createVaultSnapshot(engine);
}

export function sharedVaultMountsFromSnapshot(snapshot: VaultEngineSnapshot): SharedVaultMountInfo[] {
  return snapshot.vaults.flatMap((vault) => vault.mount ? [{
    vaultId: vault.vaultId,
    relativePath: vault.mount.relativePath,
    label: vault.label,
    authority: vault.authority,
    provisional: vault.provisional,
    provisionalPaths: vault.provisionalPaths,
    provisionalCount: vault.provisionalCount,
    provisionalOtherPaths: vault.provisionalOtherPaths,
    enabled: vault.enabled,
    conflictCount: vault.conflictCount,
  }] : []);
}

// ---------------------------------------------------------------------------
// Profiles: one lookup per pubkey/relay set; failures are not retried in a loop
// ---------------------------------------------------------------------------

const PROFILE_RETRY_AFTER_MS = 10 * 60 * 1000;
interface ProfileCacheEntry {
  readonly promise: Promise<NostrProfile | null>;
  failedAt: number | null;
}
const profileCache = new Map<string, ProfileCacheEntry>();

export type ProfileLookup = (pubkey: string, relays: readonly string[]) => Promise<NostrProfile | null>;

export const lookupProfile: ProfileLookup = (pubkey, relays) => {
  const cacheKey = JSON.stringify([pubkey, [...new Set(relays)].sort()]);
  const existing = profileCache.get(cacheKey);
  if (existing && (existing.failedAt === null || Date.now() - existing.failedAt < PROFILE_RETRY_AFTER_MS)) {
    return existing.promise;
  }
  if (relays.length === 0) return Promise.resolve(null);
  const entry: ProfileCacheEntry = {
    failedAt: null,
    promise: fetchUserProfile(pubkey, [...relays]).then(
      (profile) => {
        if (!profile) {
          entry.failedAt = Date.now();
          return null;
        }
        return {
          pubkey,
          name: profile.displayName || profile.name,
          picture: profile.picture,
          nip05: profile.nip05,
        };
      },
      () => {
        entry.failedAt = Date.now();
        return null;
      },
    ),
  };
  profileCache.set(cacheKey, entry);
  return entry.promise;
};

export function clearProfileCache(): void {
  profileCache.clear();
}

export function defaultProfileRelays(snapshot?: VaultEngineSnapshot, vaultId?: VaultId): readonly string[] {
  const networks = [snapshot?.networkDefaults, ...(snapshot?.vaults ?? [])
    .filter(vault => vault.mount && (!vaultId || vault.vaultId === vaultId)).map(vault => vault.network)];
  const configured = [...new Set(networks.flatMap(network => network ? [...network.readRelays, ...network.writeRelays] : []))];
  return configured.length ? configured : snapshot?.lifecycle === 'running' ? DEFAULT_SYNC_CONFIG.relays : [];
}

/** Reactive pubkey → profile map; each pubkey/relay set is requested at most once. */
export function createProfileMap(
  pubkeys: () => readonly string[],
  relays: () => readonly string[] = defaultProfileRelays,
  lookup: ProfileLookup = lookupProfile,
): Accessor<ReadonlyMap<string, NostrProfile>> {
  const [profiles, setProfiles] = createSignal<ReadonlyMap<string, NostrProfile>>(new Map());
  const requested = new Set<string>();
  let disposed = false;
  onCleanup(() => { disposed = true; });
  createEffect(() => {
    const relayList = relays();
    if (relayList.length === 0) return;
    for (const pubkey of pubkeys()) {
      const requestKey = JSON.stringify([pubkey, [...new Set(relayList)].sort()]);
      if (requested.has(requestKey)) continue;
      requested.add(requestKey);
      void lookup(pubkey, relayList).then((profile) => {
        if (!profile || disposed) return;
        setProfiles((prev) => new Map(prev).set(pubkey, profile));
      }, () => undefined);
    }
  });
  return profiles;
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

export function formatBytes(value: bigint | number): string {
  const n = typeof value === 'bigint' ? Number(value) : value;
  if (!Number.isFinite(n) || n < 1024) return `${Math.max(0, Math.floor(n))} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function shortVaultId(vaultId: string): string {
  return vaultId.length > 16 ? `${vaultId.slice(0, 8)}…${vaultId.slice(-8)}` : vaultId;
}

export function formatUnixTime(seconds: bigint | number): string {
  const ms = Number(seconds) * 1000;
  if (!Number.isFinite(ms) || ms <= 0) return 'unknown';
  return new Date(ms).toLocaleString();
}

export const AUTHORITY_LABELS: Record<VaultAuthority, string> = {
  owner: 'Owner',
  writer: 'Writer',
  reader: 'Read-only',
};

/** Display text for an error: VaultError/display objects use their fixed text. */
export function describeVaultError(error: unknown): string {
  if (error instanceof VaultError) return error.message;
  if (error && typeof error === 'object' && 'code' in error && 'message' in error
    && typeof (error as { message: unknown }).message === 'string') {
    return (error as { message: string }).message;
  }
  if (error instanceof Error && error.message) return error.message;
  return 'The operation failed';
}

export function isRetryableError(error: unknown): boolean {
  if (error instanceof VaultError) return error.retryable;
  if (error && typeof error === 'object' && 'retryable' in error) {
    return Boolean((error as { retryable: unknown }).retryable);
  }
  return true;
}

export const DEFAULT_GRANT_LIMIT_BYTES = NIP59_MAX_PLAINTEXT;

/** Remaining bytes before a regrant would exceed the NIP-59 plaintext limit. */
export function headroomBytes(headroom: VaultRegrantHeadroom): number {
  return (headroom.limitBytes ?? DEFAULT_GRANT_LIMIT_BYTES) - headroom.largestSealBytes;
}

export function headroomExhausted(headroom: VaultRegrantHeadroom | null | undefined): boolean {
  if (!headroom) return false;
  return headroomBytes(headroom) <= 0 || headroom.remainingRevocations === 0;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

export const RESERVED_VAULT_ARTIFACT_NAMES: readonly string[] = ['.onyx-vault-conflicts', '.onyx-vault-staging'];

export function isReservedVaultArtifactName(name: string): boolean {
  return RESERVED_VAULT_ARTIFACT_NAMES.includes(name);
}

function isWindowsLike(path: string): boolean {
  return /^(?:[a-z]:|\/\/|\\\\)/i.test(path);
}

/** Split into components, resolving `.` and `..` so traversal cannot dodge mount checks. */
function components(path: string): string[] {
  const out: string[] = [];
  for (const part of path.replace(/\\/g, '/').split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') {
      if (out.length && out[out.length - 1] !== '..') out.pop();
      else out.push('..');
      continue;
    }
    out.push(part);
  }
  return out;
}

/**
 * Convert a sidebar path (notebook-qualified) to a notebook-relative `/` path.
 * Returns null when the path is outside the notebook. The notebook root is ''.
 */
export function toNotebookRelative(path: string, notebookPath: string): string | null {
  const insensitive = isWindowsLike(notebookPath);
  const root = components(notebookPath);
  const target = components(path);
  if (target.length < root.length) return null;
  for (let i = 0; i < root.length; i++) {
    const a = insensitive ? root[i].toLowerCase() : root[i];
    const b = insensitive ? target[i].toLowerCase() : target[i];
    if (a !== b) return null;
  }
  return target.slice(root.length).join('/');
}

export function normalizeRelative(path: string): string {
  return components(path).join('/');
}

export interface MountMatch<M extends { relativePath: string }> {
  readonly mount: M;
  /** The path is the mount root itself. */
  readonly isRoot: boolean;
}

/** Component-aware: finds the mount containing a notebook-relative path. */
export function findMountForPath<M extends { relativePath: string }>(
  relativePath: string,
  mounts: readonly M[],
  caseInsensitive = false,
): MountMatch<M> | null {
  const fold = (s: string) => (caseInsensitive ? s.toLowerCase() : s);
  const target = components(relativePath).map(fold);
  for (const mount of mounts) {
    const root = components(mount.relativePath).map(fold);
    if (root.length === 0 || root.length > target.length) continue;
    if (root.every((part, i) => part === target[i])) {
      return { mount, isRoot: root.length === target.length };
    }
  }
  return null;
}

/** True when the path is a strict ancestor of any mount (directory ops would intersect it). */
export function containsMount(
  relativePath: string,
  mounts: readonly { relativePath: string }[],
  caseInsensitive = false,
): boolean {
  const fold = (s: string) => (caseInsensitive ? s.toLowerCase() : s);
  const target = components(relativePath).map(fold);
  return mounts.some((mount) => {
    const root = components(mount.relativePath).map(fold);
    return root.length > target.length && target.every((part, i) => part === root[i]);
  });
}

/** Validate a notebook-relative folder for a new mount; returns an error or null. */
export function validateMountFolder(path: string): string | null {
  const raw = path.trim();
  if (!raw) return 'Choose a folder inside this notebook.';
  if (/^(?:[a-z]:|[\\/])/i.test(raw)) return 'Use a path relative to this notebook.';
  const parts = raw.replace(/\\/g, '/').split('/').filter(Boolean);
  if (parts.some((part) => part === '..' || part === '.')) return 'The folder path cannot contain "." or ".." segments.';
  if (parts.some(isReservedVaultArtifactName)) return 'That folder name is reserved for vault data.';
  if (parts.some((part) => /[\u0000-\u001f]/.test(part))) return 'The folder path contains control characters.';
  return null;
}

/** Validate a keep-both basename; returns an error or null. */
export function validateBasename(name: string, currentName?: string): string | null {
  if (!name) return 'Enter a new name.';
  if (name !== name.trim()) return 'Names cannot start or end with spaces.';
  if (name === '.' || name === '..') return 'That name is not allowed.';
  if (/[\\/\u0000-\u001f]/.test(name)) return 'Names cannot contain slashes or control characters.';
  if (isReservedVaultArtifactName(name)) return 'That name is reserved for vault data.';
  if (new TextEncoder().encode(name).length > PORTHOME_NAME_PLAIN_MAX_BYTES) return 'That name is too long.';
  if (currentName !== undefined && name === currentName) return 'Choose a name different from the current one.';
  return null;
}

export function basenameOf(path: string): string {
  const parts = components(path);
  return parts[parts.length - 1] ?? '';
}
