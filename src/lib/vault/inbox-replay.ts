import { VaultError } from './errors';
import { VAULT_INBOX_MAX_REPLAY_BYTES, VAULT_INBOX_MAX_REPLAY_IDS } from './protocol';

/**
 * Replay protection is partitioned by what a replay could actually change (SEC-G).
 *
 * Durable tier — wraps that opened to a *valid grant*. Their IDs, together with the
 * invitation rows that record read/accept/dismiss decisions, are what SEC-A finding 9
 * protects: they are never silently evicted. Every durable ID is also listed in some
 * invitation row's `wrapIds` (invitation rows are never deleted), so the durable set
 * can always be rebuilt from the invitations store.
 *
 * Transient tier — wraps that were terminally invalid or not grants (NIP-17 DMs, other
 * NIP-59 applications, spam). Rejecting them is deterministic on every sight, so their
 * IDs are only a cost cache (a remote NIP-46 signer pays a round trip per decrypt): a
 * bounded LRU persisted separately as `config.inboxRejected`, never counted against the
 * durable budget. Evicting one only costs a deterministic re-rejection.
 *
 * Durable capacity: the 256 KiB serialized budget allows (262144 - 1) / 67 = 3,912
 * IDs, below the 4,096-ID cap, so 3,912 grant wraps (one per invitation delivery,
 * including re-wraps) is the effective limit. That is orders of magnitude above any
 * realistic number of shares an account receives. Reaching it stops *ingestion* of new
 * invitations; it never stops the engine or hides vaults.
 */
export const VAULT_INBOX_MAX_TRANSIENT_IDS = 2048;
export const VAULT_INBOX_DURABLE_CAPACITY = Math.min(VAULT_INBOX_MAX_REPLAY_IDS, Math.floor((VAULT_INBOX_MAX_REPLAY_BYTES - 1) / 67));

const ID = /^[0-9a-f]{64}$/;

export function inboxReplayCapacityError(): VaultError {
  return new VaultError('BUDGET', { operation: 'accept', retryable: true, reason: 'inbox-capacity' });
}

/** Canonical IDs are 64 ASCII hex bytes, plus JSON quotes and a separator.
 * Count the complete serialized array, not merely its decoded string bytes. */
export function assertInboxReplayCapacity(count: number): void {
  const bytes = count === 0 ? 2 : 1 + count * 67;
  if (count > VAULT_INBOX_MAX_REPLAY_IDS || bytes > VAULT_INBOX_MAX_REPLAY_BYTES) throw inboxReplayCapacityError();
}
/** True when one more durable ID would not fit. */
export function inboxReplayFull(count: number): boolean {
  try { assertInboxReplayCapacity(count + 1); return false; } catch { return true; }
}

/** Valid canonical IDs from untrusted stored shapes; malformed entries are skipped, never fatal. */
export function replayIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((id): id is string => typeof id === 'string' && ID.test(id));
}

/**
 * Splits a stored replay list (possibly the unbounded pre-SEC-A one, which held every
 * kind-1059 wrap ID) into tiers. Never throws and never drops an ID tied to an invitation.
 * `transient` keeps the most recent legacy non-grant IDs, bounded by the LRU size.
 */
export function partitionInboxReplay(stored: unknown, invitationWrapIds: Iterable<unknown>, rejected?: unknown): { durable: string[]; transient: string[]; migrated: boolean } {
  const durable = new Set(replayIds([...invitationWrapIds]));
  const legacy = replayIds(stored);
  // Legacy extras first, then the persisted transient tier (most recent last).
  const rest = [...new Set([...legacy, ...replayIds(rejected)].filter(id => !durable.has(id)).reverse())].reverse();
  // Unchanged only if the stored list is exactly the durable set (no legacy extras,
  // duplicates or malformed entries); anything else is rewritten once on start.
  const same = stored === undefined ? durable.size === 0 : Array.isArray(stored) && stored.length === durable.size &&
    new Set(stored).size === stored.length && stored.every(id => typeof id === 'string' && durable.has(id));
  const migrated = !same;
  return { durable: [...durable], transient: rest.slice(-VAULT_INBOX_MAX_TRANSIENT_IDS), migrated };
}

/** Bounded insertion-ordered LRU for terminally rejected wrap IDs. Memory only. */
export class TransientReplay {
  private readonly ids = new Map<string, true>();
  constructor(private readonly limit = VAULT_INBOX_MAX_TRANSIENT_IDS) {}
  get size(): number { return this.ids.size; }
  has(id: string): boolean {
    if (!this.ids.has(id)) return false;
    this.ids.delete(id); this.ids.set(id, true); return true;
  }
  add(id: string): void {
    this.ids.delete(id); this.ids.set(id, true);
    while (this.ids.size > this.limit) this.ids.delete(this.ids.keys().next().value!);
  }
  delete(id: string): void { this.ids.delete(id); }
  values(): string[] { return [...this.ids.keys()]; }
  clear(): void { this.ids.clear(); }
}
