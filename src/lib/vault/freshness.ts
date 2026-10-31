import { VaultError } from './errors';
import type { StoredFreshness, StoredFreshnessGrant, VaultGrant, VerifiedRecord } from './types';

/** SV-35 freshness state: compact per-(vault, author) sequence high-water plus
 * the owner-checkpoint floor and the granted-root floor, persisted independently
 * of retained record blobs. Pure functions; the engine owns persistence. */

export const EMPTY_FRESHNESS: StoredFreshness = { authors: {}, checkpoint: null, granted: null, verified: false };

type HeadEvidence = Pick<VerifiedRecord, 'writer' | 'head' | 'canonicalHeadHash'>;

const last = <T>(items: readonly T[]): T => items[items.length - 1];

/** The grant's root is an identity, not an ordinal. It binds an (epoch, grants_rev)
 * floor and exactly one owner-authenticated root address. */
export function grantedFloor(grant: Pick<VaultGrant, 'rootManifest' | 'ring'>, grantsRev: bigint | null): StoredFreshnessGrant {
  return { rootManifest: grant.rootManifest, epoch: String(last(grant.ring.entries).epoch), grantsRev: grantsRev === null ? null : String(grantsRev) };
}

export type HeadPosition = 'ahead' | 'level' | 'behind';

/** Position relative to the author's durable high-water. `level` admits a
 * different canonical body as equivocation evidence; `behind` is a replay. */
export function headPosition(f: StoredFreshness, writer: string, seq: bigint): HeadPosition {
  const held = f.authors[writer];
  if (!held) return 'ahead';
  const high = BigInt(held.seq);
  return seq > high ? 'ahead' : seq === high ? 'level' : 'behind';
}

export function noteHead(f: StoredFreshness, record: HeadEvidence): StoredFreshness {
  const held = f.authors[record.writer];
  if (held && BigInt(held.seq) > record.head.seq) return f;
  if (held && BigInt(held.seq) === record.head.seq) {
    if (held.hashes.includes(record.canonicalHeadHash)) return f;
    return { ...f, authors: { ...f.authors, [record.writer]: { seq: held.seq, hashes: [...held.hashes, record.canonicalHeadHash] } } };
  }
  return { ...f, authors: { ...f.authors, [record.writer]: { seq: String(record.head.seq), hashes: [record.canonicalHeadHash] } } };
}

export type CheckpointBinding = 'verified' | 'unverified' | 'stale';

/** Granted-root binding rule (plan §6.7). For a selected owner checkpoint C and
 * granted floor G = (root R, epoch E, grants_rev V; V may be unknown):
 *  - stale:      C.epoch < E, or C.grants_rev < V — an owner-authenticated later
 *                state is known to exist, so C is a rollback.
 *  - verified:   C.epoch > E, or C.grants_rev > V, or C.root == R, or an owner
 *                parent tuple of C names R, or the client holds a verified owner
 *                head with root R and seq <= C.seq — C is, or demonstrably follows, R.
 *  - unverified: same epoch and revision, different root, no reference to R.
 *                C may legitimately be two or more owner steps past R; a root
 *                address carries no order, so C is admitted and the gap is
 *                surfaced until a later checkpoint, held head or grant verifies it. */
export function bindCheckpoint(checkpoint: Pick<VerifiedRecord, 'writer' | 'head'>, granted: StoredFreshnessGrant, grantedSeq?: bigint): CheckpointBinding {
  const epoch = BigInt(granted.epoch), rev = granted.grantsRev === null ? null : BigInt(granted.grantsRev);
  if (checkpoint.head.epoch < epoch) return 'stale';
  if (checkpoint.head.epoch > epoch) return 'verified';
  if (rev !== null && checkpoint.head.grantsRev < rev) return 'stale';
  if (rev !== null && checkpoint.head.grantsRev > rev) return 'verified';
  if (checkpoint.head.rootManifest === granted.rootManifest) return 'verified';
  if (checkpoint.head.parents.some(p => p.writer === checkpoint.writer && p.rootManifest === granted.rootManifest)) return 'verified';
  if (grantedSeq !== undefined && grantedSeq <= checkpoint.head.seq) return 'verified';
  return 'unverified';
}

/** Sequence of a held, verified owner head whose root is the granted root, if any. */
export function grantedHeadSeq(granted: StoredFreshnessGrant | null, owner: string, history: Iterable<Pick<VerifiedRecord, 'writer' | 'head'>>): bigint | undefined {
  if (!granted) return undefined;
  let found: bigint | undefined;
  for (const r of history) if (r.writer === owner && r.head.rootManifest === granted.rootManifest && (found === undefined || r.head.seq < found)) found = r.head.seq;
  return found;
}

/** A previously verified owner checkpoint is a hard floor: lower seq/epoch is a
 * rollback; the same seq with a different canonical body is owner equivocation. */
export function checkCheckpointFloor(f: StoredFreshness, checkpoint: HeadEvidence): void {
  const floor = f.checkpoint; if (!floor) return;
  if (checkpoint.head.epoch < BigInt(floor.epoch) || checkpoint.head.seq < BigInt(floor.seq)) throw new VaultError('INCOMPLETE', { operation: 'fold', reason: 'stale-checkpoint' });
  if (checkpoint.head.seq === BigInt(floor.seq) && checkpoint.canonicalHeadHash !== floor.headHash) throw new VaultError('CONFLICT', { operation: 'fold' });
}

/** Floor check, granted-root binding and floor advance in one step. Throws before
 * any state derived from `checkpoint` may be trusted. */
export function acceptCheckpoint(f: StoredFreshness, checkpoint: HeadEvidence, grantedSeq?: bigint): StoredFreshness {
  checkCheckpointFloor(f, checkpoint);
  let verified = f.verified;
  if (!verified) {
    if (!f.granted) verified = true;
    else {
      const binding = bindCheckpoint(checkpoint, f.granted, grantedSeq);
      if (binding === 'stale') throw new VaultError('INCOMPLETE', { operation: 'fold', reason: 'stale-checkpoint' });
      verified = binding === 'verified';
    }
  }
  return { ...noteHead(f, checkpoint), verified, checkpoint: { seq: String(checkpoint.head.seq), epoch: String(checkpoint.head.epoch),
    grantsRev: String(checkpoint.head.grantsRev), rootManifest: checkpoint.head.rootManifest, headHash: checkpoint.canonicalHeadHash } };
}

/** The local owner's own committed head is the checkpoint by authority (only the
 * designated publisher commits). It never lowers an existing floor. */
export function publishedCheckpoint(f: StoredFreshness, record: HeadEvidence): StoredFreshness {
  const noted = noteHead(f, record);
  if (f.checkpoint && BigInt(f.checkpoint.seq) > record.head.seq) return { ...noted, verified: true };
  return { ...noted, verified: true, checkpoint: { seq: String(record.head.seq), epoch: String(record.head.epoch),
    grantsRev: String(record.head.grantsRev), rootManifest: record.head.rootManifest, headHash: record.canonicalHeadHash } };
}

/** A newer grant re-arms binding: it is owner-authenticated evidence of a state
 * the next selected checkpoint must be shown to follow. */
export function withGrant(f: StoredFreshness, granted: StoredFreshnessGrant): StoredFreshness {
  if (f.granted && JSON.stringify(f.granted) === JSON.stringify(granted)) return f;
  return { ...f, granted, verified: false };
}
