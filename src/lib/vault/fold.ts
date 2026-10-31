import { hashAddress, hexToBytes } from './crypto';
import { VaultError } from './errors';
import { VAULT_MAX_HEADS } from './protocol';
import { differingPaths, recordId } from './record';
import type {
  Disposition, FoldResult, PathConflict, VaultGrant, VaultPolicy, VerifiedRecord,
} from './types';

export class FoldConflictError extends VaultError {
  readonly result: FoldResult;
  constructor(result: FoldResult) {
    super('CONFLICT', { operation: 'fold' });
    this.result = { ...result, viewRecordId: null };
  }
}

/** fold.c: sorted, deduplicated pubkey bytes; readers and array order do not vote. */
export function writerSetHash(policy: VaultPolicy): string {
  const writers = [...new Set(policy.writers)].sort();
  const bytes = new Uint8Array(writers.length * 32);
  writers.forEach((writer, i) => bytes.set(hexToBytes(writer), i * 32));
  return hashAddress(bytes);
}

function compareRecords(a: VerifiedRecord, b: VerifiedRecord): number {
  return a.writer < b.writer ? -1 : a.writer > b.writer ? 1
    : a.head.seq < b.head.seq ? -1 : a.head.seq > b.head.seq ? 1
    : a.head.rootManifest < b.head.rootManifest ? -1 : a.head.rootManifest > b.head.rootManifest ? 1 : 0;
}

/** SV-30 local budget. `maxConflicts` aborts enumeration fail-closed (TOO_LARGE)
 * once the per-path conflict output would exceed it; view, frontier and
 * dispositions of admitted records are computed exactly as without a limit. */
export interface FoldLimits {
  readonly maxConflicts?: number;
  /** Engine projection only; not part of the normative FoldResult. Called once
   * per differing path of each accepted head not covered by the owner. */
  readonly onCheckpointDifference?: (record: VerifiedRecord, pathEnc: string) => void;
}

/** Exact current-head checkpoint algorithm, NOT the signed-history DAG fold.
 * On CONFLICT the error retains the C-style partial result, with no view. */
export function foldCheckpoint(grant: Pick<VaultGrant, 'vaultId' | 'nodeId' | 'owner'>,
  records: readonly VerifiedRecord[], ownerIndex: number, limits: FoldLimits = {}): FoldResult {
  if (!Number.isInteger(ownerIndex) || ownerIndex < 0 || ownerIndex >= records.length || records.length > VAULT_MAX_HEADS)
    throw new VaultError('ARG');
  const owner = records[ownerIndex], policy = owner.root.vault;
  if (!policy || owner.writer !== grant.owner || policy.owner !== grant.owner || policy.vaultId !== grant.vaultId ||
      owner.root.nodeId !== grant.nodeId) throw new VaultError('AUTH');
  if (records.some(r => r.writer === grant.owner && r.head.seq > owner.head.seq)) throw new VaultError('CONFLICT');
  if (records.some(r => !r.root.vault)) throw new VaultError('ARG');
  const retainedRoots = [...new Set(records.flatMap(r => [r.head.rootManifest, ...r.head.parents.map(p => p.rootManifest)]))].sort();
  const policyHash = writerSetHash(policy);
  const hashes = records.map(r => writerSetHash(r.root.vault!));
  let ambiguous = records.some((r, i) => r.writer === policy.owner && r.root.vault!.owner === policy.owner &&
    r.root.vault!.vaultId === policy.vaultId && r.root.vault!.grantsRev === policy.grantsRev && hashes[i] !== policyHash);
  const dispositions: Disposition[] = [];
  for (let i = 0; i < records.length; i++) {
    const r = records[i], p = r.root.vault!;
    let disposition: Disposition = !policy.writers.includes(r.writer) ? 'NONWRITER'
      : r.head.grantsRev < policy.grantsRev ? 'STALE'
      : r.head.grantsRev !== policy.grantsRev || p.owner !== policy.owner || p.vaultId !== policy.vaultId || hashes[i] !== policyHash
        ? 'POLICY' : 'ACCEPTED';
    for (let j = 0; j < i; j++) if (compareRecords(r, records[j]) === 0) {
      if (r.canonicalHeadHash !== records[j].canonicalHeadHash) {
        if (disposition === 'ACCEPTED' && dispositions[j] === 'ACCEPTED' && r.writer === policy.owner) ambiguous = true;
      } else if (disposition === 'ACCEPTED') disposition = 'DUPLICATE';
      break;
    }
    dispositions.push(disposition);
  }
  const partial: FoldResult = { viewRecordId: null, frontier: [], conflicts: [], retainedRoots,
    dispositions: records.map((r, i) => ({ recordId: recordId(r), disposition: dispositions[i] })) };
  if (ambiguous) throw new FoldConflictError(partial);
  const accepted = records.map((_, i) => i).filter(i => dispositions[i] === 'ACCEPTED');
  for (const i of accepted) for (const j of accepted)
    if (i !== j && records[i].writer === policy.owner && records[j].writer === policy.owner &&
        records[i].head.seq === records[j].head.seq && records[i].canonicalHeadHash !== records[j].canonicalHeadHash)
      throw new FoldConflictError(partial);
  // Parents cover sequence ranges regardless of the tuple's root; ignored heads
  // have no edges, and larger seq alone is deliberately not an edge.
  const frontier = accepted.filter(i => !accepted.some(j => records[j].head.parents.some(p =>
    p.writer === records[i].writer && records[i].head.seq <= p.seq)))
    .sort((i, j) => compareRecords(records[i], records[j]));
  const result = { ...partial, frontier: frontier.map(i => recordId(records[i])) };
  if (!frontier.length) throw new FoldConflictError(result);
  let view = frontier[0];
  if (frontier.length > 1) {
    const owners = accepted.filter(i => records[i].writer === policy.owner)
      .sort((i, j) => records[i].head.seq > records[j].head.seq ? -1 : records[i].head.seq < records[j].head.seq ? 1 : 0);
    if (!owners.length) throw new FoldConflictError(result);
    view = owners[0];
  }
  const conflicts: PathConflict[] = [];
  const selected = records[view];
  const checkpointCompared = new Set<number>();
  for (const index of frontier) {
    if (index === view) continue;
    const other = records[index];
    function conflict(pathEnc: string, inView: boolean, inOther: boolean): void {
      if (limits.maxConflicts !== undefined && conflicts.length >= limits.maxConflicts)
        throw new VaultError('TOO_LARGE', { operation: 'fold', reason: 'conflict-budget' });
      conflicts.push({ pathEnc, otherRecordId: recordId(other), inView, inOther,
        writer: other.writer, seq: other.head.seq, rootManifest: other.head.rootManifest });
    }
    for (const path of differingPaths(selected.paths, other.paths)) {
      conflict(path.pathEnc, path.inLeft, path.inRight);
      if (view === ownerIndex) limits.onCheckpointDifference?.(other, path.pathEnc);
    }
    if (view === ownerIndex) checkpointCompared.add(index);
  }
  // Reuse the conflict enumeration above when it already compared with the
  // checkpoint. A sole member view (or a dominated, uncovered member) still
  // needs a checkpoint comparison, without inventing normative conflict rows.
  if (limits.onCheckpointDifference) for (const index of accepted) {
    const record = records[index];
    if (record.writer === policy.owner || checkpointCompared.has(index) ||
        owner.head.parents.some(p => p.writer === record.writer && record.head.seq <= p.seq)) continue;
    for (const path of differingPaths(owner.paths, record.paths)) limits.onCheckpointDifference(record, path.pathEnc);
  }
  conflicts.sort((a, b) => a.pathEnc < b.pathEnc ? -1 : a.pathEnc > b.pathEnc ? 1
    : a.writer < b.writer ? -1 : a.writer > b.writer ? 1
    : a.seq < b.seq ? -1 : a.seq > b.seq ? 1
    : a.rootManifest < b.rootManifest ? -1 : a.rootManifest > b.rootManifest ? 1 : 0);
  return { ...result, viewRecordId: recordId(selected), conflicts };
}

/** Only byte-equivalent canonical bodies may use outer replaceable ordering.
 * This chooses retained signature evidence, never a state/conflict winner. */
function compareCopies(a: VerifiedRecord, b: VerifiedRecord): number {
  return a.signedEvent.created_at > b.signedEvent.created_at ? -1 : a.signedEvent.created_at < b.signedEvent.created_at ? 1
    : a.eventId < b.eventId ? -1 : a.eventId > b.eventId ? 1 : 0;
}

export interface FoldInputs {
  readonly records: readonly VerifiedRecord[];
  readonly ownerIndex: number;
  /** Audit-only: never frontier candidates, dispositions or retained-root input.
   * The cache retains these historical roots independently of the current fold. */
  readonly ownerAuditRecords: readonly VerifiedRecord[];
}

/** Onyx §6.8 selection. Keep ALL distinct highest-seq canonical bodies at ties;
 * sorting is not an LWW tiebreaker. Older member cache rows never participate. */
export function selectFoldInputs(grant: Pick<VaultGrant, 'owner' | 'vaultId' | 'nodeId'>,
  history: readonly VerifiedRecord[]): FoldInputs {
  const owners = history.filter(r => r.writer === grant.owner).sort((a, b) =>
    a.head.seq > b.head.seq ? -1 : a.head.seq < b.head.seq ? 1 : a.canonicalHeadHash < b.canonicalHeadHash ? -1
      : a.canonicalHeadHash > b.canonicalHeadHash ? 1 : compareCopies(a, b));
  if (!owners.length) throw new VaultError('INCOMPLETE');
  const checkpoint = owners[0], policy = checkpoint.root.vault;
  if (!policy || policy.owner !== grant.owner || policy.vaultId !== grant.vaultId || checkpoint.root.nodeId !== grant.nodeId)
    throw new VaultError('AUTH');
  const authors = new Set([grant.owner, ...policy.writers]);
  const latest = new Map<string, bigint>();
  for (const r of history) if (authors.has(r.writer) && (!latest.has(r.writer) || r.head.seq > latest.get(r.writer)!))
    latest.set(r.writer, r.head.seq);
  const bodies = new Set<string>();
  const records = history.filter(r => authors.has(r.writer) && r.head.seq === latest.get(r.writer))
    .sort((a, b) => compareRecords(a, b) || (a.canonicalHeadHash < b.canonicalHeadHash ? -1 : a.canonicalHeadHash > b.canonicalHeadHash ? 1
      : compareCopies(a, b)))
    .filter(r => {
      const identity = `${r.writer}:${r.canonicalHeadHash}`;
      if (bodies.has(identity)) return false;
      bodies.add(identity); return true;
    });
  const ownerAuditRecords = owners.filter(r => r.head.grantsRev === policy.grantsRev);
  if (records.length > VAULT_MAX_HEADS) throw new VaultError('TOO_LARGE');
  return { records, ownerIndex: records.findIndex(r => r.writer === checkpoint.writer &&
    r.canonicalHeadHash === checkpoint.canonicalHeadHash && r.eventId === checkpoint.eventId), ownerAuditRecords };
}

/** Stable public FoldResult across warm/cold caches; old owner rows affect only
 * security checks, not successful frontier/conflict/retention/disposition output. */
export function foldCurrentHeads(grant: Pick<VaultGrant, 'owner' | 'vaultId' | 'nodeId'>,
  history: readonly VerifiedRecord[], limits: FoldLimits = {}): FoldResult {
  const { records, ownerIndex, ownerAuditRecords } = selectFoldInputs(grant, history);
  const owner = records[ownerIndex], policy = owner.root.vault!, hash = writerSetHash(policy);
  const audit = (result: FoldResult): void => {
    const sequences = new Map<bigint, string>();
    for (const record of ownerAuditRecords) {
      const p = record.root.vault!;
      if (p.owner !== policy.owner || p.vaultId !== policy.vaultId) continue;
      const previousHash = sequences.get(record.head.seq);
      if (writerSetHash(p) !== hash || (policy.writers.includes(policy.owner) &&
          previousHash !== undefined && previousHash !== record.canonicalHeadHash))
        throw new FoldConflictError({ ...result, frontier: [], conflicts: [] });
      sequences.set(record.head.seq, record.canonicalHeadHash);
    }
  };
  let result: FoldResult;
  try { result = foldCheckpoint(grant, records, ownerIndex, limits); }
  catch (error) {
    // Owner ambiguity among cached rows outranks a resource abort: audit first so
    // a budget-quarantined fold never leaves an equivocating checkpoint standing.
    if (error instanceof VaultError && error.code === 'TOO_LARGE') audit({ viewRecordId: null, frontier: [], conflicts: [], dispositions: [], retainedRoots: [] });
    throw error;
  }
  audit(result);
  return result;
}
