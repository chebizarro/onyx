import { describe, expect, it } from 'vitest';
import { finalizeEvent } from 'nostr-tools';
import { encryptName, hex32 } from '../crypto';
import { sealDirectoryNode } from '../dir-node';
import { FoldConflictError, foldCheckpoint, foldCurrentHeads, selectFoldInputs, writerSetHash } from '../fold';
import { buildHeadEvent } from '../head';
import { coverHead, includeHead, memberHeadParents, mergeParents } from '../parents';
import { openRecord, recordId } from '../record';
import type { Address, DirectoryNode, HeadParent, NodeEntry, VaultHead, VaultId } from '../types';
import { address, chunk, errorCode, fileEntry, id, makeRecord, tuple, world } from './policy-fixtures';

function conflictResult(action: () => unknown) {
  try { action(); }
  catch (e) { expect(e).toBeInstanceOf(FoldConflictError); return (e as FoldConflictError).result; }
  throw new Error('Expected fold conflict');
}

describe('checkpoint fold (pinned fold.c current-head semantics)', () => {
  it('classifies in NONWRITER/STALE/POLICY order, retains every root, and ignores unauthorized coverage', () => {
    const w = world(), base = makeRecord(w);
    const owner = makeRecord(w, { seq: 2n, text: 'owner edit', parents: [tuple(base)] });
    const writer = makeRecord(w, { writer: 1, seq: 2n, text: 'writer edit', parents: [tuple(base)] });
    const cover = [{ ...tuple(owner), seq: 999n, rootManifest: address(0x71) }];
    const stale = makeRecord(w, { writer: 1, revision: 7n, parents: cover });
    const reader = makeRecord(w, { writer: 2, revision: 1n, parents: cover });
    const forged = makeRecord(w, { writer: 1, seq: 3n, revision: 999n, parents: cover });
    const records = [base, owner, writer, stale, reader, forged];
    const before = [w.io.reads.length, w.io.puts.length, w.io.blobs.size];
    const r = foldCheckpoint(w.grant, records, 1);
    expect(r.viewRecordId).toBe(recordId(owner));
    expect(r.frontier).toHaveLength(2);
    expect(r.dispositions.map(d => d.disposition)).toEqual(['ACCEPTED', 'ACCEPTED', 'ACCEPTED', 'STALE', 'NONWRITER', 'POLICY']);
    expect(r.conflicts).toEqual([{ pathEnc: owner.paths[0].pathEnc, otherRecordId: recordId(writer), inView: true, inOther: true,
      writer: writer.writer, seq: 2n, rootManifest: writer.head.rootManifest }]);
    expect(r.retainedRoots).toEqual([...new Set([...records.map(x => x.head.rootManifest), base.head.rootManifest, address(0x71)])].sort());
    expect([w.io.reads.length, w.io.puts.length, w.io.blobs.size]).toEqual(before);
  });

  it.each(['owner', 'vault', 'writer-set'] as const)('rejects %s policy forgery at the current revision', which => {
    const w = world(), owner = makeRecord(w, { seq: 2n });
    const p = { ...w.policy, ...(which === 'owner' ? { owner: w.pub[3] }
      : which === 'vault' ? { vaultId: hex32<VaultId>(id(0x72)) } : { writers: [w.pub[0]] }) };
    const forged = makeRecord(w, { writer: 1, policy: p });
    expect(foldCheckpoint(w.grant, [owner, forged], 0).dispositions[1].disposition).toBe('POLICY');
  });

  it('hashes sorted deduplicated writers, not readers or insertion order', () => {
    const w = world();
    expect(writerSetHash(w.policy)).toBe(writerSetHash({ ...w.policy, writers: [w.pub[1], w.pub[0], w.pub[1]], readers: [] }));
    const owner = makeRecord(w), reordered = makeRecord(w, { writer: 1,
      policy: { ...w.policy, writers: [w.pub[1], w.pub[0], w.pub[1]], readers: [] } });
    expect(foldCheckpoint(w.grant, [owner, reordered], 0).dispositions[1].disposition).toBe('ACCEPTED');
  });

  it('has no owner bypass, and a removed writer listed as a reader is still NONWRITER', () => {
    const w = world();
    const policy = { ...w.policy, writers: [w.pub[1]], readers: [w.pub[0], w.pub[1]] };
    const owner = makeRecord(w, { policy }), writer = makeRecord(w, { writer: 1, policy });
    const result = foldCheckpoint(w.grant, [owner, writer], 0);
    expect(result.dispositions[0].disposition).toBe('NONWRITER');
    expect(result.viewRecordId).toBe(recordId(writer));
    const newOwner = makeRecord(w, { policy: { ...w.policy, writers: [w.pub[0]], readers: [w.pub[1]] }, revision: 9n, seq: 2n });
    expect(foldCheckpoint(w.grant, [newOwner, writer], 0).dispositions[1].disposition).toBe('NONWRITER');
  });

  it('marks later canonical copies DUPLICATE, but ignores conflicting nonwriter copies', () => {
    const w = world(), owner = makeRecord(w), writer = makeRecord(w, { writer: 1 });
    const readerA = makeRecord(w, { writer: 2 }), readerB = makeRecord(w, { writer: 2, parents: [tuple(owner)] });
    const result = foldCheckpoint(w.grant, [owner, writer, writer, readerA, readerB], 0);
    expect(result.dispositions.map(d => d.disposition)).toEqual(['ACCEPTED', 'ACCEPTED', 'DUPLICATE', 'NONWRITER', 'NONWRITER']);
    expect(result.frontier).toHaveLength(2);
  });

  it('rejects owner-policy ambiguity with retention/disposition diagnostics and no view', () => {
    const w = world(), base = makeRecord(w);
    const changed = makeRecord(w, { seq: 2n, policy: { ...w.policy, writers: [w.pub[0]] } });
    const result = conflictResult(() => foldCheckpoint(w.grant, [base, changed], 1));
    expect(result.viewRecordId).toBeNull();
    expect(result.retainedRoots).toEqual([base.head.rootManifest, changed.head.rootManifest].sort());
  });

  it.each(['different roots', 'same root different body'] as const)('rejects same-sequence owner equivocation: %s', kind => {
    const w = world(), a = makeRecord(w, { seq: 4n });
    const b = makeRecord(w, { seq: 4n, ...(kind === 'different roots' ? { text: 'fork' } : { parents: [tuple(a)] }) });
    const r = conflictResult(() => foldCheckpoint(w.grant, [a, b], 0));
    expect(r.viewRecordId).toBeNull(); expect(r.frontier).toEqual([]);
  });

  it('keeps member forks instead of choosing a seq/root/hash winner', () => {
    const w = world(), owner = makeRecord(w), a = makeRecord(w, { writer: 1, seq: 2n, text: 'a' }),
      b = makeRecord(w, { writer: 1, seq: 2n, text: 'b' });
    const r = foldCheckpoint(w.grant, [owner, a, b], 0);
    expect(r.frontier).toHaveLength(3); expect(r.conflicts).toHaveLength(2);
    expect(r.viewRecordId).toBe(recordId(owner));
  });

  it('sequence-range parents dominate without matching roots or fetching ancestors', () => {
    const w = world(), writer = makeRecord(w, { writer: 1, seq: 2n });
    const owner = makeRecord(w, { seq: 3n, parents: [{ ...tuple(writer), seq: 5n, rootManifest: address(0x77) }] });
    const r = foldCheckpoint(w.grant, [owner, writer], 0);
    expect(r.frontier).toEqual([recordId(owner)]); expect(w.io.reads).toEqual([]);
    expect(r.retainedRoots).toContain(address(0x77));
  });

  it('higher seq alone has no edge; member parents create a sole provisional frontier', () => {
    const w = world(), owner = makeRecord(w), old = makeRecord(w, { writer: 1 });
    const noParents = makeRecord(w, { writer: 1, seq: 2n });
    expect(foldCheckpoint(w.grant, [owner, old, noParents], 0).frontier).toHaveLength(3);
    const newer = makeRecord(w, { writer: 1, seq: 2n, parents: memberHeadParents(w.pub[1], old.head, owner) });
    const r = foldCheckpoint(w.grant, [owner, old, newer], 0);
    expect(r.frontier).toEqual([recordId(newer)]); expect(r.viewRecordId).toBe(recordId(newer));
  });

  it('uses the highest accepted owner even off-frontier, never the latest timestamp', () => {
    const w = world(), owner = makeRecord(w, { writtenAt: 999n });
    const a = makeRecord(w, { writer: 1, seq: 2n, text: 'a', writtenAt: 10000n, parents: [tuple(owner)] });
    const b = makeRecord(w, { writer: 1, seq: 2n, text: 'b', parents: [tuple(owner)] });
    const r = foldCheckpoint(w.grant, [owner, a, b], 0);
    expect(r.frontier).not.toContain(recordId(owner)); expect(r.viewRecordId).toBe(recordId(owner));
  });

  it('fails closed for an empty frontier and for multi-frontier without accepted owner authority', () => {
    const w = world(), owner = makeRecord(w), writer = makeRecord(w, { writer: 1 });
    const a = makeRecord(w, { parents: [tuple(writer)] }), b = makeRecord(w, { writer: 1, parents: [tuple(owner)] });
    expect(conflictResult(() => foldCheckpoint(w.grant, [a, b], 0)).viewRecordId).toBeNull();
    const policy = { ...w.policy, writers: [w.pub[1], w.pub[3]] };
    const nonwriterOwner = makeRecord(w, { policy }), one = makeRecord(w, { writer: 1, policy }), two = makeRecord(w, { writer: 3, policy });
    expect(conflictResult(() => foldCheckpoint(w.grant, [nonwriterOwner, one, two], 0)).viewRecordId).toBeNull();
  });

  it('does not turn checkpoint dominance into strict DAG validation', () => {
    const w = world(), policy = { ...w.policy, writers: [w.pub[0], w.pub[1], w.pub[3]] };
    const owner = makeRecord(w, { policy }), a = makeRecord(w, { writer: 1, policy }), b = makeRecord(w, { writer: 3, policy });
    const ca = makeRecord(w, { writer: 1, policy, parents: [tuple(b)] }), cb = makeRecord(w, { writer: 3, policy, parents: [tuple(a)] });
    expect(foldCheckpoint(w.grant, [owner, ca, cb], 0).frontier).toEqual([recordId(owner)]);
  });

  it('enumerates changed files, directories, descendants, additions, deletions and long names in sorted order', () => {
    const w = world(), long = 'x'.repeat(255), childId = id(10);
    const child = (text: string): DirectoryNode => ({ version: 2, nodeId: childId, epoch: 1n,
      entries: [fileEntry(w.key, 'inside', [chunk(w, w.key, 1n, text)])] });
    const c1 = sealDirectoryNode(child('one'), w.key), c2 = sealDirectoryNode(child('two'), w.key);
    const dir = (root: Address): NodeEntry => ({ kind: 'directory', namePlain: 'directory', nameEnc: encryptName(w.key, 'directory'),
      mode: 0o755, mtimeNs: 0n, sizePlain: 0n, childNodeId: childId, childEpoch: 1n, manifestAddress: root });
    const entries = (which: number): NodeEntry[] => [dir(which ? c2.address : c1.address),
      fileEntry(w.key, 'file', [chunk(w, w.key, 1n, which ? 'other' : 'view')]),
      fileEntry(w.key, long, [], { mtimeNs: BigInt(which) }), fileEntry(w.key, which ? 'addition' : 'deleted-in-other', [])];
    const owner = makeRecord(w, { entries: entries(0), extraObjects: [{ ...c1, epoch: 1n, ring: w.ring }] });
    const other = makeRecord(w, { writer: 1, entries: entries(1), extraObjects: [{ ...c2, epoch: 1n, ring: w.ring }] });
    const r = foldCheckpoint(w.grant, [owner, other], 0);
    expect(r.conflicts).toHaveLength(6);
    expect(r.conflicts.map(c => c.pathEnc)).toEqual([...r.conflicts.map(c => c.pathEnc)].sort());
    expect(r.conflicts.filter(c => c.inView && c.inOther)).toHaveLength(4);
    expect(r.conflicts).toContainEqual(expect.objectContaining({ pathEnc: encryptName(w.key, 'addition'), inView: false, inOther: true }));
    expect(r.conflicts).toContainEqual(expect.objectContaining({ pathEnc: encryptName(w.key, 'deleted-in-other'), inView: true, inOther: false }));
    expect(r.conflicts.some(c => c.pathEnc.includes('/'))).toBe(true);
  });

  it('retains deletion-only conflicts without fabricating file bytes', () => {
    const w = world(), owner = makeRecord(w, { text: null }), other = makeRecord(w, { writer: 1 });
    expect(foldCheckpoint(w.grant, [owner, other], 0).conflicts[0]).toMatchObject({ inView: false, inOther: true });
    const deleted = makeRecord(w, { writer: 1, text: null }), withFile = makeRecord(w);
    expect(foldCheckpoint(w.grant, [withFile, deleted], 0).conflicts[0]).toMatchObject({ inView: true, inOther: false });
  });

  it('binds the checkpoint to grant owner/vault/node and rejects a deliberately older owner', () => {
    const w = world(), owner = makeRecord(w), newer = makeRecord(w, { seq: 2n }), writer = makeRecord(w, { writer: 1 });
    expect(errorCode(() => foldCheckpoint(w.grant, [owner, newer], 0))).toBe('CONFLICT');
    expect(errorCode(() => foldCheckpoint(w.grant, [owner, writer], 1))).toBe('AUTH');
    expect(errorCode(() => foldCheckpoint({ ...w.grant, nodeId: id(0xee) }, [owner], 0))).toBe('AUTH');
    expect(errorCode(() => foldCheckpoint({ ...w.grant, vaultId: hex32<VaultId>(id(0xee)) }, [owner], 0))).toBe('AUTH');
    expect(errorCode(() => foldCheckpoint(w.grant, Array(257).fill(owner), 0))).toBe('ARG');
  });
});

describe('Onyx fold input set and warm/cold equivalence', () => {
  it('returns byte-for-byte identical FoldResults with old cached members and audit-only owners', () => {
    const w = world(), base = makeRecord(w), oldWriter = makeRecord(w, { writer: 1, text: 'old member edit' });
    const owner = makeRecord(w, { seq: 2n, parents: [tuple(base)] });
    const writer = makeRecord(w, { writer: 1, seq: 2n, parents: [tuple(base)], text: 'current member edit' });
    const cold = foldCurrentHeads(w.grant, [owner, writer]);
    for (const warm of [[base, oldWriter, owner, writer], [writer, owner, oldWriter, base], [base, owner, writer, writer]]) {
      expect(foldCurrentHeads(w.grant, warm)).toEqual(cold);
      const input = selectFoldInputs(w.grant, warm);
      expect(input.records).toHaveLength(2);
      expect(input.records).not.toContain(oldWriter);
    }
  });

  it('keeps warm/cold record identities stable for equivalent bodies in replaced outer events', () => {
    const w = world(), old = makeRecord(w);
    const event = finalizeEvent({ ...buildHeadEvent(old.head, w.key, w.pub[0]), created_at: 2 }, w.secrets[0]);
    const sealed = sealDirectoryNode(old.root, w.key);
    const current = openRecord(event, w.vaultId, w.ring, 1n, [{ ...sealed, epoch: 1n, ring: w.ring }]);
    expect(current.canonicalHeadHash).toBe(old.canonicalHeadHash);
    expect(current.eventId).not.toBe(old.eventId);
    expect(foldCurrentHeads(w.grant, [old, current])).toEqual(foldCurrentHeads(w.grant, [current]));
    expect(foldCurrentHeads(w.grant, [current, old]).viewRecordId).toBe(recordId(current));
    expect(foldCheckpoint(w.grant, [old, current], 0).dispositions[1].disposition).toBe('DUPLICATE');
  });

  it('does not apply the current-head cap to 257 audit-only historical owner heads', () => {
    const w = world();
    const history = Array.from({ length: 258 }, (_, n) => makeRecord(w, { seq: BigInt(n + 1) }));
    const latest = history[history.length - 1];
    const cold = foldCurrentHeads(w.grant, [latest]);
    expect(foldCurrentHeads(w.grant, history)).toEqual(cold);
    expect(foldCurrentHeads(w.grant, [...history].reverse())).toEqual(cold);
    expect(selectFoldInputs(w.grant, history).records).toEqual([latest]);
  });

  it('uses cached owner rows only to detect ambiguity and prior accepted equivocation', () => {
    const w = world(), owner = makeRecord(w, { seq: 3n });
    const ambiguous = makeRecord(w, { policy: { ...w.policy, writers: [w.pub[0]] } });
    expect(conflictResult(() => foldCurrentHeads(w.grant, [owner, ambiguous])).viewRecordId).toBeNull();
    const oldA = makeRecord(w), oldB = makeRecord(w, { text: 'old owner fork' });
    expect(conflictResult(() => foldCurrentHeads(w.grant, [owner, oldA, oldB])).viewRecordId).toBeNull();
    const oldPolicy = makeRecord(w, { revision: 7n, policy: { ...w.policy, writers: [w.pub[0]] } });
    expect(foldCurrentHeads(w.grant, [owner, oldPolicy])).toEqual(foldCurrentHeads(w.grant, [owner]));
  });

  it('keeps highest-sequence ties for security checks, not arbitrary LWW', () => {
    const w = world(), owner = makeRecord(w), fork = makeRecord(w, { text: 'fork' });
    expect(errorCode(() => foldCurrentHeads(w.grant, [owner, fork]))).toBe('CONFLICT');
    const a = makeRecord(w, { writer: 1, text: 'a' }), b = makeRecord(w, { writer: 1, text: 'b' });
    expect(foldCurrentHeads(w.grant, [owner, a, b]).frontier).toHaveLength(3);
    expect(errorCode(() => foldCurrentHeads(w.grant, [a, b]))).toBe('INCOMPLETE');
  });
});

describe('parent coverage', () => {
  it('carries incorporated tuples and transitive coverage, sorted highest seq per writer', () => {
    const w = world(), owner = makeRecord(w), member = makeRecord(w, { writer: 1, seq: 2n,
      parents: [{ writer: w.pub[3], seq: 9n, rootManifest: address(0x71) }] });
    const successor: VaultHead = { ...owner.head, seq: 3n, parents: [tuple(owner)] };
    const result = coverHead(successor, [owner, member]);
    expect(result.parents).toHaveLength(3);
    expect(result.parents.map(p => p.writer)).toEqual([...result.parents.map(p => p.writer)].sort());
    expect(result.parents.find(p => p.writer === w.pub[3])!.seq).toBe(9n);
    expect(includeHead(successor, member.head, member.writer).parents).toEqual(result.parents);
    expect(memberHeadParents(member.writer, member.head, owner)).toEqual(result.parents);
    expect(successor.parents).toEqual([tuple(owner)]);
  });

  it('detects every equal-seq root fork even when a higher seq hides it, in any order', () => {
    const w = world();
    const low: HeadParent = { writer: w.pub[1], seq: 2n, rootManifest: address(1) },
      fork = { ...low, rootManifest: address(2) }, high = { ...low, seq: 9n };
    for (const parents of [[low, fork, high], [high, low, fork], [fork, high, low]])
      expect(errorCode(() => mergeParents(parents))).toBe('CONFLICT');
  });

  it('never truncates the 64-writer cap and leaves input heads unchanged on errors', () => {
    const w = world(), owner = makeRecord(w);
    const parents = Array.from({ length: 64 }, (_, n): HeadParent => ({ writer: hex32(id(n + 100)), seq: 1n, rootManifest: address(0) }));
    const head = { ...owner.head, parents }, saved = structuredClone(head);
    expect(coverHead(head, []).parents).toHaveLength(64);
    expect(errorCode(() => coverHead(head, [owner]))).toBe('TOO_LARGE');
    expect(head).toEqual(saved);
    expect(errorCode(() => coverHead(head, [makeRecord(w, { policy: { ...w.policy, vaultId: hex32<VaultId>(id(0x99)) } })]))).toBe('ARG');
    expect(head).toEqual(saved);
  });
});
