import { describe, expect, it } from 'vitest';
import { encryptName, equalBytes, hashAddress, openChunk, sealChunk } from '../crypto';
import { encodeDirectoryNode, sealDirectoryNode } from '../dir-node';
import { decodeGrant, encodeGrant } from '../grant';
import { foldCheckpoint } from '../fold';
import { openHead, sealHead } from '../head';
import { fetchRecord, openRecord, recordId } from '../record';
import { appendRing, initRing } from '../ring';
import {
  checkTreeChunks, readChunk, resealCandidate, resealCost, ResealTask, treeResealItems,
} from '../reseal';
import { createTree, newOwnerHead, revokeNode, revokeTree, sealTree } from '../tree';
import { UINT64_MAX } from '../protocol';
import type { ChunkRef, DirectoryNode, NodeEntry, VaultBlobIO } from '../types';
import { address, cBytes, chunk, errorCode, fileEntry, makeRecord, nestedTree, signHead, world } from './policy-fixtures';

function randomKeys(start = 0x70) { let n = start; return () => cBytes(++n); }

async function resealFixture() {
  const w = world();
  const data = new Uint8Array([104, 101, 108, 108, 111, 0, 0]);
  const entries = ['first', 'second'].map(name => fileEntry(w.key, name, [chunk(w, w.key, 1n, data)]));
  const initial = await sealTree(createTree([{ node: { version: 2, nodeId: w.nodeId, epoch: 1n, entries, vault: w.policy }, ring: w.ring }]), w.io);
  const head = newOwnerHead(initial.tree, null, w.pub[0], initial.rootManifest, 1n);
  const rotated = revokeTree(initial.tree, head, w.pub[0], w.pub[1], 2n, randomKeys());
  w.io.reads.length = w.io.puts.length = 0;
  return { w, data, initial, head, rotated, items: treeResealItems(rotated) };
}

describe('recursive revocation proposals', () => {
  it('rotates every directory, rehashes basenames, preserves chunks/history and input bytes', async () => {
    const w = world(), built = await nestedTree(w), before = structuredClone(built.tree);
    const next = revokeTree(built.tree, built.head, w.pub[0], w.pub[1], 2n, randomKeys());
    expect(built.tree).toEqual(before); expect(built.head.epoch).toBe(1n);
    expect(next.nodes.map(v => v.node.epoch)).toEqual([2n, 2n, 2n]);
    for (let i = 0; i < next.nodes.length; i++) {
      const old = built.tree.nodes[i], fresh = next.nodes[i];
      expect(fresh.ring.entries).toHaveLength(2);
      expect(fresh.ring.entries[0]).toEqual(old.ring.entries[0]);
      expect(fresh.ring.entries[1].nodeKey).not.toEqual(old.ring.entries[0].nodeKey);
      for (let j = 0; j < fresh.node.entries.length; j++) {
        const entry = fresh.node.entries[j];
        expect(entry.nameEnc).toBe(encryptName(fresh.ring.entries[1].nodeKey, entry.namePlain));
        expect(entry.nameEnc).not.toBe(old.node.entries[j].nameEnc);
        if (entry.kind === 'file') expect(entry.chunks).toEqual((old.node.entries[j] as Extract<NodeEntry, { kind: 'file' }>).chunks);
        else if (entry.kind === 'directory') {
          const child = next.nodes.find(v => v.node.nodeId === entry.childNodeId)!;
          expect(entry.childEpoch).toBe(2n); expect(entry.keyOverride).toEqual(child.ring.entries[1].nodeKey);
        }
      }
    }
    expect(next.nodes[0].node.vault).toMatchObject({ grantsRev: 9n, writers: [w.pub[0]], readers: [w.pub[2]] });
    const sealed = await sealTree(next, w.io);
    const previous = { ...built.head, parents: [{ writer: w.pub[3], seq: 7n, rootManifest: address(0x77) }] };
    const head = newOwnerHead(sealed.tree, previous, w.pub[0], sealed.rootManifest, 2n);
    expect(head.parents).toHaveLength(2); expect(head.keyOverride).toEqual(next.nodes[0].ring.entries[1].nodeKey);
    const payload = sealHead(head, next.nodes[0].ring.entries[1].nodeKey);
    expect(openHead(next.nodes[0].ring, 2n, payload)).toEqual(head);
    expect(errorCode(() => openHead(w.ring, 2n, payload))).toBe('EPOCH');
    expect(errorCode(() => sealHead(head, w.key))).toBe('ARG');
    const record = openRecord(signHead(w, head, 0, next.nodes[0].ring.entries[1].nodeKey), w.vaultId,
      next.nodes[0].ring, 2n, sealed.objects);
    expect(record.root.vault!.grantsRev).toBe(9n);
  });

  it('keeps revoked pending member edits and roots without treating them as incorporated', async () => {
    const w = world(), built = await nestedTree(w);
    const pending = makeRecord(w, { writer: 1, seq: 8n, text: 'unincorporated member edit' });
    const rotated = revokeTree(built.tree, built.head, w.pub[0], w.pub[1], 2n, randomKeys());
    const sealed = await sealTree(rotated, w.io), rootRing = sealed.tree.nodes[0].ring;
    const head = newOwnerHead(sealed.tree, built.head, w.pub[0], sealed.rootManifest, 2n);
    const owner = openRecord(signHead(w, head, 0, rootRing.entries[1].nodeKey), w.vaultId, rootRing, 2n, sealed.objects);
    const result = foldCheckpoint(w.grant, [owner, pending], 0);
    expect(result.dispositions[1].disposition).toBe('NONWRITER');
    expect(result.viewRecordId).toBe(recordId(owner)); expect(result.retainedRoots).toContain(pending.head.rootManifest);
    expect(head.parents.some(p => p.writer === pending.writer)).toBe(false);
    expect(pending.root.entries[0].kind).toBe('file');
  });

  it('low-level subtree boundary uses an independent override and does not change siblings', () => {
    const w = world(), record = makeRecord(w);
    const parent: Extract<NodeEntry, { kind: 'directory' }> = { kind: 'directory', namePlain: 'subtree', nameEnc: encryptName(w.key, 'subtree'),
      mode: 0o755, mtimeNs: 0n, sizePlain: 0n, childNodeId: w.nodeId, childEpoch: 1n, manifestAddress: record.head.rootManifest };
    const result = revokeNode(record.root, w.ring, w.pub[0], w.pub[1], { parent }, 2n, () => cBytes(0x55));
    expect(result.parent!.childEpoch).toBe(2n); expect(result.parent!.keyOverride).toEqual(cBytes(0x55));
    expect(result.parent!.manifestAddress).toBe(result.address);
    expect(parent.keyOverride).toBeUndefined(); expect(w.ring.entries).toHaveLength(1);
    expect(result.node.entries).toEqual(record.root.entries); // low-level revoke does not rehash names
    const sibling = sealChunk(w.key, new TextEncoder().encode('sibling'));
    expect(openChunk(w.ring, 1n, sibling.sealed, 7n)).toEqual(new TextEncoder().encode('sibling'));
  });

  it('requires exactly one subtree-parent or owner-head reference at the runtime boundary', () => {
    const w = world(), record = makeRecord(w);
    const parent: Extract<NodeEntry, { kind: 'directory' }> = { kind: 'directory', namePlain: 'subtree',
      nameEnc: encryptName(w.key, 'subtree'), mode: 0, mtimeNs: 0n, sizePlain: 0n, childNodeId: w.nodeId,
      childEpoch: 1n, manifestAddress: record.head.rootManifest };
    for (const reference of [{}, { parent, head: record.head }]) {
      expect(errorCode(() => revokeNode(record.root, w.ring, w.pub[0], w.pub[1],
        reference as Parameters<typeof revokeNode>[4], 2n, randomKeys()))).toBe('ARG');
    }
  });

  it.each(['unauthorized', 'self', 'wrong epoch', 'wrong root', 'revision overflow', 'sequence overflow', 'duplicate key'] as const)(
    'refuses %s without changing the input tree', async reason => {
      const w = world(), built = await nestedTree(w), before = structuredClone(built.tree);
      let tree = built.tree, head = built.head;
      if (reason === 'wrong epoch') head = { ...head, epoch: 2n };
      if (reason === 'wrong root') head = { ...head, rootManifest: address(0xff) };
      if (reason === 'sequence overflow') head = { ...head, seq: UINT64_MAX };
      if (reason === 'revision overflow') tree = createTree(tree.nodes.map((v, i) => i ? v : { ...v,
        node: { ...v.node, vault: { ...v.node.vault!, grantsRev: UINT64_MAX } } }));
      const code = errorCode(() => revokeTree(tree, head, reason === 'unauthorized' ? w.pub[2] : w.pub[0],
        reason === 'self' ? w.pub[0] : w.pub[1], 2n, reason === 'duplicate key' ? () => w.key.slice() : randomKeys()));
      expect(code).toBe({ unauthorized: 'AUTH', self: 'AUTH', 'wrong epoch': 'ARG', 'wrong root': 'HASH_MISMATCH',
        'revision overflow': 'TOO_LARGE', 'sequence overflow': 'TOO_LARGE', 'duplicate key': 'ARG' }[reason]);
      expect(built.tree).toEqual(before);
    });

  it('fresh-recipient historical-key gate FAILS CLOSED after override + recursive revoke + regrant', async () => {
    const w = world(), built = await nestedTree(w, true);
    const rotated = revokeTree(built.tree, built.head, w.pub[0], w.pub[1], 2n, randomKeys());
    const sealed = await sealTree(rotated, w.io), rootRing = sealed.tree.nodes[0].ring;
    const head = newOwnerHead(sealed.tree, built.head, w.pub[0], sealed.rootManifest, 2n);
    // This wire grant is ALL that a brand-new remaining reader receives.
    const grant = decodeGrant(encodeGrant({ ...w.grant, cap: 'read', ring: rootRing, rootManifest: sealed.rootManifest }));
    const event = signHead(w, head, 0, rootRing.entries[1].nodeKey);
    const cold = await fetchRecord(event, grant, grant.ring, 2n, w.io);
    expect(cold.tree.nodes[0].ring.entries.map(e => e.epoch)).toEqual([1n, 2n]);
    expect(cold.tree.nodes.slice(1).every(v => v.ring.entries.length === 1 && v.ring.entries[0].epoch === 2n)).toBe(true);
    const oldOverride = built.tree.nodes[1].ring.entries[0].nodeKey;
    expect(grant.ring.entries.some(e => equalBytes(e.nodeKey, oldOverride))).toBe(false);
    expect(await readChunk(built.rootFile, cold.tree.nodes[0].ring, w.io)).toHaveLength(7);
    w.io.reads.length = 0;
    await expect(checkTreeChunks(cold.tree, w.io)).rejects.toMatchObject({ code: 'EPOCH' });
    expect(w.io.reads).toEqual([]); // no trial keys, silent skip or undocumented eager rewrite
    // Explicitly held per-node history succeeds against exactly the same graph.
    const warm = await fetchRecord(event, grant, grant.ring, 2n, w.io,
      nodeId => rotated.nodes.find(v => v.node.nodeId === nodeId)?.ring);
    expect(await checkTreeChunks(warm.tree, w.io)).toMatchObject({ nodes: 3, chunks: 2, sizePlain: 14n });
    expect(built.childFile.kind === 'file' && built.childFile.chunks[0].chunkKeyId).toBe(1n);
  });
});

describe('lazy/eager immutable re-seal tasks (pinned reseal.c)', () => {
  it('reserves exactly 122 bytes per seven-byte job and runs only the fitting input prefix', async () => {
    const { w, rotated, items } = await resealFixture(), before = structuredClone(rotated);
    const task = new ResealTask(items);
    expect(items.map(i => resealCost((i.node.entries[i.entry] as Extract<NodeEntry, { kind: 'file' }>).chunks[i.chunk]))).toEqual([122n, 122n]);
    await expect(task.run(121n, w.io)).rejects.toMatchObject({ code: 'BUDGET' });
    expect(task.reserved).toBe(0n); expect(w.io.reads).toEqual([]); expect(w.io.puts).toEqual([]);
    await expect(task.run(122n, w.io)).rejects.toMatchObject({ code: 'BUDGET' });
    expect(task.completed).toBe(1); expect(task.remaining).toBe(1); expect(task.reserved).toBe(122n);
    const candidate = task.candidateFor(items[0].node);
    expect((candidate.entries[items[0].entry] as Extract<NodeEntry, { kind: 'file' }>).chunks[0].chunkKeyId).toBe(2n);
    expect((candidate.entries[items[1].entry] as Extract<NodeEntry, { kind: 'file' }>).chunks[0].chunkKeyId).toBe(1n);
    expect(rotated).toEqual(before);
    await task.run(122n, w.io);
    expect(task.completed).toBe(2); expect(task.reserved).toBe(244n); expect(task.pendingAddress).toBeNull();
    const next = resealCandidate(rotated, task);
    expect(await checkTreeChunks(next, w.io)).toMatchObject({ chunks: 2, sizePlain: 14n });
    expect(next.nodes[0].ring.entries).toHaveLength(2); expect(w.io.blobs.size).toBeGreaterThan(2);
    const snapshot = task.snapshot();
    const snapFile = snapshot.candidateNodes[0].entries[0] as Extract<NodeEntry, { kind: 'file' }>;
    (snapFile.chunks as ChunkRef[])[0] = { ...snapFile.chunks[0], chunkKeyId: 99n };
    expect(task.candidateFor(items[0].node)).not.toEqual(snapshot.candidateNodes[0]);
    task.dispose(); await expect(task.run(244n, w.io)).rejects.toMatchObject({ code: 'ARG' });
  });

  it('eager pre-flight refuses one byte short before ALL I/O', async () => {
    const { w, items } = await resealFixture(), task = new ResealTask(items, true);
    await expect(task.run(243n, w.io)).rejects.toMatchObject({ code: 'BUDGET' });
    expect(task.completed).toBe(0); expect(task.reserved).toBe(0n);
    expect(w.io.reads).toEqual([]); expect(w.io.puts).toEqual([]);
    expect((await task.run(244n, w.io)).completed).toBe(2);
  });

  it('rejects duplicate old-epoch jobs, skips current chunks, and gates missing historical keys before I/O', async () => {
    const { w, rotated, items } = await resealFixture();
    expect(errorCode(() => new ResealTask([items[0], items[0]]))).toBe('ARG');
    const noHistory = createTree(rotated.nodes.map(v => ({ ...v, ring: { entries: [v.ring.entries[1]] } })));
    expect(errorCode(() => new ResealTask(treeResealItems(noHistory)))).toBe('EPOCH');
    expect(w.io.reads).toEqual([]);
    const fresh = sealChunk(rotated.nodes[0].ring.entries[1].nodeKey, new Uint8Array([1]));
    const file = fileEntry(rotated.nodes[0].ring.entries[1].nodeKey, 'new', [{ address: fresh.address,
      sizeSealed: BigInt(fresh.sealed.length), sizePlain: 1n, chunkKeyId: 2n }]);
    const node: DirectoryNode = { ...rotated.nodes[0].node, entries: [file] };
    const item = { node, ring: rotated.nodes[0].ring, entry: 0, chunk: 0 };
    const task = new ResealTask([item, item]);
    expect((await task.run(0n, w.io)).remaining).toBe(0); expect(w.io.puts).toEqual([]);
  });

  it('canonical old-key re-sealing rejects a false true length within the zero tail', async () => {
    const { w, rotated } = await resealFixture();
    const source = rotated.nodes[0];
    const entries = source.node.entries.map((e, i): NodeEntry => i || e.kind !== 'file' ? e
      : { ...e, sizePlain: 6n, chunks: e.chunks.map(c => ({ ...c, sizePlain: 6n })) });
    const bad = createTree([{ ...source, node: { ...source.node, entries } }]);
    const task = new ResealTask(treeResealItems(bad).filter(item => item.entry === 0));
    await expect(task.run(UINT64_MAX, w.io)).rejects.toMatchObject({ code: 'ARG' });
    expect(w.io.puts).toEqual([]); expect(task.pendingAddress).toBeNull();
    const reads = w.io.reads.length;
    await expect(task.run(UINT64_MAX, w.io)).rejects.toMatchObject({ code: 'ARG' });
    expect(w.io.reads).toHaveLength(reads);
  });

  it('keeps an uncertain durable PUT pending, never advances refs, and never retries a failed task', async () => {
    const { w, data, items } = await resealFixture(), task = new ResealTask([items[0]]);
    const before = encodeDirectoryNode(items[0].node), key = items[0].ring.entries[1].nodeKey;
    const expected = sealChunk(key, data).address;
    w.io.failPut = true;
    await expect(task.run(UINT64_MAX, w.io)).rejects.toMatchObject({ code: 'IO' });
    expect(task.pendingAddress).toBe(expected); expect(w.io.blobs.has(expected)).toBe(true);
    expect(task.completed).toBe(0); expect(task.reserved).toBe(122n);
    expect(encodeDirectoryNode(task.candidateFor(items[0].node))).toEqual(before);
    w.io.failPut = false;
    await expect(task.run(UINT64_MAX, w.io)).rejects.toMatchObject({ code: 'IO' });
    expect(w.io.puts).toHaveLength(1); expect(w.io.reads).toHaveLength(1);
  });

  it.each(['hash', 'length', 'read failure'] as const)('rejects %s before upload and keeps the candidate unchanged', async kind => {
    const { w, items } = await resealFixture(), task = new ResealTask([items[0]]), before = task.snapshot();
    const io: VaultBlobIO = { read: a => {
      if (kind === 'read failure') throw new Error('read failed');
      const b = w.io.read(a);
      if (kind === 'hash') { b[0] ^= 1; return b; }
      return b.slice(1);
    }, put: w.io.put.bind(w.io) };
    await expect(task.run(UINT64_MAX, io)).rejects.toMatchObject({ code: kind === 'hash' ? 'HASH_MISMATCH' : 'IO' });
    expect(task.snapshot().candidateNodes).toEqual(before.candidateNodes); expect(w.io.puts).toEqual([]);
    expect(task.pendingAddress).toBeNull(); expect(task.reserved).toBe(122n);
  });

  it('refuses stale source keys mid-read, and cannot install an old-target candidate after a second revoke', async () => {
    const { w, rotated, items, head } = await resealFixture(), task = new ResealTask([items[0]]);
    const io: VaultBlobIO = { read: a => {
      const blob = w.io.read(a); items[0].ring.entries[1].nodeKey[0] ^= 1; return blob;
    }, put: w.io.put.bind(w.io) };
    await expect(task.run(UINT64_MAX, io)).rejects.toMatchObject({ code: 'ARG' });
    expect(w.io.puts).toEqual([]);
    items[0].ring.entries[1].nodeKey[0] ^= 1;
    const freshTask = new ResealTask(items); await freshTask.run(244n, w.io);
    const sealed = await sealTree(rotated, w.io), current = newOwnerHead(sealed.tree, head, w.pub[0], sealed.rootManifest, 2n);
    const second = revokeTree(sealed.tree, current, w.pub[0], w.pub[2], 3n, randomKeys(0x80));
    expect(errorCode(() => resealCandidate(second, freshTask))).toBe('ARG');
  });

  it('copies item coordinates at planning time instead of allowing job retargeting', async () => {
    const { w, items } = await resealFixture();
    const item = { ...items[0] }, originalEntry = item.entry;
    const task = new ResealTask([item]);
    item.entry = items[1].entry; // both source chunks have identical descriptors
    await task.run(122n, w.io);
    const node = task.candidateFor(item.node);
    expect((node.entries[originalEntry] as Extract<NodeEntry, { kind: 'file' }>).chunks[0].chunkKeyId).toBe(2n);
    expect((node.entries[item.entry] as Extract<NodeEntry, { kind: 'file' }>).chunks[0].chunkKeyId).toBe(1n);
  });

  it('checks source descriptors before I/O and target keys again before candidate installation', async () => {
    const { w, rotated, items } = await resealFixture();
    const task = new ResealTask([items[0]]);
    const file = items[0].node.entries[items[0].entry] as Extract<NodeEntry, { kind: 'file' }>;
    const old = file.chunks[0];
    (file.chunks as ChunkRef[])[0] = { ...old, address: address(0xff) };
    await expect(task.run(122n, w.io)).rejects.toMatchObject({ code: 'ARG' });
    expect(w.io.reads).toEqual([]);
    (file.chunks as ChunkRef[])[0] = old;
    const fresh = new ResealTask(items); await fresh.run(244n, w.io);
    items[0].ring.entries[1].nodeKey[0] ^= 1;
    expect(errorCode(() => resealCandidate(rotated, fresh))).toBe('ARG');
  });

  it('validates lengths and latest epochs before creating any job', async () => {
    const { w, items } = await resealFixture();
    expect(errorCode(() => new ResealTask([{ ...items[0], ring: appendRing(items[0].ring, cBytes(0x99)) }]))).toBe('ARG');
    expect(errorCode(() => new ResealTask([{ ...items[0], entry: -1 }]))).toBe('ARG');
    expect(errorCode(() => resealCost({ address: address(0), chunkKeyId: 1n, sizePlain: 1n << 40n, sizeSealed: 61n }))).toBe('TOO_LARGE');
    expect(w.io.reads).toEqual([]);
  });

  it('explicitly refuses legacy PCS v1 even though the pinned C migration branch supports it', async () => {
    const w = world(), sealed = new Uint8Array(61); sealed[0] = 1;
    const chunkRef: ChunkRef = { address: hashAddress(sealed), sizeSealed: 61n, sizePlain: 7n, chunkKeyId: 1n };
    w.io.blobs.set(chunkRef.address, sealed);
    await expect(readChunk(chunkRef, initRing(1n, cBytes(0x55)), w.io)).rejects.toMatchObject({ code: 'VERSION' });
  });

  it('stable tree jobs are ordered by encrypted path then chunk index', async () => {
    const w = world(), built = await nestedTree(w), items = treeResealItems(built.tree);
    const record = openRecord(built.event, w.vaultId, w.ring, 1n, built.objects);
    const paths = items.map(item => record.paths.find(p => p.nodeId === item.node.nodeId && p.entryIndex === item.entry)!.pathEnc);
    expect(paths).toEqual([...paths].sort());
    expect(items).toHaveLength(2);
    expect(sealDirectoryNode(built.tree.nodes[0].node, w.key).address).toBe(built.rootManifest);
  });
});
