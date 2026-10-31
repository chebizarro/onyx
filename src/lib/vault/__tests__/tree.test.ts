import { describe, expect, it } from 'vitest';
import { finalizeEvent } from 'nostr-tools';
import cborFixture from '../../../../tests/fixtures/vault/dir-node.json';
import keys from '../../../../tests/fixtures/vault/ring-derivation.json';
import {
  bytes32, bytesToHex, deriveChildNodeKey, deriveRootNodeKey, encryptName, hex32, hexToBytes, nameEnc, openChunk, sealChunk,
} from '../crypto';
import { decodeDirectoryNode, encodeDirectoryNode, sealDirectoryNode } from '../dir-node';
import { buildHeadEvent } from '../head';
import { entryDigest, fetchRecord, openRecord } from '../record';
import {
  appendRing, copyRing, dropRingBefore, initRing, mergeRings, resolveChildRing, selectedRing, validateKeyRing,
} from '../ring';
import { addTreeMember, captureTree, createTree, newOwnerHead, revokeTree, sealTree, treeFromRecord, validatePublicationTree, validateTree } from '../tree';
import { PORTHOME_MAX_ENTRIES, PORTHOME_SEAL_OVERHEAD, UINT64_MAX, VAULT_MAX_MANIFEST_RECEPTION_BYTES } from '../protocol';
import type { NodeEntry, NodeId, RefState, VaultTree } from '../types';
import { address, cBytes, errorCode, id, makeRecord, nestedTree, signHead, tuple, world } from './policy-fixtures';

function wideGraph(w: ReturnType<typeof world>, count: number, entries: readonly NodeEntry[], last = entries): VaultTree {
  return { nodes: [{ node: { version: 2, nodeId: id(250), epoch: 1n, vault: w.policy,
    entries: Array.from({ length: count }, (_, n): NodeEntry => ({ kind: 'directory', namePlain: `dir${n}`,
      nameEnc: nameEnc(n.toString(16).padStart(48, '0')), mode: 0, mtimeNs: 0n, sizePlain: 0n,
      childNodeId: id(n + 1), childEpoch: 1n, manifestAddress: address(0), keyOverride: w.key })) }, ring: w.ring },
  ...Array.from({ length: count }, (_, n) => ({ node: { version: 2 as const, nodeId: id(n + 1), epoch: 1n,
    entries: n === count - 1 ? last : entries }, ring: w.ring }))] };
}


describe('rings and exact descendant key composition', () => {
  it('uses pinned HKDF bytes and literal key overrides', () => {
    const root = deriveRootNodeKey(hexToBytes(keys.seedHex));
    const childId = hex32<NodeId>(keys.childNodeIdHex);
    const child = deriveChildNodeKey(root, childId);
    expect(bytesToHex(root)).toBe(keys.keys.root); expect(bytesToHex(child)).toBe(keys.keys.child);
    const override = bytes32(cBytes(0x55));
    expect(deriveChildNodeKey(root, childId, override)).toEqual(override);
    expect(deriveChildNodeKey(root, id(10))).not.toEqual(child);
    expect(deriveChildNodeKey(override, id(10))).not.toEqual(deriveChildNodeKey(child, id(10)));
  });

  it('owns copies, appends latest+1, allows decoded gaps, and never drops history implicitly', () => {
    const one = initRing(1n, cBytes(1));
    const gapped = copyRing({ entries: [one.entries[0], { epoch: 3n, nodeKey: bytes32(cBytes(2)) }] });
    expect(appendRing(gapped, cBytes(3)).entries.map(e => e.epoch)).toEqual([1n, 3n, 4n]);
    const copy = copyRing(gapped); copy.entries[0].nodeKey[0] = 0xff;
    expect(gapped.entries[0].nodeKey[0]).toBe(1);
    expect(dropRingBefore(gapped, 3n).entries.map(e => e.epoch)).toEqual([3n]);
    expect(gapped.entries).toHaveLength(2);
    expect(errorCode(() => dropRingBefore(gapped, 2n))).toBe('EPOCH');
    expect(errorCode(() => appendRing(gapped, cBytes(1)))).toBe('ARG');
    expect(errorCode(() => appendRing(initRing(UINT64_MAX, cBytes(1)), cBytes(2)))).toBe('TOO_LARGE');
  });

  it.each([
    [], [{ epoch: 0n, nodeKey: bytes32(cBytes(1)) }],
    [{ epoch: 2n, nodeKey: bytes32(cBytes(1)) }, { epoch: 1n, nodeKey: bytes32(cBytes(2)) }],
    [{ epoch: 1n, nodeKey: bytes32(cBytes(1)) }, { epoch: 2n, nodeKey: bytes32(cBytes(1)) }],
  ].map(entries => ({ entries })))('rejects invalid ring shape %#', ({ entries }) => {
    expect(errorCode(() => validateKeyRing({ entries }))).toBe('ARG');
  });

  it('never tries another epoch after failed authentication or a missing epoch', () => {
    const old = initRing(1n, cBytes(0x55)), ring = appendRing(old, cBytes(0x77));
    const sealed = sealChunk(old.entries[0].nodeKey, new TextEncoder().encode('old'));
    expect(openChunk(ring, 1n, sealed.sealed, 3n)).toEqual(new TextEncoder().encode('old'));
    expect(errorCode(() => openChunk(ring, 2n, sealed.sealed, 3n))).toBe('CRYPTO');
    expect(errorCode(() => openChunk(dropRingBefore(ring, 2n), 1n, sealed.sealed, 3n))).toBe('EPOCH');
  });

  it('merges grants without rollback or silently replacing a known epoch key', () => {
    const old = initRing(1n, cBytes(1)), next = appendRing(old, cBytes(2));
    expect(mergeRings(next, old)).toEqual(next);
    expect(errorCode(() => mergeRings(old, initRing(1n, cBytes(3))))).toBe('EPOCH');
  });

  it('ports fetch.c current override/held/derive priority without inventing history', () => {
    const w = world(), childId = id(10), derived = deriveChildNodeKey(w.key, childId);
    const history = appendRing(initRing(1n, derived), cBytes(0x55));
    const entry: Extract<NodeEntry, { kind: 'directory' }> = { kind: 'directory', namePlain: 'dir', nameEnc: encryptName(w.key, 'dir'),
      mode: 0, mtimeNs: 0n, sizePlain: 0n, childNodeId: childId, childEpoch: 2n, manifestAddress: address(0), keyOverride: bytes32(cBytes(0x77)) };
    const composed = resolveChildRing(w.ring, 1n, entry, history);
    expect(composed.entries.map(e => e.epoch)).toEqual([1n, 2n]);
    expect(composed.entries[0].nodeKey).toEqual(derived);
    expect(composed.entries[1].nodeKey).toEqual(cBytes(0x77));
    const { keyOverride: _override, ...without } = entry;
    expect(resolveChildRing(w.ring, 1n, without, history)).toEqual(history);
    expect(resolveChildRing(w.ring, 1n, without).entries).toEqual([{ epoch: 2n, nodeKey: derived }]);
    expect(selectedRing(appendRing(history, cBytes(0x88)), 2n, cBytes(0x77))).toEqual(composed);
  });
});

describe('capture and immutable closed trees', () => {
  it('sorts new capture entries by UTF-8 basename, preserves imported order and zero-chunk files', () => {
    const w = world();
    const tree = captureTree({ nodeId: w.nodeId, epoch: 1n, vault: w.policy, entries: ['z', 'ä', 'a', '.hidden'].map(namePlain =>
      ({ kind: 'file' as const, namePlain, mode: 0o644, mtimeNs: 0n, chunks: [] })) }, w.ring);
    expect(tree.nodes[0].node.entries.map(e => e.namePlain)).toEqual(['.hidden', 'a', 'z', 'ä']);
    expect(tree.nodes[0].node.entries.every(e => e.sizePlain === 0n && e.kind === 'file' && e.chunks.length === 0)).toBe(true);
    const reverse = { ...tree.nodes[0].node, entries: [...tree.nodes[0].node.entries].reverse() };
    const imported = createTree([{ node: reverse, ring: w.ring }]);
    expect(imported.nodes[0].node.entries).toEqual(reverse.entries);
    imported.nodes[0].ring.entries[0].nodeKey[0] ^= 1;
    expect(w.ring.entries[0].nodeKey).toEqual(w.key);
  });

  it('builds empty descendants, seals bottom-up and binds the signed root', async () => {
    const w = world(), built = await nestedTree(w);
    expect(built.tree.nodes).toHaveLength(3);
    expect(built.objects.map(o => o.address)).toEqual(w.io.puts);
    expect(built.objects[built.objects.length - 1].address).toBe(built.rootManifest);
    expect(built.tree.nodes[1].node.entries.find(e => e.kind === 'directory')!.kind).toBe('directory');
    const fetched = await fetchRecord(built.event, w.grant, w.ring, 1n, w.io);
    expect(fetched.record.nodesById.size).toBe(3);
    expect(fetched.record.paths.map(p => p.pathEnc)).toEqual([...fetched.record.paths.map(p => p.pathEnc)].sort());
    const restored = treeFromRecord(fetched.record, nodeId => built.tree.nodes.find(v => v.node.nodeId === nodeId)!.ring);
    expect(restored).toEqual(built.tree);
    expect(fetched.tree.nodes[1].ring).toEqual(built.tree.nodes[1].ring);
  });

  it.each(['missing', 'orphan', 'duplicate', 'child epoch', 'latest epoch'] as const)('rejects an invalid graph: %s', async kind => {
    const w = world(), { tree } = await nestedTree(w);
    let nodes = [...tree.nodes];
    if (kind === 'missing') nodes = nodes.slice(0, 1);
    if (kind === 'orphan') nodes = [...nodes, { node: { version: 2, nodeId: id(0xee), epoch: 1n, entries: [] }, ring: w.ring }];
    if (kind === 'duplicate') nodes = [...nodes, nodes[1]];
    if (kind === 'child epoch') nodes[1] = { ...nodes[1], node: { ...nodes[1].node, epoch: 2n }, ring: initRing(2n, w.key) };
    if (kind === 'latest epoch') nodes[0] = { ...nodes[0], ring: appendRing(nodes[0].ring, cBytes(0x77)) };
    expect(errorCode(() => createTree(nodes))).toBe({ missing: 'INCOMPLETE', orphan: 'ARG', duplicate: 'CONFLICT', 'child epoch': 'EPOCH', 'latest epoch': 'EPOCH' }[kind]);
  });

  it('rejects graph aliases and encoded paths beyond the pinned limit', async () => {
    const w = world(), { tree } = await nestedTree(w);
    const dir = tree.nodes[0].node.entries.find(e => e.kind === 'directory')!;
    const alias = { ...dir, namePlain: 'alias', nameEnc: encryptName(w.key, 'alias') };
    expect(errorCode(() => createTree(tree.nodes.map((v, i) => i ? v : { ...v, node: { ...v.node, entries: [...v.node.entries, alias] } })))).toBe('CONFLICT');
    let child = { nodeId: id(100), epoch: 1n, entries: [] } as import('../tree').CaptureDirectory;
    for (let i = 0; i < 84; i++) child = { nodeId: id(101 + i), epoch: 1n, entries: [
      { kind: 'directory', namePlain: 'd', mode: 0, mtimeNs: 0n, child },
    ] };
    expect(errorCode(() => captureTree({ ...child, vault: w.policy }, w.ring))).toBe('TOO_LARGE');
  });

  it('owner add-member is idempotent and read membership never removes writer authority', async () => {
    const w = world(), { tree } = await nestedTree(w);
    expect(errorCode(() => addTreeMember(tree, w.pub[2], w.pub[3], 'write'))).toBe('AUTH');
    const next = addTreeMember(tree, w.pub[0], w.pub[3], 'write');
    expect(next.nodes[0].node.vault!.grantsRev).toBe(9n);
    expect(addTreeMember(next, w.pub[0], w.pub[3], 'write')).toEqual(next);
    const readToo = addTreeMember(next, w.pub[0], w.pub[3], 'read');
    expect(readToo.nodes[0].node.vault!.writers).toContain(w.pub[3]);
    expect(tree.nodes[0].node.vault!.grantsRev).toBe(8n);
  });

  it('owner head construction includes transitive coverage and preserves root overrides', async () => {
    const w = world(), { tree, rootManifest, head } = await nestedTree(w);
    const prior = { ...head, keyOverride: bytes32(w.key), parents: [{ writer: w.pub[1], seq: 7n, rootManifest: address(0x71) }] };
    const next = newOwnerHead(tree, prior, w.pub[0], rootManifest, 2n);
    expect(next.seq).toBe(2n); expect(next.keyOverride).toEqual(w.key);
    expect(next.parents).toContainEqual(tuple({ writer: w.pub[0], head: prior }));
    expect(next.parents).toContainEqual(prior.parents[0]);
    expect(errorCode(() => newOwnerHead(tree, null, w.pub[1], rootManifest, 2n))).toBe('AUTH');
    expect(errorCode(() => newOwnerHead(tree, head, w.pub[0], address(0xee), 2n))).toBe('HASH_MISMATCH');
    expect(errorCode(() => newOwnerHead(tree, { ...head, seq: UINT64_MAX }, w.pub[0], rootManifest, 2n))).toBe('TOO_LARGE');
    expect(errorCode(() => newOwnerHead(tree, { ...head, refState: hex32<RefState>(id(0x77)) }, w.pub[0], rootManifest, 2n))).toBe('INCOMPLETE');
  });

  it('does not mutate any parent address when a durable manifest PUT fails', async () => {
    const w = world(), built = await nestedTree(w), before = structuredClone(built.tree);
    w.io.failPut = true;
    await expect(sealTree(built.tree, w.io)).rejects.toThrow('response lost');
    expect(built.tree).toEqual(before);
  });

  it('rejects nested share boundaries and unsupported ref_state for recursive revoke', async () => {
    const w = world(), built = await nestedTree(w);
    const nested = createTree(built.tree.nodes.map((v, i) => i === 1 ? { ...v, node: { ...v.node, vault: w.policy } } : v));
    expect(errorCode(() => revokeTree(nested, built.head, w.pub[0], w.pub[1], 2n))).toBe('CONFLICT');
    expect(errorCode(() => revokeTree(built.tree, { ...built.head, refState: hex32<RefState>(id(0x77)) }, w.pub[0], w.pub[1], 2n))).toBe('INCOMPLETE');
  });
});

describe('publication safety against inherited C producer/reader asymmetries', () => {
  it('allows exactly 500000 aggregate paths and refuses one more before any PUT/head', async () => {
    const w = world();
    const files = Array.from({ length: 5000 }, (_, n): NodeEntry => ({ kind: 'file', namePlain: `file${n}`,
      nameEnc: nameEnc(n.toString(16).padStart(48, '0')), mode: 0, mtimeNs: 0n, sizePlain: 0n, chunks: [] }));
    const boundary = wideGraph(w, 100, files, files.slice(0, 4900));
    expect(boundary.nodes.reduce((n, v) => n + v.node.entries.length, 0)).toBe(PORTHOME_MAX_ENTRIES);
    expect(() => validatePublicationTree(boundary)).not.toThrow();
    const over = wideGraph(w, 100, files, files.slice(0, 4901));
    await expect(sealTree(over, w.io)).rejects.toMatchObject({ code: 'TOO_LARGE' });
    expect(errorCode(() => newOwnerHead(over, null, w.pub[0], address(0), 1n))).toBe('TOO_LARGE');
    expect(w.io.puts).toEqual([]);
  }, 60000);

  it('preflights the 64 MiB final sealed-manifest graph before PUTs or a publishable head', async () => {
    const w = world();
    const entries = Array.from({ length: 250 }, (_, n): NodeEntry => ({ kind: 'symlink', namePlain: `link${n}`,
      nameEnc: nameEnc(n.toString(16).padStart(48, '0')), mode: 0, mtimeNs: 0n, sizePlain: 0n, target: 'x'.repeat(4096) }));
    const within = wideGraph(w, 64, entries), over = wideGraph(w, 65, entries);
    const childBytes = encodeDirectoryNode(within.nodes[1].node).length + PORTHOME_SEAL_OVERHEAD;
    expect(childBytes * 64 + encodeDirectoryNode(within.nodes[0].node).length + PORTHOME_SEAL_OVERHEAD)
      .toBeLessThanOrEqual(VAULT_MAX_MANIFEST_RECEPTION_BYTES);
    expect(childBytes * 65).toBeGreaterThan(VAULT_MAX_MANIFEST_RECEPTION_BYTES);
    expect(() => validatePublicationTree(within)).not.toThrow();
    await expect(sealTree(over, w.io)).rejects.toMatchObject({ code: 'TOO_LARGE' });
    expect(errorCode(() => newOwnerHead(over, null, w.pub[0], address(0), 1n))).toBe('TOO_LARGE');
    expect(w.io.puts).toEqual([]);
  }, 60000);
});

describe('verified record walks', () => {
  it('matches the C-produced synthetic one-entry-node digest exactly', () => {
    const vector = cborFixture.valid.find(v => v.name === 'one-file-one-chunk')!;
    const node = decodeDirectoryNode(hexToBytes(vector.cborHex));
    expect(entryDigest(node.entries[0])).toBe('be871082964bf3675cb5b211bc7bfcf1f1e23f754b4df2b09010588fa9eb063c');
    // The enclosing node's ID/epoch/vault are not part of the per-entry digest.
    const w = world(), record = makeRecord(w, { entries: node.entries });
    expect(record.paths[0].entryDigest).toBe(entryDigest(node.entries[0]));
  });

  it('hashes every requested sealed object before decode, never treating corrupt ciphertext as plaintext', async () => {
    const w = world(), built = await nestedTree(w);
    w.io.corrupt = true;
    await expect(fetchRecord(built.event, w.grant, w.ring, 1n, w.io)).rejects.toMatchObject({ code: 'HASH_MISMATCH' });
    const corrupt = built.objects.map(o => ({ ...o, sealed: o.sealed.slice() }));
    corrupt[0].sealed[0] ^= 1;
    expect(errorCode(() => openRecord(built.event, w.vaultId, w.ring, 1n, corrupt))).toBe('HASH_MISMATCH');
    const unaddressed = corrupt.map(({ address: _address, ...o }) => o);
    expect(errorCode(() => openRecord(built.event, w.vaultId, w.ring, 1n, unaddressed))).toBe('INCOMPLETE');
  });

  it('rejects missing/repeated objects, wrong child IDs/epochs and a mismatched root policy', async () => {
    const w = world(), built = await nestedTree(w);
    expect(errorCode(() => openRecord(built.event, w.vaultId, w.ring, 1n, []))).toBe('INCOMPLETE');
    expect(errorCode(() => openRecord(built.event, w.vaultId, w.ring, 1n, [...built.objects, built.objects[0]]))).toBe('ARG');
    const rootObject = built.objects[built.objects.length - 1];
    expect(errorCode(() => openRecord(built.event, w.vaultId, w.ring, 1n, [{ ...rootObject, epoch: 2n }, ...built.objects.slice(0, -1)]))).toBe('EPOCH');
    const root = built.tree.nodes[0].node;
    for (const change of [{ childNodeId: id(0xff) }, { childEpoch: 2n }]) {
      const changed = { ...root, entries: root.entries.map(e => e.kind === 'directory' ? { ...e, ...change } : e) };
      const sealed = sealDirectoryNode(changed, w.key), head = { ...built.head, rootManifest: sealed.address };
      expect(errorCode(() => openRecord(signHead(w, head), w.vaultId, w.ring, 1n,
        [...built.objects.slice(0, -1), { ...sealed, epoch: 1n, ring: w.ring }]))).toBe('childEpoch' in change ? 'EPOCH' : 'ARG');
    }
    expect(errorCode(() => openRecord(signHead(w, { ...built.head, grantsRev: 9n }), w.vaultId, w.ring, 1n, built.objects))).toBe('ARG');
    expect(errorCode(() => openRecord(built.event, w.vaultId, w.ring, 1n, built.objects, { nodeId: id(0xff) }))).toBe('ARG');
    expect(errorCode(() => openRecord(built.event, w.vaultId, w.ring, 1n, built.objects, { owner: w.pub[3] }))).toBe('ARG');
  });

  it('never trusts the signature cache or timestamp equality; owns the retained signed event', async () => {
    const w = world(), built = await nestedTree(w);
    const template = buildHeadEvent(built.head, w.key, w.pub[0]);
    const event = finalizeEvent({ ...template, created_at: 1000000 }, w.secrets[0]);
    const record = openRecord(event, w.vaultId, w.ring, 1n, built.objects);
    expect(record.head.writtenAt).toBe(1n);
    event.tags[0][1] = 'mutated';
    expect(record.signedEvent.tags[0][1]).not.toBe('mutated');
    expect(errorCode(() => openRecord({ ...built.event, sig: '00'.repeat(64) }, w.vaultId, w.ring, 1n, built.objects))).toBe('CRYPTO');
  });

  it('permits unused inventory like snapshot.c, but does not open it', async () => {
    const w = world(), built = await nestedTree(w);
    const record = openRecord(built.event, w.vaultId, w.ring, 1n,
      [...built.objects, { sealed: new Uint8Array([0xff]), epoch: 1n, ring: w.ring }]);
    expect(record.nodesById.size).toBe(3);
    const original = encodeDirectoryNode(record.root);
    expect(original).toEqual(encodeDirectoryNode(built.tree.nodes[0].node));
    validateTree(built.tree);
  });
});
