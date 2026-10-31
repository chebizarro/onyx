import { describe, expect, it, vi } from 'vitest';
import { reconstructHistoricalRings } from '../engine';
import { retainRootEvidence } from '../retained-roots';
import { openDirectoryNode } from '../dir-node';
import { hashAddress } from '../crypto';
import { fetchRecord } from '../record';
import { newOwnerHead, revokeTree, sealTree } from '../tree';
import { world, nestedTree, signHead, cBytes } from './policy-fixtures';

async function history() {
  const w = world(), old = await nestedTree(w, true);
  const rotated = revokeTree(old.tree, old.head, w.pub[0], w.pub[1], 1800000000n, () => cBytes(0x77));
  const sealed = await sealTree(rotated, w.io);
  const head = newOwnerHead(sealed.tree, old.head, w.pub[0], sealed.rootManifest, 1800000000n);
  const event = signHead(w, head, 0, sealed.tree.nodes[0].ring.entries[1].nodeKey);
  const grant = { ...w.grant, rootManifest: sealed.rootManifest, ring: sealed.tree.nodes[0].ring };
  const fresh = await fetchRecord(event, grant, grant.ring, head.epoch, w.io);
  return { w, old, fresh, grant };
}

describe('authenticated historical root epochs', () => {
  it('opens every retained manifest once with its recorded epoch, including old overrides', async () => {
    const { w, old, fresh, grant } = await history();
    const open = vi.fn(openDirectoryNode);
    const tree = await reconstructHistoricalRings(fresh.tree, grant.ring, retainRootEvidence([], [old.head]), async address => w.io.read(address), undefined, open);
    expect(open.mock.calls.map(([ring, epoch, bytes]) => ({ epochs: ring.entries.map(e => e.epoch), epoch, bytes: bytes.length })))
      .toEqual(old.tree.nodes.map(() => ({ epochs: [1n], epoch: 1n, bytes: expect.any(Number) })));
    expect(tree.nodes[1].ring.entries.map(e => e.epoch)).toEqual([1n, 2n]);
    const expected = [old.rootManifest, ...old.tree.nodes.flatMap(item => item.node.entries.flatMap(entry => entry.kind === 'directory' ? [entry.manifestAddress] : []))];
    expect(open.mock.calls.map(([, , bytes]) => hashAddress(bytes))).toEqual(expected);
  });
  it('never tries another ring key after the recorded key fails authentication', async () => {
    const { w, old, fresh, grant } = await history();
    const open = vi.fn(openDirectoryNode);
    await expect(reconstructHistoricalRings(fresh.tree, grant.ring, [{ address: old.rootManifest, epoch: '2' }], async address => w.io.read(address), undefined, open))
      .rejects.toMatchObject({ code: 'CRYPTO' });
    expect(open).toHaveBeenCalledTimes(1);
    expect(open.mock.calls[0][1]).toBe(2n);
    expect(open.mock.calls[0][0].entries.map(e => e.epoch)).toEqual([2n]);
  });
  it.each(['legacy', 'unknown', 'null'] as const)('fails closed without opening a %s root', async shape => {
    const { w, old, fresh, grant } = await history();
    const open = vi.fn(openDirectoryNode), read = vi.fn(async address => w.io.read(address));
    const retained = shape === 'null' ? null : shape === 'legacy' ? [old.rootManifest] : [{ address: old.rootManifest, epoch: null }];
    await expect(reconstructHistoricalRings(fresh.tree, grant.ring, retained, read, undefined, open)).rejects.toMatchObject({ code: 'EPOCH' });
    expect(open).not.toHaveBeenCalled(); expect(read).not.toHaveBeenCalled();
  });
  it('upgrades legacy addresses only with verified head evidence, never parent tuples', async () => {
    const { old, fresh } = await history();
    const roots = retainRootEvidence([old.rootManifest], [fresh.record.head]);
    expect(roots.find(root => root.address === old.rootManifest)?.epoch).toBeNull();
    expect(retainRootEvidence(roots, [old.head]).find(root => root.address === old.rootManifest)?.epoch).toBe('1');
    expect(retainRootEvidence(null)).toEqual([]);
    expect(() => retainRootEvidence([{ address: old.rootManifest, epoch: '2' }], [old.head])).toThrow();
  });
});
