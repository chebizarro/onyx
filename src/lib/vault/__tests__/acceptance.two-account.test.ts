import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Event } from 'nostr-tools';
import { openGrantWrap } from '../carrier';
import { encodeHead, openHeadEvent } from '../head';
import { filterLegacyPaths, intersectsManagedMount, isManagedPath } from '../legacy-exclusion';
import type { VaultEngine, VaultConflictResolution } from '../engine-api';
import type { VaultGrant, VaultId } from '../types';
import { encodeUtf8, hashAddress, hex32, openChunk } from '../crypto';
import { openDirectoryNode } from '../dir-node';
import { historyDTag, openEpochLedgerEvent } from '../epoch-ledger';
import { fetchRecord } from '../record';
import { network, signer, snapshot } from './engine-fixtures';
import { AcceptanceNetwork, device, recipient, type AcceptanceDevice } from './acceptance-two-account-fixtures';

const last = <T>(items: readonly T[]): T => items[items.length - 1];
const devices: AcceptanceDevice[] = [];
afterEach(async () => { await Promise.all(devices.splice(0).map(d => d.stop())); vi.useRealTimers(); });
async function makeDevice(net: AcceptanceNetwork, name: string, identity = signer(1), seed = 101) {
  const d = await device(net, name, identity, seed); devices.push(d); return d;
}
const view = (engine: VaultEngine, id: VaultId) => snapshot(engine).vaults.find(v => v.vaultId === id)!;
async function accept(engine: VaultEngine, id: VaultId, cap: 'read' | 'write', path?: string) {
  await engine.refreshInbox();
  const invite = snapshot(engine).invitations.find(i => i.vaultId === id && i.cap === cap && !i.accepted)!;
  expect(invite, `undelivered ${cap} invitation`).toBeDefined();
  return engine.accept(invite.invitationId, { ...(path ? { relativePath: path } : {}), trustConfirmed: true, endpointsConfirmed: true, network });
}
async function grantFrom(net: AcceptanceNetwork, d: AcceptanceDevice): Promise<VaultGrant> {
  const wrap = last(net.wraps(d.pubkey));
  const opened = await openGrantWrap(wrap, d.identity, []);
  expect(opened).not.toBeNull(); return opened!.grant;
}
function decode(event: Event, grant: VaultGrant) {
  return openHeadEvent(event, grant.vaultId, grant.ring, last(grant.ring.entries).epoch);
}
function hashes(d: AcceptanceDevice, root: string) {
  return new Map([...d.fs.files].filter(([p]) => p.startsWith(root + '/') && !p.includes('/.onyx-vault-')).map(([p, b]) => [p.slice(root.length + 1), hashAddress(b)]));
}
async function resolveView(engine: VaultEngine, id: VaultId) {
  const conflicts = view(engine, id).conflicts!;
  expect(conflicts.length).toBeGreaterThan(0);
  await engine.resolveConflicts(id, conflicts.map(c => ({ conflictId: c.conflictId, action: 'keep-view' })));
}
async function pair(populated = false, authRequired = false) {
  const net = new AcceptanceNetwork(authRequired);
  const a = await makeDevice(net, 'A1'), b = await makeDevice(net, 'B', signer(2), 202);
  await a.mkdir('/notebook/notes');
  await a.fs.write('/notebook/notes/note.md', '# Initial\n');
  await a.fs.write('/notebook/notes/delete.md', 'delete me');
  if (populated) {
    await a.mkdir('/notebook/notes/empty/nested');
    await a.mkdir('/notebook/notes/assets');
    await a.fs.writeBinary('/notebook/notes/assets/image.png', new Uint8Array([137, 80, 78, 71, 0, 255, 128, 10]));
    await a.fs.writeBinary('/notebook/notes/assets/paper.pdf', new Uint8Array([...encodeUtf8('%PDF-1.7\n'), 0, 255, 129]));
    // Over the forced 1 MiB cut; the tail is different so dedup cannot mask a missing chunk.
    await a.fs.writeBinary('/notebook/notes/assets/multi.bin', Uint8Array.from({ length: 1048576 + 65537 }, (_, i) => (i * 31 + (i >>> 10)) & 255));
  }
  const ae = await a.start(), be = await b.start();
  const id = await ae.create('notes', {});
  return { net, a, b, ae, be, id };
}
async function writable() {
  const p = await pair();
  await p.ae.share(p.id, [p.b.pubkey], 'write', {}); await accept(p.be, p.id, 'write', 'shared');
  return p;
}

/** Automated fixtures only: this is not a web/Tauri or manual two-device run. */
describe('§13.5 deterministic two-account acceptance (SV-16)', () => {
  it('SV-27: a one-note edit in 500 files sends 2 PUTs, 2 HEADs, no verifying GETs or new REQs, and reaches B live', async () => {
    const net = new AcceptanceNetwork(), a = await makeDevice(net, 'A1'), b = await makeDevice(net, 'B', signer(2), 202);
    await a.mkdir('/notebook/notes');
    for (let i = 0; i < 500; i++) await a.fs.write(`/notebook/notes/${i}.md`, `note ${i}`);
    const ae = await a.start(), be = await b.start(), id = await ae.create('notes', {});
    await ae.share(id, [b.pubkey], 'read', {}); await accept(be, id, 'read', 'shared');
    await ae.refreshInbox(); await be.refreshInbox();
    const as = await a.openStore(), bs = await b.openStore();
    const changedHash = hashAddress(encodeUtf8('one changed note'));
    const baselineReceipt = (engine: VaultEngine, store: typeof as) => new Promise<void>((resolve, reject) => {
      let off = () => {};
      off = engine.subscribe(() => { void store.read('vaults', [id]).then(row => {
        if (row?.value.baseline['0.md']?.byteHash === changedHash && row.value.pendingCandidateId === null) { off(); resolve(); }
      }, reject); });
    });
    const liveReqs = () => net.traffic.filter(t => t.frame === 'REQ' && t.filter?.limit === undefined);
    const liveBefore = liveReqs().length;
    const aReceipt = baselineReceipt(ae, as), bReceipt = baselineReceipt(be, bs);
    // Exercise the same notification echo produced by platform materialisation.
    b.fs.afterWrite = path => { be.notifyFilesChanged([path]); };
    net.tick(); await a.fs.write('/notebook/notes/0.md', 'one changed note');
    const from = net.traffic.length;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    ae.notifyFilesChanged(['/notebook/notes/0.md']);
    await vi.advanceTimersByTimeAsync(750); await Promise.all([aReceipt, bReceipt]);
    let capturing = false, off = () => {};
    const echoReceipt = new Promise<void>(resolve => { off = be.subscribe(state => {
      if (state.activity === 'capturing') capturing = true;
      if (capturing && state.activity === 'idle') { off(); resolve(); }
    }); });
    await vi.advanceTimersByTimeAsync(750); await echoReceipt;
    const traffic = net.traffic.slice(from), owner = traffic.filter(t => t.device === 'A1');
    const count = (frame: string) => owner.filter(t => t.frame === frame).length;
    expect({ PUT: count('PUT'), HEAD: count('HEAD'), GET: count('GET'), REQ: count('REQ') }).toEqual({ PUT: 2, HEAD: 2, GET: 0, REQ: 0 });
    expect(traffic.filter(t => t.device === 'B' && t.frame === 'GET')).toHaveLength(2);
    expect(traffic.filter(t => t.device === 'B' && ['PUT', 'HEAD', 'EVENT', 'REQ'].includes(t.frame))).toEqual([]);
    expect(await b.fs.read('/notebook/shared/0.md')).toBe('one changed note');
    expect(hashes(b, '/notebook/shared')).toEqual(hashes(a, '/notebook/notes'));
    expect(net.heads('B')).toHaveLength(0); expect(liveReqs()).toHaveLength(liveBefore);
    // Manual sync remains a full pass, but it never replaces unchanged live REQs.
    await ae.sync(id); await be.sync(id); expect(liveReqs()).toHaveLength(liveBefore);
    expect(liveReqs().filter(t => t.filter?.['#d']?.some(d => d.startsWith('porthome/v2/'))).every(t => t.filter?.since === undefined)).toBe(true);
    as.stop(); bs.stop();
  }, 60000);

  it('SV-22 steps 1–2: ready, create, invite and full-byte materialisation using only auth-required endpoints', async () => {
    const { net, a, b, ae, be, id } = await pair(true, true);
    for (const engine of [ae, be]) {
      expect(snapshot(engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
      expect(snapshot(engine).endpoints).toHaveLength(2);
      expect(snapshot(engine).endpoints?.every(e => e.status === 'authenticated')).toBe(true);
      expect(snapshot(engine).endpoints).toContainEqual(expect.objectContaining({ kind: 'relay', service: 'private vault service' }));
      expect(snapshot(engine).networkDefaults).toEqual(network);
    }
    expect(a.pubkey).not.toBe(b.pubkey);
    expect((await net.database.databases()).map(d => d.name).sort()).toEqual([a.databaseName, b.databaseName].sort());
    expect([...a.secretValues.values()][0]).not.toBe([...b.secretValues.values()][0]);
    expect(view(ae, id)).toMatchObject({ authority: 'owner', provisional: false });
    expect(net.wraps(a.pubkey)).toHaveLength(1);
    const initialGrant = await grantFrom(net, a);
    expect(decode(net.heads('A1')[0], initialGrant)).toMatchObject({ epoch: 1n, seq: 1n });
    await ae.share(id, [b.pubkey, b.pubkey], 'read', {}); await ae.share(id, [b.pubkey], 'read', {});
    expect(net.wraps(b.pubkey)).toHaveLength(1); expect(b.fs.files.size).toBe(0);
    await accept(be, id, 'read', 'shared');
    expect(view(be, id).authority).toBe('reader');
    expect(hashes(b, '/notebook/shared')).toEqual(hashes(a, '/notebook/notes'));
    expect(await b.fs.exists('/notebook/shared/empty/nested')).toBe(true);
    expect((await b.fs.readBinary('/notebook/shared/assets/multi.bin')).length).toBeGreaterThan(1048576);
    expect(net.heads('B')).toHaveLength(0);
    for (const d of [a, b]) {
      expect(net.traffic.some(t => t.device === d.name && t.frame === 'AUTH' && t.auth?.kind === 22242 && t.auth.pubkey === d.pubkey)).toBe(true);
      expect(net.traffic.some(t => t.device === d.name && t.frame === 'HEAD' && t.auth?.kind === 24242 && t.auth.pubkey === d.pubkey)).toBe(true);
    }
    expect(net.traffic.filter(t => ['GET', 'HEAD', 'PUT'].includes(t.frame)).every(t => t.auth?.kind === 24242)).toBe(true);
    expect(net.traffic.some(t => t.device === 'B' && t.frame === 'GET' && t.auth?.tags.some(tag => tag[0] === 't' && tag[1] === 'get'))).toBe(true);
    const wrapIndex = net.traffic.findIndex(t => t.frame === 'EVENT' && t.event?.id === net.wraps(b.pubkey)[0].id);
    const policyHead = last(net.heads('A1'));
    expect(decode(policyHead, initialGrant).rootManifest).toBe((await grantFrom(net, b)).rootManifest);
    const policyOK = net.traffic.findIndex(t => t.frame === 'OK' && t.event?.id === policyHead.id);
    expect(policyOK).toBeGreaterThanOrEqual(0); expect(policyOK).toBeLessThan(wrapIndex);
    expect(snapshot(be).condition).toBe('ready');
  });
  it('steps 1–7: full-byte read, writer proposal, explicit owner fold, conflicts/resolution, revoke isolation', async () => {
    const { net, a, b, ae, be, id } = await pair(true);
    // 1. Complete subtree and independent account state.
    expect(a.pubkey).not.toBe(b.pubkey);
    expect((await net.database.databases()).map(d => d.name).sort()).toEqual([a.databaseName, b.databaseName].sort());
    expect([...a.secretValues.keys()]).not.toEqual([...b.secretValues.keys()]);
    expect([...a.secretValues.values()][0]).not.toBe([...b.secretValues.values()][0]);
    expect(view(ae, id)).toMatchObject({ authority: 'owner', publisher: { isCurrentDevice: true }, provisional: false });
    expect(net.wraps(a.pubkey)).toHaveLength(1);
    const initialGrant = await grantFrom(net, a);
    const initial = decode(net.heads('A1')[0], initialGrant);
    expect(initial).toMatchObject({ epoch: 1n, seq: 1n });
    expect(net.traffic.filter(t => t.frame === 'PUT').every(t => t.auth?.kind === 24242 && t.auth.pubkey === a.pubkey)).toBe(true);
    // 2. Dedupe recipients and unchanged resend; don't auto-accept on receipt.
    await ae.share(id, [b.pubkey, b.pubkey], 'read', {}); await ae.share(id, [b.pubkey], 'read', {});
    expect(net.wraps(b.pubkey)).toHaveLength(1);
    expect(b.fs.files.size).toBe(0);
    await accept(be, id, 'read', 'shared');
    expect(view(be, id).authority).toBe('reader');
    expect(hashes(b, '/notebook/shared')).toEqual(hashes(a, '/notebook/notes'));
    expect(await b.fs.exists('/notebook/shared/empty/nested')).toBe(true);
    expect((await b.fs.readBinary('/notebook/shared/assets/multi.bin')).length).toBeGreaterThan(1048576);
    expect(net.traffic.some(t => t.device === 'B' && t.frame === 'GET')).toBe(true);
    expect(net.heads('B')).toHaveLength(0);
    // Positive policy OK must precede the grant EVENT.
    const wrapIndex = net.traffic.findIndex(t => t.frame === 'EVENT' && t.event?.id === net.wraps(b.pubkey)[0].id);
    const policyHead = last(net.heads('A1'));
    expect(decode(policyHead, initialGrant).rootManifest).toBe((await grantFrom(net, b)).rootManifest);
    const policyOK = net.traffic.findIndex(t => t.frame === 'OK' && t.event?.id === policyHead.id);
    expect(policyOK).toBeGreaterThanOrEqual(0); expect(policyOK).toBeLessThan(wrapIndex);
    // 3. Upgrade in place, then publish a provisional writer head.
    net.tick(); await ae.share(id, [b.pubkey], 'write', {}); await accept(be, id, 'write');
    expect(view(be, id).mount?.relativePath).toBe('shared');
    expect(net.wraps(b.pubkey)).toHaveLength(2);
    await b.fs.write('/notebook/shared/note.md', 'B proposal'); await be.sync(id);
    expect(view(be, id)).toMatchObject({ authority: 'writer', provisional: true,
      provisionalCount: 1, provisionalPaths: ['shared/note.md'], provisionalOtherPaths: [] });
    expect(net.heads('B')).toHaveLength(1);
    const writerGrant = await grantFrom(net, b), proposal = decode(net.heads('B')[0], writerGrant);
    expect(proposal.parents.some(p => p.writer === a.pubkey)).toBe(true);
    // 4. Non-identical member changes require explicit owner acknowledgement.
    await ae.sync(id); expect(view(ae, id)).toMatchObject({ provisional: true,
      provisionalCount: 1, provisionalPaths: ['notes/note.md'], provisionalOtherPaths: ['notes/note.md'] });
    await resolveView(ae, id); await be.sync(id);
    expect(view(be, id)).toMatchObject({ provisional: false, provisionalCount: 0, provisionalPaths: [],
      provisionalOtherPaths: [], conflictCount: 0, conflicts: [] });
    await be.sync(id);
    expect(view(be, id).conflicts).toEqual([]);
    expect(await a.fs.read('/notebook/notes/note.md')).toBe('B proposal');
    expect(await b.fs.read('/notebook/shared/note.md')).toBe('B proposal');
    const folded = decode(last(net.heads('A1')), initialGrant);
    expect(folded.parents).toContainEqual({ writer: b.pubkey, seq: proposal.seq, rootManifest: proposal.rootManifest });
    // 5. Capture B before A publishes, using an adapter boundary rather than time.
    await b.fs.write('/notebook/shared/note.md', 'B divergent');
    await b.fs.write('/notebook/shared/delete.md', 'B preserved deletion alternate');
    const gate = net.gate('B', 'PUT');
    const pending = be.sync(id); void pending.catch(() => {});
    await gate.entered;
    try {
      await a.fs.write('/notebook/notes/note.md', 'A divergent'); await a.fs.remove('/notebook/notes/delete.md');
      net.tick(); await ae.sync(id);
    } finally { gate.resume(); }
    await pending; await ae.sync(id); await be.sync(id);
    for (const [e, d, root] of [[ae, a, '/notebook/notes'], [be, b, '/notebook/shared']] as const) {
      const conflicts = view(e, id).conflicts!;
      expect(conflicts.some(c => c.path === 'note.md' && c.inView && c.inOther)).toBe(true);
      expect(conflicts.some(c => c.path === 'delete.md' && c.inView !== c.inOther)).toBe(true);
      const inspectable = [...d.fs.files].filter(([p]) => p.startsWith(root + '/') && (p.endsWith('/note.md') || p.includes('/.onyx-vault-conflicts/'))).map(([, bytes]) => new TextDecoder().decode(bytes));
      expect(inspectable).toContain('A divergent'); expect(inspectable).toContain('B divergent');
      expect(inspectable).toContain('B preserved deletion alternate');
    }
    // 6. Explicit merged file and deletion cover the concurrent proposal.
    const resolutions: VaultConflictResolution[] = view(ae, id).conflicts!.map(c => c.path === 'note.md'
      ? { conflictId: c.conflictId, action: 'manual-merge', bytes: encodeUtf8('A + B resolved') }
      : c.path === 'delete.md' ? { conflictId: c.conflictId, action: 'delete' } : { conflictId: c.conflictId, action: 'keep-view' });
    await ae.resolveConflicts(id, resolutions); await be.sync(id); await ae.sync(id);
    expect(await a.fs.read('/notebook/notes/note.md')).toBe('A + B resolved');
    expect(await b.fs.read('/notebook/shared/note.md')).toBe('A + B resolved');
    expect(await a.fs.exists('/notebook/notes/delete.md')).toBe(false); expect(await b.fs.exists('/notebook/shared/delete.md')).toBe(false);
    expect(hashes(b, '/notebook/shared')).toEqual(hashes(a, '/notebook/notes'));
    expect(view(ae, id)).toMatchObject({ provisional: false, conflictCount: 0 });
    // 7. Revocation cannot retract the old local copy, but new content fails closed.
    const oldLocal = hashes(b, '/notebook/shared'), wrapsBefore = net.wraps(b.pubkey).length;
    net.tick(); await ae.revoke(id, b.pubkey);
    await a.fs.write('/notebook/notes/private.md', 'epoch 2 secret'); await ae.sync(id);
    await be.sync(id);
    expect(view(be, id).lastError).not.toBeNull();
    expect(hashes(b, '/notebook/shared')).toEqual(oldLocal);
    expect(await b.fs.exists('/notebook/shared/private.md')).toBe(false);
    expect(net.wraps(b.pubkey)).toHaveLength(wrapsBefore);
    expect((await grantFrom(net, a)).ring.entries.map(e => e.epoch)).toEqual([1n, 2n]);
  }, 30000);

  it('step 7: quarantines an unreadable new head as CRYPTO, preserves the verified view, and selects EPOCH for explicit new-epoch objects', async () => {
    const { net, a, b, ae, be, id } = await pair();
    await ae.share(id, [b.pubkey], 'read', {}); await accept(be, id, 'read', 'shared');
    const old = hashes(b, '/notebook/shared'), oldGrant = await grantFrom(net, b), wrapsBefore = net.wraps(b.pubkey).length;
    const priorStore = await b.openStore(), prior = (await priorStore.read('vaults', [id]))!.value; priorStore.stop();
    net.tick(); await ae.revoke(id, b.pubkey);
    await a.fs.write('/notebook/notes/private.md', 'new epoch'); await ae.sync(id); await be.sync(id);
    // Heads have no public epoch: authentication failure alone cannot establish revocation.
    const event = last(net.heads('A1'));
    expect(event.tags).toEqual([['d', `porthome/v2/${id}`]]);
    expect(view(be, id).lastError).toMatchObject({ code: 'CRYPTO', message: 'Vault data could not be authenticated' });
    expect(hashes(b, '/notebook/shared')).toEqual(old);
    expect(await b.fs.exists('/notebook/shared/private.md')).toBe(false);
    expect(net.wraps(b.pubkey)).toHaveLength(wrapsBefore);
    const store = await b.openStore(), kept = (await store.read('vaults', [id]))!.value;
    expect(kept.quarantinedHeads?.[event.id]).toMatchObject({ code: 'CRYPTO', signedEvent: event });
    expect(await store.read('records', [id, event.id])).toBeNull();
    expect(kept.ownerCheckpointId).toBe(prior.ownerCheckpointId);
    expect(kept.materializedViewId).toBe(prior.materializedViewId);
    expect(kept.baseline).toEqual(prior.baseline);
    expect(kept.epochLedgerEvent?.id).toBe(prior.epochLedgerEvent?.id); store.stop();
    const currentGrant = await grantFrom(net, a), head = decode(event, currentGrant);
    const root = net.objects.get(head.rootManifest)!;
    const node = openDirectoryNode(currentGrant.ring, head.epoch, root);
    const file = node.entries.find(e => e.namePlain === 'private.md');
    if (file?.kind !== 'file') throw new Error('Missing new-epoch fixture chunk');
    const chunk = file.chunks[0], sealed = net.objects.get(chunk.address)!;
    expect(head.epoch).toBe(2n); expect(chunk.chunkKeyId).toBe(2n);
    expect(openChunk(currentGrant.ring, chunk.chunkKeyId, sealed, chunk.sizePlain)).toEqual(encodeUtf8('new epoch'));
    expect(() => openDirectoryNode(oldGrant.ring, head.epoch, root)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    expect(() => openChunk(oldGrant.ring, chunk.chunkKeyId, sealed, chunk.sizePlain)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
  });

  it.each([true, false])('step 8: fresh third-member regrant after two rotations, with ledger=%s', async historyAvailable => {
    const { net, a, b, ae, be, id } = await pair(true);
    const identity = signer(3), cPubkey = hex32<typeof b.pubkey>(await identity.getPublicKey());
    const removedFirst = hex32<typeof b.pubkey>(await signer(4).getPublicKey());
    await ae.share(id, [b.pubkey], 'write', {}); await accept(be, id, 'write', 'shared');
    await ae.share(id, [cPubkey, removedFirst], 'read', {});
    net.tick(); await ae.revoke(id, removedFirst); await accept(be, id, 'write');
    // Publish under an independently rotated descendant override in epoch 2.
    // A resolves the member proposal directly; no owner sync/eager re-seal runs.
    const epoch2Bytes = new Uint8Array([137, 80, 78, 71, 2, 0, 255, 42]);
    let off = () => {};
    const proposalObserved = new Promise<void>(resolve => {
      off = ae.subscribe(state => {
        if (state.vaults.find(v => v.vaultId === id)?.conflicts?.some(c => c.path === 'assets/image.png')) resolve();
      });
    });
    try {
      await b.fs.writeBinary('/notebook/shared/assets/image.png', epoch2Bytes); await be.sync(id);
      await proposalObserved;
    } finally { off(); }
    await resolveView(ae, id);
    const epoch2Grant = await grantFrom(net, a), epoch2Head = decode(last(net.heads('A1')), epoch2Grant);
    const epoch2Root = openDirectoryNode(epoch2Grant.ring, 2n, net.objects.get(epoch2Head.rootManifest)!);
    const epoch2Assets = epoch2Root.entries.find(e => e.namePlain === 'assets');
    expect(epoch2Assets).toMatchObject({ kind: 'directory', childEpoch: 2n, keyOverride: expect.any(Uint8Array) });
    const expected = hashes(a, '/notebook/notes');
    net.tick(); await ae.revoke(id, b.pubkey);
    const latestWrap = last(net.wraps(cPubkey));
    // This relay supplies only the current C regrant, not its older invitations.
    for (const event of [...net.events.values()]) if (event.kind === 1059 && recipient(event) === cPubkey && event.id !== latestWrap.id) net.events.delete(event.id);
    expect((await net.database.databases()).map(d => d.name)).not.toContain('sv16:C-fresh');
    const c = await makeDevice(net, 'C-fresh', identity, 404), ce = await c.start();
    const empty = await c.openStore();
    for (const table of ['vaults', 'records', 'operations'] as const) expect(await empty.list(table)).toEqual([]);
    empty.stop(); expect(c.fs.files.size).toBe(0);
    const opened = await openGrantWrap(latestWrap, c.identity, []);
    expect(opened).not.toBeNull(); const grant = opened!.grant;
    expect(grant.ring.entries.map(e => e.epoch)).toEqual([1n, 2n, 3n]);
    const heads = [...net.events.values()].filter(event => event.kind === 30078 && event.tags.some(t => t[1] === `porthome/v2/${id}`));
    expect(heads.filter(e => e.pubkey === a.pubkey)).toHaveLength(1);
    const current = await fetchRecord(heads.find(e => e.pubkey === a.pubkey)!, grant, grant.ring, 3n, { read: async address => net.objects.get(address)! });
    const root = current.tree.nodes[0].node, assets = root.entries.find(e => e.namePlain === 'assets');
    if (assets?.kind !== 'directory') throw new Error('Missing rotated assets directory');
    const dir = current.tree.nodes.find(n => n.node.nodeId === assets.childNodeId)!;
    expect(assets).toMatchObject({ childEpoch: 3n, keyOverride: expect.any(Uint8Array) });
    expect(dir.ring.entries.map(e => e.epoch)).toEqual([3n]);
    for (const [name, epoch] of [['image.png', 2n], ['multi.bin', 1n]] as const) {
      const file = dir.node.entries.find(e => e.namePlain === name);
      if (file?.kind !== 'file') throw new Error(`Missing historical ${name}`);
      expect(file.chunks.every(c => c.chunkKeyId === epoch)).toBe(true);
    }
    const ledgerEvent = [...net.events.values()].find(e => e.tags.some(t => t[1] === historyDTag(id)))!;
    const ledger = openEpochLedgerEvent(ledgerEvent, id, a.pubkey, grant.ring);
    expect(ledger.epochs.map(e => e.epoch)).toEqual([1n, 2n, 3n]);
    expect(ledger.epochs[1].rootManifest).toBe(epoch2Head.rootManifest);
    expect(current.record.head.parents.map(p => p.rootManifest)).not.toContain(ledger.epochs[0].rootManifest);
    if (!historyAvailable) net.events.delete(ledgerEvent.id);
    const headsBefore = net.heads().length, putsBefore = net.traffic.filter(t => t.frame === 'PUT').length;
    await ce.refreshInbox();
    expect(net.traffic.some(t => t.device === c.name && t.frame === 'GET')).toBe(false);
    const invite = snapshot(ce).invitations.find(i => i.invitationId === opened!.rumorId)!; expect(invite).toBeDefined();
    const accepted = ce.accept(invite.invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    if (historyAvailable) {
      await accepted;
      expect(hashes(c, '/notebook/shared')).toEqual(expected);
      expect(await c.fs.readBinary('/notebook/shared/assets/image.png')).toEqual(epoch2Bytes);
      expect(await c.fs.exists('/notebook/shared/empty/nested')).toBe(true);
      expect(view(ce, id)).toMatchObject({ authority: 'reader', lastError: null });
    } else {
      await expect(accepted).rejects.toMatchObject({ code: 'EPOCH', message: expect.stringContaining('History unavailable from this owner') });
      expect(c.fs.files.size).toBe(0);
    }
    expect(net.heads()).toHaveLength(headsBefore);
    expect(net.traffic.filter(t => t.frame === 'PUT')).toHaveLength(putsBefore);
  }, 30000);

  it.each(['PUT', 'HEAD'] as const)('step 9: abort %s mid-flight, restart the same store, preserve candidate bytes and signed-event allocation', async point => {
    const { net, a, b, ae, be, id } = await writable();
    const text = `durable candidate interrupted at ${point}`;
    await a.fs.write('/notebook/notes/note.md', text);
    const before = net.heads('A1').length, gate = net.gate('A1', point);
    const pending = ae.sync(id).catch(error => error); await gate.entered;
    await ae.stop(); expect(await pending).toMatchObject({ code: point === 'HEAD' ? 'NETWORK' : 'CANCELLED' });
    const interrupted = gate.event;
    const restarted = await a.start(); await restarted.sync(id); await be.sync(id);
    expect(await a.fs.read('/notebook/notes/note.md')).toBe(text);
    expect(await b.fs.read('/notebook/shared/note.md')).toBe(text);
    expect(view(restarted, id).lastError).toBeNull();
    const heads = net.heads('A1').slice(before);
    expect(new Set(heads.map(e => e.id)).size).toBe(1);
    if (interrupted) { expect(heads).toHaveLength(2); expect(heads[0]).toEqual(heads[1]); }
    if (gate.address) expect(net.objects.has(gate.address)).toBe(true);
    const grant = await grantFrom(net, a), decoded = heads.map(e => decode(e, grant));
    expect(new Set(decoded.map(h => `${h.seq}:${h.rootManifest}`)).size).toBe(1);
    expect(decoded[0].seq).toBe(BigInt(before + 1));
  });

  it('step 9: abort a post-revoke regrant before OK, restart, retry the identical wrap without rotating twice', async () => {
    const { net, a, b, ae, be, id } = await writable();
    const removed = await signer(3).getPublicKey() as typeof b.pubkey;
    await ae.share(id, [removed], 'read', {});
    const beforeB = net.wraps(b.pubkey).length, gate = net.gate('A1', 'WRAP');
    const revoking = ae.revoke(id, removed).catch(error => error); await gate.entered;
    expect(recipient(gate.event!)).toBe(b.pubkey);
    await ae.stop(); await revoking;
    const restarted = await a.start(); await restarted.sync(id);
    const replay = net.wraps(b.pubkey).slice(beforeB);
    expect(replay).toHaveLength(2); expect(replay[0]).toEqual(replay[1]);
    expect((await grantFrom(net, a)).ring.entries.map(e => e.epoch)).toEqual([1n, 2n]);
    const headCount = net.heads('A1').length;
    await restarted.revoke(id, removed); expect(net.heads('A1')).toHaveLength(headCount);
    expect(view(restarted, id).pendingDeliveryCount).toBe(0);
    await accept(be, id, 'write'); expect(view(be, id).authority).toBe('writer');
  });

  it('step 10: legacy disk orchestration still writes outside the mount and excludes mount/ancestor mutations', async () => {
    const { net, a, ae, id } = await pair();
    const registry = a.registry(ae), sharedBefore = hashes(a, '/notebook/notes');
    const incoming = new Map([['/notebook/legacy.md', 'legacy 30801 download'], ['/notebook/notes-sibling.md', 'not a path-prefix mount'], ['/notebook/notes/note.md', 'must not overwrite']]);
    for (const path of filterLegacyPaths([...incoming.keys()], registry)) await a.fs.write(path, incoming.get(path)!);
    expect(await a.fs.read('/notebook/legacy.md')).toBe('legacy 30801 download');
    expect(await a.fs.read('/notebook/notes-sibling.md')).toBe('not a path-prefix mount');
    expect(hashes(a, '/notebook/notes')).toEqual(sharedBefore);
    expect(isManagedPath('/notebook/notes/note.md', registry)).toBe(true);
    expect(intersectsManagedMount('/notebook', registry)).toBe(true);
    const before = net.heads('A1').length; await ae.sync(id); expect(net.heads('A1')).toHaveLength(before);
    expect(await a.fs.read('/notebook/legacy.md')).toBe('legacy 30801 download');
    expect(await a.fs.read('/notebook/notes-sibling.md')).toBe('not a path-prefix mount');
    // This is the shared mount exclusion boundary, not a claim of live 30800/30802/preferences acceptance.
  });

  it('step 11: populated original-path attach preserves files; handover fences device 1 and device 2 publishes unique owner sequences', async () => {
    const { net, a, ae, id } = await pair();
    const a2 = await makeDevice(net, 'A2', a.identity, 303);
    await a2.mkdir('/notebook/notes'); await a2.fs.write('/notebook/notes/note.md', 'legacy device 2 copy');
    await a2.fs.write('/notebook/notes/delete.md', 'delete me'); await a2.fs.write('/notebook/notes/local-only.md', 'never erase');
    const before = hashes(a2, '/notebook/notes'), e2 = await a2.start();
    await e2.refreshInbox();
    expect(snapshot(e2).invitations).toEqual([]);
    expect(view(e2, id).mount).toBeNull();
    await e2.attach(id, 'notes');
    expect(a2.pubkey).toBe(a.pubkey);
    expect(a2.databaseName).not.toBe(a.databaseName);
    expect([...a2.secretValues.values()][0]).not.toBe([...a.secretValues.values()][0]);
    expect(hashes(a2, '/notebook/notes')).toEqual(before);
    expect(view(e2, id)).toMatchObject({ publisher: { isCurrentDevice: false }, mount: { relativePath: 'notes' } });
    expect(view(e2, id).conflicts!.some(c => c.path === 'note.md')).toBe(true);
    await e2.sync(id); expect(net.heads('A2')).toHaveLength(0);
    expect(isManagedPath('/notebook/notes/note.md', a2.registry(e2))).toBe(true);
    expect(filterLegacyPaths(['/notebook/notes/note.md', '/notebook/outside.md'], a2.registry(e2))).toEqual(['/notebook/outside.md']);
    // Preserve a candidate that was already uploading when the designation changed.
    await a.fs.write('/notebook/notes/note.md', 'device 1 pending local');
    const gate = net.gate('A1', 'PUT'), pending = ae.sync(id).catch(error => error); await gate.entered;
    const beforeA1 = net.heads('A1').length;
    try { net.tick(); await e2.takeOverPublishing(id); } finally { gate.resume(); }
    expect(await pending).toMatchObject({ code: 'POLICY' });
    await ae.sync(id);
    expect(view(ae, id).publisher?.isCurrentDevice).toBe(false);
    expect(await a.fs.read('/notebook/notes/note.md')).toBe('device 1 pending local');
    expect(net.heads('A1')).toHaveLength(beforeA1);
    await resolveView(e2, id);
    const beforeA2 = net.heads('A2').length;
    await a2.fs.write('/notebook/notes/note.md', 'device 2 published'); await e2.sync(id);
    expect(net.heads('A2')).toHaveLength(beforeA2 + 1);
    expect(view(e2, id).publisher?.isCurrentDevice).toBe(true);
    const grant = await grantFrom(net, a), heads = net.heads().map(e => decode(e, grant));
    const bySequence = new Map<string, Set<string>>();
    for (const h of heads) { const key = String(h.seq); if (!bySequence.has(key)) bySequence.set(key, new Set()); bySequence.get(key)!.add(encodeHead(h)); }
    expect([...bySequence.values()].every(bodies => bodies.size === 1)).toBe(true);
    expect(last(heads).seq).toBeGreaterThan(decode(last(net.heads('A1')), grant).seq);
    await ae.sync(id); expect(await a.fs.read('/notebook/notes/note.md')).toBe('device 1 pending local');
    expect(net.heads('A1')).toHaveLength(beforeA1);
  });

  it('Blossom fake rejects missing/wrong-hash/expired 24242 auth and serves content-addressed GET/HEAD across devices', async () => {
    const net = new AcceptanceNetwork(), identity = signer(1), bytes = encodeUtf8('sealed-object fixture'), address = hashAddress(bytes);
    const fetch = net.blossomFetch('probe');
    const request = async (tags?: string[][]) => {
      const headers: Record<string, string> = { 'x-sha-256': address };
      if (tags) headers.authorization = `Nostr ${btoa(JSON.stringify(await identity.signEvent({ kind: 24242, created_at: net.now, content: '', tags })))}`;
      return fetch(`${network.writeBlossom[0]}upload`, { method: 'PUT', body: new Uint8Array(bytes), headers });
    };
    expect((await request()).status).toBe(401);
    expect((await request([['t', 'upload'], ['x', '0'.repeat(64)], ['expiration', String(net.now + 60)]])).status).toBe(401);
    expect((await request([['t', 'upload'], ['x', address], ['expiration', String(net.now - 1)]])).status).toBe(401);
    expect(net.objects.size).toBe(0);
    const uploader = net.blossomFactory('A1')(network.writeBlossom[0]), reader = net.blossomFactory('B')(network.readBlossom[0]);
    try {
      expect(await reader.head(address)).toEqual({ exists: false });
      await uploader.put(bytes, address, identity);
      expect(await reader.head(address)).toEqual({ exists: true, size: bytes.length });
      expect(await reader.get(address)).toEqual(bytes);
      expect(net.traffic.find(t => t.frame === 'PUT')?.auth).toMatchObject({ kind: 24242, pubkey: await identity.getPublicKey() });
    } finally { uploader.stop(); reader.stop(); }
  });

  it('relay fake retains only author+d winners, filters #p, pages inclusive until ties, and emits OK/EOSE', async () => {
    const net = new AcceptanceNetwork(), identity = signer(1), other = await signer(2).getPublicKey();
    const relay = net.relayFactory('probe')(network.writeRelays);
    const publish = async (kind: number, created_at: number, tags: string[][], content = '') => {
      const event = await identity.signEvent({ kind, created_at, tags, content }); await relay.publish(event); return event;
    };
    const old = await publish(30078, 10, [['d', 'porthome/v2/test']]);
    const latest = await publish(30078, 12, [['d', 'porthome/v2/test']]);
    await publish(30078, 11, [['d', 'porthome/v2/test']]);
    const tie = await publish(30078, 12, [['d', 'porthome/v2/test']], 'tie');
    const preferences = await publish(30078, 10, [['d', 'onyx/preferences']]);
    expect(net.events.has(old.id)).toBe(false);
    expect(net.page('probe', { kinds: [30078], '#d': ['porthome/v2/test'] }).map(e => e.id)).toEqual([[latest, tie].sort((a, b) => a.id.localeCompare(b.id))[0].id]);
    expect(net.events.has(preferences.id)).toBe(true);
    const wanted: Event[] = [];
    for (let i = 0; i < 5; i++) wanted.push(await publish(1059, i < 4 ? 20 : 19, [['p', other]], String(i)));
    await publish(1059, 20, [['p', await identity.getPublicKey()]], 'not B');
    const observed: Event[] = [], frames: string[] = [];
    await relay.backfill([{ kinds: [1059], '#p': [other] }], { onevent: e => { observed.push(e); frames.push('EVENT'); }, oneose: () => { frames.push('EOSE'); } });
    expect(observed.map(e => e.id).sort()).toEqual(wanted.map(e => e.id).sort());
    expect(last(frames)).toBe('EOSE'); expect(new Set(observed.map(e => e.id)).size).toBe(5);
    expect(net.traffic.some(t => t.frame === 'REQ' && t.filter?.until === 20 && t.filter.limit! > 2)).toBe(true);
    expect(net.page('probe', { kinds: [1059], '#p': [other], until: 19 }).map(e => e.id)).toEqual([wanted[4].id]);
    expect(net.traffic.filter(t => t.frame === 'OK')).toHaveLength(11);
    relay.stop();
  });
});
