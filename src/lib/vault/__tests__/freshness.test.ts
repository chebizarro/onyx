import { afterEach, describe, expect, it } from 'vitest';
import { finalizeEvent, type Event } from 'nostr-tools';
import { wrap } from 'idb';
import { bytes32, encodeUtf8, sealChunk } from '../crypto';
import { sealDirectoryNode } from '../dir-node';
import { HeadlessVaultEngine, hydrateRing } from '../engine';
import type { VaultEngineDeps } from '../engine-api';
import { historyDTag } from '../epoch-ledger';
import { buildHeadEvent } from '../head';
import { EMPTY_FRESHNESS, acceptCheckpoint, bindCheckpoint, grantedFloor, grantedHeadSeq, headPosition, noteHead, publishedCheckpoint, withGrant } from '../freshness';
import { openHeadEvent } from '../head';
import { appendRing } from '../ring';
import { VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION } from '../store';
import type { DirectoryNode, Pubkey, StoredFreshness, VaultHead, VaultId, VaultPolicy } from '../types';
import { fixture, network, signer, snapshot } from './engine-fixtures';
import { address, cBytes, errorCode, fileEntry, makeRecord, tuple, world } from './policy-fixtures';

const engines: HeadlessVaultEngine[] = [];
afterEach(async () => { await Promise.all(engines.splice(0).map(e => e.stop())); });
type Fixture = Awaited<ReturnType<typeof fixture>>;
const mountOptions = { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network } as const;
const isHead = (event: Event) => event.kind === 30078 && event.tags.some(t => t[0] === 'd' && t[1].startsWith('porthome/v2/'));
async function start(f: Fixture, budgets?: VaultEngineDeps['budgets']) {
  const engine = new HeadlessVaultEngine({ ...f.deps, ...(budgets ? { budgets } : {}) }); engines.push(engine); await engine.start(f.session); return engine;
}
async function owned(memberBudgets?: VaultEngineDeps['budgets']) {
  const f = await fixture(); await f.mkdir('/notebook/notes'); await f.fs.write('/notebook/notes/a.md', 'initial');
  const e = await start(f); const id = await e.create('notes', {});
  const member = await fixture(f.net, signer(2)); const m = await start(member, memberBudgets);
  return { f, e, id, member, m };
}
const secretOf = (n: number): Uint8Array => { const secret = new Uint8Array(32); secret[31] = n; return secret; };
/** A head over a one-file root at the current policy, signed by `author`; only the relay and Blossom fake see it.
 * With `covering`, its parents name the owner checkpoint (a member proposal); otherwise it has no parents. */
async function craftHead(f: Fixture, id: VaultId, author: { pubkey: Pubkey; secret: Uint8Array }, seq: bigint, text: string, nonce: number, covering: boolean): Promise<{ event: Event; root: string }> {
  const vault = await vaultRow(f, id);
  const store = await f.openStore(); const checkpoint = (await store.read('records', [id, vault.ownerCheckpointId!]))!.value.record; store.stop();
  const ring = hydrateRing(vault.nodeRings[vault.rootNodeId]), latest = ring.entries[ring.entries.length - 1];
  const policy: VaultPolicy = { ...checkpoint.root.vault!, grantsRev: BigInt(checkpoint.root.vault!.grantsRev) };
  const chunk = sealChunk(latest.nodeKey, encodeUtf8(text)); f.net.objects.set(chunk.address, chunk.sealed);
  const entry = fileEntry(latest.nodeKey, 'a.md', [{ address: chunk.address, sizeSealed: BigInt(chunk.sealed.length), chunkKeyId: latest.epoch, sizePlain: BigInt(text.length) }]);
  const node: DirectoryNode = { version: 2, nodeId: vault.rootNodeId, epoch: latest.epoch, entries: [entry], vault: policy };
  const sealed = sealDirectoryNode(node, latest.nodeKey); f.net.objects.set(sealed.address, sealed.sealed);
  const head: VaultHead = { vaultId: id, epoch: latest.epoch, rootManifest: sealed.address, seq, grantsRev: policy.grantsRev, writtenAt: 1800000000n + BigInt(nonce),
    parents: covering ? [{ writer: checkpoint.writer, seq: BigInt(checkpoint.head.seq), rootManifest: checkpoint.head.rootManifest }] : [] };
  return { event: finalizeEvent(buildHeadEvent(head, latest.nodeKey, author.pubkey, cBytes(nonce)), author.secret), root: sealed.address };
}

async function vaultRow(f: Fixture, id: VaultId) { const store = await f.openStore(); const vault = (await store.read('vaults', [id]))!.value; store.stop(); return vault; }
/** Owner heads the relay currently holds, decoded under the owner's own ring. */
async function ownerHeads(f: Fixture, id: VaultId): Promise<{ event: Event; seq: bigint }[]> {
  const vault = await vaultRow(f, id), ring = hydrateRing(vault.nodeRings[vault.rootNodeId]), epoch = ring.entries[ring.entries.length - 1].epoch;
  return [...f.net.events.values()].filter(ev => ev.pubkey === vault.owner && isHead(ev))
    .map(ev => ({ event: ev, seq: openHeadEvent(ev, id, ring, epoch).seq })).sort((a, b) => a.seq < b.seq ? -1 : 1);
}
async function clearRecords(factory: IDBFactory): Promise<void> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = factory.open(VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
  const tx = wrap(db).transaction('records', 'readwrite'); await tx.store.clear(); await tx.done; db.close();
}

describe('SV-35 freshness floors (pure)', () => {
  it('implements the §6.7 granted-root binding rule: epoch/revision floors, identity or reference verifies, else unverified', () => {
    const w = world(), granted = grantedFloor({ rootManifest: address(0x66), ring: w.ring }, 8n);
    const same = makeRecord(w, { seq: 5n, text: 'later' });
    expect(bindCheckpoint(same, granted)).toBe('unverified');
    expect(bindCheckpoint(makeRecord(w, { seq: 5n, revision: 7n }), granted)).toBe('stale');
    expect(bindCheckpoint(makeRecord(w, { seq: 5n, revision: 9n }), granted)).toBe('verified');
    const rooted = makeRecord(w, { seq: 5n });
    expect(bindCheckpoint(rooted, grantedFloor({ rootManifest: rooted.head.rootManifest, ring: w.ring }, 8n))).toBe('verified');
    expect(bindCheckpoint(makeRecord(w, { seq: 6n, parents: [{ writer: w.pub[0], seq: 5n, rootManifest: address(0x66) }] }), granted)).toBe('verified');
    // A member parent naming the root is not owner evidence.
    expect(bindCheckpoint(makeRecord(w, { seq: 6n, parents: [{ writer: w.pub[1], seq: 5n, rootManifest: address(0x66) }] }), granted)).toBe('unverified');
    expect(bindCheckpoint(same, granted, 4n)).toBe('verified'); expect(bindCheckpoint(same, granted, 6n)).toBe('unverified');
    const ring2 = appendRing(w.ring, bytes32(cBytes(0x99)));
    expect(bindCheckpoint(makeRecord(w, { seq: 7n, ring: ring2 }), granted)).toBe('verified');
    expect(bindCheckpoint(same, grantedFloor({ rootManifest: address(0x66), ring: ring2 }, 8n))).toBe('stale');
    // Unknown revision (migration) cannot reject by revision.
    expect(bindCheckpoint(makeRecord(w, { seq: 5n, revision: 7n }), { ...granted, grantsRev: null })).toBe('unverified');
    expect(grantedHeadSeq(granted, w.pub[0], [same, { writer: w.pub[0], head: { ...same.head, seq: 3n, rootManifest: address(0x66) } }])).toBe(3n);
    expect(grantedHeadSeq(granted, w.pub[0], [{ writer: w.pub[1], head: { ...same.head, rootManifest: address(0x66) } }])).toBeUndefined();
  });
  it('treats a verified checkpoint as a hard floor and same-sequence divergence as equivocation', () => {
    const w = world(), c3 = makeRecord(w, { seq: 3n }), c3b = makeRecord(w, { seq: 3n, text: 'fork' }), c2 = makeRecord(w, { seq: 2n }), c4 = makeRecord(w, { seq: 4n });
    const f = acceptCheckpoint(EMPTY_FRESHNESS, c3);
    expect(f).toMatchObject({ verified: true, checkpoint: { seq: '3', headHash: c3.canonicalHeadHash }, authors: { [w.pub[0]]: { seq: '3', hashes: [c3.canonicalHeadHash] } } });
    expect(errorCode(() => acceptCheckpoint(f, c2))).toBe('INCOMPLETE');
    expect(() => acceptCheckpoint(f, c2)).toThrowError(/newer owner checkpoint/);
    expect(errorCode(() => acceptCheckpoint(f, c3b))).toBe('CONFLICT');
    expect(acceptCheckpoint(f, c3)).toEqual(f);
    expect(acceptCheckpoint(f, c4).checkpoint?.seq).toBe('4');
    const armed = withGrant(f, grantedFloor({ rootManifest: address(0x66), ring: w.ring }, 8n));
    expect(armed.verified).toBe(false);
    expect(acceptCheckpoint(armed, c4).verified).toBe(false);
    expect(acceptCheckpoint(armed, c4, 4n).verified).toBe(true);
    expect(errorCode(() => acceptCheckpoint(armed, makeRecord(w, { seq: 4n, revision: 7n })))).toBe('INCOMPLETE');
    expect(withGrant(armed, armed.granted!)).toBe(armed);
  });
  it('tracks per-author high-water with body evidence and never lowers a published floor', () => {
    const w = world(), m1 = makeRecord(w, { writer: 1, seq: 1n }), m2 = makeRecord(w, { writer: 1, seq: 2n }), m2b = makeRecord(w, { writer: 1, seq: 2n, text: 'b' });
    let f: StoredFreshness = noteHead(EMPTY_FRESHNESS, m2);
    expect(headPosition(f, w.pub[1], 1n)).toBe('behind'); expect(headPosition(f, w.pub[1], 2n)).toBe('level'); expect(headPosition(f, w.pub[1], 3n)).toBe('ahead');
    expect(headPosition(f, w.pub[0], 1n)).toBe('ahead');
    expect(noteHead(f, m1)).toBe(f); expect(noteHead(f, m2)).toBe(f);
    f = noteHead(f, m2b); expect(f.authors[w.pub[1]].hashes).toEqual([m2.canonicalHeadHash, m2b.canonicalHeadHash]);
    const own5 = makeRecord(w, { seq: 5n }), own4 = makeRecord(w, { seq: 4n });
    const published = publishedCheckpoint(acceptCheckpoint(EMPTY_FRESHNESS, own5), own4);
    expect(published.checkpoint?.seq).toBe('5'); expect(published.verified).toBe(true);
    expect(publishedCheckpoint(withGrant(EMPTY_FRESHNESS, grantedFloor({ rootManifest: address(0x66), ring: w.ring }, 8n)), own5)).toMatchObject({ verified: true, checkpoint: { seq: '5' } });
    expect(tuple(own5).seq).toBe(5n);
  });
});

describe('SV-35 fresh and reset clients', () => {
  it('rejects a stale owner checkpoint served to a fresh client when the grant proves a later revision', async () => {
    const { f, e, id, member, m } = await owned();
    await e.share(id, [member.pubkey], 'write', {});
    const heads = await ownerHeads(f, id), share = heads[heads.length - 1];
    expect(share.seq).toBeGreaterThan(heads[0].seq);
    f.net.events.delete(share.event.id);
    await m.refreshInbox(); const invite = snapshot(m).invitations[0];
    await expect(m.accept(invite.invitationId, mountOptions)).rejects.toMatchObject({ code: 'INCOMPLETE', message: expect.stringContaining('newer owner checkpoint') });
    expect(snapshot(m).vaults.find(v => v.vaultId === id)?.mount ?? null).toBeNull();
    expect(await member.fs.exists('/notebook/shared/a.md')).toBe(false);
    expect(snapshot(m).invitations[0].accepted).toBe(false);
    f.net.events.set(share.event.id, share.event);
    await m.accept(invite.invitationId, mountOptions);
    expect(snapshot(m).vaults.find(v => v.vaultId === id)).toMatchObject({ freshness: 'verified', authority: 'writer' });
    expect(await member.fs.read('/notebook/shared/a.md')).toBe('initial');
    expect((await vaultRow(member, id)).freshness).toMatchObject({ verified: true, granted: { rootManifest: expect.any(String), epoch: '1', grantsRev: expect.any(String) }, checkpoint: { seq: String(share.seq) } });
  });
  it('admits a same-epoch, same-revision checkpoint two owner steps past the granted root as freshness-unverified until the chain is held', async () => {
    const { f, e, id, member, m } = await owned();
    await e.share(id, [member.pubkey], 'write', {});
    const grantedSeq = (await ownerHeads(f, id)).slice(-1)[0].seq;
    await f.fs.write('/notebook/notes/a.md', 'v3'); await e.sync(id);
    await f.fs.write('/notebook/notes/a.md', 'v4'); await e.sync(id);
    const heads = await ownerHeads(f, id), latest = heads[heads.length - 1];
    expect(latest.seq).toBe(grantedSeq + 2n);
    const withheld = heads.filter(h => h.seq >= grantedSeq && h.seq < latest.seq);
    expect(withheld).toHaveLength(2);
    for (const h of withheld) f.net.events.delete(h.event.id);
    await m.refreshInbox(); await m.accept(snapshot(m).invitations[0].invitationId, mountOptions);
    expect(snapshot(m).vaults.find(v => v.vaultId === id)).toMatchObject({ freshness: 'unverified', authority: 'writer' });
    expect(await member.fs.read('/notebook/shared/a.md')).toBe('v4');
    expect((await vaultRow(member, id)).freshness).toMatchObject({ verified: false, checkpoint: { seq: String(latest.seq) } });
    // Holding the granted root as a verified owner head (seq <= checkpoint) completes the binding.
    for (const h of withheld) f.net.events.set(h.event.id, h.event);
    await m.sync(id);
    expect(snapshot(m).vaults.find(v => v.vaultId === id)?.freshness).toBe('verified');
    await m.sync(id);
    expect((await vaultRow(member, id)).freshness).toMatchObject({ verified: true, checkpoint: { seq: String(latest.seq) } });
  });
  it('refuses to roll a reset client back below its persisted checkpoint floor when record blobs are gone', async () => {
    const { f, e, id, member, m } = await owned();
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, mountOptions);
    await f.fs.write('/notebook/notes/a.md', 'v3'); await e.sync(id); await m.sync(id);
    expect(await member.fs.read('/notebook/shared/a.md')).toBe('v3');
    const heads = await ownerHeads(f, id), latest = heads[heads.length - 1];
    expect((await vaultRow(member, id)).freshness).toMatchObject({ verified: true, checkpoint: { seq: String(latest.seq) } });
    await m.stop(); f.net.events.delete(latest.event.id); await clearRecords(member.factory);
    const restarted = await start(member);
    await expect(restarted.sync(id)).rejects.toMatchObject({ code: 'INCOMPLETE', retryable: true, message: expect.stringContaining('newer owner checkpoint') });
    const kept = await vaultRow(member, id);
    expect(kept.freshness?.checkpoint?.seq).toBe(String(latest.seq));
    expect(await member.fs.read('/notebook/shared/a.md')).toBe('v3');
    expect(snapshot(restarted).vaults.find(v => v.vaultId === id)?.lastError).toMatchObject({ code: 'INCOMPLETE' });
    f.net.events.set(latest.event.id, latest.event);
    await restarted.sync(id);
    expect(snapshot(restarted).vaults.find(v => v.vaultId === id)?.freshness).toBe('verified');
    expect((await vaultRow(member, id)).ownerCheckpointId).toBe(latest.event.id);
  });
});

describe('SV-35 member replay gate', () => {
  it('skips a member head below its durable high-water without fetching or quarantining it', async () => {
    const { f, e, id, member, m } = await owned();
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, mountOptions);
    const author = { pubkey: member.pubkey, secret: secretOf(2) };
    const current = await craftHead(f, id, author, 2n, 'current', 0x20, true);
    f.net.events.set(current.event.id, current.event); await e.sync(id);
    expect((await vaultRow(f, id)).freshness?.authors[member.pubkey]).toEqual({ seq: '2', hashes: [expect.any(String)] });
    const stale = await craftHead(f, id, author, 1n, 'stale', 0x21, true);
    f.net.events.set(stale.event.id, stale.event); await e.sync(id);
    const store = await f.openStore(); expect(await store.read('records', [id, stale.event.id])).toBeNull(); store.stop();
    expect(f.net.gets).not.toContain(stale.root);
    const vault = await vaultRow(f, id);
    expect(vault.quarantinedHeads?.[stale.event.id]).toBeUndefined();
    expect(vault.freshness?.authors[member.pubkey]?.seq).toBe('2');
    expect(snapshot(e).vaults[0].conflictCount).toBe(1);
  });
});

describe('SV-35 historical owner admission', () => {
  async function replayed(memberBudgets?: VaultEngineDeps['budgets']) {
    const { f, e, id, member, m } = await owned(memberBudgets);
    await e.share(id, [member.pubkey], 'write', {});
    await f.fs.write('/notebook/notes/a.md', 'v3'); await e.sync(id);
    await m.refreshInbox(); await m.accept(snapshot(m).invitations[0].invitationId, mountOptions);
    const heads = await ownerHeads(f, id), share = heads[heads.length - 2];
    expect((await vaultRow(member, id)).freshness?.authors[(await vaultRow(f, id)).owner]?.seq).toBe(String(heads[heads.length - 1].seq));
    // A second owner body at an already-covered sequence and the current revision.
    const replay = await craftHead(f, id, { pubkey: (await vaultRow(f, id)).owner, secret: secretOf(1) }, share.seq, 'equivocation', 0x60, false);
    f.net.events.set(replay.event.id, replay.event);
    return { f, id, member, m, replay };
  }
  it('still admits a below-high-water owner head as audit evidence, so prior equivocation fails closed', async () => {
    const { member, m, id, replay } = await replayed();
    await expect(m.sync(id)).rejects.toMatchObject({ code: 'CONFLICT', operation: 'fold' });
    const store = await member.openStore();
    expect(await store.read('records', [id, replay.event.id])).not.toBeNull(); store.stop();
    expect(snapshot(m).vaults.find(v => v.vaultId === id)?.lastError).toMatchObject({ code: 'CONFLICT' });
  });
  it('skips further historical owner heads before any manifest fetch once the audit budget is spent', async () => {
    const { f, id, member, m, replay } = await replayed({ ownerAuditRecords: 0 });
    await m.sync(id);
    const store = await member.openStore();
    expect(await store.read('records', [id, replay.event.id])).toBeNull(); store.stop();
    expect(f.net.gets).not.toContain(replay.root);
    expect(snapshot(m).vaults.find(v => v.vaultId === id)).toMatchObject({ freshness: 'verified', conflictCount: 0 });
  });
});

describe('SV-36 epoch-ledger freshness', () => {
  it('treats a behind-ring ledger as incomplete history, verifies the newest-epoch ledger and never reselects below the durable high-water', async () => {
    const { f, e, id, member, m } = await owned();
    const third = await signer(3).getPublicKey() as Pubkey;
    await e.share(id, [member.pubkey, third], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, mountOptions);
    expect(snapshot(m).vaults.find(v => v.vaultId === id)?.history).toBe('verified');
    expect((await vaultRow(member, id)).ledgerHighWater).toMatchObject({ epoch: '1' });
    await e.revoke(id, third);
    const ledgers = [...f.net.events.values()].filter(ev => ev.kind === 30078 && ev.tags.some(t => t[0] === 'd' && t[1] === historyDTag(id)));
    const ledger2 = ledgers.find(ev => ev.tags.some(t => t[0] === 'epoch' && t[1] === '2'))!;
    expect(ledger2).toBeDefined(); expect(ledgers).toHaveLength(2);
    f.net.events.delete(ledger2.id);
    await m.refreshInbox();
    await m.accept(snapshot(m).invitations.find(i => i.vaultId === id && !i.accepted)!.invitationId, { trustConfirmed: true, endpointsConfirmed: true, network });
    const behind = snapshot(m).vaults.find(v => v.vaultId === id)!;
    expect(behind).toMatchObject({ history: 'incomplete', freshness: 'verified' });
    expect((await vaultRow(member, id)).ledgerHighWater).toMatchObject({ epoch: '1' });
    f.net.events.set(ledger2.id, ledger2); await m.sync(id);
    expect(snapshot(m).vaults.find(v => v.vaultId === id)?.history).toBe('verified');
    const verified = await vaultRow(member, id);
    expect(verified.ledgerHighWater).toEqual({ epoch: '2', eventId: ledger2.id }); expect(verified.epochLedgerEvent?.id).toBe(ledger2.id);
    // Lose the cached blob but keep the durable high-water: the older ledger is not reselected.
    await m.stop(); f.net.events.delete(ledger2.id);
    const store = await member.openStore(); const row = (await store.read('vaults', [id]))!;
    const { epochLedgerEvent: _dropped, ...stripped } = row.value; void _dropped;
    await store.updateVault(stripped, row.revision); store.stop();
    const restarted = await start(member); await restarted.sync(id);
    expect(snapshot(restarted).vaults.find(v => v.vaultId === id)?.history).toBe('incomplete');
    const after = await vaultRow(member, id);
    expect(after.epochLedgerEvent).toBeUndefined(); expect(after.ledgerHighWater).toMatchObject({ epoch: '2' });
    f.net.events.set(ledger2.id, ledger2); await restarted.sync(id);
    expect(snapshot(restarted).vaults.find(v => v.vaultId === id)?.history).toBe('verified');
  });
});
