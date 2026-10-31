import { afterEach, describe, expect, it } from 'vitest';
import { finalizeEvent, type Event } from 'nostr-tools';
import { DEFAULT_VAULT_BUDGETS, VAULT_MAX_CONFLICT_ROWS, VAULT_MAX_RECORDS_PER_AUTHOR_SEQ } from '../budgets';
import { encodeUtf8, sealChunk } from '../crypto';
import { sealDirectoryNode } from '../dir-node';
import { HeadlessVaultEngine, hydrateRing } from '../engine';
import type { VaultEngineDeps } from '../engine-api';
import { FoldConflictError, foldCheckpoint, foldCurrentHeads } from '../fold';
import { buildHeadEvent } from '../head';
import type { DirectoryNode, Pubkey, VaultHead, VaultId, VaultPolicy } from '../types';
import { fixture, network, signer, snapshot } from './engine-fixtures';
import { cBytes, fileEntry, makeRecord, world } from './policy-fixtures';

const engines: HeadlessVaultEngine[] = [];
afterEach(async () => { await Promise.all(engines.splice(0).map(e => e.stop())); });
type Fixture = Awaited<ReturnType<typeof fixture>>;
const mountOptions = { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network } as const;
async function start(f: Fixture, budgets?: VaultEngineDeps['budgets']) {
  const engine = new HeadlessVaultEngine({ ...f.deps, ...(budgets ? { budgets } : {}) }); engines.push(engine); await engine.start(f.session); return engine;
}
async function sharedWriter(budgets?: VaultEngineDeps['budgets']) {
  const f = await fixture(); await f.mkdir('/notebook/notes'); await f.fs.write('/notebook/notes/a.md', 'initial');
  const e = await start(f, budgets); const id = await e.create('notes', {});
  const member = await fixture(f.net, signer(2)); const m = await start(member);
  await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
  await m.accept(snapshot(m).invitations[0].invitationId, mountOptions);
  const secret = new Uint8Array(32); secret[31] = 2;
  return { f, e, id, member, m, secret };
}
/** A member head over a one-file root, signed with the member key; only the relay and Blossom fake see it. */
async function memberHead(f: Fixture, id: VaultId, writer: Pubkey, secret: Uint8Array, seq: bigint, text: string, nonce: number): Promise<{ event: Event; root: string }> {
  const store = await f.openStore(); const vault = (await store.read('vaults', [id]))!.value;
  const owner = (await store.read('records', [id, vault.ownerCheckpointId!]))!.value.record; store.stop();
  const ring = hydrateRing(vault.nodeRings[vault.rootNodeId]), latest = ring.entries[ring.entries.length - 1];
  const policy: VaultPolicy = { ...owner.root.vault!, grantsRev: BigInt(owner.root.vault!.grantsRev) };
  const chunk = sealChunk(latest.nodeKey, encodeUtf8(text)); f.net.objects.set(chunk.address, chunk.sealed);
  const entry = fileEntry(latest.nodeKey, 'a.md', [{ address: chunk.address, sizeSealed: BigInt(chunk.sealed.length), chunkKeyId: latest.epoch, sizePlain: BigInt(text.length) }]);
  const node: DirectoryNode = { version: 2, nodeId: vault.rootNodeId, epoch: latest.epoch, entries: [entry], vault: policy };
  const sealed = sealDirectoryNode(node, latest.nodeKey); f.net.objects.set(sealed.address, sealed.sealed);
  const head: VaultHead = { vaultId: id, epoch: latest.epoch, rootManifest: sealed.address, seq, grantsRev: policy.grantsRev, writtenAt: 1800000000n + BigInt(nonce),
    parents: [{ writer: owner.writer, seq: BigInt(owner.head.seq), rootManifest: owner.head.rootManifest }] };
  return { event: finalizeEvent(buildHeadEvent(head, latest.nodeKey, writer, cBytes(nonce)), secret), root: sealed.address };
}
async function vaultRow(f: Fixture, id: VaultId) {
  const store = await f.openStore();
  const vault = (await store.read('vaults', [id]))!.value;
  const records = (await store.list('records')).filter(r => r.value.vaultId === id).map(r => r.value.record);
  const conflicts = (await store.list('conflicts')).filter(r => r.value.vaultId === id).map(r => r.value);
  store.stop(); return { vault, records, conflicts };
}

describe('SV-30 fold conflict budget (pure)', () => {
  it('aborts enumeration fail-closed at the limit without changing any admitted disposition', () => {
    const w = world(), owner = makeRecord(w), a = makeRecord(w, { writer: 1, seq: 2n, text: 'a' }), b = makeRecord(w, { writer: 1, seq: 2n, text: 'b' });
    const full = foldCheckpoint(w.grant, [owner, a, b], 0);
    expect(full.conflicts).toHaveLength(2);
    expect(foldCheckpoint(w.grant, [owner, a, b], 0, { maxConflicts: 2 })).toEqual(full);
    expect(() => foldCheckpoint(w.grant, [owner, a, b], 0, { maxConflicts: 1 })).toThrowError(expect.objectContaining({ code: 'TOO_LARGE', operation: 'fold' }));
    expect(() => foldCurrentHeads(w.grant, [owner, a, b], { maxConflicts: 1 })).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    expect(foldCurrentHeads(w.grant, [owner, a, b], { maxConflicts: VAULT_MAX_CONFLICT_ROWS })).toEqual(foldCurrentHeads(w.grant, [owner, a, b]));
    expect(DEFAULT_VAULT_BUDGETS).toMatchObject({ recordsPerAuthorSeq: 4, conflictRows: 10_000, conflictBytes: 16 * 1024 * 1024, conflictArtifactBytes: 256 * 1024 * 1024 });
  });
  it('owner ambiguity among cached rows outranks a budget abort', () => {
    const w = world(), base = makeRecord(w), fork = makeRecord(w, { text: 'equivocation' }), current = makeRecord(w, { seq: 2n });
    const member = makeRecord(w, { writer: 1, seq: 1n, text: 'member' });
    expect(() => foldCurrentHeads(w.grant, [base, current, member], { maxConflicts: 0 })).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    expect(() => foldCurrentHeads(w.grant, [base, fork, current, member], { maxConflicts: 0 })).toThrowError(FoldConflictError);
  });
});

describe('SV-30 engine admission and persistence budgets', () => {
  it('admits at most four member bodies per sequence before any manifest fetch and quarantines the rest', async () => {
    const { f, e, id, member, secret } = await sharedWriter();
    const forks = []; for (let i = 0; i < 6; i++) forks.push(await memberHead(f, id, member.pubkey, secret, 1n, `fork ${i}`, 0x10 + i));
    for (const fork of forks) f.net.events.set(fork.event.id, fork.event);
    await e.sync(id);
    const { vault, records } = await vaultRow(f, id);
    const admitted = records.filter(r => r.writer === member.pubkey);
    expect(admitted).toHaveLength(VAULT_MAX_RECORDS_PER_AUTHOR_SEQ);
    const quarantined = Object.entries(vault.quarantinedHeads ?? {});
    expect(quarantined).toHaveLength(2);
    for (const [eventId, held] of quarantined) {
      expect(held.code).toBe('TOO_LARGE');
      const fork = forks.find(x => x.event.id === eventId)!;
      expect(fork).toBeDefined(); expect(f.net.gets).not.toContain(fork.root);
    }
    // Admitted forks fold exactly as nostrc does: every one is an explicit alternate.
    expect(snapshot(e).vaults[0]).toMatchObject({ conflictCount: 4, foldQuarantine: null, lastError: expect.objectContaining({ code: 'TOO_LARGE' }) });
    expect(snapshot(e).vaults[0].lastError!.message).toContain('quarantined');
  });
  it('quarantines an over-budget fold without rows, winners or materialisation, and revoke still repairs it', async () => {
    const { f, e, id, member, secret } = await sharedWriter({ conflictRows: 2 });
    const before = await vaultRow(f, id);
    for (let i = 0; i < 3; i++) { const fork = await memberHead(f, id, member.pubkey, secret, 1n, `fork ${i}`, 0x30 + i); f.net.events.set(fork.event.id, fork.event); }
    await expect(e.sync(id)).rejects.toMatchObject({ code: 'TOO_LARGE', operation: 'fold', message: expect.stringContaining('conflict budget') });
    const after = await vaultRow(f, id);
    expect(after.vault.foldQuarantine).toMatchObject({ reason: 'conflict-rows', rows: 2 });
    expect(after.vault.materializedViewId).toBe(before.vault.materializedViewId);
    expect(after.vault.ownerCheckpointId).toBe(before.vault.ownerCheckpointId);
    expect(after.conflicts).toEqual([]);
    expect(await f.fs.read('/notebook/notes/a.md')).toBe('initial');
    expect(snapshot(e).vaults[0]).toMatchObject({ conflictCount: 0, foldQuarantine: { reason: 'conflict-rows', rows: 2, bytes: 0 }, lastError: expect.objectContaining({ code: 'TOO_LARGE' }) });
    await e.revoke(id, member.pubkey); await e.sync(id);
    expect(snapshot(e).vaults[0]).toMatchObject({ conflictCount: 0, foldQuarantine: null });
    expect(snapshot(e).vaults[0].members?.some(x => x.pubkey === member.pubkey)).toBe(false);
    expect((await vaultRow(f, id)).vault.foldQuarantine).toBeNull();
  });
  it('quarantines on the serialized-byte budget too, before any row is written', async () => {
    const { f, e, id, member, secret } = await sharedWriter({ conflictBytes: 64 });
    const fork = await memberHead(f, id, member.pubkey, secret, 1n, 'fork', 0x40); f.net.events.set(fork.event.id, fork.event);
    await expect(e.sync(id)).rejects.toMatchObject({ code: 'TOO_LARGE', operation: 'fold' });
    const { vault, conflicts } = await vaultRow(f, id);
    expect(conflicts).toEqual([]);
    expect(vault.foldQuarantine).toMatchObject({ reason: 'conflict-bytes', rows: 1 });
    expect(vault.foldQuarantine!.bytes).toBeGreaterThan(64);
  });
  it('defers alternate artifacts beyond the aggregate byte budget while rows stay recorded and resolvable', async () => {
    const { f, e, id, member, secret } = await sharedWriter({ conflictArtifactBytes: 0 });
    const fork = await memberHead(f, id, member.pubkey, secret, 1n, 'member version', 0x50); f.net.events.set(fork.event.id, fork.event);
    await e.sync(id);
    // The fork covers the owner checkpoint, so it is the sole (provisional) frontier
    // view (fold rule 8); the owner's own version is the recorded alternate.
    expect(await f.fs.read('/notebook/notes/a.md')).toBe('member version');
    expect(snapshot(e).vaults[0].provisional).toBe(true);
    const { conflicts } = await vaultRow(f, id);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]).toMatchObject({ artifactRefs: [], artifactDeferred: true, resolution: 'unresolved', kind: 'file', displayPath: 'a.md' });
    expect([...f.fs.files.keys()].some(path => path.includes('.onyx-vault-conflicts'))).toBe(false);
    const summary = snapshot(e).vaults[0].conflicts![0];
    expect(summary).toMatchObject({ path: 'a.md', alternatePath: null, inView: true, inOther: true });
    await e.resolveConflicts(id, [{ conflictId: summary.conflictId, action: 'use-other' }]);
    expect(await f.fs.read('/notebook/notes/a.md')).toBe('initial');
    await e.sync(id);
    expect(snapshot(e).vaults[0]).toMatchObject({ conflictCount: 0, provisional: false, foldQuarantine: null });
  });
});
