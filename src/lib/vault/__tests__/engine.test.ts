import { getPublicKey, nip19, verifyEvent } from 'nostr-tools';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createRoot } from 'solid-js';
import { useVaultEngine } from '../useVaultEngine';
import { retainDeviceKey, buildDeviceAnnouncement } from '../device-keys';
import { HeadlessVaultEngine } from '../engine';
import type { VaultDeliveryOptions, VaultRecoveryPassphraseRequest } from '../engine-api';
import { parseNcryptsec } from '../recovery';
import { fixture, network, signer, snapshot, journalFaultFactory, editCache } from './engine-fixtures';
import { bytes32, encodeUtf8, hashAddress, hex32, hexToBytes } from '../crypto';
import { buildGrantWrap, grantWrapPlaintextSizes } from '../carrier';
import { captureTree, newOwnerHead, revokeTree, sealTree } from '../tree';
import { world, nestedTree, makeRecord, signHead, cBytes } from './policy-fixtures';
import { ScriptedNetwork } from './engine-fixtures';
import { realWorkerBundle } from './engine-worker-fixture';
import { setImmediate, clearImmediate } from 'node:timers';
import type { NodeId, Pubkey, RecordId, StoredConflict, StoredVault, VaultGrant, VaultId } from '../types';
import { openRecovery, toStorage, VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION, VaultStore } from '../store';
import { VaultError } from '../errors';
import { buildHeadEvent } from '../head';
import { buildEpochLedgerEvent, historyDTag, ledgerWithHeads, openEpochLedgerEvent } from '../epoch-ledger';
import { hydrateRing } from '../engine';
import { ONYX_VAULT_PUBLISHER_D_PREFIX, ONYX_VAULT_PUBLISHER_KIND, PROTOCOL_ID } from '../protocol';

const engines: HeadlessVaultEngine[] = [];
afterEach(async () => { await Promise.all(engines.splice(0).map(e => e.stop())); });
async function start(f: Awaited<ReturnType<typeof fixture>>) { const engine = new HeadlessVaultEngine(f.deps); engines.push(engine); await engine.start(f.session); return engine; }
async function created() { const f = await fixture(); await f.mkdir('/notebook/notes'); await f.fs.write('/notebook/notes/a.md', 'initial'); const e = await start(f); const id = await e.create('notes', {}); return { f, e, id }; }
describe('headless vault engine', () => {
  it('creates, persists a designation/self-grant, captures bytes not mtime and resumes on restart', async () => {
    const { f, e, id } = await created();
    expect(snapshot(e).vaults[0]).toMatchObject({ vaultId: id, authority: 'owner', provisional: false, publisher: { isCurrentDevice: true } });
    expect(f.net.published.filter(e => e.kind === 1059)).toHaveLength(1);
    expect(snapshot(e).vaults[0]).toMatchObject({ members: [{ pubkey: f.pubkey, role: 'owner', informational: false }], network,
      deliveries: [{ recipient: f.pubkey, envelopeKey: f.pubkey, state: 'acknowledged' }] });
    expect(snapshot(e).vaults[0].regrantHeadroomBytes).toBeGreaterThan(0);
    expect(snapshot(e).deviceKeys).toMatchObject({ enabled: false, announcedPubkey: null, retainedKeyCount: 0 });
    const heads = () => f.net.published.filter(e => e.tags.some(t => t[0] === 'd' && t[1].startsWith('porthome/')));
    expect(heads()).toHaveLength(1);
    const ledgers = f.net.published.filter(event => event.tags.some(t => t[0] === 'd' && t[1] === historyDTag(id)));
    expect(ledgers).toHaveLength(1);
    expect(f.net.published.indexOf(heads()[0])).toBeLessThan(f.net.published.indexOf(ledgers[0]));
    const stored = await f.openStore(), vault = (await stored.read('vaults', [id]))!.value; stored.stop();
    expect(openEpochLedgerEvent(ledgers[0], id, f.pubkey, hydrateRing(vault.nodeRings[vault.rootNodeId])).epochs.map(e => e.epoch)).toEqual([1n]);
    f.fs.modified.set('/notebook/notes/a.md', 20);
    await e.sync(id); expect(heads()).toHaveLength(1);
    await f.fs.write('/notebook/notes/a.md', 'edited'); await e.sync(id); expect(heads()).toHaveLength(2);
    await e.stop(); const next = await start(f); expect(snapshot(next).vaults[0].vaultId).toBe(id); await next.sync(id); expect(heads()).toHaveLength(2);
    const state = JSON.stringify(snapshot(next), (_key, value) => typeof value === 'bigint' ? String(value) : value); expect(state).not.toContain('nodeKey'); expect(state).not.toContain('nodeRings');
  });
  it('no-op capture reads 0 bytes; a one-note sync reads only that note and journals at most ten times', async () => {
    const f = await fixture(); await f.mkdir('/notebook/notes');
    for (let i = 0; i < 6; i++) await f.fs.write(`/notebook/notes/n${i}.md`, `note ${i} `.repeat(200));
    const e = await start(f); const id = await e.create('notes', {});
    const heads = () => new Set(f.net.published.filter(ev => ev.tags.some(t => t[0] === 'd' && t[1].startsWith('porthome/'))).map(ev => ev.id)).size;
    const reads = vi.spyOn(f.fs, 'readBinary'), journals = vi.spyOn(VaultStore.prototype, 'saveJournal');
    try {
      await e.sync(id);
      expect(reads).not.toHaveBeenCalled(); expect(journals).not.toHaveBeenCalled();
      // An mtime-only touch re-hashes that one file (its bytes might have changed) but publishes nothing.
      const published = heads();
      f.fs.modified.set('/notebook/notes/n2.md', (f.fs.modified.get('/notebook/notes/n2.md') ?? 0) + 1);
      await e.sync(id);
      expect(reads.mock.calls.map(call => call[0])).toEqual(['/notebook/notes/n2.md']); expect(heads()).toBe(published); expect(journals).not.toHaveBeenCalled();
      reads.mockClear();
      await e.sync(id); expect(reads).not.toHaveBeenCalled();
      await f.fs.write('/notebook/notes/n3.md', 'changed');
      await e.sync(id);
      expect(reads.mock.calls.map(call => call[0])).toEqual(['/notebook/notes/n3.md']);
      expect(heads()).toBe(published + 1); expect(journals.mock.calls.length).toBeLessThanOrEqual(10);
      reads.mockClear(); journals.mockClear();
      await e.sync(id); expect(reads).not.toHaveBeenCalled(); expect(journals).not.toHaveBeenCalled();
      const store = await f.openStore(); expect((await store.read('vaults', [id]))!.value.baseline['n3.md'].disk).toMatchObject({ size: 7 }); store.stop();
    } finally { reads.mockRestore(); journals.mockRestore(); }
  });
  it('silently merges self-grants, keeps recovery discovery detached and never exposes invitations', async () => {
    const { f, e, id } = await created();
    const seen: number[] = [], unsubscribe = e.subscribe(s => seen.push(s.invitations.length));
    await e.refreshInbox(); await e.refreshInbox();
    expect(seen.every(count => count === 0)).toBe(true); unsubscribe();
    const store = await f.openStore(), vault = (await store.read('vaults', [id]))!.value;
    expect(vault.grant?.owner).toBe(f.pubkey);
    expect((await store.list('invitations')).map(row => ({ read: row.value.read, accepted: row.value.accepted }))).toEqual([{ read: true, accepted: true }]);
    expect(vault.epochLedgerEvent).toBeDefined();
    const newestGrant = { ...vault.grant!, ring: hydrateRing(vault.nodeRings[vault.rootNodeId]), issuedAt: BigInt(vault.grant!.issuedAt) + 1n, rootManifest: hashAddress(encodeUtf8('new discovery hint')) };
    const wrapped = await buildGrantWrap(newestGrant, f.session.signer, f.pubkey, { clock: f.deps.clock });
    f.net.events.set(wrapped.wrap.id, wrapped.wrap); await e.refreshInbox();
    const updated = (await store.read('vaults', [id]))!.value;
    expect(updated.grant?.rootManifest).toBe(newestGrant.rootManifest);
    expect(updated.epochLedgerEvent).toEqual(vault.epochLedgerEvent);
    expect(updated.ownerCheckpointId).toBe(vault.ownerCheckpointId);
    expect(updated.retainedRoots).toContainEqual({ address: newestGrant.rootManifest, epoch: null });
    store.stop();
    await e.stop(); const restarted = await start(f);
    expect(snapshot(restarted).invitations).toEqual([]);

    const second = await fixture(f.net, f.session.signer), other = await start(second);
    await other.refreshInbox(); expect(snapshot(other).invitations).toEqual([]);
    expect(snapshot(other).vaults[0]).toMatchObject({ vaultId: id, authority: 'owner', mount: null });
    expect(second.fs.files.size).toBe(0);
  });
  it('reconciles a PUT accepted with lost response without changing its candidate', async () => {
    const f = await fixture(); await f.mkdir('/notebook/notes'); await f.fs.write('/notebook/notes/a.md', 'bytes'); const e = await start(f);
    f.net.losePut = true; await expect(e.create('notes', {})).rejects.toMatchObject({ code: 'INCOMPLETE' });
    const id = snapshot(e).vaults[0].vaultId, store = await f.openStore(); const pending = await store.pendingOperations(); expect(pending[0].pendingAddress).not.toBeNull(); const candidate = pending[0].candidate; store.stop();
    await e.stop(); const next = await start(f); expect(snapshot(next).vaults[0].lastError).toBeNull();
    const check = await f.openStore(); const op = await check.read('operations', [id, pending[0].operationId]); expect(op!.value.stage).toBe('committed'); expect(op!.value.candidate).toEqual(candidate); check.stop();
    expect(f.net.puts.filter(a => a === pending[0].pendingAddress)).toHaveLength(1);
  });
  // Journal boundaries per publish after SV-27 (incremental uploads) and SV-28 (batched
  // saves): prepared, uploading, confirmed-object migration, one save per upload batch
  // (chunks first, then each manifest level), ready-to-publish, awaiting-ack, relay
  // outcomes, committed. The one-file create below also journals its epoch-ledger
  // receipt: ten boundaries; the one-manifest policy publish has eight.
  const matrix = (journals: number) => Array.from({ length: journals * 2 }, (_, index) => ({ boundary: index % 2 ? 'after' as const : 'before' as const, journal: Math.floor(index / 2) + 1 }));
  const journalMatrix = matrix(10), policyMatrix = matrix(8);
  it.each(journalMatrix)('recovers a storage crash $boundary journal commit $journal', async ({ boundary, journal }) => {
    const f = await fixture(); await f.mkdir('/notebook/v'); await f.fs.write('/notebook/v/a', 'payload');
    let stopping: Promise<void> | undefined;
    let e!: HeadlessVaultEngine;
    const fault = journalFaultFactory(f.factory, journal, boundary, () => { stopping = e.stop(); });
    e = new HeadlessVaultEngine({ ...f.deps, idbFactory: () => fault.factory }); engines.push(e); await e.start(f.session);
    await e.create('v', {}).catch(() => {}); fault.disable();
    await (stopping ?? e.stop());
    const next = await start(f); const id = snapshot(next).vaults[0].vaultId; await next.sync(id);
    const store = await f.openStore(); const state = (await store.read('vaults', [id]))!.value; expect(state.lastOwnSeq).toBe('1'); expect(state.pendingCandidateId).toBeNull(); expect(state.baseline.a.byteHash).toBeDefined(); store.stop();
    const heads = f.net.published.filter(event => event.tags.some(tag => tag[1]?.startsWith('porthome/')));
    expect(new Set(heads.map(event => event.id)).size).toBe(1); expect(fault.count()).toBe(journal);
  });
  it.each(policyMatrix)('recovers a policy crash $boundary journal commit $journal', async ({ boundary, journal }) => {
    const { f, e: original, id } = await created(); await original.stop();
    let stopping: Promise<void> | undefined;
    let e!: HeadlessVaultEngine;
    const fault = journalFaultFactory(f.factory, journal, boundary, () => { stopping = e.stop(); }, false);
    e = new HeadlessVaultEngine({ ...f.deps, idbFactory: () => fault.factory }); engines.push(e); await e.start(f.session);
    await e.sync(id); fault.arm();
    const member = hex32<Pubkey>(await signer(2).getPublicKey());
    await e.share(id, [member], 'read', {}).catch(() => {}); fault.disable();
    await (stopping ?? e.stop());
    const next = await start(f); await next.sync(id);
    const check = await f.openStore();
    const state = (await check.read('vaults', [id]))!.value;
    expect(state.pendingCandidateId).toBeNull();
    const operations = (await check.list('operations')).filter(op => op.value.kind === 'policy');
    expect(operations.every(op => op.value.stage === 'committed')).toBe(true);
    // Before the first intent commit there is nothing to recover. Otherwise the
    // policy survives and its immutable signed event is never replaced.
    if (journal > 1 || boundary === 'after') expect(snapshot(next).vaults[0].members).toContainEqual({ pubkey: member, role: 'reader', informational: true });
    expect(fault.count()).toBe(journal); check.stop();
  });

  it('recovers every journal across concurrent vault lanes, including an unlinked policy, and preserves failed phases', async () => {
    const { f, e, id } = await created();
    const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = f.factory.open(VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    const previous = await new Promise<unknown>((resolve, reject) => { const tx = db.transaction('vaults'); const request = tx.objectStore('vaults').get([f.pubkey, id]); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
    f.net.rejectHead = true;
    await f.mkdir('/notebook/other');
    const member = hex32<Pubkey>(await signer(2).getPublicKey());
    await Promise.allSettled([e.share(id, [member], 'read', {}), e.create('other', {})]);
    await e.stop();
    // Native IDB fault fixture: leave the encrypted journal intact but restore
    // the earlier valid vault envelope, simulating an unlinked imported journal.
    await new Promise<void>((resolve, reject) => { const tx = db.transaction('vaults', 'readwrite'); tx.objectStore('vaults').put(previous, [f.pubkey, id]); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); }); db.close();
    const failed = await start(f);
    const check = await f.openStore(); const unresolved = await check.pendingOperations();
    expect(new Set(unresolved.map(op => op.kind))).toEqual(new Set(['policy', 'create']));
    expect(unresolved.every(op => op.stage === 'needs-recovery' && op.recoveryStage === 'awaiting-ack')).toBe(true);
    const signed = unresolved.map(op => op.signedEvent!.id); check.stop(); await failed.stop();
    f.net.rejectHead = false;
    const resumed = await start(f); const after = await f.openStore();
    expect(await after.pendingOperations()).toEqual([]);
    expect(snapshot(resumed).vaults).toHaveLength(2);
    expect(snapshot(resumed).vaults.find(vault => vault.vaultId === id)?.members).toContainEqual({ pubkey: member, role: 'reader', informational: true });
    for (const eventId of signed) expect((await after.list('operations')).some(op => op.value.stage === 'committed' && op.value.signedEvent?.id === eventId)).toBe(true);
    after.stop();
  });

  it('needs-key explicitly requires start again after external secret-store unlock', async () => {
    const { f, e, id } = await created(); await e.stop();
    let locked = true;
    const secrets = { ...f.secrets, isLocked: () => locked };
    const next = new HeadlessVaultEngine(f.deps); engines.push(next);
    await next.start({ ...f.session, secrets });
    expect(snapshot(next)).toMatchObject({ lifecycle: 'stopped', condition: 'needs-key', lastError: { message: expect.stringContaining('call start() again') } });
    expect(f.workers).toHaveLength(1);
    locked = false;
    expect(snapshot(next).lifecycle).toBe('stopped');
    await next.start({ ...f.session, secrets });
    expect(snapshot(next)).toMatchObject({ lifecycle: 'running', condition: 'ready', vaults: [{ vaultId: id }] });
  });

  it('retries the exact signed event after relay acknowledgement is lost', async () => {
    const f = await fixture(); await f.mkdir('/notebook/notes'); const e = await start(f); f.net.loseHead = true;
    await expect(e.create('notes', {})).rejects.toMatchObject({ code: 'NETWORK' });
    const signed = f.net.published.find(e => e.tags.some(t => t[1]?.startsWith('porthome/')))!;
    await e.stop(); await start(f);
    const attempts = f.net.published.filter(e => e.id === signed.id); expect(attempts).toHaveLength(2); expect(attempts[0]).toEqual(attempts[1]);
  });
  it('shares, accepts into an approved empty mount and publishes member changes provisionally', async () => {
    const { f, e, id } = await created(); const member = await fixture(f.net, signer(2)); const m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    expect(snapshot(e).vaults[0].members).toContainEqual({ pubkey: member.pubkey, role: 'writer', informational: false });
    const invite = snapshot(m).invitations.find(i => i.vaultId === id)!;
    const mount = await m.accept(invite.invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    expect(mount.relativePath).toBe('shared'); expect(await member.fs.read('/notebook/shared/a.md')).toBe('initial');
    await member.fs.write('/notebook/shared/a.md', 'member edit'); await m.sync(id);
    expect(snapshot(m).vaults[0]).toMatchObject({ authority: 'writer', provisional: true });
    await e.sync(id); expect(snapshot(e).vaults[0].provisional).toBe(true);
  });
  it('SV-45: marks only two edited paths out of ten, clears on coverage, and includes deletion and addition', async () => {
    const f = await fixture(); await f.mkdir('/notebook/notes');
    for (let i = 0; i < 10; i++) await f.fs.write(`/notebook/notes/n${i}.md`, `note ${i}`);
    const e = await start(f), id = await e.create('notes', {});
    const member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    await member.fs.write('/notebook/shared/n1.md', 'first edit');
    await member.fs.write('/notebook/shared/n7.md', 'second edit');
    await m.sync(id);
    const own = snapshot(m).vaults[0];
    expect(own).toMatchObject({ provisional: true, provisionalCount: 2, provisionalOtherPaths: [] });
    expect(new Set(own.provisionalPaths)).toEqual(new Set(['shared/n1.md', 'shared/n7.md']));
    expect(Object.isFrozen(own.provisionalPaths)).toBe(true);
    // A second reconcile and a cold start give the same digest-derived paths.
    await m.sync(id); await m.stop(); const resumed = await start(member); await resumed.sync(id);
    expect(snapshot(resumed).vaults[0].provisionalPaths).toEqual(own.provisionalPaths);
    await e.sync(id);
    expect(snapshot(e).vaults[0].provisionalCount).toBe(2);
    expect(new Set(snapshot(e).vaults[0].provisionalPaths)).toEqual(new Set(['notes/n1.md', 'notes/n7.md']));
    expect(new Set(snapshot(e).vaults[0].provisionalOtherPaths)).toEqual(new Set(['notes/n1.md', 'notes/n7.md']));
    await e.resolveConflicts(id, snapshot(e).vaults[0].conflicts!.map(c => ({ conflictId: c.conflictId, action: 'keep-view' })));
    await resumed.sync(id);
    for (const engine of [e, resumed]) expect(snapshot(engine).vaults[0]).toMatchObject({
      provisional: false, provisionalCount: 0, provisionalPaths: [], provisionalOtherPaths: [],
    });
    await member.fs.remove('/notebook/shared/n3.md');
    await member.fs.write('/notebook/shared/新しい.md', 'added');
    await resumed.sync(id);
    expect(snapshot(resumed).vaults[0]).toMatchObject({ provisionalCount: 2 });
    expect(new Set(snapshot(resumed).vaults[0].provisionalPaths)).toEqual(new Set(['shared/n3.md', 'shared/新しい.md']));
    await e.sync(id);
    await e.resolveConflicts(id, snapshot(e).vaults[0].conflicts!.map(c => ({ conflictId: c.conflictId, action: 'keep-view' })));
    await resumed.sync(id);
    expect(snapshot(resumed).vaults[0]).toMatchObject({ provisional: false, provisionalCount: 0, provisionalPaths: [] });
  });
  it('SV-45: a failed pending publication reports the full total but caps the decoded path list', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    for (let i = 0; i < 2001; i++) await member.fs.write(`/notebook/shared/new-${i}.md`, 'new');
    f.net.failPut = true;
    await expect(m.sync(id)).rejects.toBeInstanceOf(VaultError);
    const pending = snapshot(m).vaults[0];
    expect(pending).toMatchObject({ provisional: true, provisionalCount: 2001, provisionalOtherPaths: [] });
    expect(pending.provisionalPaths).toHaveLength(2000);
    expect(pending.provisionalPaths.every(path => path.startsWith('shared/new-'))).toBe(true);
    expect(pending.provisionalPaths).not.toContain('shared/a.md');
    f.net.failPut = false; await m.sync(id);
    expect(snapshot(m).vaults[0].provisionalCount).toBe(2001);
    expect(snapshot(m).vaults[0].provisionalPaths).toHaveLength(2000);
  }, 60000);
  it('SV-45: read-only local candidates remain path-specific after a cold reconciliation', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'read', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    await member.fs.write('/notebook/shared/a.md', 'local-only'); await m.sync(id);
    expect(snapshot(m).vaults[0]).toMatchObject({ authority: 'reader', provisionalCount: 1, provisionalPaths: ['shared/a.md'] });
    await m.stop(); const resumed = await start(member); await resumed.sync(id);
    expect(snapshot(resumed).vaults[0]).toMatchObject({ provisional: true, provisionalCount: 1,
      provisionalPaths: ['shared/a.md'], provisionalOtherPaths: [] });
  });
  it('retires a legacy fold row when paths agree and reactivates it for a new difference', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    const store = await member.openStore(), vault = (await store.read('vaults', [id]))!.value;
    const owner = (await store.read('records', [id, vault.ownerCheckpointId!]))!.value.record;
    const conflict: StoredConflict['conflict'] = { pathEnc: owner.paths[0].pathEnc, otherRecordId: owner.eventId as unknown as RecordId,
      inView: true, inOther: true, writer: owner.writer, seq: owner.head.seq, rootManifest: owner.head.rootManifest };
    // Seed the pre-SV-20 row format and id, without a retirement marker.
    const conflictId = hashAddress(encodeUtf8(JSON.stringify(toStorage({ vaultId: id, ...conflict }))));
    const artifact = `/notebook/shared/.onyx-vault-conflicts/${conflictId}/a.md`;
    await member.mkdir(artifact.slice(0, artifact.lastIndexOf('/'))); await member.fs.write(artifact, 'initial');
    await store.put('conflicts', [id, conflictId], { schemaVersion: 1, protocolId: PROTOCOL_ID, vaultId: id, conflictId,
      conflict, retainedVersions: [owner.head.rootManifest], artifactRefs: [artifact], displayPath: 'a.md', kind: 'file', resolution: 'unresolved' });
    await m.sync(id);
    expect(snapshot(m).vaults[0].conflicts).toEqual([]);
    expect((await store.read('conflicts', [id, conflictId]))!.value).toMatchObject({ resolution: 'resolved', retiredByFold: true });
    await member.fs.write('/notebook/shared/a.md', 'new difference'); await m.sync(id); await m.sync(id);
    expect(snapshot(m).vaults[0].conflicts).toContainEqual(expect.objectContaining({ conflictId, alternatePath: artifact }));
    expect((await store.read('conflicts', [id, conflictId]))!.value.resolution).toBe('unresolved');
    expect(await member.fs.read(artifact)).toBe('initial'); store.stop();
  });
  it('keeps an uncovered deletion alternative across rekey/restart until both versions delete the path', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    await member.fs.remove('/notebook/shared/a.md');
    let release!: () => void, entered!: () => void, blocked = false;
    const hold = new Promise<void>(resolve => { release = resolve; }), ready = new Promise<void>(resolve => { entered = resolve; });
    f.net.beforePut = async () => { if (!blocked) { blocked = true; entered(); await hold; } };
    const pending = m.sync(id); void pending.catch(() => {});
    try {
      await ready; await f.fs.write('/notebook/notes/a.md', 'owner retained file'); await e.sync(id);
    } finally { release(); f.net.beforePut = undefined; }
    await pending; await e.sync(id);
    const deletion = snapshot(e).vaults[0].conflicts!.find(c => c.path === 'a.md' && c.inView && !c.inOther)!;
    expect(deletion).toBeDefined();
    await e.revoke(id, member.pubkey); await e.sync(id);
    expect(snapshot(e).vaults[0].conflicts).toContainEqual(expect.objectContaining({ conflictId: deletion.conflictId }));
    expect(await f.fs.read('/notebook/notes/a.md')).toBe('owner retained file');
    const store = await f.openStore(), vault = (await store.read('vaults', [id]))!.value;
    const owner = (await store.read('records', [id, vault.ownerCheckpointId!]))!.value.record;
    expect(owner.head.parents.some(parent => parent.writer === member.pubkey && BigInt(parent.seq) >= deletion.seq)).toBe(false); store.stop();
    await e.stop(); const restarted = await start(f);
    expect(snapshot(restarted).vaults[0].conflicts!.some(c => c.conflictId === deletion.conflictId)).toBe(true);
    // Equality must mean absence at the decoded path, not just an old name_enc.
    await f.fs.remove('/notebook/notes/a.md'); await restarted.sync(id); await restarted.sync(id);
    expect(snapshot(restarted).vaults[0].conflicts!.some(c => c.conflictId === deletion.conflictId)).toBe(false);
    const checked = await f.openStore();
    expect((await checked.read('conflicts', [id, deletion.conflictId]))!.value).toMatchObject({ resolution: 'resolved', retiredByFold: true }); checked.stop();
  });
  it('retires covered fold conflicts durably without removing alternates or local divergence', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    await member.fs.write('/notebook/shared/a.md', 'member proposal'); await m.sync(id); await m.sync(id);
    const stale = snapshot(m).vaults[0].conflicts!;
    expect(stale.length).toBeGreaterThan(0);
    const alternates = new Map(await Promise.all(stale.flatMap(c => c.alternatePath ? [c.alternatePath] : []).map(async path => [path, await member.fs.readBinary(path)] as const)));
    expect(alternates.size).toBeGreaterThan(0);
    await e.sync(id);
    await e.resolveConflicts(id, snapshot(e).vaults[0].conflicts!.map(c => ({ conflictId: c.conflictId, action: 'keep-view' })));
    await m.sync(id); await m.sync(id);
    expect(snapshot(m).vaults[0]).toMatchObject({ provisional: false, conflictCount: 0, conflicts: [] });
    const store = await member.openStore();
    for (const c of stale) {
      const row = (await store.read('conflicts', [id, c.conflictId]))!.value;
      expect(row.resolution).toBe('resolved'); expect(row.artifactRefs.length).toBeGreaterThan(0);
    }
    store.stop();
    for (const [path, bytes] of alternates) expect(await member.fs.readBinary(path)).toEqual(bytes);
    await m.stop(); const restarted = await start(member);
    expect(snapshot(restarted).vaults[0].conflicts).toEqual([]);

    // A remote update races a local edit: this is NOT a fold/frontier conflict.
    await member.fs.write('/notebook/shared/a.md', 'unsaved local divergence');
    await f.fs.write('/notebook/notes/a.md', 'new owner version'); await e.sync(id); await restarted.sync(id);
    const localStore = await member.openStore();
    const local = (await localStore.list('conflicts')).find(row => row.value.resolution === 'unresolved' && row.value.artifactRefs.some(path => path.endsWith('/local')))!.value;
    localStore.stop(); expect(local).toBeDefined();
    await e.sync(id);
    await e.resolveConflicts(id, snapshot(e).vaults[0].conflicts!.map(c => ({ conflictId: c.conflictId, action: 'keep-view' })));
    await restarted.sync(id); await restarted.sync(id);
    expect(snapshot(restarted).vaults[0].conflicts!.some(c => c.conflictId === local.conflictId)).toBe(true);
    expect(await member.fs.read(local.artifactRefs.find(path => path.endsWith('/local'))!)).toBe('unsaved local divergence');
  });
  it('attaches a populated owner folder without overwriting different bytes and blocks publications on the other device', async () => {
    const { f, e, id } = await created(); const second = await fixture(f.net, f.session.signer); await second.mkdir('/notebook/existing'); await second.fs.write('/notebook/existing/a.md', 'local copy');
    const other = await start(second); await other.refreshInbox(); await other.attach(id, 'existing');
    expect(await second.fs.read('/notebook/existing/a.md')).toBe('local copy'); expect(snapshot(other).vaults[0].conflictCount).toBeGreaterThan(0);
    expect(snapshot(other).vaults[0].conflicts?.[0]).toMatchObject({ path: 'a.md', displayPath: 'a.md', kind: 'file', inView: true, inOther: true });
    const before = f.net.published.length; await other.sync(id); expect(f.net.published).toHaveLength(before);
    await expect(other.share(id, [hex32<Pubkey>(await signer(3).getPublicKey())], 'read', {})).rejects.toMatchObject({ code: 'POLICY' });
    await other.takeOverPublishing(id); await expect(e.share(id, [second.pubkey], 'read', {})).rejects.toMatchObject({ code: 'POLICY' });
  });
  it('refuses missing account ownership before opening state', async () => {
    const f = await fixture(); const e = new HeadlessVaultEngine({ ...f.deps, lockProvider: { request: (async (_name: string, _options: unknown, callback: (lock: null) => unknown) => callback(null)) as LockManager['request'] } }); engines.push(e);
    await expect(e.start(f.session)).rejects.toMatchObject({ code: 'CONFLICT' }); expect(snapshot(e).lifecycle).toBe('stopped');
  });
  it('shares with the delivery options the UI passes (explicit undefined fallback, device-key summary)', async () => {
    // VaultShareDialog sends { enabled: false, allowIdentityFallback: undefined } when device keys are off;
    // the journal must not reject that as unserializable (live E2E 2026-10-29 failed every share with ARG).
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'read', { enabled: false, allowIdentityFallback: undefined });
    await m.refreshInbox(); expect(snapshot(m).invitations.map(i => i.cap)).toEqual(['read']);
    const summary = { ...snapshot(e).deviceKeys } as unknown as VaultDeliveryOptions;
    await e.share(id, [member.pubkey], 'write', summary);
    await m.refreshInbox(); expect(snapshot(m).invitations.map(i => i.cap).sort()).toEqual(['read', 'write']);
    expect(snapshot(e).lastError).toBeNull();
  });
  it('refreshes an accepted grant in place without remounting or publishing deletions', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'read', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'existing', trustConfirmed: true, endpointsConfirmed: true, network });
    await e.share(id, [member.pubkey], 'write', {}); await m.sync(id); await m.refreshInbox();
    const updated = snapshot(m).invitations.find(i => i.cap === 'write')!;
    const mount = await m.accept(updated.invitationId, { trustConfirmed: true, endpointsConfirmed: true, network });
    expect(mount.relativePath).toBe('existing'); expect(await member.fs.read('/notebook/existing/a.md')).toBe('initial');
    const before = f.net.published.length; await m.sync(id); expect(f.net.published).toHaveLength(before);
  });
  it('reseals a child-only alternate resolution when concurrent directories use different node keys', async () => {
    const f = await fixture(); await f.mkdir('/notebook/v'); const e = await start(f), id = await e.create('v', {});
    const member = await fixture(f.net, signer(2)), m = await start(member); await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox();
    await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'm', trustConfirmed: true, endpointsConfirmed: true, network });
    await member.mkdir('/notebook/m/d'); await member.fs.write('/notebook/m/d/a.md', 'member version');
    let release!: () => void, entered!: () => void, blocked = false;
    const hold = new Promise<void>(resolve => { release = resolve; }), ready = new Promise<void>(resolve => { entered = resolve; });
    f.net.beforePut = async () => { if (!blocked) { blocked = true; entered(); await hold; } };
    const pending = m.sync(id); void pending.catch(() => {});
    try {
      await ready; await f.mkdir('/notebook/v/d'); await f.fs.write('/notebook/v/d/a.md', 'owner version'); await e.sync(id);
    } finally { release(); f.net.beforePut = undefined; }
    await pending; await e.sync(id);
    const conflict = snapshot(e).vaults[0].conflicts!.find(c => c.kind === 'file' && c.path === 'd/a.md' && c.writer === member.pubkey && c.inOther)!;
    expect(conflict).toBeDefined(); await e.resolveConflicts(id, [{ conflictId: conflict.conflictId, action: 'use-other' }]);
    expect(await f.fs.read('/notebook/v/d/a.md')).toBe('member version');
    await m.sync(id); expect(await member.fs.read('/notebook/m/d/a.md')).toBe('member version');
    // An old directory version must not restore revoked epoch-1 write keys.
    await e.revoke(id, member.pubkey);
    // Review the current fold after rotation retires paths that no longer differ.
    await e.sync(id);
    const directory = snapshot(e).vaults[0].conflicts!.find(c => c.kind === 'directory' && c.path === 'd')!;
    await e.resolveConflicts(id, [{ conflictId: directory.conflictId, action: 'use-other' }]);
    const store = await f.openStore(), vault = (await store.read('vaults', [id]))!.value;
    const record = (await store.read('records', [id, vault.ownerCheckpointId!]))!.value.record;
    const dir = record.root.entries.find(entry => entry.kind === 'directory' && entry.namePlain === 'd');
    expect(dir?.kind).toBe('directory');
    if (dir?.kind === 'directory') {
      expect(dir.childEpoch).toBe('2');
      const file = record.nodesById[dir.childNodeId].entries.find(entry => entry.kind === 'file');
      expect(file?.kind === 'file' && file.chunks.every(chunk => chunk.chunkKeyId === '2')).toBe(true);
    }
    store.stop();
  });
  it('policy publication preserves an unapproved member view without rebinding its baseline to different chunks', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox(); await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'm', trustConfirmed: true, endpointsConfirmed: true, network });
    await member.fs.write('/notebook/m/a.md', 'proposal'); await m.sync(id); await e.sync(id);
    const store = await f.openStore(), before = (await store.read('vaults', [id]))!.value.materializedViewId;
    await e.share(id, [hex32<Pubkey>(await signer(3).getPublicKey())], 'read', {});
    expect((await store.read('vaults', [id]))!.value.materializedViewId).toBe(before);
    const localCopies = (await store.list('conflicts')).flatMap(row => row.value.artifactRefs.filter(path => path.endsWith('/local')));
    expect((await Promise.all(localCopies.map(path => f.fs.read(path)))).includes('proposal')).toBe(true);
    await e.sync(id); expect(await f.fs.read('/notebook/notes/a.md')).toBe('initial');
    expect((await store.read('vaults', [id]))!.value.baseline['a.md'].byteHash).toBe(hashAddress(encodeUtf8('initial'))); store.stop();
  });
  it('rejects stale resolutions rather than covering newly arrived proposals', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox(); await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'm', trustConfirmed: true, endpointsConfirmed: true, network });
    await member.fs.write('/notebook/m/a.md', 'first proposal'); await m.sync(id); await e.sync(id);
    const resolutions = snapshot(e).vaults[0].conflicts!.map(c => ({ conflictId: c.conflictId, action: 'keep-view' as const }));
    await member.fs.write('/notebook/m/a.md', 'new unreviewed proposal'); await m.sync(id); const before = f.net.published.length;
    await expect(e.resolveConflicts(id, resolutions)).rejects.toMatchObject({ code: 'CONFLICT' }); expect(f.net.published).toHaveLength(before);
  });
  it('replays resolution materialisation after the owner head committed but staging crashed', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    await e.share(id, [member.pubkey], 'write', {}); await m.refreshInbox(); await m.accept(snapshot(m).invitations[0].invitationId, { relativePath: 'm', trustConfirmed: true, endpointsConfirmed: true, network });
    await member.fs.write('/notebook/m/a.md', 'proposal'); await m.sync(id); await e.sync(id);
    const choices = snapshot(e).vaults[0].conflicts!.map(c => ({ conflictId: c.conflictId, action: 'use-other' as const }));
    f.fs.beforeWrite = path => { if (path.endsWith('.new')) throw new Error('resolution staging crash'); };
    await expect(e.resolveConflicts(id, choices)).rejects.toThrow();
    const pinned = await f.openStore(); expect((await pinned.pendingOperations()).find(op => op.kind === 'materialize')!.pinnedAddresses.length).toBeGreaterThanOrEqual(2); pinned.stop();
    f.fs.beforeWrite = undefined; await e.stop();
    const restarted = await start(f); expect(await f.fs.read('/notebook/notes/a.md')).toBe('initial'); expect(snapshot(restarted).vaults[0].conflictCount).toBe(0);
    await restarted.sync(id); expect(await f.fs.read('/notebook/notes/a.md')).toBe('initial');
  });
  it.each(['clear', 'corrupt'] as const)('repairs %s ciphertext cache entries before publishing unchanged dependencies', async mode => {
    const { f, e, id } = await created(); await editCache(f.factory, mode); await f.fs.write('/notebook/notes/b.md', 'new file');
    await e.sync(id); const store = await f.openStore(); expect((await store.read('vaults', [id]))!.value.lastOwnSeq).toBe('2'); store.stop();
  });
  it('retires a pending owner publication to local-only state after handover', async () => {
    const { f, e, id } = await created(), second = await fixture(f.net, f.session.signer); await second.mkdir('/notebook/v'); await second.fs.write('/notebook/v/a.md', 'initial');
    const other = await start(second); await other.refreshInbox(); await other.attach(id, 'v');
    await f.fs.write('/notebook/notes/a.md', 'pending local');
    let release!: () => void, entered!: () => void;
    const hold = new Promise<void>(resolve => { release = resolve; }), ready = new Promise<void>(resolve => { entered = resolve; });
    f.net.beforePut = async () => { entered(); await hold; };
    const syncing = e.sync(id); const result = syncing.catch(error => error); await ready;
    await other.takeOverPublishing(id); release(); expect(await result).toMatchObject({ code: 'POLICY' }); f.net.beforePut = undefined;
    const store = await f.openStore(); const state = (await store.read('vaults', [id]))!.value;
    expect(state.pendingCandidateId).toBeNull(); expect(state.localCandidate).toBeDefined(); expect(state.lastOwnSeq).toBe('1'); store.stop();
    expect(await f.fs.read('/notebook/notes/a.md')).toBe('pending local');
    const count = f.net.published.length; await e.sync(id); expect(f.net.published).toHaveLength(count);
  });
  it('resolves simultaneous publishing handovers by replaceable ordering and the loser refuses owner mutations', async () => {
    const { f, e, id } = await created(), second = await fixture(f.net, f.session.signer); await second.mkdir('/notebook/v'); await second.fs.write('/notebook/v/a.md', 'initial');
    const other = await start(second); await other.refreshInbox(); await other.attach(id, 'v');
    let count = 0, release!: () => void; const both = new Promise<void>(resolve => { release = resolve; });
    f.net.beforePublish = async event => { if (event.tags.some(tag => tag[0] === 'd' && tag[1].startsWith(ONYX_VAULT_PUBLISHER_D_PREFIX))) { if (++count === 2) release(); await both; } };
    const results = await Promise.allSettled([e.takeOverPublishing(id), other.takeOverPublishing(id)]); f.net.beforePublish = undefined;
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    const loser = snapshot(e).vaults[0].publisher!.isCurrentDevice ? other : e;
    const before = f.net.published.length, member = hex32<Pubkey>(await signer(2).getPublicKey());
    await expect(loser.share(id, [member], 'read', {})).rejects.toMatchObject({ code: 'POLICY' });
    await expect(loser.revoke(id, member)).rejects.toMatchObject({ code: 'POLICY' });
    await expect(loser.reseal(id, 0n, 'lazy')).rejects.toMatchObject({ code: 'POLICY' }); expect(f.net.published).toHaveLength(before);
  });
  it('replays an uncertain revoke once and delivers regrants without rotating a second time', async () => {
    const { f, e, id } = await created(), removed = hex32<Pubkey>(await signer(2).getPublicKey()), remaining = hex32<Pubkey>(await signer(3).getPublicKey());
    await e.share(id, [removed, remaining], 'read', {}); f.net.loseHead = true;
    await expect(e.revoke(id, removed)).rejects.toMatchObject({ code: 'NETWORK' }); await e.stop();
    const restarted = await start(f), store = await f.openStore();
    const state = (await store.read('vaults', [id]))!.value; expect(state.nodeRings[state.rootNodeId].entries).toHaveLength(2); expect(state.lastOwnSeq).toBe('3');
    expect((await store.list('operations')).filter(row => row.value.kind === 'revoke')).toHaveLength(1);
    expect(state.deliveryLedger.filter(d => d.recipient === remaining)).toHaveLength(2);
    const before = f.net.published.length; await restarted.revoke(id, removed); expect(f.net.published).toHaveLength(before); store.stop();
  });
  it('drains the old session before switching account and notebook during upload', async () => {
    const { f, e, id } = await created(); await f.fs.write('/notebook/notes/a.md', 'in flight');
    let release!: () => void, entered!: () => void; const hold = new Promise<void>(resolve => { release = resolve; }), ready = new Promise<void>(resolve => { entered = resolve; });
    f.net.beforePut = async () => { entered(); await hold; };
    const syncing = e.sync(id).catch(error => error); await ready; const stopping = e.stop();
    const next = await fixture(undefined, signer(2)); await next.mkdir('/other'); const starting = e.start({ ...next.session, notebookPath: '/other' }, next.deps);
    release(); await syncing; await stopping; await starting; expect(snapshot(e).vaults).toEqual([]); expect(next.fs.files.size).toBe(0); expect(snapshot(e).lifecycle).toBe('running');
  });
  it('pauses a disappeared root instead of publishing mass deletion', async () => {
    const { f, e, id } = await created(); const count = f.net.published.length; await f.fs.remove('/notebook/notes');
    await expect(e.sync(id)).rejects.toMatchObject({ code: 'IO' }); expect(f.net.published).toHaveLength(count); expect(snapshot(e).vaults[0].enabled).toBe(false);
  });
  it('closes all adapters and callbacks on failed startup before releasing ownership', async () => {
    const { f, e } = await created(); await e.stop(); let calls = 0;
    f.net.beforeBackfill = () => { if (++calls === 1) throw new Error('inbox startup failed'); };
    const broken = new HeadlessVaultEngine(f.deps); engines.push(broken); await expect(broken.start(f.session)).rejects.toThrow();
    expect(f.net.subscribers.size).toBe(0); expect(snapshot(broken).lifecycle).toBe('stopped');
    f.net.beforeBackfill = undefined; await broken.start(f.session); expect(snapshot(broken).lifecycle).toBe('running');
  });
  it('reports failed grant deliveries and retries the exact stored envelope without a policy bump', async () => {
    const { f, e, id } = await created(), recipient = hex32<Pubkey>(await signer(2).getPublicKey()); f.net.rejectWrap = true;
    await e.share(id, [recipient], 'read', {});
    const delivery = snapshot(e).vaults[0].deliveries!.find(d => d.recipient === recipient)!;
    expect(delivery).toMatchObject({ envelopeKey: recipient, state: 'failed', relayOutcomes: [{ relay: network.writeRelays[0], status: 'rejected' }] });
    const first = f.net.published.filter(event => event.kind === 1059).slice(-1)[0]; f.net.rejectWrap = false;
    const heads = f.net.published.filter(event => event.tags.some(tag => tag[1]?.startsWith('porthome/'))).length;
    await e.share(id, [recipient], 'read', {});
    expect(f.net.published.filter(event => event.kind === 1059).slice(-1)[0]).toEqual(first);
    expect(f.net.published.filter(event => event.tags.some(tag => tag[1]?.startsWith('porthome/')))).toHaveLength(heads);
    expect(snapshot(e).vaults[0].deliveries!.find(d => d.recipient === recipient)!.state).toBe('acknowledged');
  });
  it('round-trips device-key settings, rotations and announcements through injected adapters', async () => {
    const f = await fixture(), e = await start(f), keys = e.deviceKeys;
    expect(keys.getState()).toMatchObject({ enabled: false, retainedKeyCount: 0, lastAnnouncement: null });
    await keys.setEnabled(true); await keys.useIdentityFallback(true);
    const first = await keys.generate();
    const secret = new Uint8Array(32); secret[31] = 77;
    const imported = await keys.import(Array.from(secret, b => b.toString(16).padStart(2, '0')).join(''));
    expect(imported).toBe(getPublicKey(secret));
    await keys.import(nip19.nsecEncode(secret));
    expect(keys.getState()).toMatchObject({ enabled: true, allowIdentityFallback: true, retainedKeyCount: 2,
      current: { pubkey: imported, announced: false }, retained: [first] });
    expect([...f.net.subscribers].some(s => s.filters.some(filter =>
      filter['#p']?.includes(first) && filter['#p']?.includes(imported) && filter['#p']?.includes(f.pubkey)))).toBe(true);
    let pendingRecorded = false;
    f.net.beforePublish = async event => {
      if (event.kind !== 10044) return;
      const store = await f.openStore();
      try {
        const config = (await store.read('accounts', []))!.value.config.deviceKeys;
        expect(config).toMatchObject({ signedAnnouncement: { id: event.id }, lastAnnouncement: { state: 'pending', eventId: event.id } });
        pendingRecorded = true;
      } finally { store.stop(); }
    };
    await keys.announce();
    expect(pendingRecorded).toBe(true);
    const event = f.net.published.find(event => event.kind === 10044)!;
    expect(verifyEvent(event)).toBe(true);
    expect(event).toMatchObject({ pubkey: f.pubkey, tags: [['n', imported]], content: '', created_at: f.deps.clock!() });
    expect(keys.getState()).toMatchObject({ announcedPubkey: imported, current: { announced: true },
      lastAnnouncement: { eventId: event.id, pubkey: imported, state: 'acknowledged', relayOutcomes: [{ relay: network.writeRelays[0], status: 'accepted' }] } });
    expect(Object.isFrozen(keys.getState())).toBe(true);
    expect(JSON.stringify(snapshot(e))).not.toContain(Array.from(secret, b => b.toString(16).padStart(2, '0')).join(''));
    expect(JSON.stringify(snapshot(e))).not.toContain('secretKey');
    const savedState = keys.getState();
    await e.stop(); const next = await start(f);
    expect(next.deviceKeys.getState()).toEqual(savedState);
    expect(next.deviceKeys.getState()).toMatchObject({ enabled: true, allowIdentityFallback: true, retainedKeyCount: 2, retained: [first],
      announcedPubkey: imported, lastAnnouncement: { state: 'acknowledged', eventId: event.id } });
    await next.deviceKeys.setEnabled(false); await next.deviceKeys.useIdentityFallback(false);
    expect(next.deviceKeys.getState()).toMatchObject({ enabled: false, allowIdentityFallback: false, retainedKeyCount: 2 });
    await next.stop(); const again = await start(f);
    expect(again.deviceKeys.getState()).toMatchObject({ enabled: false, allowIdentityFallback: false, retainedKeyCount: 2 });
  });

  it('orders rapid rotations after the previous announcement and retains the old decryptor', async () => {
    const f = await fixture(), e = await start(f);
    const first = await e.deviceKeys.generate(); await e.deviceKeys.announce();
    const second = await e.deviceKeys.generate(); await e.deviceKeys.announce();
    const announcements = f.net.published.filter(event => event.kind === 10044);
    expect(announcements[1].created_at).toBeGreaterThan(announcements[0].created_at);
    await e.stop(); const next = await start(f);
    expect(next.deviceKeys.getState()).toMatchObject({ announcedPubkey: second, retained: [first], retainedKeyCount: 2 });
  });

  it('records announcement refusal without claiming it was announced or silently falling back', async () => {
    const net = new ScriptedNetwork(), relayFactory = net.relayFactory;
    net.relayFactory = endpoints => {
      const relay = relayFactory(endpoints);
      return { ...relay, publish: async event => event.kind === 10044 ? {
        event, durable: false, degraded: true, outcomes: endpoints.map(relay => ({ relay, status: 'rejected' as const, reason: 'denied' })),
      } : relay.publish(event) };
    };
    const f = await fixture(net), e = await start(f); await e.deviceKeys.generate(); await e.deviceKeys.useIdentityFallback(true);
    await expect(e.deviceKeys.announce()).rejects.toMatchObject({ code: 'NETWORK' });
    expect(e.deviceKeys.getState()).toMatchObject({ announcedPubkey: null, current: { announced: false },
      lastAnnouncement: { state: 'failed', relayOutcomes: [{ status: 'rejected' }] } });
    expect(f.net.published).toHaveLength(0);
    await e.stop(); const next = await start(f);
    expect(next.deviceKeys.getState()).toMatchObject({ lastAnnouncement: { state: 'failed' }, announcedPubkey: null });
  });

  it('rejects invalid imports without changing retained keys or leaking input', async () => {
    const f = await fixture(), e = await start(f), before = e.deviceKeys.getState();
    for (const secret of ['private secret input', '0'.repeat(64), 'f'.repeat(64), 'nsec1invalid']) {
      await expect(e.deviceKeys.import(secret)).rejects.toMatchObject({ code: 'ARG' });
    }
    expect(e.deviceKeys.getState()).toEqual(before);
    expect(JSON.stringify(snapshot(e))).not.toContain('private secret input');
    await expect(e.deviceKeys.announce()).rejects.toMatchObject({ code: 'INCOMPLETE' });
    await e.stop(); await expect(e.deviceKeys.generate()).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('populates the key-free device-key projection from encrypted account state and a verified announcement', async () => {
    const f = await fixture(), key = new Uint8Array(32); key[31] = 99; const store = await f.openStore();
    const pubkey = await retainDeviceKey(store, key), account = (await store.read('accounts', []))!;
    await store.put('accounts', [], { ...account.value, config: { deviceKeys: { enabled: true, allowIdentityFallback: false } } }, account.revision); store.stop();
    const announcement = await buildDeviceAnnouncement(f.session.signer, pubkey); f.net.events.set(announcement.id, announcement);
    const e = await start(f); expect(snapshot(e).deviceKeys).toMatchObject({ enabled: true, announcedPubkey: pubkey, retainedKeyCount: 1, current: { pubkey, announced: true } });
    expect(JSON.stringify(snapshot(e))).not.toContain(Array.from(key, b => b.toString(16).padStart(2, '0')).join(''));
  });
  it('keeps oversized tracked files out of new capture without turning them into deletions', async () => {
    const { f, e, id } = await created(), original = f.fs.stats.bind(f.fs);
    vi.spyOn(f.fs, 'stats').mockImplementation(async path => path.endsWith('/a.md') ? { size: 128 * 1024 * 1024 + 1, created: 0, modified: 0 } : original(path));
    await f.fs.write('/notebook/notes/b.md', 'new'); await e.sync(id);
    expect(snapshot(e).vaults[0].fileErrors).toMatchObject([{ path: 'a.md', error: { code: 'TOO_LARGE' } }]);
    const store = await f.openStore(); expect((await store.read('vaults', [id]))!.value.baseline['a.md'].byteHash).toBe(hashAddress(encodeUtf8('initial'))); store.stop();
  });
  it('the Solid bridge subscribes once, replaces snapshots, and cleans up', () => {
    const engine = new HeadlessVaultEngine(), state = snapshot(engine); let released = 0;
    createRoot(dispose => {
      const value = useVaultEngine({ subscribe: listener => { listener(state); return () => { released++; }; } });
      expect(value()).toBe(state); dispose();
    });
    expect(released).toBe(1); expect(Object.isFrozen(state.vaults)).toBe(true);
  });
  it('journals an uncertain revoke ledger and retries the identical event without rotating again', async () => {
    const { f, e, id } = await created(), removed = hex32<Pubkey>(await signer(2).getPublicKey());
    await e.share(id, [removed], 'read', {});
    let fail = true;
    f.net.beforePublish = event => {
      if (fail && event.tags.some(t => t[1] === historyDTag(id))) {
        fail = false; f.net.events.set(event.id, structuredClone(event)); throw new VaultError('NETWORK');
      }
    };
    await expect(e.revoke(id, removed)).rejects.toMatchObject({ code: 'NETWORK' });
    const check = await f.openStore(), pending = (await check.pendingOperations()).find(op => op.kind === 'revoke')!;
    expect(pending.signedEpochLedgerEvent).toBeDefined();
    expect(pending.relayOutcomes.epochLedgerAcknowledged).toBe(false);
    expect(pending.signedEvent).toBeDefined();
    const wrapsBeforeRetry = f.net.published.filter(e => e.kind === 1059).length; check.stop();
    await e.stop(); const next = await start(f); await next.sync(id);
    const final = await f.openStore(), operation = (await final.read('operations', [id, pending.operationId]))!.value;
    const state = (await final.read('vaults', [id]))!.value; final.stop();
    expect(operation.stage).toBe('committed'); expect(operation.signedEpochLedgerEvent?.id).toBe(pending.signedEpochLedgerEvent?.id);
    expect(state.epochLedgerEvent?.id).toBe(pending.signedEpochLedgerEvent?.id);
    expect(state.nodeRings[state.rootNodeId].entries.map(e => e.epoch)).toEqual(['1', '2']);
    const ledgers = f.net.published.filter(e => e.tags.some(t => t[1] === historyDTag(id)));
    expect(ledgers[ledgers.length - 1].id).toBe(pending.signedEpochLedgerEvent?.id);
    expect(f.net.published.filter(e => e.kind === 1059).length).toBe(wrapsBeforeRetry + 1);
  });
  it('requires explicit trust before any invitation endpoint request', async () => {
    const { f, e, id } = await created(); const member = await fixture(f.net, signer(2)); await e.share(id, [member.pubkey], 'read', {}); const m = await start(member); await m.refreshInbox();
    const invite = snapshot(m).invitations[0];
    expect(invite.endpointHints).toEqual(network);
    expect(Object.isFrozen(invite.endpointHints?.readRelays)).toBe(true);
    let reads = 0; f.net.beforeBackfill = () => { reads++; };
    await expect(m.accept(invite.invitationId, { trustConfirmed: false, endpointsConfirmed: true, network } as unknown as Parameters<typeof m.accept>[1])).rejects.toMatchObject({ code: 'POLICY' }); expect(reads).toBe(0);
  });
  it.each([
    { missing: false, historyAvailable: true },
    { missing: true, historyAvailable: true },
    { missing: false, historyAvailable: false },
  ])('fresh regrant with authenticated history=$historyAvailable (missing retained root=$missing)', async ({ missing, historyAvailable }) => {
    const w = world(), old = await nestedTree(w, true);
    // A valid seq-0 checkpoint has a newer timestamp but no overridden child.
    // The seq-1 outgoing checkpoint must win despite its lower written_at.
    const earliest = makeRecord(w, { seq: 0n, entries: [], writtenAt: 1000n });
    const rotated = revokeTree(old.tree, old.head, w.pub[0], w.pub[1], 1800000000n, () => cBytes(0x77));
    const intermediate = await sealTree(rotated, w.io);
    const intermediateHead = newOwnerHead(intermediate.tree, old.head, w.pub[0], intermediate.rootManifest, 1800000000n);
    const rotatedAgain = revokeTree(intermediate.tree, intermediateHead, w.pub[0], w.pub[2], 1800000001n, () => cBytes(0x78));
    const sealed = await sealTree(rotatedAgain, w.io);
    const head = newOwnerHead(sealed.tree, intermediateHead, w.pub[0], sealed.rootManifest, 1800000001n);
    expect(head.parents.map(p => p.rootManifest)).not.toContain(old.rootManifest);
    const event = signHead(w, head, 0, sealed.tree.nodes[0].ring.entries[2].nodeKey);
    const net = new ScriptedNetwork(); for (const [a, bytes] of w.io.blobs) net.objects.set(a, bytes); net.events.set(event.id, event);
    if (missing) net.objects.delete(old.rootManifest);
    const owner = signer(1, w.secrets[0]), member = await fixture(net, signer(3, w.secrets[2]));
    const grant = { ...w.grant, cap: 'read' as const, ring: sealed.tree.nodes[0].ring, rootManifest: sealed.rootManifest, issuedAt: 1800000000n, hints: { relays: network.readRelays, blossom: network.readBlossom } };
    const wrap = await buildGrantWrap(grant, owner, member.pubkey); net.events.set(wrap.wrap.id, wrap.wrap);
    // A genuinely fresh member has no local historical records, grant or rings.
    // Only the replaceable current head and owner ledger survive on this relay.
    if (historyAvailable) {
      const initialLedger = ledgerWithHeads(w.vaultId, undefined, [earliest.head]);
      const ledger = ledgerWithHeads(w.vaultId, initialLedger, [earliest.head, old.head, intermediateHead, head]);
      expect(ledger.epochs[0].rootManifest).toBe(old.rootManifest);
      const event = await owner.signEvent(buildEpochLedgerEvent(ledger, grant.ring, w.pub[0], head.writtenAt));
      net.events.set(event.id, event);
    }
    const e = await start(member); await e.refreshInbox(); const invite = snapshot(e).invitations[0];
    const accepted = e.accept(invite.invitationId, { relativePath: 'accepted', trustConfirmed: true, endpointsConfirmed: true, network });
    if (missing || !historyAvailable) {
      await expect(accepted).rejects.toMatchObject({ code: 'EPOCH' }); expect(member.fs.files.size).toBe(0);
      if (!historyAvailable) expect(snapshot(e).lastError?.message).toContain('History unavailable from this owner');
    }
    else {
      await accepted; expect([...await member.fs.readBinary('/notebook/accepted/directory/child-file')]).toEqual([99, 104, 105, 108, 100, 0, 0]);
      const store = await member.openStore(); const state = (await store.read('vaults', [w.vaultId]))!.value; expect(state.nodeRings[old.tree.nodes[1].node.nodeId].entries.map(e => e.epoch)).toEqual(expect.arrayContaining(['1', '3'])); store.stop();
    }
  });
  it('blocks revoke before rotation/publication when a remaining regrant exceeds the nested plaintext limit', async () => {
    const f = await fixture(); await f.mkdir('/notebook/v'); const store = await f.openStore(), account = (await store.read('accounts', []))!.value;
    const vaultId = hex32<VaultId>('aa'.repeat(32)), rootNodeId = hex32<NodeId>('bb'.repeat(32));
    const ring = { entries: Array.from({ length: 450 }, (_, i) => ({ epoch: BigInt(i + 1), nodeKey: bytes32(hexToBytes(hashAddress(encodeUtf8(`key:${i}`)))) })) };
    const removed = hex32<Pubkey>(await signer(2).getPublicKey()), remaining = hex32<Pubkey>(await signer(3).getPublicKey());
    const tree = captureTree({ nodeId: rootNodeId, epoch: 450n, entries: [], vault: { vaultId, owner: f.pubkey, writers: [f.pubkey], readers: [removed, remaining], grantsRev: 1n } }, ring);
    const sealed = await sealTree(tree, { put: (bytes, address) => { f.net.objects.set(address, bytes); } });
    const head = newOwnerHead(sealed.tree, null, f.pubkey, sealed.rootManifest, 1800000000n);
    const event = await f.session.signer.signEvent(buildHeadEvent(head, ring.entries[449].nodeKey, f.pubkey)); f.net.events.set(event.id, event);
    const designation = await f.session.signer.signEvent({ kind: ONYX_VAULT_PUBLISHER_KIND, tags: [['d', ONYX_VAULT_PUBLISHER_D_PREFIX + vaultId]], created_at: 1800000000,
      content: await f.session.signer.nip44!.encrypt(f.pubkey, JSON.stringify({ v: 1, vault_id: vaultId, device_id: account.deviceId, device_label: '', since: 1800000000 })) }); f.net.events.set(designation.id, designation);
    const grant: VaultGrant = { vaultId, nodeId: rootNodeId, owner: f.pubkey, ring, cap: 'write', rootManifest: sealed.rootManifest, issuedAt: 1800000000n, hints: { relays: network.readRelays, blossom: network.readBlossom } };
    expect(grantWrapPlaintextSizes(grant).sealBytes).toBeGreaterThan(65535);
    const vault: StoredVault = { schemaVersion: 1, protocolId: PROTOCOL_ID, vaultId, rootNodeId, owner: f.pubkey, mount: { notebookPath: '/notebook', relativePath: 'v' }, label: 'v',
      publisher: { deviceId: account.deviceId, deviceLabel: '', since: '1800000000' }, publisherEvent: designation, attachedAt: '1800000000', grant: toStorage(grant), nodeRings: { [rootNodeId]: toStorage(ring) }, network, enabled: true,
      lastOwnSeq: '0', lastOwnWrittenAt: '0', ownerCheckpointId: null, materializedViewId: null, baseline: {}, pendingCandidateId: null, retainedRoots: [sealed.rootManifest], deliveryLedger: [], resealProgress: null };
    await store.createVault(vault); store.stop(); const e = await start(f);
    await expect(e.revoke(vaultId, removed)).rejects.toMatchObject({ code: 'TOO_LARGE' });
    expect(f.net.puts).toEqual([]); expect(f.net.published).toEqual([]); expect(snapshot(e).vaults[0].regrantHeadroomBytes).toBeLessThanOrEqual(0);
    const check = await f.openStore(); expect((await check.read('vaults', [vaultId]))!.value.nodeRings[rootNodeId].entries).toHaveLength(450);
    expect((await check.list('operations')).some(op => op.value.kind === 'revoke')).toBe(false); check.stop();
  });
  it('refuses an oversized proposed ledger before any revoke publication even when regrants fit', async () => {
    const f = await fixture(); await f.mkdir('/notebook/v'); const store = await f.openStore(), account = (await store.read('accounts', []))!.value;
    const vaultId = hex32<VaultId>('aa'.repeat(32)), rootNodeId = hex32<NodeId>('bb'.repeat(32));
    const ring = { entries: Array.from({ length: 323 }, (_, i) => ({ epoch: BigInt(i + 1), nodeKey: bytes32(hexToBytes(hashAddress(encodeUtf8(`ledger-key:${i}`)))) })) };
    const removed = hex32<Pubkey>(await signer(2).getPublicKey());
    const tree = captureTree({ nodeId: rootNodeId, epoch: 323n, entries: [], vault: { vaultId, owner: f.pubkey, writers: [f.pubkey], readers: [removed], grantsRev: 1n } }, ring);
    const sealed = await sealTree(tree, { put: (bytes, address) => { f.net.objects.set(address, bytes); } });
    const head = newOwnerHead(sealed.tree, null, f.pubkey, sealed.rootManifest, 1800000000n);
    const event = await f.session.signer.signEvent(buildHeadEvent(head, ring.entries[322].nodeKey, f.pubkey)); f.net.events.set(event.id, event);
    const ledger = { v: 1 as const, vaultId, epochs: ring.entries.map((key, i) => ({ epoch: key.epoch,
      rootManifest: i === 322 ? sealed.rootManifest : hashAddress(encodeUtf8(`ledger-root:${i}`)),
      keyOverride: i === 0 ? null : Array.from(key.nodeKey, b => b.toString(16).padStart(2, '0')).join(''), writtenAt: 1800000000n })) };
    const ledgerEvent = await f.session.signer.signEvent(buildEpochLedgerEvent(ledger, ring, f.pubkey, head.writtenAt)); f.net.events.set(ledgerEvent.id, ledgerEvent);
    const designation = await f.session.signer.signEvent({ kind: ONYX_VAULT_PUBLISHER_KIND, tags: [['d', ONYX_VAULT_PUBLISHER_D_PREFIX + vaultId]], created_at: 1800000000,
      content: await f.session.signer.nip44!.encrypt(f.pubkey, JSON.stringify({ v: 1, vault_id: vaultId, device_id: account.deviceId, device_label: '', since: 1800000000 })) }); f.net.events.set(designation.id, designation);
    const grant: VaultGrant = { vaultId, nodeId: rootNodeId, owner: f.pubkey, ring, cap: 'write', rootManifest: sealed.rootManifest, issuedAt: 1800000000n, hints: { relays: network.readRelays, blossom: network.readBlossom } };
    const rotated = revokeTree(sealed.tree, head, f.pubkey, removed, 1800000001n, () => cBytes(0x77));
    expect(grantWrapPlaintextSizes({ ...grant, ring: rotated.nodes[0].ring }).sealBytes).toBeLessThan(65535);
    const vault: StoredVault = { schemaVersion: 1, protocolId: PROTOCOL_ID, vaultId, rootNodeId, owner: f.pubkey, mount: { notebookPath: '/notebook', relativePath: 'v' }, label: 'v',
      publisher: { deviceId: account.deviceId, deviceLabel: '', since: '1800000000' }, publisherEvent: designation, epochLedgerEvent: ledgerEvent, attachedAt: '1800000000', grant: toStorage(grant), nodeRings: { [rootNodeId]: toStorage(ring) }, network, enabled: true,
      lastOwnSeq: '0', lastOwnWrittenAt: '0', ownerCheckpointId: null, materializedViewId: null, baseline: {}, pendingCandidateId: null, retainedRoots: [], deliveryLedger: [], resealProgress: null };
    await store.createVault(vault); store.stop(); const e = await start(f);
    await expect(e.revoke(vaultId, removed)).rejects.toMatchObject({ code: 'TOO_LARGE', message: expect.stringContaining('Create a new vault') });
    expect(f.net.puts).toEqual([]); expect(f.net.published).toEqual([]);
    const check = await f.openStore(), state = (await check.read('vaults', [vaultId]))!.value;
    expect(state.nodeRings[rootNodeId].entries).toHaveLength(323); expect(state.epochLedgerEvent?.id).toBe(ledgerEvent.id);
    expect((await check.list('operations')).some(op => op.value.kind === 'revoke')).toBe(false); check.stop();
  });
  it('revokes once, regrants remaining identities, and bounds lazy re-seal', async () => {
    const { f, e, id } = await created(); const member = hex32<Pubkey>(await signer(2).getPublicKey()), remaining = hex32<Pubkey>(await signer(3).getPublicKey());
    await e.share(id, [member, remaining], 'read', {}); await e.revoke(id, member);
    const store = await f.openStore(); const state = (await store.read('vaults', [id]))!.value; expect(state.nodeRings[state.rootNodeId].entries.map(e => e.epoch)).toEqual(['1', '2']);
    const deliveries = state.deliveryLedger.filter(d => d.recipient === remaining); expect(deliveries).toHaveLength(2);
    const ledgers = f.net.published.filter(event => event.tags.some(t => t[0] === 'd' && t[1] === historyDTag(id)));
    expect(ledgers).toHaveLength(2);
    const ledger = openEpochLedgerEvent(ledgers[1], id, f.pubkey, hydrateRing(state.nodeRings[state.rootNodeId]));
    expect(ledger.epochs.map(e => e.epoch)).toEqual([1n, 2n]);
    expect(ledger.epochs[0].writtenAt).toBe(1800000001n); // latest policy checkpoint, not the creation root
    const heads = f.net.published.filter(event => event.tags.some(t => t[1]?.startsWith('porthome/'))), latestHead = heads[heads.length - 1];
    expect(f.net.published.indexOf(latestHead)).toBeLessThan(f.net.published.indexOf(ledgers[1])); store.stop();
    expect(snapshot(e).vaults[0].resealRemainingBytes).toBe(122n);
    expect(state.resealTotalBytes).toBe('122');
    expect(snapshot(e).vaults[0].resealTotalBytes).toBe(122n);
    expect(snapshot(e).vaults[0].members).toContainEqual({ pubkey: remaining, role: 'reader', informational: true });
    const before = f.net.puts.length; await e.reseal(id, 0n, 'lazy'); expect(f.net.puts).toHaveLength(before);
    await expect(e.reseal(id, 0n, 'eager')).rejects.toMatchObject({ code: 'BUDGET' });
    await e.reseal(id, 1024n, 'lazy');
    const check = await f.openStore(); const after = (await check.read('vaults', [id]))!.value; expect(after.lastOwnSeq).toBe('4');
    expect(after.resealTotalBytes).toBe('122'); check.stop();
    await e.stop(); const restarted = await start(f);
    expect(snapshot(restarted).vaults[0]).toMatchObject({ resealRemainingBytes: 0n, resealTotalBytes: 122n });
    await restarted.revoke(id, remaining);
    expect(snapshot(restarted).vaults[0]).toMatchObject({ resealRemainingBytes: 122n, resealTotalBytes: 122n });
  });
  it.each(['prepared', 'awaiting-ack'] as const)('revoke invalidates a %s reseal without republishing it or reusing its allocation', async phase => {
    const { f, e, id } = await created();
    const first = hex32<Pubkey>(await signer(2).getPublicKey()), second = hex32<Pubkey>(await signer(3).getPublicKey());
    await e.share(id, [first, second], 'read', {}); await e.revoke(id, first);
    if (phase === 'prepared') f.net.failPut = true; else f.net.loseHead = true;
    await e.reseal(id, 1024n, 'lazy').catch(() => {}); f.net.failPut = false;
    const check = await f.openStore(); const pending = (await check.pendingOperations()).find(op => op.kind === 'reseal')!;
    expect(pending).toBeDefined();
    const candidate = pending.candidate.head as { seq: string; writtenAt: string };
    const attempts = pending.signedEvent ? f.net.published.filter(event => event.id === pending.signedEvent!.id).length : 0;
    // Simulate late relay delivery: startup/backfill cannot see the uncertain head.
    if (pending.signedEvent) f.net.events.delete(pending.signedEvent.id);
    check.stop();
    await e.revoke(id, second);
    const after = await f.openStore(); const invalidated = (await after.read('operations', [id, pending.operationId]))!.value;
    expect(invalidated).toMatchObject({ stage: 'committed', relayOutcomes: { invalidatedByRevoke: true } });
    const state = (await after.read('vaults', [id]))!.value;
    expect(BigInt(state.lastOwnSeq)).toBeGreaterThan(BigInt(candidate.seq));
    expect(BigInt(state.lastOwnWrittenAt)).toBeGreaterThan(BigInt(candidate.writtenAt));
    expect(state.nodeRings[state.rootNodeId].entries.map(entry => entry.epoch)).toEqual(['1', '2', '3']);
    if (pending.signedEvent) expect(f.net.published.filter(event => event.id === pending.signedEvent!.id)).toHaveLength(attempts);
    after.stop();
  });

  it('round-trips a 50 MB attachment through the real emitted worker without blocking the event loop', async () => {
    const bundle = await realWorkerBundle();
    const owner = await fixture(), member = await fixture(owner.net, signer(2));
    const ownerWorker = await bundle.create(), memberWorker = await bundle.create();
    const e = new HeadlessVaultEngine({ ...owner.deps, workerFactory: () => ownerWorker });
    const m = new HeadlessVaultEngine({ ...member.deps, workerFactory: () => memberWorker }); engines.push(e, m);
    let heartbeat: ReturnType<typeof setImmediate> | undefined, ticks = 0;
    const beat = () => { ticks++; heartbeat = setImmediate(beat); };
    try {
      await owner.mkdir('/notebook/large'); const bytes = Uint8Array.from({ length: 50_000_000 }, (_, i) => (i * 31 + (i >>> 10)) & 255);
      await owner.fs.writeBinary('/notebook/large/attachment.bin', bytes);
      await e.start(owner.session); await m.start(member.session); beat();
      const id = await e.create('large', {}); await e.share(id, [member.pubkey], 'read', {}); await m.refreshInbox();
      const invite = snapshot(m).invitations[0]; await m.accept(invite.invitationId, { relativePath: 'large', trustConfirmed: true, endpointsConfirmed: true, network });
      const roundTrip = await member.fs.readBinary('/notebook/large/attachment.bin'); expect(roundTrip.length).toBe(50_000_000); expect(hashAddress(roundTrip)).toBe(hashAddress(bytes)); expect(ticks).toBeGreaterThan(10);
    } finally { if (heartbeat) clearImmediate(heartbeat); await e.stop(); await m.stop(); await bundle.close(); }
  }, 120000);
  it('exports an encrypted passphrase-protected recovery package', async () => {
    const { e, id } = await created(); const recovery = await e.exportRecovery(id); expect(recovery.ncryptsec.startsWith('ncryptsec1')).toBe(true); expect(recovery.payload.ciphertext).not.toContain('nodeKey');
  }, 30000);
  it('offers a generated passphrase, rejects weak input and exports a vault-scoped package at a calibrated cost (SV-34)', async () => {
    const f = await fixture(); await f.mkdir('/notebook/v');
    const requests: VaultRecoveryPassphraseRequest[] = []; let answer: (request: VaultRecoveryPassphraseRequest) => string | null = request => request.suggested;
    f.deps = { ...f.deps, requestRecoveryPassphrase: async request => { requests.push(request!); return answer(request!); } };
    const e = await start(f), id = await e.create('v', {});
    const pkg = await e.exportRecovery(id);
    expect(requests[0]).toMatchObject({ minimumLength: 12, notes: expect.arrayContaining([expect.stringContaining('offline'), expect.stringContaining('device-key history')]) });
    expect([17, 18]).toContain(requests[0].logn); expect(requests[0].suggested).toMatch(/^[a-z2-9]{5}(-[a-z2-9]{5}){5}$/);
    expect(parseNcryptsec(pkg.ncryptsec).logn).toBe(requests[0].logn);
    const opened = await openRecovery(pkg, requests[0].suggested, { vaultId: id });
    expect(Object.keys(opened).sort()).toEqual(['grant', 'network', 'nodeRings', 'protocolId', 'schemaVersion', 'vaultId']);
    await expect(openRecovery(pkg, requests[0].suggested, { vaultId: 'c'.repeat(64) as VaultId })).rejects.toMatchObject({ code: 'POLICY' });
    answer = () => 'password1234'; await expect(e.exportRecovery(id)).rejects.toMatchObject({ code: 'ARG', message: expect.stringContaining('too weak') });
    answer = () => null; await expect(e.exportRecovery(id)).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(requests).toHaveLength(3); expect(JSON.stringify(snapshot(e), (_k, v) => typeof v === 'bigint' ? String(v) : v)).not.toContain(requests[0].suggested);
  }, 60000);
  it('gates device delivery on an approved pinned fingerprint and refuses withheld or rolled-back announcements (SV-33)', async () => {
    const { f, e, id } = await created(), member = await fixture(f.net, signer(2)), m = await start(member);
    const keyA = new Uint8Array(32); keyA[31] = 41; const keyB = new Uint8Array(32); keyB[31] = 42;
    const deviceA = getPublicKey(keyA) as Pubkey, deviceB = getPublicKey(keyB) as Pubkey;
    const retired = await buildDeviceAnnouncement(member.session.signer, deviceB, () => 1700000000);
    const current = await buildDeviceAnnouncement(member.session.signer, deviceA, () => 1700000100);
    f.net.events.set(current.id, current);
    await e.deviceKeys.setEnabled(true);
    const delivery = () => snapshot(e).vaults[0].deliveries!.find(d => d.recipient === member.pubkey)!;
    // 1. First contact: the announcement is pinned but unapproved, so the grant goes to the identity key with a notice.
    await e.share(id, [member.pubkey], 'read', { enabled: true });
    expect(delivery()).toMatchObject({ envelopeKey: member.pubkey, state: 'acknowledged', notice: 'unapproved', evidence: 'fresh' });
    expect(snapshot(e).deviceKeys!.recipients).toEqual([{ identity: member.pubkey, status: 'unapproved', observed: { eventId: current.id, createdAt: 1700000100, encryptionKey: deviceA }, approvedKey: null, observedAt: f.deps.clock!() }]);
    // 2. Approval is bound to the observed fingerprint.
    await expect(e.deviceKeys.approveRecipientKey(member.pubkey, deviceB)).rejects.toMatchObject({ code: 'ARG' });
    expect(await e.deviceKeys.approveRecipientKey(member.pubkey, deviceA)).toMatchObject({ status: 'approved', approvedKey: deviceA });
    // 3. The relay now withholds the current announcement and serves only the retired one: the pin wins.
    f.net.events.delete(current.id); f.net.events.set(retired.id, retired);
    await e.share(id, [member.pubkey], 'write', { enabled: true });
    expect(delivery()).toMatchObject({ envelopeKey: deviceA, evidence: 'stale' }); expect(delivery().notice).toBeUndefined();
    expect(snapshot(e).deviceKeys!.recipients![0]).toMatchObject({ status: 'approved', observed: { eventId: current.id } });
    // 4. The relay serves nothing: still the pinned key, and the evidence says so.
    f.net.events.delete(retired.id);
    await e.share(id, [member.pubkey], 'read', { enabled: true });
    expect(delivery()).toMatchObject({ envelopeKey: deviceA, evidence: 'none' });
    // 5. A newer rotation is a decision, never an automatic re-key: fail closed, or identity with a notice when allowed.
    const rotated = await buildDeviceAnnouncement(member.session.signer, deviceB, () => 1700000200); f.net.events.set(rotated.id, rotated);
    await e.share(id, [member.pubkey], 'write', { enabled: true });
    expect(snapshot(e).vaults[0].lastError).toMatchObject({ code: 'POLICY', message: expect.stringContaining('fingerprint') });
    expect(delivery()).toMatchObject({ envelopeKey: null, state: 'pending' });
    expect(snapshot(e).deviceKeys!.recipients![0]).toMatchObject({ status: 'changed', approvedKey: deviceA, observed: { encryptionKey: deviceB } });
    await expect(e.share(id, [member.pubkey], 'write', { enabled: true })).rejects.toMatchObject({ code: 'POLICY' });
    await e.share(id, [member.pubkey], 'write', { enabled: true, allowIdentityFallback: true });
    expect(delivery()).toMatchObject({ envelopeKey: member.pubkey, state: 'acknowledged', notice: 'key-changed' });
    // 6. Approving the new fingerprint delivers to it; reset returns to identity delivery with the bootstrap notice.
    await e.deviceKeys.approveRecipientKey(member.pubkey, deviceB);
    await e.share(id, [member.pubkey], 'read', { enabled: true });
    expect(delivery()).toMatchObject({ envelopeKey: deviceB, evidence: 'current' });
    await e.deviceKeys.resetRecipientPin(member.pubkey); expect(snapshot(e).deviceKeys!.recipients).toEqual([]);
    await e.share(id, [member.pubkey], 'write', { enabled: true });
    expect(delivery()).toMatchObject({ envelopeKey: member.pubkey, notice: 'unapproved' });
    expect(JSON.stringify(snapshot(e), (_k, v) => typeof v === 'bigint' ? String(v) : v)).not.toContain('secretKey');
    await e.stop(); const next = await start(f);
    expect(snapshot(next).deviceKeys!.recipients![0]).toMatchObject({ status: 'unapproved', observed: { encryptionKey: deviceB }, approvedKey: null });
    await m.refreshInbox(); expect(snapshot(m).invitations.length).toBeGreaterThan(0);
  }, 60000);
});
