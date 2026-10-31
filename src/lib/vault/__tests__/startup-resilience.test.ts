import { afterEach, describe, expect, it } from 'vitest';
import { wrap } from 'idb';
import { HeadlessVaultEngine } from '../engine';
import { PROTOCOL_ID } from '../protocol';
import { VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION } from '../store';
import type { VaultId } from '../types';
import { fixture, snapshot } from './engine-fixtures';

/**
 * SEC-G: a pre-existing vault must load, or be listed with a visible needs-repair
 * state and its reason. No stored-state defect may abort start() and hide them all.
 */
const engines: HeadlessVaultEngine[] = [];
afterEach(async () => { await Promise.all(engines.splice(0).map(engine => engine.stop())); });
async function start(f: Awaited<ReturnType<typeof fixture>>) {
  const engine = new HeadlessVaultEngine(f.deps); engines.push(engine); await engine.start(f.session); return engine;
}
async function twoVaults() {
  const f = await fixture(); await f.mkdir('/notebook/a'); await f.mkdir('/notebook/b');
  const engine = await start(f);
  const a = await engine.create('a', {}), b = await engine.create('b', {});
  await engine.stop(); return { f, a, b };
}
async function rawDelete(f: Awaited<ReturnType<typeof fixture>>, name: 'operations', key: string[]) {
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = f.factory.open(VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  const wrapped = wrap(db), tx = wrapped.transaction(name, 'readwrite'); await tx.store.delete(key); await tx.done; db.close();
}
/** Flips one ciphertext byte at the raw IDB boundary, as storage corruption would. */
async function corruptVaultRow(f: Awaited<ReturnType<typeof fixture>>, id: VaultId, name: 'vaults' | 'invitations' = 'vaults', rest: string[] = []) {
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = f.factory.open(VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  const wrapped = wrap(db), tx = wrapped.transaction(name, 'readwrite');
  const key = [f.pubkey, id, ...rest], row = await tx.store.get(key) as { ciphertext: ArrayBuffer };
  const bytes = new Uint8Array(row.ciphertext.slice(0)); bytes[0] ^= 1;
  await tx.store.put({ ...row, ciphertext: bytes.buffer }, key); await tx.done; db.close();
}

describe('startup never hides pre-existing vaults (SEC-G)', () => {
  it('lists an undecodable vault row as needs-repair and still loads the others', async () => {
    const { f, a, b } = await twoVaults(); await corruptVaultRow(f, b);
    const engine = await start(f), state = snapshot(engine);
    expect(state.lifecycle).toBe('running');
    expect(state.vaults.map(v => v.vaultId)).toEqual([a]);
    expect(state.unavailableVaults).toEqual([{ vaultId: b, state: 'needs-repair', error: expect.objectContaining({ code: 'STORAGE' }) }]);
    await engine.sync(a);
    // The quarantined original is retained; a restart reports it again rather than forgetting it.
    await engine.stop(); const next = await start(f);
    expect(snapshot(next).unavailableVaults?.map(v => v.vaultId)).toEqual([b]);
    const store = await f.openStore();
    expect((await store.quarantinedRecords()).filter(r => r.store === 'vaults').map(r => r.key[0])).toEqual([b]); store.stop();
  });

  it('marks a vault whose startup recovery fails with a non-network error instead of aborting start', async () => {
    const { f, a, b } = await twoVaults();
    const store = await f.openStore(), row = (await store.read('vaults', [b]))!, operationId = 'ff'.repeat(32);
    // A dangling candidate pointer (journal row lost) used to throw STORAGE out of start().
    await store.saveJournal({ schemaVersion: 1, protocolId: PROTOCOL_ID, vaultId: b, operationId, kind: 'materialize', stage: 'prepared',
      candidate: { attachOnly: true, relativePath: 'b' }, signedEvent: null, pinnedAddresses: [], pendingAddress: null, uploadOutcomes: {}, relayOutcomes: {} },
    { ...row.value, pendingCandidateId: operationId }, { vault: row.revision, operation: 0 }); store.stop();
    await rawDelete(f, 'operations', [f.pubkey, b, operationId]);
    const engine = await start(f), state = snapshot(engine);
    expect(state.lifecycle).toBe('running');
    expect(state.vaults.map(v => v.vaultId).sort()).toEqual([a, b].sort());
    expect(state.vaults.find(v => v.vaultId === b)!.lastError).toMatchObject({ code: 'STORAGE' });
    expect(state.vaults.find(v => v.vaultId === a)!.lastError).toBeNull();
  });

  it('matches the mount registry across a trailing-separator spelling of the notebook path', async () => {
    const { f, a, b } = await twoVaults();
    const engine = new HeadlessVaultEngine(f.deps); engines.push(engine);
    await engine.start({ ...f.session, notebookPath: '/notebook/' });
    expect(snapshot(engine).vaults.map(v => v.vaultId).sort()).toEqual([a, b].sort());
  });

  it('fails closed on an unreadable invitation row: vaults load, stored replay IDs stay durable, ingestion pauses', async () => {
    const { f, a, b } = await twoVaults();
    const store = await f.openStore(), invitations = await store.list('invitations');
    expect(invitations.length).toBeGreaterThan(0);
    const victim = invitations[0], account = (await store.read('accounts', []))!;
    const legacy = [...(account.value.config.inboxSeen as string[]), 'ee'.repeat(32)];
    await store.put('accounts', [], { ...account.value, config: { ...account.value.config, inboxSeen: legacy } }, account.revision); store.stop();
    await corruptVaultRow(f, victim.key[0] as VaultId, 'invitations', [victim.key[1]]);
    const engine = await start(f), state = snapshot(engine);
    expect(state.lifecycle).toBe('running');
    expect(state.vaults.map(v => v.vaultId).sort()).toEqual([a, b].sort());
    expect(state.inbox).toMatchObject({ state: 'stopped' }); expect(state.inbox!.durableIds).toBeGreaterThanOrEqual(legacy.length);
    expect(state.inbox!.message).toMatch(/could not be read/);
    const after = await f.openStore();
    expect((await after.read('accounts', []))!.value.config.inboxSeen).toEqual(legacy); after.stop();
    // Repair re-checks and stays closed while the row is still unreadable.
    await engine.repairInbox(); expect(snapshot(engine).inbox).toMatchObject({ state: 'stopped' });
  });
});
