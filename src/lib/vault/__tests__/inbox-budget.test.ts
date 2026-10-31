import { afterEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent } from 'nostr-tools';
import { HeadlessVaultEngine } from '../engine';
import { buildGrantWrap } from '../carrier';
import { bytes32, hex32 } from '../crypto';
import { assertInboxReplayCapacity, partitionInboxReplay, TransientReplay, VAULT_INBOX_DURABLE_CAPACITY, VAULT_INBOX_MAX_TRANSIENT_IDS } from '../inbox-replay';
import { initRing } from '../ring';
import { toStorage } from '../store';
import type { Address, EventId, NodeId, Pubkey, VaultGrant, VaultId } from '../types';
import { PROTOCOL_ID, VAULT_INGRESS_MAX_QUEUED_ITEMS, VAULT_INBOX_MAX_REPLAY_IDS, VAULT_INBOX_MAX_REPLAY_BYTES } from '../protocol';
import { fixture, network, signer, snapshot } from './engine-fixtures';

const engines: HeadlessVaultEngine[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(engines.splice(0).map(engine => engine.stop())); });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(yes => { resolve = yes; }); return { promise, resolve }; };

async function start(f: Awaited<ReturnType<typeof fixture>>, refresh = true) {
  const engine = new HeadlessVaultEngine(f.deps); engines.push(engine); await engine.start(f.session); if (refresh) await engine.refreshInbox(); return engine;
}
function spam(recipient: string, index: number, content = 'not ciphertext') {
  return finalizeEvent({ kind: 1059, created_at: 1800000000, tags: [['p', recipient], ['n', String(index)]], content }, new Uint8Array(32).fill(9));
}

const maximumReplayIds = VAULT_INBOX_DURABLE_CAPACITY;
const replayIds = (count: number, offset = 0) => Array.from({ length: count }, (_, i) => (i + offset).toString(16).padStart(64, '0'));
async function seedReplay(f: Awaited<ReturnType<typeof fixture>>, count: number) {
  const store = await f.openStore(), row = (await store.read('accounts', []))!;
  await store.put('accounts', [], { ...row.value, config: { ...row.value.config, inboxSeen: replayIds(count), inboxWatermarks: { [network.readRelays[0]]: 1700000000 } } }, row.revision); store.stop();
}
async function grantFixture(f: Awaited<ReturnType<typeof fixture>>) {
  const owner = signer(2);
  const grant: VaultGrant = { vaultId: hex32<VaultId>('11'.repeat(32)), nodeId: hex32<NodeId>('22'.repeat(32)), owner: hex32<Pubkey>(await owner.getPublicKey()),
    ring: initRing(1n, bytes32(new Uint8Array(32).fill(3))), cap: 'read', rootManifest: hex32<Address>('33'.repeat(32)),
    hints: { relays: network.readRelays, blossom: network.readBlossom }, issuedAt: BigInt(f.deps.clock!()) };
  return { owner, grant };
}
/** An invitation row holding `count` durable wrap IDs: the only way to fill the durable tier. */
async function seedDecisions(f: Awaited<ReturnType<typeof fixture>>, count: number, decided = { read: true, accepted: true, dismissed: true }) {
  const { owner, grant } = await grantFixture(f), first = await buildGrantWrap(grant, owner, f.pubkey, { clock: f.deps.clock });
  const store = await f.openStore();
  const wrapIds = [...replayIds(count - 1, 1 << 20), first.wrap.id].map(id => hex32<EventId>(id));
  await store.put('invitations', [grant.vaultId, first.rumorId], { schemaVersion: 1, protocolId: PROTOCOL_ID, vaultId: grant.vaultId, rumorId: hex32<EventId>(first.rumorId),
    grant: toStorage(grant), wrapIds, ...decided });
  store.stop(); return { owner, grant, first, wrapIds };
}

describe('partitioned replay-ID budget (SV-37, SEC-G)', () => {
  it('documents the durable capacity and bounds the serialized durable array', () => {
    expect(VAULT_INBOX_DURABLE_CAPACITY).toBe(3912);
    expect(VAULT_INBOX_DURABLE_CAPACITY).toBe(Math.min(VAULT_INBOX_MAX_REPLAY_IDS, Math.floor((VAULT_INBOX_MAX_REPLAY_BYTES - 1) / 67)));
    expect(new TextEncoder().encode(JSON.stringify(replayIds(maximumReplayIds))).length).toBeLessThanOrEqual(VAULT_INBOX_MAX_REPLAY_BYTES);
    expect(() => assertInboxReplayCapacity(maximumReplayIds + 1)).toThrow(expect.objectContaining({ code: 'BUDGET' }));
  });

  it('partitions a legacy list: invitation IDs stay durable, everything else goes to the bounded transient tier', () => {
    const grants = replayIds(3, 1 << 20), legacy = [...replayIds(VAULT_INBOX_MAX_TRANSIENT_IDS + 10), grants[0], 'junk', 7];
    const { durable, transient, migrated } = partitionInboxReplay(legacy, grants);
    expect(durable).toEqual(grants); expect(migrated).toBe(true);
    expect(transient).toEqual(replayIds(VAULT_INBOX_MAX_TRANSIENT_IDS + 10).slice(-VAULT_INBOX_MAX_TRANSIENT_IDS));
    expect(partitionInboxReplay(grants, grants).migrated).toBe(false);
    expect(partitionInboxReplay(undefined, []).migrated).toBe(false);
    expect(partitionInboxReplay('not an array', grants)).toMatchObject({ durable: grants, transient: [], migrated: true });
    const lru = new TransientReplay(2); lru.add('a'); lru.add('b'); expect(lru.has('a')).toBe(true); lru.add('c');
    expect([lru.has('a'), lru.has('b'), lru.has('c')]).toEqual([true, false, true]);
  });

  it('starts an over-capacity pre-SEC-A store (every kind-1059 ID), keeps the vault listed, and migrates to grant IDs only', async () => {
    const f = await fixture(); await f.mkdir('/notebook/notes');
    const first = await start(f); const id = await first.create('notes', {}); await first.stop();
    await seedReplay(f, maximumReplayIds * 2);
    const engine = await start(f, false);
    expect(snapshot(engine)).toMatchObject({ lifecycle: 'running', inbox: { state: 'active' } });
    expect(snapshot(engine).vaults.map(v => [v.vaultId, v.authority])).toEqual([[id, 'owner']]);
    const store = await f.openStore();
    const invitationIds = (await store.list('invitations')).flatMap(row => row.value.wrapIds);
    const config = (await store.read('accounts', []))!.value.config;
    expect([...(config.inboxSeen as string[])].sort()).toEqual([...invitationIds].sort());
    expect((config.inboxWatermarks as Record<string, number>)[network.readRelays[0]]).toBeGreaterThanOrEqual(1700000000);
    // Migrated legacy IDs are still skipped without decrypting (transient tier).
    const decrypt = vi.spyOn(f.session.signer.nip44!, 'decrypt');
    f.net.emit({ ...spam(f.pubkey, 1), id: replayIds(maximumReplayIds * 2)[maximumReplayIds * 2 - 1] });
    expect(decrypt).not.toHaveBeenCalled(); store.stop();
  });

  it('never spends durable budget on terminally invalid wraps; the bounded transient tier remembers them across restart', async () => {
    const f = await fixture(); const { wrapIds } = await seedDecisions(f, maximumReplayIds - 1);
    const engine = await start(f), decrypt = vi.spyOn(f.session.signer.nip44!, 'decrypt');
    const events = Array.from({ length: 20 }, (_, i) => spam(f.pubkey, 200 + i));
    for (const event of events) f.net.events.set(event.id, event);
    await engine.refreshInbox(); expect(decrypt).toHaveBeenCalledTimes(20);
    expect(snapshot(engine)).toMatchObject({ lifecycle: 'running', inbox: { state: 'active', durableIds: maximumReplayIds - 1 } });
    for (const event of events) f.net.emit(event); expect(decrypt).toHaveBeenCalledTimes(20);
    const store = await f.openStore();
    const config = (await store.read('accounts', []))!.value.config;
    expect(config.inboxSeen).toEqual(wrapIds); expect(config.inboxRejected).toEqual(events.map(e => e.id)); await engine.stop();
    const next = await start(f); expect(decrypt).toHaveBeenCalledTimes(20);
    expect(snapshot(next).inbox).toMatchObject({ state: 'active' });
    expect((await store.read('accounts', []))!.value.config.inboxSeen).toEqual(wrapIds); store.stop();
  });

  it('a full durable tier latches an inbox notice; start, vaults and decisions are unaffected and nothing is evicted', async () => {
    const f = await fixture(); await f.mkdir('/notebook/notes');
    const first = await start(f); const id = await first.create('notes', {}); await first.stop();
    const store = await f.openStore();
    const own = (await store.list('invitations')).reduce((n, row) => n + row.value.wrapIds.length, 0);
    const { grant, first: wrap, wrapIds } = await seedDecisions(f, maximumReplayIds - own);
    const decrypt = vi.spyOn(f.session.signer.nip44!, 'decrypt'), engine = await start(f, false);
    expect(snapshot(engine)).toMatchObject({ lifecycle: 'running', condition: 'error', lastError: { code: 'BUDGET' },
      inbox: { state: 'at-capacity', durableIds: maximumReplayIds, capacity: maximumReplayIds } });
    expect(snapshot(engine).inbox!.message).toMatch(/Invitation inbox at capacity/);
    expect(snapshot(engine).vaults.map(v => v.vaultId)).toEqual([id]);
    expect(f.net.subscribers.size).toBeGreaterThan(0); // vault subscriptions only
    f.net.emit(spam(f.pubkey, 1));
    await expect(engine.refreshInbox()).rejects.toMatchObject({ code: 'BUDGET' }); expect(decrypt).not.toHaveBeenCalled();
    await engine.sync(id);
    // Repair cannot evict a grant decision: it stays at capacity.
    await engine.repairInbox(); expect(snapshot(engine).inbox).toMatchObject({ state: 'at-capacity' });
    expect((await store.read('invitations', [grant.vaultId, wrap.rumorId]))!.value).toMatchObject({ wrapIds, read: true, accepted: true, dismissed: true });
    expect(((await store.read('accounts', []))!.value.config.inboxSeen as string[])).toHaveLength(maximumReplayIds); store.stop();
  });

  it('preserves read/accepted/dismissed decisions across a rewrap that fills the durable tier and a restart', async () => {
    const f = await fixture(); const { owner, grant, first } = await seedDecisions(f, maximumReplayIds - 1);
    const engine = await start(f), decrypt = vi.spyOn(f.session.signer.nip44!, 'decrypt');
    const second = await buildGrantWrap(grant, owner, f.pubkey, { clock: f.deps.clock }); f.net.events.set(second.wrap.id, second.wrap);
    await expect(engine.refreshInbox()).rejects.toMatchObject({ code: 'BUDGET' }); expect(decrypt).toHaveBeenCalledTimes(2);
    expect(snapshot(engine).inbox).toMatchObject({ state: 'at-capacity' });
    const store = await f.openStore(), invitation = (await store.read('invitations', [grant.vaultId, first.rumorId]))!.value;
    expect(invitation).toMatchObject({ read: true, accepted: true, dismissed: true }); expect(invitation.wrapIds).toContain(second.wrap.id);
    const config = (await store.read('accounts', []))!.value.config;
    expect(config.inboxSeen).toContain(first.wrap.id); expect(config.inboxSeen).toContain(second.wrap.id);
    expect(config.inboxSeen).toHaveLength(maximumReplayIds); await engine.stop();
    const next = await start(f, false); expect(snapshot(next)).toMatchObject({ lifecycle: 'running', inbox: { state: 'at-capacity' } });
    await expect(next.refreshInbox()).rejects.toMatchObject({ code: 'BUDGET' });
    expect(decrypt).toHaveBeenCalledTimes(2); expect((await store.read('invitations', [grant.vaultId, first.rumorId]))!.value).toEqual(invitation); store.stop();
  });

  it('repairInbox resumes an inbox stopped by the ingress budget', async () => {
    const f = await fixture(), engine = await start(f);
    for (let i = 0; i <= VAULT_INGRESS_MAX_QUEUED_ITEMS; i++) { const event = spam(f.pubkey, i); f.net.events.set(event.id, event); }
    await expect(engine.refreshInbox()).rejects.toMatchObject({ code: 'BUDGET' });
    expect(snapshot(engine).inbox).toMatchObject({ state: 'stopped' }); f.net.events.clear();
    await engine.repairInbox();
    expect(snapshot(engine)).toMatchObject({ condition: 'ready', inbox: { state: 'active' } });
    expect(f.net.subscribers.size).toBeGreaterThan(0);
  });
});

describe('inbox ingress budget (SV-29)', () => {
  it.each(['items', 'bytes'] as const)('applies the shared %s budget to primary backfill before opening any retained batch', async mode => {
    const f = await fixture(), engine = await start(f), decrypt = vi.spyOn(f.session.signer.nip44!, 'decrypt');
    const count = mode === 'items' ? VAULT_INGRESS_MAX_QUEUED_ITEMS + 1 : 14;
    for (let i = 0; i < count; i++) {
      const event = spam(f.pubkey, i, mode === 'items' ? 'not ciphertext' : 'a'.repeat(85000)); f.net.events.set(event.id, event);
    }
    await expect(engine.refreshInbox()).rejects.toMatchObject({ code: 'BUDGET' });
    expect(snapshot(engine)).toMatchObject({ condition: 'error', lastError: { code: 'BUDGET' } });
    expect(decrypt).not.toHaveBeenCalled();
  });
  it.each(['items', 'bytes'] as const)('bounds queued %s while keeping grant-opening concurrency at one', async mode => {
    const f = await fixture(), engine = await start(f), entered = deferred(), release = deferred();
    const original = f.session.signer.nip44!.decrypt;
    let active = 0, maximum = 0;
    const decrypt = vi.spyOn(f.session.signer.nip44!, 'decrypt').mockImplementation(async (...args) => {
      active++; maximum = Math.max(maximum, active); entered.resolve();
      try { await release.promise; return await original(...args); } finally { active--; }
    });
    try {
      f.net.emit(spam(f.pubkey, 0)); await entered.promise;
      const count = mode === 'items' ? VAULT_INGRESS_MAX_QUEUED_ITEMS : 14;
      for (let i = 1; i <= count; i++) f.net.emit(spam(f.pubkey, i, mode === 'items' ? 'not ciphertext' : 'a'.repeat(85000)));
      expect(snapshot(engine)).toMatchObject({ condition: 'error', lastError: { code: 'BUDGET' } });
      expect(f.net.subscribers.size).toBe(0); expect(decrypt).toHaveBeenCalledTimes(1); expect(maximum).toBe(1);
      release.resolve(); f.net.events.clear();
      const store = await f.openStore(), before = (await store.read('accounts', []))!.value.config.inboxWatermarks;
      const waves = f.net.backfills.length;
      await expect(engine.refreshInbox()).rejects.toMatchObject({ code: 'BUDGET' });
      expect(f.net.backfills).toHaveLength(waves);
      expect((await store.read('accounts', []))!.value.config.inboxWatermarks).toEqual(before); store.stop();
    } finally { release.resolve(); }
  });
});
