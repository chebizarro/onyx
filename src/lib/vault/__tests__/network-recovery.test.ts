import { afterEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools';
import { HeadlessVaultEngine, hydrateRing } from '../engine';
import type { VaultEngineDeps } from '../engine-api';
import { bytes32, bytesToHex, hex32 } from '../crypto';
import { buildGrantWrap } from '../carrier';
import { buildHeadEvent, openHeadEvent } from '../head';
import { VaultError } from '../errors';
import { initRing } from '../ring';
import { mergeRelayOutcomes, VaultStore, VAULT_DATABASE_NAME } from '../store';
import type { Address, NodeId, Pubkey, VaultGrant, VaultId } from '../types';
import { fixture, network, signer, snapshot } from './engine-fixtures';

const engines: HeadlessVaultEngine[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(engines.splice(0).map(engine => engine.stop())); });
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(yes => { resolve = yes; }); return { promise, resolve }; };
async function start(f: Awaited<ReturnType<typeof fixture>>, deps = f.deps) {
  const engine = new HeadlessVaultEngine(deps); engines.push(engine); await engine.start(f.session); return engine;
}
async function invitation(f: Awaited<ReturnType<typeof fixture>>, recipient = f.pubkey, age = 0) {
  const owner = signer(2), time = f.deps.clock!() - age;
  const grant: VaultGrant = { vaultId: hex32<VaultId>('11'.repeat(32)), nodeId: hex32<NodeId>('22'.repeat(32)), owner: hex32<Pubkey>(await owner.getPublicKey()),
    ring: initRing(1n, bytes32(new Uint8Array(32).fill(3))), cap: 'read', rootManifest: hex32<Address>('33'.repeat(32)),
    hints: { relays: network.readRelays, blossom: network.readBlossom }, issuedAt: BigInt(time) };
  return buildGrantWrap(grant, owner, recipient, { clock: () => time });
}
function receipt(engine: HeadlessVaultEngine, predicate: () => boolean): Promise<void> {
  return new Promise(resolve => { let off = () => {}; off = engine.subscribe(() => { if (predicate()) { off(); resolve(); } }); });
}

describe('SV-27 review regressions', () => {
  it.each(['handover', 'conflicting-head'] as const)('fences journal recovery at live EOSE before processing a delayed %s', async mode => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a.md', 'initial');
    const engine = await start(f), id = await engine.create('Team', {}); await engine.refreshInbox();
    await f.fs.write('/notebook/Team/a.md', 'pending'); f.net.loseHead = true;
    await expect(engine.sync(id)).rejects.toMatchObject({ code: 'NETWORK' }); await engine.stop();
    const store = await f.openStore(), vault = (await store.read('vaults', [id]))!.value, pending = (await store.pendingOperations())[0];
    const ring = hydrateRing(vault.nodeRings[vault.rootNodeId]), key = ring.entries[ring.entries.length - 1];
    let newer: Event;
    if (mode === 'handover') {
      const time = vault.publisherEvent!.created_at + 1;
      newer = await f.session.signer.signEvent({ kind: 30078, created_at: time, tags: vault.publisherEvent!.tags,
        content: await f.session.signer.nip44!.encrypt(f.pubkey, JSON.stringify({ v: 1, vault_id: id, device_id: 'another-device', device_label: 'Other', since: time })) });
    } else {
      const head = openHeadEvent(pending.signedEvent!, id, ring, key.epoch);
      newer = await f.session.signer.signEvent(buildHeadEvent({ ...head, writtenAt: head.writtenAt + 1n }, key.nodeKey, f.pubkey));
    }
    const ready = deferred(), eoses: (() => void)[] = [], buffered: (() => void)[] = [];
    let blocked = true;
    const relayFactory: NonNullable<VaultEngineDeps['relayFactory']> = (endpoints, options) => {
      const relay = f.net.relayFactory(endpoints, options);
      return { ...relay, subscribe: (filters, handlers) => relay.subscribe(filters, { ...handlers,
        onevent: (event, url) => { if (blocked) buffered.push(() => handlers.onevent(event, url)); else handlers.onevent(event, url); },
        oneose: url => {
          if (!filters.some(filter => filter['#d'])) { handlers.oneose?.(url); return; }
          if (blocked) { eoses.push(() => handlers.oneose?.(url)); if (eoses.length === 3) ready.resolve(); }
          else handlers.oneose?.(url);
        },
      }) };
    };
    const before = f.net.published.length;
    f.net.beforePublish = () => { expect(blocked, 'EVENT before authority EOSE').toBe(false); };
    const next = new HeadlessVaultEngine({ ...f.deps, relayFactory }); engines.push(next); const starting = next.start(f.session);
    await ready.promise; f.net.emit(newer); expect(f.net.published).toHaveLength(before);
    blocked = false; buffered.splice(0).forEach(deliver => deliver()); eoses.splice(0).forEach(eose => eose()); await starting;
    expect(f.net.published).toHaveLength(before);
    const recovered = (await store.read('operations', [id, pending.operationId]))!.value;
    expect(recovered.stage).toBe('committed'); expect(recovered.uploadOutcomes.localOnly).toBe(true);
    expect(recovered.candidate).toEqual(pending.candidate); expect(recovered.signedEvent).toEqual(pending.signedEvent);
    expect((await store.read('vaults', [id]))!.value.localCandidate).toBeDefined(); store.stop();
  });

  it('retains a still-probing configured write replica and confirms every object there before the head', async () => {
    const f = await fixture(), slow = 'https://slow.example.com/', release = deferred(), entered = deferred();
    await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a.md', 'initial');
    const defaults = { ...network, readBlossom: [...network.readBlossom, slow], writeBlossom: [...network.writeBlossom, slow] };
    const slowObjects = new Set<string>(), puts: { endpoint: string; address: string }[] = [];
    const blossomFactory: NonNullable<VaultEngineDeps['blossomFactory']> = (endpoint, options) => {
      const client = f.net.blossomFactory(endpoint, options);
      return { ...client, head: async (address, signal) => {
        if (endpoint === slow) {
          if (address === '0'.repeat(64)) { entered.resolve(); await release.promise; }
          return { exists: slowObjects.has(address) };
        }
        return client.head(address, signal);
      }, put: async (...args) => { const result = await client.put(...args); if (endpoint === slow) slowObjects.add(args[1]); puts.push({ endpoint, address: args[1] }); return result; } };
    };
    const engine = await start({ ...f, session: { ...f.session, networkDefaults: defaults } }, { ...f.deps, blossomFactory });
    await entered.promise; expect(snapshot(engine).networkDefaults?.writeBlossom).toContain(slow);
    f.net.beforePublish = event => { if (event.tags.some(t => t[1].startsWith('porthome/v2/'))) expect(slowObjects.size).toBe(2); };
    const id = await engine.create('Team', {}); expect(puts.filter(p => p.endpoint === slow)).toHaveLength(2);
    expect(snapshot(engine).vaults.find(v => v.vaultId === id)?.network?.writeBlossom).toContain(slow); release.resolve();
  });

  it('adds an inbox REQ for late own NIP-65 hints without re-sending the existing live REQs', async () => {
    const f = await fixture(), urls = ['wss://fast.example.com/', 'wss://slow.example.com/'], inbox = 'wss://own-inbox.example.com/', release = deferred();
    const list = await f.session.signer.signEvent({ kind: 10002, created_at: f.deps.clock!(), content: '', tags: [['r', inbox, 'read']] }); f.net.events.set(list.id, list);
    const live: { endpoint: string; kinds: readonly number[] | undefined }[] = [];
    const relayFactory: NonNullable<VaultEngineDeps['relayFactory']> = (endpoints, options) => {
      const relay = f.net.relayFactory(endpoints, options);
      return { ...relay, subscribe: (filters, handlers) => { for (const filter of filters) live.push({ endpoint: endpoints[0], kinds: filter.kinds }); return relay.subscribe(filters, handlers); },
        backfill: async (filters, handlers, signal) => {
          if (filters.some(filter => filter.kinds?.includes(10002))) {
            if (endpoints[0] === urls[0]) { handlers.oneose?.(endpoints[0]); return; }
            if (endpoints[0] === urls[1]) await release.promise;
          }
          return relay.backfill(filters, handlers, signal);
        } };
    };
    const engine = await start({ ...f, session: { ...f.session, networkDefaults: { ...network, readRelays: urls, writeRelays: urls } } }, { ...f.deps, relayFactory });
    await engine.refreshInbox(); expect(live.filter(s => s.kinds?.includes(1059))).toHaveLength(2);
    const learned = receipt(engine, () => live.some(s => s.endpoint === inbox && s.kinds?.includes(1059)));
    release.resolve(); await learned; await engine.refreshInbox();
    expect(live.filter(s => s.kinds?.includes(1059)).map(s => s.endpoint).sort()).toEqual([...urls, inbox].sort());
  });

  it('uses late NIP-65 routing after a fast empty EOSE, even after initial delivery was acknowledged', async () => {
    const f = await fixture(), target = hex32<Pubkey>(await signer(2).getPublicKey()), urls = ['wss://fast.example.com/', 'wss://slow.example.com/'];
    const inbox = 'wss://recipient-inbox.example.com/', release = deferred(), entered = deferred(), deliveries: string[] = [];
    await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a.md', 'initial');
    const list = await signer(2).signEvent({ kind: 10002, created_at: f.deps.clock!(), content: '', tags: [['r', inbox, 'read']] });
    f.net.events.set(list.id, list);
    const relayFactory: NonNullable<VaultEngineDeps['relayFactory']> = (endpoints, options) => {
      const relay = f.net.relayFactory(endpoints, options);
      return { ...relay, backfill: async (filters, handlers, signal) => {
        if (filters.some(filter => filter.kinds?.includes(10002) && filter.authors?.includes(target))) {
          if (endpoints[0] === urls[0]) { handlers.oneose?.(endpoints[0]); return; }
          if (endpoints[0] === urls[1]) { entered.resolve(); await release.promise; }
        }
        return relay.backfill(filters, handlers, signal);
      }, publish: async event => { if (event.kind === 1059) deliveries.push(endpoints[0]); return relay.publish(event); } };
    };
    const engine = await start({ ...f, session: { ...f.session, networkDefaults: { ...network, readRelays: urls, writeRelays: urls } } }, { ...f.deps, relayFactory });
    const id = await engine.create('Team', {}); await engine.share(id, [target], 'read', {}); await entered.promise;
    expect(deliveries).not.toContain(inbox);
    const received = receipt(engine, () => snapshot(engine).vaults.find(v => v.vaultId === id)?.deliveries?.some(d => d.recipient === target && d.acknowledged.includes(inbox)) === true);
    release.resolve(); await received; expect(deliveries).toContain(inbox);
  });

  it('restarts historical paging when a newly imported device key expands the recipient set', async () => {
    const f = await fixture(), engine = await start(f), key = new Uint8Array(32).fill(7), pubkey = hex32<Pubkey>(getPublicKey(key));
    const old = await invitation(f, pubkey, 30 * 86400); f.net.events.set(old.wrap.id, old.wrap);
    await engine.refreshInbox(); expect(snapshot(engine).invitations).toEqual([]);
    await engine.deviceKeys.import(bytesToHex(key)); await engine.refreshInbox();
    expect(snapshot(engine).invitations).toContainEqual(expect.objectContaining({ vaultId: hex32<VaultId>('11'.repeat(32)) }));
    expect(f.net.backfills.some(filters => filters.some(filter => filter.kinds?.includes(1059) && filter['#p']?.includes(pubkey) && filter.since === undefined))).toBe(true);
  });

  it('does not persist an in-flight wrap as seen when invitation storage fails', async () => {
    const f = await fixture(), engine = await start(f); await engine.refreshInbox();
    const good = await invitation(f); f.net.events.set(good.wrap.id, good.wrap);
    const put = vi.spyOn(VaultStore.prototype, 'put').mockRejectedValueOnce(new VaultError('STORAGE'));
    await expect(engine.refreshInbox()).rejects.toMatchObject({ code: 'STORAGE' }); put.mockRestore();
    f.net.events.delete(good.wrap.id);
    const spam = finalizeEvent({ kind: 1059, created_at: f.deps.clock!(), content: 'not ciphertext', tags: [['p', f.pubkey]] }, new Uint8Array(32).fill(9));
    f.net.events.set(spam.id, spam); await engine.refreshInbox();
    const store = await f.openStore(); expect((await store.read('accounts', []))!.value.config.inboxSeen).not.toContain(good.wrap.id); store.stop();
    await engine.stop(); f.net.events.set(good.wrap.id, good.wrap);
    const next = await start(f); await next.refreshInbox(); expect(snapshot(next).invitations).toHaveLength(1);
  });

  it('refuses publication while paused instead of spinning on a retired authority fence', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a', 'bytes');
    const engine = await start(f), id = await engine.create('Team', {}); await engine.refreshInbox();
    await engine.pause(id); const before = f.net.published.length;
    await expect(engine.share(id, [hex32<Pubkey>(await signer(2).getPublicKey())], 'read', {})).rejects.toMatchObject({ code: 'NETWORK' });
    expect(f.net.published).toHaveLength(before); await engine.resume(id); expect(snapshot(engine).vaults[0].enabled).toBe(true);
  });

  it('ignores late receipts for an SV-28-compacted journal without recreating it or changing vault state', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a', 'bytes');
    const engine = await start(f), id = await engine.create('Team', {}); await engine.refreshInbox();
    const store = await f.openStore(), row = (await store.list('operations')).find(r => r.value.kind === 'create')!, vault = (await store.read('vaults', [id]))!.value;
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = f.factory.open(VAULT_DATABASE_NAME); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
    });
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('operations', 'readwrite'); tx.objectStore('operations').delete([f.pubkey, id, row.value.operationId]);
      tx.oncomplete = () => resolve(); tx.onabort = () => reject(tx.error);
    }); db.close();
    await expect(store.recordRelayOutcomes(id, row.value.operationId, { replica: 'accepted' })).resolves.toBeUndefined();
    expect(await store.read('operations', [id, row.value.operationId])).toBeNull(); expect((await store.read('vaults', [id]))!.value).toEqual(vault); store.stop();
  });

  it('keeps positive head/ledger receipts monotonic without mutating committed candidates or pointers', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a', 'bytes');
    const engine = await start(f), id = await engine.create('Team', {}); await engine.refreshInbox();
    const store = await f.openStore(), row = (await store.list('operations')).find(r => r.value.kind === 'create')!, vault = (await store.read('vaults', [id]))!.value;
    const accepted = { replica: 'accepted', epochLedger: { replica: 'accepted' }, epochLedgerAcknowledged: true };
    const older = { replica: 'unknown', epochLedger: { replica: 'unknown' }, epochLedgerAcknowledged: false };
    expect(mergeRelayOutcomes(accepted, older)).toEqual(accepted);
    await store.recordRelayOutcomes(id, row.value.operationId, accepted); await store.recordRelayOutcomes(id, row.value.operationId, older);
    const current = (await store.read('operations', [id, row.value.operationId]))!.value;
    expect(current.relayOutcomes).toMatchObject(accepted); expect(current.candidate).toEqual(row.value.candidate); expect(current.signedEvent).toEqual(row.value.signedEvent);
    expect((await store.read('vaults', [id]))!.value).toEqual(vault); store.stop();
  });
});
