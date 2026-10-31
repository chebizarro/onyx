import { afterEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, nip44 } from 'nostr-tools';
import { HeadlessVaultEngine } from '../engine';
import { VaultStore } from '../store';
import type { VaultId } from '../types';
import { fixture, network, signer, snapshot } from './engine-fixtures';

const engines: HeadlessVaultEngine[] = [];
afterEach(async () => { await Promise.all(engines.splice(0).map(engine => engine.stop())); vi.useRealTimers(); });
const deferred = <T = void>() => { let resolve!: (value: T) => void; const promise = new Promise<T>(yes => { resolve = yes; }); return { promise, resolve }; };
async function start(f: Awaited<ReturnType<typeof fixture>>) {
  const engine = new HeadlessVaultEngine(f.deps); engines.push(engine); await engine.start(f.session); return engine;
}
/** Wait on engine/store receipts, never elapsed time or a polling loop. */
function committed(engine: HeadlessVaultEngine, store: VaultStore, id: VaultId, seq: string) {
  return new Promise<void>((resolve, reject) => {
    let off = () => {};
    off = engine.subscribe(() => { void store.read('vaults', [id]).then(row => {
      if (row?.value.lastOwnSeq === seq && row.value.pendingCandidateId === null) { off(); resolve(); }
    }, reject); });
  });
}

describe('SV-27 incremental traffic and live state', () => {
  it('a local edit captures only its mount, sends no one-shot REQs, and uploads only a chunk plus root', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); await f.mkdir('/notebook/Other');
    for (let i = 0; i < 12; i++) await f.fs.write(`/notebook/Team/${i}.md`, `original ${i}`);
    await f.fs.write('/notebook/Other/untouched.md', 'other vault');
    const engine = await start(f), id = await engine.create('Team', {}); await engine.create('Other', {});
    await engine.refreshInbox();
    const store = await f.openStore();
    const before = snapshot(engine).vaults.find(v => v.vaultId !== id)!;
    await f.fs.write('/notebook/Team/0.md', 'one changed note');
    const headCount = f.net.published.length, subscriptions = f.net.subscriptionFrames.length;
    f.net.heads.length = f.net.gets.length = f.net.puts.length = f.net.backfills.length = 0;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const receipt = committed(engine, store, id, '2');
    // Accept both the old notebook-relative call model and absolute watcher paths.
    engine.notifyFilesChanged(['Team/0.md', '/notebook/Team/0.md']);
    await vi.advanceTimersByTimeAsync(750); await receipt;
    expect(f.net.heads).toHaveLength(2); expect(f.net.puts).toHaveLength(2); expect(f.net.gets).toEqual([]);
    expect(f.net.backfills).toEqual([]); expect(f.net.subscriptionFrames).toHaveLength(subscriptions);
    expect(f.net.published.slice(headCount)).toHaveLength(1);
    expect((await store.read('vaults', [before.vaultId]))!.value.lastOwnSeq).toBe('1');
    expect(snapshot(engine).vaults.find(v => v.vaultId === before.vaultId)?.lastError).toBeNull();
    store.stop();
  });

  it('persists confirmations, migrates legacy journal receipts on restart and never verifies an existing blob with GET', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team');
    for (let i = 0; i < 6; i++) await f.fs.write(`/notebook/Team/${i}.md`, `content ${i}`);
    const engine = await start(f), id = await engine.create('Team', {}); await engine.refreshInbox(); await engine.stop();
    const legacyStore = await f.openStore(), row = (await legacyStore.read('vaults', [id]))!;
    const { confirmedObjects, ...legacy } = row.value;
    expect(Object.keys(confirmedObjects!)).toHaveLength(7);
    await legacyStore.updateVault(legacy, row.revision); legacyStore.stop();
    const next = await start(f); await next.refreshInbox();
    f.net.heads.length = f.net.gets.length = f.net.puts.length = 0;
    await f.fs.write('/notebook/Team/0.md', 'changed after restart'); await next.sync(id);
    expect(f.net.heads).toHaveLength(2); expect(f.net.puts).toHaveLength(2); expect(f.net.gets).toEqual([]);
    const store = await f.openStore(), vault = (await store.read('vaults', [id]))!.value;
    expect(Object.values(vault.confirmedObjects!).every(urls => urls.includes(network.writeBlossom[0]))).toBe(true); store.stop();
  });

  it('uses necessary download confirmations for a fresh member so its first one-note edit is incremental too', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team');
    for (let i = 0; i < 8; i++) await f.fs.write(`/notebook/Team/${i}.md`, `content ${i}`);
    const owner = await start(f), id = await owner.create('Team', {}), member = await fixture(f.net, signer(2));
    const counts = { GET: 0, HEAD: 0, PUT: 0 };
    const blossomFactory: typeof member.net.blossomFactory = (endpoint, options) => {
      const client = member.net.blossomFactory(endpoint, options);
      return { ...client, get: (...args) => { counts.GET++; return client.get(...args); }, head: (...args) => { counts.HEAD++; return client.head(...args); }, put: (...args) => { counts.PUT++; return client.put(...args); } };
    };
    const writer = await start({ ...member, deps: { ...member.deps, blossomFactory } });
    await owner.share(id, [member.pubkey], 'write', {}); await writer.refreshInbox();
    await writer.accept(snapshot(writer).invitations[0].invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    counts.GET = counts.HEAD = counts.PUT = 0;
    await member.fs.write('/notebook/shared/0.md', 'member edit'); await writer.sync(id);
    expect(counts).toEqual({ HEAD: 2, PUT: 2, GET: 0 });
  });

  it('HEADs unknown confirmations without a verifying GET, including a newly added write server', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a.md', 'initial'); await f.fs.write('/notebook/Team/b.md', 'unchanged');
    const engine = await start(f), id = await engine.create('Team', {}); await engine.refreshInbox(); await engine.stop();
    const store = await f.openStore(), row = (await store.read('vaults', [id]))!;
    await store.updateVault({ ...row.value, network: { ...row.value.network, writeBlossom: [...row.value.network.writeBlossom, 'https://replica.example.com/'] } }, row.revision); store.stop();
    const next = await start(f); await next.refreshInbox(); f.net.heads.length = f.net.gets.length = f.net.puts.length = 0;
    await f.fs.write('/notebook/Team/a.md', 'changed'); await next.sync(id);
    // This fixture exposes the same content-addressed inventory on both URLs.
    // Two unknown new pairs on the primary, plus all three on the new replica.
    expect(f.net.heads).toHaveLength(5); expect(f.net.puts).toHaveLength(2); expect(f.net.gets).toEqual([]);
    const check = await f.openStore(), vault = (await check.read('vaults', [id]))!.value;
    const current = (await check.list('operations')).map(r => r.value).find(op => op.kind === 'publish')!;
    for (const address of current.pinnedAddresses) expect(vault.confirmedObjects![address]).toContain('https://replica.example.com/'); check.stop();
  });

  it('runs four uploads in flight, waits for all chunks before the root, and journals their receipts', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team');
    for (let i = 0; i < 8; i++) await f.fs.write(`/notebook/Team/${i}`, `unique ${i}`);
    const engine = await start(f), batches = [deferred(), deferred(), deferred()], releases: (() => void)[] = [];
    let active = 0, maximum = 0, arrived = 0;
    f.net.beforePut = async () => {
      active++; maximum = Math.max(active, maximum); const n = ++arrived, gate = deferred(); releases.push(() => gate.resolve());
      if (n === 4) batches[0].resolve(); if (n === 8) batches[1].resolve(); if (n === 9) batches[2].resolve();
      await gate.promise; active--;
    };
    const creating = engine.create('Team', {});
    await batches[0].promise; expect(arrived).toBe(4); releases.splice(0).forEach(release => release());
    await batches[1].promise; expect(arrived).toBe(8); expect(f.net.puts).toHaveLength(4); releases.splice(0).forEach(release => release());
    await batches[2].promise; expect(f.net.puts).toHaveLength(8); releases.splice(0).forEach(release => release());
    const id = await creating; expect(maximum).toBe(4); expect(f.net.puts).toHaveLength(9);
    const store = await f.openStore(), records = await store.list('records');
    expect(f.net.puts[8]).toBe(records.find(r => r.value.vaultId === id)!.value.record.head.rootManifest); store.stop();
  });

  it('deduplicates publisher records and inbox wraps before signer decrypt, including after restart', async () => {
    const identity = signer(), decrypt = vi.fn(identity.nip44!.decrypt);
    identity.nip44 = { ...identity.nip44!, decrypt };
    const f = await fixture(undefined, identity); await f.mkdir('/notebook/Team');
    const engine = await start(f); await engine.create('Team', {}); await engine.refreshInbox();
    const publisher = f.net.published.find(e => e.tags.some(t => t[1].startsWith('onyx/vault-publisher/')))!;
    const wrap = f.net.published.find(e => e.kind === 1059)!;
    const count = decrypt.mock.calls.length;
    for (let i = 0; i < 4; i++) { f.net.emit(publisher); f.net.emit(wrap); }
    await engine.refreshInbox(); expect(decrypt).toHaveBeenCalledTimes(count);
    await engine.stop(); const next = await start(f); await next.refreshInbox(); expect(decrypt).toHaveBeenCalledTimes(count);
    expect(f.net.backfills.filter(filters => filters.some(filter => filter.kinds?.includes(1059))).slice(-1)[0][0].since).toBe(f.deps.clock!() - 2 * 86400);
  });

  it('commits at the first OK and journals a late replica receipt without changing the candidate or pointers', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a.md', 'initial');
    const urls = ['wss://fast.example.com/', 'wss://slow.example.com/'];
    const factory = f.net.relayFactory, slow = deferred(); let hold = false;
    const relayFactory: typeof factory = (endpoints, options) => {
      const relay = factory(endpoints, options);
      return { ...relay, publish: async event => {
        const result = await relay.publish(event);
        if (hold && endpoints[0] === urls[1] && event.tags.some(t => t[1].startsWith('porthome/v2/'))) await slow.promise;
        return result;
      } };
    };
    const engine = await start({ ...f, deps: { ...f.deps, relayFactory }, session: { ...f.session, networkDefaults: { ...network, readRelays: urls, writeRelays: urls } } });
    const id = await engine.create('Team', {}); await engine.refreshInbox();
    hold = true; await f.fs.write('/notebook/Team/a.md', 'new');
    // The slow relay has not returned its scripted OK. No deadline is advanced.
    await engine.sync(id);
    const store = await f.openStore(), row = (await store.list('operations')).find(r => r.value.kind === 'publish')!;
    expect(row.value.stage).toBe('committed'); expect(row.value.relayOutcomes[urls[0]]).toBe('accepted'); expect(row.value.relayOutcomes[urls[1]]).toBeUndefined();
    const vault = (await store.read('vaults', [id]))!.value;
    const receipt = new Promise<void>((resolve, reject) => {
      let off = () => {};
      off = engine.subscribe(() => { void store.read('operations', [id, row.value.operationId]).then(current => {
        if (current?.value.relayOutcomes[urls[1]] === 'accepted') { off(); resolve(); }
      }, reject); });
    });
    slow.resolve(); await receipt;
    const updated = (await store.read('operations', [id, row.value.operationId]))!.value;
    expect(updated.candidate).toEqual(row.value.candidate); expect(updated.signedEvent).toEqual(row.value.signedEvent);
    expect((await store.read('vaults', [id]))!.value).toEqual(vault); store.stop();
    expect(f.net.relayClients).toEqual(urls.map(url => [url]));
  });

  it('remembers foreign/failed wraps too, rather than asking a remote signer to open each replay', async () => {
    const identity = signer(), decrypt = vi.fn(identity.nip44!.decrypt); identity.nip44 = { ...identity.nip44!, decrypt };
    const f = await fixture(undefined, identity), engine = await start(f);
    const key = new Uint8Array(32).fill(42);
    const foreign = finalizeEvent({ kind: 1059, created_at: f.deps.clock!(), tags: [['p', f.pubkey]],
      content: nip44.v2.encrypt('not a seal', nip44.v2.utils.getConversationKey(key, f.pubkey)) }, key);
    f.net.emit(foreign); await engine.refreshInbox(); expect(decrypt).toHaveBeenCalledTimes(1);
    await engine.stop(); const next = await start(f); f.net.emit(foreign); await next.refreshInbox(); expect(decrypt).toHaveBeenCalledTimes(1);
  });
});
