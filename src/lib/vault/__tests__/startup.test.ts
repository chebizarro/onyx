import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, getPublicKey, matchFilters, nip44, nip59, verifyEvent, type Event, type Filter } from 'nostr-tools';
import { useWebSocketImplementation } from 'nostr-tools/relay';
import { HeadlessVaultEngine } from '../engine';
import { VaultRelay } from '../relay';
import { BlossomError, VaultBlossom } from '../blossom';
import { VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION } from '../store';
import { buildGrantWrap } from '../carrier';
import { bytes32, hex32 } from '../crypto';
import type { Address, NodeId, Pubkey, VaultId } from '../types';
import { fixture, network, signer, snapshot } from './engine-fixtures';

// Exercise the actual pinned relay adapter, including CLOSED/AUTH/OK/EOSE.
class StartupSocket {
  static OPEN = 1;
  static events = new Map<string, Event>();
  static sent: { url: string; frame: unknown[] }[] = [];
  static open = new Set<StartupSocket>();
  static stalled = new Set<string>();
  /** Push to open REQs as a relay does after EOSE. */
  static deliver(event: Event) {
    for (const socket of StartupSocket.open) for (const [id, filters] of socket.reqs) if (matchFilters(filters, event)) socket.frame('EVENT', id, event);
  }
  readonly reqs = new Map<string, Filter[]>();
  readyState = 0;
  authenticated = false;
  onopen: (() => void) | null = null;
  onclose: ((event: { message: string }) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror = null;
  constructor(readonly url: string) { StartupSocket.open.add(this); queueMicrotask(() => { if (!StartupSocket.stalled.has(url)) { this.readyState = 1; this.onopen?.(); } }); }
  frame(...frame: unknown[]) { this.onmessage?.({ data: JSON.stringify(frame) } as MessageEvent); }
  send(message: string) {
    const frame = JSON.parse(message) as unknown[];
    StartupSocket.sent.push({ url: this.url, frame });
    queueMicrotask(() => {
      if (frame[0] === 'REQ') {
        if ((this.url.includes('private') || this.url.includes('challenge') || this.url.includes('auth-reject')) && !this.authenticated) {
          this.frame('AUTH', 'challenge'); this.frame('CLOSED', frame[1], 'auth-required: sign in'); return;
        }
        if (this.url.includes('private')) { this.frame('CLOSED', frame[1], 'restricted: not allowlisted'); return; }
        for (const event of StartupSocket.events.values()) if (matchFilters(frame.slice(2) as Filter[], event)) this.frame('EVENT', frame[1], event);
        this.frame('EOSE', frame[1]); this.reqs.set(frame[1] as string, frame.slice(2) as Filter[]);
      } else if (frame[0] === 'CLOSE') { this.reqs.delete(frame[1] as string);
      } else if (frame[0] === 'AUTH') {
        const event = frame[1] as Event;
        this.authenticated = verifyEvent(structuredClone(event)) && event.kind === 22242 &&
          event.tags.some(t => t[0] === 'relay' && t[1] === this.url) && event.tags.some(t => t[0] === 'challenge' && t[1] === 'challenge');
        this.frame('OK', event.id, this.authenticated, '');
      } else if (frame[0] === 'EVENT') {
        const event = frame[1] as Event;
        if (this.url.includes('auth-reject')) { this.frame('OK', event.id, false, 'auth-required: session rejected'); return; }
        StartupSocket.events.set(event.id, event); this.frame('OK', event.id, true, '');
      }
    });
  }
  close() { this.readyState = 3; StartupSocket.open.delete(this); this.onclose?.({ message: 'closed' }); }
}
const engines: HeadlessVaultEngine[] = [];
const engineFor = (deps: ConstructorParameters<typeof HeadlessVaultEngine>[0]) => {
  const engine = new HeadlessVaultEngine(deps); engines.push(engine); return engine;
};
beforeEach(() => {
  StartupSocket.events.clear(); StartupSocket.sent = []; StartupSocket.open.clear(); StartupSocket.stalled.clear(); useWebSocketImplementation(StartupSocket);
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ vault: true, limitation: { auth_required: true } })));
});
afterEach(async () => {
  for (const engine of engines.splice(0)) await engine.stop();
  vi.useRealTimers(); vi.unstubAllGlobals(); useWebSocketImplementation(WebSocket);
});

async function wireFixture(status = 401) {
  const f = await fixture();
  const network = { readRelays: ['wss://private.example/', 'wss://healthy.example/'], writeRelays: ['wss://private.example/', 'wss://healthy.example/'],
    readBlossom: ['https://private.example/', 'https://healthy.example/'], writeBlossom: ['https://private.example/', 'https://healthy.example/'] };
  const engine = engineFor({ ...f.deps, relayFactory: (endpoints, options) => new VaultRelay(endpoints, options),
    blossomFactory: (url, options) => url.includes('private') ? new VaultBlossom(url, { ...options, fetch: vi.fn(async () => new Response(null, { status })) }) : f.net.blossomFactory(url) });
  return { ...f, engine, network, session: { ...f.session, networkDefaults: network } };
}

describe('shared-vault service isolation', () => {
  it('reaches running from the first healthy relay and reuses one socket for discovery, inbox, heads, ledger and publisher', async () => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); await f.fs.write('/notebook/Team/a.md', 'cached');
    const defaults = { ...network, readRelays: ['wss://healthy.example/'], writeRelays: ['wss://healthy.example/'] };
    const deps = { ...f.deps, relayFactory: (endpoints: readonly string[], options: Parameters<NonNullable<typeof f.deps.relayFactory>>[1]) => new VaultRelay(endpoints, options) };
    const first = engineFor(deps); await first.start({ ...f.session, networkDefaults: defaults }); const id = await first.create('Team', {}); await first.refreshInbox(); await first.stop();
    const store = await f.openStore(), row = (await store.read('vaults', [id]))!;
    const relays = ['wss://healthy.example/', 'wss://dead.example/'];
    await store.updateVault({ ...row.value, network: { ...row.value.network, readRelays: relays, writeRelays: relays } }, row.revision); store.stop();
    StartupSocket.sent = []; StartupSocket.stalled.add('wss://dead.example/');
    const restarted = engineFor(deps); await restarted.start({ ...f.session, networkDefaults: { ...defaults, readRelays: relays, writeRelays: relays } });
    expect(snapshot(restarted)).toMatchObject({ lifecycle: 'running', condition: 'ready' });
    expect(StartupSocket.sent.some(s => s.url.includes('dead'))).toBe(false);
    expect([...StartupSocket.open].filter(s => s.url.includes('healthy'))).toHaveLength(1);
    expect([...StartupSocket.open].filter(s => s.url.includes('dead'))).toHaveLength(1);
    const filters = StartupSocket.sent.filter(s => s.frame[0] === 'REQ').flatMap(s => s.frame.slice(2) as Filter[]);
    expect(filters.some(f => f['#d']?.some(d => d.startsWith('porthome/v2/')))).toBe(true);
    expect(filters.some(f => f['#d']?.some(d => d.startsWith('onyx/vault-history/')))).toBe(true);
    expect(filters.some(f => f['#d']?.some(d => d.startsWith('onyx/vault-publisher/')))).toBe(true);
    expect(filters.filter(f => f.kinds?.includes(10002))).toHaveLength(1);
    expect(filters.filter(f => f['#d']?.some(d => d.startsWith('porthome/v2/'))).every(f => f.since === undefined)).toBe(true);
  });
  it.each([401, 402, 403])('isolates relay allowlist and Blossom HTTP %i refusals, starts ready with alternatives', async status => {
    const f = await wireFixture(status);
    await f.engine.start(f.session);
    expect(snapshot(f.engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
    expect(snapshot(f.engine).endpoints).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'relay', url: 'wss://private.example/', status: 'unsupported', message: expect.stringContaining('Not allowlisted') }),
      expect.objectContaining({ kind: 'blossom', url: 'https://private.example/', status: status === 401 ? 'offline' : 'unsupported',
        message: expect.stringContaining(status === 401 ? 'Authentication failed' : 'not used for shared vaults') }),
    ]));
    await f.mkdir('/notebook/Team');
    await f.fs.write('/notebook/Team/note.md', 'shared');
    const id = await f.engine.create('Team', {});
    const state = snapshot(f.engine);
    expect(state.condition).toBe('ready');
    expect(state.vaults.find(v => v.vaultId === id)?.network).toEqual({
      readRelays: ['wss://healthy.example/'], writeRelays: ['wss://healthy.example/'],
      readBlossom: ['https://healthy.example/'], writeBlossom: ['https://healthy.example/'],
    });
    expect(StartupSocket.sent.some(({ frame }) => frame[0] === 'AUTH')).toBe(true);
    expect(StartupSocket.sent.some(({ url, frame }) => url.includes('private') && frame[0] === 'EVENT')).toBe(false);
    expect(StartupSocket.sent.some(({ url, frame }) => url.includes('healthy') && frame[0] === 'EVENT')).toBe(true);
  });

  it('uses AUTH-capable endpoints and reports VSP classification informationally', async () => {
    const f = await wireFixture();
    const network = { ...f.network, readRelays: ['wss://challenge.example/', 'wss://healthy.example/'], writeRelays: ['wss://challenge.example/', 'wss://healthy.example/'] };
    await f.engine.start({ ...f.session, networkDefaults: network });
    expect(snapshot(f.engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
    expect(snapshot(f.engine).endpoints).toContainEqual(expect.objectContaining({ url: 'wss://challenge.example/', status: 'authenticated', service: 'private vault service' }));
  });

  it('reports a signer refusal as endpoint authentication failure, not an allowlist exclusion', async () => {
    const f = await wireFixture(403);
    const network = { ...f.network, readRelays: ['wss://challenge.example/', 'wss://healthy.example/'], writeRelays: ['wss://challenge.example/', 'wss://healthy.example/'] };
    await f.engine.start({ ...f.session, networkDefaults: network, signer: { ...f.session.signer, signEvent: async event => {
      if (event.kind === 22242) throw new Error('user denied'); return f.session.signer.signEvent(event);
    } } });
    expect(snapshot(f.engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
    expect(snapshot(f.engine).endpoints).toContainEqual(expect.objectContaining({ url: 'wss://challenge.example/', status: 'offline', message: expect.stringContaining('Authentication failed') }));
  });

  it('does not relabel post-auth auth-required publication refusal as not allowlisted', async () => {
    const f = await wireFixture(403);
    const network = { ...f.network, readRelays: ['wss://auth-reject.example/', 'wss://healthy.example/'], writeRelays: ['wss://auth-reject.example/', 'wss://healthy.example/'] };
    await f.engine.start({ ...f.session, networkDefaults: network }); await f.mkdir('/notebook/Team');
    const id = await f.engine.create('Team', {});
    expect(snapshot(f.engine).vaults.find(v => v.vaultId === id)?.lastError).toMatchObject({ code: 'NETWORK', operation: 'publish' });
    expect(snapshot(f.engine).endpoints).toContainEqual(expect.objectContaining({ url: 'wss://auth-reject.example/', status: 'offline', message: expect.stringContaining('Authentication failed') }));
    expect(snapshot(f.engine)).toMatchObject({ condition: 'ready', lastError: null });
  });

  it('blocks actionably when no authorised service remains and can retry corrected defaults', async () => {
    const f = await wireFixture(403);
    await expect(f.engine.start({ ...f.session, networkDefaults: { ...f.network, readBlossom: ['https://private.example/'], writeBlossom: ['https://private.example/'] } })).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    expect(snapshot(f.engine)).toMatchObject({ lifecycle: 'stopped', condition: 'blocked', lastError: { message: expect.stringContaining('https://private.example/') } });
    expect(snapshot(f.engine).endpoints).toContainEqual(expect.objectContaining({ kind: 'blossom', status: 'unsupported' }));
    await f.engine.stop();
    expect(snapshot(f.engine).endpoints).toEqual([]);
    await f.engine.start(f.session);
    expect(snapshot(f.engine).condition).toBe('ready');
  });

  it('keeps a pinned vault service refusal local when account defaults have healthy alternatives', async () => {
    const f = await fixture(); let privateServiceRequiresAuth = false;
    const defaults = { ...f.session.networkDefaults, readBlossom: ['https://private.example/', 'https://healthy.example/'], writeBlossom: ['https://private.example/', 'https://healthy.example/'] };
    const engine = engineFor({ ...f.deps, blossomFactory: url => {
      const client = f.net.blossomFactory(url);
      return { ...client, head: async (address, signal) => {
        if (privateServiceRequiresAuth && url.includes('private')) throw new BlossomError('AUTH', 403, 'fetch');
        return client.head(address, signal);
      } };
    } });
    await engine.start({ ...f.session, networkDefaults: defaults }); await f.mkdir('/notebook/Team');
    await f.fs.write('/notebook/Team/note.md', 'before');
    const id = await engine.create('Team', { network: { ...defaults, readBlossom: ['https://private.example/'], writeBlossom: ['https://private.example/'] } });
    privateServiceRequiresAuth = true; await f.fs.write('/notebook/Team/note.md', 'after');
    await expect(engine.sync(id)).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    expect(snapshot(engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
    expect(snapshot(engine).vaults[0].lastError?.code).toBe('UNSUPPORTED');
    await expect(engine.sync(id)).rejects.toMatchObject({ code: 'UNSUPPORTED', message: expect.stringContaining('https://private.example/') });
    expect(snapshot(engine).condition).toBe('ready');
    await engine.stop();
    await engine.start({ ...f.session, networkDefaults: defaults });
    expect(snapshot(engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
  });

  it('validates explicit creation endpoints before persisting a mount', async () => {
    const f = await wireFixture(); await f.engine.start(f.session); await f.mkdir('/notebook/Team');
    await expect(f.engine.create('Team', { network: { ...f.network, readRelays: ['wss://private.example/'], writeRelays: ['wss://private.example/'] } })).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    expect(snapshot(f.engine).vaults).toEqual([]);
    const store = await f.openStore(); expect(await store.list('vaults')).toEqual([]); store.stop();
    expect(snapshot(f.engine)).toMatchObject({ condition: 'ready', lastError: null });
    expect(snapshot(f.engine).endpoints).toContainEqual(expect.objectContaining({ url: 'wss://private.example/', status: 'unsupported' }));
    // A failed override does not make subsequent creation with usable defaults fail.
    await f.engine.create('Team', {});
    expect(snapshot(f.engine).vaults).toHaveLength(1);
  });
});

describe('startup refusal visibility', () => {
  it('distinguishes a missing notebook and mismatched signer from service authorisation', async () => {
    const f = await fixture(); const engine = engineFor(f.deps);
    await expect(engine.start({ ...f.session, notebookPath: '' })).rejects.toMatchObject({ code: 'ARG' });
    expect(snapshot(engine).lastError?.message).toContain('Open a notebook');
    await expect(engine.start({ ...f.session, signer: { ...f.session.signer, getPublicKey: async () => 'f'.repeat(64) } })).rejects.toMatchObject({ code: 'AUTH' });
    expect(snapshot(engine).lastError?.message).toContain('signer does not match');
  });

  it('reports an incomplete IndexedDB schema without erasing it', async () => {
    const f = await fixture();
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = f.factory.open(VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION);
      request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
    });
    database.close();
    const engine = engineFor(f.deps);
    await expect(engine.start(f.session)).rejects.toMatchObject({ code: 'STORAGE' });
    expect(snapshot(engine).lastError?.message).toContain('schema is incomplete');
    const preserved = await new Promise<IDBDatabase>(resolve => { const request = f.factory.open(VAULT_DATABASE_NAME); request.onsuccess = () => resolve(request.result); });
    expect(preserved.objectStoreNames.length).toBe(0); preserved.close();
  });

  it('reports unavailable Web Locks without opening account state', async () => {
    vi.stubGlobal('navigator', {});
    const f = await fixture(); const engine = engineFor({ ...f.deps, lockProvider: undefined });
    await expect(engine.start(f.session)).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    expect(snapshot(engine).lastError?.message).toContain('Web Locks are unavailable');
  });

  it('times out a webview that never grants the lock; late callbacks cannot acquire it', async () => {
    vi.useFakeTimers(); const f = await fixture();
    let callback!: LockGrantedCallback<void>, requested!: () => void;
    const request = new Promise<void>(resolve => { requested = resolve; });
    const engine = engineFor({ ...f.deps, lockProvider: { request: ((_name: string, _options: unknown, action: LockGrantedCallback<void>) => {
      callback = action; requested(); return new Promise(() => {});
    }) as LockManager['request'] } });
    const starting = engine.start(f.session); const failure = expect(starting).rejects.toMatchObject({ code: 'CONFLICT' });
    await request;
    expect(snapshot(engine).lastError?.message).toContain('Waiting for');
    await vi.advanceTimersByTimeAsync(5001); await failure;
    expect(snapshot(engine)).toMatchObject({ lifecycle: 'stopped', condition: 'blocked', lastError: { message: expect.stringContaining('Timed out') } });
    await callback({ name: 'late', mode: 'exclusive' } as Lock);
    expect(snapshot(engine).lifecycle).toBe('stopped');
  });

  it('reports IndexedDB failures and locked secrets distinctly', async () => {
    const f = await fixture();
    const broken = engineFor({ ...f.deps, idbFactory: () => ({ open: () => { throw new Error('denied'); } }) as unknown as IDBFactory });
    await expect(broken.start(f.session)).rejects.toMatchObject({ code: 'STORAGE' });
    expect(snapshot(broken).lastError?.message).toContain('IndexedDB is unavailable');
    const locked = engineFor(f.deps);
    await locked.start({ ...f.session, secrets: { ...f.secrets, isLocked: () => true } });
    expect(snapshot(locked)).toMatchObject({ lifecycle: 'stopped', condition: 'needs-key', lastError: { message: expect.stringContaining('Unlock the secret store') } });
  });
});

describe('startup inbox delivery (SV-24)', () => {
  async function startupInbox() {
    const f = await fixture(), owner = signer(3), vaultId = hex32<VaultId>('11'.repeat(32));
    const invitation = await buildGrantWrap({ vaultId, nodeId: hex32<NodeId>('22'.repeat(32)), owner: hex32<Pubkey>(await owner.getPublicKey()),
      rootManifest: hex32<Address>('33'.repeat(32)), cap: 'read', issuedAt: 1700000000n, ring: { entries: [{ epoch: 1n, nodeKey: bytes32(new Uint8Array(32).fill(4)) }] },
      hints: { relays: [...f.session.networkDefaults.readRelays], blossom: [...f.session.networkDefaults.readBlossom] } }, owner, f.pubkey);
    const spam = finalizeEvent({ kind: 1059, tags: [['p', f.pubkey]], created_at: 1700000000, content: 'not NIP-44' }, new Uint8Array(32).fill(5));
    const foreign = nip59.wrapEvent({ kind: 14, content: 'a private message', tags: [['p', f.pubkey]] }, new Uint8Array(32).fill(6), f.pubkey);
    let delivered!: () => void;
    const received = new Set<string>(), delivery = new Promise<void>(resolve => { delivered = resolve; });
    const engine = engineFor({ ...f.deps, relayFactory: (endpoints, options) => {
      const relay = new VaultRelay(endpoints, options), subscribe = relay.subscribe.bind(relay);
      vi.spyOn(relay, 'subscribe').mockImplementation((filters, handlers) => subscribe(filters, { ...handlers, onevent: (event, url) => {
        handlers.onevent(event, url);
        if (received.size < 3 && [invitation.wrap.id, spam.id, foreign.id].includes(event.id)) {
          expect(snapshot(engine).lifecycle).toBe('starting'); received.add(event.id);
          if (received.size === 3) delivered();
        }
      } }));
      return relay;
    } });
    // Hold the last asynchronous startup step so delivery and stop are deterministic.
    const checkpoint = engine as unknown as { refreshCounts(): Promise<void> };
    const refreshCounts = checkpoint.refreshCounts.bind(engine);
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const held = vi.spyOn(checkpoint, 'refreshCounts').mockImplementation(async () => { await refreshCounts(); await gate; });
    const starting = engine.start(f.session);
    await vi.waitFor(() => expect([...StartupSocket.open].some(socket => [...socket.reqs.values()].some(filters => filters.some(filter => filter.kinds?.includes(1059))))).toBe(true));
    // Repeated live delivery carries the same event id during startup.
    for (const event of [spam, foreign, invitation.wrap, invitation.wrap]) StartupSocket.deliver(event);
    await delivery;
    return { ...f, engine, invitation, vaultId, starting, release: () => { held.mockRestore(); release(); } };
  }

  it('accepts an invitation delivered before running, silently drops foreign/spam wraps and tolerates backfill/live duplicates', async () => {
    const f = await startupInbox();
    expect(snapshot(f.engine).invitations).toEqual([]);
    f.release(); await f.starting;
    expect(snapshot(f.engine).invitations).toEqual([expect.objectContaining({ vaultId: f.vaultId })]);
    // An explicit backfill replay and another live push must not add invitations.
    StartupSocket.events.set(f.invitation.wrap.id, f.invitation.wrap);
    StartupSocket.deliver(f.invitation.wrap);
    await f.engine.refreshInbox();
    const store = await f.openStore();
    try {
      expect((await store.list('invitations')).map(row => row.value.wrapIds)).toEqual([[f.invitation.wrap.id]]);
    } finally { store.stop(); }
    expect(snapshot(f.engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
    const inboxReqs = StartupSocket.sent.filter(({ frame }) => frame[0] === 'REQ' && (frame.slice(2) as Filter[]).some(filter => filter.kinds?.includes(1059)));
    expect((inboxReqs[0].frame[2] as Filter).since).toBeUndefined();
    expect((inboxReqs[inboxReqs.length - 1].frame[2] as Filter).since).toBe(f.deps.clock!() - 2 * 86400);
    expect(StartupSocket.sent.some(({ frame }) => frame[0] === 'CLOSE' && frame[1] === inboxReqs[0].frame[1])).toBe(false);
  });

  it('discards buffered wraps when stopped during startup and does not replay them on restart', async () => {
    const f = await startupInbox();
    const cancelled = expect(f.starting).rejects.toMatchObject({ code: 'CANCELLED' });
    const stopping = f.engine.stop(); f.release();
    await cancelled; await stopping;
    expect(snapshot(f.engine)).toMatchObject({ lifecycle: 'stopped', invitations: [], lastError: null });
    await f.engine.start(f.session);
    expect(snapshot(f.engine)).toMatchObject({ lifecycle: 'running', invitations: [], condition: 'ready', lastError: null });
    const store = await f.openStore();
    try { expect(await store.list('invitations')).toEqual([]); } finally { store.stop(); }
  });
});

describe('shared-vault inbox shared with other NIP-59 traffic (SV-23)', () => {
  it('starts ready on the reported endpoints when the account inbox holds DMs, malformed wraps and spam', async () => {
    const f = await fixture();
    const network = { readRelays: ['wss://relay.sharegap.net/', 'wss://nos.lol/', 'wss://relay.primal.net/'], writeRelays: ['wss://relay.sharegap.net/', 'wss://nos.lol/', 'wss://relay.primal.net/'],
      readBlossom: ['https://blossom.sharegap.net/'], writeBlossom: ['https://blossom.sharegap.net/'] };
    // The endpoint probe HEADs the all-zero address; an unknown blob is a 404.
    const blossomFetch = vi.fn(async () => new Response(null, { status: 404 }));
    const engine = engineFor({ ...f.deps, relayFactory: (endpoints, options) => new VaultRelay(endpoints, options),
      blossomFactory: (url, options) => new VaultBlossom(url, { ...options, fetch: blossomFetch }) });
    const me = f.pubkey, otherKey = new Uint8Array(32); otherKey[31] = 3;
    const toMe = (text: string) => nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(otherKey, me));
    const seal = (rumor: string, tags: string[][] = []) => finalizeEvent({ kind: 13, tags, created_at: 1700000000, content: toMe(rumor) }, otherKey);
    let n = 0; const ephemeral = () => { const key = new Uint8Array(32); key[0] = 9; key[31] = ++n; return key; };
    const foreign: Event[] = [
      nip59.wrapEvent({ kind: 14, content: 'a private message', tags: [['p', me]] }, otherKey, me),
      nip59.createWrap(seal(JSON.stringify({ kind: 14, content: 'tagged seal', tags: [], created_at: 1, pubkey: getPublicKey(otherKey) }), [['p', me]]), me),
      nip59.createWrap(seal('"not an object"'), me),
      finalizeEvent({ kind: 1059, tags: [['p', me]], created_at: 1700000000, content: 'spam, not NIP-44' }, ephemeral()),
      ((key = ephemeral()) => finalizeEvent({ kind: 1059, tags: [['p', me], ['p', getPublicKey(otherKey)]], created_at: 1700000000,
        content: nip44.v2.encrypt(JSON.stringify(seal('{}')), nip44.v2.utils.getConversationKey(key, me)) }, key))(),
    ];
    // A genuine invitation queued behind the foreign wraps proves the inbox lane processed them.
    const owner = signer(3), vaultId = hex32<VaultId>('11'.repeat(32));
    const invitation = await buildGrantWrap({ vaultId, nodeId: hex32<NodeId>('22'.repeat(32)), owner: hex32<Pubkey>(await owner.getPublicKey()),
      rootManifest: hex32<Address>('33'.repeat(32)), cap: 'read', issuedAt: 1700000000n, ring: { entries: [{ epoch: 1n, nodeKey: bytes32(new Uint8Array(32).fill(4)) }] },
      hints: { relays: ['wss://relay.sharegap.net/'], blossom: ['https://blossom.sharegap.net/'] } }, owner, me);

    await engine.start({ ...f.session, networkDefaults: network });
    expect(snapshot(engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
    for (const event of [...foreign, invitation.wrap]) StartupSocket.deliver(event);
    await vi.waitFor(() => expect(snapshot(engine).invitations).toEqual([expect.objectContaining({ vaultId })]));
    // One persistent live REQ plus the paged historical catch-up per relay.
    expect(StartupSocket.sent.filter(s => s.frame[0] === 'REQ' && JSON.stringify(s.frame).includes('"kinds":[1059]')).map(s => s.url).sort())
      .toEqual(network.readRelays.flatMap(url => [url, url]).sort());
    // Service discovery is reused by inbox startup, not fetched a second time.
    expect(StartupSocket.sent.filter(s => s.frame[0] === 'REQ' && JSON.stringify(s.frame).includes('"kinds":[10002]')).map(s => s.url).sort())
      .toEqual([...network.readRelays].sort());
    expect(blossomFetch).toHaveBeenCalledWith(expect.stringContaining('0'.repeat(64)), expect.objectContaining({ method: 'HEAD' }));
    expect(snapshot(engine)).toMatchObject({ lifecycle: 'running', condition: 'ready', lastError: null });
    expect((snapshot(engine).endpoints ?? []).map(e => [e.kind, e.url, e.status]).sort()).toEqual([
      ['blossom', 'https://blossom.sharegap.net/', 'usable'],
      ...network.readRelays.map(url => ['relay', url, 'usable']),
    ].sort());
  });
});
