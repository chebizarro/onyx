import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { matchFilter, verifyEvent, type Event, type Filter } from 'nostr-tools';
import { useWebSocketImplementation } from 'nostr-tools/relay';
import { VaultBlossom } from '../blossom';
import { HeadlessVaultEngine } from '../engine';
import type { VaultEngineDeps, VaultSession } from '../engine-api';
import { VaultError } from '../errors';
import { hashAddress } from '../crypto';
import { VaultStore } from '../store';
import { VaultRelay, type RelayHandlers, type RelayPublishResult } from '../relay';
import type { MountRegistry } from '../types';
import { LocalWorker, MemoryFS, network, signer, snapshot } from './engine-fixtures';

export const isHead = (event: Event) => event.kind === 30078 && event.tags.some(t => t[0] === 'd' && t[1].startsWith('porthome/v2/'));
export const recipient = (event: Event) => event.tags.find(t => t[0] === 'p')?.[1];
const order = (a: Event, b: Event) => b.created_at - a.created_at || a.id.localeCompare(b.id);

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(r => { resolve = r; });
  return { promise, resolve };
}

/** A protocol boundary, not a timer: stop() must abort an outstanding request. */
export class RequestGate {
  private readonly arrival = deferred();
  private readonly release = deferred();
  readonly entered = this.arrival.promise;
  event?: Event;
  address?: string;
  resume() { this.release.resolve(); }
  async wait(signal: AbortSignal) {
    this.arrival.resolve();
    await new Promise<void>((resolve, reject) => {
      const abort = () => { cleanup(); reject(new DOMException('Request aborted', 'AbortError')); };
      const cleanup = () => signal.removeEventListener('abort', abort);
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort();
      this.release.promise.then(() => { cleanup(); resolve(); });
    });
  }
}

type Traffic = { device: string; frame: 'AUTH' | 'EVENT' | 'OK' | 'REQ' | 'EOSE' | 'GET' | 'HEAD' | 'PUT'; event?: Event; filter?: Filter; address?: string; auth?: Event };

/** One relay and one content-addressed Blossom server shared by all devices. */
export class AcceptanceNetwork {
  now = 1800000000;
  constructor(readonly authRequired = false) {}
  readonly events = new Map<string, Event>();
  readonly objects = new Map<string, Uint8Array>();
  readonly traffic: Traffic[] = [];
  readonly database = new IDBFactory();
  private readonly subscribers = new Set<{ device: string; filters: readonly Filter[]; handlers: RelayHandlers; seen: Set<string> }>();
  private fault?: { device: string; point: 'PUT' | 'HEAD' | 'WRAP'; gate: RequestGate };
  tick() { this.now += 100; }
  gate(device: string, point: 'PUT' | 'HEAD' | 'WRAP') {
    if (this.fault) throw new Error('Only one boundary may be armed at a time');
    const gate = new RequestGate(); this.fault = { device, point, gate }; return gate;
  }
  private takeGate(device: string, point: 'PUT' | 'HEAD' | 'WRAP') {
    if (this.fault?.device !== device || this.fault.point !== point) return undefined;
    const gate = this.fault.gate; this.fault = undefined; return gate;
  }
  heads(device?: string) { return this.traffic.filter(t => t.frame === 'EVENT' && t.event && isHead(t.event) && (!device || t.device === device)).map(t => t.event!); }
  wraps(pubkey: string) { return this.traffic.filter(t => t.frame === 'EVENT' && t.event?.kind === 1059 && recipient(t.event) === pubkey).map(t => t.event!); }
  private send(item: { device: string; filters: readonly Filter[]; handlers: RelayHandlers; seen: Set<string> }, event: Event) {
    if (!item.seen.has(event.id) && item.filters.some(f => matchFilter(f, event))) {
      item.seen.add(event.id); item.handlers.onevent(structuredClone(event), network.readRelays[0]);
    }
  }
  /** NIP-01 addressable ordering: latest timestamp, lowest id on a tie. */
  private retain(event: Event) {
    if (event.kind === 30078) {
      const d = event.tags.find(t => t[0] === 'd')?.[1] ?? '';
      const previous = [...this.events.values()].find(e => e.kind === event.kind && e.pubkey === event.pubkey && (e.tags.find(t => t[0] === 'd')?.[1] ?? '') === d);
      if (previous && order(previous, event) <= 0) return false;
      if (previous) this.events.delete(previous.id);
    } else if (this.events.has(event.id)) return false;
    this.events.set(event.id, structuredClone(event)); return true;
  }
  page(device: string, filter: Filter): Event[] {
    this.traffic.push({ device, frame: 'REQ', filter: structuredClone(filter) });
    return [...this.events.values()].filter(e => matchFilter(filter, e)).sort(order).slice(0, filter.limit ?? Infinity).map(e => structuredClone(e));
  }
  /** Auth mode crosses the real pinned relay adapter rather than simulating auth success. */
  private authenticatedRelay(device: string, endpoints: readonly string[], options: Parameters<NonNullable<VaultEngineDeps['relayFactory']>>[1]) {
    const net = this;
    class AuthSocket {
      static OPEN = 1;
      readyState = 0;
      onopen: (() => void) | null = null;
      onclose: ((event: { message: string }) => void) | null = null;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: ((event: { message: string }) => void) | null = null;
      private authenticated = false;
      private challenged = false;
      private readonly subscriptions = new Map<string, { device: string; filters: readonly Filter[]; handlers: RelayHandlers; seen: Set<string> }>();
      constructor(readonly url: string) { queueMicrotask(() => { this.readyState = 1; this.onopen?.(); }); }
      frame(...frame: unknown[]) { if (this.readyState === 1) this.onmessage?.({ data: JSON.stringify(frame) } as MessageEvent); }
      send(message: string) {
        const frame = JSON.parse(message) as unknown[];
        queueMicrotask(() => {
          if (this.readyState !== 1) return;
          if (frame[0] === 'AUTH') {
            const event = frame[1] as Event;
            this.authenticated = verifyEvent(structuredClone(event)) && event.kind === 22242 && event.content === '' &&
              event.tags.some(t => t[0] === 'relay' && t[1] === this.url) && event.tags.some(t => t[0] === 'challenge' && t[1] === `acceptance:${device}`);
            net.traffic.push({ device, frame: 'AUTH', auth: structuredClone(event) });
            this.frame('OK', event.id, this.authenticated, this.authenticated ? '' : 'restricted: invalid auth');
            return;
          }
          if (frame[0] === 'CLOSE') {
            const sub = this.subscriptions.get(String(frame[1]));
            if (sub) net.subscribers.delete(sub);
            this.subscriptions.delete(String(frame[1])); return;
          }
          if (!this.authenticated) {
            if (!this.challenged) { this.challenged = true; this.frame('AUTH', `acceptance:${device}`); }
            if (frame[0] === 'REQ') this.frame('CLOSED', frame[1], 'auth-required: login');
            if (frame[0] === 'EVENT') this.frame('OK', (frame[1] as Event).id, false, 'auth-required: login');
            return;
          }
          if (frame[0] === 'REQ') {
            const id = String(frame[1]), filters = frame.slice(2) as Filter[];
            const old = this.subscriptions.get(id); if (old) net.subscribers.delete(old);
            const item = { device, filters, seen: new Set<string>(), handlers: { onevent: (event: Event) => this.frame('EVENT', id, event) } };
            this.subscriptions.set(id, item); net.subscribers.add(item);
            for (const filter of filters) for (const event of net.page(device, filter)) net.send(item, event);
            net.traffic.push({ device, frame: 'EOSE' }); this.frame('EOSE', id);
          } else if (frame[0] === 'EVENT') {
            const event = frame[1] as Event;
            if (!verifyEvent(structuredClone(event))) { this.frame('OK', event.id, false, 'invalid: signature'); return; }
            net.traffic.push({ device, frame: 'EVENT', event: structuredClone(event) });
            if (net.retain(event)) for (const item of [...net.subscribers]) net.send(item, event);
            net.traffic.push({ device, frame: 'OK', event: structuredClone(event) }); this.frame('OK', event.id, true, '');
          }
        });
      }
      close() {
        for (const sub of this.subscriptions.values()) net.subscribers.delete(sub);
        this.subscriptions.clear(); this.readyState = 3; this.onclose?.({ message: 'closed' });
      }
    }
    const relay = new VaultRelay(endpoints, { ...options, fetch: async () => Response.json({ vault: true, limitation: { auth_required: true } }) });
    // VaultRelay opens SDK connections lazily. Scope the SDK's global constructor
    // override to each synchronous entry, so A and B capture different sockets.
    const enter = <T>(work: () => T): T => {
      useWebSocketImplementation(AuthSocket);
      try { return work(); } finally { useWebSocketImplementation(globalThis.WebSocket); }
    };
    return { endpoints: relay.endpoints, subscribe: (...args: Parameters<VaultRelay['subscribe']>) => enter(() => relay.subscribe(...args)),
      backfill: (...args: Parameters<VaultRelay['backfill']>) => enter(() => relay.backfill(...args)),
      publish: (event: Event) => enter(() => relay.publish(event)), retry: (event: Event) => enter(() => relay.retry(event)), stop: () => relay.stop() };
  }
  relayFactory(device: string): NonNullable<VaultEngineDeps['relayFactory']> {
    return (endpoints, options) => {
      if (this.authRequired) return this.authenticatedRelay(device, endpoints, options);
      const abort = new AbortController();
      const own = new Set<() => void>();
      const check = () => { if (abort.signal.aborted) throw new VaultError('CANCELLED'); };
      const publish = async (event: Event): Promise<RelayPublishResult> => {
        check(); if (!verifyEvent(structuredClone(event))) throw new VaultError('CRYPTO');
        this.traffic.push({ device, frame: 'EVENT', event: structuredClone(event) });
        if (this.retain(event)) for (const item of [...this.subscribers]) this.send(item, event);
        // Relay has stored the event; kill the connection before the OK arrives.
        const gate = isHead(event) ? this.takeGate(device, 'HEAD') : event.kind === 1059 ? this.takeGate(device, 'WRAP') : undefined;
        if (gate) { gate.event = structuredClone(event); await gate.wait(abort.signal); }
        check(); this.traffic.push({ device, frame: 'OK', event: structuredClone(event) });
        return { event, durable: true, degraded: false, outcomes: endpoints.map(relay => ({ relay, status: 'accepted', reason: '' })) };
      };
      return { endpoints, publish, retry: publish,
        subscribe: (filters, handlers) => {
          check(); const item = { device, filters: structuredClone(filters), handlers, seen: new Set<string>() };
          const replay = () => {
            for (const filter of filters) for (const event of this.page(device, filter)) this.send(item, event);
            this.traffic.push({ device, frame: 'EOSE' }); endpoints.forEach(e => handlers.oneose?.(e));
          };
          this.subscribers.add(item);
          let closed = false;
          const close = () => { closed = true; this.subscribers.delete(item); own.delete(close); };
          own.add(close); queueMicrotask(() => { if (!closed && !abort.signal.aborted) replay(); });
          return { close, reconnect: async () => { check(); if (!closed) replay(); } };
        },
        backfill: async (filters, handlers) => {
          check(); const seen = new Set<string>();
          for (const filter of filters) {
            let until = filter.until, limit = 2;
            for (;;) {
              const page = this.page(device, { ...filter, until, limit });
              for (const event of page) if (!seen.has(event.id)) { seen.add(event.id); handlers.onevent(event, endpoints[0]); }
              if (page.length < limit) break;
              const oldest = page[page.length - 1].created_at;
              // Inclusive until: widen ties rather than skip events at the boundary.
              if (until === oldest) limit *= 2; else { until = oldest; limit = 2; }
            }
          }
          check(); this.traffic.push({ device, frame: 'EOSE' }); endpoints.forEach(e => handlers.oneose?.(e));
        },
        stop: () => { abort.abort(); for (const close of [...own]) close(); },
      };
    };
  }
  blossomFactory(device: string): NonNullable<VaultEngineDeps['blossomFactory']> {
    return (endpoint, options) => new VaultBlossom(endpoint, { ...options, now: () => this.now, fetch: this.blossomFetch(device) });
  }
  blossomFetch(device: string): typeof fetch {
    return async (input, init) => {
      const url = new URL(String(input)), method = init?.method ?? 'GET', headers = new Headers(init?.headers);
      const address = method === 'PUT' ? headers.get('x-sha-256')! : url.pathname.slice(1);
      if (method === 'PUT') {
        let auth: Event;
        try { auth = JSON.parse(atob(headers.get('authorization')!.replace(/^Nostr /, ''))); } catch { return new Response(null, { status: 401 }); }
        const body = new Uint8Array(await new Response(init?.body).arrayBuffer());
        if (url.pathname !== '/upload' || !verifyEvent(structuredClone(auth)) || auth.kind !== 24242 || auth.created_at > this.now ||
            !auth.tags.some(t => t[0] === 't' && t[1] === 'upload') || !auth.tags.some(t => t[0] === 'x' && t[1] === address) ||
            !auth.tags.some(t => t[0] === 'expiration' && Number(t[1]) > this.now) || hashAddress(body) !== address) return new Response(null, { status: 401 });
        this.traffic.push({ device, frame: 'PUT', address, auth: structuredClone(auth) });
        const gate = this.takeGate(device, 'PUT');
        if (gate) { gate.address = address; await gate.wait(init!.signal!); }
        if (init?.signal?.aborted) throw new DOMException('Request aborted', 'AbortError');
        this.objects.set(address, body);
        return Response.json({ sha256: address, size: body.length }, { headers: { 'x-sha-256': address } });
      }
      if (method !== 'GET' && method !== 'HEAD') return new Response(null, { status: 405 });
      let auth: Event | undefined;
      if (this.authRequired) {
        try { auth = JSON.parse(atob(headers.get('authorization')!.replace(/^Nostr /, ''))); } catch { return new Response(null, { status: 401, headers: { 'WWW-Authenticate': 'Nostr' } }); }
        if (!auth || !verifyEvent(structuredClone(auth)) || auth.kind !== 24242 || auth.created_at > this.now ||
            !auth.tags.some(t => t[0] === 't' && t[1] === 'get') || !auth.tags.some(t => t[0] === 'x' && t[1] === address) ||
            !auth.tags.some(t => t[0] === 'expiration' && Number(t[1]) > this.now)) return new Response(null, { status: 403 });
      }
      this.traffic.push({ device, frame: method, address, ...(auth ? { auth: structuredClone(auth) } : {}) });
      const bytes = this.objects.get(address);
      if (!bytes) return new Response(null, { status: 404 });
      return new Response(method === 'HEAD' ? null : new Uint8Array(bytes), { headers: { 'content-length': String(bytes.length) } });
    };
  }
}

export async function device(net: AcceptanceNetwork, name: string, identity = signer(1), seed = 1) {
  const fs = new MemoryFS(), secretValues = new Map<string, string>();
  const secrets = { get: async (key: string) => secretValues.get(key) ?? null, set: async (key: string, value: string) => { secretValues.set(key, value); }, delete: async (key: string) => { secretValues.delete(key); } };
  // The engine has a fixed production DB name; namespace at the injected IDB boundary.
  const databaseName = `sv16:${name}`;
  const factory = new Proxy(net.database, { get(target, property) {
    if (property === 'open') return (_name: string, version?: number) => target.open(databaseName, version);
    const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value;
  } });
  const pubkey = await identity.getPublicKey() as VaultSession['accountPubkey'];
  const session: VaultSession = { accountPubkey: pubkey, signer: identity, notebookPath: '/notebook', fs, secrets, networkDefaults: network,
    editorBarrier: { enter: async () => ({ flushedHashes: new Map(), release() {} }) } };
  let state = seed;
  const deps: VaultEngineDeps = { clock: () => net.now, rng: length => Uint8Array.from({ length }, () => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state & 255;
  }), relayFactory: net.relayFactory(name), blossomFactory: net.blossomFactory(name), idbFactory: () => factory,
    workerFactory: () => new LocalWorker(), lockProvider: { request: (async (_name: string, _options: unknown, callback: (lock: Lock) => unknown) => callback({ name: _name, mode: 'exclusive' } as Lock)) as LockManager['request'] } };
  const engines: HeadlessVaultEngine[] = [];
  const start = async () => { const e = new HeadlessVaultEngine(deps); engines.push(e); await e.start(session); return e; };
  const mkdir = async (path: string) => { let prefix = ''; for (const part of path.split('/').filter(Boolean)) { prefix += '/' + part; await fs.createFolder(prefix); } };
  const openStore = async () => { const store = new VaultStore({ accountPubkey: pubkey, secrets, idbFactory: factory }); await store.start(); return store; };
  const registry = (engine: HeadlessVaultEngine): MountRegistry => ({ getMounts: () => snapshot(engine).vaults.flatMap(v => v.mount ? [v.mount] : []) });
  return { name, pubkey, fs, identity, secretValues, databaseName, start, mkdir, registry, openStore, stop: async () => { await Promise.all(engines.map(e => e.stop())); } };
}
export type AcceptanceDevice = Awaited<ReturnType<typeof device>>;
