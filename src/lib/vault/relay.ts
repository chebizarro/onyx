import { verifyEvent, type Event, type Filter } from 'nostr-tools';
import type { NostrSigner } from '../nostr/signer';
import { Relay, Subscription } from 'nostr-tools/relay';
import { VaultError } from './errors';
import { boundedEvent, boundedTextBytes } from './ingress';
import { VAULT_MAX_URL, VAULT_RELAY_MAX_FRAME_BYTES, VAULT_INGRESS_MAX_QUEUED_BYTES, VAULT_INGRESS_MAX_QUEUED_ITEMS, VAULT_RELAY_MAX_PAGE_EVENTS } from './protocol';

/** Browser-side URL policy. DNS resolution/rebinding still depends on the runtime. */
export function validatePublicEndpoint(value: string, protocol: 'https:' | 'wss:'): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new VaultError('ARG'); }
  const host = url.hostname.toLowerCase().replace(/\.+$/, '');
  if (value.length > VAULT_MAX_URL || url.protocol !== protocol || url.username || url.password ||
      url.search || url.hash || !host.includes('.') && !host.startsWith('[') ||
      /(^|\.)(localhost|local|localdomain|internal|lan|home|arpa|onion)$/.test(host)) {
    throw new VaultError('UNSUPPORTED');
  }
  if (host.startsWith('[')) {
    // Only global-unicast IPv6; mapped IPv4, ULA, link-local and multicast fail closed.
    const [first, second] = host.slice(1, -1).split(':').map(part => parseInt(part || '0', 16));
    if (!/^\[[23][0-9a-f]{3}:/.test(host) || first === 0x2001 && (second < 0x200 || second === 0xdb8) ||
        first === 0x2002 || first === 0x3fff) throw new VaultError('UNSUPPORTED');
  } else if (/^[\d.]+$/.test(host)) {
    const [a, b, c] = host.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 ||
        a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 ||
        a === 172 && b >= 16 && b <= 31 || a === 192 && (b === 168 || b === 0 || b === 88 && c === 99) ||
        a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) ||
        a === 203 && b === 0 && c === 113) throw new VaultError('UNSUPPORTED');
  }
  return url.href;
}

export type RelayPublishOutcome =
  | { relay: string; status: 'accepted'; reason: string }
  | { relay: string; status: 'rejected'; reason: string; error?: VaultError }
  | { relay: string; status: 'unknown'; error: VaultError };
export interface RelayPublishResult {
  event: Event;
  outcomes: readonly RelayPublishOutcome[];
  durable: boolean;
  degraded: boolean;
  /** Remaining replicas continue after the first OK; journals can retain late outcomes. */
  settled?: Promise<readonly RelayPublishOutcome[]>;
}
export interface RelayHandlers {
  onevent(event: Event, relay: string): void;
  oneose?(relay: string): void;
  onclose?(relay: string, reason: string): void;
  onerror?(relay: string, error: VaultError): void;
  onnotice?(relay: string, notice: string): void;
}
export interface VaultRelaySubscription {
  close(): void;
  /** Explicit retry, preserving the original historical filters and deduplication. */
  reconnect(): Promise<void>;
}

function restrictedRelay(reason: string): boolean {
  return /^restricted:/.test(reason);
}
class NegativeOK extends Error {}

/** First complete answer, or failure only after every source failed. */
export function firstSufficient<T>(tasks: readonly Promise<T>[]): Promise<T> {
  return new Promise((resolve, reject) => {
    if (!tasks.length) { reject(new VaultError('NETWORK')); return; }
    let remaining = tasks.length;
    for (const task of tasks) void task.then(resolve, error => { if (!--remaining) reject(error); });
  });
}

/** Resolve on >=1 actual positive OK, not socket send or a timeout. */
export function firstOK(event: Event, tasks: readonly Promise<RelayPublishOutcome>[]): Promise<RelayPublishResult> {
  return new Promise(resolve => {
    const outcomes: RelayPublishOutcome[] = [];
    let finish!: (outcomes: readonly RelayPublishOutcome[]) => void;
    const settled = new Promise<readonly RelayPublishOutcome[]>(yes => { finish = yes; });
    const result = () => ({ event, outcomes: [...outcomes], durable: outcomes.some(o => o.status === 'accepted'),
      degraded: outcomes.length < tasks.length || outcomes.some(o => o.status !== 'accepted'), settled });
    if (!tasks.length) { finish([]); resolve(result()); }
    for (const task of tasks) void task.catch(error => ({ relay: '', status: 'unknown' as const,
      error: error instanceof VaultError ? error : new VaultError('NETWORK') })).then(outcome => {
      outcomes.push(outcome);
      if (outcomes.length === tasks.length) finish([...outcomes]);
      if (outcome.status === 'accepted' || outcomes.length === tasks.length) resolve(result());
    });
  });
}

/** Fail loudly if the exact pinned SDK no longer provides the compatibility hooks. */
export function assertPinnedRelayCompatibility(): void {
  if (typeof Relay.prototype._onmessage !== 'function' || typeof Relay.prototype.send !== 'function' || typeof Relay.prototype.prepareSubscription !== 'function'
    || [Subscription.prototype.fire, Subscription.prototype.receivedEose, Subscription.prototype.close].some(method => typeof method !== 'function')) {
    throw new Error('nostr-tools 2.19.4 relay compatibility hooks changed; re-audit wire EOSE/OK/AUTH before upgrading');
  }
}

/** All private SDK access and AUTH frames are isolated here. In 2.19.4,
 * auth() swallows signer rejection and caches one promise across new challenges;
 * it cannot provide bounded, cancellable challenge rotation. Use send() for AUTH
 * and observe its actual OK here. Normal EVENT/REQ/EOSE/OK routing stays in the SDK.
 * The SDK also has no wire-only EOSE option and conflates negative OK/transport errors.
 * See https://github.com/nbd-wtf/nostr-tools/blob/v2.19.4/abstract-relay.ts.
 */
function createPinnedObservedRelay(url: string, options: VaultRelayOptions, failed: (error: VaultError) => void): Relay {
  assertPinnedRelayCompatibility();
  const relay = new Relay(url, { enableReconnect: false, enablePing: false });
  // Pinned SDK queue hook: release the reservation when its single consumer
  // dequeues, not at a microtask boundary (the SDK yields between messages).
  const queue = (relay as unknown as { incomingMessageQueue: { dequeue(): string | null } }).incomingMessageQueue;
  if (!queue || typeof queue.dequeue !== 'function') throw new Error('nostr-tools 2.19.4 inbound queue hook changed; re-audit ingress bounds');
  const dequeue = queue.dequeue.bind(queue);
  let queuedBytes = 0, queuedItems = 0;
  queue.dequeue = () => {
    const raw = dequeue();
    if (raw !== null) { queuedBytes -= boundedTextBytes(raw, VAULT_RELAY_MAX_FRAME_BYTES); queuedItems--; }
    return raw;
  };
  const negativeOK = new Map<string, string | undefined>();
  const active = new Map<(generation: number) => void, (reason?: string) => void>();
  type Auth = { latest?: string; eventId?: string; generation: number; attempts: number; done: boolean;
    promise: Promise<void>; resolve(): void; reject(error: VaultError): void; timer: ReturnType<typeof setTimeout> };
  let auth: Auth | undefined;
  let challenge: string | undefined;
  let generation = 0;
  let dead = false;
  let signing = false;
  const reset = () => {
    dead = true;
    while (queue.dequeue() !== null) { /* Discard unprocessed frames from this connection. */ }
    if (auth) {
      clearTimeout(auth.timer);
      if (!auth.done) auth.reject(new VaultError('NETWORK', { operation: 'subscribe' }));
    }
    auth = undefined;
    for (const close of [...active.values()]) close('relay connection closed');
  };
  relay.onclose = () => { if (!dead) failed(new VaultError('NETWORK', { operation: 'subscribe' })); reset(); };
  const fail = (error: VaultError) => {
    if (dead) return;
    if (auth && !auth.done) { auth.done = true; auth.reject(error); }
    failed(error); reset(); relay.close();
  };
  const beginAuth = (): Auth => {
    let resolve!: () => void, reject!: (error: VaultError) => void;
    const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
    // A challenge can arrive without an operation currently awaiting authentication.
    void promise.catch(() => {});
    return auth = { generation: ++generation, attempts: 0, done: false, promise, resolve, reject,
      timer: setTimeout(() => fail(new VaultError('AUTH', { operation: 'subscribe' })), relay.publishTimeout) };
  };
  const waitAuthentication = (): Promise<void> => {
    if (dead) return Promise.reject(new VaultError('AUTH', { operation: 'subscribe' }));
    return (auth ?? beginAuth()).promise;
  };
  const drive = async (): Promise<void> => {
    const attempt = auth, c = attempt?.latest;
    if (dead || signing || !attempt || attempt.done || !c || attempt.eventId) return;
    if (!options.signer || attempt.attempts >= 3) { fail(new VaultError('AUTH', { operation: 'subscribe' })); return; }
    signing = true; attempt.attempts++;
    try {
      const pubkey = options.accountPubkey ?? await options.signer.getPublicKey();
      if (dead || auth !== attempt || attempt.latest !== c) return;
      const template = { kind: 22242, created_at: Math.floor(Date.now() / 1000), content: '',
        tags: [['relay', relay.url], ['challenge', c]] };
      // Own plain data before verification: strip SDK verification-cache symbols and
      // prevent signer-retained mutations from changing the validated wire payload.
      const event: Event = JSON.parse(JSON.stringify(await options.signer.signEvent(structuredClone(template))));
      if (dead || auth !== attempt || attempt.latest !== c || !relay.connected) return;
      if (!verifyEvent(event) || event.kind !== template.kind || event.created_at !== template.created_at ||
          event.content !== template.content || JSON.stringify(event.tags) !== JSON.stringify(template.tags) || event.pubkey !== pubkey) {
        throw new VaultError('AUTH');
      }
      attempt.eventId = event.id;
      await relay.send(JSON.stringify(['AUTH', event]));
    } catch { if (!dead && auth === attempt && attempt.latest === c) fail(new VaultError('AUTH', { operation: 'subscribe' })); }
    finally {
      signing = false;
      // Coalesce rotations while one signer call is outstanding. The absolute
      // exchange deadline and three-signature budget are never reset by rotation.
      if (!dead && auth && !auth.done && !auth.eventId) void drive();
    }
  };
  const onmessage = relay._onmessage.bind(relay);
  relay._onmessage = (message: MessageEvent): void => {
    if (dead) return;
    let bytes: number;
    try {
      if (typeof message.data !== 'string') throw new VaultError('TOO_LARGE');
      bytes = boundedTextBytes(message.data, VAULT_RELAY_MAX_FRAME_BYTES);
      if (queuedItems >= VAULT_INGRESS_MAX_QUEUED_ITEMS || queuedBytes + bytes > VAULT_INGRESS_MAX_QUEUED_BYTES) throw new VaultError('BUDGET');
    } catch (error) { fail(error instanceof VaultError ? error : new VaultError('TOO_LARGE')); return; }
    try {
      const frame: unknown = JSON.parse(message.data);
      if (!Array.isArray(frame)) return;
      // Reject before the SDK queues/parses/hashes or verifies an EVENT.
      if (Array.isArray(frame) && frame[0] === 'EVENT') boundedEvent(frame[2]);
      if (Array.isArray(frame)) {
        if (frame[0] === 'AUTH' && typeof frame[1] === 'string' && frame[1]) {
          if (!dead && challenge !== frame[1]) {
            challenge = frame[1];
            const attempt = !auth || auth.done ? beginAuth() : auth;
            attempt.latest = frame[1]; attempt.eventId = undefined;
            void drive();
          }
          return;
        }
        if (frame[0] === 'OK' && auth?.eventId && auth.eventId === frame[1]) {
          if (auth.done) return;
          if (frame[2] !== true) { fail(new VaultError(restrictedRelay(String(frame[3])) ? 'UNSUPPORTED' : 'AUTH', { operation: 'subscribe' })); return; }
          clearTimeout(auth.timer); auth.done = true; auth.resolve();
          options.onAuthenticated?.(url);
          // New IDs retire all old CLOSED/EOSE responses, including SDK-queued ones.
          for (const replay of [...active.keys()]) replay(auth.generation);
          return;
        }
        if (frame[0] === 'OK' && typeof frame[1] === 'string' && frame[2] === false && typeof frame[3] === 'string' && negativeOK.has(frame[1])) {
          negativeOK.set(frame[1], frame[3]);
        }
      }
    } catch (error) {
      if (error instanceof VaultError) { fail(error); return; }
      // Malformed JSON carries no useful protocol progress and is never queued.
      return;
    }
    queuedBytes += bytes; queuedItems++;
    onmessage(message);
  };
  relay.subscribe = (filters, params): Subscription => {
    const original = structuredClone(filters);
    let current: Subscription;
    let retire = () => {};
    let closed = false;
    let replayed = 0;
    const close = (reason?: string) => {
      if (closed) return;
      closed = true; active.delete(replay); retire();
      if (reason && reason !== 'closed by caller') params.onclose?.(reason);
    };
    const install = () => {
      current = relay.prepareSubscription(structuredClone(original), { ...params, id: undefined, onclose: undefined });
      const sub = current, receivedEose = sub.receivedEose.bind(sub), nativeClose = sub.close.bind(sub);
      retire = () => {
        // 2.19.4 close() does not clear its EOSE timer. No synthetic EOSE.
        sub.oneose = undefined; receivedEose(); nativeClose();
      };
      sub.close = reason => {
        if (reason?.startsWith('auth-required:') && !closed) {
          retire();
          if (auth?.done && replayed === auth.generation) { close(reason); return; }
          void waitAuthentication().then(() => { if (!closed && auth) replay(auth.generation); }, () => {});
        } else close(reason);
      };
      // fire() binds this method into its timer; real EOSE stays SDK-queue ordered.
      sub.receivedEose = () => {};
      try { sub.fire(); } finally { sub.receivedEose = receivedEose; }
    };
    const replay = (authGeneration: number) => {
      if (closed || replayed === authGeneration) return;
      replayed = authGeneration; retire(); install();
    };
    active.set(replay, close); install();
    // The first Subscription is the stable external close handle. Its close method
    // routes to the current physical subscription after fresh-ID replacements.
    return current!;
  };
  const publish = relay.publish.bind(relay);
  const publishAttempt = async (event: Event): Promise<string> => {
    negativeOK.set(event.id, undefined);
    try { return await publish(event); }
    catch (error) {
      const reason = negativeOK.get(event.id);
      if (reason !== undefined) throw new NegativeOK(reason);
      throw error;
    } finally { negativeOK.delete(event.id); }
  };
  relay.publish = async (event: Event): Promise<string> => {
    try { return await publishAttempt(event); }
    catch (error) {
      if (!(error instanceof NegativeOK) || !error.message.startsWith('auth-required:')) throw error;
      // Wait for BOTH original refusal and AUTH success. The normal SDK publish
      // path gives the exact-event retry its own acknowledgement deadline.
      await waitAuthentication();
      return publishAttempt(event);
    }
  };
  const connect = relay.connect.bind(relay);
  relay.connect = () => {
    if (!relay.connected && dead) { dead = false; challenge = undefined; auth = undefined; }
    return connect();
  };
  const close = relay.close.bind(relay);
  relay.close = () => { reset(); close(); };
  return relay;
}

export interface VaultRelayOptions {
  signer?: NostrSigner;
  /** Established session identity; auth must not follow a changing signer identity. */
  accountPubkey?: string;
  onAuthenticated?: (url: string) => void;
  onPrivateVaultService?: (url: string) => void;
  fetch?: typeof fetch;
  connectionTimeoutMs?: number;
  publishTimeoutMs?: number;
  backfillTimeoutMs?: number;
  pageSize?: number;
  maxPageSize?: number;
}

export type VaultRelayClient = Pick<VaultRelay, keyof VaultRelay>;

/** Endpoint-set facade. All physical connections belong to the URL-keyed clients. */
export function combineRelays(clients: readonly VaultRelayClient[]): VaultRelayClient {
  const publish = (event: Event) => firstOK(event, clients.map(async client => {
    try { return (await client.publish(event)).outcomes[0]; }
    catch (error) { return { relay: client.endpoints[0], status: 'unknown' as const,
      error: error instanceof VaultError ? error : new VaultError('NETWORK', { operation: 'publish' }) }; }
  }));
  return {
    endpoints: clients.flatMap(client => [...client.endpoints]), publish, retry: publish,
    subscribe(filters, handlers) {
      const seen = new Set<string>();
      const subscriptions = clients.map(client => client.subscribe(filters, { ...handlers, onevent: (event, url) => {
        if (seen.has(event.id)) return; seen.add(event.id); handlers.onevent(event, url);
      } }));
      return { close: () => subscriptions.forEach(sub => sub.close()), reconnect: async () => { await Promise.all(subscriptions.map(sub => sub.reconnect())); } };
    },
    async backfill(filters, handlers, signal) {
      const seen = new Set<string>();
      await firstSufficient(clients.map(client => client.backfill(filters, { ...handlers, onevent: (event, url) => {
        if (seen.has(event.id)) return; seen.add(event.id); handlers.onevent(event, url);
      } }, signal)));
    },
    stop: () => clients.forEach(client => client.stop()),
  };
}

export class VaultRelay {
  readonly endpoints: readonly string[];
  private readonly connections = new Map<string, Relay>();
  private readonly unsupported = new Set<string>();
  private readonly connectionErrors = new Map<string, VaultError>();
  private readonly connecting = new Map<string, Promise<Relay>>();
  private readonly failures = new Map<string, { attempts: number; retryAt: number }>();
  private readonly subscriptions = new Set<() => void>();
  private readonly listeners = new Set<RelayHandlers>();
  private readonly abort = new AbortController();
  private readonly publishing = new Set<string>();
  private readonly options: VaultRelayOptions & Required<Pick<VaultRelayOptions, 'connectionTimeoutMs' | 'publishTimeoutMs' | 'backfillTimeoutMs' | 'pageSize' | 'maxPageSize'>>;

  constructor(endpoints: readonly string[], options: VaultRelayOptions = {}) {
    this.endpoints = [...new Set(endpoints.map(url => validatePublicEndpoint(url, 'wss:')))];
    this.options = { connectionTimeoutMs: 10000, publishTimeoutMs: 10000, backfillTimeoutMs: 15000,
      pageSize: 256, maxPageSize: VAULT_RELAY_MAX_PAGE_EVENTS, ...options };
    if (!this.endpoints.length || [this.options.connectionTimeoutMs, this.options.publishTimeoutMs, this.options.backfillTimeoutMs, this.options.pageSize, this.options.maxPageSize].some(n => !Number.isSafeInteger(n) || n <= 0) ||
        this.options.pageSize > this.options.maxPageSize || this.options.maxPageSize > VAULT_RELAY_MAX_PAGE_EVENTS) throw new VaultError('ARG');
  }

  private cooldown(url: string, error: VaultError): void {
    if (this.abort.signal.aborted || this.unsupported.has(url)) return;
    this.connectionErrors.set(url, error);
    const previous = this.failures.get(url);
    if (previous && previous.retryAt > Date.now()) return;
    const attempts = (previous?.attempts ?? 0) + 1;
    this.failures.set(url, { attempts, retryAt: Date.now() + Math.min(5000 * 2 ** Math.min(attempts - 1, 6), 300000) });
  }
  private async connection(url: string): Promise<Relay> {
    this.check();
    if (this.unsupported.has(url)) throw new VaultError('UNSUPPORTED', { operation: 'subscribe' });
    const pending = this.connecting.get(url);
    if (pending) return this.wait(pending);
    if ((this.failures.get(url)?.retryAt ?? 0) > Date.now()) throw this.connectionErrors.get(url) ?? new VaultError('NETWORK');
    const task = this.openConnection(url);
    this.connecting.set(url, task);
    try { return await task; } finally { this.connecting.delete(url); }
  }
  private async openConnection(url: string): Promise<Relay> {
    let relay = this.connections.get(url);
    if (!relay) {
      relay = createPinnedObservedRelay(url, this.options, error => {
        this.cooldown(url, error);
        if (error.code === 'UNSUPPORTED') this.markUnsupported(url);
        else for (const listener of this.listeners) listener.onerror?.(url, error);
      });
      if (this.options.onPrivateVaultService) void this.probeInfo(url);
      relay.connectionTimeout = this.options.connectionTimeoutMs;
      relay.publishTimeout = this.options.publishTimeoutMs;
      relay.onnotice = notice => {
        for (const listener of this.listeners) listener.onnotice?.(url, notice);
        if (restrictedRelay(notice)) this.markUnsupported(url);
      };
      this.connections.set(url, relay);
    }
    const connection = relay;
    // A subscription CLOSED need not close the socket. Once its cooldown has
    // elapsed, a fresh REQ must not inherit that old connection error forever.
    this.connectionErrors.delete(url);
    try {
      await this.wait(connection.connect().then(() => {
        if (this.abort.signal.aborted) connection.close();
        this.check();
      }));
    } catch (error) {
      const failure = error instanceof VaultError ? error : new VaultError('NETWORK', { operation: 'subscribe' });
      this.cooldown(url, failure);
      this.connections.delete(url); connection.close();
      throw failure;
    }
    this.check();
    if (this.unsupported.has(url)) throw new VaultError('UNSUPPORTED', { operation: 'subscribe' });
    const failure = this.connectionErrors.get(url);
    if (failure) throw failure;
    if (!relay.connected) throw new VaultError('NETWORK', { operation: 'subscribe' });
    this.failures.delete(url);
    return relay;
  }

  private async probeInfo(url: string): Promise<void> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    this.abort.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, this.options.connectionTimeoutMs);
    try {
      const response = await (this.options.fetch ?? fetch)(url.replace(/^wss:/, 'https:'), {
        headers: { Accept: 'application/nostr+json' }, credentials: 'omit', redirect: 'error', signal: controller.signal,
      });
      if (response.ok) {
        // NIP-11 is only an informational hint, never an admission decision.
        const reader = response.body?.getReader();
        if (!reader) return;
        const cancel = () => { void reader.cancel().catch(() => {}); };
        controller.signal.addEventListener('abort', cancel, { once: true });
        let text = '', size = 0;
        const decoder = new TextDecoder('utf-8', { fatal: true });
        try {
          for (;;) {
            const { value, done } = await reader.read();
            if (done || controller.signal.aborted) break;
            size += value.length;
            if (size > 65536) { await reader.cancel(); return; }
            text += decoder.decode(value, { stream: true });
          }
          text += decoder.decode();
        } finally { controller.signal.removeEventListener('abort', cancel); reader.releaseLock(); }
        if (controller.signal.aborted) return;
        const info = JSON.parse(text);
        if (!this.abort.signal.aborted && info?.vault === true && info?.limitation?.auth_required === true) this.options.onPrivateVaultService?.(url);
      }
    } catch { /* Discovery failure does not exclude an otherwise working endpoint. */ }
    finally { clearTimeout(timer); this.abort.signal.removeEventListener('abort', abort); controller.abort(); }
  }

  private markUnsupported(url: string): void {
    if (this.unsupported.has(url)) return;
    this.unsupported.add(url);
    this.connectionErrors.set(url, new VaultError('UNSUPPORTED', { operation: 'subscribe' }));
    for (const listener of this.listeners) listener.onerror?.(url, new VaultError('UNSUPPORTED', { operation: 'subscribe' }));
    this.connections.get(url)?.close();
  }
  private check(signal?: AbortSignal): void {
    if (this.abort.signal.aborted || signal?.aborted) throw new VaultError('CANCELLED');
  }
  private wait<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        this.abort.signal.removeEventListener('abort', cancel);
        signal?.removeEventListener('abort', cancel);
      };
      const cancel = () => { cleanup(); reject(new VaultError('CANCELLED')); };
      this.abort.signal.addEventListener('abort', cancel, { once: true });
      signal?.addEventListener('abort', cancel, { once: true });
      if (this.abort.signal.aborted || signal?.aborted) cancel();
      promise.then(value => { cleanup(); resolve(value); }, error => { cleanup(); reject(error); });
    });
  }

  subscribe(filters: readonly Filter[], handlers: RelayHandlers): VaultRelaySubscription {
    this.check();
    if (!filters.length) throw new VaultError('ARG');
    const original = structuredClone([...filters]);
    const seen = new Set<string>();
    const active = new Map<string, Subscription>();
    let closed = false;
    const generations = new Map<string, number>();
    const timers = new Map<string, ReturnType<typeof setTimeout>>();
    this.listeners.add(handlers);
    const retry = (url: string) => {
      if (closed || this.abort.signal.aborted || this.unsupported.has(url) || timers.has(url)) return;
      const delay = Math.max(1, (this.failures.get(url)?.retryAt ?? Date.now() + 5000) - Date.now());
      timers.set(url, setTimeout(() => { timers.delete(url); void connectOne(url); }, delay));
    };
    const connectOne = async (url: string) => {
      const current = (generations.get(url) ?? 0) + 1; generations.set(url, current);
      const valid = () => !closed && current === generations.get(url);
      try {
        const relay = await this.connection(url);
        if (!valid()) return;
        const sub = relay.subscribe(structuredClone(original), {
          onevent: event => {
            if (!valid() || seen.has(event.id)) return;
            seen.add(event.id); handlers.onevent(event, url);
          },
          oneose: () => { if (valid()) handlers.oneose?.(url); },
          onclose: reason => {
            if (!valid()) return;
            active.delete(url); handlers.onclose?.(url, reason);
            if (restrictedRelay(reason)) this.markUnsupported(url);
            else {
              const error = this.connectionErrors.get(url) ?? new VaultError(reason.startsWith('auth-required:') ? 'AUTH' : 'NETWORK', { operation: 'subscribe' });
              this.cooldown(url, error); handlers.onerror?.(url, error); retry(url);
            }
          },
        });
        active.set(url, sub);
      } catch (error) {
        if (valid()) {
          const failure = error instanceof VaultError ? error : new VaultError('NETWORK', { operation: 'subscribe' });
          if (!['UNSUPPORTED', 'CANCELLED'].includes(failure.code)) this.cooldown(url, failure);
          handlers.onerror?.(url, failure); retry(url);
        }
      }
    };
    const connect = async () => {
      if (closed) throw new VaultError('CANCELLED');
      for (const url of this.endpoints) generations.set(url, (generations.get(url) ?? 0) + 1);
      for (const timer of timers.values()) clearTimeout(timer); timers.clear();
      for (const sub of active.values()) sub.close(); active.clear();
      await Promise.all(this.endpoints.map(connectOne));
    };
    const close = () => {
      if (closed) return;
      closed = true;
      for (const timer of timers.values()) clearTimeout(timer); timers.clear();
      for (const sub of active.values()) sub.close(); active.clear();
      this.listeners.delete(handlers);
      this.subscriptions.delete(close);
    };
    this.subscriptions.add(close);
    void connect();
    return { close, reconnect: connect };
  }

  /** EOSE-complete, per-relay history. Inclusive boundaries never skip a timestamp. */
  async backfill(filters: readonly Filter[], handlers: RelayHandlers, signal?: AbortSignal): Promise<void> {
    this.check(signal);
    if (!filters.length) throw new VaultError('ARG');
    const seen = new Set<string>();
    const listener: RelayHandlers = { ...handlers, onevent: (event, url) => {
      if (!seen.has(event.id)) { seen.add(event.id); handlers.onevent(event, url); }
    } };
    // Each source must finish every page/filter. Other sources keep delivering
    // late history after the first complete answer; EOSE is never synthesised.
    this.listeners.add(listener);
    const tasks = this.endpoints.map(async url => {
      try {
        for (const filter of filters) {
          let until = filter.until;
          let limit = this.options.pageSize;
          for (;;) {
            this.check(signal);
            const times = await this.page(url, { ...structuredClone(filter), until, limit }, event => listener.onevent(event, url), signal);
            if (times.length < limit) break;
            const oldest = Math.min(...times);
            if (oldest === until) {
              if (limit >= this.options.maxPageSize) throw new VaultError('INCOMPLETE', { operation: 'fetch' });
              limit = Math.min(limit * 2, this.options.maxPageSize);
            } else { until = oldest; limit = this.options.pageSize; }
          }
        }
        handlers.oneose?.(url);
      } catch (error) {
        handlers.onerror?.(url, error instanceof VaultError ? error : new VaultError('NETWORK', { operation: 'fetch' }));
        throw error;
      }
    });
    void Promise.allSettled(tasks).then(() => this.listeners.delete(listener));
    await firstSufficient(tasks);
  }

  private async page(url: string, filter: Filter, receive: (event: Event) => void, signal?: AbortSignal): Promise<number[]> {
    const relay = await this.wait(this.connection(url), signal);
    this.check(signal);
    let sub: Subscription | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const times = new Map<string, number>();
    let overflow = false;
    try {
      return await this.wait(new Promise<number[]>((resolve, reject) => {
        timer = setTimeout(() => reject(new VaultError('NETWORK', { operation: 'fetch' })), this.options.backfillTimeoutMs);
        sub = relay.subscribe([filter], {
          onevent: event => {
            if (overflow || times.has(event.id)) return;
            if (times.size >= (filter.limit ?? VAULT_RELAY_MAX_PAGE_EVENTS)) {
              overflow = true; reject(new VaultError('BUDGET', { operation: 'fetch' })); return;
            }
            times.set(event.id, event.created_at); receive(event);
          },
          oneose: () => resolve([...times.values()]),
          onclose: reason => {
            if (restrictedRelay(reason)) this.markUnsupported(url);
            reject(this.connectionErrors.get(url) ?? new VaultError(reason.startsWith('auth-required:') ? 'AUTH' : 'NETWORK', { operation: 'fetch' }));
          },
        });
      }), signal);
    } finally { clearTimeout(timer); sub?.close(); }
  }

  /** Caller persists the application event first; only ephemeral AUTH is signed here. */
  async publish(event: Event): Promise<RelayPublishResult> {
    this.check();
    const exact: Event = JSON.parse(JSON.stringify(event));
    if (!verifyEvent(exact) || this.publishing.has(exact.id)) throw new VaultError('ARG', { operation: 'publish' });
    this.publishing.add(exact.id);
    try {
      const tasks = this.endpoints.map(async (url): Promise<RelayPublishOutcome> => {
        try {
          const relay = await this.connection(url);
          const reason = await this.wait(relay.publish(exact));
          return { relay: url, status: 'accepted', reason };
        } catch (error) {
          this.check();
          if (error instanceof NegativeOK) {
            if (restrictedRelay(error.message)) this.markUnsupported(url);
            return { relay: url, status: 'rejected', reason: error.message,
              ...(/^(auth-required:|restricted:)/.test(error.message) ? { error: new VaultError(restrictedRelay(error.message) ? 'UNSUPPORTED' : 'AUTH', { operation: 'publish' }) } : {}) };
          }
          return { relay: url, status: 'unknown', error: this.connectionErrors.get(url) ?? (error instanceof VaultError ? error : new VaultError('NETWORK', { operation: 'publish' })) };
        }
      });
      const result = await firstOK(exact, tasks);
      void result.settled!.then(() => this.publishing.delete(exact.id));
      this.check(); return result;
    } catch (error) { this.publishing.delete(exact.id); throw error; }
  }

  /** Retry the engine's journaled event verbatim, with no sequence/time allocation. */
  retry(event: Event): Promise<RelayPublishResult> { return this.publish(event); }

  stop(): void {
    if (this.abort.signal.aborted) return;
    this.abort.abort();
    for (const close of this.subscriptions) close();
    for (const relay of this.connections.values()) relay.close();
    this.connections.clear();
    this.listeners.clear();
  }
}
