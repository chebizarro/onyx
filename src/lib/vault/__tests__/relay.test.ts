import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, getPublicKey, verifyEvent, type Event, type Filter } from 'nostr-tools';
import type { NostrSigner } from '../../nostr/signer';
import { Relay, useWebSocketImplementation } from 'nostr-tools/relay';
import { assertPinnedRelayCompatibility, VaultRelay, validatePublicEndpoint } from '../relay';
import { NIP59_MAX_TAGS, PORTHOME_HEAD_MAX_PAYLOAD, NIP59_MAX_PAYLOAD, VAULT_RELAY_MAX_FRAME_BYTES,
  VAULT_INGRESS_MAX_QUEUED_ITEMS, VAULT_EVENT_MAX_TAG_STRING_BYTES } from '../protocol';

class ScriptedSocket {
  static OPEN = 1;
  static sockets: ScriptedSocket[] = [];
  readyState = 0;
  onopen: (() => void) | null = null;
  onclose: ((event: { message: string }) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: { message: string }) => void) | null = null;
  readonly sent: unknown[][] = [];
  constructor(readonly url: string) { ScriptedSocket.sockets.push(this); }
  open(): void { this.readyState = 1; this.onopen?.(); }
  send(frame: string): void { this.sent.push(JSON.parse(frame)); }
  frame(...frame: unknown[]): void { this.onmessage?.({ data: JSON.stringify(frame) } as MessageEvent); }
  close(): void { this.readyState = 3; this.onclose?.({ message: 'socket closed' }); }
  requests(): unknown[][] { return this.sent.filter(frame => frame[0] === 'REQ'); }
  publications(): Event[] { return this.sent.filter(frame => frame[0] === 'EVENT').map(frame => frame[1] as Event); }
}
it('fails loudly if the pinned private observation hook disappears', () => {
  expect(assertPinnedRelayCompatibility).not.toThrow();
  const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Relay.prototype), '_onmessage')!;
  const prototype = Object.getPrototypeOf(Relay.prototype);
  try {
    Object.defineProperty(prototype, '_onmessage', { ...descriptor, value: undefined });
    expect(assertPinnedRelayCompatibility).toThrow('nostr-tools 2.19.4 relay compatibility hooks changed');
  } finally { Object.defineProperty(prototype, '_onmessage', descriptor); }
});

const key = new Uint8Array(32).fill(7);
const signer = (): NostrSigner => ({ getType: () => 'local', getPublicKey: async () => getPublicKey(key),
  signEvent: vi.fn(async template => finalizeEvent(template, key)) });
const event = (time = 10, content = ''): Event => JSON.parse(JSON.stringify(
  finalizeEvent({ kind: 1, created_at: time, content, tags: [] }, key)));
// Flush only promise continuations and nostr-tools' inbound queue: no real/fake sleeps.
async function flush(): Promise<void> { for (let i = 0; i < 20; i++) await Promise.resolve(); }
const adapters: VaultRelay[] = [];
function adapter(urls = ['wss://relay.example.com'], options = {}): VaultRelay {
  const result = new VaultRelay(urls, options);
  adapters.push(result);
  return result;
}
function socketsOpen(): void { for (const socket of ScriptedSocket.sockets) if (socket.readyState === 0) socket.open(); }

beforeEach(() => {
  vi.useFakeTimers();
  ScriptedSocket.sockets = [];
  useWebSocketImplementation(ScriptedSocket);
  // Make the SDK's MessageChannel queue scheduler deterministic, not time-driven.
  vi.stubGlobal('MessageChannel', class {
    private handler = () => {};
    port1 = { addEventListener: (_: string, handler: () => void) => { this.handler = handler; },
      removeEventListener: () => {}, start: () => {} };
    port2 = { postMessage: () => { void Promise.resolve().then(() => this.handler()); } };
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const adapter of adapters.splice(0)) adapter.stop();
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  useWebSocketImplementation(globalThis.WebSocket);
});

describe('bounded untrusted relay ingress (SV-29)', () => {
  function verificationSpy(relay: VaultRelay) {
    const physical = [...(relay as unknown as { connections: Map<string, { verifyEvent(event: Event): boolean }> }).connections.values()][0];
    return vi.spyOn(physical, 'verifyEvent');
  }
  it.each(['ascii', 'utf8', 'binary'] as const)('rejects an oversized/non-text %s frame before JSON parse or SDK verification', async mode => {
    const relay = adapter(), received = vi.fn(), errors = vi.fn();
    relay.subscribe([{}], { onevent: received, onerror: errors }); socketsOpen(); await flush();
    const verify = verificationSpy(relay), parse = vi.spyOn(JSON, 'parse');
    const data = mode === 'ascii' ? 'x'.repeat(VAULT_RELAY_MAX_FRAME_BYTES + 1) :
      mode === 'utf8' ? 'é'.repeat(VAULT_RELAY_MAX_FRAME_BYTES / 2 + 1) : new Uint8Array(10);
    ScriptedSocket.sockets[0].onmessage?.({ data } as MessageEvent);
    expect(parse).not.toHaveBeenCalled(); expect(verify).not.toHaveBeenCalled();
    expect(received).not.toHaveBeenCalled(); expect(errors).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ code: 'TOO_LARGE' }));
  });

  it('rejects object-form EVENT frames instead of bypassing the SDK admission check', async () => {
    const relay = adapter(), received = vi.fn(); relay.subscribe([{}], { onevent: received }); socketsOpen(); await flush();
    const verify = verificationSpy(relay), socket = ScriptedSocket.sockets[0];
    socket.onmessage?.({ data: JSON.stringify({ 0: 'EVENT', 1: socket.requests()[0][1], 2: { ...event(), tags: Array.from({ length: NIP59_MAX_TAGS + 1 }, () => ['x']) } }) } as MessageEvent);
    await flush(); expect(verify).not.toHaveBeenCalled(); expect(received).not.toHaveBeenCalled();
  });

  it('streams history without retaining event batches and rejects a server exceeding its page limit', async () => {
    const relay = adapter(undefined, { pageSize: 2 }), received = vi.fn();
    const wave = relay.backfill([{ kinds: [1] }], { onevent: received }).catch(error => error);
    socketsOpen(); await flush(); const socket = ScriptedSocket.sockets[0], id = socket.requests()[0][1];
    socket.frame('EVENT', id, event(1)); await flush(); expect(received).toHaveBeenCalledTimes(1);
    socket.frame('EVENT', id, event(2)); await flush();
    socket.frame('EVENT', id, event(3)); await flush();
    expect(await wave).toMatchObject({ code: 'BUDGET' }); expect(received).toHaveBeenCalledTimes(2);
  });

  it.each(['total', 'content', 'tag-count', 'tag-string', 'tag-aggregate'] as const)
    ('rejects an oversized event %s before SDK verification', async mode => {
    const relay = adapter(), received = vi.fn(); relay.subscribe([{}], { onevent: received }); socketsOpen(); await flush();
    const verify = verificationSpy(relay), oversized = event();
    if (mode === 'total') oversized.content = '"'.repeat(70000);
    if (mode === 'content') { oversized.kind = 1059; oversized.content = 'x'.repeat(NIP59_MAX_PAYLOAD + 1); }
    if (mode === 'tag-count') oversized.tags = Array.from({ length: NIP59_MAX_TAGS + 1 }, () => ['x']);
    if (mode === 'tag-string') oversized.tags = [['é'.repeat(VAULT_EVENT_MAX_TAG_STRING_BYTES)]];
    if (mode === 'tag-aggregate') oversized.tags = Array.from({ length: 9 }, () => ['x'.repeat(VAULT_EVENT_MAX_TAG_STRING_BYTES)]);
    const socket = ScriptedSocket.sockets[0]; socket.frame('EVENT', socket.requests()[0][1], oversized); await flush();
    expect(verify).not.toHaveBeenCalled(); expect(received).not.toHaveBeenCalled();
  });

  it.each(['items', 'bytes'] as const)('fails the connection at queued %s capacity and discards pending work', async mode => {
    const relay = adapter(), errors = vi.fn(); relay.subscribe([{}], { onevent: () => {}, onerror: errors }); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0];
    // First message starts the SDK's single consumer. Further messages accumulate
    // until the deterministic MessageChannel scheduler is allowed to continue.
    socket.frame('NOTICE', 'first');
    const count = mode === 'items' ? VAULT_INGRESS_MAX_QUEUED_ITEMS + 1 : 9;
    for (let i = 0; i < count; i++) socket.frame('NOTICE', mode === 'items' ? 'queued' : 'x'.repeat(140000));
    expect(errors).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ code: 'BUDGET' }));
    expect(socket.readyState).toBe(3); await flush();
  });

  it('allows a maximum-size head payload with envelope headroom and preserves EOSE order', async () => {
    const relay = adapter(), order: string[] = [];
    relay.subscribe([{ kinds: [30078] }], { onevent: () => order.push('EVENT'), oneose: () => order.push('EOSE') });
    socketsOpen(); await flush(); const socket = ScriptedSocket.sockets[0];
    const head = finalizeEvent({ kind: 30078, created_at: 10, content: 'a'.repeat(PORTHOME_HEAD_MAX_PAYLOAD), tags: [['d', 'porthome/v2/' + 'a'.repeat(64)]] }, key);
    socket.frame('EVENT', socket.requests()[0][1], head); socket.frame('EOSE', socket.requests()[0][1]); await flush();
    expect(order).toEqual(['EVENT', 'EOSE']);
  });
});

describe('first-sufficient history and connection lifecycle (SV-27)', () => {
  it('finishes a wave at the first complete EOSE, before a dead relay even connects; late history still arrives', async () => {
    const relay = adapter(['wss://fast.example.com', 'wss://dead.example.com']);
    const received = vi.fn(), eose = vi.fn(); let done = false;
    const wave = relay.backfill([{ kinds: [1] }], { onevent: received, oneose: eose }).then(() => { done = true; });
    const [fast, dead] = ScriptedSocket.sockets;
    fast.open(); await flush(); expect(done).toBe(false);
    fast.frame('EVENT', fast.requests()[0][1], event(1)); fast.frame('EOSE', fast.requests()[0][1]);
    await wave; expect(done).toBe(true); expect(dead.requests()).toHaveLength(0);
    dead.open(); await flush();
    dead.frame('EVENT', dead.requests()[0][1], event(1)); dead.frame('EVENT', dead.requests()[0][1], event(2));
    dead.frame('EOSE', dead.requests()[0][1]); await flush();
    expect(received.mock.calls.map(([e]) => e.id)).toEqual([event(1).id, event(2).id]); expect(eose).toHaveBeenCalledTimes(2);
  });

  it('does not mistake a full page EOSE for complete history', async () => {
    const relay = adapter(undefined, { pageSize: 2 }); let done = false;
    const wave = relay.backfill([{ kinds: [1] }], { onevent: () => {} }).then(() => { done = true; });
    socketsOpen(); await flush(); const socket = ScriptedSocket.sockets[0], first = socket.requests()[0];
    socket.frame('EVENT', first[1], event(2)); socket.frame('EVENT', first[1], event(1)); socket.frame('EOSE', first[1]);
    await flush(); expect(done).toBe(false); expect(socket.requests()).toHaveLength(2);
    socket.frame('EOSE', socket.requests()[1][1]); await wave; expect(done).toBe(true);
  });

  it('backs failed connections off exponentially rather than dialling on each wave', async () => {
    const relay = adapter(undefined, { connectionTimeoutMs: 1000 });
    const wave = relay.backfill([{}], { onevent: () => {} }).catch(error => error);
    ScriptedSocket.sockets[0].onerror?.({ message: 'offline' }); await wave;
    expect(ScriptedSocket.sockets).toHaveLength(1);
    await relay.backfill([{}], { onevent: () => {} }).catch(() => {});
    await relay.publish(event()); expect(ScriptedSocket.sockets).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(5000);
    const next = relay.backfill([{}], { onevent: () => {} }).catch(error => error);
    expect(ScriptedSocket.sockets).toHaveLength(2);
    ScriptedSocket.sockets[1].onerror?.({ message: 'still offline' }); await next;
    await vi.advanceTimersByTimeAsync(9999);
    await relay.backfill([{}], { onevent: () => {} }).catch(() => {}); expect(ScriptedSocket.sockets).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    const recovered = relay.backfill([{}], { onevent: () => {} });
    expect(ScriptedSocket.sockets).toHaveLength(3); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[2]; socket.frame('EOSE', socket.requests()[0][1]); await recovered;
  });

  it('recovers a transient CLOSED on a still-open socket without a one-millisecond retry loop', async () => {
    const relay = adapter(), received = vi.fn(); relay.subscribe([{ kinds: [1] }], { onevent: received });
    socketsOpen(); await flush(); const socket = ScriptedSocket.sockets[0];
    socket.frame('CLOSED', socket.requests()[0][1], 'error: try again later'); await flush();
    await vi.advanceTimersByTimeAsync(4999); expect(socket.requests()).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1); await flush();
    expect(ScriptedSocket.sockets).toHaveLength(1); expect(socket.requests()).toHaveLength(2);
    socket.frame('EVENT', socket.requests()[1][1], event()); socket.frame('EOSE', socket.requests()[1][1]); await flush();
    expect(received).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(100); expect(socket.requests()).toHaveLength(2);
  });

  it('reconnects only the dropped socket and replays historical live filters with dedup intact', async () => {
    const relay = adapter(['wss://one.example.com', 'wss://two.example.com']), received = vi.fn();
    const filter = { kinds: [1], since: 12 };
    relay.subscribe([filter], { onevent: received }); socketsOpen(); await flush();
    const [one, two] = ScriptedSocket.sockets;
    one.frame('EVENT', one.requests()[0][1], event(15)); await flush(); one.close(); await flush();
    expect(two.requests()).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(5000); socketsOpen(); await flush();
    const replacement = ScriptedSocket.sockets[2]; expect(replacement.requests()[0][2]).toEqual(filter);
    replacement.frame('EVENT', replacement.requests()[0][1], event(15)); replacement.frame('EOSE', replacement.requests()[0][1]); await flush();
    expect(received).toHaveBeenCalledTimes(1); expect(two.requests()).toHaveLength(1);
  });
});

describe('VaultRelay OK outcomes and exact-event retry', () => {
  it('resolves on the first positive OK and retains late replica outcomes', async () => {
    const relay = adapter(['wss://one.example.com', 'wss://two.example.com']);
    const signed = event();
    const publish = relay.publish(signed);
    let done = false;
    void publish.then(() => { done = true; });
    socketsOpen();
    await flush();
    const [one, two] = ScriptedSocket.sockets;
    expect(done).toBe(false);
    one.frame('OK', signed.id, true, 'saved');
    await flush();
    expect(done).toBe(true);
    const result = await publish;
    expect(result).toMatchObject({ durable: true, degraded: true, outcomes: [{ status: 'accepted', reason: 'saved' }] });
    two.frame('OK', signed.id, false, 'blocked: not permitted');
    expect(await result.settled).toEqual([
      expect.objectContaining({ status: 'accepted', reason: 'saved' }), expect.objectContaining({ status: 'rejected', reason: 'blocked: not permitted' }),
    ]);
    expect(one.publications()).toEqual([signed]);
  });

  it('never promotes negative OK to success, including a transport-like reason', async () => {
    const relay = adapter();
    const signed = event();
    const publish = relay.publish(signed);
    socketsOpen(); await flush();
    ScriptedSocket.sockets[0].frame('OK', signed.id, false, 'publish timed out');
    expect(await publish).toMatchObject({ durable: false, degraded: true,
      outcomes: [{ status: 'rejected', reason: 'publish timed out' }] });
  });

  it('returns unknown on a lost OK and retries the journaled signed event verbatim', async () => {
    const relay = adapter(undefined, { publishTimeoutMs: 25 });
    const signed = event();
    const publish = relay.publish(signed);
    socketsOpen(); await flush();
    await vi.advanceTimersByTimeAsync(25);
    const first = await publish;
    expect(first).toMatchObject({ durable: false, outcomes: [{ status: 'unknown' }] });
    const retry = relay.retry(first.event);
    await flush();
    const socket = ScriptedSocket.sockets[0];
    expect(socket.publications()).toEqual([signed, signed]);
    socket.frame('OK', signed.id, true, 'duplicate: already saved');
    expect(await retry).toMatchObject({ durable: true, degraded: false });
  });

  it('reports disconnected publication as unknown, and stop rejects pending waits', async () => {
    const relay = adapter();
    const publish = relay.publish(event());
    socketsOpen(); await flush();
    ScriptedSocket.sockets[0].close();
    expect(await publish).toMatchObject({ durable: false, outcomes: [{ status: 'unknown' }] });
    const pending = relay.publish(event(11));
    const assertion = expect(pending).rejects.toMatchObject({ code: 'CANCELLED' });
    relay.stop();
    await assertion;
    expect(() => relay.subscribe([{}], { onevent: () => {} })).toThrow(expect.objectContaining({ code: 'CANCELLED' }));
  });

  it('rejects invalid and simultaneous duplicate publications', async () => {
    const relay = adapter();
    const signed = event();
    await expect(relay.publish({ ...signed, content: 'changed' })).rejects.toMatchObject({ code: 'ARG' });
    const pending = relay.publish(signed);
    const stopped = expect(pending).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(relay.publish(signed)).rejects.toMatchObject({ code: 'ARG' });
    relay.stop(); await stopped;
  });
});

describe('VaultRelay subscriptions and history', () => {
  it('emits real per-relay EOSE, keeps live REQs open and deduplicates events before handlers', async () => {
    const relay = adapter(['wss://one.example.com', 'wss://two.example.com']);
    const onevent = vi.fn(), oneose = vi.fn(), onnotice = vi.fn();
    const sub = relay.subscribe([{ kinds: [1] }], { onevent, oneose, onnotice });
    socketsOpen(); await flush();
    const [one, two] = ScriptedSocket.sockets;
    const id1 = one.requests()[0][1], id2 = two.requests()[0][1];
    // nostr-tools' 4400ms synthetic EOSE is not evidence of backfill completion.
    await vi.advanceTimersByTimeAsync(4400);
    expect(oneose).not.toHaveBeenCalled();
    one.frame('EOSE', id1); await flush();
    expect(oneose.mock.calls).toEqual([['wss://one.example.com/']]);
    expect(one.sent.some(frame => frame[0] === 'CLOSE')).toBe(false);
    const signed = event();
    one.frame('EVENT', id1, signed); two.frame('EVENT', id2, signed);
    two.frame('EOSE', id2); one.frame('NOTICE', 'hello'); await flush();
    expect(onevent).toHaveBeenCalledTimes(1);
    expect(oneose).toHaveBeenCalledTimes(2);
    expect(onnotice).toHaveBeenCalledWith('wss://one.example.com/', 'hello');
    one.frame('EVENT', id1, event(11)); await flush();
    expect(onevent).toHaveBeenCalledTimes(2);
    sub.close(); await flush();
    expect(one.sent.some(frame => frame[0] === 'CLOSE')).toBe(true);
    one.frame('EVENT', id1, event(12)); await flush();
    expect(onevent).toHaveBeenCalledTimes(2);
  });

  it('reports CLOSED and connection failures and reconnects with the original history, never since=now', async () => {
    const relay = adapter();
    const filters: Filter[] = [{ kinds: [1], since: 2, until: 50 }];
    const onevent = vi.fn(), onclose = vi.fn(), onerror = vi.fn();
    const sub = relay.subscribe(filters, { onevent, onclose, onerror });
    socketsOpen(); await flush();
    let socket = ScriptedSocket.sockets[0];
    socket.frame('EVENT', socket.requests()[0][1], event()); await flush();
    socket.frame('CLOSED', socket.requests()[0][1], 'error: unavailable'); await flush();
    expect(onclose).toHaveBeenCalledWith('wss://relay.example.com/', 'error: unavailable');
    expect(onerror).toHaveBeenCalledWith('wss://relay.example.com/', expect.objectContaining({ code: 'NETWORK' }));
    socket.close();
    filters[0].since = 999;
    const reconnect = sub.reconnect();
    socketsOpen(); await reconnect; await flush();
    socket = ScriptedSocket.sockets.slice(-1)[0]!;
    expect(socket.requests()[0][2]).toEqual({ kinds: [1], since: 2, until: 50 });
    socket.frame('EVENT', socket.requests()[0][1], event()); await flush();
    expect(onevent).toHaveBeenCalledTimes(1);
  });

  it.each(['before', 'after'])('authenticates a challenge %s CLOSED and replays the original REQ exactly once', async order => {
    const signing = signer(), onAuthenticated = vi.fn();
    const relay = adapter(undefined, { signer: signing, onAuthenticated });
    const onevent = vi.fn(), oneose = vi.fn(), onerror = vi.fn();
    relay.subscribe([{ kinds: [1], since: 2 }], { onevent, oneose, onerror });
    socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0], req = socket.requests()[0];
    if (order === 'before') socket.frame('AUTH', 'challenge');
    socket.frame('CLOSED', req[1], 'auth-required: login');
    if (order === 'after') socket.frame('AUTH', 'challenge');
    await flush();
    const auth = socket.sent.find(frame => frame[0] === 'AUTH')![1] as Event;
    expect(verifyEvent(auth)).toBe(true);
    expect(auth).toMatchObject({ kind: 22242, content: '', tags: [['relay', 'wss://relay.example.com/'], ['challenge', 'challenge']] });
    expect(socket.requests()).toHaveLength(1);
    socket.frame('OK', auth.id, true, ''); await flush();
    const retry = socket.requests()[1];
    expect(retry.slice(2)).toEqual(req.slice(2)); expect(retry[1]).not.toBe(req[1]);
    socket.frame('AUTH', 'challenge'); await flush();
    expect(signing.signEvent).toHaveBeenCalledTimes(1);
    expect(onAuthenticated).toHaveBeenCalledExactlyOnceWith('wss://relay.example.com/');
    socket.frame('EVENT', retry[1], event()); socket.frame('EOSE', retry[1]); await flush();
    expect(onevent).toHaveBeenCalledTimes(1); expect(oneose).toHaveBeenCalledTimes(1); expect(onerror).not.toHaveBeenCalled();
  });

  it('replays a journaled EVENT after AUTH, without re-signing the application event', async () => {
    const signing = signer(), signed = event();
    const relay = adapter(undefined, { signer: signing });
    const publishing = relay.publish(signed);
    socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0];
    socket.frame('AUTH', 'publish'); socket.frame('OK', signed.id, false, 'auth-required: login'); await flush();
    const auth = socket.sent.find(frame => frame[0] === 'AUTH')![1] as Event;
    socket.frame('OK', auth.id, true, ''); await flush();
    expect(socket.publications()).toEqual([signed, signed]);
    socket.frame('OK', signed.id, true, 'stored');
    expect(await publishing).toMatchObject({ durable: true });
    expect(signing.signEvent).toHaveBeenCalledTimes(1);
  });

  it('lists restricted after successful AUTH and leaves another endpoint live', async () => {
    const relay = adapter(['wss://private.example.com', 'wss://public.example.com'], { signer: signer() });
    const onerror = vi.fn(), onevent = vi.fn();
    relay.subscribe([{ kinds: [1] }], { onevent, onerror }); socketsOpen(); await flush();
    const [privateSocket, publicSocket] = ScriptedSocket.sockets;
    privateSocket.frame('AUTH', 'allowlist'); await flush();
    const auth = privateSocket.sent.find(frame => frame[0] === 'AUTH')![1] as Event;
    privateSocket.frame('OK', auth.id, true, ''); await flush();
    privateSocket.frame('CLOSED', privateSocket.requests().slice(-1)[0]![1], 'restricted: not on list'); await flush();
    expect(onerror).toHaveBeenCalledWith('wss://private.example.com/', expect.objectContaining({ code: 'UNSUPPORTED' }));
    expect(privateSocket.readyState).toBe(3);
    publicSocket.frame('EVENT', publicSocket.requests()[0][1], event()); await flush();
    expect(onevent).toHaveBeenCalledTimes(1);
  });

  it('handles AUTH mid-subscription, preserving dedup and the original history', async () => {
    const relay = adapter(undefined, { signer: signer() }), onevent = vi.fn();
    relay.subscribe([{ kinds: [1], since: 2 }], { onevent }); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0], req = socket.requests()[0];
    socket.frame('EVENT', req[1], event()); socket.frame('EOSE', req[1]); await flush();
    socket.frame('AUTH', 'mid-subscription'); await flush();
    const auth = socket.sent.find(frame => frame[0] === 'AUTH')![1] as Event;
    socket.frame('OK', auth.id, true, ''); await flush();
    const retry = socket.requests()[1];
    expect(retry.slice(2)).toEqual(req.slice(2)); expect(retry[1]).not.toBe(req[1]);
    socket.frame('EVENT', retry[1], event()); socket.frame('EVENT', retry[1], event(11)); await flush();
    expect(onevent).toHaveBeenCalledTimes(2);
  });

  it('bounds repeated auth-required rejection and does not replay twice', async () => {
    const relay = adapter(undefined, { signer: signer() }), signed = event();
    const publishing = relay.publish(signed); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0];
    socket.frame('AUTH', 'once'); await flush();
    const auth = socket.sent.find(frame => frame[0] === 'AUTH')![1] as Event;
    socket.frame('OK', auth.id, true, ''); await flush();
    socket.frame('OK', signed.id, false, 'auth-required: delayed original denial'); await flush();
    socket.frame('OK', signed.id, false, 'auth-required: still denied');
    expect(await publishing).toMatchObject({ durable: false, outcomes: [{ status: 'rejected', error: { code: 'AUTH' } }] });
    expect(socket.publications()).toEqual([signed, signed]);
  });

  it('does not send AUTH after stop during signing and reports signer rejection without hanging', async () => {
    const signing = signer(); let finish!: () => void;
    signing.signEvent = vi.fn<NostrSigner['signEvent']>(template => new Promise(resolve => { finish = () => resolve(finalizeEvent(template, key)); }));
    const relay = adapter(undefined, { signer: signing });
    relay.subscribe([{}], { onevent: () => {} }); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0]; socket.frame('AUTH', 'late'); await flush();
    relay.stop(); finish(); await flush();
    expect(socket.sent.some(frame => frame[0] === 'AUTH')).toBe(false);
    const refused = adapter(undefined, { signer: { ...signer(), signEvent: async () => { throw new Error('denied'); } } });
    const onerror = vi.fn(); refused.subscribe([{}], { onevent: () => {}, onerror }); socketsOpen(); await flush();
    ScriptedSocket.sockets[1].frame('AUTH', 'denied'); await flush();
    expect(onerror).toHaveBeenCalledWith('wss://relay.example.com/', expect.objectContaining({ code: 'AUTH' }));
  });

  it('owns connections independently and keeps another adapter live after stop', async () => {
    const first = adapter(), second = adapter();
    const onevent = vi.fn(), onerror = vi.fn();
    first.subscribe([{}], { onevent: () => {} });
    second.subscribe([{}], { onevent, onerror });
    socketsOpen(); await flush();
    const [one, two] = ScriptedSocket.sockets;
    first.stop();
    expect(one.readyState).toBe(3); expect(two.readyState).toBe(1);
    two.frame('EVENT', two.requests()[0][1], event()); await flush();
    expect(onevent).toHaveBeenCalledTimes(1); expect(onerror).not.toHaveBeenCalled();
    two.close(); await flush();
    expect(onerror).toHaveBeenCalledWith('wss://relay.example.com/', expect.objectContaining({ code: 'NETWORK' }));
  });

  it('closes a connection that opens after stop and does not publish stale work', async () => {
    const relay = adapter();
    const pending = relay.publish(event());
    const stopped = expect(pending).rejects.toMatchObject({ code: 'CANCELLED' });
    relay.stop(); await stopped;
    const socket = ScriptedSocket.sockets[0];
    socket.open(); await flush();
    expect(socket.readyState).toBe(3);
    expect(socket.publications()).toHaveLength(0);
  });

  it('reports failed connections and allows backfill abort during connection establishment', async () => {
    const relay = adapter();
    const onerror = vi.fn();
    const sub = relay.subscribe([{}], { onevent: () => {}, onerror });
    ScriptedSocket.sockets[0].onerror?.({ message: 'failed' }); await flush();
    expect(onerror).toHaveBeenCalledWith('wss://relay.example.com/', expect.objectContaining({ code: 'NETWORK' }));
    sub.close();
    const controller = new AbortController();
    const backfill = relay.backfill([{}], { onevent: () => {} }, controller.signal);
    const aborted = expect(backfill).rejects.toMatchObject({ code: 'CANCELLED' });
    controller.abort(); await aborted;
  });

  it('pages history with inclusive until boundaries and preserves equal-timestamp events', async () => {
    const relay = adapter(undefined, { pageSize: 2, maxPageSize: 4 });
    const onevent = vi.fn(), oneose = vi.fn();
    const backfill = relay.backfill([{ kinds: [1] }], { onevent, oneose });
    socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0];
    const page = async (events: Event[]) => {
      const req = socket.requests().slice(-1)[0]!;
      for (const event of events) socket.frame('EVENT', req[1], event);
      socket.frame('EOSE', req[1]); await flush();
    };
    await page([event(30), event(20, 'a')]);
    expect(socket.requests().slice(-1)[0]![2]).toEqual({ kinds: [1], until: 20, limit: 2 });
    await page([event(20, 'a'), event(20, 'b')]);
    expect(socket.requests().slice(-1)[0]![2]).toEqual({ kinds: [1], until: 20, limit: 4 });
    await page([event(20, 'a'), event(20, 'b'), event(10)]);
    await backfill;
    expect(onevent).toHaveBeenCalledTimes(4);
    expect(oneose).toHaveBeenCalledExactlyOnceWith('wss://relay.example.com/');
  });

  it('fails closed when a timestamp is saturated at the page cap', async () => {
    const relay = adapter(undefined, { pageSize: 1, maxPageSize: 1 });
    const backfill = relay.backfill([{ until: 10 }], { onevent: () => {} });
    const assertion = expect(backfill).rejects.toMatchObject({ code: 'INCOMPLETE' });
    socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0];
    const req = socket.requests()[0];
    socket.frame('EVENT', req[1], event()); socket.frame('EOSE', req[1]);
    await assertion;
  });

  it('does not complete history on synthetic EOSE, and cancels backfill on abort/stop', async () => {
    const relay = adapter(undefined, { backfillTimeoutMs: 5000 });
    const backfill = relay.backfill([{}], { onevent: () => {} });
    const assertion = expect(backfill).rejects.toMatchObject({ code: 'NETWORK' });
    socketsOpen(); await flush();
    await vi.advanceTimersByTimeAsync(5000); await assertion;
    const controller = new AbortController();
    const next = relay.backfill([{}], { onevent: () => {} }, controller.signal);
    const cancelled = expect(next).rejects.toMatchObject({ code: 'CANCELLED' });
    await flush(); controller.abort(); await cancelled;
    const last = relay.backfill([{}], { onevent: () => {} });
    const stopped = expect(last).rejects.toMatchObject({ code: 'CANCELLED' });
    await flush(); relay.stop(); await stopped;
  });
});

describe('VaultRelay AUTH ordering and failure regressions', () => {
  it('treats NIP-11 private-vault metadata as informational, not a challenge or an exclusion', async () => {
    const signing = signer(), onPrivateVaultService = vi.fn(), onAuthenticated = vi.fn(), oneose = vi.fn(), onerror = vi.fn();
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ vault: true, limitation: { auth_required: true } }));
    const relay = adapter(undefined, { signer: signing, fetch: fetcher, onPrivateVaultService, onAuthenticated });
    relay.subscribe([{}], { onevent: () => {}, oneose, onerror }); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0]; socket.frame('EOSE', socket.requests()[0][1]); await flush();
    expect(fetcher.mock.calls[0]).toEqual(['https://relay.example.com/', expect.objectContaining({
      headers: { Accept: 'application/nostr+json' }, credentials: 'omit', redirect: 'error',
    })]);
    expect(onPrivateVaultService).toHaveBeenCalledExactlyOnceWith('wss://relay.example.com/');
    expect(oneose).toHaveBeenCalledTimes(1); expect(onerror).not.toHaveBeenCalled();
    expect(signing.signEvent).not.toHaveBeenCalled(); expect(onAuthenticated).not.toHaveBeenCalled();
  });
  it('waits for a delayed EVENT refusal and isolates old CLOSED/EOSE from the replacement REQ', async () => {
    const relay = adapter(undefined, { signer: signer() }), signed = event(), oneose = vi.fn(), onevent = vi.fn(), onerror = vi.fn();
    relay.subscribe([{ kinds: [1] }], { oneose, onevent, onerror });
    const publishing = relay.publish(signed); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0], original = socket.requests()[0];
    socket.frame('AUTH', 'race'); await flush();
    const auth = socket.sent.find(f => f[0] === 'AUTH')![1] as Event;
    // Put old frames behind the SDK queue's yield before synchronous AUTH handling.
    socket.frame('NOTICE', 'queue boundary'); socket.frame('EVENT', original[1], signed); socket.frame('EOSE', original[1]);
    socket.frame('OK', auth.id, true, ''); await flush();
    const replacement = socket.requests()[1];
    expect(replacement[1]).not.toBe(original[1]); expect(oneose).not.toHaveBeenCalled();
    expect(socket.publications()).toHaveLength(1);
    socket.frame('CLOSED', original[1], 'auth-required: delayed original denial');
    socket.frame('OK', signed.id, false, 'auth-required: delayed original denial'); await flush();
    expect(socket.publications()).toEqual([signed, signed]);
    socket.frame('OK', signed.id, true, 'stored');
    socket.frame('EVENT', replacement[1], signed); socket.frame('EOSE', replacement[1]); await flush();
    expect(await publishing).toMatchObject({ durable: true });
    expect(onevent).toHaveBeenCalledTimes(1); expect(oneose).toHaveBeenCalledTimes(1); expect(onerror).not.toHaveBeenCalled();
  });

  it('reissues live subscriptions once for every new challenge, including two later rotations', async () => {
    const signing = signer(), relay = adapter(undefined, { signer: signing }), onevent = vi.fn(), onerror = vi.fn();
    relay.subscribe([{ kinds: [1], since: 2 }], { onevent, onerror }); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0];
    for (const [i, challenge] of ['initial', 'later-1', 'later-2'].entries()) {
      const before = socket.requests().slice(-1)[0]!;
      socket.frame('AUTH', challenge); socket.frame('CLOSED', before[1], 'auth-required: login'); await flush();
      const auth = socket.sent.filter(f => f[0] === 'AUTH').slice(-1)[0]![1] as Event;
      socket.frame('OK', auth.id, true, ''); await flush();
      const after = socket.requests().slice(-1)[0]!;
      expect(after[1]).not.toBe(before[1]); expect(after.slice(2)).toEqual(before.slice(2));
      socket.frame('EVENT', after[1], event(10 + i)); socket.frame('EOSE', after[1]); await flush();
      socket.frame('AUTH', challenge); await flush();
      expect(socket.requests()).toHaveLength(i + 2);
    }
    expect(onevent).toHaveBeenCalledTimes(3); expect(signing.signEvent).toHaveBeenCalledTimes(3); expect(onerror).not.toHaveBeenCalled();
  });

  it('gives the post-AUTH EVENT retry its own full OK timeout', async () => {
    const signing = signer(); let finish!: () => void;
    signing.signEvent = vi.fn<NostrSigner['signEvent']>(template => new Promise(resolve => { finish = () => resolve(finalizeEvent(template, key)); }));
    const relay = adapter(undefined, { signer: signing, publishTimeoutMs: 100 }), signed = event();
    const publishing = relay.publish(signed); let done = false; void publishing.then(() => { done = true; });
    socketsOpen(); await flush(); const socket = ScriptedSocket.sockets[0];
    socket.frame('AUTH', 'slow signer'); socket.frame('OK', signed.id, false, 'auth-required: login'); await flush();
    await vi.advanceTimersByTimeAsync(80); finish(); await flush();
    const auth = socket.sent.find(f => f[0] === 'AUTH')![1] as Event;
    socket.frame('OK', auth.id, true, ''); await flush();
    await vi.advanceTimersByTimeAsync(50); expect(done).toBe(false);
    expect(socket.publications()).toEqual([signed, signed]);
    socket.frame('OK', signed.id, true, ''); expect(await publishing).toMatchObject({ durable: true });
  });

  it('re-arms the missing-challenge deadline after disconnect and reconnect', async () => {
    const relay = adapter(undefined, { signer: signer(), publishTimeoutMs: 20 }), onerror = vi.fn();
    const sub = relay.subscribe([{}], { onevent: () => {}, onerror }); socketsOpen(); await flush();
    let socket = ScriptedSocket.sockets[0];
    socket.frame('CLOSED', socket.requests()[0][1], 'auth-required: no challenge'); await flush(); socket.close(); await flush();
    const reconnect = sub.reconnect(); await reconnect;
    expect(ScriptedSocket.sockets).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(5000); socketsOpen(); await flush();
    socket = ScriptedSocket.sockets.slice(-1)[0]!; onerror.mockClear();
    socket.frame('CLOSED', socket.requests()[0][1], 'auth-required: still no challenge'); await flush();
    await vi.advanceTimersByTimeAsync(20);
    expect(socket.readyState).toBe(3); expect(onerror).toHaveBeenCalledWith('wss://relay.example.com/', expect.objectContaining({ code: 'AUTH' }));
  });

  it('coalesces challenge rotations with one outstanding signer and an absolute deadline', async () => {
    const signing = signer(), finishes: (() => void)[] = [];
    signing.signEvent = vi.fn<NostrSigner['signEvent']>(template => new Promise(resolve => { finishes.push(() => resolve(finalizeEvent(template, key))); }));
    const relay = adapter(undefined, { signer: signing, publishTimeoutMs: 100 }), onerror = vi.fn();
    relay.subscribe([{}], { onevent: () => {}, onerror }); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0]; socket.frame('AUTH', 'A'); await flush();
    socket.frame('AUTH', 'B'); socket.frame('AUTH', 'C'); await flush(); expect(finishes).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(60); finishes[0](); await flush();
    expect(finishes).toHaveLength(2); expect(socket.sent.some(f => f[0] === 'AUTH')).toBe(false);
    socket.frame('AUTH', 'D'); await vi.advanceTimersByTimeAsync(40);
    expect(socket.readyState).toBe(3); expect(onerror).toHaveBeenCalledWith('wss://relay.example.com/', expect.objectContaining({ code: 'AUTH' }));
    finishes[1](); await flush(); expect(socket.sent.some(f => f[0] === 'AUTH')).toBe(false);
  });

  it('caps signatures across repeated unacknowledged challenge rotations', async () => {
    const signing = signer(), relay = adapter(undefined, { signer: signing });
    relay.subscribe([{}], { onevent: () => {} }); socketsOpen(); await flush(); const socket = ScriptedSocket.sockets[0];
    for (const c of ['A', 'B', 'C', 'D']) { socket.frame('AUTH', c); await flush(); }
    expect(signing.signEvent).toHaveBeenCalledTimes(3); expect(socket.readyState).toBe(3);
  });

  it.each(['signature', 'id', 'account'] as const)('rejects cached signer output with altered %s without sending AUTH', async mode => {
    const signing = signer();
    signing.signEvent = vi.fn(async template => {
      const signed = finalizeEvent(template, key);
      if (mode === 'signature') signed.sig = '0'.repeat(128);
      if (mode === 'id') signed.id = '0'.repeat(64);
      return signed;
    });
    const relay = adapter(undefined, { signer: signing, accountPubkey: mode === 'account' ? 'f'.repeat(64) : getPublicKey(key) }), onerror = vi.fn();
    relay.subscribe([{}], { onevent: () => {}, onerror }); socketsOpen(); await flush();
    const socket = ScriptedSocket.sockets[0]; socket.frame('AUTH', 'bad signer'); await flush();
    expect(socket.sent.some(f => f[0] === 'AUTH')).toBe(false);
    expect(onerror).toHaveBeenCalledWith('wss://relay.example.com/', expect.objectContaining({ code: 'AUTH' }));
  });

  it.each(['signer', 'negative-auth'] as const)('preserves %s authentication failures in pending backfill and publication', async mode => {
    const signing = signer(); if (mode === 'signer') signing.signEvent = vi.fn(async () => { throw new Error('denied'); });
    const relay = adapter(undefined, { signer: signing }), signed = event();
    const backfill = relay.backfill([{}], { onevent: () => {} });
    const rejected = expect(backfill).rejects.toMatchObject({ code: 'AUTH' });
    const publishing = relay.publish(signed); socketsOpen(); await flush(); const socket = ScriptedSocket.sockets[0];
    socket.frame('AUTH', 'denied'); socket.frame('CLOSED', socket.requests()[0][1], 'auth-required: login'); await flush();
    if (mode === 'negative-auth') {
      const auth = socket.sent.find(f => f[0] === 'AUTH')![1] as Event; socket.frame('OK', auth.id, false, 'error: signer rejected'); await flush();
    }
    await rejected; expect(await publishing).toMatchObject({ durable: false, outcomes: [{ error: { code: 'AUTH' } }] });
  });
});

describe('public endpoint policy', () => {
  it.each([
    'ws://relay.example.com', 'https://relay.example.com', 'wss://localhost', 'wss://localhost.',
    'wss://relay.local', 'wss://relay.internal', 'wss://relay', 'wss://127.0.0.1', 'wss://127.1',
    'wss://localhost..', 'wss://relay.localdomain', 'wss://[2001::1]', 'wss://[2002:7f00:1::1]',
    'wss://2130706433', 'wss://0x7f000001', 'wss://10.0.0.1', 'wss://172.16.0.1', 'wss://192.168.0.1',
    'wss://169.254.169.254', 'wss://100.64.0.1', 'wss://[::1]', 'wss://[fc00::1]', 'wss://[fe80::1]',
    'wss://[::ffff:127.0.0.1]', 'wss://user:password@relay.example.com', 'wss://relay.example.com/?secret=x',
  ])('rejects %s', url => expect(() => validatePublicEndpoint(url, 'wss:')).toThrow());
  it('accepts secure public DNS and global-unicast IP endpoints', () => {
    expect(validatePublicEndpoint('wss://relay.example.com/path', 'wss:')).toBe('wss://relay.example.com/path');
    expect(validatePublicEndpoint('wss://8.8.8.8', 'wss:')).toBe('wss://8.8.8.8/');
    expect(validatePublicEndpoint('wss://192.2.1.1', 'wss:')).toBe('wss://192.2.1.1/');
    expect(validatePublicEndpoint('wss://[2606:4700:4700::1111]', 'wss:')).toContain('2606:4700');
  });
});
