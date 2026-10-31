import { afterEach, describe, expect, it, vi } from 'vitest';
import { VaultBlossom } from '../blossom';
import { hashAddress } from '../crypto';
import { HeadlessVaultEngine } from '../engine';
import { editCache, fixture, network, signer } from './engine-fixtures';

const bytes = new TextEncoder().encode('sealed ciphertext'), address = hashAddress(bytes);
const engines: HeadlessVaultEngine[] = [];
const clients: VaultBlossom[] = [];
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(yes => { resolve = yes; }); return { promise, resolve }; };
function timers() { vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] }); }
function client(fetcher: typeof fetch, options = {}) {
  const result = new VaultBlossom('https://blossom.example.com', { fetch: fetcher, totalTimeoutMs: 100, bodyIdleTimeoutMs: 20, ...options });
  clients.push(result); return result;
}
afterEach(async () => {
  for (const c of clients.splice(0)) c.stop();
  await Promise.all(engines.splice(0).map(engine => engine.stop()));
  vi.useRealTimers(); vi.restoreAllMocks();
});

// The investigation's HTTP-200 stream: headers arrive, but body EOF never does.
describe('adapter-owned Blossom deadlines (SV-31)', () => {
  it.each(['GET', 'PUT'] as const)('times out a stalled HTTP-200 %s body and cancels its reader', async method => {
    timers(); const entered = deferred(), cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({ pull() { entered.resolve(); }, cancel });
    const blossom = client(vi.fn<typeof fetch>().mockResolvedValue(new Response(stream)));
    const result = (method === 'GET' ? blossom.get(address) : blossom.put(bytes, address, signer())).catch(error => error);
    await entered.promise; await vi.advanceTimersByTimeAsync(20);
    expect(await result).toMatchObject({ code: 'NETWORK', retryable: true, operation: method === 'GET' ? 'fetch' : 'upload' });
    expect(cancel).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['GET', 'HEAD', 'PUT'] as const)('bounds stalled %s headers even if fetch ignores abort', async method => {
    timers(); const entered = deferred(); let signal!: AbortSignal;
    const fetcher = vi.fn<typeof fetch>().mockImplementation((_url, init) => { signal = init!.signal!; entered.resolve(); return new Promise(() => {}); });
    const blossom = client(fetcher);
    const result = (method === 'GET' ? blossom.get(address) : method === 'HEAD' ? blossom.head(address) : blossom.put(bytes, address, signer())).catch(error => error);
    await entered.promise; await vi.advanceTimersByTimeAsync(100);
    expect(await result).toMatchObject({ code: 'NETWORK', retryable: true }); expect(signal.aborted).toBe(true); expect(vi.getTimerCount()).toBe(0);
  });

  it('resets idle on real byte progress and still accepts a complete hash-verified object', async () => {
    timers(); const entered = deferred(); let body!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({ start(controller) { body = controller; }, pull() { entered.resolve(); } });
    const blossom = client(vi.fn<typeof fetch>().mockResolvedValue(new Response(stream)));
    const result = blossom.get(address); await entered.promise;
    await vi.advanceTimersByTimeAsync(15); body.enqueue(bytes.slice(0, 4));
    await vi.advanceTimersByTimeAsync(15); body.enqueue(bytes.slice(4)); body.close();
    expect(await result).toEqual(bytes); expect(vi.getTimerCount()).toBe(0);
  });

  it('does not let empty chunks reset the body-progress deadline', async () => {
    timers(); const entered = deferred(); let body!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({ start(controller) { body = controller; }, pull() { entered.resolve(); } });
    const result = client(vi.fn<typeof fetch>().mockResolvedValue(new Response(stream))).get(address).catch(error => error);
    await entered.promise; await vi.advanceTimersByTimeAsync(10); body.enqueue(new Uint8Array());
    await vi.advanceTimersByTimeAsync(10); expect(await result).toMatchObject({ code: 'NETWORK' });
  });

  it('enforces the absolute deadline even while the body keeps progressing', async () => {
    timers(); const entered = deferred(); let body!: ReadableStreamDefaultController<Uint8Array>;
    const stream = new ReadableStream<Uint8Array>({ start(controller) { body = controller; }, pull() { entered.resolve(); } });
    const result = client(vi.fn<typeof fetch>().mockResolvedValue(new Response(stream)), { totalTimeoutMs: 50 }).get(address).catch(error => error);
    await entered.promise;
    for (let i = 0; i < 4; i++) { await vi.advanceTimersByTimeAsync(10); body.enqueue(bytes.slice(i, i + 1)); }
    await vi.advanceTimersByTimeAsync(10); expect(await result).toMatchObject({ code: 'NETWORK' }); expect(vi.getTimerCount()).toBe(0);
  });

  it('keeps caller cancellation distinct from a deadline failure', async () => {
    timers(); const abort = new AbortController(), entered = deferred();
    const blossom = client(vi.fn<typeof fetch>().mockImplementation(() => { entered.resolve(); return new Promise(() => {}); }));
    const result = blossom.head(address, abort.signal).catch(error => error);
    await entered.promise; abort.abort(); expect(await result).toMatchObject({ code: 'CANCELLED' }); expect(vi.getTimerCount()).toBe(0);
  });
});

describe('engine fallback with real Blossom deadline adapters', () => {
  const slow = 'https://slow.example.com/', fast = 'https://fast.example.com/';
  it('advances from a stalled HTTP-200 GET body to the next server during persisted-record recovery', async () => {
    const f = await fixture(), seed = new HeadlessVaultEngine(f.deps); engines.push(seed);
    await seed.start(f.session); await f.mkdir('/notebook/Team');
    await seed.create('Team', { network: { ...network, readBlossom: [slow, fast], writeBlossom: [fast] } }); await seed.stop();
    await editCache(f.factory, 'clear'); timers(); const entered = deferred(), cancel = vi.fn(), calls: string[] = [];
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (input, init) => {
      const url = String(input), source = new URL(url), object = source.pathname.slice(1); calls.push(`${init?.method} ${source.host}`);
      if (init?.method === 'HEAD') return new Response(null, { status: f.net.objects.has(object) ? 200 : 404 });
      if (source.host === 'slow.example.com') return new Response(new ReadableStream<Uint8Array>({ pull() { entered.resolve(); }, cancel }));
      return new Response(new Uint8Array(f.net.objects.get(object)!));
    });
    const engine = new HeadlessVaultEngine({ ...f.deps, blossomFactory: (endpoint, options) => {
      const c = new VaultBlossom(endpoint, { ...options, fetch: fetcher, totalTimeoutMs: 1000, bodyIdleTimeoutMs: 100 }); clients.push(c); return c;
    } }); engines.push(engine);
    const starting = engine.start(f.session); await entered.promise; await vi.advanceTimersByTimeAsync(100); await starting;
    expect(calls).toContain('GET slow.example.com'); expect(calls).toContain('GET fast.example.com'); expect(cancel).toHaveBeenCalled();
  });

  it.each(['HEAD', 'PUT'] as const)('advances after stalled %s without recording a confirmed-object success for that server', async method => {
    const f = await fixture(); await f.mkdir('/notebook/Team'); timers(); const entered = deferred();
    const objects = new Map<string, Uint8Array>();
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (input, init) => {
      const url = new URL(String(input)), object = url.pathname.slice(1), isSlow = url.host === 'slow.example.com';
      // Probe remains an ordinary authorised 404, not the operation under test.
      if (object === '0'.repeat(64)) return new Response(null, { status: 404 });
      if (isSlow && init?.method === method) {
        if (method === 'HEAD') { entered.resolve(); return new Promise<Response>(() => {}); }
        return new Response(new ReadableStream<Uint8Array>({ pull() { entered.resolve(); } }));
      }
      if (init?.method === 'HEAD') return new Response(null, { status: objects.has(object) ? 200 : 404 });
      if (init?.method === 'PUT') { objects.set(new Headers(init.headers).get('x-sha-256')!, new Uint8Array(init.body as Uint8Array)); return new Response(null, { status: 204 }); }
      return new Response(new Uint8Array(objects.get(object)!));
    });
    const engine = new HeadlessVaultEngine({ ...f.deps, blossomFactory: (endpoint, options) => {
      const c = new VaultBlossom(endpoint, { ...options, fetch: fetcher, totalTimeoutMs: 1000, bodyIdleTimeoutMs: 100 }); clients.push(c); return c;
    } }); engines.push(engine); await engine.start(f.session);
    const creation = engine.create('Team', { network: { ...network, readBlossom: [slow, fast], writeBlossom: [slow, fast] } });
    await entered.promise; await vi.advanceTimersByTimeAsync(method === 'HEAD' ? 1000 : 100); const id = await creation;
    const store = await f.openStore(), vault = (await store.read('vaults', [id]))!.value;
    expect(Object.values(vault.confirmedObjects!)).not.toHaveLength(0);
    for (const urls of Object.values(vault.confirmedObjects!)) { expect(urls).toContain(fast); expect(urls).not.toContain(slow); }
    const operation = (await store.list('operations')).find(row => row.value.kind === 'create')!.value;
    expect(JSON.stringify(operation.uploadOutcomes)).toContain('NETWORK'); store.stop();
  });
});
