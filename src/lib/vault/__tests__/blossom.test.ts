import { describe, expect, it, vi } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools';
import type { NostrSigner } from '../../nostr/signer';
import { VaultBlossom } from '../blossom';
import { BLOSSOM_AUTH_KIND, PORTHOME_CHUNK_MAX, PORTHOME_SEAL_OVERHEAD } from '../protocol';

const bytes = new TextEncoder().encode('sealed ciphertext');
const address = bytesToHex(sha256(bytes));
const key = new Uint8Array(32).fill(7);
function signer(): NostrSigner {
  return { getType: () => 'local', getPublicKey: vi.fn(async () => getPublicKey(key)), signEvent: vi.fn(async template => finalizeEvent(template, key)) };
}
const bodyResponse = () => new Response(bytes);
function client(fetcher: typeof fetch, options = {}): VaultBlossom {
  return new VaultBlossom('https://blossom.example.com/base/', { fetch: fetcher, now: () => 1000, ...options });
}

it('public GET/HEAD verify hashes without signing or sending credentials', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(bodyResponse())
    .mockResolvedValueOnce(new Response(null, { headers: { 'content-length': String(bytes.length) } }));
  const signing = signer();
  const blossom = client(fetcher, { signer: signing });
  expect(await blossom.get(address, BigInt(bytes.length))).toEqual(bytes);
  expect(await blossom.head(address)).toEqual({ exists: true, size: bytes.length });
  expect(fetcher.mock.calls[0][0]).toBe(`https://blossom.example.com/base/${address}`);
  for (const [, init] of fetcher.mock.calls) {
    expect(init).toMatchObject({ credentials: 'omit', redirect: 'error' });
    expect(init?.headers).toBeUndefined();
  }
  expect(signing.signEvent).not.toHaveBeenCalled();
});

it.each(['GET', 'HEAD'] as const)('retries %s only after 401, with fresh scoped t=get auth (with or without challenge header)', async method => {
  const signing = signer(), onAuthenticated = vi.fn();
  for (const headers of [new Headers(), new Headers({ 'WWW-Authenticate': 'Nostr' })]) {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(null, { status: 401, headers }))
      .mockResolvedValueOnce(method === 'GET' ? bodyResponse() : new Response(null));
    const blossom = client(fetcher, { signer: signing, serverTag: true, onAuthenticated });
    if (method === 'GET') expect(await blossom.get(address)).toEqual(bytes);
    else expect(await blossom.head(address)).toEqual({ exists: true });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0][1]?.headers).toBeUndefined();
    const auth = JSON.parse(atob(new Headers(fetcher.mock.calls[1][1]?.headers).get('authorization')!.slice(6)));
    expect(verifyEvent(auth)).toBe(true);
    expect(auth).toMatchObject({ kind: 24242, created_at: 1000, content: 'Authorize ',
      tags: [['t', 'get'], ['x', address], ['expiration', '1300'], ['server', 'https://blossom.example.com/base']] });
    expect(fetcher.mock.calls[1][1]).toMatchObject({ method, credentials: 'omit', redirect: 'error' });
  }
  expect(signing.signEvent).toHaveBeenCalledTimes(2); expect(onAuthenticated).toHaveBeenCalledTimes(2);
});

it.each([401, 403])('bounds a challenged read to one retry and reports HTTP %i without anonymous fallback', async status => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(null, { status: 401 }))
    .mockResolvedValueOnce(new Response(null, { status }));
  const signing = signer();
  await expect(client(fetcher, { signer: signing }).get(address)).rejects.toMatchObject({ code: 'AUTH', status,
    message: status === 403 ? 'Not allowlisted — ask the operator' : 'Server did not accept authentication — ask the operator' });
  expect(fetcher).toHaveBeenCalledTimes(2); expect(signing.signEvent).toHaveBeenCalledTimes(1);
});

it('does not sign or retry a 402 payment refusal', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 402 })), signing = signer();
  await expect(client(fetcher, { signer: signing }).get(address)).rejects.toMatchObject({ status: 402,
    message: 'Server requires payment/authorisation for this pubkey' });
  expect(fetcher).toHaveBeenCalledTimes(1); expect(signing.signEvent).not.toHaveBeenCalled();
});

it('does not send an authenticated read after cancellation during signing', async () => {
  const signing = signer(); let finish!: () => void;
  let entered!: () => void; const signingStarted = new Promise<void>(resolve => { entered = resolve; });
  signing.signEvent = vi.fn<NostrSigner['signEvent']>(template => new Promise(resolve => { finish = () => resolve(finalizeEvent(template, key)); entered(); }));
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 401 }));
  const blossom = client(fetcher, { signer: signing }); const reading = blossom.get(address);
  await signingStarted; blossom.stop(); await expect(reading).rejects.toMatchObject({ code: 'CANCELLED' });
  finish(); await Promise.resolve(); await Promise.resolve(); expect(fetcher).toHaveBeenCalledTimes(1);
});

it('signs fresh BUD-02 upload auth through NostrSigner with exact content/tags and verifies returned hashes', async () => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => new Response(JSON.stringify({ sha256: address })));
  let now = 1000;
  const blossom = client(fetcher, { serverTag: true, now: () => now });
  const signing = signer();
  expect(await blossom.put(bytes, address, signing)).toEqual({ address, size: bytes.length });
  now++;
  await blossom.put(bytes, address, signing);
  expect(signing.signEvent).toHaveBeenCalledTimes(2);
  for (const [index, [url, init]] of fetcher.mock.calls.entries()) {
    expect(url).toBe('https://blossom.example.com/base/upload');
    expect(init).toMatchObject({ method: 'PUT', redirect: 'error', credentials: 'omit', body: bytes });
    const headers = new Headers(init?.headers);
    expect(headers.get('content-type')).toBe('application/octet-stream');
    expect(headers.get('x-sha-256')).toBe(address);
    const auth = JSON.parse(atob(headers.get('authorization')!.slice('Nostr '.length)));
    expect(verifyEvent(auth)).toBe(true);
    expect(auth).toMatchObject({ kind: BLOSSOM_AUTH_KIND, content: 'Authorize ', created_at: 1000 + index,
      tags: [['t', 'upload'], ['x', address], ['expiration', String(1300 + index)], ['server', 'https://blossom.example.com/base']] });
  }
});

it('omits the optional server tag by default and accepts an empty successful PUT response', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));
  const signing = signer();
  await client(fetcher).put(bytes, address, signing);
  expect(signing.signEvent).toHaveBeenCalledWith(expect.objectContaining({ tags: [
    ['t', 'upload'], ['x', address], ['expiration', '1300'],
  ] }));
});

describe('HTTP errors are never missing/deletion or false durability', () => {
  it.each([
    [401, 'AUTH'], [403, 'AUTH'], [402, 'AUTH'], [413, 'TOO_LARGE'], [404, 'INCOMPLETE'], [500, 'NETWORK'], [302, 'NETWORK'],
  ])('maps GET/PUT status %s to %s', async (status, code) => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => new Response(null, { status: Number(status) }));
    const blossom = client(fetcher);
    await expect(blossom.get(address)).rejects.toMatchObject({ code, status });
    await expect(blossom.put(bytes, address, signer())).rejects.toMatchObject({ code, status });
  });
  it.each([401, 403, 402])('HEAD %s is AUTH, never exists=false', async status => {
    await expect(client(vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status })))
      .head(address)).rejects.toMatchObject({ code: 'AUTH', status });
  });
  it('HEAD 404 alone returns exists=false', async () => {
    expect(await client(vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 404 })))
      .head(address)).toEqual({ exists: false });
  });
  it('gives fixed actionable payment and size reasons without response-body leakage', async () => {
    for (const [status, message] of [[402, 'Server requires payment/authorisation for this pubkey'],
      [413, 'Server rejects this object size']] as const) {
      await expect(client(vi.fn<typeof fetch>().mockResolvedValue(new Response('secret server text', { status })))
        .put(bytes, address, signer())).rejects.toMatchObject({ message });
    }
  });
  it('treats transport failure/lost PUT response as unknown NETWORK, retaining the caller address', async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new TypeError('response lost'));
    await expect(client(fetcher).put(bytes, address, signer())).rejects.toMatchObject({ code: 'NETWORK' });
    expect(new Headers(fetcher.mock.calls[0][1]?.headers).get('x-sha-256')).toBe(address);
  });
});

it('rejects corrupted GET bytes, short bodies, and either returned PUT hash mismatch', async () => {
  await expect(client(vi.fn<typeof fetch>().mockResolvedValue(new Response('corrupt'))).get(address))
    .rejects.toMatchObject({ code: 'HASH_MISMATCH' });
  await expect(client(vi.fn<typeof fetch>().mockResolvedValue(bodyResponse())).get(address, bytes.length + 1))
    .rejects.toMatchObject({ code: 'INCOMPLETE' });
  for (const response of [new Response(JSON.stringify({ sha256: '0'.repeat(64) })),
    new Response(null, { status: 204, headers: { 'x-sha-256': '0'.repeat(64) } })]) {
    await expect(client(vi.fn<typeof fetch>().mockResolvedValue(response)).put(bytes, address, signer()))
      .rejects.toMatchObject({ code: 'HASH_MISMATCH' });
  }
});

it('rejects bad upload bytes before signing or fetch and bounds every streamed GET', async () => {
  const fetcher = vi.fn<typeof fetch>();
  const signing = signer();
  expect(() => client(fetcher).put(bytes, '0'.repeat(64), signing)).toThrow(expect.objectContaining({ code: 'HASH_MISMATCH' }));
  expect(signing.signEvent).not.toHaveBeenCalled(); expect(fetcher).not.toHaveBeenCalled();
  const cancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>({ start(controller) {
    controller.enqueue(bytes.slice(0, 5)); controller.enqueue(bytes);
  }, cancel });
  await expect(client(vi.fn<typeof fetch>().mockResolvedValue(new Response(stream))).get(address, bytes.length))
    .rejects.toMatchObject({ code: 'TOO_LARGE' });
  expect(cancel).toHaveBeenCalled();
});

it('enforces content-length, protocol object size and upload response caps', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { headers: { 'content-length': '99999999' } }));
  await expect(client(fetcher).get(address)).rejects.toMatchObject({ code: 'TOO_LARGE' });
  expect(() => client(fetcher).get(address, 99999999n)).toThrow(expect.objectContaining({ code: 'TOO_LARGE' }));
  const huge = new Uint8Array(PORTHOME_CHUNK_MAX + PORTHOME_SEAL_OVERHEAD + 1);
  expect(() => client(fetcher).put(huge, address, signer())).toThrow(expect.objectContaining({ code: 'TOO_LARGE' }));
  await expect(client(vi.fn<typeof fetch>().mockResolvedValue(new Response(' '.repeat(16385))))
    .put(bytes, address, signer())).rejects.toMatchObject({ code: 'TOO_LARGE' });
});

it('owns upload bytes across a delayed signer and rejects a signer that changes the auth template', async () => {
  let signed!: () => void;
  const signing = signer();
  signing.signEvent = vi.fn<NostrSigner['signEvent']>(template => new Promise(resolve => { signed = () => resolve(finalizeEvent(template, key)); }));
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));
  const mutable = new Uint8Array(bytes);
  const put = client(fetcher).put(mutable, address, signing);
  mutable.fill(0); await Promise.resolve(); signed(); await put;
  expect(fetcher.mock.calls[0][1]?.body).toEqual(bytes);
  signing.signEvent = vi.fn(async template => finalizeEvent({ ...template, content: 'wrong' }, key));
  await expect(client(fetcher).put(bytes, address, signing)).rejects.toMatchObject({ code: 'AUTH' });
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('aborts before fetch, during fetch, during streaming, during signing, and on stop', async () => {
  const fetcher = vi.fn<typeof fetch>(() => new Promise(() => {}));
  const blossom = client(fetcher);
  const controller = new AbortController(); controller.abort();
  await expect(blossom.get(address, undefined, controller.signal)).rejects.toMatchObject({ code: 'CANCELLED' });
  expect(fetcher).not.toHaveBeenCalled();
  const next = new AbortController();
  const fetching = blossom.get(address, undefined, next.signal);
  next.abort(); await expect(fetching).rejects.toMatchObject({ code: 'CANCELLED' });
  expect(fetcher.mock.calls[0][1]?.signal?.aborted).toBe(true);
  const cancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>({ cancel });
  const streaming = client(vi.fn<typeof fetch>().mockResolvedValue(new Response(stream)));
  const reading = streaming.get(address);
  await Promise.resolve(); await Promise.resolve();
  streaming.stop(); await expect(reading).rejects.toMatchObject({ code: 'CANCELLED' });
  expect(cancel).toHaveBeenCalled();
  const signing = signer();
  let finish!: () => void;
  signing.signEvent = vi.fn<NostrSigner['signEvent']>(template => new Promise(resolve => { finish = () => resolve(finalizeEvent(template, key)); }));
  const signingFetch = vi.fn<typeof fetch>();
  const uploading = client(signingFetch);
  const put = uploading.put(bytes, address, signing);
  await Promise.resolve();
  uploading.stop(); await expect(put).rejects.toMatchObject({ code: 'CANCELLED' });
  finish(); await Promise.resolve();
  expect(signingFetch).not.toHaveBeenCalled();
  await expect(uploading.head(address)).rejects.toMatchObject({ code: 'CANCELLED' });
  const pending = blossom.head(address); blossom.stop();
  await expect(pending).rejects.toMatchObject({ code: 'CANCELLED' });
});

it.each(['signature', 'id', 'account', 'public-key'] as const)('refuses invalid %s signer output as AUTH without sending a header', async mode => {
  const signing = signer();
  signing.signEvent = vi.fn(async template => {
    const signed = finalizeEvent(template, key);
    if (mode === 'signature') signed.sig = '0'.repeat(128);
    if (mode === 'id') signed.id = '0'.repeat(64);
    return signed;
  });
  if (mode === 'public-key') signing.getPublicKey = vi.fn(async () => { throw new Error('locked'); });
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 401 }));
  await expect(client(fetcher, { signer: signing, ...(mode === 'account' ? { accountPubkey: 'f'.repeat(64) } : {}) }).get(address))
    .rejects.toMatchObject({ code: 'AUTH' });
  expect(fetcher).toHaveBeenCalledTimes(1); expect(fetcher.mock.calls[0][1]?.headers).toBeUndefined();
});

it('takes an owned signer snapshot before serialising the authenticated header', async () => {
  const signing = signer(); let retained: ReturnType<typeof finalizeEvent>;
  signing.signEvent = vi.fn(async template => { retained = finalizeEvent(template, key); return retained; });
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(null, { status: 401 })).mockImplementationOnce(async (_url, init) => {
    retained.tags[0][1] = 'upload'; retained.sig = '0'.repeat(128);
    const sent = JSON.parse(atob(new Headers(init?.headers).get('authorization')!.slice(6)));
    expect(verifyEvent(sent)).toBe(true); expect(sent.tags[0]).toEqual(['t', 'get']); return bodyResponse();
  });
  expect(await client(fetcher, { signer: signing, accountPubkey: getPublicKey(key) }).get(address)).toEqual(bytes);
});

it.each(['http://blossom.example.com', 'https://localhost', 'https://127.0.0.1', 'https://10.0.0.1',
  'https://[::1]', 'https://[fd00::1]', 'https://metadata.internal'])('rejects unsafe Blossom endpoint %s before fetch', endpoint => {
  const fetcher = vi.fn<typeof fetch>();
  expect(() => new VaultBlossom(endpoint, { fetch: fetcher })).toThrow();
  expect(fetcher).not.toHaveBeenCalled();
});
