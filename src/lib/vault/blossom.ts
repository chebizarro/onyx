import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { verifyEvent, type Event } from 'nostr-tools';
import type { NostrSigner } from '../nostr/signer';
import { VaultError, type VaultErrorCode, type VaultOperation } from './errors';
import { BLOSSOM_AUTH_EXPIRATION_SECONDS, BLOSSOM_AUTH_KIND, BLOSSOM_TOTAL_TIMEOUT_MS, BLOSSOM_BODY_IDLE_TIMEOUT_MS, PORTHOME_CHUNK_MAX,
  PORTHOME_MAX_CBOR_BYTES, PORTHOME_SEAL_OVERHEAD } from './protocol';
import { validatePublicEndpoint } from './relay';

const MAX_OBJECT_BYTES = Math.max(PORTHOME_CHUNK_MAX, PORTHOME_MAX_CBOR_BYTES) + PORTHOME_SEAL_OVERHEAD;
const MAX_UPLOAD_RESPONSE_BYTES = 16384;
export interface BlossomHead { exists: boolean; size?: number }
export interface BlossomPut { address: string; size: number }
export interface BlossomOptions {
  fetch?: typeof fetch;
  signer?: NostrSigner;
  accountPubkey?: string;
  onAuthenticated?: () => void;
  now?: () => number;
  /** Include the optional server restriction in read and upload authorisations. */
  serverTag?: boolean;
  totalTimeoutMs?: number;
  bodyIdleTimeoutMs?: number;
}

/** Safe, fixed HTTP diagnostics; never include response bodies or authorisation headers. */
export class BlossomError extends VaultError {
  constructor(code: VaultErrorCode, readonly status: number, operation: VaultOperation) {
    super(code, { operation });
    if (status === 402) this.message = 'Server requires payment/authorisation for this pubkey';
    if (status === 403) this.message = 'Not allowlisted — ask the operator';
    if (status === 401) this.message = 'Server did not accept authentication — ask the operator';
    if (status === 413) this.message = 'Server rejects this object size';
  }
}

function addressChecked(address: string): void {
  if (!/^[0-9a-f]{64}$/.test(address)) throw new VaultError('ARG');
}
function responseStatus(response: Response, operation: VaultOperation): void {
  const status = response.status;
  if (status >= 200 && status < 300) return;
  const code = status === 401 || status === 402 || status === 403 ? 'AUTH'
    : status === 413 ? 'TOO_LARGE' : status === 404 ? 'INCOMPLETE' : 'NETWORK';
  throw new BlossomError(code, status, operation);
}
function sizeHeader(response: Response): number | undefined {
  const value = response.headers.get('content-length');
  if (value === null) return undefined;
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) throw new VaultError('TOO_LARGE', { operation: 'fetch' });
  return Number(value);
}

export class VaultBlossom {
  readonly endpoint: string;
  private readonly fetcher: typeof fetch;
  private readonly now: () => number;
  private readonly serverTag: boolean;
  private readonly totalTimeoutMs: number;
  private readonly bodyIdleTimeoutMs: number;
  private readonly requests = new Set<AbortController>();
  private readonly signer?: NostrSigner;
  private readonly accountPubkey?: string;
  private readonly onAuthenticated?: () => void;
  private stopped = false;

  constructor(endpoint: string, options: BlossomOptions = {}) {
    this.endpoint = validatePublicEndpoint(endpoint, 'https:').replace(/\/$/, '');
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.serverTag = options.serverTag ?? false;
    this.totalTimeoutMs = options.totalTimeoutMs ?? BLOSSOM_TOTAL_TIMEOUT_MS;
    this.bodyIdleTimeoutMs = options.bodyIdleTimeoutMs ?? BLOSSOM_BODY_IDLE_TIMEOUT_MS;
    if ([this.totalTimeoutMs, this.bodyIdleTimeoutMs].some(ms => !Number.isSafeInteger(ms) || ms <= 0 || ms > 0x7fffffff)) throw new VaultError('ARG');
    this.signer = options.signer;
    this.accountPubkey = options.accountPubkey;
    this.onAuthenticated = options.onAuthenticated;
  }

  private async run<T>(signal: AbortSignal | undefined, operation: VaultOperation,
    work: (signal: AbortSignal) => Promise<T>): Promise<T> {
    if (this.stopped || signal?.aborted) throw new VaultError('CANCELLED', { operation });
    const controller = new AbortController();
    const abort = () => controller.abort(new VaultError('CANCELLED', { operation }));
    const failure = () => controller.signal.reason instanceof VaultError ? controller.signal.reason : new VaultError('CANCELLED', { operation });
    const timer = setTimeout(() => controller.abort(new VaultError('NETWORK', { operation })), this.totalTimeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    this.requests.add(controller);
    let cancel: () => void = () => {};
    try {
      return await Promise.race([
        new Promise<never>((_, reject) => {
          cancel = () => reject(failure());
          controller.signal.addEventListener('abort', cancel, { once: true });
        }),
        work(controller.signal),
      ]);
    } catch (error) {
      if (controller.signal.aborted) throw failure();
      if (error instanceof VaultError) throw error;
      throw new VaultError('NETWORK', { operation });
    } finally {
      clearTimeout(timer);
      controller.signal.removeEventListener('abort', cancel);
      signal?.removeEventListener('abort', abort);
      this.requests.delete(controller);
      // Also abort/cancel an over-limit or otherwise unfinished response body.
      controller.abort();
    }
  }

  private async body(response: Response, cap: number, signal: AbortSignal, operation: VaultOperation): Promise<Uint8Array> {
    const length = sizeHeader(response);
    if (length !== undefined && length > cap) {
      void response.body?.cancel().catch(() => {});
      throw new VaultError('TOO_LARGE', { operation });
    }
    if (!response.body) return new Uint8Array();
    const reader = response.body.getReader();
    const abort = () => { void reader.cancel().catch(() => {}); };
    signal.addEventListener('abort', abort, { once: true });
    const chunks: Uint8Array[] = [];
    let total = 0, complete = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let rejectIdle!: (error: VaultError) => void;
    const idle = new Promise<never>((_, reject) => { rejectIdle = reject; });
    const progress = () => {
      clearTimeout(timer);
      timer = setTimeout(() => rejectIdle(new VaultError('NETWORK', { operation })), this.bodyIdleTimeoutMs);
    };
    progress();
    try {
      for (;;) {
        if (signal.aborted) throw new VaultError('CANCELLED');
        const { value, done } = await Promise.race([reader.read(), idle]);
        if (done) { complete = true; break; }
        // Empty chunks are not progress and cannot keep a stalled stream alive.
        if (value.byteLength) progress();
        total += value.byteLength;
        if (total > cap) {
          throw new VaultError('TOO_LARGE', { operation });
        }
        chunks.push(value);
      }
      if (signal.aborted) throw new VaultError('CANCELLED');
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      return bytes;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', abort);
      if (!complete) void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }

  private async authorization(action: 'get' | 'upload', address: string, signer: NostrSigner,
    signal: AbortSignal): Promise<string> {
    const operation = action === 'get' ? 'fetch' : 'upload';
    const now = this.now();
    if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(now + BLOSSOM_AUTH_EXPIRATION_SECONDS)) {
      throw new VaultError('ARG', { operation });
    }
    const template = { kind: BLOSSOM_AUTH_KIND, created_at: now, content: 'Authorize ',
      tags: [['t', action], ['x', address], ['expiration', String(now + BLOSSOM_AUTH_EXPIRATION_SECONDS)]] };
    if (this.serverTag) template.tags.push(['server', this.endpoint]);
    let event: Event, pubkey: string;
    try {
      pubkey = this.accountPubkey ?? await signer.getPublicKey();
      if (signal.aborted) throw new VaultError('CANCELLED', { operation });
      event = JSON.parse(JSON.stringify(await signer.signEvent(structuredClone(template))));
    } catch { throw new VaultError(signal.aborted ? 'CANCELLED' : 'AUTH', { operation }); }
    if (signal.aborted) throw new VaultError('CANCELLED', { operation });
    try {
      if (!verifyEvent(event) || event.kind !== template.kind || event.created_at !== now ||
          event.content !== template.content || JSON.stringify(event.tags) !== JSON.stringify(template.tags) ||
          event.pubkey !== pubkey) throw new Error('Invalid auth event');
    } catch { throw new VaultError('AUTH', { operation }); }
    if (signal.aborted) throw new VaultError('CANCELLED', { operation });
    const compact = JSON.stringify({ id: event.id, pubkey: event.pubkey, created_at: event.created_at,
      kind: event.kind, tags: event.tags, content: event.content, sig: event.sig });
    return `Nostr ${btoa(compact)}`;
  }

  private async read(method: 'GET' | 'HEAD', address: string, signal: AbortSignal): Promise<Response> {
    const init: RequestInit = { method, credentials: 'omit', redirect: 'error', signal };
    let response = await this.fetcher(`${this.endpoint}/${address}`, init);
    if (signal.aborted) { void response.body?.cancel().catch(() => {}); throw new VaultError('CANCELLED'); }
    if (response.status === 401 && this.signer) {
      void response.body?.cancel().catch(() => {});
      const authorization = await this.authorization('get', address, this.signer, signal);
      if (signal.aborted) throw new VaultError('CANCELLED', { operation: 'fetch' });
      response = await this.fetcher(`${this.endpoint}/${address}`, { ...init, headers: { Authorization: authorization } });
      if (signal.aborted) { void response.body?.cancel().catch(() => {}); throw new VaultError('CANCELLED'); }
      if (response.ok || response.status === 404) this.onAuthenticated?.();
    }
    return response;
  }

  get(address: string, expectedSize?: number | bigint, signal?: AbortSignal): Promise<Uint8Array> {
    addressChecked(address);
    const size = expectedSize === undefined ? undefined : Number(expectedSize);
    if (size !== undefined && (!Number.isSafeInteger(size) || size < 0)) throw new VaultError('ARG');
    if (size !== undefined && size > MAX_OBJECT_BYTES) throw new VaultError('TOO_LARGE');
    return this.run(signal, 'fetch', async requestSignal => {
      const response = await this.read('GET', address, requestSignal);
      responseStatus(response, 'fetch');
      const bytes = await this.body(response, size ?? MAX_OBJECT_BYTES, requestSignal, 'fetch');
      if (size !== undefined && bytes.length !== size) throw new VaultError('INCOMPLETE', { operation: 'fetch' });
      if (bytesToHex(sha256(bytes)) !== address) throw new VaultError('HASH_MISMATCH', { operation: 'fetch' });
      return bytes;
    });
  }

  head(address: string, signal?: AbortSignal): Promise<BlossomHead> {
    addressChecked(address);
    return this.run(signal, 'fetch', async requestSignal => {
      const response = await this.read('HEAD', address, requestSignal);
      if (response.status === 404) return { exists: false };
      responseStatus(response, 'fetch');
      const size = sizeHeader(response);
      if (size !== undefined && size > MAX_OBJECT_BYTES) throw new VaultError('TOO_LARGE', { operation: 'fetch' });
      return { exists: true, ...(size === undefined ? {} : { size }) };
    });
  }

  put(bytes: Uint8Array, address: string, signer: NostrSigner, signal?: AbortSignal): Promise<BlossomPut> {
    addressChecked(address);
    if (bytes.length > MAX_OBJECT_BYTES) throw new VaultError('TOO_LARGE', { operation: 'upload' });
    // Own the bytes before the signer/network await; caller mutations cannot alter the authorised hash.
    const body = new Uint8Array(bytes);
    if (bytesToHex(sha256(body)) !== address) throw new VaultError('HASH_MISMATCH', { operation: 'upload' });
    return this.run(signal, 'upload', async requestSignal => {
      const authorization = await this.authorization('upload', address, signer, requestSignal);
      const response = await this.fetcher(`${this.endpoint}/upload`, {
        method: 'PUT', credentials: 'omit', redirect: 'error', signal: requestSignal, body,
        headers: { 'Content-Type': 'application/octet-stream', 'X-SHA-256': address,
          Authorization: authorization },
      });
      if (requestSignal.aborted) { void response.body?.cancel().catch(() => {}); throw new VaultError('CANCELLED'); }
      responseStatus(response, 'upload');
      this.onAuthenticated?.();
      const returnedHeader = response.headers.get('x-sha-256');
      if (returnedHeader !== null && returnedHeader !== address) throw new VaultError('HASH_MISMATCH', { operation: 'upload' });
      const result = await this.body(response, MAX_UPLOAD_RESPONSE_BYTES, requestSignal, 'upload');
      if (result.length) {
        let descriptor: unknown;
        try { descriptor = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result)); }
        catch { throw new VaultError('NETWORK', { operation: 'upload' }); }
        if (typeof descriptor !== 'object' || descriptor === null || Array.isArray(descriptor)) {
          throw new VaultError('NETWORK', { operation: 'upload' });
        }
        if ('sha256' in descriptor && descriptor.sha256 !== address) throw new VaultError('HASH_MISMATCH', { operation: 'upload' });
      }
      return { address, size: body.length };
    });
  }

  stop(): void {
    this.stopped = true;
    for (const request of this.requests) request.abort();
    this.requests.clear();
  }
}
