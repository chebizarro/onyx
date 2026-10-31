import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker as NodeWorker } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import chunkerFixture from '../../../../tests/fixtures/vault/chunker.json';
import sealFixture from '../../../../tests/fixtures/vault/seal-v2.json';
import { bytesToHex, hexToBytes, sealManifest } from '../crypto';
import { sealDirectoryNode } from '../dir-node';
import { build } from 'vite';
import {
  VaultWorkerClient, type WorkerRequest, type WorkerResponse, type WorkerTransport,
} from '../worker-client';
import { defaultWorkerTasks, installVaultWorker, type WorkerTaskTable } from '../vault.worker';
import type { Address, DirectoryNode, NodeId } from '../types';

declare module '../worker-client' {
  interface VaultWorkerTasks {
    'test-injected': { parameters: { value: number }; result: { echoed: number } };
  }
}

/** Uses the production dispatcher and real structured-clone transfers, not a task simulation. */
class LocalTransport implements WorkerTransport {
  onmessage: WorkerTransport['onmessage'] = null;
  onerror: WorkerTransport['onerror'] = null;
  readonly requests: WorkerRequest[] = [];
  readonly responses: WorkerResponse[] = [];
  terminated = false;
  private listener?: (event: MessageEvent<WorkerRequest>) => void;
  private readonly uninstall: () => void;
  private readonly barriers: { count: number; resolve: () => void }[] = [];
  constructor(tasks: WorkerTaskTable = defaultWorkerTasks) {
    this.uninstall = installVaultWorker({
      addEventListener: (_type, listener) => { this.listener = listener; },
      removeEventListener: () => { this.listener = undefined; },
      postMessage: (response, transfer) => {
        if (this.terminated) return;
        const cloned = structuredClone(response, { transfer });
        this.responses.push(cloned);
        queueMicrotask(() => {
          if (!this.terminated) this.onmessage?.({ data: cloned } as MessageEvent<WorkerResponse>);
          for (const barrier of this.barriers) {
            if (this.chunks >= barrier.count) barrier.resolve();
          }
        });
      },
    }, tasks);
  }
  get chunks(): number { return this.responses.filter(response => response.type === 'chunk').length; }
  whenChunks(count: number): Promise<void> {
    return this.chunks >= count ? Promise.resolve() : new Promise(resolve => this.barriers.push({ count, resolve }));
  }
  postMessage(request: WorkerRequest, transfer: Transferable[]): void {
    const cloned = structuredClone(request, { transfer });
    this.requests.push(structuredClone(cloned));
    queueMicrotask(() => { if (!this.terminated) this.listener?.({ data: cloned } as MessageEvent<WorkerRequest>); });
  }
  terminate(): void { this.terminated = true; this.uninstall(); }
}
const clients: VaultWorkerClient[] = [];
function localClient(tasks?: WorkerTaskTable) {
  const transports: LocalTransport[] = [];
  const client = new VaultWorkerClient(() => {
    const transport = new LocalTransport(tasks);
    transports.push(transport);
    return transport;
  });
  clients.push(client);
  return { client, transports };
}
function buffers(...values: number[]): ArrayBuffer[] { return values.map(value => Uint8Array.of(value).buffer); }
async function collect(chunks: AsyncIterable<Uint8Array>): Promise<number[][]> {
  const result: number[][] = [];
  for await (const chunk of chunks) result.push([...chunk]);
  return result;
}
async function collectValues<T>(chunks: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const chunk of chunks) result.push(chunk);
  return result;
}
function xorshiftInput(): Uint8Array<ArrayBuffer> {
  let state = Number(chunkerFixture.input.generator.seed);
  return Uint8Array.from({ length: chunkerFixture.input.length }, () => {
    state = (state ^ (state << 13)) >>> 0;
    state = (state ^ (state >>> 17)) >>> 0;
    state = (state ^ (state << 5)) >>> 0;
    return state & 255;
  });
}
function ownedBuffer(bytes: Uint8Array): ArrayBuffer { return new Uint8Array(bytes).buffer; }
function sha256Hex(bytes: Uint8Array): string { return createHash('sha256').update(bytes).digest('hex'); }
const vectorKey = hexToBytes(sealFixture.nodeKeyHex);
const emptyNode: DirectoryNode = { version: 2, nodeId: 'a'.repeat(64) as NodeId, epoch: 3n, entries: [] };
afterEach(() => { clients.splice(0).forEach(client => client.dispose()); });

describe('worker transport', () => {
  it('accepts a typed injected task with its own parameter and result schema', async () => {
    const { client } = localClient({
      'test-injected': async ({ parameters, emit }) => {
        await emit(Uint8Array.of(parameters.value));
        return { echoed: parameters.value };
      },
    });
    const job = client.run('test-injected', { parameters: { value: 42 }, buffers: [] });
    expect(await collect(job.chunks)).toEqual([[42]]);
    expect((await job.result).echoed).toBe(42);
  });

  it('never posts more than two unconsumed chunks and completes only after acknowledgement', async () => {
    const { client, transports } = localClient();
    const input = buffers(1, 2, 3, 4, 5);
    const job = client.run('echo', { parameters: {}, buffers: input });
    expect(input.every(buffer => buffer.byteLength === 0)).toBe(true);
    const transport = transports[0];
    await transport.whenChunks(2);
    expect(transport.chunks).toBe(2);
    expect(transport.responses.some(response => response.type === 'done')).toBe(false);
    const iterator = job.chunks[Symbol.asyncIterator]();
    expect([...(await iterator.next()).value!]).toEqual([1]);
    await transport.whenChunks(3);
    expect(transport.chunks).toBe(3);
    expect(transport.requests.filter(request => request.type === 'consumed')).toHaveLength(1);
    const remaining: number[][] = [];
    for (let next = await iterator.next(); !next.done; next = await iterator.next()) remaining.push([...next.value]);
    expect(remaining).toEqual([[2], [3], [4], [5]]);
    expect(await job.result).toEqual({ byteLength: 5 });
    expect(transport.requests.filter(request => request.type === 'consumed')).toHaveLength(5);
  });

  it('enforces the same credit limit if an injected task emits concurrently', async () => {
    const { client, transports } = localClient({
      echo: async ({ emit }) => {
        await Promise.all([1, 2, 3, 4].map(value => emit(Uint8Array.of(value))));
        return { byteLength: 4 };
      },
    });
    const job = client.run('echo', { parameters: {}, buffers: [] });
    await transports[0].whenChunks(2);
    expect(transports[0].chunks).toBe(2);
    expect(await collect(job.chunks)).toEqual([[1], [2], [3], [4]]);
    expect(await job.result).toEqual({ byteLength: 4 });
  });

  it('transfers only copies of explicitly selected node/epoch keys, never a whole ring or identity key', async () => {
    const { client, transports } = localClient();
    const nodeId = 'a'.repeat(64) as NodeId;
    const ring = new Map([[1n, new Uint8Array(32).fill(1)], [2n, new Uint8Array(32).fill(2)], [3n, new Uint8Array(32).fill(3)]]);
    const requested: bigint[] = [];
    const job = client.run('echo', { parameters: {}, buffers: buffers(7) }, {
      neededKeys: [{ nodeId, epoch: 2n }],
      resolveNodeKey: reference => { requested.push(reference.epoch); return ring.get(reference.epoch)!; },
    });
    await collect(job.chunks);
    await job.result;
    const request = transports[0].requests[0];
    expect(request.type).toBe('run');
    if (request.type !== 'run') throw new Error('not a run request');
    expect(Object.keys(request).sort()).toEqual(['type', 'jobId', 'task', 'parameters', 'buffers', 'nodeKeys'].sort());
    expect(requested).toEqual([2n]);
    expect(request.nodeKeys).toEqual([{ nodeId, epoch: '2', key: new Uint8Array(32).fill(2) }]);
    expect(JSON.stringify(request)).not.toMatch(/identity|secretKey|ring|nsec/);
    expect([...ring.values()].map(key => [key.byteLength, key[0]])).toEqual([[32, 1], [32, 2], [32, 3]]);
  });

  it('rejects key-bearing extras and invalid key selections before sending any request', () => {
    const { client, transports } = localClient();
    const nodeId = 'a'.repeat(64) as NodeId;
    const valid = { nodeId, epoch: 1n };
    expect(() => client.run('echo', { parameters: {}, buffers: [], identityKey: new Uint8Array(32) } as unknown as Parameters<typeof client.run<'echo'>>[1])).toThrow();
    expect(() => client.run('echo', { parameters: { ring: {} }, buffers: [] } as unknown as Parameters<typeof client.run<'echo'>>[1])).toThrow();
    expect(() => client.run('echo', { parameters: {}, buffers: [] }, { neededKeys: [valid] })).toThrow();
    expect(() => client.run('echo', { parameters: {}, buffers: [] }, { neededKeys: [valid, valid], resolveNodeKey: () => new Uint8Array(32) })).toThrow();
    expect(() => client.run('echo', { parameters: {}, buffers: [] }, { neededKeys: [{ nodeId, epoch: 0n }], resolveNodeKey: () => new Uint8Array(32) })).toThrow();
    expect(() => client.run('echo', { parameters: {}, buffers: [] }, { neededKeys: [valid], resolveNodeKey: () => new Uint8Array(31) })).toThrow();
    expect(transports[0].requests).toHaveLength(0);
  });

  it('abort terminates and recreates the worker, rejects both stream/result, and permits a fresh job', async () => {
    const { client, transports } = localClient();
    const controller = new AbortController();
    const job = client.run('echo', { parameters: {}, buffers: buffers(1, 2, 3, 4) }, { signal: controller.signal });
    await transports[0].whenChunks(2);
    controller.abort();
    expect(transports[0].terminated).toBe(true);
    expect(transports).toHaveLength(2);
    await expect(job.result).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(job.chunks[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'CANCELLED' });
    const fresh = client.run('echo', { parameters: {}, buffers: buffers(9) });
    expect(fresh.id).not.toBe(job.id);
    expect(await collect(fresh.chunks)).toEqual([[9]]);
    expect(await fresh.result).toEqual({ byteLength: 1 });
    controller.abort();
    expect(transports).toHaveLength(2);
  });

  it('breaking a stream terminates the worker instead of leaving a blocked producer', async () => {
    const { client, transports } = localClient();
    const job = client.run('echo', { parameters: {}, buffers: buffers(1, 2, 3, 4) });
    for await (const chunk of job.chunks) { expect([...chunk]).toEqual([1]); break; }
    await expect(job.result).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(transports[0].terminated).toBe(true);
    expect(transports).toHaveLength(2);
  });

  it('rejects an already-aborted signal without transferring buffers', () => {
    const { client, transports } = localClient();
    const controller = new AbortController();
    controller.abort();
    const input = buffers(1);
    expect(() => client.run('echo', { parameters: {}, buffers: input }, { signal: controller.signal })).toThrow();
    expect(input[0].byteLength).toBe(1);
    expect(transports[0].requests).toEqual([]);
  });

  it('honors cancellation raised while resolving keys, before transferring file buffers', async () => {
    const { client, transports } = localClient();
    const controller = new AbortController();
    const input = buffers(1);
    const key = new Uint8Array(32).fill(9);
    const job = client.run('echo', { parameters: {}, buffers: input }, {
      signal: controller.signal,
      neededKeys: [{ nodeId: 'a'.repeat(64) as NodeId, epoch: 1n }],
      resolveNodeKey: () => { controller.abort(); return key; },
    });
    await expect(job.result).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(transports[0].requests).toEqual([]);
    expect(transports[0].terminated).toBe(true);
    expect(input[0].byteLength).toBe(1);
    expect(key).toEqual(new Uint8Array(32).fill(9));
  });

  it('isolates the single active job and returns a fixed safe error for task failures', async () => {
    const { client, transports } = localClient({ echo: async () => { throw new Error('sensitive task details'); } });
    const job = client.run('echo', { parameters: {}, buffers: [] });
    expect(() => client.run('echo', { parameters: {}, buffers: [] })).toThrow();
    await expect(job.result).rejects.toMatchObject({ code: 'IO', message: 'Vault file operation failed' });
    await expect(job.chunks[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'IO' });
    expect(JSON.stringify(transports[0].responses)).not.toContain('sensitive task details');
    expect(transports).toHaveLength(2);
  });

  it('runs the real SHA-256 task through the dispatcher and consumes transferred output', async () => {
    const { client } = localClient();
    const job = client.run('hash', { parameters: {}, buffers: [new TextEncoder().encode('abc').buffer] });
    const chunks = await collect(job.chunks);
    expect(chunks).toHaveLength(1);
    expect(chunks[0].map(value => value.toString(16).padStart(2, '0')).join('')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(await job.result).toEqual({ byteLength: 32 });
  });
});

describe('worker codec tasks', () => {
  it('streams fixture chunk boundaries/hashes and sealed chunks for the 4 MiB xorshift32 file', async () => {
    const input = xorshiftInput();
    const { client, transports } = localClient();
    const chunkBuffer = ownedBuffer(input);
    const chunkJob = client.chunk(chunkBuffer);
    expect(chunkBuffer.byteLength).toBe(0);
    await transports[0].whenChunks(2);
    expect(transports[0].chunks).toBe(2);
    const hashes = await collectValues(chunkJob.chunks);
    const expectedHashes = chunkerFixture.cutEnds.map((end, i) => sha256Hex(input.subarray(i ? chunkerFixture.cutEnds[i - 1] : 0, end)));
    expect(hashes).toEqual(chunkerFixture.cutEnds.map((boundary, i) => ({ boundary, plaintextHash: expectedHashes[i] })));
    expect(await chunkJob.result).toEqual({ boundaries: chunkerFixture.cutEnds, plaintextHashes: expectedHashes });

    const sealBuffer = ownedBuffer(input);
    const sealJob = client.sealChunks({ nodeKey: vectorKey, epoch: 3n, buffer: sealBuffer });
    expect(sealBuffer.byteLength).toBe(0);
    const sealedChunks = await collectValues(sealJob.chunks);
    expect(await sealJob.result).toEqual({ chunkCount: chunkerFixture.cutEnds.length });
    let offset = 0;
    for (const [i, chunk] of sealedChunks.entries()) {
      offset += Number(chunk.sizePlain);
      expect(offset).toBe(chunkerFixture.cutEnds[i]);
      expect(chunk.sizeSealed).toBe(BigInt(chunk.sealed.length));
      expect(chunk.chunkKeyId).toBe(3n);
      expect(chunk.address).toBe(sha256Hex(chunk.sealed));
      const opened = client.openChunk({ nodeKey: vectorKey, epoch: chunk.chunkKeyId, sealed: chunk.sealed.buffer, sizePlain: chunk.sizePlain, expectedAddress: chunk.address });
      const plaintext = await collectValues(opened.chunks);
      expect(plaintext).toHaveLength(1);
      expect(sha256Hex(plaintext[0])).toBe(expectedHashes[i]);
      expect(await opened.result).toEqual({ byteLength: Number(chunk.sizePlain) });
    }
    expect(offset).toBe(input.length);
    expect(bytesToHex(vectorKey)).toBe(sealFixture.nodeKeyHex);
  }, 30000);

  it.each(sealFixture.chunks)('seals and opens the $name single-chunk vector, including empty bytes', async vector => {
    const { client, transports } = localClient();
    const plaintext = hexToBytes(vector.plaintextHex);
    const job = client.sealChunk({ nodeKey: vectorKey, epoch: BigInt(vector.epoch), buffer: ownedBuffer(plaintext) });
    const chunks = await collectValues(job.chunks);
    expect(await job.result).toEqual({ chunkCount: 1 });
    expect(chunks).toHaveLength(1);
    const chunk = chunks[0];
    expect(bytesToHex(chunk.sealed)).toBe(vector.sealedHex);
    expect(chunk).toMatchObject({ address: vector.address, sizePlain: BigInt(plaintext.length), sizeSealed: BigInt(vector.sealedHex.length / 2), chunkKeyId: BigInt(vector.epoch) });
    const request = transports[0].requests[0];
    if (request.type !== 'run') throw new Error('not a run request');
    expect(request.nodeKeys).toEqual([{ epoch: vector.epoch, key: vectorKey }]);
    expect(request.parameters).toEqual({ epoch: BigInt(vector.epoch) });
    expect(JSON.stringify(request.nodeKeys)).not.toMatch(/identity|secretKey|ring|nsec/);
    const opened = client.openChunk({ nodeKey: vectorKey, epoch: chunk.chunkKeyId, sealed: chunk.sealed.buffer, sizePlain: chunk.sizePlain, expectedAddress: chunk.address });
    expect(await collect(opened.chunks)).toEqual([[...plaintext]]);
    expect(await opened.result).toEqual({ byteLength: plaintext.length });
    expect(bytesToHex(vectorKey)).toBe(sealFixture.nodeKeyHex);
  });

  it('emits no file chunks or hashes for an empty file', async () => {
    const { client } = localClient();
    const chunked = client.chunk(new ArrayBuffer(0));
    expect(await collectValues(chunked.chunks)).toEqual([]);
    expect(await chunked.result).toEqual({ boundaries: [], plaintextHashes: [] });
    const sealed = client.sealChunks({ nodeKey: vectorKey, epoch: 3n, buffer: new ArrayBuffer(0) });
    expect(await collectValues(sealed.chunks)).toEqual([]);
    expect(await sealed.result).toEqual({ chunkCount: 0 });
  });

  it('aborts mid-file at backpressure, rejects the stream, and runs a fresh codec job', async () => {
    const { client, transports } = localClient();
    const controller = new AbortController();
    const job = client.sealChunks({ nodeKey: vectorKey, epoch: 3n, buffer: xorshiftInput().buffer }, { signal: controller.signal });
    await transports[0].whenChunks(2);
    expect(transports[0].chunks).toBe(2);
    const iterator = job.chunks[Symbol.asyncIterator]();
    const first = await iterator.next();
    expect(first.value!.sizePlain).toBe(BigInt(chunkerFixture.cutEnds[0]));
    await transports[0].whenChunks(3);
    controller.abort();
    expect(transports[0].terminated).toBe(true);
    expect(transports).toHaveLength(2);
    await expect(job.result).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(iterator.next()).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(transports[0].responses.some(response => response.type === 'done')).toBe(false);
    const fresh = client.sealChunk({ nodeKey: vectorKey, epoch: 3n, buffer: ownedBuffer(hexToBytes(sealFixture.chunks[1].plaintextHex)) });
    const [sealed] = await collectValues(fresh.chunks);
    expect(sealed.address).toBe(sealFixture.chunks[1].address);
    expect(await fresh.result).toEqual({ chunkCount: 1 });
    expect(bytesToHex(vectorKey)).toBe(sealFixture.nodeKeyHex);
  }, 30000);

  it('seals and opens strict dir-node CBOR without changing codec bytes or bigint fields', async () => {
    const { client } = localClient();
    const job = client.sealManifest({ nodeKey: vectorKey, epoch: emptyNode.epoch, node: emptyNode });
    const [manifest] = await collectValues(job.chunks);
    const expected = sealDirectoryNode(emptyNode, vectorKey);
    expect(manifest).toEqual(expected);
    expect(await job.result).toEqual({ address: expected.address });
    const opened = client.openManifest({ nodeKey: vectorKey, epoch: emptyNode.epoch, sealed: manifest.sealed.buffer, expectedAddress: manifest.address });
    expect(await collect(opened.chunks)).toEqual([]);
    expect(await opened.result).toEqual(emptyNode);
  });

  it('refuses wrong addresses before authentication and rejects the one supplied wrong key or epoch', async () => {
    const { client } = localClient();
    const vector = sealFixture.chunks[1];
    const wrongAddress = client.openChunk({ nodeKey: vectorKey, epoch: 3n, sealed: buffers(1)[0], sizePlain: 1n, expectedAddress: vector.address as Address });
    await expect(wrongAddress.result).rejects.toMatchObject({ code: 'HASH_MISMATCH' });
    const wrongKey = client.openChunk({ nodeKey: new Uint8Array(32), epoch: 3n, sealed: ownedBuffer(hexToBytes(vector.sealedHex)), sizePlain: BigInt(vector.plaintextHex.length / 2), expectedAddress: vector.address as Address });
    await expect(wrongKey.result).rejects.toMatchObject({ code: 'CRYPTO' });
    const wrongEpoch = client.run('openChunk', {
      parameters: { epoch: 2n, sizePlain: BigInt(vector.plaintextHex.length / 2), expectedAddress: vector.address as Address },
      buffers: [ownedBuffer(hexToBytes(vector.sealedHex))],
    }, { nodeKey: { nodeKey: vectorKey, epoch: 3n } });
    await expect(wrongEpoch.result).rejects.toMatchObject({ code: 'EPOCH' });
  });

  it('rejects invalid manifest CBOR, mismatched epochs, and wrong manifest addresses', async () => {
    const { client } = localClient();
    const malformed = sealManifest(vectorKey, Uint8Array.of(0));
    const invalid = client.openManifest({ nodeKey: vectorKey, epoch: 3n, sealed: ownedBuffer(malformed.sealed), expectedAddress: malformed.address });
    await expect(invalid.result).rejects.toMatchObject({ code: 'ARG' });
    const wrongSealEpoch = client.sealManifest({ nodeKey: vectorKey, epoch: 2n, node: emptyNode });
    await expect(wrongSealEpoch.result).rejects.toMatchObject({ code: 'EPOCH' });
    const manifest = sealDirectoryNode(emptyNode, vectorKey);
    const wrongOpenEpoch = client.openManifest({ nodeKey: vectorKey, epoch: 2n, sealed: ownedBuffer(manifest.sealed), expectedAddress: manifest.address });
    await expect(wrongOpenEpoch.result).rejects.toMatchObject({ code: 'EPOCH' });
    const wrongAddress = client.openManifest({ nodeKey: vectorKey, epoch: 3n, sealed: ownedBuffer(manifest.sealed), expectedAddress: '0'.repeat(64) as Address });
    await expect(wrongAddress.result).rejects.toMatchObject({ code: 'HASH_MISMATCH' });
  });

  it('rejects invalid direct keys and key-bearing task extras before transfer', () => {
    const { client, transports } = localClient();
    const input = buffers(7)[0];
    expect(() => client.sealChunks({ nodeKey: new Uint8Array(31), epoch: 3n, buffer: input })).toThrow();
    expect(() => client.sealChunk({ nodeKey: vectorKey, epoch: 0n, buffer: input })).toThrow();
    expect(() => client.run('sealChunks', { parameters: { epoch: 3n, identityKey: vectorKey }, buffers: [input] } as unknown as Parameters<typeof client.run<'sealChunks'>>[1])).toThrow();
    expect(input.byteLength).toBe(1);
    expect(transports[0].requests).toEqual([]);
  });
});

it.each(['tauri', 'web'])('builds and executes the actual %s Vite ESM worker asset in a separate Node worker thread', async target => {
  const previousTarget = process.env.BUILD_TARGET;
  process.env.BUILD_TARGET = target;
  const root = fileURLToPath(new URL('../../../../', import.meta.url));
  const temporary = await mkdtemp(path.join(tmpdir(), 'onyx-vault-worker-'));
  let worker: NodeWorker | undefined;
  let client: VaultWorkerClient | undefined;
  try {
    // Use the owning Vite config (including worker.format), but a minimal client entry.
    await build({
      root, configFile: path.join(root, 'vite.config.ts'), logLevel: 'silent',
      build: {
        outDir: path.join(temporary, 'dist'), emptyOutDir: true, minify: false,
        lib: { entry: path.join(root, 'src/lib/vault/worker-client.ts'), formats: ['es'], fileName: 'client' },
      },
    });
    const assets = await readdir(path.join(temporary, 'dist/assets'));
    const asset = assets.find(name => /^vault\.worker-.*\.js$/.test(name));
    expect(asset).toBeTruthy();
    const workerPath = path.join(temporary, 'dist/assets', asset!);
    expect(await readFile(workerPath, 'utf8')).not.toContain('importScripts(');
    const bootstrap = path.join(temporary, 'bootstrap.mjs');
    // Only adapts Node's parentPort to the browser message API; task code is the emitted asset.
    await writeFile(bootstrap, `
      import { parentPort } from 'node:worker_threads';
      const listeners = new Map();
      globalThis.postMessage = (message, transfer) => parentPort.postMessage(message, transfer);
      globalThis.addEventListener = (_type, listener) => {
        const wrapped = data => listener({ data }); listeners.set(listener, wrapped);
        parentPort.on('message', wrapped);
      };
      globalThis.removeEventListener = (_type, listener) => parentPort.off('message', listeners.get(listener));
      await import(${JSON.stringify(pathToFileURL(workerPath).href)});
      parentPort.postMessage({ type: 'ready' });
    `);
    worker = new NodeWorker(pathToFileURL(bootstrap));
    await new Promise<void>((resolve, reject) => {
      worker!.once('error', reject);
      worker!.once('message', message => { if (message.type === 'ready') resolve(); else reject(new Error('worker did not initialize')); });
    });
    const transport: WorkerTransport = {
      onmessage: null, onerror: null,
      postMessage: (request, transfer) => worker!.postMessage(request, transfer.filter((item): item is ArrayBuffer => item instanceof ArrayBuffer)),
      terminate: () => { void worker!.terminate(); },
    };
    worker.on('message', (message: WorkerResponse) => transport.onmessage?.({ data: message } as MessageEvent<WorkerResponse>));
    worker.on('error', () => transport.onerror?.({} as ErrorEvent));
    client = new VaultWorkerClient(() => transport);
    const input = new TextEncoder().encode('abc').buffer;
    const hash = client.run('hash', { parameters: {}, buffers: [input] });
    expect(input.byteLength).toBe(0);
    const output = await collect(hash.chunks);
    expect(output[0].map(value => value.toString(16).padStart(2, '0')).join('')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(await hash.result).toEqual({ byteLength: 32 });
    const echo = client.run('echo', { parameters: {}, buffers: buffers(1, 2, 3, 4) });
    expect(await collect(echo.chunks)).toEqual([[1], [2], [3], [4]]);
    expect(await echo.result).toEqual({ byteLength: 4 });
    const vector = sealFixture.chunks[1];
    const seal = client.sealChunk({ nodeKey: vectorKey, epoch: 3n, buffer: ownedBuffer(hexToBytes(vector.plaintextHex)) });
    const [sealed] = await collectValues(seal.chunks);
    expect(bytesToHex(sealed.sealed)).toBe(vector.sealedHex);
    expect(sealed.address).toBe(vector.address);
    expect(await seal.result).toEqual({ chunkCount: 1 });
    const open = client.openChunk({ nodeKey: vectorKey, epoch: sealed.chunkKeyId, sealed: sealed.sealed.buffer, sizePlain: sealed.sizePlain, expectedAddress: sealed.address });
    expect(await collect(open.chunks)).toEqual([[...hexToBytes(vector.plaintextHex)]]);
    expect(await open.result).toEqual({ byteLength: vector.plaintextHex.length / 2 });
    const manifestJob = client.sealManifest({ nodeKey: vectorKey, epoch: emptyNode.epoch, node: emptyNode });
    const [manifest] = await collectValues(manifestJob.chunks);
    expect(await manifestJob.result).toEqual({ address: manifest.address });
    const openNode = client.openManifest({ nodeKey: vectorKey, epoch: emptyNode.epoch, sealed: manifest.sealed.buffer, expectedAddress: manifest.address });
    expect(await openNode.result).toEqual(emptyNode);
  } finally {
    if (previousTarget === undefined) delete process.env.BUILD_TARGET;
    else process.env.BUILD_TARGET = previousTarget;
    client?.dispose();
    await worker?.terminate();
    await rm(temporary, { recursive: true, force: true });
  }
}, 30000);
