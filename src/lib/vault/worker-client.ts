import { VaultError, type VaultErrorCode } from './errors';
import { UINT64_MAX } from './protocol';
import type { Address, ChunkRef, DirectoryNode, NodeId } from './types';

export interface ChunkHash { readonly boundary: number; readonly plaintextHash: string }
export interface ChunkResult { readonly boundaries: number[]; readonly plaintextHashes: string[] }
export interface SealedChunk extends ChunkRef { readonly sealed: Uint8Array<ArrayBuffer> }
export interface SealedManifest { readonly address: Address; readonly sealed: Uint8Array<ArrayBuffer> }
export interface NodeKeyInput { readonly nodeKey: Uint8Array; readonly epoch: bigint }
export interface SealChunksInput extends NodeKeyInput { readonly buffer: ArrayBuffer }
export interface OpenChunkInput extends NodeKeyInput {
  readonly sealed: ArrayBuffer;
  readonly sizePlain: bigint;
  readonly expectedAddress: Address;
}
export interface SealManifestInput extends NodeKeyInput { readonly node: DirectoryNode }
export interface OpenManifestInput extends NodeKeyInput { readonly sealed: ArrayBuffer; readonly expectedAddress: Address }
export type WorkerChunkMetadata = ChunkHash | ChunkRef | { readonly address: Address };
export type WorkerTaskChunk<K extends WorkerTaskName> = VaultWorkerTasks[K] extends { chunk: infer C } ? C : Uint8Array<ArrayBuffer>;

/** Codec modules can extend this interface when registering their task table. */
export interface VaultWorkerTasks {
  echo: { parameters: Record<string, never>; result: { byteLength: number } };
  hash: { parameters: Record<string, never>; result: { byteLength: number } };
  chunk: { parameters: Record<string, never>; result: ChunkResult; chunk: ChunkHash };
  sealChunk: { parameters: { epoch: bigint }; result: { chunkCount: number }; chunk: SealedChunk };
  sealChunks: { parameters: { epoch: bigint }; result: { chunkCount: number }; chunk: SealedChunk };
  openChunk: { parameters: { epoch: bigint; sizePlain: bigint; expectedAddress: Address }; result: { byteLength: number } };
  sealManifest: { parameters: { epoch: bigint; node: DirectoryNode }; result: { address: Address }; chunk: SealedManifest };
  openManifest: { parameters: { epoch: bigint; expectedAddress: Address }; result: DirectoryNode };
}
export type WorkerTaskName = keyof VaultWorkerTasks;
export interface JobKeyRef { readonly nodeId: NodeId; readonly epoch: bigint }
export interface JobNodeKey { readonly nodeId?: NodeId; readonly epoch: string; readonly key: Uint8Array<ArrayBuffer> }
export interface WorkerInput<K extends WorkerTaskName> {
  readonly parameters: VaultWorkerTasks[K]['parameters'];
  /** Ownership transfers to the worker. Node-key source buffers never transfer. */
  readonly buffers: readonly ArrayBuffer[];
}
export interface WorkerJobOptions {
  readonly signal?: AbortSignal;
  /** A single job-local key, copied before transfer; never an identity key or ring. */
  readonly nodeKey?: NodeKeyInput;
  readonly neededKeys?: readonly JobKeyRef[];
  readonly resolveNodeKey?: (reference: JobKeyRef) => Uint8Array;
}
export type WorkerRequest =
  | { readonly type: 'run'; readonly jobId: string; readonly task: WorkerTaskName; readonly parameters: unknown; readonly buffers: readonly ArrayBuffer[]; readonly nodeKeys: readonly JobNodeKey[] }
  | { readonly type: 'consumed'; readonly jobId: string; readonly sequence: number };
export type WorkerResponse =
  | { readonly type: 'chunk'; readonly jobId: string; readonly sequence: number; readonly buffer: ArrayBuffer; readonly metadata?: WorkerChunkMetadata }
  | { readonly type: 'done'; readonly jobId: string; readonly result: unknown }
  | { readonly type: 'error'; readonly jobId: string; readonly code: VaultErrorCode };
export interface WorkerTransport {
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  postMessage(request: WorkerRequest, transfer: Transferable[]): void;
  terminate(): void;
}
export interface WorkerJob<R, C = Uint8Array<ArrayBuffer>> {
  readonly id: string;
  readonly chunks: AsyncIterable<C>;
  /** Completion waits until all chunks have been consumed. */
  readonly result: Promise<R>;
  abort(): void;
}
interface PendingChunk { sequence: number; bytes: Uint8Array<ArrayBuffer>; metadata?: WorkerChunkMetadata }
interface ActiveJob {
  id: string;
  queue: PendingChunk[];
  nextSequence: number;
  waiting?: { resolve: (value: IteratorResult<PendingChunk>) => void; reject: (error: VaultError) => void };
  resolve: (result: unknown) => void;
  reject: (error: VaultError) => void;
  error?: VaultError;
  done: boolean;
  removeAbort: () => void;
}

/** One active job per worker: terminating a cancelled job cannot silently kill peers. */
export class VaultWorkerClient {
  private worker: WorkerTransport;
  private active?: ActiveJob;
  private closed = false;
  constructor(private readonly workerFactory: () => WorkerTransport = () => new Worker(new URL('./vault.worker.ts', import.meta.url), { type: 'module' })) {
    this.worker = this.createWorker();
  }
  private createWorker(): WorkerTransport {
    const worker = this.workerFactory();
    worker.onmessage = event => this.receive(event.data);
    worker.onerror = () => this.fail(new VaultError('IO'), true);
    return worker;
  }
  chunk(buffer: ArrayBuffer, options: Pick<WorkerJobOptions, 'signal'> = {}) {
    return this.run('chunk', { parameters: {}, buffers: [buffer] }, { signal: options.signal });
  }
  sealChunk(input: SealChunksInput, options: Pick<WorkerJobOptions, 'signal'> = {}) {
    return this.run('sealChunk', { parameters: { epoch: input.epoch }, buffers: [input.buffer] }, { signal: options.signal, nodeKey: input });
  }
  sealChunks(input: SealChunksInput, options: Pick<WorkerJobOptions, 'signal'> = {}) {
    return this.run('sealChunks', { parameters: { epoch: input.epoch }, buffers: [input.buffer] }, { signal: options.signal, nodeKey: input });
  }
  openChunk(input: OpenChunkInput, options: Pick<WorkerJobOptions, 'signal'> = {}) {
    return this.run('openChunk', {
      parameters: { epoch: input.epoch, sizePlain: input.sizePlain, expectedAddress: input.expectedAddress }, buffers: [input.sealed],
    }, { signal: options.signal, nodeKey: input });
  }
  sealManifest(input: SealManifestInput, options: Pick<WorkerJobOptions, 'signal'> = {}) {
    return this.run('sealManifest', { parameters: { epoch: input.epoch, node: input.node }, buffers: [] }, { signal: options.signal, nodeKey: input });
  }
  openManifest(input: OpenManifestInput, options: Pick<WorkerJobOptions, 'signal'> = {}) {
    return this.run('openManifest', {
      parameters: { epoch: input.epoch, expectedAddress: input.expectedAddress }, buffers: [input.sealed],
    }, { signal: options.signal, nodeKey: input });
  }
  run<K extends WorkerTaskName>(task: K, input: WorkerInput<K>, options: WorkerJobOptions = {}): WorkerJob<VaultWorkerTasks[K]['result'], WorkerTaskChunk<K>> {
    if (this.closed) throw new VaultError('CANCELLED');
    if (this.active) throw new VaultError('CONFLICT');
    if (options.signal?.aborted) throw new VaultError('CANCELLED');
    if (Object.keys(input).some(key => key !== 'parameters' && key !== 'buffers')
      || input.buffers.some(buffer => !(buffer instanceof ArrayBuffer))
      || new Set(input.buffers).size !== input.buffers.length
      || !input.parameters || typeof input.parameters !== 'object') throw new VaultError('ARG');
    const fields: Partial<Record<WorkerTaskName, readonly string[]>> = {
      echo: [], hash: [], chunk: [], sealChunk: ['epoch'], sealChunks: ['epoch'],
      openChunk: ['epoch', 'sizePlain', 'expectedAddress'], sealManifest: ['epoch', 'node'],
      openManifest: ['epoch', 'expectedAddress'],
    };
    const allowed = fields[task];
    if (allowed && Object.keys(input.parameters).some(key => !allowed.includes(key))) throw new VaultError('ARG');
    const seen = new Set<string>();
    const nodeKeys: JobNodeKey[] = [];
    try {
      if (options.nodeKey) {
        if (options.neededKeys?.length || typeof options.nodeKey.epoch !== 'bigint'
          || options.nodeKey.epoch < 1n || options.nodeKey.epoch > UINT64_MAX
          || !(options.nodeKey.nodeKey instanceof Uint8Array) || options.nodeKey.nodeKey.byteLength !== 32) throw new VaultError('ARG');
        nodeKeys.push({ epoch: options.nodeKey.epoch.toString(10), key: new Uint8Array(options.nodeKey.nodeKey) });
      }
      for (const reference of options.neededKeys ?? []) {
        if (!/^[0-9a-f]{64}$/.test(reference.nodeId) || typeof reference.epoch !== 'bigint'
          || reference.epoch < 1n || reference.epoch > UINT64_MAX || !options.resolveNodeKey) throw new VaultError('ARG');
        const identity = `${reference.nodeId}:${reference.epoch}`;
        if (seen.has(identity)) throw new VaultError('ARG');
        seen.add(identity);
        const key = new Uint8Array(options.resolveNodeKey(reference));
        if (key.byteLength !== 32) { key.fill(0); throw new VaultError('ARG'); }
        nodeKeys.push({ nodeId: reference.nodeId, epoch: reference.epoch.toString(10), key });
      }
    } catch (error) {
      nodeKeys.forEach(key => key.key.fill(0));
      throw error instanceof VaultError ? error : new VaultError('ARG');
    }
    let resolve!: (result: unknown) => void;
    let reject!: (error: VaultError) => void;
    const result = new Promise<unknown>((yes, no) => { resolve = yes; reject = no; });
    // A consumer may observe only the stream's rejection, not the result promise.
    void result.catch(() => undefined);
    const job: ActiveJob = {
      id: crypto.randomUUID(), queue: [], nextSequence: 0, resolve, reject, done: false, removeAbort: () => undefined,
    };
    this.active = job;
    const abort = () => { if (this.active === job) this.fail(new VaultError('CANCELLED'), true); };
    options.signal?.addEventListener('abort', abort, { once: true });
    job.removeAbort = () => options.signal?.removeEventListener('abort', abort);
    try {
      if (options.signal?.aborted) {
        nodeKeys.forEach(key => key.key.fill(0));
        abort();
      } else this.worker.postMessage({
        type: 'run', jobId: job.id, task, parameters: input.parameters,
        buffers: [...input.buffers], nodeKeys,
      }, [...input.buffers, ...nodeKeys.map(key => key.key.buffer)]);
    } catch {
      nodeKeys.forEach(key => { if (key.key.byteLength) key.key.fill(0); });
      this.fail(new VaultError('ARG'), true);
    }
    let iterated = false;
    return {
      id: job.id, result: result as Promise<VaultWorkerTasks[K]['result']>, abort,
      chunks: {
        [Symbol.asyncIterator]: () => {
          if (iterated) throw new VaultError('CONFLICT');
          iterated = true;
          return {
            next: async (): Promise<IteratorResult<WorkerTaskChunk<K>>> => {
              const next = await this.next(job);
              if (next.done) return { done: true, value: undefined };
              const { bytes, metadata } = next.value;
              const value = task === 'chunk' ? metadata
                : task === 'sealChunk' || task === 'sealChunks' || task === 'sealManifest' ? { ...metadata, sealed: bytes }
                : bytes;
              return { done: false, value: value as WorkerTaskChunk<K> };
            },
            return: async () => { abort(); return { done: true, value: undefined }; },
          };
        },
      },
    };
  }
  private next(job: ActiveJob): Promise<IteratorResult<PendingChunk>> {
    if (job.error) return Promise.reject(job.error);
    const chunk = job.queue.shift();
    if (chunk) {
      this.worker.postMessage({ type: 'consumed', jobId: job.id, sequence: chunk.sequence }, []);
      return Promise.resolve({ done: false, value: chunk });
    }
    if (job.done) return Promise.resolve({ done: true, value: undefined });
    if (job.waiting) return Promise.reject(new VaultError('CONFLICT'));
    return new Promise((resolve, reject) => { job.waiting = { resolve, reject }; });
  }
  private receive(message: WorkerResponse): void {
    const job = this.active;
    if (!job || message.jobId !== job.id) return;
    if (message.type === 'chunk') {
      if (message.sequence !== job.nextSequence++ || !(message.buffer instanceof ArrayBuffer) || job.queue.length >= 2) {
        this.fail(new VaultError('ARG'), true);
        return;
      }
      const bytes = new Uint8Array(message.buffer);
      const chunk: PendingChunk = { sequence: message.sequence, bytes, metadata: message.metadata };
      if (job.waiting) {
        const waiting = job.waiting;
        job.waiting = undefined;
        this.worker.postMessage({ type: 'consumed', jobId: job.id, sequence: message.sequence }, []);
        waiting.resolve({ done: false, value: chunk });
      } else job.queue.push(chunk);
    } else if (message.type === 'done') {
      if (job.queue.length) { this.fail(new VaultError('ARG'), true); return; }
      job.done = true;
      job.removeAbort();
      this.active = undefined;
      job.waiting?.resolve({ done: true, value: undefined });
      job.waiting = undefined;
      job.resolve(message.result);
    } else if (message.type === 'error') {
      this.fail(new VaultError(message.code), true);
    } else this.fail(new VaultError('ARG'), true);
  }
  private fail(error: VaultError, recreate: boolean): void {
    const job = this.active;
    this.active = undefined;
    if (job) {
      job.error = error;
      job.queue.forEach(chunk => chunk.bytes.fill(0));
      job.queue = [];
      job.removeAbort();
      job.waiting?.reject(error);
      job.waiting = undefined;
      job.reject(error);
    }
    this.worker.onmessage = null;
    this.worker.onerror = null;
    this.worker.terminate();
    if (recreate && !this.closed) this.worker = this.createWorker();
  }
  dispose(): void {
    this.closed = true;
    this.fail(new VaultError('CANCELLED'), false);
  }
}
