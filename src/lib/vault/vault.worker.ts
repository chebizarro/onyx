import { VaultError } from './errors';
import { chunkNext } from './chunker';
import { assertUint64, bytes32, hashAddress, openChunk, sealChunk, verifyAddress } from './crypto';
import { openDirectoryNode, sealDirectoryNode } from './dir-node';
import type { Bytes32 } from './types';
import type {
  JobNodeKey, VaultWorkerTasks, WorkerRequest, WorkerResponse, WorkerTaskName, WorkerChunkMetadata,
} from './worker-client';

export interface WorkerTaskContext<P> {
  readonly parameters: P;
  readonly buffers: readonly ArrayBuffer[];
  readonly nodeKeys: readonly JobNodeKey[];
  /** Reserves a credit before posting. At most two chunks can be unconsumed. */
  emit(bytes: Uint8Array, metadata?: WorkerChunkMetadata): Promise<void>;
}
export type WorkerTaskTable = {
  readonly [K in WorkerTaskName]?: (context: WorkerTaskContext<VaultWorkerTasks[K]['parameters']>) => Promise<VaultWorkerTasks[K]['result']>;
};
export interface VaultWorkerScope {
  postMessage(response: WorkerResponse, transfer: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerRequest>) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent<WorkerRequest>) => void): void;
}

function singleBuffer(buffers: readonly ArrayBuffer[]): Uint8Array {
  if (buffers.length !== 1) throw new VaultError('ARG');
  return new Uint8Array(buffers[0]);
}
async function withNodeKey<P extends { epoch: bigint }, R>(context: WorkerTaskContext<P>, run: (key: Bytes32) => Promise<R>): Promise<R> {
  assertUint64(context.parameters.epoch, true);
  if (context.nodeKeys.length !== 1) throw new VaultError('ARG');
  if (context.nodeKeys[0].epoch !== context.parameters.epoch.toString(10)) throw new VaultError('EPOCH');
  const key = bytes32(context.nodeKeys[0].key);
  try { return await run(key); }
  finally { key.fill(0); }
}
async function sealFile(context: WorkerTaskContext<{ epoch: bigint }>, single: boolean): Promise<{ chunkCount: number }> {
  return withNodeKey(context, async key => {
    const bytes = singleBuffer(context.buffers);
    let chunkCount = 0;
    for (let offset = 0; offset < bytes.length || (single && chunkCount === 0);) {
      const length = single ? bytes.length : chunkNext(bytes.subarray(offset));
      const { address, sealed } = sealChunk(key, bytes.subarray(offset, offset + length));
      await context.emit(sealed, { address, sizePlain: BigInt(length), sizeSealed: BigInt(sealed.length), chunkKeyId: context.parameters.epoch });
      chunkCount++;
      offset += length;
    }
    return { chunkCount };
  });
}

export const defaultWorkerTasks: WorkerTaskTable = {
  async chunk({ buffers, nodeKeys, emit }) {
    if (nodeKeys.length) throw new VaultError('ARG');
    const bytes = singleBuffer(buffers);
    const boundaries: number[] = [];
    const plaintextHashes: string[] = [];
    for (let offset = 0; offset < bytes.length;) {
      const end = offset + chunkNext(bytes.subarray(offset));
      const plaintextHash = hashAddress(bytes.subarray(offset, end));
      boundaries.push(end);
      plaintextHashes.push(plaintextHash);
      await emit(new Uint8Array(), { boundary: end, plaintextHash });
      offset = end;
    }
    return { boundaries, plaintextHashes };
  },
  sealChunk: context => sealFile(context, true),
  sealChunks: context => sealFile(context, false),
  async openChunk(context) {
    const sealed = singleBuffer(context.buffers);
    verifyAddress(sealed, context.parameters.expectedAddress);
    return withNodeKey(context, async key => {
      const plaintext = openChunk({ entries: [{ epoch: context.parameters.epoch, nodeKey: key }] }, context.parameters.epoch, sealed, context.parameters.sizePlain);
      try {
        await context.emit(plaintext);
        return { byteLength: plaintext.length };
      } finally { plaintext.fill(0); }
    });
  },
  async sealManifest(context) {
    if (context.buffers.length) throw new VaultError('ARG');
    return withNodeKey(context, async key => {
      if (context.parameters.node.epoch !== context.parameters.epoch) throw new VaultError('EPOCH');
      const { address, sealed } = sealDirectoryNode(context.parameters.node, key);
      await context.emit(sealed, { address });
      return { address };
    });
  },
  async openManifest(context) {
    const sealed = singleBuffer(context.buffers);
    verifyAddress(sealed, context.parameters.expectedAddress);
    return withNodeKey(context, async key => openDirectoryNode(
      { entries: [{ epoch: context.parameters.epoch, nodeKey: key }] }, context.parameters.epoch, sealed,
    ));
  },
  async echo({ buffers, emit }) {
    let byteLength = 0;
    for (const buffer of buffers) {
      byteLength += buffer.byteLength;
      await emit(new Uint8Array(buffer));
    }
    return { byteLength };
  },
  async hash({ buffers, emit }) {
    if (buffers.length !== 1) throw new VaultError('ARG');
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buffers[0]));
    await emit(hash);
    return { byteLength: hash.byteLength };
  },
};
interface RunningJob {
  readonly id: string;
  readonly outstanding: Set<number>;
  sequence: number;
  wake?: () => void;
  stopped: boolean;
}
/** Injectable CPU-only table; no signer, identity, key rings, store or network adapters. */
export function installVaultWorker(scope: VaultWorkerScope, tasks: WorkerTaskTable = defaultWorkerTasks): () => void {
  let running: RunningJob | undefined;
  function execute<K extends WorkerTaskName>(name: K, context: WorkerTaskContext<VaultWorkerTasks[K]['parameters']>) {
    const task = Object.prototype.hasOwnProperty.call(tasks, name) ? tasks[name] : undefined;
    if (!task) throw new VaultError('UNSUPPORTED');
    return task(context);
  }
  async function run(request: Extract<WorkerRequest, { type: 'run' }>): Promise<void> {
    const job: RunningJob = { id: request.jobId, outstanding: new Set(), sequence: 0, stopped: false };
    running = job;
    async function waitForCredit(drain = false): Promise<void> {
      while (!job.stopped && job.outstanding.size >= (drain ? 1 : 2)) {
        await new Promise<void>(resolve => { job.wake = resolve; });
      }
      if (job.stopped) throw new VaultError('CANCELLED');
    }
    let emission = Promise.resolve();
    try {
      if (!Array.isArray(request.buffers) || request.buffers.some(buffer => !(buffer instanceof ArrayBuffer))
        || !Array.isArray(request.nodeKeys)
        || request.nodeKeys.some(key => (key.nodeId !== undefined && !/^[0-9a-f]{64}$/.test(key.nodeId)) || !/^[1-9][0-9]*$/.test(key.epoch)
          || key.key?.byteLength !== 32 || !(key.key instanceof Uint8Array))) throw new VaultError('ARG');
      // The typed client pairs task names with their parameters; tasks validate their own schema.
      const result = await execute(request.task, {
        parameters: request.parameters as VaultWorkerTasks[WorkerTaskName]['parameters'],
        buffers: request.buffers, nodeKeys: request.nodeKeys,
        emit(bytes, metadata) {
          emission = emission.then(async () => {
            await waitForCredit();
            const owned = new Uint8Array(bytes);
            const sequence = job.sequence++;
            job.outstanding.add(sequence);
            scope.postMessage({ type: 'chunk', jobId: job.id, sequence, buffer: owned.buffer, ...(metadata ? { metadata } : {}) }, [owned.buffer]);
          });
          return emission;
        },
      });
      await emission;
      await waitForCredit(true);
      scope.postMessage({ type: 'done', jobId: job.id, result }, []);
    } catch (error) {
      if (!job.stopped) scope.postMessage({
        type: 'error', jobId: job.id, code: error instanceof VaultError ? error.code : 'IO',
      }, []);
    } finally {
      request.nodeKeys?.forEach(key => key.key?.fill(0));
      job.stopped = true;
      job.wake?.();
      if (running === job) running = undefined;
    }
  }
  const listener = (event: MessageEvent<WorkerRequest>) => {
    const request = event.data;
    if (request.type === 'consumed') {
      if (running?.id === request.jobId && running.outstanding.delete(request.sequence)) {
        running.wake?.();
        running.wake = undefined;
      }
    } else if (request.type === 'run') {
      if (running) {
        scope.postMessage({ type: 'error', jobId: request.jobId, code: 'CONFLICT' }, []);
        return;
      }
      void run(request);
    }
  };
  scope.addEventListener('message', listener);
  return () => {
    scope.removeEventListener('message', listener);
    if (running) {
      running.stopped = true;
      running.wake?.();
    }
  };
}

const scope = globalThis as unknown as VaultWorkerScope;
if (typeof document === 'undefined' && typeof scope.postMessage === 'function' && typeof scope.addEventListener === 'function') {
  installVaultWorker(scope);
}
