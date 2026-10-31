import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Worker } from 'node:worker_threads';
import { build } from 'vite';
import type { WorkerTransport, WorkerResponse } from '../worker-client';

/** Browser-message shim only; all task code executes in the emitted worker. */
export async function realWorkerBundle() {
  const root = fileURLToPath(new URL('../../../../', import.meta.url));
  const temporary = await mkdtemp(path.join(tmpdir(), 'onyx-engine-worker-'));
  await build({ root, configFile: path.join(root, 'vite.config.ts'), logLevel: 'silent', build: {
    outDir: path.join(temporary, 'dist'), emptyOutDir: true, minify: false,
    lib: { entry: path.join(root, 'src/lib/vault/worker-client.ts'), formats: ['es'], fileName: 'client' },
  } });
  const asset = (await readdir(path.join(temporary, 'dist/assets'))).find(name => /^vault\.worker-.*\.js$/.test(name));
  if (!asset) throw new Error('Missing worker asset');
  const bootstrap = path.join(temporary, 'bootstrap.mjs');
  await writeFile(bootstrap, `
    import { parentPort } from 'node:worker_threads';
    const listeners = new Map();
    globalThis.postMessage = (data, transfer) => parentPort.postMessage(data, transfer);
    globalThis.addEventListener = (_type, listener) => {
      const wrapped = data => listener({data}); listeners.set(listener, wrapped); parentPort.on('message', wrapped);
    };
    globalThis.removeEventListener = (_type, listener) => parentPort.off('message', listeners.get(listener));
    await import(${JSON.stringify(pathToFileURL(path.join(temporary, 'dist/assets', asset)).href)});
    parentPort.postMessage({type:'ready'});
  `);
  const workers: Worker[] = [];
  return {
    async create(): Promise<WorkerTransport> {
      const worker = new Worker(pathToFileURL(bootstrap)); workers.push(worker);
      await new Promise<void>((resolve, reject) => { worker.once('error', reject); worker.once('message', message => { if (message.type === 'ready') resolve(); else reject(new Error('worker readiness')); }); });
      const transport: WorkerTransport = { onmessage: null, onerror: null,
        postMessage: (request, transfer) => worker.postMessage(request, transfer.filter((v): v is ArrayBuffer => v instanceof ArrayBuffer)), terminate: () => { void worker.terminate(); } };
      worker.on('message', (data: WorkerResponse) => transport.onmessage?.({ data } as MessageEvent<WorkerResponse>));
      worker.on('error', () => transport.onerror?.({} as ErrorEvent));
      return transport;
    },
    async close() { await Promise.all(workers.map(worker => worker.terminate())); await rm(temporary, { recursive: true, force: true }); },
  };
}
