import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { finalizeEvent, getPublicKey, matchFilters, nip44, type Event, type Filter } from 'nostr-tools';
import type { FileEntry, SecretStore, VaultFS } from '../../../platform/types';
import type { NostrSigner } from '../../nostr/signer';
import { hashAddress, hex32 } from '../crypto';
import type { VaultEngineDeps, VaultEngineSnapshot, VaultSession } from '../engine-api';
import { VaultError } from '../errors';
import type { RelayHandlers, RelayPublishResult, VaultRelaySubscription } from '../relay';
import { VaultStore, VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION } from '../store';
import { wrap } from 'idb';
import { installVaultWorker } from '../vault.worker';
import type { WorkerRequest, WorkerResponse, WorkerTransport } from '../worker-client';
import type { Address, Pubkey, StoredNetwork } from '../types';

export const network: StoredNetwork = { readRelays: ['wss://relay.example.com/'], writeRelays: ['wss://relay.example.com/'], readBlossom: ['https://blossom.example.com/'], writeBlossom: ['https://blossom.example.com/'] };
export class MemoryFS implements VaultFS {
  readonly files = new Map<string, Uint8Array>();
  readonly directories = new Set(['/notebook']);
  readonly writes: string[] = [];
  readonly modified = new Map<string, number>();
  beforeWrite?: (path: string) => void | Promise<void>;
  afterWrite?: (path: string) => void | Promise<void>;
  omit = new Set<string>();
  async list(root: string) { return this.listAll(root); }
  async listAll(root: string): Promise<FileEntry[]> {
    if (!this.directories.has(root)) throw new VaultError('IO');
    const prefix = root + '/'; const entries: FileEntry[] = [];
    for (const path of [...this.directories, ...this.files.keys()]) if (path.startsWith(prefix) && !path.slice(prefix.length).includes('/') && !this.omit.has(path)) {
      const isDirectory = this.directories.has(path);
      entries.push({ name: path.slice(prefix.length), path, isDirectory, ...(isDirectory ? { children: await this.listAll(path) } : {}) });
    }
    return entries;
  }
  async listAssets() { return []; }
  async read(path: string) { return new TextDecoder().decode(await this.readBinary(path)); }
  async readBinary(path: string) { const bytes = this.files.get(path); if (!bytes) throw new VaultError('IO'); return new Uint8Array(bytes); }
  async write(path: string, text: string) { await this.writeBinary(path, new TextEncoder().encode(text)); }
  async writeBinary(path: string, bytes: Uint8Array) {
    await this.beforeWrite?.(path);
    if (!this.directories.has(path.slice(0, path.lastIndexOf('/'))) || this.directories.has(path)) throw new VaultError('IO');
    this.files.set(path, new Uint8Array(bytes)); this.modified.set(path, (this.modified.get(path) ?? 0) + 1); this.writes.push(path);
    await this.afterWrite?.(path);
  }
  async createFile(path: string) { await this.write(path, ''); }
  async createFolder(path: string) { if (this.files.has(path)) throw new VaultError('IO'); this.directories.add(path); }
  async rename(from: string, to: string) { await this.copy(from, to); await this.remove(from); }
  async remove(path: string) { for (const file of this.files.keys()) if (file === path || file.startsWith(path + '/')) this.files.delete(file); for (const dir of this.directories) if (dir === path || dir.startsWith(path + '/')) this.directories.delete(dir); }
  async copy(from: string, to: string) { await this.writeBinary(to, await this.readBinary(from)); }
  async exists(path: string) { return this.files.has(path) || this.directories.has(path); }
  async modifiedTime(path: string) { return this.modified.get(path) ?? 0; }
  async stats(path: string) { if (!await this.exists(path)) throw new VaultError('IO'); return { size: this.files.get(path)?.length ?? 0, created: 0, modified: await this.modifiedTime(path) }; }
  async setVaultScope() {} async startWatching() {} async stopWatching() {}
  async onFilesChanged() { return () => {}; } async onFileModified() { return () => {}; }
}
export class LocalWorker implements WorkerTransport {
  onmessage: WorkerTransport['onmessage'] = null;
  onerror: WorkerTransport['onerror'] = null;
  readonly requests: WorkerRequest[] = [];
  private listener?: (event: MessageEvent<WorkerRequest>) => void;
  private stopped = false;
  private uninstall: () => void;
  constructor() {
    this.uninstall = installVaultWorker({
      addEventListener: (_type, listener) => { this.listener = listener; }, removeEventListener: () => { this.listener = undefined; },
      postMessage: (response, transfer) => { const clone = structuredClone(response, { transfer }); queueMicrotask(() => { if (!this.stopped) this.onmessage?.({ data: clone } as MessageEvent<WorkerResponse>); }); },
    });
  }
  postMessage(request: WorkerRequest, transfer: Transferable[]) { const cloned = structuredClone(request, { transfer }); this.requests.push(structuredClone(cloned)); queueMicrotask(() => { if (!this.stopped) this.listener?.({ data: cloned } as MessageEvent<WorkerRequest>); }); }
  terminate() { this.stopped = true; this.uninstall(); }
}
export class ScriptedNetwork {
  readonly events = new Map<string, Event>();
  readonly objects = new Map<string, Uint8Array>();
  readonly published: Event[] = [];
  readonly puts: string[] = [];
  readonly heads: string[] = [];
  readonly gets: string[] = [];
  readonly backfills: Filter[][] = [];
  readonly subscriptionFrames: Filter[][] = [];
  readonly relayClients: string[][] = [];
  readonly subscribers = new Set<{ filters: readonly Filter[]; handlers: RelayHandlers }>();
  losePut = false;
  loseHead = false;
  rejectHead = false;
  rejectWrap = false;
  failPut = false;
  beforePublish?: (event: Event) => void | Promise<void>;
  beforePut?: (address: string) => void | Promise<void>;
  afterPut?: (address: string) => void | Promise<void>;
  beforeBackfill?: () => void | Promise<void>;
  relayFactory: NonNullable<VaultEngineDeps['relayFactory']> = endpoints => {
    this.relayClients.push([...endpoints]);
    let stopped = false;
    const own = new Set<{ filters: readonly Filter[]; handlers: RelayHandlers }>();
    const publish = async (event: Event): Promise<RelayPublishResult> => {
      await this.beforePublish?.(event); if (stopped) throw new VaultError('CANCELLED');
      this.published.push(structuredClone(event));
      const head = event.tags.some(t => t[0] === 'd' && t[1].startsWith('porthome/v2/'));
      const rejected = head && this.rejectHead || event.kind === 1059 && this.rejectWrap;
      if (!rejected) this.emit(structuredClone(event));
      const lost = head && this.loseHead; if (head) this.loseHead = false;
      return { event, durable: !(lost || rejected), degraded: !!lost,
        outcomes: endpoints.map(relay => lost ? { relay, status: 'unknown', error: new VaultError('NETWORK') } : rejected ? { relay, status: 'rejected', reason: 'denied' } : { relay, status: 'accepted', reason: '' }) };
    };
    return { endpoints, publish, retry: publish,
      subscribe: (filters, handlers): VaultRelaySubscription => { this.subscriptionFrames.push(structuredClone([...filters])); const item = { filters, handlers }; own.add(item); this.subscribers.add(item); queueMicrotask(() => { if (!stopped && own.has(item)) endpoints.forEach(endpoint => handlers.oneose?.(endpoint)); }); return { close: () => { own.delete(item); this.subscribers.delete(item); }, reconnect: async () => {} }; },
      backfill: async (filters, handlers) => { this.backfills.push(structuredClone([...filters])); await this.beforeBackfill?.(); if (stopped) throw new VaultError('CANCELLED'); for (const event of this.events.values()) if (matchFilters([...filters], event)) handlers.onevent(structuredClone(event), endpoints[0]); endpoints.forEach(e => handlers.oneose?.(e)); },
      stop: () => { stopped = true; for (const item of own) this.subscribers.delete(item); },
    };
  };
  blossomFactory: NonNullable<VaultEngineDeps['blossomFactory']> = endpoint => ({ endpoint,
    get: async address => { this.gets.push(address); const bytes = this.objects.get(address); if (!bytes) throw new VaultError('INCOMPLETE'); return new Uint8Array(bytes); },
    head: async address => { this.heads.push(address); return { exists: this.objects.has(address), size: this.objects.get(address)?.length }; },
    put: async (bytes, address) => {
      await this.beforePut?.(address); if (this.failPut) throw new VaultError('NETWORK');
      if (hashAddress(bytes) !== address) throw new VaultError('HASH_MISMATCH');
      this.puts.push(address); this.objects.set(address, new Uint8Array(bytes)); await this.afterPut?.(address);
      if (this.losePut) { this.losePut = false; throw new VaultError('NETWORK'); }
      return { address, size: bytes.length };
    }, stop: () => {},
  });
  emit(event: Event) { this.events.set(event.id, event); for (const item of [...this.subscribers]) if (matchFilters([...item.filters], event)) item.handlers.onevent(event, network.readRelays[0]); }
}
export function signer(number = 1, sourceKey?: Uint8Array): NostrSigner {
  const key = sourceKey ? new Uint8Array(sourceKey) : new Uint8Array(32); if (!sourceKey) key[31] = number;
  return { getType: () => 'local', getPublicKey: async () => getPublicKey(key), signEvent: async event => finalizeEvent(event, key), nip44: {
    encrypt: async (peer, text) => nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(key, peer)),
    decrypt: async (peer, text) => nip44.v2.decrypt(text, nip44.v2.utils.getConversationKey(key, peer)),
  } };
}
export const unlockedSecrets = (): SecretStore => {
  const values = new Map<string, string>();
  return { get: async key => values.get(key) ?? null, set: async (key, value) => { values.set(key, value); }, delete: async key => { values.delete(key); } };
};
export async function fixture(net = new ScriptedNetwork(), identity = signer(), factory = new IDBFactory()) {
  const fs = new MemoryFS(), secrets = unlockedSecrets(), pubkey = hex32<Pubkey>(await identity.getPublicKey());
  const workers: LocalWorker[] = [];
  let counter = 1;
  const session: VaultSession = { accountPubkey: pubkey, signer: identity, notebookPath: '/notebook', fs, secrets, networkDefaults: network,
    editorBarrier: { enter: async () => ({ flushedHashes: new Map(), release: () => {} }) } };
  const lockProvider: NonNullable<VaultEngineDeps['lockProvider']> = { request: (async (_name: string, _options: unknown, callback: (lock: Lock) => unknown) => callback({ name: _name, mode: 'exclusive' } as Lock)) as LockManager['request'] };
  const deps: VaultEngineDeps = { relayFactory: net.relayFactory, blossomFactory: net.blossomFactory, clock: () => 1800000000,
    rng: length => { const n = counter++; return Uint8Array.from({ length }, (_, i) => (n + i) % 256); }, lockProvider, workerFactory: () => { const worker = new LocalWorker(); workers.push(worker); return worker; }, idbFactory: () => factory, requestRecoveryPassphrase: async () => 'test package passphrase' };
  const openStore = async () => { const store = new VaultStore({ accountPubkey: pubkey, secrets, idbFactory: factory }); await store.start(); return store; };
  const mkdir = async (path: string) => { const parts = path.split('/').filter(Boolean); let root = ''; for (const part of parts) { root += '/' + part; await fs.createFolder(root); } };
  return { fs, secrets, session, deps, net, workers, openStore, mkdir, pubkey, factory };
}
export function snapshot(engine: { subscribe: (listener: (state: VaultEngineSnapshot) => void) => () => void }): VaultEngineSnapshot { let state!: VaultEngineSnapshot; engine.subscribe(s => { state = s; })(); return state; }
export const address = (text: string): Address => hashAddress(new TextEncoder().encode(text));

export async function editCache(factory: IDBFactory, mode: 'clear' | 'corrupt'): Promise<void> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = factory.open(VAULT_DATABASE_NAME, VAULT_DATABASE_VERSION); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
  const wrapped = wrap(db), tx = wrapped.transaction('objects', 'readwrite');
  // Bytes vanish behind the store's back; its size/LRU index is left stale on purpose.
  if (mode === 'clear') await tx.store.clear();
  else {
    let cursor = await tx.store.openCursor();
    while (cursor) { const row = cursor.value as { bytes: Uint8Array; lastUsed: number }; row.bytes[0] ^= 1; await cursor.update(row); cursor = await cursor.continue(); }
  }
  await tx.done; db.close();
}

/** Faults at the injected native IDB boundary, not by replacing engine/store code. */
export function journalFaultFactory(factory: IDBFactory, index: number, boundary: 'before' | 'after', after: () => void, armed = true) {
  let count = 0, enabled = armed;
  const proxy = new Proxy(factory, { get(target, property) {
    if (property !== 'open') { const value = Reflect.get(target, property); return typeof value === 'function' ? value.bind(target) : value; }
    return (...args: Parameters<IDBFactory['open']>) => {
      const request = target.open(...args);
      request.addEventListener('success', () => {
        const db = request.result, transaction = db.transaction.bind(db);
        db.transaction = ((stores: string | string[], mode?: IDBTransactionMode, options?: IDBTransactionOptions) => {
          const tx = transaction(stores, mode, options);
          const names = typeof stores === 'string' ? [stores] : stores;
          // A journal commit writes operations + vaults (+ the unencrypted meta pin/order rows).
          if (enabled && mode === 'readwrite' && names.includes('operations') && names.includes('vaults') && ++count === index) {
            enabled = false;
            if (boundary === 'before') tx.abort(); else tx.addEventListener('complete', after, { once: true });
          }
          return tx;
        }) as IDBDatabase['transaction'];
      }, { once: true });
      return request;
    };
  } });
  return { factory: proxy, arm: () => { enabled = true; count = 0; }, disable: () => { enabled = false; }, count: () => count };
}
