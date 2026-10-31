/**
 * Raw persisted-state codec for backward-compatibility fixtures (SEC-G).
 *
 * Dumps every IndexedDB object store byte-for-byte (encrypted rows, meta and
 * object-index rows, schema incl. indexes) plus secret-store entries, the
 * in-memory notebook filesystem and the scripted relay/Blossom contents, as JSON.
 * Binary values are tagged, never re-encoded through application types, so a
 * fixture captures exactly what an old build left on disk.
 *
 * This file is self-contained on purpose: it is copied verbatim into an old
 * checkout to generate fixtures there.
 */
import type { Event } from 'nostr-tools';

type Tagged = { $t: 'ArrayBuffer' | 'Uint8Array'; hex: string } | { $t: 'bigint'; v: string };
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const unhex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], b => parseInt(b, 16));

export function encodeValue(value: unknown): unknown {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (value === undefined) return { $t: 'undefined' };
  if (typeof value === 'bigint') return { $t: 'bigint', v: value.toString() } satisfies Tagged;
  if (value instanceof ArrayBuffer) return { $t: 'ArrayBuffer', hex: hex(new Uint8Array(value)) } satisfies Tagged;
  if (value instanceof Uint8Array) return { $t: 'Uint8Array', hex: hex(value) } satisfies Tagged;
  if (Array.isArray(value)) return value.map(encodeValue);
  if (Object.getPrototypeOf(value) === Object.prototype) return Object.fromEntries(Object.entries(value as object).map(([k, v]) => [k, encodeValue(v)]));
  throw new Error(`compat-codec: unsupported persisted value ${Object.prototype.toString.call(value)}`);
}
export function decodeValue(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(decodeValue);
  const tagged = value as { $t?: string; hex?: string; v?: string };
  if (tagged.$t === 'undefined') return undefined;
  if (tagged.$t === 'bigint') return BigInt(tagged.v!);
  if (tagged.$t === 'ArrayBuffer') return unhex(tagged.hex!).buffer;
  if (tagged.$t === 'Uint8Array') return unhex(tagged.hex!);
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, decodeValue(v)]));
}

export interface DumpedIndex { name: string; keyPath: string | string[]; unique: boolean; multiEntry: boolean }
export interface DumpedStore { name: string; keyPath: string | string[] | null; autoIncrement: boolean; indexes: DumpedIndex[]; rows: { key: unknown; value: unknown }[] }
export interface DumpedDatabase { name: string; version: number; stores: DumpedStore[] }
export interface DumpedDevice {
  name: string; pubkey: string; databaseName: string; notebookPath: string;
  idb: DumpedDatabase;
  secrets: Record<string, string>;
  fs: { directories: string[]; files: Record<string, string> };
}
export interface DumpedNetwork { now: number; events: Event[]; objects: Record<string, string> }

const request = <T>(r: IDBRequest<T>) => new Promise<T>((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });

export async function dumpDatabase(factory: IDBFactory, name: string): Promise<DumpedDatabase> {
  const open = factory.open(name);
  const db = await request(open);
  try {
    const names = [...db.objectStoreNames].sort();
    const tx = db.transaction(names, 'readonly');
    const stores: DumpedStore[] = [];
    for (const storeName of names) {
      const store = tx.objectStore(storeName);
      const keys = await request(store.getAllKeys()), values = await request(store.getAll());
      stores.push({ name: storeName, keyPath: store.keyPath as string | string[] | null, autoIncrement: store.autoIncrement,
        indexes: [...store.indexNames].sort().map(index => { const i = store.index(index); return { name: i.name, keyPath: i.keyPath as string | string[], unique: i.unique, multiEntry: i.multiEntry }; }),
        rows: keys.map((key, index) => ({ key: encodeValue(key), value: encodeValue(values[index]) })) });
    }
    return { name, version: db.version, stores };
  } finally { db.close(); }
}

/** Recreates a dumped database at its original version, so the current build runs its own upgrade path. */
export async function loadDatabase(factory: IDBFactory, dump: DumpedDatabase, name = dump.name): Promise<void> {
  const open = factory.open(name, dump.version);
  open.onupgradeneeded = () => {
    for (const store of dump.stores) {
      const created = open.result.createObjectStore(store.name, { keyPath: store.keyPath, autoIncrement: store.autoIncrement });
      for (const index of store.indexes) created.createIndex(index.name, index.keyPath, { unique: index.unique, multiEntry: index.multiEntry });
    }
  };
  const db = await request(open);
  try {
    const tx = db.transaction(dump.stores.map(s => s.name), 'readwrite');
    for (const store of dump.stores) for (const row of store.rows) {
      const target = tx.objectStore(store.name);
      if (store.keyPath === null) target.put(decodeValue(row.value), decodeValue(row.key) as IDBValidKey);
      else target.put(decodeValue(row.value));
    }
    await new Promise<void>((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error); });
  } finally { db.close(); }
}

export function dumpFs(fs: { directories: Set<string>; files: Map<string, Uint8Array> }): DumpedDevice['fs'] {
  return { directories: [...fs.directories].sort(), files: Object.fromEntries([...fs.files].sort(([a], [b]) => a.localeCompare(b)).map(([path, bytes]) => [path, hex(bytes)])) };
}
export function loadFs(fs: { directories: Set<string>; files: Map<string, Uint8Array> }, dump: DumpedDevice['fs']): void {
  for (const dir of dump.directories) fs.directories.add(dir);
  for (const [path, bytes] of Object.entries(dump.files)) fs.files.set(path, unhex(bytes));
}
export function dumpNetwork(net: { now: number; events: Map<string, Event>; objects: Map<string, Uint8Array> }): DumpedNetwork {
  return { now: net.now, events: [...net.events.values()].map(e => structuredClone(e)), objects: Object.fromEntries([...net.objects].map(([address, bytes]) => [address, hex(bytes)])) };
}
export function loadNetwork(net: { now: number; events: Map<string, Event>; objects: Map<string, Uint8Array> }, dump: DumpedNetwork): void {
  net.now = dump.now;
  for (const event of dump.events) net.events.set(event.id, structuredClone(event));
  for (const [address, bytes] of Object.entries(dump.objects)) net.objects.set(address, unhex(bytes));
}
