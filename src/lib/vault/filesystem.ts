import type { FileEntry, FileStats, VaultFS } from '../../platform/types';
import { hashAddress } from './crypto';
import { VaultError } from './errors';
import type { Address, StoredBaselineEntry, StoredDiskStat, VaultMount } from './types';

export const MAX_CAPTURE_BYTES = 128 * 1024 * 1024;
export const CAPTURE_COALESCE_MS = 750;
export const RESERVED_PATHS = ['.onyx-vault-staging', '.onyx-vault-conflicts'] as const;
/** Prefix of the temporary a native atomic install writes beside its target
 * (`MANAGED_TEMP_PREFIX` in `src-tauri/src/lib.rs`). A crash can orphan one;
 * capture skips it and no remote entry may carry the name. */
export const MANAGED_TEMP_PREFIX = '.onyx-vault-tmp-';
const reservedName = (name: string): boolean => RESERVED_PATHS.some(reserved => reserved === name) || name.startsWith(MANAGED_TEMP_PREFIX);
export function checkAbort(signal?: AbortSignal): void {
  if (signal?.aborted) throw new VaultError('CANCELLED');
}
export function validateRelativePath(path: string): string {
  if (!path || path.includes('\\') || path.startsWith('/') || path.includes('\0') || path.split('/').some(p =>
    !p || p === '.' || p === '..' || /[\x00-\x1f<>:"|?*]/.test(p) || /[. ]$/.test(p) ||
    /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p) || new TextEncoder().encode(p).length > 255))
    throw new VaultError('ARG', { operation: 'validate' });
  return path;
}
export function isReservedPath(path: string): boolean {
  return path.split('/').some(reservedName);
}
export function absolutePath(notebook: string, relative: string): string {
  return `${notebook.replace(/[\\/]+$/, '')}/${relative}`;
}
export function relativeMountPath(notebook: string, folder: string): string {
  const root = notebook.replace(/\\/g, '/').replace(/\/+$/, '');
  const path = folder.replace(/\\/g, '/').replace(/\/+$/, '');
  return validateRelativePath(path.startsWith(root + '/') ? path.slice(root.length + 1) : path);
}
export function validateMount(notebook: string, folder: string, mounts: readonly VaultMount[], except?: string): string {
  const path = relativeMountPath(notebook, folder);
  if (isReservedPath(path)) throw new VaultError('ARG');
  const key = path.normalize('NFC').toLowerCase();
  for (const mount of mounts) {
    if (mount.vaultId === except || mount.notebookPath !== notebook) continue;
    const other = mount.relativePath.normalize('NFC').toLowerCase();
    if (key === other || key.startsWith(other + '/') || other.startsWith(key + '/')) throw new VaultError('CONFLICT');
  }
  return path;
}
export interface DiskEntry { readonly path: string; readonly kind: 'file' | 'directory'; }
const compareNames = (a: FileEntry, b: FileEntry) => {
  const x = new TextEncoder().encode(a.name), y = new TextEncoder().encode(b.name);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
};
/** listAll is authoritative, but an omitted extant baseline path is never a deletion. */
export async function traverseMount(fs: VaultFS, root: string, baseline: Readonly<Record<string, StoredBaselineEntry>> = {}, signal?: AbortSignal): Promise<readonly DiskEntry[]> {
  checkAbort(signal);
  if (!await fs.exists(root)) throw new VaultError('IO', { operation: 'capture' });
  const listed = await fs.listAll(root);
  checkAbort(signal);
  const result: DiskEntry[] = [], seen = new Set<string>();
  function walk(entries: readonly FileEntry[], prefix: string) {
    for (const entry of [...entries].sort(compareNames)) {
      if (entry.isSymlink) throw new VaultError('IO', { operation: 'capture' });
      if (reservedName(entry.name)) continue;
      const path = validateRelativePath(prefix ? `${prefix}/${entry.name}` : entry.name);
      const expected = absolutePath(root, path).replace(/\\/g, '/');
      if (entry.path.replace(/\\/g, '/') !== expected) throw new VaultError('ARG');
      const key = path.normalize('NFC').toLowerCase();
      if (seen.has(key)) throw new VaultError('CONFLICT');
      seen.add(key);
      result.push({ path, kind: entry.isDirectory ? 'directory' : 'file' });
      if (entry.isDirectory) walk(entry.children ?? [], path);
    }
  }
  walk(listed, '');
  const observed = new Set(result.map(e => e.path));
  for (const path of Object.keys(baseline)) {
    validateRelativePath(path);
    if (!isReservedPath(path) && !observed.has(path) && await fs.exists(absolutePath(root, path))) throw new VaultError('IO', { operation: 'capture' });
    checkAbort(signal);
  }
  return result;
}
export async function validateArtifactRoots(fs: VaultFS, root: string): Promise<void> {
  const entries = await fs.listAll(root);
  if (entries.some(e => RESERVED_PATHS.some(name => name === e.name))) throw new VaultError('CONFLICT');
}
/** A hash observed for a stat; trusted only while the stat is strictly older than the observation. */
export interface DiskObservation { readonly stat: StoredDiskStat; readonly hash: Address }
export const nowSeconds = (): number => Math.floor(Date.now() / 1000);
/** `observedAt` must be the second at which the stat/read interval STARTED, never its end:
 * an edit after that second always moves the mtime to >= observedAt, which is untrusted. */
export function diskStat(stats: FileStats, observedAt: number): StoredDiskStat {
  return { size: stats.size, modified: String(stats.modified), observedAt };
}
/** Equal size and mtime, and the mtime second ended before the hash was taken (racy-mtime rule). */
export function matchesObservation(stats: FileStats, known: DiskObservation | undefined): known is DiskObservation {
  return !!known && known.stat.size === stats.size && known.stat.modified === String(stats.modified)
    && Number(known.stat.modified) < known.stat.observedAt;
}
export interface StableFile { bytes?: Uint8Array<ArrayBuffer>; hash: Address; mtimeNs: bigint; stat: StoredDiskStat }
/** Stat first; bytes are read once (stat-bracketed) only when no `known` observation matches the stat. */
export async function readStableFile(fs: VaultFS, notebook: string, path: string, signal?: AbortSignal, digest: (bytes: Uint8Array) => Promise<Address> = async bytes => hashAddress(bytes), known: readonly (DiskObservation | undefined)[] = []): Promise<StableFile> {
  checkAbort(signal);
  const observedAt = nowSeconds();
  const before = await fs.stats(path);
  if (before.size > MAX_CAPTURE_BYTES) throw new VaultError('TOO_LARGE', { operation: 'capture' });
  const mtimeNs = (stats: FileStats) => BigInt(Math.max(0, Math.floor(stats.modified))) * 1000000000n;
  const match = known.find(observation => matchesObservation(before, observation));
  if (match) return { hash: match.hash, mtimeNs: mtimeNs(before), stat: match.stat };
  const bytes = new Uint8Array(await fs.readBinary(path, notebook));
  checkAbort(signal);
  if (bytes.length > MAX_CAPTURE_BYTES) throw new VaultError('TOO_LARGE', { operation: 'capture' });
  const after = await fs.stats(path);
  if (before.size !== after.size || before.modified !== after.modified || bytes.length !== after.size) throw new VaultError('CONFLICT', { operation: 'capture', retryable: true });
  const stat = diskStat(after, observedAt);
  const hash = await digest(bytes); checkAbort(signal);
  return { bytes, hash, mtimeNs: mtimeNs(after), stat };
}
export type ReconcileAction = 'apply' | 'preserve' | 'converge' | 'conflict' | 'delete';
export function compareBaseline(baseline: Address | null, local: Address | null, remote: Address | null): ReconcileAction {
  if (local === remote) return 'converge';
  if (local === baseline) return remote === null ? 'delete' : 'apply';
  if (remote === baseline) return 'preserve';
  return 'conflict';
}
/** Echoes are acknowledged by content, never by a time-based ignore window. */
export class ExpectedHashes {
  private readonly hashes = new Map<string, Address | null>();
  expect(path: string, hash: Address | null): void { this.hashes.set(path, hash); }
  acknowledge(path: string, hash: Address | null): boolean {
    if (!this.hashes.has(path) || this.hashes.get(path) !== hash) return false;
    this.hashes.delete(path); return true;
  }
  clear(): void { this.hashes.clear(); }
}
/** Scheduling is injectable so tests advance time without sleeps. */
export class CaptureCoalescer {
  private timer?: ReturnType<typeof setTimeout>;
  private running = false;
  private dirty = false;
  private stopped = false;
  constructor(private readonly scan: () => Promise<void>, private readonly schedule = setTimeout, private readonly cancel = clearTimeout) {}
  notify(): void {
    if (this.stopped) return;
    this.dirty = true;
    if (this.running) return;
    // Call unbound: WebKit throws if setTimeout/clearTimeout receive a non-Window `this`.
    const { schedule, cancel } = this;
    if (this.timer !== undefined) cancel(this.timer);
    this.timer = schedule(() => { this.timer = undefined; void this.run(); }, CAPTURE_COALESCE_MS);
  }
  private async run(): Promise<void> {
    this.running = true;
    try { do { this.dirty = false; await this.scan(); } while (this.dirty && !this.stopped); }
    finally { this.running = false; }
  }
  stop(): void { this.stopped = true; const { cancel } = this; if (this.timer !== undefined) cancel(this.timer); }
}
