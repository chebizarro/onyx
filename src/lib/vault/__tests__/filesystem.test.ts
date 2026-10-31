import { describe, expect, it, vi } from 'vitest';
import { absolutePath, CaptureCoalescer, compareBaseline, ExpectedHashes, isReservedPath, MANAGED_TEMP_PREFIX, MAX_CAPTURE_BYTES, readStableFile, traverseMount, validateArtifactRoots, validateMount, validateRelativePath } from '../filesystem';
import { address, fixture } from './engine-fixtures';
import type { StoredBaselineEntry, VaultId } from '../types';

describe('vault filesystem boundary', () => {
  it.each(['../escape', '/absolute', 'a/../b', 'a//b', 'a\\b', 'NUL.txt', 'trail.', 'trailing ', 'a\0b'])('rejects unrepresentable path %j', path => expect(() => validateRelativePath(path)).toThrow());
  it('traverses dotfiles, all extensions and empty directories deterministically via listAll', async () => {
    const f = await fixture(); await f.mkdir('/notebook/v/empty'); await f.fs.write('/notebook/v/z.exe', 'z'); await f.fs.write('/notebook/v/.config', 'c'); await f.mkdir('/notebook/v/.onyx-vault-staging/op');
    expect((await traverseMount(f.fs, '/notebook/v')).map(e => e.path)).toEqual(['.config', 'empty', 'z.exe']);
    await expect(validateArtifactRoots(f.fs, '/notebook/v')).rejects.toMatchObject({ code: 'CONFLICT' });
  });
  it.each([false, true])('refuses a backend-reported symlink before capture (directory=%s)', async isDirectory => {
    const f = await fixture(); await f.mkdir('/notebook/v');
    vi.spyOn(f.fs, 'listAll').mockResolvedValue([{ name: 'link', path: '/notebook/v/link', isDirectory, isSymlink: true, children: [] }]);
    const read = vi.spyOn(f.fs, 'readBinary');
    await expect(traverseMount(f.fs, '/notebook/v')).rejects.toMatchObject({ code: 'IO' });
    expect(read).not.toHaveBeenCalled();
  });
  it('skips a native install temporary a crash left behind and reserves its name (SV-39)', async () => {
    const f = await fixture(); await f.mkdir('/notebook/v/d'); await f.fs.write('/notebook/v/a.md', 'a'); await f.fs.write(`/notebook/v/${MANAGED_TEMP_PREFIX}4242-7`, 'partial'); await f.fs.write(`/notebook/v/d/${MANAGED_TEMP_PREFIX}1-0`, 'partial');
    expect((await traverseMount(f.fs, '/notebook/v')).map(e => e.path)).toEqual(['a.md', 'd']);
    expect(isReservedPath(`dir/${MANAGED_TEMP_PREFIX}1-2`)).toBe(true);
    expect(isReservedPath('dir/.onyx-vault-tmp')).toBe(false);
    expect(isReservedPath('dir/.onyx-vault-user')).toBe(false);
  });
  it('rejects overlapping mounts and root escapes, not sibling prefixes', () => {
    const mounts = [{ vaultId: 'a'.repeat(64) as VaultId, notebookPath: '/notebook', relativePath: 'a' }];
    expect(() => validateMount('/notebook', 'a/child', mounts)).toThrow(); expect(() => validateMount('/notebook', '/outside/a', mounts)).toThrow();
    expect(validateMount('/notebook', 'ab', mounts)).toBe('ab'); expect(absolutePath('/notebook/', 'ab')).toBe('/notebook/ab');
  });
  it('refuses to infer deletion for an extant baseline file missing from listing', async () => {
    const f = await fixture(); await f.mkdir('/notebook/v'); await f.fs.write('/notebook/v/hidden.dat', 'content'); f.fs.omit.add('/notebook/v/hidden.dat');
    await expect(traverseMount(f.fs, '/notebook/v', { 'hidden.dat': {} as StoredBaselineEntry })).rejects.toMatchObject({ code: 'IO' });
  });
  it('enforces 128 MiB before reading and rejects changes during a read', async () => {
    const f = await fixture(); await f.fs.write('/notebook/file', 'bytes');
    const stats = vi.spyOn(f.fs, 'stats'); stats.mockResolvedValueOnce({ size: MAX_CAPTURE_BYTES + 1, created: 0, modified: 0 });
    await expect(readStableFile(f.fs, '/notebook', '/notebook/file')).rejects.toMatchObject({ code: 'TOO_LARGE' });
    stats.mockResolvedValueOnce({ size: 5, created: 0, modified: 1 }).mockResolvedValueOnce({ size: 5, created: 0, modified: 2 });
    await expect(readStableFile(f.fs, '/notebook', '/notebook/file')).rejects.toMatchObject({ code: 'CONFLICT' });
  });
  it('skips reading for a trusted matching observation but re-hashes a same-second (racy) one', async () => {
    const f = await fixture(); await f.fs.write('/notebook/file', 'bytes'); f.fs.modified.set('/notebook/file', 10);
    const reads = vi.spyOn(f.fs, 'readBinary'), hash = address('bytes');
    const trusted = { stat: { size: 5, modified: '10', observedAt: 11 }, hash };
    const skipped = await readStableFile(f.fs, '/notebook', '/notebook/file', undefined, undefined, [trusted]);
    expect(skipped).toMatchObject({ hash, stat: trusted.stat }); expect(skipped.bytes).toBeUndefined();
    expect(reads).not.toHaveBeenCalled();
    const racy = { stat: { size: 5, modified: '10', observedAt: 10 }, hash };
    const read = await readStableFile(f.fs, '/notebook', '/notebook/file', undefined, undefined, [racy]);
    expect(read.bytes).toHaveLength(5); expect(read.stat).toMatchObject({ size: 5, modified: '10' }); expect(reads).toHaveBeenCalledTimes(1);
    const stale = { stat: { size: 4, modified: '10', observedAt: 11 }, hash };
    expect((await readStableFile(f.fs, '/notebook', '/notebook/file', undefined, undefined, [undefined, stale, trusted])).bytes).toBeUndefined();
    expect(reads).toHaveBeenCalledTimes(1);
  });
  it.each([
    ['old', 'old', 'new', 'apply'], ['old', 'new', 'old', 'preserve'], ['old', 'new', 'new', 'converge'],
    ['old', 'local', 'remote', 'conflict'], ['old', 'old', null, 'delete'], [null, 'local', 'remote', 'conflict'],
  ] as const)('compares baseline/local/remote %s %s %s', (b, l, r, action) => expect(compareBaseline(b && address(b), l && address(l), r && address(r))).toBe(action));
  it('acknowledges echoes by expected content, not elapsed time', () => {
    const echoes = new ExpectedHashes(); echoes.expect('a', address('remote')); expect(echoes.acknowledge('a', address('local'))).toBe(false); expect(echoes.acknowledge('a', address('remote'))).toBe(true); expect(echoes.acknowledge('a', address('remote'))).toBe(false);
  });
  it('coalesces bursts for 750 ms and follows changes during capture without sleeping', async () => {
    vi.useFakeTimers(); let calls = 0, release!: () => void; const hold = new Promise<void>(resolve => { release = resolve; });
    const coalescer = new CaptureCoalescer(async () => { calls++; if (calls === 1) await hold; });
    try {
      coalescer.notify(); await vi.advanceTimersByTimeAsync(500); coalescer.notify(); await vi.advanceTimersByTimeAsync(749); expect(calls).toBe(0);
      await vi.advanceTimersByTimeAsync(1); expect(calls).toBe(1); coalescer.notify(); release(); await vi.advanceTimersByTimeAsync(0); expect(calls).toBe(2);
    } finally { coalescer.stop(); vi.useRealTimers(); }
  });
  it('calls the timer functions unbound (WebKit rejects setTimeout with a non-Window receiver)', () => {
    // Live E2E 2026-10-29: `this.schedule(...)` threw "Can only call Window.setTimeout on instances of Window"
    // in the Tauri WebView on every watcher notification, so local edits were never auto-captured.
    const timers: (() => void)[] = []; let cancelled = 0;
    function schedule(this: unknown, fn: () => void): number {
      if (this !== undefined && this !== globalThis) throw new TypeError('Can only call Window.setTimeout on instances of Window');
      return timers.push(fn);
    }
    function cancel(this: unknown): void {
      if (this !== undefined && this !== globalThis) throw new TypeError('Can only call Window.clearTimeout on instances of Window');
      cancelled++;
    }
    let calls = 0;
    const coalescer = new CaptureCoalescer(async () => { calls++; }, schedule as unknown as typeof setTimeout, cancel as unknown as typeof clearTimeout);
    expect(() => { coalescer.notify(); coalescer.notify(); }).not.toThrow();
    expect(timers).toHaveLength(2); expect(cancelled).toBe(1);
    timers[1](); expect(calls).toBe(1);
    expect(() => coalescer.stop()).not.toThrow();
  });
});
