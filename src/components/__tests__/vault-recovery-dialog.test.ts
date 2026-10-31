import { afterEach, describe, expect, it, vi } from 'vitest';
import { dialog } from '../../platform/web/dialog';
import { dialog as desktopDialog } from '../../platform/tauri/dialog';

const native = vi.hoisted(() => ({ save: vi.fn(), invoke: vi.fn() }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: native.save }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke }));
vi.mock('@tauri-apps/plugin-fs', () => ({ readTextFile: vi.fn(), writeTextFile: vi.fn(), mkdir: vi.fn(), exists: vi.fn() }));

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); native.save.mockReset(); native.invoke.mockReset(); });

function picker(value: unknown) {
  Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value });
}

describe('recovery destination adapters', () => {
  it('writes only through the explicitly picked web handle, awaits close, and releases it', async () => {
    const write = vi.fn().mockResolvedValue(undefined), close = vi.fn().mockResolvedValue(undefined);
    const show = vi.fn().mockResolvedValue({ createWritable: async () => ({ write, close, abort: vi.fn() }) });
    picker(show);
    const path = await dialog.save({ defaultPath: 'recovery.json', excludedDirectory: '/opfs/notebook' });
    expect(show).toHaveBeenCalledWith({ suggestedName: 'recovery.json' });
    await dialog.writeTextFile(path!, 'encrypted package');
    expect(write).toHaveBeenCalledWith('encrypted package');
    expect(close).toHaveBeenCalledOnce();
    await expect(dialog.writeTextFile(path!, 'again')).rejects.toThrow('arbitrary paths');
  });

  it('discards an unused picked handle after cancellation', async () => {
    const createWritable = vi.fn();
    picker(vi.fn().mockResolvedValue({ createWritable }));
    const path = await dialog.save();
    dialog.discardSave?.(path!);
    await expect(dialog.writeTextFile(path!, 'package')).rejects.toThrow('arbitrary paths');
    expect(createWritable).not.toHaveBeenCalled();
  });

  it('does not fabricate a path when the web picker is cancelled or unsupported', async () => {
    picker(vi.fn().mockRejectedValue(new DOMException('Cancelled', 'AbortError')));
    expect(await dialog.save()).toBeNull();
    picker(undefined);
    await expect(dialog.save()).rejects.toThrow('no save picker');
    await expect(dialog.writeTextFile('/unpicked.json', 'secret')).rejects.toThrow('arbitrary paths');
  });

  it('aborts a failed web write and propagates the failure', async () => {
    const abort = vi.fn().mockResolvedValue(undefined), close = vi.fn();
    picker(vi.fn().mockResolvedValue({ createWritable: async () => ({ write: vi.fn().mockRejectedValue(new Error('Disk full')), close, abort }) }));
    const path = await dialog.save();
    await expect(dialog.writeTextFile(path!, 'package')).rejects.toThrow('Disk full');
    expect(abort).toHaveBeenCalledOnce();
    expect(close).not.toHaveBeenCalled();
  });

  it('resolves native destinations against the notebook before returning a writable path', async () => {
    native.save.mockResolvedValue('/alias/recovery.json');
    native.invoke.mockResolvedValue('/outside/recovery.json');
    expect(await desktopDialog.save({ defaultPath: 'recovery.json', excludedDirectory: '/notebook' })).toBe('/outside/recovery.json');
    expect(native.save).toHaveBeenCalledWith({ defaultPath: 'recovery.json' });
    expect(native.invoke).toHaveBeenCalledWith('resolve_recovery_destination', { path: '/alias/recovery.json', notebookPath: '/notebook' });
    native.invoke.mockRejectedValue(new Error('Inside notebook'));
    await expect(desktopDialog.save({ excludedDirectory: '/notebook' })).rejects.toThrow('Inside notebook');
  });

  it('does not resolve or write a cancelled native destination', async () => {
    native.save.mockResolvedValue(null);
    expect(await desktopDialog.save({ excludedDirectory: '/notebook' })).toBeNull();
    expect(native.invoke).not.toHaveBeenCalled();
  });
});
