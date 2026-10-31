import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ invoke: vi.fn<(command: string, args?: Record<string, unknown>) => Promise<unknown>>() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

import { managedVault, vault } from '../../../platform/tauri/vault';

describe('Tauri vault adapters', () => {
  beforeEach(() => { mocks.invoke.mockReset(); mocks.invoke.mockResolvedValue(undefined); });

  it('never sends a caller-supplied scope: the notebook is held natively (SV-40)', async () => {
    await vault.listAll('/notebook/v');
    await vault.read('/notebook/a.md', '/notebook');
    await vault.writeBinary('/notebook/a.bin', new Uint8Array([1]), '/notebook');
    await vault.rename('/notebook/a.md', '/notebook/b.md', '/notebook');
    await vault.copy('/notebook/a.md', '/notebook/c.md', '/notebook');
    await vault.remove('/notebook/c.md', '/notebook');
    for (const [, args] of mocks.invoke.mock.calls) expect(args).not.toHaveProperty('vaultPath');
    expect(mocks.invoke.mock.calls.map(([command]) => command))
      .toEqual(['list_files_all', 'read_file', 'write_binary_file', 'rename_file', 'copy_file', 'delete_file']);
  });

  it('routes engine reads, writes, folders and removals to the managed commands and shares the rest (SV-32)', async () => {
    await managedVault.writeBinary('/notebook/v/a', new Uint8Array([1, 2]), '/notebook');
    await managedVault.write('/notebook/v/b', 'hi', '/notebook');
    await managedVault.createFolder('/notebook/v/d', '/notebook');
    await managedVault.remove('/notebook/v/a', '/notebook');
    mocks.invoke.mockResolvedValueOnce(new Uint8Array([104, 105]).buffer);
    expect(await managedVault.read('/notebook/v/b', '/notebook')).toBe('hi');
    mocks.invoke.mockResolvedValueOnce(new Uint8Array([7]).buffer);
    expect(await managedVault.readBinary('/notebook/v/a', '/notebook')).toEqual(new Uint8Array([7]));
    await managedVault.listAll('/notebook/v');
    await managedVault.exists('/notebook/v/a');
    expect(mocks.invoke.mock.calls).toEqual([
      ['managed_write_binary', { path: '/notebook/v/a', data: [1, 2] }],
      ['managed_write_binary', { path: '/notebook/v/b', data: [104, 105] }],
      ['managed_mkdir', { path: '/notebook/v/d' }],
      ['managed_delete', { path: '/notebook/v/a' }],
      ['managed_read_binary', { path: '/notebook/v/b' }],
      ['managed_read_binary', { path: '/notebook/v/a' }],
      ['list_files_all', { path: '/notebook/v' }],
      ['file_exists', { path: '/notebook/v/a' }],
    ]);
    // The legacy surface keeps its link-following commands for the same calls.
    await vault.writeBinary('/notebook/v/a', new Uint8Array([1]), '/notebook');
    await vault.createFolder('/notebook/v/d', '/notebook');
    expect(mocks.invoke.mock.calls.slice(-2).map(([command]) => command)).toEqual(['write_binary_file', 'create_folder']);
    // Link-following mutations the engine never uses are refused, not inherited.
    const before = mocks.invoke.mock.calls.length;
    await expect(managedVault.createFile('/notebook/v/x', '/notebook')).rejects.toThrow('managed vault surface');
    await expect(managedVault.rename('/notebook/v/x', '/notebook/v/y', '/notebook')).rejects.toThrow('managed vault surface');
    await expect(managedVault.copy('/notebook/v/x', '/notebook/v/y', '/notebook')).rejects.toThrow('managed vault surface');
    expect(mocks.invoke.mock.calls).toHaveLength(before);
  });

  it('answers realPath with null when the backend refuses (SV-42)', async () => {
    mocks.invoke.mockRejectedValueOnce(new Error('Access denied'));
    expect(await vault.realPath!('/elsewhere/x')).toBeNull();
    mocks.invoke.mockResolvedValueOnce('/private/notebook/Shared/x');
    expect(await vault.realPath!('/notebook/Alias/x')).toBe('/private/notebook/Shared/x');
    expect(mocks.invoke.mock.calls.map(([command]) => command)).toEqual(['resolve_real_path', 'resolve_real_path']);
  });
});
