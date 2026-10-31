import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { AssetEntry, FileEntry, FileStats, VaultFS } from '../types';

// The notebook these commands are confined to is held natively (loaded from
// settings, kept current by `set_vault_scope`); it is deliberately not an
// argument here, so the `vaultPath` parameter of the VaultFS contract is only
// meaningful to backends that need it to locate storage (OPFS). SV-40.
export const vault: VaultFS = {
  list(vaultPath) {
    return invoke<FileEntry[]>('list_files', { path: vaultPath });
  },
  listAll(root) {
    return invoke<FileEntry[]>('list_files_all', { path: root });
  },
  listAssets(vaultPath) {
    return invoke<AssetEntry[]>('list_assets', { path: vaultPath });
  },
  read(path) {
    return invoke<string>('read_file', { path });
  },
  async readBinary(path) {
    // The backend returns a raw tauri::ipc::Response, so this arrives as an
    // ArrayBuffer instead of a JSON-serialized number array.
    const data = await invoke<ArrayBuffer>('read_binary_file', { path });
    return new Uint8Array(data);
  },
  write(path, content) {
    return invoke<void>('write_file', { path, content });
  },
  writeBinary(path, data) {
    return invoke<void>('write_binary_file', { path, data: Array.from(data) });
  },
  createFile(path) {
    return invoke<void>('create_file', { path });
  },
  createFolder(path) {
    return invoke<void>('create_folder', { path });
  },
  rename(oldPath, newPath) {
    return invoke<void>('rename_file', { oldPath, newPath });
  },
  remove(path) {
    return invoke<void>('delete_file', { path });
  },
  copy(source, dest) {
    return invoke<void>('copy_file', { source, dest });
  },
  exists(path) {
    return invoke<boolean>('file_exists', { path });
  },
  modifiedTime(path) {
    return invoke<number>('get_file_modified_time', { path });
  },
  stats(path) {
    return invoke<FileStats>('get_file_stats', { path });
  },
  async realPath(path) {
    try {
      return await invoke<string>('resolve_real_path', { path });
    } catch {
      return null;
    }
  },
  setVaultScope(vaultPath) {
    return invoke<void>('set_vault_scope', { vaultPath });
  },
  startWatching(vaultPath) {
    return invoke<void>('start_watching', { path: vaultPath });
  },
  stopWatching() {
    return invoke<void>('stop_watching');
  },
  async onFilesChanged(cb) {
    const off = await listen<string[] | null>('files-changed', event => cb(event.payload ?? undefined));
    return () => off();
  },
  async onFileModified(cb) {
    const off = await listen<string[]>('file-modified', (event) => cb(event.payload));
    return () => off();
  },
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const unavailable = (operation: string) => () =>
  Promise.reject(new Error(`${operation} is not available on the managed vault surface; it would follow links`));

/** Engine-facing surface (see `PlatformAdapter.managedVault`): the `managed_*`
 * commands walk every component below the notebook root with `O_NOFOLLOW`
 * relative to the previous directory handle and install files by temp+rename.
 * Listing and metadata are shared with `vault`; the link-following mutations the
 * engine never uses are refused rather than inherited. */
export const managedVault: VaultFS = {
  ...vault,
  createFile: unavailable('createFile'),
  rename: unavailable('rename'),
  copy: unavailable('copy'),
  async read(path) {
    return decoder.decode(await managedVault.readBinary(path, ''));
  },
  async readBinary(path) {
    const data = await invoke<ArrayBuffer>('managed_read_binary', { path });
    return new Uint8Array(data);
  },
  write(path, content) {
    return invoke<void>('managed_write_binary', { path, data: Array.from(encoder.encode(content)) });
  },
  writeBinary(path, data) {
    return invoke<void>('managed_write_binary', { path, data: Array.from(data) });
  },
  createFolder(path) {
    return invoke<void>('managed_mkdir', { path });
  },
  remove(path) {
    return invoke<void>('managed_delete', { path });
  },
};
