import { invoke } from '@tauri-apps/api/core';
import { open, save } from '@tauri-apps/plugin-dialog';
import { readTextFile, writeTextFile, mkdir, exists } from '@tauri-apps/plugin-fs';
import type { Dialog } from '../types';

export const dialog: Dialog = {
  async open(options) {
    return (await open(options as Parameters<typeof open>[0])) as
      | string
      | string[]
      | null;
  },
  async save(options = {}) {
    const { excludedDirectory, ...pickerOptions } = options;
    const path = await save(pickerOptions);
    if (!path || !excludedDirectory) return path;
    return invoke<string>('resolve_recovery_destination', { path, notebookPath: excludedDirectory });
  },
  readTextFile(path) {
    return readTextFile(path);
  },
  writeTextFile(path, content) {
    return writeTextFile(path, content);
  },
  async mkdir(path, recursive = true) {
    await mkdir(path, { recursive });
  },
  pathExists(path) {
    return exists(path);
  },
};
