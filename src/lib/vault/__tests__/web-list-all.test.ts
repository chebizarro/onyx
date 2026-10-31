import { afterEach, describe, expect, it, vi } from 'vitest';
import { vault } from '../../../platform/web/vault';
import type { FileEntry } from '../../../platform/types';
import conformance from '../../../../tests/fixtures/list-all-conformance.json';

interface TestHandle {
  name: string;
  kind: 'directory' | 'file';
  values?(): AsyncIterableIterator<TestHandle>;
  getDirectoryHandle?(name: string): Promise<TestHandle>;
}

function directory(name: string, children: TestHandle[]): TestHandle {
  return {
    name,
    kind: 'directory',
    async *values() { yield* children; },
    async getDirectoryHandle(childName) {
      const child = children.find(entry => entry.name === childName && entry.kind === 'directory');
      if (!child) throw new Error(`Directory not found: ${childName}`);
      return child;
    },
  };
}

function file(name: string): TestHandle {
  return { name, kind: 'file' };
}

afterEach(() => vi.unstubAllGlobals());

describe('web VaultFS.listAll', () => {
  it('matches the same relative tree fixture as native list_files_all', async () => {
    const handles = new Map<string, TestHandle[]>(); handles.set('', []);
    for (const entry of conformance) {
      const slash = entry.path.lastIndexOf('/');
      const parent = slash < 0 ? '' : entry.path.slice(0, slash), name = entry.path.slice(slash + 1);
      if (entry.isDirectory) { const children: TestHandle[] = []; handles.set(entry.path, children); handles.get(parent)!.push(directory(name, children)); }
      else handles.get(parent)!.push(file(name));
    }
    vi.stubGlobal('navigator', { storage: { getDirectory: async () => directory('', [directory('notebook', handles.get('')!)]) } });
    const actual: { path: string; isDirectory: boolean }[] = [];
    const flatten = (entries: FileEntry[]) => { for (const entry of entries) {
      actual.push({ path: entry.path.slice('notebook/'.length), isDirectory: entry.isDirectory });
      if (entry.isDirectory) flatten(entry.children ?? []);
    } };
    flatten(await vault.listAll('notebook'));
    expect(actual.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).toEqual(conformance);
  });

  it('returns dotfiles, non-markdown binary files, nested and empty directories', async () => {
    const notebook = directory('notebook', [
      file('notes.txt'), file('.env'), file('note.md'), file('archive.bin'),
      directory('.config', [file('settings.json')]), directory('empty', []),
      directory('nested', [file('.hidden'), file('audio.mp3')]),
    ]);
    vi.stubGlobal('navigator', {
      storage: { getDirectory: async () => directory('', [notebook]) },
    });

    const entries = await vault.listAll('notebook');
    expect(entries).toEqual([
      { name: '.config', path: 'notebook/.config', isDirectory: true, children: [
        { name: 'settings.json', path: 'notebook/.config/settings.json', isDirectory: false },
      ] },
      { name: 'empty', path: 'notebook/empty', isDirectory: true, children: [] },
      { name: 'nested', path: 'notebook/nested', isDirectory: true, children: [
        { name: '.hidden', path: 'notebook/nested/.hidden', isDirectory: false },
        { name: 'audio.mp3', path: 'notebook/nested/audio.mp3', isDirectory: false },
      ] },
      { name: '.env', path: 'notebook/.env', isDirectory: false },
      { name: 'archive.bin', path: 'notebook/archive.bin', isDirectory: false },
      { name: 'note.md', path: 'notebook/note.md', isDirectory: false },
      { name: 'notes.txt', path: 'notebook/notes.txt', isDirectory: false },
    ]);
    expect(await vault.list('notebook')).toEqual(entries);
    expect(await vault.listAll('notebook/nested')).toEqual(entries[2].children);
  });
});
