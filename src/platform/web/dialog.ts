import type { Dialog, DialogOpenOptions } from '../types';

// Picked files (and directories) on the web don't have a stable absolute path,
// so we synthesize a "virtual path" and stash the actual File handle in a map
// keyed by that path. readTextFile/writeTextFile/etc. look the handle up later.

interface PickedEntry {
  file?: File;
  dirHandle?: FileSystemDirectoryHandle;
  saveHandle?: { createWritable(): Promise<{ write(content: string): Promise<void>; close(): Promise<void>; abort(): Promise<void> }> };
}

const pickedRegistry = new Map<string, PickedEntry>();

function virtualPath(name: string): string {
  return `webpick://${crypto.randomUUID()}/${name}`;
}

function buildAcceptString(filters?: DialogOpenOptions['filters']): string {
  if (!filters) return '';
  return filters
    .flatMap((f) => f.extensions.map((ext) => `.${ext.replace(/^\./, '')}`))
    .join(',');
}

async function pickFiles(options: DialogOpenOptions): Promise<string | string[] | null> {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = options.multiple ?? false;
    input.accept = buildAcceptString(options.filters);
    input.style.display = 'none';
    input.onchange = () => {
      const files = Array.from(input.files ?? []);
      document.body.removeChild(input);
      if (files.length === 0) {
        resolve(null);
        return;
      }
      const paths = files.map((file) => {
        const p = virtualPath(file.name);
        pickedRegistry.set(p, { file });
        return p;
      });
      resolve(options.multiple ? paths : paths[0]);
    };
    input.oncancel = () => {
      document.body.removeChild(input);
      resolve(null);
    };
    document.body.appendChild(input);
    input.click();
  });
}

async function pickDirectory(): Promise<string | null> {
  const w = window as unknown as {
    showDirectoryPicker?: () => Promise<FileSystemDirectoryHandle>;
  };
  if (!w.showDirectoryPicker) {
    console.warn('[dialog] showDirectoryPicker not supported in this browser');
    return null;
  }
  try {
    const handle = await w.showDirectoryPicker();
    const p = virtualPath(handle.name);
    pickedRegistry.set(p, { dirHandle: handle });
    return p;
  } catch {
    return null;
  }
}

export const dialog: Dialog = {
  async open(options = {}) {
    if (options.directory) return pickDirectory();
    return pickFiles(options);
  },
  discardSave(path) {
    if (pickedRegistry.get(path)?.saveHandle) pickedRegistry.delete(path);
  },
  async save(options = {}) {
    const picker = (window as unknown as {
      showSaveFilePicker?: (options: { suggestedName?: string }) => Promise<NonNullable<PickedEntry['saveHandle']>>;
    }).showSaveFilePicker;
    if (!picker) throw new Error('This browser has no save picker. Export recovery from a supported browser or desktop app.');
    try {
      const handle = await picker.call(window, { suggestedName: options.defaultPath });
      const path = virtualPath(options.defaultPath ?? 'recovery.json');
      pickedRegistry.set(path, { saveHandle: handle });
      return path;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') return null;
      throw error;
    }
  },
  async readTextFile(path) {
    const entry = pickedRegistry.get(path);
    if (!entry?.file) {
      throw new Error(`Cannot read external file on web (path: ${path})`);
    }
    return entry.file.text();
  },
  async writeTextFile(path, content) {
    const handle = pickedRegistry.get(path)?.saveHandle;
    if (!handle) throw new Error('Writing to arbitrary paths is not supported on web');
    try {
      const writable = await handle.createWritable();
      try { await writable.write(content); await writable.close(); }
      catch (error) { await writable.abort().catch(() => {}); throw error; }
    } finally { pickedRegistry.delete(path); }
  },
  async mkdir(_path) {
    throw new Error('mkdir on arbitrary paths is not supported on web');
  },
  async pathExists(path) {
    return pickedRegistry.has(path);
  },
};
