import { cleanup, fireEvent, render, screen, waitFor } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FileEntry } from '@platform';
const platformMock = vi.hoisted(() => ({
  vault: {
    list: vi.fn(async (_path: string): Promise<FileEntry[]> => []),
    rename: vi.fn(async () => undefined),
    remove: vi.fn(async () => undefined),
    createFile: vi.fn(async () => undefined),
    createFolder: vi.fn(async () => undefined),
    copy: vi.fn(async () => undefined),
    read: vi.fn(async () => ''),
  },
  dialog: { open: vi.fn(async () => null) },
  clipboard: { writeText: vi.fn(async (_text: string) => undefined) },
  shell: { openInDefaultApp: vi.fn(), showInFolder: vi.fn() },
  search: { searchVault: vi.fn(async () => []) },
  refreshInfo: vi.fn(async () => ({ platform: 'web', default_vault_path: '', is_web: true })),
}));
vi.mock('@platform', () => ({ platform: platformMock }));

import Sidebar from '../Sidebar';

beforeEach(() => {
  Object.values(platformMock.vault).forEach((fn) => fn.mockClear());
});
afterEach(() => cleanup());

describe('Sidebar gestures and input focus', () => {
  const tree: FileEntry[] = [
    { name: 'Projects', path: '/nb/Projects', isDirectory: true, children: [
      { name: 'plan.md', path: '/nb/Projects/plan.md', isDirectory: false },
    ] },
    { name: 'Inbox', path: '/nb/Inbox', isDirectory: true, children: [] },
  ];
  function renderSidebar(extra: Record<string, unknown> = {}, listing = tree) {
    platformMock.vault.list.mockResolvedValue(listing);
    render(() => (
      <Sidebar
        onFileSelect={() => undefined}
        currentFile={null}
        vaultPath="/nb"
        onVaultOpen={() => undefined}
        onFileCreated={() => undefined}
        onFileDeleted={() => undefined}
        view="files"
        bookmarks={[]}
        onToggleBookmark={() => undefined}
        savedSearches={[]}
        onToggleSavedSearch={() => undefined}
        expandedFolders={new Set(['/nb/Projects'])}
        {...extra}
      />
    ));
  }

  const item = (name: string) => screen.getByText(name).closest('.file-tree-item') as HTMLElement;

  describe('context menu gestures (WebKit event order)', () => {
    // WebKit on macOS fires `contextmenu` during mousedown; the press is still held
    // while the menu opens, and its mouseup (and, for Control+click, a `click`) follow.
    const press = (el: Element, init: MouseEventInit) => {
      fireEvent.pointerDown(el, init);
      fireEvent.mouseDown(el, init);
    };
    /** Control+click, exactly as observed live: down, contextmenu, mouseup, click on the row. */
    const controlClick = (row: Element) => {
      const init = { button: 0, ctrlKey: true, clientX: 20, clientY: 20 };
      press(row, init);
      fireEvent.contextMenu(row, init);
      expect(document.querySelector('.context-menu')).not.toBeNull();
      fireEvent.mouseUp(row, init);
      fireEvent.click(row, init);
    };
    /** A real primary click on a menu item: pointerdown, mousedown, mouseup, click. */
    const clickItem = (label: string) => {
      const el = screen.getByText(label);
      const init = { button: 0, clientX: 60, clientY: 60 };
      press(el, init);
      fireEvent.mouseUp(el, init);
      fireEvent.click(el, init);
    };

    it('keeps the menu open after Control+click and lets every item work', async () => {
      const onFileSelect = vi.fn();
      const [expanded, setExpanded] = createSignal(new Set(['/nb/Projects']));
      renderSidebar({
        onFileSelect,
        get expandedFolders() { return expanded(); },
        onExpandedFoldersChange: setExpanded,
      });
      await screen.findByText('Inbox');

      controlClick(item('plan'));
      expect(document.querySelector('.context-menu')).not.toBeNull();
      expect(onFileSelect).not.toHaveBeenCalled();

      // Inbox is collapsed: New note must reveal it so the name input is visible.
      controlClick(item('Inbox'));
      clickItem('New note');
      expect(expanded().has('/nb/Inbox')).toBe(true);
      const newItem = document.querySelector('.new-item input') as HTMLInputElement;
      expect(newItem).not.toBeNull();
      // WebKit only honours `autofocus` once per document; the input must focus itself.
      await waitFor(() => expect(document.activeElement).toBe(newItem));
      fireEvent.keyDown(newItem, { key: 'Escape' });

      for (let i = 0; i < 2; i++) {
        controlClick(item('Inbox'));
        clickItem('Rename');
        const rename = document.querySelector('.rename-input') as HTMLInputElement;
        expect(rename).not.toBeNull();
        await waitFor(() => expect(document.activeElement).toBe(rename));
        fireEvent.keyDown(rename, { key: 'Escape' });
      }

      controlClick(item('Inbox'));
      clickItem('Delete');
      expect(screen.getByText(/This will permanently delete/)).toBeTruthy();
    });

    it('activates the item under a press-hold-release, but not a release in place', async () => {
      renderSidebar();
      await screen.findByText('Inbox');
      const init = { button: 2, clientX: 20, clientY: 20 };

      press(item('Inbox'), init);
      fireEvent.contextMenu(item('Inbox'), init);
      fireEvent.mouseUp(screen.getByText('Delete'), init);
      expect(document.querySelector('.context-menu')).not.toBeNull();
      expect(screen.queryByText(/This will permanently delete/)).toBeNull();

      press(item('Inbox'), init);
      fireEvent.contextMenu(item('Inbox'), init);
      fireEvent.mouseUp(screen.getByText('Delete'), { button: 2, clientX: 40, clientY: 90 });
      expect(document.querySelector('.context-menu')).toBeNull();
      expect(screen.getByText(/This will permanently delete/)).toBeTruthy();
    });

    it('swallows the trailing click of a Control press-hold-release onto an item', async () => {
      renderSidebar();
      await screen.findByText('Inbox');
      const init = { button: 0, ctrlKey: true, clientX: 20, clientY: 20 };
      press(item('Inbox'), init);
      fireEvent.contextMenu(item('Inbox'), init);
      const share = screen.getByText('Rename');
      fireEvent.mouseUp(share, { ...init, clientY: 80 });
      // WebKit targets the click at the common ancestor of the row and the item.
      fireEvent.click(document.querySelector('.sidebar') as HTMLElement, { ...init, clientY: 80 });
      expect(document.querySelector('.rename-input')).not.toBeNull();
    });

    it('dismisses on a press outside the menu and on Escape', async () => {
      renderSidebar();
      await screen.findByText('Inbox');
      fireEvent.contextMenu(item('Inbox'));
      press(screen.getByText('Inbox'), { button: 0 });
      expect(document.querySelector('.context-menu')).toBeNull();

      fireEvent.contextMenu(item('Inbox'));
      press(screen.getByText('Delete'), { button: 0 });
      expect(document.querySelector('.context-menu')).not.toBeNull();
      fireEvent.keyDown(window, { key: 'Escape' });
      expect(document.querySelector('.context-menu')).toBeNull();
    });
  });
});
