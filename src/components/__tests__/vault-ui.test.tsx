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
import ShareDialog, { SHARE_VALIDATION_DEBOUNCE_MS } from '../ShareDialog';
import NotificationsPanel from '../NotificationsPanel';
import type { SharedDocument } from '../../lib/nostr/types';

const fetchUserProfile = vi.hoisted(() => vi.fn(async (_pubkey: string, _relays: string[]) => null as null | { name?: string; picture?: string }));
vi.mock('../../lib/nostr/login', () => ({ fetchUserProfile }));
vi.mock('../../lib/nostr/sync', () => ({
  getSyncEngine: () => ({ getConfig: () => ({ relays: ['wss://profile.example'] }) }),
}));

const BOB = 'b'.repeat(64);
const CAROL = 'c'.repeat(64);
const resolveRecipient = vi.fn(async (input: string) => {
  const map: Record<string, string> = { bob: BOB, carol: CAROL, me: 'a'.repeat(64) };
  const pubkey = map[input] ?? null;
  return pubkey
    ? { pubkey, type: 'hex' as const }
    : { pubkey: null, type: 'invalid' as const, error: 'Invalid format' };
});


beforeEach(() => {
  fetchUserProfile.mockClear();
  resolveRecipient.mockClear();
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

describe('NotificationsPanel failed profile lookups', () => {
  it.each(['empty', 'rejected'])('does not retry a %s lookup on reactive updates', async outcome => {
    if (outcome === 'rejected') fetchUserProfile.mockRejectedValueOnce(new Error('offline'));
    else fetchUserProfile.mockResolvedValueOnce(null);
    const doc: SharedDocument = {
      eventId: 'event', d: 'document', title: 'Shared note', senderPubkey: BOB,
      createdAt: 1, isRead: false,
      data: { path: 'note.md', content: '', checksum: '', sharedBy: { pubkey: BOB }, sharedAt: 1 },
    };
    const [docs, setDocs] = createSignal([doc]);
    render(() => <NotificationsPanel sharedDocuments={docs()} isLoading={false}
      onPreview={() => undefined} onRefresh={() => undefined} onClose={() => undefined} />);
    await waitFor(() => expect(fetchUserProfile).toHaveBeenCalledTimes(1));
    await Promise.resolve();
    setDocs([{ ...doc, isRead: true }]);
    await Promise.resolve();
    expect(fetchUserProfile).toHaveBeenCalledTimes(1);
  });
});

describe('ShareDialog recipient binding', () => {
  const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  type Resolver = (input: string) => Promise<{ pubkey: string | null; type: 'hex' | 'invalid'; error?: string }>;
  type ShareFn = (pubkey: string, title: string, content: string, filePath: string) => Promise<{ eventId: string }>;
  const shareMock = () => vi.fn<ShareFn>(async () => ({ eventId: 'evt' }));
  const renderDialog = (shareDocument: ReturnType<typeof shareMock>, resolve: Resolver = resolveRecipient) => render(() => (
    <ShareDialog filePath="notes/a.md" content="hello" title="a" onClose={() => undefined}
      resolveRecipient={resolve as never} shareDocument={shareDocument as never} />
  ));
  const field = () => screen.getByLabelText('Share with') as HTMLInputElement;
  const shareButton = () => screen.getByRole('button', { name: 'Share' }) as HTMLButtonElement;

  it('cancels the pending debounce when the field is cleared; nothing is shared to the earlier key', async () => {
    const shareDocument = shareMock();
    renderDialog(shareDocument);
    // Report fixture: type key A, clear, let the 500 ms timer elapse, press Share/Enter.
    fireEvent.input(field(), { target: { value: 'bob' } });
    fireEvent.input(field(), { target: { value: '' } });
    await vi.advanceTimersByTimeAsync(SHARE_VALIDATION_DEBOUNCE_MS + 100);
    await flush();
    expect(resolveRecipient).not.toHaveBeenCalled();
    expect(field().value).toBe('');
    expect(shareButton().disabled).toBe(true);
    fireEvent.click(shareButton());
    fireEvent.keyDown(field(), { key: 'Enter' });
    await flush();
    expect(shareDocument).not.toHaveBeenCalled();
  });

  it('discards a resolution that settles after the field changed and shares only the current pair', async () => {
    let resolveBob!: (value: { pubkey: string; type: 'hex' }) => void;
    const slow: Resolver = vi.fn((input: string) => input === 'bob'
      ? new Promise<{ pubkey: string; type: 'hex' }>((r) => { resolveBob = r; })
      : resolveRecipient(input));
    const shareDocument = shareMock();
    renderDialog(shareDocument, slow);

    fireEvent.input(field(), { target: { value: 'bob' } });
    await vi.advanceTimersByTimeAsync(SHARE_VALIDATION_DEBOUNCE_MS + 10); // bob resolution now in flight
    fireEvent.input(field(), { target: { value: 'carol' } });
    await vi.advanceTimersByTimeAsync(SHARE_VALIDATION_DEBOUNCE_MS + 10);
    await flush();
    resolveBob({ pubkey: BOB, type: 'hex' }); // stale generation settles last
    await flush();

    expect(shareButton().disabled).toBe(false);
    fireEvent.click(shareButton());
    await flush();
    expect(shareDocument).toHaveBeenCalledTimes(1);
    expect(shareDocument.mock.calls[0][0]).toBe(CAROL);
  });

  it('disables sharing again as soon as a validated recipient is edited', async () => {
    const shareDocument = shareMock();
    renderDialog(shareDocument);
    fireEvent.input(field(), { target: { value: 'bob' } });
    await vi.advanceTimersByTimeAsync(SHARE_VALIDATION_DEBOUNCE_MS + 10);
    await flush();
    expect(shareButton().disabled).toBe(false);
    fireEvent.input(field(), { target: { value: 'bo' } });
    expect(shareButton().disabled).toBe(true);
    fireEvent.keyDown(field(), { key: 'Enter' });
    await flush();
    expect(shareDocument).not.toHaveBeenCalled();
  });
});
