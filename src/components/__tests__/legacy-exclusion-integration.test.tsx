import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@solidjs/testing-library';
import App from '../../App';
import { platform } from '@platform';
import Settings from '../Settings';
import { getVaultEngine, registerVaultEngineFactory, resetVaultEngine, type VaultEngine,
  type VaultEngineSnapshot, type VaultSession } from '../../lib/vault/engine-api';
import { hashAddress, hex32 } from '../../lib/vault/crypto';
import type { Pubkey, VaultId } from '../../lib/vault/types';

const mocks = vi.hoisted(() => {
  const files = new Map<string, string>();
  const signer = { getPublicKey: vi.fn(async () => 'a'.repeat(64)), getType: () => 'local' };
  const login = { id: 'login', type: 'nsec', pubkey: 'a'.repeat(64) };
  const vault = { data: { files: [] as { path: string; d: string }[], deleted: [] as { path: string; lastEventId: string; deletedAt: number }[] } };
  const legacy = {
    getSigner: vi.fn(() => signer), setSigner: vi.fn(async () => {}),
    getConfig: vi.fn(() => ({ relays: [] })), setConfig: vi.fn(),
    fetchVaults: vi.fn(async () => [vault]), fetchVaultFiles: vi.fn(async () => [] as ReturnType<typeof remote>[]),
    publishFile: vi.fn(async () => ({ vault })), deleteFile: vi.fn(async () => vault),
    moveFile: vi.fn(async () => ({ vault })), fetchSharedWithMe: vi.fn(async () => []),
    fetchSentShares: vi.fn(async () => []), fetchPreferences: vi.fn(async () => null),
    fetchMuteList: vi.fn(async () => ({ pubkeys: [] })), importSharedDocument: vi.fn(),
    pool: { querySync: vi.fn(async () => [{ content: 'encrypted' }]) },
    decryptContent: vi.fn(async () => JSON.stringify({ content: 'recovered' })),
  };
  function remote(path: string) {
    return { d: path, data: { path, content: 'remote', checksum: `checksum:remote:${path}`, modified: 20 } };
  }
  return { files, signer, login, vault, legacy, remote,
    currentLogin: vi.fn(async () => login as typeof login | null),
    write: vi.fn(async (path: string, content: string) => { files.set(path, content); }),
    createFolder: vi.fn(async () => {}), createFile: vi.fn(async () => {}),
    list: vi.fn(async () => [] as { name: string; path: string; isDirectory: boolean; isSymlink?: boolean; children?: unknown[] }[]),
    filesChanged: undefined as undefined | ((paths?: string[]) => void),
    modified: undefined as undefined | ((paths: string[]) => Promise<void>),
    onSave: undefined as undefined | (() => Promise<void>),
    unlistenFiles: vi.fn(), unlistenModified: vi.fn(), unlistenDeepLink: vi.fn(),
    clip: undefined as undefined | ((urls: string[]) => Promise<void>),
    read: vi.fn(async (path: string) => files.get(path) ?? ''),
    realPath: vi.fn(async (path: string) => path as string | null),
  };
});

vi.mock('@platform', () => ({ platform: {
  info: { platform: 'linux', is_web: false },
  vault: {
    list: mocks.list, listAssets: vi.fn(async () => []), read: mocks.read,
    write: mocks.write, createFolder: mocks.createFolder, createFile: mocks.createFile,
    exists: vi.fn(async () => false), modifiedTime: vi.fn(async () => 1), realPath: mocks.realPath,
    setVaultScope: vi.fn(async () => {}), startWatching: vi.fn(async () => {}), stopWatching: vi.fn(async () => {}),
    onFilesChanged: vi.fn(async (cb: (paths?: string[]) => void) => { mocks.filesChanged = cb; return mocks.unlistenFiles; }),
    onFileModified: vi.fn(async (cb: (paths: string[]) => Promise<void>) => { mocks.modified = cb; return mocks.unlistenModified; }),
  },
  settings: { load: vi.fn(async () => ({ vault_path: '/notes' })), save: vi.fn(async () => {}) },
  secrets: {}, clipboard: { readText: vi.fn(async () => 'clip content') },
  app: { getVersion: vi.fn(async () => 'test') },
  opencode: { getRegisteredPath: vi.fn(async () => null) },
  deepLink: {
    onOpenUrl: vi.fn(async (cb: (urls: string[]) => Promise<void>) => { mocks.clip = cb; return mocks.unlistenDeepLink; }),
    onReceived: vi.fn(async () => mocks.unlistenDeepLink), getCurrent: vi.fn(async () => []),
    getLaunchArgs: vi.fn(async () => []),
  },
  dialog: { pathExists: vi.fn(async () => true), mkdir: mocks.createFolder, writeTextFile: mocks.write },
  skills: { getManifest: vi.fn(async () => []), isInstalled: vi.fn(async () => false) },
} }));
vi.mock('../../lib/platform', () => ({
  initPlatform: vi.fn(async () => ({ platform: 'linux' })),
  usePlatformInfo: () => () => ({ platform: 'linux' }), isWeb: () => false, isMobile: () => false,
}));
vi.mock('../../lib/nostr', () => ({
  getSyncEngine: () => mocks.legacy, getCurrentLogin: mocks.currentLogin, getCurrentLoginWithAuth: mocks.currentLogin,
  calculateChecksum: (content: string) => `checksum:${content}`,
  DEFAULT_SYNC_CONFIG: { relays: ['wss://default.test'], blossomServers: ['https://default.test'] },
  setOnSaveSyncCallback: (cb: () => Promise<void>) => { mocks.onSave = cb; },
  getIdentityFromLogin: () => null, getSavedProfile: vi.fn(async () => null),
  fetchUserProfile: vi.fn(async () => null), fetchUserRelays: vi.fn(async () => []),
  fetchUserBlossomServers: vi.fn(async () => []), clearLogins: vi.fn(async () => {}),
  saveLogin: vi.fn(async () => {}), saveUserProfile: vi.fn(), removeLogin: vi.fn(),
  generateNewLogin: vi.fn(() => ({ identity: null, login: mocks.login })),
  importNsecLogin: vi.fn(() => ({ identity: null, login: mocks.login })),
}));
vi.mock('../../lib/nostr/signer', () => ({
  getSignerFromStoredLogin: vi.fn(async () => mocks.signer), createSignerFromLogin: () => mocks.signer,
}));
vi.mock('../../lib/ai-credentials', () => ({
  getOpenClawToken: vi.fn(async () => null), getCustomProviderApiKey: vi.fn(async () => null),
  setOpenClawToken: vi.fn(), clearOpenClawToken: vi.fn(), setCustomProviderApiKey: vi.fn(), clearCustomProviderApiKey: vi.fn(),
}));
vi.mock('../../lib/haptics', () => ({ impactLight: vi.fn(), impactMedium: vi.fn(), notificationSuccess: vi.fn(), notificationError: vi.fn() }));
vi.mock('../../lib/opencode/client', () => ({
  initClient: vi.fn(), isServerRunning: vi.fn(async () => false), getProviders: vi.fn(async () => []),
  getCurrentModel: vi.fn(), setCurrentModel: vi.fn(), getAllProvidersWithAuthStatus: vi.fn(async () => []),
  setProviderApiKey: vi.fn(), removeProviderAuth: vi.fn(), startProviderOAuth: vi.fn(),
}));
vi.mock('../../lib/openclaw/gateway', () => ({ getSkillsStatus: vi.fn(async () => []), updateSkill: vi.fn(), installSkill: vi.fn() }));
vi.mock('../../lib/skills', () => ({
  fetchSkillsShLeaderboard: vi.fn(async () => []), searchSkillsSh: vi.fn(async () => []), sortSkillsSh: vi.fn(),
  formatInstallCount: vi.fn(), getSkillGitHubUrl: vi.fn(), installSkillFromSkillsSh: vi.fn(), isSkillInstalled: vi.fn(),
}));
vi.mock('../Editor', () => ({ default: (props: { content: string; onContentChange(content: string): void }) =>
  <textarea aria-label="Test editor" value={props.content} onInput={e => props.onContentChange(e.currentTarget.value)} /> }));
vi.mock('../Sidebar', () => ({ default: (props: { onFileInfo(path: string): void; onCreateSharedVault?(folder: string): void; onAttachSharedVault?(folder: string): void }) => <>
  <button onClick={() => props.onFileInfo('/notes/Team/note.md')}>Managed file info</button>
  <button onClick={() => props.onCreateSharedVault?.('Team')}>Share folder as vault...</button>
  <button onClick={() => props.onAttachSharedVault?.('Team')}>Attach owned vault...</button>
</> }));
vi.mock('../QuickSwitcher', () => ({ default: () => null }));
vi.mock('../CommandPalette', () => ({ default: () => null }));
vi.mock('../SearchPanel', () => ({ default: () => null }));
vi.mock('../OpenCodePanel', () => ({ default: () => null }));
vi.mock('../OpenClawChat', () => ({ default: () => null }));
vi.mock('../CustomProviderChat', () => ({ default: () => null }));
vi.mock('../GraphView', () => ({ default: () => null }));
vi.mock('../OutlinePanel', () => ({ default: () => null }));
vi.mock('../BacklinksPanel', () => ({ default: () => null }));
vi.mock('../PropertiesPanel', () => ({ default: () => null }));
vi.mock('../ShareDialog', () => ({ default: () => null }));
vi.mock('../NotificationsPanel', () => ({ default: () => null }));
vi.mock('../SharedDocPreview', () => ({ default: () => null }));
vi.mock('../SentSharesPanel', () => ({ default: () => null }));
vi.mock('../FileInfoDialog', () => ({ default: (props: { onSyncFile(): Promise<unknown> }) =>
  <button onClick={() => { void props.onSyncFile().catch(() => {}); }}>Sync managed file</button> }));
vi.mock('../PostToNostrDialog', () => ({ default: () => null }));
vi.mock('../Onboarding', () => ({ default: () => null }));
vi.mock('../UnlockDialog', () => ({ default: () => null }));
vi.mock('../mobile', () => ({ MobileHeader: () => null, MobileNav: () => null, MobileDrawer: () => null }));

const vaultId = hex32<VaultId>('1'.repeat(64));
const owner = hex32<Pubkey>('a'.repeat(64));
const snapshot: VaultEngineSnapshot = {
  lifecycle: 'running', activity: 'idle', condition: 'ready', invitations: [], lastError: null,
  vaults: [{ vaultId, owner, label: 'Team', authority: 'owner', enabled: true, provisional: false,
    provisionalCount: 0, provisionalPaths: [], provisionalOtherPaths: [],
    conflictCount: 0, pendingDeliveryCount: 0, resealRemainingBytes: 0n, publisher: null, lastError: null,
    mount: { vaultId, notebookPath: '/notes', relativePath: 'Team' } }],
};
let engine: VaultEngine;
let session: VaultSession;
let emit: (snapshot: VaultEngineSnapshot) => void;
let unsubscribe = vi.fn<() => void>();

function fakeEngine(): VaultEngine {
  unsubscribe = vi.fn();
  return {
    deviceKeys: { getState: vi.fn(() => ({ enabled: false, allowIdentityFallback: false, announcedPubkey: null, retainedKeyCount: 0, current: null, retained: [] })),
      setEnabled: vi.fn(), generate: vi.fn(), import: vi.fn(), announce: vi.fn(), useIdentityFallback: vi.fn(),
      observeRecipient: vi.fn(), approveRecipientKey: vi.fn(), resetRecipientPin: vi.fn() },
    start: vi.fn(async value => { session = value; }), stop: vi.fn(async () => {}),
    subscribe: vi.fn(listener => { emit = listener; listener(snapshot); return unsubscribe; }),
    updateNetworkDefaults: vi.fn(async () => {}), notifyFilesChanged: vi.fn(), sync: vi.fn(async () => {}),
    create: vi.fn(), share: vi.fn(), attach: vi.fn(), takeOverPublishing: vi.fn(), accept: vi.fn(),
    revoke: vi.fn(), resolveConflicts: vi.fn(), reseal: vi.fn(), pause: vi.fn(), resume: vi.fn(),
    detach: vi.fn(), refreshInbox: vi.fn(), repairInbox: vi.fn(), exportRecovery: vi.fn(),
  };
}

beforeEach(async () => {
  vi.clearAllMocks();
  // Node's experimental global localStorage can shadow jsdom's storage.
  const storage = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, String(value)),
    removeItem: (key: string) => storage.delete(key), clear: () => storage.clear(),
    key: (index: number) => [...storage.keys()][index] ?? null,
    get length() { return storage.size; },
  });
  localStorage.setItem('onboarding_completed', 'true');
  localStorage.setItem('sync_enabled', 'true');
  localStorage.setItem('sync_on_startup', 'false');
  mocks.files.clear();
  mocks.onSave = undefined;
  mocks.filesChanged = undefined;
  mocks.modified = undefined;
  mocks.clip = undefined;
  mocks.list.mockResolvedValue([]);
  mocks.legacy.fetchVaultFiles.mockResolvedValue([]);
  mocks.currentLogin.mockResolvedValue(mocks.login);
  mocks.vault.data.deleted = [];
  mocks.write.mockImplementation(async (path, content) => { mocks.files.set(path, content); });
  mocks.read.mockImplementation(async path => mocks.files.get(path) ?? '');
  mocks.realPath.mockImplementation(async path => path);
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  engine = fakeEngine();
  registerVaultEngineFactory(() => engine);
});
afterEach(async () => {
  cleanup();
  await resetVaultEngine();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function legacyFixture() {
  mocks.files.set('/notes/Team/local.md', 'private');
  mocks.files.set('/notes/upload.md', 'public');
  mocks.list.mockResolvedValue([
    { name: 'Team', path: '/notes/Team', isDirectory: true, children: [
      { name: 'local.md', path: '/notes/Team/local.md', isDirectory: false },
    ] },
    { name: 'upload.md', path: '/notes/upload.md', isDirectory: false },
  ]);
  mocks.legacy.fetchVaultFiles.mockResolvedValue([
    'Team/remote.md', 'Team/deleted.md', 'Team/old.md', 'Team',
    '.onyx-vault-staging/remote.md', 'Team-sibling/remote.md', 'deleted.md',
  ].map(mocks.remote));
  localStorage.setItem('deleted_paths', JSON.stringify(['Team/deleted.md', 'deleted.md']));
  localStorage.setItem('moved_paths', JSON.stringify([{ from: 'Team/old.md', to: 'upload.md' }]));
  localStorage.setItem('file_dtag_map', JSON.stringify({ 'upload.md': 'Team/old.md' }));
}
function expectLegacyExclusion() {
  expect(mocks.write.mock.calls.map(([path]) => path)).toEqual(['/notes/Team-sibling/remote.md']);
  expect(mocks.legacy.publishFile.mock.calls.map(call => (call as unknown[])[1])).toEqual(['upload.md']);
  expect(mocks.legacy.deleteFile.mock.calls.map(call => (call as unknown[])[1])).toEqual(['deleted.md']);
  expect(mocks.legacy.moveFile).not.toHaveBeenCalled();
  expect(JSON.parse(localStorage.getItem('deleted_paths')!)).toEqual([]);
  expect(JSON.parse(localStorage.getItem('moved_paths')!)).toEqual([]);
}
async function mountApp(path = '/notes/Team/note.md') {
  mocks.files.set(path, 'original');
  localStorage.setItem('session_state', JSON.stringify({ tabs: [{ path, name: 'note' }], activeTabIndex: 0 }));
  const result = render(() => <App />);
  await waitFor(() => expect(engine.start).toHaveBeenCalledTimes(1));
  return result;
}

describe('shared vault startup feedback', () => {
  it.each(['Share folder as vault...', 'Attach owned vault...'])('opens an explanation and retries from %s when startup fails', async action => {
    vi.mocked(engine.start).mockRejectedValueOnce(new Error('IndexedDB unavailable'));
    await mountApp();
    await waitFor(() => expect(document.querySelector('.shared-vault-status')?.textContent).toContain('IndexedDB unavailable'));
    emit({ ...snapshot, lifecycle: 'stopped', condition: 'error' });
    fireEvent.click(screen.getAllByRole('button', { name: action })[0]);
    expect(screen.getByRole('dialog', { name: 'Shared vaults' })).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('failed to start');
    fireEvent.click(screen.getByRole('button', { name: 'Retry shared vaults' }));
    await waitFor(() => expect(engine.start).toHaveBeenCalledTimes(2));
    expect(screen.getByRole('dialog', { name: 'Shared vaults' })).toBeTruthy();
    expect(engine.create).not.toHaveBeenCalled();
    expect(engine.attach).not.toHaveBeenCalled();
  });

  it('retry cancels an in-flight start immediately and ignores its stale error', async () => {
    let abortStart!: (error: Error) => void;
    vi.mocked(engine.start).mockImplementationOnce(() => new Promise((_, reject) => { abortStart = reject; }));
    await mountApp();
    vi.mocked(engine.stop).mockImplementationOnce(async () => { abortStart(new Error('stale startup aborted')); });
    emit({ ...snapshot, lifecycle: 'starting' });
    fireEvent.click(document.querySelector('.shared-vault-status')!);
    fireEvent.click(screen.getByRole('button', { name: 'Retry shared vaults' }));
    await waitFor(() => expect(engine.stop).toHaveBeenCalledOnce());
    await waitFor(() => expect(engine.start).toHaveBeenCalledTimes(2));
    expect(document.querySelector('.shared-vault-status')?.textContent).not.toContain('stale startup aborted');
  });

  it('explains a locked/missing login and retries after it is unlocked', async () => {
    mocks.currentLogin.mockResolvedValue(null);
    render(() => <App />);
    await waitFor(() => expect(document.querySelector('.shared-vault-status')?.textContent).toContain('unlock your identity'));
    expect(engine.start).not.toHaveBeenCalled();
    fireEvent.click(screen.getAllByRole('button', { name: 'Share folder as vault...' })[0]);
    expect(screen.getByRole('alert').textContent).toContain('Biometric authentication may have been cancelled');
    mocks.currentLogin.mockResolvedValue(mocks.login);
    fireEvent.click(screen.getByRole('button', { name: 'Retry shared vaults' }));
    await waitFor(() => expect(engine.start).toHaveBeenCalledOnce());
    expect(session.signer).toBe(mocks.signer);
  });

  it('shows non-ready engine messages visibly, not just in the status tooltip', async () => {
    await mountApp();
    emit({ ...snapshot, lifecycle: 'stopped', condition: 'needs-key', lastError: {
      code: 'EPOCH', operation: 'start', retryable: true, message: 'Unlock the secret store, then retry.',
    } });
    expect(document.querySelector('.shared-vault-status')?.textContent).toContain('needs-key — Unlock the secret store');
    expect(document.querySelector('.shared-vault-status--attention')).toBeTruthy();
  });
});

describe('legacy exclusion at both orchestration sites', () => {
  it('file-info Sync file refuses managed paths before reading or publishing', async () => {
    await mountApp();
    fireEvent.click(screen.getAllByRole('button', { name: 'Managed file info' })[0]);
    await screen.findByRole('button', { name: 'Sync managed file' });
    mocks.read.mockClear();
    fireEvent.click(screen.getByRole('button', { name: 'Sync managed file' }));
    await Promise.resolve();
    expect(mocks.read).not.toHaveBeenCalled();
    expect(mocks.legacy.publishFile).not.toHaveBeenCalled();
  });

  it('App excludes managed upload/download/delete/move paths but still syncs siblings', async () => {
    legacyFixture();
    await mountApp();
    fireEvent.click(document.querySelector('.sync-status')!);
    await waitFor(() => expect(document.querySelector('.sync-status')?.classList.contains('idle')).toBe(true));
    expectLegacyExclusion();
  });

  it('App excludes mount content reached through local aliases by filesystem identity (SV-42)', async () => {
    legacyFixture();
    for (const path of ['/notes/Direct/local.md', '/notes/Alias/Team/local.md']) mocks.files.set(path, 'private');
    mocks.files.set('/notes/Alias/plain.md', 'public');
    mocks.list.mockResolvedValue([
      { name: 'Team', path: '/notes/Team', isDirectory: true, children: [{ name: 'local.md', path: '/notes/Team/local.md', isDirectory: false }] },
      { name: 'upload.md', path: '/notes/upload.md', isDirectory: false },
      // `Direct -> Team`: the alias itself resolves into the mount.
      { name: 'Direct', path: '/notes/Direct', isDirectory: true, isSymlink: true, children: [{ name: 'local.md', path: '/notes/Direct/local.md', isDirectory: false }] },
      // `Alias -> /notes`: resolves outside every mount, yet its unflagged `Team` child is the mount.
      { name: 'Alias', path: '/notes/Alias', isDirectory: true, isSymlink: true, children: [
        { name: 'Team', path: '/notes/Alias/Team', isDirectory: true, children: [{ name: 'local.md', path: '/notes/Alias/Team/local.md', isDirectory: false }] },
        { name: 'plain.md', path: '/notes/Alias/plain.md', isDirectory: false },
      ] },
    ]);
    mocks.realPath.mockImplementation(async (path: string) =>
      path.replace(/^\/notes\/Direct(?=\/|$)/, '/notes/Team').replace(/^\/notes\/Alias(?=\/|$)/, '/notes'));
    mocks.legacy.fetchVaultFiles.mockResolvedValue(['Direct/remote.md', 'Alias/Team/remote.md', 'Alias/remote-plain.md', 'Team-sibling/remote.md'].map(mocks.remote));
    await mountApp();
    fireEvent.click(document.querySelector('.sync-status')!);
    await waitFor(() => expect(document.querySelector('.sync-status')?.classList.contains('idle')).toBe(true));
    // Reads are not the signal (the editor's index legitimately reads listed files); what legacy sync
    // publishes and writes is: nothing under either alias of the mount, everything beside them.
    expect(mocks.legacy.publishFile.mock.calls.map(call => (call as unknown[])[1]).sort()).toEqual(['Alias/plain.md', 'upload.md']);
    expect(mocks.write.mock.calls.map(([path]) => path).sort()).toEqual(['/notes/Alias/remote-plain.md', '/notes/Team-sibling/remote.md']);
    expect(mocks.realPath).toHaveBeenCalledWith('/notes/Direct');
    expect(mocks.realPath).toHaveBeenCalledWith('/notes/Alias');
  });

  it.each(['manual', 'periodic', 'onsave'])('Settings excludes mounts during %s sync', async mode => {
    legacyFixture();
    if (mode === 'periodic') localStorage.setItem('sync_frequency', '5min');
    if (mode === 'periodic') vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    const shared = getVaultEngine();
    render(() => <Settings vaultPath="/notes" onClose={() => {}} vaultEngine={shared} initialSection="sync" />);
    await waitFor(() => expect(mocks.onSave).toBeTypeOf('function'));
    if (mode === 'manual') fireEvent.click(screen.getByRole('button', { name: 'Sync Now' }));
    else if (mode === 'onsave') void mocks.onSave!();
    else {
      await vi.advanceTimersByTimeAsync(300000);
    }
    await waitFor(() => expect(mocks.write).toHaveBeenCalledTimes(1), { timeout: 3000 });
    expectLegacyExclusion();
  });
});

describe('managed editor coordination', () => {
  it('preserves a dirty managed tab on file-modified and forwards both watchers', async () => {
    await mountApp();
    fireEvent.input(screen.getByRole('textbox', { name: 'Test editor' }), { target: { value: 'unsaved local' } });
    mocks.files.set('/notes/Team/note.md', 'external');
    await mocks.modified!(['/notes/Team/note.md']);
    expect((screen.getByRole('textbox') as HTMLTextAreaElement).value).toBe('unsaved local');
    expect(engine.notifyFilesChanged).toHaveBeenCalledWith(['/notes/Team/note.md']);
    mocks.filesChanged!(['/notes/Team/image.bin']);
    expect(engine.notifyFilesChanged).toHaveBeenCalledWith(['/notes/Team/image.bin']);
    fireEvent.keyDown(document, { key: 's', ctrlKey: true });
    await waitFor(() => expect(mocks.files.get('/notes/Team/note.md')).toBe('unsaved local'));
  });

  it('keeps the legacy external-wins behaviour outside mounts', async () => {
    await mountApp('/notes/ordinary.md');
    fireEvent.input(screen.getByRole('textbox'), { target: { value: 'unsaved local' } });
    mocks.files.set('/notes/ordinary.md', 'external');
    await mocks.modified!(['/notes/ordinary.md']);
    expect((screen.getByRole('textbox') as HTMLTextAreaElement).value).toBe('external');
  });

  it('flushes through normal save, holds editors, and queues explicit saves until release', async () => {
    await mountApp();
    fireEvent.input(screen.getByRole('textbox'), { target: { value: 'unsaved local' } });
    const barrier = await session.editorBarrier.enter(['Team/./note.md'], new AbortController().signal);
    expect(mocks.files.get('/notes/Team/note.md')).toBe('unsaved local');
    expect(barrier.flushedHashes.get('Team/note.md')).toBe(hashAddress(new TextEncoder().encode('unsaved local')));
    expect((document.querySelector('.editor-area') as HTMLElement).inert).toBe(true);
    fireEvent.input(screen.getByRole('textbox'), { target: { value: 'blocked edit' } });
    fireEvent.keyDown(document, { key: 's', ctrlKey: true });
    await Promise.resolve();
    expect(mocks.write).toHaveBeenCalledTimes(1);
    mocks.files.set('/notes/Team/note.md', 'materialized');
    barrier.release();
    await waitFor(() => expect((document.querySelector('.editor-area') as HTMLElement).inert).toBe(false));
    expect(mocks.write).toHaveBeenCalledTimes(1);
    expect(mocks.files.get('/notes/Team/note.md')).toBe('materialized');
    expect((screen.getByRole('textbox') as HTMLTextAreaElement).value).toBe('materialized');
  });

  it('reports failed flushes and preserves dirty content', async () => {
    await mountApp();
    fireEvent.input(screen.getByRole('textbox'), { target: { value: 'unsaved local' } });
    mocks.write.mockRejectedValueOnce(new Error('disk full'));
    await expect(session.editorBarrier.enter(['Team/note.md'], new AbortController().signal)).rejects.toThrow('disk full');
    expect((screen.getByRole('textbox') as HTMLTextAreaElement).value).toBe('unsaved local');
    expect(document.querySelector('.shared-vault-status')?.getAttribute('title')).toContain('flush failed');
    expect((document.querySelector('.editor-area') as HTMLElement).inert).toBe(false);
  });

  it('bounds a stalled flush to five seconds', async () => {
    await mountApp();
    fireEvent.input(screen.getByRole('textbox'), { target: { value: 'unsaved local' } });
    vi.useFakeTimers();
    let complete!: () => void;
    mocks.write.mockImplementationOnce(() => new Promise<void>(resolve => { complete = resolve; }));
    const result = expect(session.editorBarrier.enter(['Team/note.md'], new AbortController().signal)).rejects.toThrow('5 seconds');
    await vi.advanceTimersByTimeAsync(5000);
    await result;
    expect((document.querySelector('.editor-area') as HTMLElement).inert).toBe(false);
    complete();
    await Promise.resolve();
  });

  it('routes clipper writes through the same hold and capture notification', async () => {
    await mountApp();
    const barrier = await session.editorBarrier.enter(['Team'], new AbortController().signal);
    const clip = mocks.clip!(['onyx://clip?path=Team&filename=clip&clipboard=1']);
    await Promise.resolve();
    await Promise.resolve();
    expect(mocks.write).not.toHaveBeenCalled();
    barrier.release();
    await clip;
    expect(mocks.files.get('/notes/Team/clip.md')).toBe('clip content');
    expect(engine.notifyFilesChanged).toHaveBeenCalledWith(['/notes/Team/clip.md']);
  });
});

it('Settings excludes recovery destinations, including mounts added after a scan', async () => {
  mocks.vault.data.deleted = ['Team/deleted.md', 'recover.md'].map(path => ({ path, lastEventId: path, deletedAt: 1 }));
  render(() => <Settings vaultPath="/notes" onClose={() => {}} vaultEngine={getVaultEngine()} initialSection="sync" />);
  await waitFor(() => expect(mocks.onSave).toBeTypeOf('function'));
  fireEvent.click(screen.getByRole('button', { name: 'Scan' }));
  await screen.findByText('recover.md');
  expect(screen.queryByText('Team/deleted.md')).toBeNull();
  emit({ ...snapshot, vaults: [{ ...snapshot.vaults[0], mount: { vaultId, notebookPath: '/notes', relativePath: 'recover.md' } }] });
  fireEvent.click(screen.getByRole('button', { name: 'Recover' }));
  await Promise.resolve();
  expect(mocks.write).not.toHaveBeenCalled();
});

it('Settings forwards network changes and exposes the independent shared settings slot', async () => {
  localStorage.setItem('sync_enabled', 'false');
  render(() => <Settings vaultPath="/notes" onClose={() => {}} vaultEngine={getVaultEngine()}
    initialSection="sync" sharedVaultSettings={<div>Shared settings slot</div>} />);
  expect(screen.getByText('Shared settings slot')).toBeTruthy();
  await waitFor(() => expect(engine.updateNetworkDefaults).toHaveBeenCalled());
  fireEvent.click(screen.getByRole('button', { name: 'Nostr' }));
  const relay = screen.getByPlaceholderText('wss://relay.example.com');
  fireEvent.input(relay, { target: { value: 'wss://added.test' } });
  fireEvent.keyPress(relay, { key: 'Enter', charCode: 13 });
  const blossom = screen.getByPlaceholderText('https://blossom.example.com');
  fireEvent.input(blossom, { target: { value: 'https://added.test' } });
  fireEvent.keyPress(blossom, { key: 'Enter', charCode: 13 });
  await waitFor(() => expect(engine.updateNetworkDefaults).toHaveBeenLastCalledWith({
    readRelays: ['wss://default.test', 'wss://added.test'], writeRelays: ['wss://default.test', 'wss://added.test'],
    readBlossom: ['https://default.test', 'https://added.test'], writeBlossom: ['https://default.test', 'https://added.test'],
  }));
});

it('App waits for the old session stop after a Settings identity change', async () => {
  await mountApp();
  fireEvent.click(screen.getByTitle('Settings'));
  fireEvent.click(await screen.findByRole('button', { name: 'Nostr' }));
  const logout = await screen.findByRole('button', { name: 'Logout' });
  let stopped!: () => void;
  vi.mocked(engine.stop).mockImplementationOnce(() => new Promise<void>(resolve => { stopped = resolve; }));
  mocks.currentLogin.mockResolvedValue(null);
  fireEvent.click(logout);
  await waitFor(() => expect(engine.stop).toHaveBeenCalledOnce());
  expect(engine.start).toHaveBeenCalledOnce();
  expect(screen.queryByRole('button', { name: 'Logout' })).not.toBeNull();
  stopped();
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Logout' })).toBeNull());
  expect(engine.start).toHaveBeenCalledOnce();
});

it('unsubscribes listeners whose registration resolves after App cleanup', async () => {
  let finishModified!: (unsubscribe: () => void) => void;
  let finishDeepLink!: (unsubscribe: () => void) => void;
  vi.mocked(platform.vault.onFileModified).mockImplementationOnce(() => new Promise(resolve => { finishModified = resolve; }));
  vi.mocked(platform.deepLink.onOpenUrl).mockImplementationOnce(() => new Promise(resolve => { finishDeepLink = resolve; }));
  const app = await mountApp();
  app.unmount();
  finishModified(mocks.unlistenModified);
  finishDeepLink(mocks.unlistenDeepLink);
  await waitFor(() => expect(mocks.unlistenModified).toHaveBeenCalledOnce());
  expect(mocks.unlistenDeepLink).toHaveBeenCalledOnce();
});

it('builds the session from stored network defaults and cleans up subscriptions', async () => {
  localStorage.setItem('nostr_relays', JSON.stringify([
    { url: 'wss://read.test', read: true, write: false }, { url: 'wss://write.test', read: false, write: true },
  ]));
  localStorage.setItem('blossom_servers', JSON.stringify(['https://blossom.test']));
  const app = await mountApp();
  expect(session.accountPubkey).toBe(owner);
  emit({ ...snapshot, activity: 'materializing' });
  expect(document.querySelector('.shared-vault-status')?.textContent).toContain('materializing');
  expect(session.networkDefaults).toEqual({ readRelays: ['wss://read.test'], writeRelays: ['wss://write.test'],
    readBlossom: ['https://blossom.test'], writeBlossom: ['https://blossom.test'] });
  app.unmount();
  await waitFor(() => expect(engine.stop).toHaveBeenCalledTimes(1));
  expect(unsubscribe).toHaveBeenCalledOnce();
  expect(mocks.unlistenFiles).toHaveBeenCalledOnce();
  expect(mocks.unlistenModified).toHaveBeenCalledOnce();
  expect(mocks.unlistenDeepLink).toHaveBeenCalledTimes(2);
});
