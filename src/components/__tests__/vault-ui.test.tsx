import { cleanup, fireEvent, render, screen, waitFor, within } from '@solidjs/testing-library';
import { createRoot, createSignal } from 'solid-js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FileEntry } from '@platform';
import type {
  VaultEngine, VaultEngineSnapshot, VaultInvitationSummary, VaultNetworkDefaults, VaultSummary,
} from '../../lib/vault/engine-api';
import { VaultError } from '../../lib/vault/errors';
import type { EventId, Pubkey, VaultId, VaultMount, VaultRecoveryPackage } from '../../lib/vault/types';

const fetchUserProfile = vi.hoisted(() => vi.fn(async (_pubkey: string, _relays: string[]) => null as null | { name?: string; picture?: string }));
vi.mock('../../lib/nostr/login', () => ({ fetchUserProfile }));
vi.mock('../../lib/nostr/sync', () => ({
  getSyncEngine: () => ({ getConfig: () => ({ relays: ['wss://profile.example'] }) }),
}));

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

import KeyFingerprint, { FINGERPRINT_WORDS, keyFingerprint } from '../KeyFingerprint';
import NotificationsPanel from '../NotificationsPanel';
import ShareDialog, { SHARE_VALIDATION_DEBOUNCE_MS } from '../ShareDialog';
import SharedVaultSettings from '../SharedVaultSettings';
import SharedVaultEngineStatus from '../SharedVaultEngineStatus';
import RecoveryPassphraseFields, { recoveryPassphraseValid } from '../RecoveryPassphraseFields';
import Sidebar from '../Sidebar';
import VaultConflictsPanel, { availableActions } from '../VaultConflictsPanel';
import VaultInvitationDialog from '../VaultInvitationDialog';
import VaultPanel, { DEFAULT_RESEAL_BUDGET } from '../VaultPanel';
import VaultShareDialog from '../VaultShareDialog';
import {
  clearProfileCache, createVaultSnapshot, defaultProfileRelays, findMountForPath, lookupProfile, toNotebookRelative,
  validateBasename, type DeviceKeySettingsController, type SharedVaultMountInfo, type VaultConflictView,
  type VaultDeliveryView,
} from '../vault-ui';

const ME = 'a'.repeat(64) as Pubkey;
const BOB = 'b'.repeat(64) as Pubkey;
const CAROL = 'c'.repeat(64) as Pubkey;
const OTHER_OWNER = 'd'.repeat(64) as Pubkey;
const VID = '1'.repeat(64) as VaultId;
const INV = 'e'.repeat(64) as EventId;

const MOUNT: VaultMount = { vaultId: VID, notebookPath: '/nb', relativePath: 'Projects' };

function vaultSummary(overrides: Partial<VaultSummary> = {}): VaultSummary {
  return {
    vaultId: VID,
    owner: ME,
    label: 'Projects',
    authority: 'owner',
    enabled: true,
    provisional: false,
    provisionalCount: 0,
    provisionalPaths: [],
    provisionalOtherPaths: [],
    conflictCount: 0,
    pendingDeliveryCount: 0,
    resealRemainingBytes: 0n,
    publisher: { deviceId: 'dev-1', deviceLabel: 'Laptop', since: 1_700_000_000n, isCurrentDevice: true },
    mount: MOUNT,
    lastError: null,
    ...overrides,
  };
}

function snapshotWith(vaults: VaultSummary[], invitations: VaultInvitationSummary[] = []): VaultEngineSnapshot {
  return { lifecycle: 'running', activity: 'idle', condition: 'ready', vaults, invitations, lastError: null };
}

function fakeEngine(initial: VaultEngineSnapshot = snapshotWith([vaultSummary()])) {
  let current = initial;
  const listeners = new Set<(s: VaultEngineSnapshot) => void>();
  const recovery: VaultRecoveryPackage = {
    format: 'onyx-vault-recovery', version: 1, ncryptsec: 'ncryptsec1x', payload: { nonce: 'n', ciphertext: 'c' },
  };
  let deviceState: ReturnType<VaultEngine['deviceKeys']['getState']> = {
    enabled: false, allowIdentityFallback: false, announcedPubkey: null, retainedKeyCount: 0, current: null, retained: [],
  };
  const updateDevice = (patch: Partial<typeof deviceState>) => {
    deviceState = { ...deviceState, ...patch };
    current = { ...current, deviceKeys: deviceState };
    listeners.forEach(listener => listener(current));
  };
  const mocks = {
    deviceKeys: {
      getState: vi.fn(() => deviceState),
      setEnabled: vi.fn(async (enabled: boolean) => updateDevice({ enabled })),
      useIdentityFallback: vi.fn(async (allowIdentityFallback: boolean) => updateDevice({ allowIdentityFallback })),
      generate: vi.fn(async () => { updateDevice({ current: { pubkey: BOB, announced: false }, retainedKeyCount: 1 }); return BOB; }),
      import: vi.fn(async (_secret: string) => { updateDevice({ current: { pubkey: CAROL, announced: false }, retained: [BOB], retainedKeyCount: 2 }); return CAROL; }),
      announce: vi.fn(async () => updateDevice({ announcedPubkey: deviceState.current!.pubkey, current: { ...deviceState.current!, announced: true } })),
      observeRecipient: vi.fn(), approveRecipientKey: vi.fn(), resetRecipientPin: vi.fn(),
    },
    start: vi.fn<VaultEngine['start']>(async () => undefined),
    stop: vi.fn<VaultEngine['stop']>(async () => undefined),
    subscribe: vi.fn<VaultEngine['subscribe']>((listener) => {
      listeners.add(listener);
      listener(current);
      return () => { listeners.delete(listener); };
    }),
    updateNetworkDefaults: vi.fn<VaultEngine['updateNetworkDefaults']>(async () => undefined),
    create: vi.fn<VaultEngine['create']>(async () => VID),
    share: vi.fn<VaultEngine['share']>(async () => undefined),
    attach: vi.fn<VaultEngine['attach']>(async () => MOUNT),
    takeOverPublishing: vi.fn<VaultEngine['takeOverPublishing']>(async () => undefined),
    accept: vi.fn<VaultEngine['accept']>(async () => MOUNT),
    sync: vi.fn<VaultEngine['sync']>(async () => undefined),
    revoke: vi.fn<VaultEngine['revoke']>(async () => undefined),
    resolveConflicts: vi.fn<VaultEngine['resolveConflicts']>(async () => undefined),
    reseal: vi.fn<VaultEngine['reseal']>(async () => undefined),
    pause: vi.fn<VaultEngine['pause']>(async () => undefined),
    resume: vi.fn<VaultEngine['resume']>(async () => undefined),
    detach: vi.fn<VaultEngine['detach']>(async () => undefined),
    notifyFilesChanged: vi.fn<VaultEngine['notifyFilesChanged']>(() => undefined),
    refreshInbox: vi.fn<VaultEngine['refreshInbox']>(async () => undefined),
    repairInbox: vi.fn<VaultEngine['repairInbox']>(async () => undefined),
    exportRecovery: vi.fn<VaultEngine['exportRecovery']>(async () => recovery),
  };
  const engine: VaultEngine = mocks;
  return {
    engine,
    mocks,
    recovery,
    listenerCount: () => listeners.size,
    emit(next: VaultEngineSnapshot) {
      current = next;
      listeners.forEach((l) => l(next));
    },
  };
}

const resolveRecipient = vi.fn(async (input: string) => {
  const map: Record<string, string> = { bob: BOB, carol: CAROL, me: ME };
  const pubkey = map[input] ?? null;
  return pubkey
    ? { pubkey, type: 'hex' as const }
    : { pubkey: null, type: 'invalid' as const, error: 'Invalid format' };
});
const noProfiles = vi.fn(async () => null);

beforeEach(() => {
  clearProfileCache();
  fetchUserProfile.mockClear();
  fetchUserProfile.mockImplementation(async () => null);
  resolveRecipient.mockClear();
  Object.values(platformMock.vault).forEach((fn) => fn.mockClear());
});
afterEach(() => cleanup());

async function addRecipient(name: string) {
  const input = screen.getByLabelText('Recipient');
  fireEvent.input(input, { target: { value: name } });
  fireEvent.click(screen.getByRole('button', { name: 'Add' }));
  await waitFor(() => expect((input as HTMLInputElement).value).toBe(''));
}

// ---------------------------------------------------------------------------

describe('vault-ui helpers', () => {
  it('createVaultSnapshot follows engine snapshots and unsubscribes on dispose', () => {
    const fake = fakeEngine();
    createRoot((dispose) => {
      const snap = createVaultSnapshot(fake.engine);
      expect(snap().vaults).toHaveLength(1);
      fake.emit(snapshotWith([]));
      expect(snap().vaults).toHaveLength(0);
      expect(fake.listenerCount()).toBe(1);
      dispose();
    });
    expect(fake.listenerCount()).toBe(0);
  });

  it('caches failed profile lookups instead of refetching', async () => {
    await lookupProfile(BOB, ['wss://r']);
    await lookupProfile(BOB, ['wss://r']);
    expect(fetchUserProfile).toHaveBeenCalledTimes(1);
  });

  it('uses configured user and mounted-vault profile relays, falling back only when none exist', () => {
    const user = { readRelays: ['wss://user.example'], writeRelays: ['wss://user.example', 'wss://write.example'], readBlossom: [], writeBlossom: [] };
    const network = { ...user, readRelays: ['wss://vault.example'], writeRelays: ['wss://write.example'] };
    const state = { ...snapshotWith([vaultSummary({ network })]), networkDefaults: user };
    expect(defaultProfileRelays(state, VID)).toEqual(['wss://user.example', 'wss://write.example', 'wss://vault.example']);
    expect(defaultProfileRelays({ ...state, vaults: [vaultSummary({ network, mount: null })] })).toEqual(['wss://user.example', 'wss://write.example']);
    expect(defaultProfileRelays(snapshotWith([])).length).toBeGreaterThan(0);
    expect(defaultProfileRelays(undefined)).toEqual([]);
  });

  it('keeps profile caches scoped to the selected relay set', async () => {
    await lookupProfile(BOB, ['wss://first.example']);
    await lookupProfile(BOB, ['wss://second.example']);
    await lookupProfile(BOB, ['wss://second.example']);
    expect(fetchUserProfile.mock.calls).toEqual([[BOB, ['wss://first.example']], [BOB, ['wss://second.example']]]);
  });

  it('matches mounts by path component, not string prefix', () => {
    const mounts = [{ relativePath: 'Projects' }];
    expect(findMountForPath('Projects', mounts)?.isRoot).toBe(true);
    expect(findMountForPath('Projects/a.md', mounts)?.isRoot).toBe(false);
    expect(findMountForPath('Projects2/a.md', mounts)).toBeNull();
    expect(toNotebookRelative('C:\\NB\\Projects', 'c:/nb')).toBe('Projects');
    expect(toNotebookRelative('/elsewhere/x', '/nb')).toBeNull();
    expect(toNotebookRelative('/nb/Inbox/../Read/x', '/nb')).toBe('Read/x');
    expect(findMountForPath('Inbox/../Projects/a.md', mounts)?.mount).toBe(mounts[0]);
  });

  it('validates keep-both basenames', () => {
    expect(validateBasename('a/b')).not.toBeNull();
    expect(validateBasename('..')).not.toBeNull();
    expect(validateBasename('.onyx-vault-staging')).not.toBeNull();
    expect(validateBasename('same.md', 'same.md')).not.toBeNull();
    expect(validateBasename('notes (bob).md', 'notes.md')).toBeNull();
  });
});

describe('VaultShareDialog', () => {
  it('creates a vault and shares per capability with per-recipient outcomes and retry', async () => {
    const fake = fakeEngine();
    fake.mocks.share.mockImplementation(async (_id, _recipients, cap) => {
      if (cap === 'read') throw new VaultError('NETWORK', { operation: 'share' });
    });
    const onCreated = vi.fn();
    render(() => (
      <VaultShareDialog
        engine={fake.engine}
        folderPath="Projects"
        folderSummary={{ files: 3, folders: 1, bytes: 2048 }}
        localPubkey={ME}
        resolveRecipient={resolveRecipient}
        lookupProfile={noProfiles}
        onClose={() => undefined}
        onCreated={onCreated}
      />
    ));

    expect(screen.getByText(/not its parent folders/)).toBeTruthy();
    expect(screen.getByText(/3 file\(s\), 1 folder\(s\)/)).toBeTruthy();

    await addRecipient('bob');
    await addRecipient('carol');
    const bobSelect = screen.getAllByRole('combobox')[0] as HTMLSelectElement;
    fireEvent.change(bobSelect, { target: { value: 'write' } });

    fireEvent.click(screen.getByRole('button', { name: 'Create and share' }));
    await waitFor(() => expect(fake.mocks.share).toHaveBeenCalledTimes(2));

    expect(fake.mocks.create).toHaveBeenCalledWith('Projects', { label: 'Projects', network: undefined });
    expect(onCreated).toHaveBeenCalledWith(VID);
    expect(fake.mocks.share).toHaveBeenNthCalledWith(1, VID, [BOB], 'write', { enabled: false, allowIdentityFallback: undefined });
    expect(fake.mocks.share).toHaveBeenNthCalledWith(2, VID, [CAROL], 'read', { enabled: false, allowIdentityFallback: undefined });

    const carolRow = document.querySelector(`[data-pubkey="${CAROL}"]`) as HTMLElement;
    await waitFor(() => expect(carolRow.textContent).toContain('Vault service could not be reached'));
    const bobRow = document.querySelector(`[data-pubkey="${BOB}"]`) as HTMLElement;
    expect(bobRow.textContent).toContain('Invitation sent');

    fake.mocks.share.mockImplementation(async () => undefined);
    const retryButton = within(carolRow).getByRole('button', { name: 'Retry' }) as HTMLButtonElement;
    await waitFor(() => expect(retryButton.disabled).toBe(false));
    fireEvent.click(retryButton);
    await waitFor(() => expect(fake.mocks.share).toHaveBeenCalledTimes(3));
    expect(fake.mocks.share).toHaveBeenLastCalledWith(VID, [CAROL], 'read', expect.anything());
    expect(fake.mocks.create).toHaveBeenCalledTimes(1);
  });

  it.each(['read', 'write'] as const)('never uses an earlier delivery to mark a failed %s attempt delivered', async cap => {
    const fake = fakeEngine();
    fake.mocks.share.mockRejectedValue(new VaultError('NETWORK', { operation: 'share' }));
    const [deliveries, setDeliveries] = createSignal<VaultDeliveryView[]>([]);
    render(() => (
      <VaultShareDialog engine={fake.engine} folderPath="Projects" vaultId={VID}
        deliveries={deliveries()} resolveRecipient={resolveRecipient} lookupProfile={noProfiles}
        onClose={() => undefined} />
    ));
    await addRecipient('bob');
    await addRecipient('carol');
    fireEvent.click(screen.getByRole('button', { name: 'Share' }));
    const bobRow = () => document.querySelector(`[data-pubkey="${BOB}"]`) as HTMLElement;
    await waitFor(() => expect(bobRow().textContent).toContain('could not be reached'));
    setDeliveries([{ recipient: BOB, cap, acknowledged: ['wss://relay.one'], pending: [] }]);
    expect(bobRow().textContent).toContain('could not be reached');
    expect(bobRow().textContent).not.toContain('Delivered');
    expect(within(bobRow()).getByRole('button', { name: 'Retry' })).toBeTruthy();

    fake.mocks.share.mockResolvedValue(undefined);
    const retryFailed = screen.getByRole('button', { name: 'Retry failed' }) as HTMLButtonElement;
    await waitFor(() => expect(retryFailed.disabled).toBe(false));
    fireEvent.click(retryFailed);
    await waitFor(() => expect(fake.mocks.share).toHaveBeenLastCalledWith(VID, [BOB, CAROL], 'read', expect.anything()));
  });

  it('rejects the local identity and duplicates; passes explicit identity fallback', async () => {
    const fake = fakeEngine();
    render(() => (
      <VaultShareDialog
        engine={fake.engine}
        folderPath="Projects"
        vaultId={VID}
        localPubkey={ME}
        deliveryOptions={{ enabled: true }}
        resolveRecipient={resolveRecipient}
        lookupProfile={noProfiles}
        onClose={() => undefined}
      />
    ));
    const input = screen.getByLabelText('Recipient');
    fireEvent.input(input, { target: { value: 'me' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(await screen.findByText(/owner of this vault/)).toBeTruthy();

    await addRecipient('bob');
    fireEvent.input(input, { target: { value: 'bob' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(await screen.findByText(/already in the list/)).toBeTruthy();

    fireEvent.click(screen.getByLabelText(/deliver to their identity key instead/));
    fireEvent.click(screen.getByRole('button', { name: 'Share' }));
    await waitFor(() => expect(fake.mocks.share).toHaveBeenCalledWith(VID, [BOB], 'read', { enabled: true, allowIdentityFallback: true }));
    expect(fake.mocks.create).not.toHaveBeenCalled();
  });
});

describe('KeyFingerprint (SV-41)', () => {
  it('derives a stable hex bookend plus four words from a 256-word list, without emoji', () => {
    expect(FINGERPRINT_WORDS).toHaveLength(256);
    expect(new Set(FINGERPRINT_WORDS).size).toBe(256);
    const a = keyFingerprint(BOB), again = keyFingerprint(BOB.toUpperCase()), other = keyFingerprint(CAROL);
    expect(a).toEqual(again);
    expect(a.hex).toBe(`${'b'.repeat(8)}...${'b'.repeat(8)}`);
    expect(a.words.split(' ')).toHaveLength(4);
    expect(a.words).not.toBe(other.words);
    expect(/^[a-z ]+$/.test(a.words)).toBe(true);
    render(() => <KeyFingerprint pubkey={BOB} />);
    const el = screen.getByTestId('key-fingerprint');
    expect(el.textContent).toContain(a.hex);
    expect(el.textContent).toContain(a.words);
    expect(el.getAttribute('title')).toContain(BOB);
  });
});

describe('ShareDialog recipient binding (SV-38)', () => {
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

describe('VaultInvitationDialog', () => {
  const hints: VaultNetworkDefaults = {
    readRelays: ['wss://relay.one', 'wss://relay.two'],
    writeRelays: ['wss://relay.one'],
    readBlossom: ['https://blossom.one'],
    writeBlossom: [],
  };
  const invitation = (owner: Pubkey, extra: Partial<VaultInvitationSummary> = {}): VaultInvitationSummary => ({
    invitationId: INV, vaultId: VID, owner, cap: 'write', read: false, dismissed: false, accepted: false, ...extra,
  });

  it('requires trust and endpoint approval, then accepts with only approved endpoints', async () => {
    const fake = fakeEngine();
    const onAccepted = vi.fn();
    render(() => (
      <VaultInvitationDialog
        engine={fake.engine}
        invitation={invitation(OTHER_OWNER)}
        localPubkey={ME}
        endpointHints={hints}
        defaultFolder="Shared Vaults/11111111"
        lookupProfile={noProfiles}
        onClose={() => undefined}
        onAccepted={onAccepted}
      />
    ));
    expect(screen.getByText(VID)).toBeTruthy();
    expect(screen.getByText('Can propose edits')).toBeTruthy();
    expect(screen.queryByText('Attach at existing path')).toBeNull();
    // SV-41: the owner's fingerprint is always shown, and the copy states what is fetched before approval.
    expect(screen.getByTestId('key-fingerprint').textContent).toContain(keyFingerprint(OTHER_OWNER).words);
    expect(screen.queryByText(/Nothing is fetched until you approve/)).toBeNull();
    expect(screen.getByText(/Only the owner's profile name has been looked up/)).toBeTruthy();
    expect(document.querySelector('img')).toBeNull();

    const acceptButton = screen.getByRole('button', { name: 'Accept' }) as HTMLButtonElement;
    expect(acceptButton.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText('Use wss://relay.two'));
    fireEvent.click(screen.getByLabelText(/I approve connecting/));
    expect(acceptButton.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/I recognise this owner/));
    expect(acceptButton.disabled).toBe(false);

    fireEvent.click(acceptButton);
    await waitFor(() => expect(onAccepted).toHaveBeenCalledWith(MOUNT));
    expect(fake.mocks.accept).toHaveBeenCalledWith(INV, {
      relativePath: undefined,
      label: undefined,
      trustConfirmed: true,
      endpointsConfirmed: true,
      network: { readRelays: ['wss://relay.one'], writeRelays: ['wss://relay.one'], readBlossom: ['https://blossom.one'], writeBlossom: [] },
    });
  });

  it('shows the existing mount for a write upgrade instead of requiring an empty folder', async () => {
    const fake = fakeEngine(), inspectFolder = vi.fn(async () => 'non-empty' as const);
    render(() => <VaultInvitationDialog engine={fake.engine} invitation={invitation(OTHER_OWNER)} localPubkey={ME}
      endpointHints={hints} defaultFolder="Shared Vaults/default" existingMount={MOUNT}
      inspectFolder={inspectFolder} lookupProfile={noProfiles} onClose={() => undefined} />);
    expect(screen.getByText('Existing shared folder')).toBeTruthy();
    expect(screen.getByText(MOUNT.relativePath)).toBeTruthy();
    expect(screen.queryByText(/Must be new or empty/)).toBeNull();
    expect(screen.queryByLabelText('Folder')).toBeNull();
    const update = screen.getByRole('button', { name: 'Update access' }) as HTMLButtonElement;
    expect(update.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/I approve connecting/));
    fireEvent.click(screen.getByLabelText(/I recognise this owner/));
    fireEvent.click(update);
    await waitFor(() => expect(fake.mocks.accept).toHaveBeenCalledOnce());
    expect(fake.mocks.accept.mock.calls[0][1].relativePath).toBeUndefined();
    expect(inspectFolder).not.toHaveBeenCalled(); expect(fake.mocks.attach).not.toHaveBeenCalled();
  });

  it('blocks non-empty folders and shows engine errors', async () => {
    const fake = fakeEngine();
    fake.mocks.accept.mockRejectedValue(new VaultError('INCOMPLETE', { operation: 'accept' }));
    const inspectFolder = vi.fn(async (path: string) => (path === 'Busy' ? 'non-empty' as const : 'missing' as const));
    render(() => (
      <VaultInvitationDialog
        engine={fake.engine}
        invitation={invitation(OTHER_OWNER)}
        localPubkey={ME}
        endpointHints={hints}
        defaultFolder="Shared Vaults/11111111"
        inspectFolder={inspectFolder}
        lookupProfile={noProfiles}
        onClose={() => undefined}
      />
    ));
    fireEvent.click(screen.getByLabelText(/I approve connecting/));
    fireEvent.click(screen.getByLabelText(/I recognise this owner/));
    fireEvent.input(screen.getByLabelText('Folder'), { target: { value: 'Busy' } });
    fireEvent.click(screen.getByRole('button', { name: 'Accept' }));
    expect(await screen.findByText(/That folder is not empty/)).toBeTruthy();
    expect(fake.mocks.accept).not.toHaveBeenCalled();

    fireEvent.input(screen.getByLabelText('Folder'), { target: { value: 'Fresh' } });
    fireEvent.click(screen.getByRole('button', { name: 'Accept' }));
    expect(await screen.findByText('Required vault data is unavailable')).toBeTruthy();
    expect(fake.mocks.accept.mock.calls[0][1].relativePath).toBe('Fresh');
  });

  it('requires fresh approval of the complete recorded endpoint set when switching to attach', async () => {
    const fake = fakeEngine();
    render(() => <VaultInvitationDialog engine={fake.engine} invitation={invitation(ME)} localPubkey={ME}
      endpointHints={hints} defaultFolder="Shared Vaults/default" lookupProfile={noProfiles} onClose={() => undefined} />);
    fireEvent.click(screen.getByLabelText('Use wss://relay.two'));
    fireEvent.click(screen.getByLabelText(/I approve connecting/));
    fireEvent.click(screen.getByLabelText(/I created this vault on another device/));
    fireEvent.click(screen.getByLabelText('Attach at existing path'));
    const endpoint = screen.getByLabelText('Use wss://relay.two') as HTMLInputElement;
    expect(endpoint.checked).toBe(true);
    expect(endpoint.disabled).toBe(true);
    expect((screen.getByLabelText(/I approve connecting/) as HTMLInputElement).checked).toBe(false);
    fireEvent.input(screen.getByLabelText('Existing folder'), { target: { value: 'Projects' } });
    expect((screen.getByRole('button', { name: 'Attach' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/I approve connecting/));
    fireEvent.click(screen.getByRole('button', { name: 'Attach' }));
    await waitFor(() => expect(fake.mocks.attach).toHaveBeenCalledWith(INV, 'Projects'));
  });

  it('lets the engine allocate a collision-free default without inspecting a different path', async () => {
    const fake = fakeEngine(), inspectFolder = vi.fn().mockResolvedValue('non-empty');
    render(() => <VaultInvitationDialog engine={fake.engine} invitation={invitation(OTHER_OWNER)} localPubkey={ME}
      endpointHints={hints} defaultFolder="Shared Vaults/default" inspectFolder={inspectFolder}
      lookupProfile={noProfiles} onClose={() => undefined} />);
    fireEvent.click(screen.getByLabelText(/I approve connecting/));
    fireEvent.click(screen.getByLabelText(/I recognise this owner/));
    fireEvent.click(screen.getByRole('button', { name: 'Accept' }));
    await waitFor(() => expect(fake.mocks.accept).toHaveBeenCalledOnce());
    expect(fake.mocks.accept.mock.calls[0][1].relativePath).toBeUndefined();
    expect(inspectFolder).not.toHaveBeenCalled();
  });

  it('offers attach at an existing path when the owner is the local identity', async () => {
    const fake = fakeEngine();
    render(() => (
      <VaultInvitationDialog
        engine={fake.engine}
        invitation={invitation(ME)}
        localPubkey={ME}
        endpointHints={hints}
        defaultFolder="Shared Vaults/11111111"
        attachFolder="Projects"
        lookupProfile={noProfiles}
        onClose={() => undefined}
      />
    ));
    expect(screen.getByText(/Nothing is overwritten or deleted/)).toBeTruthy();
    expect(screen.getByText(/Legacy sync copies of this folder stay on your relays/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/I approve connecting/));
    fireEvent.click(screen.getByLabelText(/I created this vault on another device/));
    fireEvent.click(screen.getByRole('button', { name: 'Attach' }));
    await waitFor(() => expect(fake.mocks.attach).toHaveBeenCalledWith(INV, 'Projects'));
    expect(fake.mocks.accept).not.toHaveBeenCalled();
  });
});

describe('Pre-existing vaults never disappear (SEC-G)', () => {
  it('keeps vaults listed while the invitation inbox is at capacity and offers the repair action', () => {
    const state = { ...snapshotWith([vaultSummary({})]), condition: 'error' as const,
      inbox: { state: 'at-capacity' as const, durableIds: 3912, capacity: 3912, message: 'Invitation inbox at capacity — new invitations are not being ingested.' },
      unavailableVaults: [{ vaultId: 'ab'.repeat(32), state: 'needs-repair' as const, error: new VaultError('STORAGE').toDisplay() }] };
    const repair = vi.fn();
    render(() => <><SharedVaultEngineStatus snapshot={state} onRepairInbox={repair} /><SharedVaultEngineStatus snapshot={state} onOpen={() => undefined} /></>);
    expect(screen.getByText(/at capacity \(3912\/3912 invitation records\)/).textContent).toContain('Your shared vaults keep syncing');
    expect(screen.getByText(/abababababab — needs repair/).textContent).toContain('Its stored data is kept unchanged');
    const item = screen.getByRole('button', { name: /Shared vaults:/ });
    expect(item.classList.contains('shared-vault-status--attention')).toBe(true);
    expect(item.textContent).toContain(`${vaultSummary({}).label}:`);
    expect(item.textContent).toContain('abababababab: needs repair');
    fireEvent.click(screen.getByRole('button', { name: 'Repair invitation inbox' }));
    expect(repair).toHaveBeenCalledTimes(1);
  });
});

describe('Security consolidation UI', () => {
  it('uses the persisted re-seal total on the first render after a reload', () => {
    const fake = fakeEngine(snapshotWith([vaultSummary({ resealRemainingBytes: 25n, resealTotalBytes: 100n })]));
    render(() => <VaultPanel engine={fake.engine} vaultId={VID} lookupProfile={noProfiles} />);
    expect(screen.getByTestId('vault-reseal-status').textContent).toContain('(75% done)');
    expect((screen.getByLabelText('Re-seal progress') as HTMLProgressElement).value).toBe(75);
  });

  it.each(['verified', 'incomplete', 'unavailable'] as const)('surfaces %s history and checkpoint in the panel and status item', history => {
    const state = snapshotWith([vaultSummary({ freshness: 'unverified', history, checkpoint: { seq: 12n, epoch: 3n, grantsRev: 4n } })]);
    const fake = fakeEngine(state);
    render(() => <><VaultPanel engine={fake.engine} vaultId={VID} lookupProfile={noProfiles} /><SharedVaultEngineStatus snapshot={state} onOpen={() => undefined} /></>);
    const panel = screen.getByRole('region', { name: 'Shared vault' });
    const status = screen.getByRole('button', { name: /Shared vaults:/ });
    for (const element of [panel, status]) {
      expect(element.textContent).toContain('Freshness: unverified');
      expect(element.textContent).toContain(`History: ${history === 'verified' ? 'complete' : history}`);
      expect(element.textContent).toContain('Checkpoint: seq 12, epoch 3, grantsRev 4');
      if (history === 'incomplete') expect(element.textContent).toContain('behind-ring');
    }
  });

  it('makes quarantine visibly block auto-publish without hiding the repair hint', () => {
    const state = snapshotWith([vaultSummary({ provisional: true, freshness: 'verified', foldQuarantine: { reason: 'conflict-rows', rows: 10001, bytes: 9000 } })]);
    const fake = fakeEngine(state);
    render(() => <><VaultPanel engine={fake.engine} vaultId={VID} lookupProfile={noProfiles} /><SharedVaultEngineStatus snapshot={state} onOpen={() => undefined} /></>);
    expect(screen.getAllByText(/Auto-publish blocked; revoke or resolve to repair/)).toHaveLength(2);
    expect(screen.getByRole('button', { name: /Shared vaults:/ }).classList.contains('shared-vault-status--attention')).toBe(true);
    expect(screen.getByRole('button', { name: /Shared vaults:/ }).textContent).toContain('Freshness: verified');
    expect(screen.queryByText(/Your local changes are provisional until/)).toBeNull();
  });

  it.each(['unpinned', 'unapproved', 'changed', 'withdrawn', 'approved'] as const)('renders recipient key status %s with identity and pinned fingerprints', status => {
    const fake = fakeEngine();
    const observed = status === 'unpinned' ? null : { eventId: INV, createdAt: 1, encryptionKey: status === 'withdrawn' ? null : CAROL };
    const controller: DeviceKeySettingsController = {
      state: { enabled: false, allowIdentityFallback: false, current: null, retained: [], recipients: [{ identity: BOB, status, observed, approvedKey: status === 'approved' ? CAROL : null, observedAt: 1 }] },
      setEnabled: vi.fn(), setAllowIdentityFallback: vi.fn(), generate: vi.fn(), import: vi.fn(), announce: vi.fn(),
      approveRecipientKey: vi.fn(), resetRecipientPin: vi.fn(),
    };
    render(() => <SharedVaultSettings engine={fake.engine} deviceKeys={controller} />);
    const list = screen.getByRole('list', { name: 'Recipient device keys' });
    expect(within(list).getByText(status)).toBeTruthy();
    expect(list.textContent).toContain(keyFingerprint(BOB).words);
    if (observed?.encryptionKey) expect(list.textContent).toContain(keyFingerprint(CAROL).words);
    expect(within(list).queryByRole('button', { name: 'Approve this key' }) !== null).toBe(status === 'unapproved' || status === 'changed');
    expect(within(list).getByRole('button', { name: 'Reset pin' })).toBeTruthy();
  });

  it('approves the displayed identity/key pair and resets its pin', async () => {
    const fake = fakeEngine();
    const recipient = { identity: BOB, status: 'changed' as const, observed: { eventId: INV, createdAt: 1, encryptionKey: CAROL }, approvedKey: ME, observedAt: 1 };
    const approve = vi.fn(async () => recipient), reset = vi.fn(async () => undefined);
    const controller: DeviceKeySettingsController = {
      state: { enabled: true, allowIdentityFallback: false, current: null, retained: [], recipients: [recipient] },
      setEnabled: vi.fn(), setAllowIdentityFallback: vi.fn(), generate: vi.fn(), import: vi.fn(), announce: vi.fn(), approveRecipientKey: approve, resetRecipientPin: reset,
    };
    render(() => <SharedVaultSettings engine={fake.engine} deviceKeys={controller} />);
    fireEvent.click(screen.getByRole('button', { name: 'Approve this key' }));
    await waitFor(() => expect(approve).toHaveBeenCalledWith(BOB, CAROL));
    await waitFor(() => expect((screen.getByRole('button', { name: 'Reset pin' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Reset pin' }));
    await waitFor(() => expect(reset).toHaveBeenCalledWith(BOB));
  });

  it('shows per-delivery fallback notice and announcement evidence in the panel and share dialog', async () => {
    const deliveries = [
      { recipient: BOB, cap: 'read' as const, acknowledged: ['wss://relay.one'], pending: [], notice: 'key-changed' as const, evidence: 'stale' as const },
      { recipient: CAROL, cap: 'read' as const, acknowledged: [], pending: ['wss://relay.one'], notice: 'withdrawn' as const, evidence: 'current' as const },
    ];
    const fake = fakeEngine();
    render(() => <><VaultPanel engine={fake.engine} vaultId={VID} deliveries={deliveries} lookupProfile={noProfiles} />
      <VaultShareDialog engine={fake.engine} vaultId={VID} folderPath="Projects" deliveries={deliveries} resolveRecipient={resolveRecipient} lookupProfile={noProfiles} onClose={() => undefined} /></>);
    const panel = screen.getByRole('region', { name: 'Deliveries' });
    expect(panel.textContent).toContain('Identity-key fallback: key-changed');
    expect(panel.textContent).toContain('Announcement evidence: stale');
    const bob = document.querySelector(`[data-recipient="${BOB}"]`) as HTMLElement;
    const carol = document.querySelector(`[data-recipient="${CAROL}"]`) as HTMLElement;
    expect(bob.textContent).toContain('Identity-key fallback: key-changed');
    expect(bob.textContent).toContain('Announcement evidence: stale');
    expect(bob.textContent).not.toContain('withdrawn');
    expect(carol.textContent).toContain('Identity-key fallback: withdrawn');
    expect(carol.textContent).toContain('Announcement evidence: current');
    expect(carol.textContent).toContain('does not prove the key is still current');
  });

  it('shows and copies the recovery suggestion, policy and caveats', async () => {
    const request = { suggested: 'generated-high-entropy-passphrase', minimumLength: 24, logn: 18, notes: ['Stolen exports permit offline guessing.', 'Keep this file outside notebooks.'] };
    const [passphrase, setPassphrase] = createSignal('');
    const [confirmation, setConfirmation] = createSignal('');
    render(() => <><RecoveryPassphraseFields request={request} passphrase={passphrase()} confirmation={confirmation()} onPassphrase={setPassphrase} onConfirmation={setConfirmation} />
      <button disabled={!recoveryPassphraseValid(passphrase(), confirmation(), request)}>Encrypt</button></>);
    expect(screen.getByLabelText('Suggested high-entropy passphrase')).toHaveProperty('value', request.suggested);
    expect(screen.getByText(/scrypt log2\(N\): 18/)).toBeTruthy();
    for (const note of request.notes) expect(screen.getByText(note)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Encrypt' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.input(screen.getByLabelText('Passphrase', { exact: true }), { target: { value: 'short' } });
    fireEvent.input(screen.getByLabelText('Confirm passphrase'), { target: { value: 'short' } });
    expect((screen.getByRole('button', { name: 'Encrypt' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Copy suggested passphrase' }));
    await waitFor(() => expect(platformMock.clipboard.writeText).toHaveBeenCalledWith(request.suggested));
    fireEvent.click(screen.getByRole('button', { name: 'Use suggested passphrase' }));
    expect((screen.getByRole('button', { name: 'Encrypt' }) as HTMLButtonElement).disabled).toBe(false);
    expect(passphrase()).toBe(request.suggested);
    expect(confirmation()).toBe(request.suggested);
  });

  it('enforces the requested minimum in normalized Unicode code points, not UTF-16 units', () => {
    const request = { suggested: '', minimumLength: 12, logn: 17, notes: [] };
    const short = '\u{10400}'.repeat(6);
    expect(recoveryPassphraseValid(short, short, request)).toBe(false);
    expect(recoveryPassphraseValid('a'.repeat(12), 'a'.repeat(11), request)).toBe(false);
    expect(recoveryPassphraseValid('\ufb03'.repeat(4), '\ufb03'.repeat(4), request)).toBe(true);
  });
});

describe('VaultPanel', () => {
  const members = [
    { pubkey: ME, role: 'owner' as const },
    { pubkey: BOB, role: 'writer' as const },
    { pubkey: CAROL, role: 'reader' as const },
  ];

  it('SV-45: lists pending paths including deletions, distinguishes other writers, and shows truncation', () => {
    const fake = fakeEngine(snapshotWith([vaultSummary({ provisional: true, provisionalCount: 2001,
      provisionalPaths: ['Projects/edited.md', 'Projects/deleted.md'], provisionalOtherPaths: ['Projects/deleted.md'] })]));
    render(() => <VaultPanel engine={fake.engine} vaultId={VID} lookupProfile={noProfiles} />);
    const list = screen.getByRole('region', { name: 'Pending owner review' });
    expect(within(list).getByText('Projects/edited.md').closest('li')?.textContent).toContain('Your edit');
    expect(within(list).getByText('Projects/deleted.md').closest('li')?.textContent).toContain("Other writer's edit");
    expect(within(list).getByText('Showing 2 of 2001 paths.')).toBeTruthy();
    fake.emit(snapshotWith([vaultSummary()]));
    expect(screen.queryByRole('region', { name: 'Pending owner review' })).toBeNull();
  });

  it('looks up profiles only on the engine configured relay, including after settings change', async () => {
    const network = { readRelays: ['wss://configured.example'], writeRelays: ['wss://configured.example'], readBlossom: [], writeBlossom: [] };
    const state = { ...snapshotWith([vaultSummary()]), networkDefaults: network };
    const fake = fakeEngine(state);
    render(() => <VaultPanel engine={fake.engine} vaultId={VID} members={members} />);
    await waitFor(() => expect(fetchUserProfile).toHaveBeenCalledWith(BOB, ['wss://configured.example']));
    expect(fetchUserProfile.mock.calls.every(([, relays]) => relays.length === 1 && relays[0] === 'wss://configured.example')).toBe(true);
    fake.emit({ ...state, networkDefaults: { ...network, readRelays: ['wss://updated.example'], writeRelays: ['wss://updated.example'] } });
    await waitFor(() => expect(fetchUserProfile).toHaveBeenCalledWith(BOB, ['wss://updated.example']));
    expect(fetchUserProfile.mock.calls.flatMap(([, relays]) => relays)).not.toContain('wss://relay.damus.io');
  });

  it('shows observable state, members and informational readers; revokes after confirmation', async () => {
    const fake = fakeEngine(snapshotWith([vaultSummary({ conflictCount: 2, pendingDeliveryCount: 1 })]));
    render(() => (
      <VaultPanel
        engine={fake.engine}
        vaultId={VID}
        localPubkey={ME}
        members={members}
        regrantHeadroom={{ largestSealBytes: 60_000, remainingRevocations: 30 }}
        lookupProfile={noProfiles}
      />
    ));
    expect(screen.getByTestId('vault-engine-state').textContent).toBe('running / idle / ready');
    expect(screen.getByText('Readers (informational)')).toBeTruthy();
    expect(screen.getByTestId('vault-publisher').textContent).toContain('Laptop (this device)');
    expect(screen.getByTestId('vault-headroom').textContent).toContain('about 30 more revocation(s)');

    const carol = document.querySelector(`[data-pubkey="${CAROL}"]`) as HTMLElement;
    expect(within(carol).getByTestId('key-fingerprint').textContent).toContain(keyFingerprint(CAROL).hex);
    expect(screen.getAllByTestId('key-fingerprint')).toHaveLength(members.length);
    fireEvent.click(within(carol).getByRole('button', { name: /Revoke/ }));
    expect(screen.getByText(/does not retract anything they have already downloaded/)).toBeTruthy();
    // SV-43: the lazy-reseal caveat is stated plainly, and eager re-seal is offered right here.
    expect(screen.getByText(/has not changed since stays readable to .* until it is re-sealed/)).toBeTruthy();
    expect((screen.getByLabelText(/Re-seal everything now after revoking/) as HTMLInputElement).checked).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(fake.mocks.revoke).toHaveBeenCalledWith(VID, CAROL));
    expect(fake.mocks.reseal).not.toHaveBeenCalled();
    await screen.findByText(/Access revoked\. Content written before this revocation .* until re-seal completes/);
  });

  it('revokes and then re-seals everything eagerly when chosen in the confirmation (SV-43)', async () => {
    const fake = fakeEngine();
    const remaining = 3n * 1024n * 1024n;
    fake.mocks.revoke.mockImplementation(async () => {
      fake.emit(snapshotWith([vaultSummary({ resealRemainingBytes: remaining })]));
    });
    render(() => <VaultPanel engine={fake.engine} vaultId={VID} localPubkey={ME} members={members} lookupProfile={noProfiles} />);
    const bob = document.querySelector(`[data-pubkey="${BOB}"]`) as HTMLElement;
    fireEvent.click(within(bob).getByRole('button', { name: /Revoke/ }));
    fireEvent.click(screen.getByLabelText(/Re-seal everything now after revoking/));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(fake.mocks.reseal).toHaveBeenCalledWith(VID, remaining, 'eager'));
    expect(fake.mocks.revoke).toHaveBeenCalledWith(VID, BOB);
    expect(fake.mocks.revoke.mock.invocationCallOrder[0]).toBeLessThan(fake.mocks.reseal.mock.invocationCallOrder[0]);
    await screen.findByText('Access revoked and all content re-sealed under the current key.');
  });

  it('shows re-seal progress from the remaining bytes and a complete state at zero (SV-43)', async () => {
    const total = 40n * 1024n * 1024n;
    const fake = fakeEngine(snapshotWith([vaultSummary({ resealRemainingBytes: total })]));
    render(() => <VaultPanel engine={fake.engine} vaultId={VID} localPubkey={ME} members={members} lookupProfile={noProfiles} />);
    const status = () => screen.getByTestId('vault-reseal-status');
    expect(status().textContent).toContain('remaining');
    expect(status().textContent).toContain('(0% done)');
    expect(screen.getByText(/stays readable to removed members who kept their old keys/)).toBeTruthy();

    fake.emit(snapshotWith([vaultSummary({ resealRemainingBytes: total / 4n })]));
    expect(status().textContent).toContain('(75% done)');
    expect((screen.getByLabelText('Re-seal progress') as HTMLProgressElement).value).toBe(75);

    fake.emit(snapshotWith([vaultSummary({ resealRemainingBytes: 0n })]));
    expect(status().textContent).toContain('Complete. All content is sealed under the current key.');
    expect(screen.queryByLabelText('Re-seal progress')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Re-seal everything now' })).toBeNull();

    // The persisted total is preferred over the local observed peak.
    fake.emit(snapshotWith([vaultSummary({ resealRemainingBytes: 10n * 1024n * 1024n, resealTotalBytes: 100n * 1024n * 1024n })]));
    expect(status().textContent).toContain('(90% done)');
  });

  it('blocks revocation when regrant headroom is exhausted', () => {
    const fake = fakeEngine();
    render(() => (
      <VaultPanel engine={fake.engine} vaultId={VID} localPubkey={ME} members={members}
        regrantHeadroom={{ largestSealBytes: 65_535 }} lookupProfile={noProfiles} />
    ));
    expect(screen.getByText(/Revocation is blocked/)).toBeTruthy();
    const bob = document.querySelector(`[data-pubkey="${BOB}"]`) as HTMLElement;
    expect((within(bob).getByRole('button', { name: /Revoke/ }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('takes over publishing on a non-publishing owner device', async () => {
    const fake = fakeEngine(snapshotWith([vaultSummary({
      publisher: { deviceId: 'dev-2', deviceLabel: 'Desktop', since: 1_700_000_000n, isCurrentDevice: false },
    })]));
    render(() => <VaultPanel engine={fake.engine} vaultId={VID} localPubkey={ME} members={members} lookupProfile={noProfiles} />);
    expect(screen.queryByRole('button', { name: /Revoke/ })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Take over publishing on this device' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(fake.mocks.takeOverPublishing).toHaveBeenCalledWith(VID));
  });

  it('continues re-seal lazily, confirms eager re-seal, retries deliveries and pauses', async () => {
    const fake = fakeEngine(snapshotWith([vaultSummary({ resealRemainingBytes: 50n * 1024n * 1024n, pendingDeliveryCount: 1 })]));
    render(() => (
      <VaultPanel engine={fake.engine} vaultId={VID} localPubkey={ME} members={members}
        deliveries={[{ recipient: BOB, cap: 'write', acknowledged: [], pending: ['wss://relay.one'] }]}
        deliveryOptions={{ enabled: false }}
        lookupProfile={noProfiles} />
    ));
    const idle = () => waitFor(() => expect((screen.getByRole('button', { name: 'Sync now' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Continue re-seal' }));
    await waitFor(() => expect(fake.mocks.reseal).toHaveBeenCalledWith(VID, DEFAULT_RESEAL_BUDGET, 'lazy'));
    await idle();

    fireEvent.click(screen.getByRole('button', { name: 'Re-seal everything now' }));
    expect(fake.mocks.reseal).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(fake.mocks.reseal).toHaveBeenLastCalledWith(VID, 50n * 1024n * 1024n, 'eager'));
    await idle();

    fireEvent.click(screen.getByRole('button', { name: 'Retry deliveries' }));
    await waitFor(() => expect(fake.mocks.share).toHaveBeenCalledWith(VID, [BOB], 'write', { enabled: false }));
    await screen.findByText('Delivery retry started.');

    fireEvent.click(screen.getByRole('button', { name: 'Pause' }));
    await waitFor(() => expect(fake.mocks.pause).toHaveBeenCalledWith(VID));
  });

  it('requires acknowledgement before exporting recovery; detaches after confirmation', async () => {
    const fake = fakeEngine();
    const onRecoveryExported = vi.fn();
    const onDetached = vi.fn();
    render(() => (
      <VaultPanel engine={fake.engine} vaultId={VID} localPubkey={ME}
        onRecoveryExported={onRecoveryExported} onDetached={onDetached} lookupProfile={noProfiles} />
    ));
    fireEvent.click(screen.getByRole('button', { name: 'Export recovery...' }));
    const confirmButton = screen.getByRole('button', { name: 'Confirm' }) as HTMLButtonElement;
    expect(confirmButton.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/I understand/));
    fireEvent.click(confirmButton);
    await waitFor(() => expect(onRecoveryExported).toHaveBeenCalledWith(fake.recovery));
    await screen.findByText('Recovery package exported.');

    fireEvent.click(screen.getByRole('button', { name: 'Detach...' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(onDetached).toHaveBeenCalledWith(VID));
    expect(fake.mocks.detach).toHaveBeenCalledWith(VID);
  });

  it('refuses recovery export with IO when no verified saving workflow is supplied', async () => {
    const fake = fakeEngine();
    render(() => <VaultPanel engine={fake.engine} vaultId={VID} lookupProfile={noProfiles} />);
    fireEvent.click(screen.getByRole('button', { name: 'Export recovery...' }));
    expect(screen.getByText(/protected by your recovery passphrase/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/I understand/));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await screen.findByText('Vault file operation failed');
    expect(screen.queryByText('Recovery package exported.')).toBeNull();
  });

  it('awaits recovery saving and never reports an unsuccessful save as exported', async () => {
    const fake = fakeEngine();
    let rejectSave!: (error: Error) => void;
    const onRecoveryExported = vi.fn(() => new Promise<void>((_, reject) => { rejectSave = reject; }));
    render(() => <VaultPanel engine={fake.engine} vaultId={VID}
      onRecoveryExported={onRecoveryExported} lookupProfile={noProfiles} />);
    fireEvent.click(screen.getByRole('button', { name: 'Export recovery...' }));
    fireEvent.click(screen.getByLabelText(/I understand/));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(onRecoveryExported).toHaveBeenCalledOnce());
    expect(screen.queryByText('Recovery package exported.')).toBeNull();
    rejectSave(new Error('Save failed'));
    await screen.findByText('Vault file operation failed');
    expect(screen.queryByText('Recovery package exported.')).toBeNull();
  });

  it('surfaces action errors', async () => {
    const fake = fakeEngine();
    fake.mocks.sync.mockRejectedValue(new VaultError('NETWORK', { operation: 'sync' }));
    render(() => <VaultPanel engine={fake.engine} vaultId={VID} lookupProfile={noProfiles} />);
    fireEvent.click(screen.getByRole('button', { name: 'Sync now' }));
    expect((await screen.findByTestId('vault-action-error')).textContent).toBe('Vault service could not be reached');
  });
});

describe('VaultConflictsPanel', () => {
  const conflicts: VaultConflictView[] = [
    { conflictId: 'c-file', path: 'notes.md', kind: 'file', inView: true, inOther: true, writer: BOB, seq: 4n, alternatePath: '.onyx-vault-conflicts/c-file/notes.md' },
    { conflictId: 'c-dir', path: 'docs', kind: 'directory', inView: true, inOther: true, writer: BOB, seq: 4n },
    { conflictId: 'c-child', path: 'docs/a.md', kind: 'file', inView: true, inOther: true, writer: BOB, seq: 4n },
    { conflictId: 'c-del', path: 'gone.md', kind: 'file', inView: false, inOther: true, writer: CAROL, seq: 2n },
  ];

  it('limits deletion-only conflicts to applicable actions', () => {
    expect(availableActions(conflicts[3])).toEqual(['keep-view', 'use-other', 'delete']);
    expect(availableActions(conflicts[0])).toContain('manual-merge');
    expect(availableActions(conflicts[1])).not.toContain('manual-merge');
  });

  it('applies owner resolutions with folder supersession and validation', async () => {
    const fake = fakeEngine();
    const onOpenVersion = vi.fn();
    render(() => (
      <VaultConflictsPanel engine={fake.engine} vaultId={VID} conflicts={conflicts}
        onOpenVersion={onOpenVersion} lookupProfile={noProfiles} />
    ));
    expect(screen.getByText(/Deleted in the selected view/)).toBeTruthy();

    fireEvent.click(within(document.querySelector('[data-conflict-id="c-file"]') as HTMLElement).getByRole('button', { name: 'Open other version' }));
    expect(onOpenVersion).toHaveBeenCalledWith(conflicts[0]);

    fireEvent.change(screen.getByLabelText('Resolution for docs/a.md'), { target: { value: 'delete' } });
    fireEvent.change(screen.getByLabelText('Resolution for docs'), { target: { value: 'use-other' } });
    expect(screen.queryByLabelText('Resolution for docs/a.md')).toBeNull();
    expect(screen.getByText(/Covered by the choice for folder docs/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Resolution for notes.md'), { target: { value: 'keep-both' } });
    fireEvent.input(screen.getByLabelText('New name for notes.md'), { target: { value: 'bad/name' } });
    const apply = () => screen.getByRole('button', { name: /Apply/ }) as HTMLButtonElement;
    expect(apply().disabled).toBe(true);
    expect(screen.getByText(/cannot contain slashes/)).toBeTruthy();
    fireEvent.input(screen.getByLabelText('New name for notes.md'), { target: { value: 'notes (bob).md' } });

    fireEvent.change(screen.getByLabelText('Resolution for gone.md'), { target: { value: 'keep-view' } });
    expect(apply().disabled).toBe(false);
    fireEvent.click(apply());
    await waitFor(() => expect(fake.mocks.resolveConflicts).toHaveBeenCalledTimes(1));
    expect(fake.mocks.resolveConflicts).toHaveBeenCalledWith(VID, [
      { conflictId: 'c-file', action: 'keep-both', newBasename: 'notes (bob).md' },
      { conflictId: 'c-dir', action: 'use-other' },
      { conflictId: 'c-del', action: 'keep-view' },
    ]);
  });

  it('sends manual merges as bytes', async () => {
    const fake = fakeEngine();
    render(() => (
      <VaultConflictsPanel engine={fake.engine} vaultId={VID} conflicts={[conflicts[0]]}
        loadMergeText={async () => 'base text'} lookupProfile={noProfiles} />
    ));
    fireEvent.change(screen.getByLabelText('Resolution for notes.md'), { target: { value: 'manual-merge' } });
    const area = screen.getByLabelText('Merged content for notes.md') as HTMLTextAreaElement;
    await waitFor(() => expect(area.value).toBe('base text'));
    fireEvent.input(area, { target: { value: 'merged' } });
    fireEvent.click(screen.getByRole('button', { name: /Apply/ }));
    await waitFor(() => expect(fake.mocks.resolveConflicts).toHaveBeenCalled());
    const [[, set]] = fake.mocks.resolveConflicts.mock.calls;
    expect(set[0]).toMatchObject({ conflictId: 'c-file', action: 'manual-merge' });
    expect(new TextDecoder().decode((set[0] as { bytes: Uint8Array }).bytes)).toBe('merged');
  });

  it('opens versions that exist only in the other version', () => {
    const fake = fakeEngine();
    const onOpenVersion = vi.fn();
    const otherOnly = { ...conflicts[3], alternatePath: '.onyx-vault-conflicts/c-del/gone.md' };
    render(() => <VaultConflictsPanel engine={fake.engine} vaultId={VID} conflicts={[otherOnly]} onOpenVersion={onOpenVersion} lookupProfile={noProfiles} />);
    fireEvent.click(screen.getByRole('button', { name: 'Open other version' }));
    expect(onOpenVersion).toHaveBeenCalledWith(otherOnly);
  });

  it('gives members a read-only view', () => {
    const fake = fakeEngine(snapshotWith([vaultSummary({ authority: 'writer', owner: OTHER_OWNER, publisher: null })]));
    const onOpenVersion = vi.fn();
    render(() => <VaultConflictsPanel engine={fake.engine} vaultId={VID} conflicts={conflicts} onOpenVersion={onOpenVersion} lookupProfile={noProfiles} />);
    expect(screen.getByTestId('vault-conflicts-readonly')).toBeTruthy();
    expect(screen.queryAllByRole('combobox')).toHaveLength(0);
    expect(screen.queryByRole('button', { name: /Apply/ })).toBeNull();
    expect(screen.getAllByRole('button', { name: 'Open other version' }).length).toBeGreaterThan(0);
  });
});

describe('SharedVaultSettings', () => {
  it('shows authenticated VSP endpoints as ready, not degraded or excluded', () => {
    const fake = fakeEngine({ ...snapshotWith([]), endpoints: [
      { kind: 'relay', url: 'wss://vault.example/', status: 'authenticated', message: 'Authenticated — available for shared vaults.', service: 'private vault service' },
      { kind: 'blossom', url: 'https://vault.example/', status: 'authenticated', message: 'Authenticated — available for shared vaults.' },
    ] });
    render(() => <SharedVaultSettings engine={fake.engine} />);
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('status').textContent).toBe('Shared vaults are ready.');
    expect(screen.getByText(/private vault service/).textContent).toContain('wss://vault.example/');
    expect(screen.queryByText(/Some endpoints are not used/)).toBeNull();
  });
  it('shows engine failure and endpoint-specific diagnostics with a working retry', () => {
    const fake = fakeEngine({ ...snapshotWith([]), lifecycle: 'stopped', condition: 'blocked', lastError: {
      code: 'UNSUPPORTED', operation: 'start', retryable: true, message: 'No usable Blossom server. Replace https://private.example/.',
    }, endpoints: [{ kind: 'blossom', url: 'https://private.example/', status: 'unsupported', message: 'Not allowlisted — ask the operator; not used for shared vaults.' }] });
    const retry = vi.fn();
    render(() => <SharedVaultSettings engine={fake.engine} onRetry={retry} />);
    expect(screen.getByRole('alert').textContent).toContain('No usable Blossom server');
    expect(screen.getByText(/Not allowlisted — ask the operator/).textContent).toContain('https://private.example/');
    fireEvent.click(screen.getByRole('button', { name: 'Retry shared vaults' }));
    expect(retry).toHaveBeenCalledOnce();
    fake.emit({ ...snapshotWith([]), endpoints: [{ kind: 'relay', url: 'wss://private.example/', status: 'unsupported', message: 'Not allowlisted — ask the operator; not used for shared vaults.' }] });
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('status').textContent).toContain('healthy services remain available');
    expect(screen.queryByRole('button', { name: 'Retry shared vaults' })).toBeNull();
  });

  function controller(): DeviceKeySettingsController & { [k: string]: unknown } {
    return {
      state: { enabled: true, allowIdentityFallback: false, current: { pubkey: BOB, announced: false }, retained: [CAROL] },
      setEnabled: vi.fn(),
      setAllowIdentityFallback: vi.fn(),
      generate: vi.fn(async () => BOB),
      import: vi.fn(async () => BOB),
      announce: vi.fn(async () => undefined),
    };
  }

  it('lists mounts with per-vault endpoints and controls', async () => {
    const fake = fakeEngine(snapshotWith([vaultSummary({ enabled: false, conflictCount: 1 })]));
    const onManageVault = vi.fn();
    render(() => (
      <SharedVaultSettings engine={fake.engine} onManageVault={onManageVault}
        networks={{ [VID]: { readRelays: ['wss://relay.one'], writeRelays: [], readBlossom: ['https://b.one'], writeBlossom: [] } }} />
    ));
    expect(screen.getByText('wss://relay.one')).toBeTruthy();
    expect(screen.getByText('1 conflict(s)')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Manage' }));
    expect(onManageVault).toHaveBeenCalledWith(VID);
    fireEvent.click(screen.getByRole('button', { name: 'Resume' }));
    await waitFor(() => expect(fake.mocks.resume).toHaveBeenCalledWith(VID));
  });

  it('drives the public device-key controller and renders updated snapshots', async () => {
    const fake = fakeEngine();
    const [snapshot, setSnapshot] = createSignal<VaultEngineSnapshot>();
    fake.engine.subscribe(setSnapshot);
    const keys = fake.engine.deviceKeys;
    render(() => <SharedVaultSettings engine={fake.engine} snapshot={snapshot()} deviceKeys={{
      get state() { return snapshot()?.deviceKeys ?? keys.getState(); },
      setEnabled: keys.setEnabled, setAllowIdentityFallback: keys.useIdentityFallback,
      generate: keys.generate, import: keys.import, announce: keys.announce,
    }} />);
    expect(screen.queryByRole('button', { name: 'Generate key' })).toBeNull();
    fireEvent.click(screen.getByLabelText('Use device keys for vault invitations'));
    await waitFor(() => expect(keys.setEnabled).toHaveBeenCalledWith(true));
    fireEvent.click(await screen.findByRole('button', { name: 'Generate key' }));
    await screen.findByText(/Device key generated/);
    expect(screen.getByTestId('device-key-current').textContent).toContain('Not announced');
    fake.mocks.deviceKeys.announce.mockRejectedValueOnce(new Error('Announcement refused'));
    fireEvent.click(screen.getByRole('button', { name: 'Announce' }));
    await screen.findByRole('alert');
    expect(screen.getByTestId('device-key-current').textContent).toContain('Not announced');
    fireEvent.click(screen.getByRole('button', { name: 'Announce' }));
    await screen.findByText('Device key announced.');
    expect(screen.getByTestId('device-key-current').textContent).not.toContain('Not announced');
    const input = screen.getByLabelText('Import device key') as HTMLInputElement;
    fireEvent.input(input, { target: { value: 'nsec1local' } });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    await screen.findByText('Device key imported.');
    expect(keys.import).toHaveBeenCalledWith('nsec1local');
    expect(input.value).toBe('');
    expect(screen.getByText(/1 kept to open older invitations/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/deliver to their identity key/));
    await waitFor(() => expect(keys.useIdentityFallback).toHaveBeenCalledWith(true));
    fireEvent.click(screen.getByLabelText('Use device keys for vault invitations'));
    await waitFor(() => expect(keys.setEnabled).toHaveBeenLastCalledWith(false));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Generate new key' })).toBeNull());
  });

  it('generates, imports and announces device keys; fallback is explicit', async () => {
    const fake = fakeEngine();
    const dk = controller();
    render(() => <SharedVaultSettings engine={fake.engine} deviceKeys={dk} />);
    expect(screen.getByText('Experimental')).toBeTruthy();
    expect(screen.getByTestId('device-key-current').textContent).toContain('Not announced');
    expect(screen.getByText(/never deleted automatically/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Announce' }));
    await waitFor(() => expect(dk.announce).toHaveBeenCalled());
    await screen.findByText('Device key announced.');
    fireEvent.click(screen.getByRole('button', { name: 'Generate new key' }));
    await waitFor(() => expect(dk.generate).toHaveBeenCalled());
    await screen.findByText(/Device key generated/);

    const importInput = screen.getByLabelText('Import device key') as HTMLInputElement;
    fireEvent.input(importInput, { target: { value: 'nsec1secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    await waitFor(() => expect(dk.import).toHaveBeenCalledWith('nsec1secret'));
    expect(importInput.value).toBe('');
    await screen.findByText('Device key imported.');

    fireEvent.click(screen.getByLabelText(/deliver to their identity key/));
    await waitFor(() => expect(dk.setAllowIdentityFallback).toHaveBeenCalledWith(true));
  });
});

describe('NotificationsPanel vault invitations', () => {
  const invitations: VaultInvitationSummary[] = [
    { invitationId: INV, vaultId: VID, owner: OTHER_OWNER, cap: 'read', read: false, dismissed: false, accepted: false },
    { invitationId: 'f'.repeat(64) as EventId, vaultId: VID, owner: BOB, cap: 'write', read: false, dismissed: true, accepted: false },
  ];

  it('renders a distinct group counted in unread, and opens previews', async () => {
    const onPreview = vi.fn();
    const [visibleInvitations, setVisibleInvitations] = createSignal(invitations);
    render(() => (
      <NotificationsPanel sharedDocuments={[]} isLoading={false} onPreview={() => undefined}
        onRefresh={() => undefined} onClose={() => undefined}
        vaultInvitations={visibleInvitations()} onPreviewVaultInvitation={onPreview} profileRelays={['wss://configured.example']} />
    ));
    expect(screen.getByText('Vault invitations')).toBeTruthy();
    expect(screen.queryByText('Nothing shared with you yet')).toBeNull();
    expect(document.querySelector('.notifications-badge')?.textContent).toBe('1');
    expect(document.querySelectorAll('.vault-invitation')).toHaveLength(1);
    fireEvent.click(document.querySelector('.vault-invitation') as HTMLElement);
    expect(onPreview).toHaveBeenCalledWith(invitations[0]);

    await waitFor(() => expect(fetchUserProfile).toHaveBeenCalledTimes(1));
    await vi.mocked(fetchUserProfile).mock.results[0].value;
    setVisibleInvitations([...invitations]);
    await Promise.resolve();
    expect(fetchUserProfile).toHaveBeenCalledTimes(1);
  });

  it('shows the empty state when nothing is visible', () => {
    render(() => (
      <NotificationsPanel sharedDocuments={[]} isLoading={false} onPreview={() => undefined}
        onRefresh={() => undefined} onClose={() => undefined} vaultInvitations={[invitations[1]]} />
    ));
    expect(screen.getByText('Nothing shared with you yet')).toBeTruthy();
  });

  it('never renders a remote avatar for an unaccepted invitation until the user asks (SV-41)', async () => {
    fetchUserProfile.mockImplementation(async () => ({ name: 'Mallory', picture: 'https://avatar.example/mallory.png' }));
    const onPreview = vi.fn();
    render(() => (
      <NotificationsPanel sharedDocuments={[]} isLoading={false} onPreview={() => undefined}
        onRefresh={() => undefined} onClose={() => undefined} vaultInvitations={[invitations[0]]}
        onPreviewVaultInvitation={onPreview} profileRelays={['wss://configured.example']} />
    ));
    await screen.findByText('Mallory');
    const item = document.querySelector('.vault-invitation') as HTMLElement;
    expect(item.querySelector('img')).toBeNull();
    expect(within(item).getByTestId('key-fingerprint').textContent).toContain(keyFingerprint(OTHER_OWNER).hex);

    fireEvent.click(within(item).getByRole('button', { name: /Load avatar/ }));
    expect(onPreview).not.toHaveBeenCalled();
    expect(item.querySelector('img')?.getAttribute('src')).toBe('https://avatar.example/mallory.png');
  });

  it('shows the avatar directly for an invitation that has been accepted', async () => {
    fetchUserProfile.mockImplementation(async () => ({ name: 'Mallory', picture: 'https://avatar.example/mallory.png' }));
    render(() => (
      <NotificationsPanel sharedDocuments={[]} isLoading={false} onPreview={() => undefined}
        onRefresh={() => undefined} onClose={() => undefined} vaultInvitations={[{ ...invitations[0], accepted: true }]}
        profileRelays={['wss://configured.example']} />
    ));
    await screen.findByText('Mallory');
    expect(document.querySelector('.vault-invitation img')?.getAttribute('src')).toBe('https://avatar.example/mallory.png');
    expect(screen.queryByRole('button', { name: /Load avatar/ })).toBeNull();
  });
});

describe('Sidebar shared vault integration', () => {
  const tree: FileEntry[] = [
    {
      name: 'Projects', path: '/nb/Projects', isDirectory: true, children: [
        { name: 'plan.md', path: '/nb/Projects/plan.md', isDirectory: false },
        { name: '.onyx-vault-conflicts', path: '/nb/Projects/.onyx-vault-conflicts', isDirectory: true, children: [] },
      ],
    },
    { name: 'Inbox', path: '/nb/Inbox', isDirectory: true, children: [] },
    { name: 'Read', path: '/nb/Read', isDirectory: true, children: [] },
    { name: 'Outer', path: '/nb/Outer', isDirectory: true, children: [] },
    { name: '.onyx-vault-staging', path: '/nb/.onyx-vault-staging', isDirectory: true, children: [] },
  ];
  const mounts: SharedVaultMountInfo[] = [
    { vaultId: VID, relativePath: 'Projects', label: 'Projects', authority: 'owner', provisional: false, provisionalCount: 0, provisionalPaths: [], provisionalOtherPaths: [], enabled: true, conflictCount: 2 },
    { vaultId: '2'.repeat(64) as VaultId, relativePath: 'Read', label: 'Read', authority: 'reader', provisional: true, provisionalCount: 1, provisionalPaths: ['Read/deleted.md'], provisionalOtherPaths: [], enabled: true, conflictCount: 0 },
    { vaultId: '3'.repeat(64) as VaultId, relativePath: 'Outer/Inner', label: 'Inner', authority: 'writer', provisional: false, provisionalCount: 0, provisionalPaths: [], provisionalOtherPaths: [], enabled: true, conflictCount: 0 },
  ];

  function renderSidebar(extra: Record<string, unknown> = {}, listing = tree) {
    platformMock.vault.list.mockResolvedValue(listing);
    const handlers = {
      onCreateSharedVault: vi.fn(),
      onAttachSharedVault: vi.fn(),
      onManageSharedVault: vi.fn(),
      onSyncSharedVault: vi.fn(),
    };
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
        sharedVaultMounts={mounts}
        {...handlers}
        {...extra}
      />
    ));
    return handlers;
  }

  const item = (name: string) => screen.getByText(name).closest('.file-tree-item') as HTMLElement;

  it('hides reserved artifacts and shows root and inherited badges', async () => {
    renderSidebar();
    await screen.findByText('Projects');
    expect(screen.queryByText('.onyx-vault-conflicts')).toBeNull();
    expect(screen.queryByText('.onyx-vault-staging')).toBeNull();
    expect(item('Projects').getAttribute('data-vault-root')).toBe(VID);
    expect(within(item('Projects')).getByText('Vault')).toBeTruthy();
    expect(within(item('Projects')).getByText('2')).toBeTruthy();
    expect(within(item('Read')).getByText('Read-only')).toBeTruthy();
    expect(within(item('Read')).getByText('1 pending owner review')).toBeTruthy();
    expect(item('Inbox').querySelector('.vault-badge')).toBeNull();
  });

  it('SV-45: badges only edited rows, counts their folder, preserves read-only inheritance and updates on coverage', async () => {
    const entries: FileEntry[] = [{ name: 'Read', path: '/nb/Read', isDirectory: true, children: [
      { name: 'edited', path: '/nb/Read/edited', isDirectory: true, children: [
        { name: 'own.md', path: '/nb/Read/edited/own.md', isDirectory: false },
        { name: 'other.md', path: '/nb/Read/edited/other.md', isDirectory: false },
        { name: 'unchanged.md', path: '/nb/Read/edited/unchanged.md', isDirectory: false },
      ] },
      { name: 'remote', path: '/nb/Read/remote', isDirectory: true, children: [] },
      { name: 'clean', path: '/nb/Read/clean', isDirectory: true, children: [] },
    ] }];
    const pending = { ...mounts[1], provisionalCount: 4,
      provisionalPaths: ['Read/edited/own.md', 'Read/edited/other.md', 'Read/deleted.md', 'Read/remote/deleted.md'],
      provisionalOtherPaths: ['Read/edited/other.md', 'Read/remote/deleted.md'] };
    const [current, setCurrent] = createSignal<readonly SharedVaultMountInfo[]>([pending]);
    renderSidebar({ get sharedVaultMounts() { return current(); }, expandedFolders: new Set(['/nb/Read', '/nb/Read/edited']) }, entries);
    await screen.findByText('own');
    expect(within(item('Read')).getByText('4 pending owner review')).toBeTruthy();
    expect(within(item('remote')).getByText('1 pending owner review').className).toContain('provisional-other');
    expect(within(item('edited')).getByText('2 provisional')).toBeTruthy();
    expect(within(item('own')).getByText('Provisional')).toBeTruthy();
    expect(within(item('other')).getByText('Pending owner review').className).toContain('provisional-other');
    for (const name of ['clean', 'unchanged']) expect(item(name).querySelector('.vault-badge--provisional')).toBeNull();
    for (const name of ['own', 'other', 'unchanged']) expect(within(item(name)).getByText('Read-only')).toBeTruthy();
    setCurrent([{ ...pending, provisional: false, provisionalCount: 0, provisionalPaths: [], provisionalOtherPaths: [] }]);
    await waitFor(() => expect(screen.queryByText('4 pending owner review')).toBeNull());
    expect(document.querySelector('.vault-badge--provisional')).toBeNull();
    expect(document.querySelector('.vault-badge--provisional-other')).toBeNull();
  });

  it('offers create/attach on unmanaged folders and manage/sync on managed ones', async () => {
    const handlers = renderSidebar();
    await screen.findByText('Inbox');
    fireEvent.contextMenu(item('Inbox'));
    fireEvent.click(screen.getByText('Share folder as vault...'));
    expect(handlers.onCreateSharedVault).toHaveBeenCalledWith('Inbox');

    fireEvent.contextMenu(item('Inbox'));
    fireEvent.click(screen.getByText('Attach existing vault...'));
    expect(handlers.onAttachSharedVault).toHaveBeenCalledWith('Inbox');

    fireEvent.contextMenu(item('Outer'));
    expect(screen.queryByText('Share folder as vault...')).toBeNull();

    fireEvent.contextMenu(item('Projects'));
    expect(screen.queryByText('Share folder as vault...')).toBeNull();
    fireEvent.click(screen.getByText('Sync shared vault'));
    expect(handlers.onSyncSharedVault).toHaveBeenCalledWith(VID);
    fireEvent.contextMenu(item('Projects'));
    fireEvent.click(screen.getByText('Manage shared vault'));
    expect(handlers.onManageSharedVault).toHaveBeenCalledWith(VID);
  });

  it('blocks rename and delete of managed roots and their ancestors', async () => {
    renderSidebar();
    await screen.findByText('Projects');
    fireEvent.contextMenu(item('Projects'));
    fireEvent.click(screen.getByText('Delete'));
    expect(screen.getByRole('alert').textContent).toContain('Detach the vault before deleting it');
    expect(screen.queryByText(/This will permanently delete/)).toBeNull();

    fireEvent.contextMenu(item('Projects'));
    fireEvent.click(screen.getByText('Rename'));
    expect(document.querySelector('.rename-input')).toBeNull();

    fireEvent.contextMenu(item('Outer'));
    fireEvent.click(screen.getByText('Delete'));
    expect(screen.getByRole('alert').textContent).toContain('contains a shared vault');
    expect(platformMock.vault.remove).not.toHaveBeenCalled();
  });

  it('blocks creating inside read-only vaults and honours canMutatePath', async () => {
    const canMutatePath = vi.fn((path: string) => path !== 'Projects/plan.md');
    renderSidebar({ canMutatePath });
    await screen.findByText('Read');
    fireEvent.contextMenu(item('Read'));
    fireEvent.click(screen.getByText('New note'));
    expect(screen.getByRole('alert').textContent).toContain('read-only');
    expect(document.querySelector('.new-item')).toBeNull();

    fireEvent.contextMenu(item('plan'));
    fireEvent.click(screen.getByText('Delete'));
    expect(canMutatePath).toHaveBeenCalledWith('Projects/plan.md', 'delete');
    expect(screen.queryByText(/This will permanently delete/)).toBeNull();

    fireEvent.contextMenu(item('Inbox'));
    fireEvent.click(screen.getByText('Delete'));
    expect(screen.getByText(/This will permanently delete/)).toBeTruthy();
  });

  it('rechecks the final destination when a new name traverses into a read-only vault', async () => {
    renderSidebar({ expandedFolders: new Set(['/nb/Inbox']) });
    await screen.findByText('Inbox');
    fireEvent.contextMenu(item('Inbox'));
    fireEvent.click(screen.getByText('New note'));
    const input = document.querySelector('.new-item input') as HTMLInputElement;
    fireEvent.input(input, { target: { value: '../Read/evil' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('read-only'));
    expect(platformMock.vault.createFile).not.toHaveBeenCalled();
  });

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
      const handlers = renderSidebar({
        onFileSelect,
        get expandedFolders() { return expanded(); },
        onExpandedFoldersChange: setExpanded,
      });
      await screen.findByText('Inbox');

      controlClick(item('plan'));
      expect(document.querySelector('.context-menu')).not.toBeNull();
      expect(onFileSelect).not.toHaveBeenCalled();

      controlClick(item('Inbox'));
      expect(document.querySelector('.context-menu')).not.toBeNull();
      clickItem('Share folder as vault...');
      expect(handlers.onCreateSharedVault).toHaveBeenCalledWith('Inbox');
      expect(document.querySelector('.context-menu')).toBeNull();

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
      const handlers = renderSidebar();
      await screen.findByText('Inbox');
      const init = { button: 0, ctrlKey: true, clientX: 20, clientY: 20 };
      press(item('Inbox'), init);
      fireEvent.contextMenu(item('Inbox'), init);
      const share = screen.getByText('Share folder as vault...');
      fireEvent.mouseUp(share, { ...init, clientY: 80 });
      // WebKit targets the click at the common ancestor of the row and the item.
      fireEvent.click(document.querySelector('.sidebar') as HTMLElement, { ...init, clientY: 80 });
      expect(handlers.onCreateSharedVault).toHaveBeenCalledTimes(1);
      expect(handlers.onCreateSharedVault).toHaveBeenCalledWith('Inbox');
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
