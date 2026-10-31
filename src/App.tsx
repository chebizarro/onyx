import { Component, createSignal, createEffect, createResource, on, untrack, For, Show, onMount, onCleanup, lazy } from 'solid-js';
import Sidebar from './components/Sidebar';
import Editor from './components/Editor';
import QuickSwitcher from './components/QuickSwitcher';
import CommandPalette from './components/CommandPalette';
import SearchPanel from './components/SearchPanel';
// Lazy-load heavy panels so vis-network, xterm, jszip, and the office/PDF
// viewers stay out of the startup bundle — they all render behind <Show>.
const OpenCodePanel = lazy(() => import('./components/OpenCodePanel'));
import OpenClawChat from './components/OpenClawChat';
import CustomProviderChat from './components/CustomProviderChat';
const Settings = lazy(() => import('./components/Settings'));
const GraphView = lazy(() => import('./components/GraphView'));
import OutlinePanel from './components/OutlinePanel';
import BacklinksPanel from './components/BacklinksPanel';
import PropertiesPanel from './components/PropertiesPanel';
import ShareDialog from './components/ShareDialog';
import NotificationsPanel from './components/NotificationsPanel';
import SharedDocPreview from './components/SharedDocPreview';
import SentSharesPanel from './components/SentSharesPanel';
import VaultShareDialog from './components/VaultShareDialog';
import VaultInvitationDialog from './components/VaultInvitationDialog';
import VaultPanel from './components/VaultPanel';
import VaultConflictsPanel from './components/VaultConflictsPanel';
import SharedVaultSettings from './components/SharedVaultSettings';
import RecoveryPassphraseFields, { recoveryPassphraseValid } from './components/RecoveryPassphraseFields';
import SharedVaultEngineStatus from './components/SharedVaultEngineStatus';
import { EMPTY_VAULT_SNAPSHOT, defaultProfileRelays, sharedVaultMountsFromSnapshot, type VaultPathOperation } from './components/vault-ui';
import './components/vault.css';
import FileInfoDialog from './components/FileInfoDialog';
import PostToNostrDialog from './components/PostToNostrDialog';
const DocxViewer = lazy(() => import('./components/DocxViewer'));
const XlsxViewer = lazy(() => import('./components/XlsxViewer'));
const PdfViewer = lazy(() => import('./components/PdfViewer'));
const PptxViewer = lazy(() => import('./components/PptxViewer'));
import Onboarding, { type OnboardingResult } from './components/Onboarding';
import UnlockDialog from './components/UnlockDialog';
import { MobileHeader, MobileNav, MobileDrawer, type MobileNavTab } from './components/mobile';
import { initPlatform, usePlatformInfo, isWeb } from './lib/platform';
import { getOpenClawToken } from './lib/ai-credentials';
import { impactLight, impactMedium, notificationSuccess, notificationError } from './lib/haptics';
import { platform } from '@platform';
import { getSyncEngine, getCurrentLogin, getCurrentLoginWithAuth, calculateChecksum, DEFAULT_SYNC_CONFIG } from './lib/nostr';
import { getVaultEngine, type VaultEngine, type VaultEngineSnapshot, type VaultEditorBarrier, type VaultRecoveryPassphraseRequest } from './lib/vault/engine-api';
import { createManagedPathResolver, isManagedPath, intersectsManagedMount } from './lib/vault/legacy-exclusion';
import { VaultError } from './lib/vault/errors';
import { hashAddress, hex32 } from './lib/vault/crypto';
import type { Address, EventId, MountRegistry, Pubkey, VaultId } from './lib/vault/types';
import { createSignerFromLogin, getSignerFromStoredLogin } from './lib/nostr/signer';
import { sanitizeFilePath } from './lib/security';
import { buildNoteIndex, resolveWikilink, NoteIndex, NoteGraph, buildNoteGraphFromContents, readContentsParallel } from './lib/editor/note-index';
import { openDailyNote, loadDailyNotesConfig } from './lib/daily-notes';
import { listTemplates, getTemplateContent, createNoteFromTemplate, loadTemplatesConfig, type TemplateInfo } from './lib/templates';
import { HeadingInfo } from './lib/editor/heading-plugin';
import { AssetIndex, buildAssetIndex } from './lib/editor/asset-index';
import type { SharedDocument, SentShare, Vault } from './lib/nostr/types';

type FileType = 'markdown' | 'image' | 'pdf' | 'docx' | 'xlsx' | 'pptx';

const IMAGE_EXTENSIONS = new Set(['avif', 'bmp', 'gif', 'jpeg', 'jpg', 'png', 'svg', 'webp']);
const DOCUMENT_TYPE_MAP: Record<string, FileType> = {
  pdf: 'pdf', docx: 'docx', xlsx: 'xlsx', pptx: 'pptx',
};

function getFileType(path: string): FileType {
  const ext = path.split('.').pop()?.toLowerCase() || '';
  if (IMAGE_EXTENSIONS.has(ext)) return 'image';
  if (ext in DOCUMENT_TYPE_MAP) return DOCUMENT_TYPE_MAP[ext];
  return 'markdown';
}

interface Tab {
  path: string;
  name: string;
  content: string;
  isDirty: boolean;
  fileType: FileType;
}

type SidebarView = 'files' | 'search' | 'bookmarks';

// Session state type for localStorage persistence
interface SessionState {
  tabs: { path: string; name: string }[];  // Don't store content, reload from disk
  activeTabIndex: number;
  sidebarWidth: number;
  sidebarCollapsed: boolean;
  sidebarView: SidebarView;
  expandedFolders: string[];
}

const App: Component = () => {
  // Load saved session state
  const savedSession = (): SessionState | null => {
    try {
      const stored = localStorage.getItem('session_state');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  };
  const session = savedSession();

  const [vaultPath, setVaultPath] = createSignal<string | null>(null);

  // Extend the plugin-fs scope whenever the vault path changes.
  // This grants the webview's fs plugin read/write access to the user-chosen
  // vault directory, which may be outside the static fs:scope paths.
  createEffect(on(vaultPath, (path: string | null) => {
    if (path) {
      platform.vault.setVaultScope(path).catch((err: unknown) => {
        console.error('[App] Failed to set vault scope:', err);
      });
    }
  }));

  const [tabs, setTabs] = createSignal<Tab[]>([]);
  const [activeTabIndex, setActiveTabIndex] = createSignal<number>(session?.activeTabIndex ?? -1);
  const [showQuickSwitcher, setShowQuickSwitcher] = createSignal(false);
  const [showCommandPalette, setShowCommandPalette] = createSignal(false);
  const [showSearch, setShowSearch] = createSignal(false);
  const [showTerminal, setShowTerminal] = createSignal(false);
  const [showOpenClaw, setShowOpenClaw] = createSignal(false);
  const [openClawWidth, setOpenClawWidth] = createSignal(
    parseInt(localStorage.getItem('openclaw_width') || '500')
  );
  const [showCustomProvider, setShowCustomProvider] = createSignal(false);
  const [customProviderWidth, setCustomProviderWidth] = createSignal(
    parseInt(localStorage.getItem('custom_provider_width') || '500')
  );
  // AI provider visibility toggles (persisted in localStorage)
  const [openCodeEnabled, setOpenCodeEnabled] = createSignal(
    localStorage.getItem('opencode_enabled') !== 'false'
  );
  const [openClawEnabled, setOpenClawEnabled] = createSignal(
    localStorage.getItem('openclaw_enabled') !== 'false'
  );
  const [customProviderEnabled, setCustomProviderEnabled] = createSignal(
    localStorage.getItem('custom_provider_enabled') !== 'false'
  );
  // Editor view mode: 'live' = rendered markdown, 'source' = raw markdown
  const [editorViewMode, setEditorViewMode] = createSignal<'live' | 'source'>(
    (localStorage.getItem('editor_view_mode') as 'live' | 'source') || 'live'
  );
  // Flag to prevent settings save effect from running before initial load completes
  const [settingsLoaded, setSettingsLoaded] = createSignal(false);
  const [showSettings, setShowSettings] = createSignal(false);
  const [settingsSection, setSettingsSection] = createSignal<string | undefined>(undefined);
  const [showGraphView, setShowGraphView] = createSignal(false);
  const [terminalWidth, setTerminalWidth] = createSignal(500);
  const [sidebarWidth, setSidebarWidth] = createSignal(session?.sidebarWidth ?? 260);
  const [sidebarCollapsed, setSidebarCollapsed] = createSignal(session?.sidebarCollapsed ?? false);
  const [sidebarView, setSidebarView] = createSignal<SidebarView>(session?.sidebarView ?? 'files');
  // Expanded folders for file tree - shared with Sidebar
  const [expandedFolders, setExpandedFolders] = createSignal<Set<string>>(
    new Set(session?.expandedFolders ?? [])
  );
  let createNoteFromSidebar: (() => void) | null = null;
  let refreshSidebar: (() => void) | null = null;
  let setSearchQuery: ((query: string) => void) | null = null;
  const [scrollToLine, setScrollToLine] = createSignal<number | null>(null);
  const [noteIndex, setNoteIndex] = createSignal<NoteIndex | null>(null);
  const [assetIndex, setAssetIndex] = createSignal<AssetIndex | null>(null);
  const [isResizing, setIsResizing] = createSignal<'sidebar' | 'terminal' | 'outline' | 'backlinks' | 'properties' | 'notifications' | null>(null);
  
  // Queue for deep links received before vault is loaded
  // Stores both the URL and clipboard content (since clipboard may change)
  let pendingDeepLinks: { url: string; clipboardContent?: string }[] = [];

  // Backlinks panel state
  const [showBacklinks, setShowBacklinks] = createSignal(
    localStorage.getItem('show_backlinks') === 'true'
  );
  const [backlinksWidth, setBacklinksWidth] = createSignal(
    parseInt(localStorage.getItem('backlinks_width') || '250')
  );

  // Properties panel state
  const [showProperties, setShowProperties] = createSignal(
    localStorage.getItem('show_properties') === 'true'
  );
  const [propertiesWidth, setPropertiesWidth] = createSignal(
    parseInt(localStorage.getItem('properties_width') || '280')
  );

  // Notifications panel state (width only - show state already exists)
  const [notificationsWidth, setNotificationsWidth] = createSignal(
    parseInt(localStorage.getItem('notifications_width') || '320')
  );

  // Note graph and file contents for backlinks
  const [noteGraph, setNoteGraph] = createSignal<NoteGraph | null>(null);
  const [fileContents, setFileContents] = createSignal<Map<string, string>>(new Map());

  // Outline panel state
  const [showOutline, setShowOutline] = createSignal(
    localStorage.getItem('show_outline') === 'true'
  );
  const [outlineWidth, setOutlineWidth] = createSignal(
    parseInt(localStorage.getItem('outline_width') || '250')
  );

  // Heading state from editor plugin
  const [currentHeadings, setCurrentHeadings] = createSignal<HeadingInfo[]>([]);
  const [activeHeadingId, setActiveHeadingId] = createSignal<string | null>(null);
  const [scrollToHeadingId, setScrollToHeadingId] = createSignal<string | null>(null);

  // Anchor navigation state (for wikilink #heading and ^blockid references)
  const [scrollToHeadingText, setScrollToHeadingText] = createSignal<string | null>(null);
  const [scrollToBlockId, setScrollToBlockId] = createSignal<string | null>(null);

  const [resizeStartX, setResizeStartX] = createSignal(0);
  const [resizeStartWidth, setResizeStartWidth] = createSignal(0);
  // Bookmarks and saved searches - synced via Nostr (NIP-78 encrypted user preferences)
  const [bookmarks, setBookmarks] = createSignal<string[]>(
    JSON.parse(localStorage.getItem('bookmarks') || '[]')
  );
  const [savedSearches, setSavedSearches] = createSignal<string[]>(
    JSON.parse(localStorage.getItem('savedSearches') || '[]')
  );

  // Close tab confirmation modal
  const [closeTabConfirm, setCloseTabConfirm] = createSignal<{ index: number; name: string } | null>(null);

  // Document Sharing state
  const [showNotifications, setShowNotifications] = createSignal(false);
  const [showSentShares, setShowSentShares] = createSignal(false);
  const [showShareDialog, setShowShareDialog] = createSignal(false);
  const [shareTarget, setShareTarget] = createSignal<{ path: string; content: string; title: string } | null>(null);
  const [sharedWithMe, setSharedWithMe] = createSignal<SharedDocument[]>([]);
  const [sentShares, setSentShares] = createSignal<SentShare[]>([]);
  const [isLoadingShares, setIsLoadingShares] = createSignal(false);
  const [previewingDoc, setPreviewingDoc] = createSignal<SharedDocument | null>(null);
  const [isImporting, setIsImporting] = createSignal(false);
  const [currentVault, setCurrentVault] = createSignal<Vault | null>(null);

  // File Info and Post to Nostr dialogs
  const [showFileInfo, setShowFileInfo] = createSignal<string | null>(null);
  const [postToNostrTarget, setPostToNostrTarget] = createSignal<{ path: string; content: string; title: string } | null>(null);

  // Onboarding state
  const [showOnboarding, setShowOnboarding] = createSignal(false);

  // Web-only: master-passphrase lock state. Tauri builds keep this false.
  const [webLocked, setWebLocked] = createSignal(
    platform.info.is_web && !!platform.secrets.isLocked?.(),
  );

  // Templates modal state
  const [showTemplatesModal, setShowTemplatesModal] = createSignal(false);
  const [availableTemplates, setAvailableTemplates] = createSignal<TemplateInfo[]>([]);
  const [templatesLoading, setTemplatesLoading] = createSignal(false);

  // Mobile state
  const platformInfo = usePlatformInfo();
  const [mobileDrawerOpen, setMobileDrawerOpen] = createSignal(false);
  const [mobileNavTab, setMobileNavTab] = createSignal<MobileNavTab>('files');
  const [mobileMoreMenu, setMobileMoreMenu] = createSignal(false);
  const isMobileApp = () => {
    const info = platformInfo();
    return info?.platform === 'android' || info?.platform === 'ios';
  };

  // Unread count for notifications badge
  const unreadShareCount = () => sharedWithMe().filter(d => !d.isRead).length
    + (vaultSnapshot()?.invitations.filter(i => !i.read && !i.dismissed && !i.accepted).length ?? 0);

  // Auto-save timer
  let autoSaveTimeout: number | null = null;

  // Share polling interval
  let sharePollingInterval: number | null = null;

  // Debounce timer for file watcher
  let fileChangeDebounce: number | null = null;

  const [vaultEngine, setVaultEngine] = createSignal<VaultEngine>();
  const [vaultSnapshot, setVaultSnapshot] = createSignal<VaultEngineSnapshot>();
  const [vaultError, setVaultError] = createSignal<string | null>(null);
  const [identityVersion, setIdentityVersion] = createSignal(0);
  const [vaultPubkey, setVaultPubkey] = createSignal<Pubkey>();
  const [showVaults, setShowVaults] = createSignal(false);
  const [selectedVaultId, setSelectedVaultId] = createSignal<VaultId>();
  const [conflictsVaultId, setConflictsVaultId] = createSignal<VaultId>();
  const [shareVault, setShareVault] = createSignal<{ folder: string; vaultId?: VaultId }>();
  const [invitationId, setInvitationId] = createSignal<EventId>();
  const [attachFolder, setAttachFolder] = createSignal<string>();
  const [recoveryPrompt, setRecoveryPrompt] = createSignal(false);
  const [recoveryRequest, setRecoveryRequest] = createSignal<VaultRecoveryPassphraseRequest>();
  const [recoveryPassphrase, setRecoveryPassphrase] = createSignal('');
  const [recoveryConfirmation, setRecoveryConfirmation] = createSignal('');
  const [recoverySaveError, setRecoverySaveError] = createSignal<string>();
  const [recoveryPicking, setRecoveryPicking] = createSignal(false);
  let recoveryDestination: { path: string; generation: number } | undefined;
  const getRecoveryDestination = () => recoveryDestination;
  let finishRecoveryPrompt: ((value: string | null) => void) | undefined;
  const closeRecoveryPrompt = (value: string | null = null) => {
    finishRecoveryPrompt?.(value);
    finishRecoveryPrompt = undefined;
    setRecoveryPassphrase('');
    setRecoveryConfirmation('');
    setRecoveryPrompt(false);
    setRecoveryRequest(undefined);
  };
  let recoveryActive = false;
  const exportVaultRecovery = async (id: VaultId) => {
    if (recoveryActive) throw new Error('Another recovery export is still running. Wait for it to finish.');
    recoveryActive = true;
    recoveryDestination = undefined;
    try {
      const engine = vaultEngine();
      if (!engine) throw new Error('Vault session closed');
      const pkg = await engine.exportRecovery(id);
      const destination = getRecoveryDestination();
      if (!destination || disposed || destination.generation !== sessionGeneration) throw new Error('Vault session changed or recovery save cancelled');
      await platform.dialog.writeTextFile(destination.path, JSON.stringify(pkg, null, 2));
    } finally {
      const unusedDestination = getRecoveryDestination();
      if (unusedDestination) platform.dialog.discardSave?.(unusedDestination.path);
      recoveryDestination = undefined;
      closeRecoveryPrompt();
      recoveryActive = false;
    }
  };
  const requestRecoveryPassphrase = (request?: VaultRecoveryPassphraseRequest) => new Promise<string | null>(resolve => {
    closeRecoveryPrompt();
    recoveryDestination = undefined;
    setRecoverySaveError(undefined);
    finishRecoveryPrompt = resolve;
    setRecoveryRequest(request);
    setRecoveryPrompt(true);
  });
  const selectedVault = () => vaultSnapshot()?.vaults.find(v => v.vaultId === selectedVaultId());
  const selectedInvitation = () => vaultSnapshot()?.invitations.find(i => i.invitationId === invitationId());
  const conflictsVault = () => vaultSnapshot()?.vaults.find(v => v.vaultId === conflictsVaultId());
  const manageSharedVault = (id: VaultId) => { setSelectedVaultId(id); setShowVaults(false); };
  const openVaultShare = (id: VaultId) => {
    const vault = vaultSnapshot()?.vaults.find(v => v.vaultId === id);
    if (vault?.mount) setShareVault({ folder: vault.mount.relativePath, vaultId: id });
  };
  const [heldEditors, setHeldEditors] = createSignal<ReadonlySet<string>>(new Set());
  const mounts: MountRegistry = {
    getMounts: () => vaultSnapshot()?.vaults.flatMap(vault => vault.mount ? [vault.mount] : []) ?? [],
  };
  const managedPath = (path: string) => isManagedPath(path, mounts, platform.info.platform);
  const legacyPath = (path: string) => !disposed && !intersectsManagedMount(path, mounts, platform.info.platform);
  const legacyRelativePath = (path: string) => legacyPath(`${vaultPath()}/${path}`);
  const relativeVaultPath = (path: string) => {
    const root = (vaultPath() ?? '').replace(/\\/g, '/').replace(/\/$/, '');
    const normalized = path.replace(/\\/g, '/');
    return normalized.slice(root.length + 1);
  };
  const pathKey = (path: string) => {
    const slashes = path.normalize('NFC').replace(/\\/g, '/');
    const components: string[] = [];
    for (const component of slashes.split('/')) {
      if (!component || component === '.') continue;
      if (component === '..' && components.length && components[components.length - 1] !== '..') components.pop();
      else components.push(component);
    }
    const normalized = `${slashes.startsWith('/') ? '/' : ''}${components.join('/')}`;
    return ['windows', 'macos'].includes(platform.info.platform) ? normalized.toLowerCase() : normalized;
  };
  const holds = new Map<string, { done: Promise<void>; release(): void }>();
  const writes = new Map<string, Promise<unknown>>();
  const appAbort = new AbortController();
  let disposed = false;
  let sessionGeneration = 0;
  let sessionWork = Promise.resolve();
  let watcherWork = Promise.resolve();
  let unsubscribeVault: (() => void) | undefined;
  const appUnsubscribers: (() => void)[] = [];
  const trackUnsubscriber = (unsubscribe: () => void) => {
    if (disposed) unsubscribe(); else appUnsubscribers.push(unsubscribe);
  };

  const pathsIntersect = (left: string, right: string) => pathKey(left) === pathKey(right)
    || pathKey(left).startsWith(`${pathKey(right)}/`) || pathKey(right).startsWith(`${pathKey(left)}/`);
  const holdFor = (path: string) => [...holds.entries()].find(([held]) => pathsIntersect(path, held))?.[1];
  const editorHeld = (path: string) => [...heldEditors()].some(held =>
    pathKey(path) === held || pathKey(path).startsWith(`${held}/`));
  const managedReadOnly = (path: string) => managedPath(path) && !vaultSnapshot()?.vaults.some(vault =>
    vault.mount && vault.authority !== 'reader' && isManagedPath(path, { getMounts: () => [vault.mount!] }, platform.info.platform));

  // All app-initiated managed writes serialize with materialisation and each other.
  const writeManaged = async <T,>(path: string, write: () => Promise<T>): Promise<T> => {
    const key = pathKey(path);
    const notebook = vaultPath();
    while (holdFor(path) || writes.has(key)) {
      if (appAbort.signal.aborted) throw new Error('Vault session closed');
      await (holdFor(path)?.done ?? writes.get(key));
    }
    if (appAbort.signal.aborted) throw new Error('Vault session closed');
    if (managedReadOnly(path)) throw new Error('Shared vault path is read-only');
    const operation = Promise.resolve().then(() => {
      if (appAbort.signal.aborted || notebook !== vaultPath()) throw new Error('Vault session changed');
      return write();
    });
    writes.set(key, operation);
    try {
      const result = await operation;
      if (notebook === vaultPath() && managedPath(path)) vaultEngine()?.notifyFilesChanged([path]);
      return result;
    } finally {
      writes.delete(key);
    }
  };

  const canMutateSharedPath = (relative: string, operation: VaultPathOperation) => {
    const path = `${vaultPath()}/${relative}`;
    if (holdFor(path) || managedReadOnly(path)) return false;
    return operation === 'create' || !mounts.getMounts().some(mount =>
      pathKey(path) === pathKey(`${mount.notebookPath}/${mount.relativePath}`)
      || pathKey(`${mount.notebookPath}/${mount.relativePath}`).startsWith(`${pathKey(path)}/`));
  };

  const editorBarrier: VaultEditorBarrier = {
    async enter(paths, signal) {
      const root = vaultPath();
      if (!root || signal.aborted || disposed) throw new Error('Vault session closed');
      const affected = paths.map(path => `${root}/${path}`);
      for (const path of affected) {
        if (holdFor(path)) throw new Error('Shared vault editor already held');
      }
      let unlock!: () => void;
      const done = new Promise<void>(resolve => { unlock = resolve; });
      let released = false;
      let unlocked = false;
      let timer: number | undefined;
      const unlockEditors = () => {
        if (unlocked) return;
        unlocked = true;
        clearTimeout(timer);
        signal.removeEventListener('abort', abort);
        appAbort.signal.removeEventListener('abort', abort);
        for (const path of affected) holds.delete(pathKey(path));
        setHeldEditors(new Set(holds.keys()));
        unlock();
        if (disposed) return;
        refreshSidebar?.();
        // Reschedule autosaves cancelled on entry, including unaffected tabs.
        if (tabs().some(tab => tab.isDirty)) {
          autoSaveTimeout = window.setTimeout(() => {
            tabs().forEach((tab, index) => { if (tab.isDirty) void saveTab(index); });
          }, 2000);
        }
      };
      const release = () => {
        if (released) return;
        released = true;
        // Refresh before unblocking input/saves, still within the original 5 s
        // deadline. Never replace dirty content or a tab changed during the read.
        const refreshes = tabs().filter(tab => !tab.isDirty && tab.fileType === 'markdown'
          && affected.some(path => pathsIntersect(tab.path, path))).map(tab =>
          platform.vault.read(tab.path, root).then(content => {
            if (!disposed && !unlocked && vaultPath() === root) setTabs(prev => prev.map(current =>
              current === tab ? { ...current, content } : current));
          }).catch(err => console.error('Failed to refresh shared tab:', err)));
        void Promise.all(refreshes).finally(unlockEditors);
      };
      let rejectHold!: (reason: Error) => void;
      const expired = new Promise<never>((_, reject) => { rejectHold = reject; });
      const abort = () => {
        rejectHold(new Error('Shared vault editor hold aborted'));
        released = true;
        unlockEditors();
      };
      signal.addEventListener('abort', abort, { once: true });
      appAbort.signal.addEventListener('abort', abort, { once: true });
      timer = window.setTimeout(() => {
        setVaultError('Shared vault editor hold exceeded 5 seconds');
        rejectHold(new Error('Shared vault editor hold exceeded 5 seconds'));
        released = true;
        unlockEditors();
      }, 5000);
      for (const path of affected) holds.set(pathKey(path), { done, release });
      setHeldEditors(new Set(holds.keys()));
      if (autoSaveTimeout) { clearTimeout(autoSaveTimeout); autoSaveTimeout = null; }
      try {
        const flushedHashes = await Promise.race([expired, (async () => {
          const hashes = new Map<string, Address>();
          await Promise.all([...writes.entries()].filter(([path]) => affected.some(held => pathsIntersect(path, held))).map(([, write]) => write));
          if (released) throw new Error('Shared vault editor hold expired');
          for (const tab of tabs().filter(tab => affected.some(path => pathsIntersect(tab.path, path)) && managedPath(tab.path))) {
            await writes.get(pathKey(tab.path));
            if (released) throw new Error('Shared vault editor hold expired');
            if (tabs().find(current => current.path === tab.path)?.isDirty) {
              const content = await persistTab(tab.path);
              hashes.set(relativeVaultPath(tab.path), hashAddress(new TextEncoder().encode(content)));
            }
          }
          return hashes;
        })()]);
        return { flushedHashes, release };
      } catch (err) {
        setVaultError(`Shared vault flush failed: ${String(err)}`);
        release();
        throw err;
      }
    },
  };

  const createSharedVault = (folder: string) => {
    if (vaultSnapshot()?.lifecycle === 'running') setShareVault({ folder });
    else { setAttachFolder(undefined); setShowVaults(true); }
  };
  const attachSharedVault = (folder: string) => {
    setAttachFolder(vaultSnapshot()?.lifecycle === 'running' ? folder : undefined);
    setShowVaults(true);
  };
  const refreshVaultIdentity = async () => {
    setIdentityVersion(version => version + 1);
    await Promise.resolve();
    await sessionWork;
  };
  createEffect(() => {
    const path = vaultPath();
    const loaded = settingsLoaded();
    const locked = webLocked();
    identityVersion();
    const generation = ++sessionGeneration;
    // Cancel an in-flight start now, not behind the promise it must abort.
    const stopping = untrack(() => vaultEngine()?.stop());
    void stopping?.catch(() => {});
    sessionWork = sessionWork.then(async () => {
      closeRecoveryPrompt();
      setShareVault(undefined);
      setInvitationId(undefined);
      setAttachFolder(undefined);
      setSelectedVaultId(undefined);
      setConflictsVaultId(undefined);
      setVaultPubkey(undefined);
      await stopping;
      if (disposed || generation !== sessionGeneration) return;
      if (!loaded) { setVaultError('Waiting for notebook settings to load.'); return; }
      if (!path) { setVaultError('Sign in and open a notebook to use shared vaults.'); return; }
      if (locked) { setVaultError('The secret store is locked. Unlock it to start shared vaults.'); return; }
      setVaultError('Starting shared vaults…');
      const login = await getCurrentLoginWithAuth();
      if (disposed || generation !== sessionGeneration) return;
      if (!login) { setVaultError('Sign in or unlock your identity, then retry shared vaults. Biometric authentication may have been cancelled.'); return; }
      const signer = createSignerFromLogin(login);
      if (!signer) { setVaultError('Could not load the signer for your identity. Unlock it or sign in again, then retry shared vaults.'); return; }
      setVaultPubkey(hex32<Pubkey>(login.pubkey));
      const engine = getVaultEngine({ requestRecoveryPassphrase });
      if (!unsubscribeVault) {
        unsubscribeVault = engine.subscribe(snapshot => { if (!disposed) setVaultSnapshot(snapshot); });
        setVaultEngine(engine);
      }
      const storedRelays: (string | { url: string; read: boolean; write: boolean })[] =
        JSON.parse(localStorage.getItem('nostr_relays') ?? 'null') ?? DEFAULT_SYNC_CONFIG.relays;
      const relays = storedRelays.map(relay => typeof relay === 'string' ? { url: relay, read: true, write: true } : relay);
      const blossom: string[] = JSON.parse(localStorage.getItem('blossom_servers') ?? 'null') ?? DEFAULT_SYNC_CONFIG.blossomServers;
      setVaultError(null);
      await engine.start({ accountPubkey: hex32<Pubkey>(login.pubkey), signer, notebookPath: path,
        fs: platform.managedVault, secrets: platform.secrets, editorBarrier,
        networkDefaults: { readRelays: relays.filter(r => r.read).map(r => r.url),
          writeRelays: relays.filter(r => r.write).map(r => r.url), readBlossom: blossom, writeBlossom: blossom } }, { requestRecoveryPassphrase });
    }).catch(err => { if (!disposed && generation === sessionGeneration) setVaultError(`Shared vault engine failed to start: ${String(err)}`); });
  });
  onCleanup(() => {
    disposed = true;
    ++sessionGeneration;
    closeRecoveryPrompt();
    appAbort.abort();
    unsubscribeVault?.();
    appUnsubscribers.splice(0).forEach(unsubscribe => unsubscribe());
    void watcherWork.then(() => platform.vault.stopWatching()).catch(console.error);
    for (const hold of holds.values()) hold.release();
    if (autoSaveTimeout) clearTimeout(autoSaveTimeout);
    if (fileChangeDebounce) clearTimeout(fileChangeDebounce);
    void vaultEngine()?.stop().catch(console.error);
  });

  // Apply appearance settings from localStorage
  const applyAppearanceSettings = () => {
    const root = document.documentElement;

    // Apply theme
    const theme = localStorage.getItem('theme') || 'dark';
    if (theme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      root.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
    } else {
      root.setAttribute('data-theme', theme);
    }

    // Apply accent color
    const accent = localStorage.getItem('accent_color') || '#8b5cf6';
    root.style.setProperty('--accent', accent);
    // Calculate hover color (lighter version)
    const num = parseInt(accent.replace('#', ''), 16);
    const amt = Math.round(2.55 * 20);
    const R = Math.min(255, (num >> 16) + amt);
    const G = Math.min(255, ((num >> 8) & 0x00FF) + amt);
    const B = Math.min(255, (num & 0x0000FF) + amt);
    const hoverColor = `#${(0x1000000 + R * 0x10000 + G * 0x100 + B).toString(16).slice(1)}`;
    root.style.setProperty('--accent-hover', hoverColor);
    root.style.setProperty('--accent-muted', `${accent}26`);
    // Calculate contrasting text color for accent backgrounds
    const luminance = (0.299 * ((num >> 16) & 0xFF) + 0.587 * ((num >> 8) & 0xFF) + 0.114 * (num & 0xFF)) / 255;
    root.style.setProperty('--accent-text', luminance > 0.5 ? '#000000' : '#ffffff');

    // Apply font size
    const fontSize = localStorage.getItem('interface_font_size') || 'medium';
    root.setAttribute('data-font-size', fontSize);

    // Apply translucent
    const translucent = localStorage.getItem('translucent_window') === 'true';
    root.setAttribute('data-translucent', translucent.toString());
  };

  // Load settings on startup
  onMount(() => {
    // Initialize platform detection first
    initPlatform().then((info) => {
      console.log('[App] Platform detected:', info.platform);
      
      // Set up Android back button handler using Tauri v2.9+ API
      if (info.platform === 'android') {
        platform.app.onBackButton((event) => {
            // Vault overlays take precedence over editor/history navigation.
            if (recoveryPrompt()) { closeRecoveryPrompt(); return; }
            if (shareVault()) { setShareVault(undefined); return; }
            if (invitationId()) { setInvitationId(undefined); setAttachFolder(undefined); return; }
            if (conflictsVaultId()) { setConflictsVaultId(undefined); return; }
            if (selectedVaultId()) { setSelectedVaultId(undefined); return; }
            if (showVaults()) { setShowVaults(false); return; }
            // Handle back navigation in order of priority:
          // 1. Close settings modal if open
          if (showSettings()) {
            setShowSettings(false);
            return;
          }
          // 2. Close mobile drawer if open
          if (mobileDrawerOpen()) {
            setMobileDrawerOpen(false);
            return;
          }
          // 3. Close any modals (quick switcher, command palette, search)
          if (showQuickSwitcher()) {
            setShowQuickSwitcher(false);
            return;
          }
          if (showCommandPalette()) {
            setShowCommandPalette(false);
            return;
          }
          if (showSearch()) {
            setShowSearch(false);
            return;
          }
          // 4. Close share dialog if open
          if (shareTarget()) {
            setShareTarget(null);
            setShowShareDialog(false);
            return;
          }
          // 5. Close graph view if showing
          if (showGraphView()) {
            setShowGraphView(false);
            return;
          }
          // 6. Close notifications/sent shares panels
          if (showNotifications()) {
            setShowNotifications(false);
            return;
          }
          if (showSentShares()) {
            setShowSentShares(false);
            return;
          }
          // 7. Close previewing doc if open
          if (previewingDoc()) {
            setPreviewingDoc(null);
            return;
          }
          // 8. Close current tab if there are multiple tabs
          const currentTabs = tabs();
          const currentIndex = activeTabIndex();
          if (currentTabs.length > 1 && currentIndex >= 0) {
            closeTab(currentIndex);
            return;
          }
          // 9. If webview can go back, do that
          if (event.canGoBack) {
            window.history.back();
            return;
          }
          // 10. No more navigation - app will exit (default behavior when handler returns without action)
        }).then(trackUnsubscriber).catch(err => {
          console.error('[App] Failed to register back button handler:', err);
        });
      }
    });

    // Apply appearance settings immediately
    applyAppearanceSettings();

    // Listen for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleThemeChange = () => {
      if (localStorage.getItem('theme') === 'system') applyAppearanceSettings();
    };
    mediaQuery.addEventListener('change', handleThemeChange);
    onCleanup(() => mediaQuery.removeEventListener('change', handleThemeChange));

    // Load settings asynchronously
    platform.settings.load().then(async (settings) => {
      console.log('[App] Settings loaded:', settings);
      let vaultToOpen = settings.vault_path ?? null;

      // On mobile, if no vault is set, auto-initialize to default vault
      if (!vaultToOpen) {
        try {
          const platformInfo = await platform.refreshInfo();
          console.log('[App] Platform info for auto-init:', platformInfo);
          if ((platformInfo.platform === 'android' || platformInfo.platform === 'ios') && platformInfo.default_vault_path) {
            // Create the directory if it doesn't exist
            console.log('[App] Auto-initializing mobile vault at:', platformInfo.default_vault_path);
            await writeManaged(platformInfo.default_vault_path, () => platform.vault.createFolder(platformInfo.default_vault_path!, platformInfo.default_vault_path!));
            vaultToOpen = platformInfo.default_vault_path;
            // Save this as the vault path
            await platform.settings.save({ vault_path: vaultToOpen, show_terminal: false });
            console.log('[App] Mobile vault auto-initialized and saved');
          }
        } catch (err) {
          console.error('Failed to auto-initialize mobile vault:', err);
        }
      }

      if (vaultToOpen) {
        console.log('[App] Setting vault path to:', vaultToOpen);
        setVaultPath(vaultToOpen);
        // Build note index for wikilink resolution
        try {
          const files = await platform.vault.list(vaultToOpen);
          setNoteIndex(buildNoteIndex(files, vaultToOpen));
        } catch (err) {
          console.error('Failed to build initial note index:', err);
        }
        // Build asset index for embed resolution
        try {
          const assets = await platform.vault.listAssets(vaultToOpen);
          setAssetIndex(buildAssetIndex(assets, vaultToOpen));
        } catch (err) {
          console.error('Failed to build initial asset index:', err);
        }
        // Process any deep links that arrived before vault was ready
        processPendingDeepLinks();

        // Restore tabs from session
        if (session?.tabs?.length) {
          const restoredTabs: Tab[] = [];
          for (const savedTab of session.tabs) {
            const fileType = getFileType(savedTab.path);
            if (fileType === 'markdown') {
              try {
                const content = await platform.vault.read(savedTab.path, vaultPath() ?? '');
                restoredTabs.push({ path: savedTab.path, name: savedTab.name, content, isDirty: false, fileType });
              } catch {
                // File may have been deleted or moved -- skip it
              }
            } else {
              // Non-markdown files don't need content
              try {
                const exists = await platform.vault.exists(savedTab.path);
                if (exists) {
                  restoredTabs.push({ path: savedTab.path, name: savedTab.name, content: '', isDirty: false, fileType });
                }
              } catch {
                // Skip if we can't verify existence
              }
            }
          }
          if (restoredTabs.length > 0) {
            setTabs(restoredTabs);
            // Restore active tab index, clamping to valid range
            const savedIndex = session.activeTabIndex ?? -1;
            setActiveTabIndex(savedIndex >= 0 && savedIndex < restoredTabs.length ? savedIndex : restoredTabs.length - 1);
          }
        }
      }
      if (settings.show_terminal) {
        setShowTerminal(true);
      }
      
      // Mark settings as loaded - now the save effect can run
      console.log('[App] Settings load complete, enabling save effect');
      setSettingsLoaded(true);
      
      // Check if this is first run - show onboarding if not completed
      const onboardingCompleted = localStorage.getItem('onboarding_completed') === 'true';
      if (!onboardingCompleted) {
        console.log('[App] First run detected, showing onboarding');
        setShowOnboarding(true);
      }
    }).catch(err => {
      console.error('Failed to load settings:', err);
      // Still mark as loaded so app can function
      setSettingsLoaded(true);
      
      // Still check for onboarding even if settings failed to load
      const onboardingCompleted = localStorage.getItem('onboarding_completed') === 'true';
      if (!onboardingCompleted) {
        setShowOnboarding(true);
      }
    });

    // Initialize sync status from localStorage
    const syncEnabled = localStorage.getItem('sync_enabled') === 'true';
    setSyncStatus(syncEnabled ? 'idle' : 'off');

    // Set up file change listener
    let unlistenFn: (() => void) | null = null;
    let unlistenFileModified: (() => void) | null = null;

    platform.vault.onFilesChanged((paths) => {
      if (disposed) return;
      vaultEngine()?.notifyFilesChanged(paths);
      // Debounce refreshes to avoid too many updates
      if (fileChangeDebounce) {
        clearTimeout(fileChangeDebounce);
      }
      fileChangeDebounce = window.setTimeout(() => {
        refreshSidebar?.();
        rebuildNoteIndex();  // Rebuild index on file changes for wikilink resolution
        fileChangeDebounce = null;
      }, 500);
    }).then(unlisten => {
      if (disposed) unlisten(); else unlistenFn = unlisten;
    }).catch(err => {
      console.error('[App] Failed to register files-changed watcher:', err);
    });

    // Listen for specific file modifications to reload open tabs
    platform.vault.onFileModified(async (modifiedPaths) => {
      if (disposed) return;
      vaultEngine()?.notifyFilesChanged(modifiedPaths);
      const currentTabs = tabs();

      for (const modifiedPath of modifiedPaths) {
        if (managedPath(modifiedPath)) continue;
        const tabIndex = currentTabs.findIndex(tab => tab.path === modifiedPath);
        if (tabIndex !== -1 && currentTabs[tabIndex].fileType === 'markdown') {
          try {
            const newContent = await platform.vault.read(modifiedPath, vaultPath() ?? '');
            if (disposed || managedPath(modifiedPath)) continue;
            const tab = currentTabs[tabIndex];

            // If the content is different from what we have, reload it
            // This handles both dirty and non-dirty cases - external changes take precedence
            // (e.g., OpenCode editing a file should always be reflected in the editor)
            if (newContent !== tab.content) {
              // Cancel any pending autosave to prevent overwriting external changes
              if (autoSaveTimeout) {
                clearTimeout(autoSaveTimeout);
                autoSaveTimeout = null;
              }

              // Update tab content and clear dirty flag since we're syncing with disk
              setTabs(prevTabs => prevTabs.map((t, i) =>
                i === tabIndex ? { ...t, content: newContent, isDirty: false } : t
              ));
            }
          } catch (err) {
            console.error('Failed to reload file:', modifiedPath, err);
          }
        }
      }

      // Update the in-memory content cache for the modified files and rebuild
      // the note graph from memory (reads only the modified paths, not the vault)
      refreshContentsForPaths(modifiedPaths);
    }).then(unlisten => {
      if (disposed) unlisten(); else unlistenFileModified = unlisten;
    }).catch(err => {
      console.error('[App] Failed to register file-modified watcher:', err);
    });

    // Cleanup must be registered synchronously
    onCleanup(() => {
      unlistenFn?.();
      unlistenFileModified?.();
      if (sharePollingInterval) {
        clearInterval(sharePollingInterval);
      }
    });

    // Fetch shared documents if logged in
    fetchSharedDocuments();

    // Set up polling for shared documents (every 5 minutes)
    sharePollingInterval = window.setInterval(() => {
      fetchSharedDocuments();
    }, 5 * 60 * 1000);
    
    // Listen for re-triggering onboarding from Settings
    const handleShowOnboarding = () => {
      setShowOnboarding(true);
    };
    window.addEventListener('show-onboarding', handleShowOnboarding);
    
    onCleanup(() => {
      window.removeEventListener('show-onboarding', handleShowOnboarding);
    });
    
    // Set up deep link handler for Onyx Clipper integration
    setupDeepLinkHandler();
  });

  // Handle deep links from Onyx Clipper browser extension
  const setupDeepLinkHandler = async () => {
    try {
      // Register handler for URLs received while app is running (macOS)
      trackUnsubscriber(await platform.deepLink.onOpenUrl(async (urls: string[]) => {
        if (disposed) return;
        console.log('[DeepLink] onOpenUrl received:', urls);
        for (const url of urls) {
          await handleDeepLink(url);
        }
      }));
      if (disposed) return;

      // Listen for deep links from single-instance plugin (Linux/Windows)
      // When a second instance tries to launch, the URL is passed via this event
      trackUnsubscriber(await platform.deepLink.onReceived(async (url) => {
        if (disposed) return;
        console.log('[DeepLink] Received from single-instance:', url);
        await handleDeepLink(url);
      }));
      if (disposed) return;

      // Check if app was launched via deep link (important for Linux/Windows)
      // On these platforms, the URL is passed as CLI argument, not via onOpenUrl
      let launchUrls = await platform.deepLink.getCurrent();

      // Fallback: check CLI args directly (more reliable on Linux)
      if (!launchUrls || launchUrls.length === 0) {
        try {
          const cliUrls = await platform.deepLink.getLaunchArgs();
          if (cliUrls && cliUrls.length > 0) {
            launchUrls = cliUrls;
          }
        } catch (e) {
          console.error('[DeepLink] Failed to get CLI args:', e);
        }
      }
      
      if (!disposed && launchUrls && launchUrls.length > 0) {
        console.log('[DeepLink] App launched with URLs:', launchUrls);
        for (const url of launchUrls) {
          await handleDeepLink(url);
        }
      }
    } catch (err) {
      console.error('[DeepLink] Failed to register handler:', err);
    }
  };

  // Process any queued deep links after vault is loaded
  const processPendingDeepLinks = async () => {
    if (pendingDeepLinks.length === 0) return;
    console.log('[DeepLink] Processing', pendingDeepLinks.length, 'pending deep links');
    const links = [...pendingDeepLinks];
    pendingDeepLinks = [];
    for (const pending of links) {
      await handleDeepLink(pending.url, pending.clipboardContent);
    }
  };

  const handleDeepLink = async (url: string, cachedClipboard?: string) => {
    console.log('[DeepLink] Handling:', url);
    try {
      const parsed = new URL(url);
      const protocol = parsed.protocol.replace(':', '');
      
      if (protocol !== 'onyx') {
        return;
      }
      
      const action = parsed.hostname;
      const params = parsed.searchParams;
      
      // If vault isn't ready yet, queue the deep link with clipboard content
      if (!vaultPath() && action === 'clip') {
        console.log('[DeepLink] Vault not ready, queueing');
        let clipboardContent: string | undefined;
        if (params.has('clipboard')) {
          try {
            clipboardContent = await platform.clipboard.readText() || undefined;
          } catch (err) {
            console.error('[DeepLink] Failed to read clipboard for queue:', err);
          }
        }
        pendingDeepLinks.push({ url, clipboardContent });
        return;
      }
      
      switch (action) {
        case 'clip':
          await handleClipDeepLink(params, cachedClipboard);
          break;
        case 'open':
          await handleOpenDeepLink(params);
          break;
        default:
          console.log('[DeepLink] Unknown action:', action);
      }
    } catch (err) {
      console.error('[DeepLink] Error parsing URL:', err);
    }
  };

  // Handle onyx://clip - Save clipped content from browser extension
  const handleClipDeepLink = async (params: URLSearchParams, cachedClipboard?: string) => {
    const vault = vaultPath();
    if (!vault) {
      console.error('[DeepLink] No vault path set');
      return;
    }
    
    const title = params.get('title') || 'Untitled';
    const path = sanitizeFilePath(params.get('path') || 'Clippings');
    const useClipboard = params.has('clipboard');
    // Sanitize filename from URL params to prevent directory traversal
    let filename = sanitizeFilename(params.get('filename') || title);
    if (!filename.endsWith('.md')) {
      filename = `${filename}.md`;
    }
    
    let content = '';
    if (useClipboard) {
      // Use cached clipboard content if available (from queued deep link)
      if (cachedClipboard) {
        content = cachedClipboard;
      } else {
        try {
          content = await platform.clipboard.readText() || '';
        } catch (err) {
          console.error('[DeepLink] Failed to read clipboard:', err);
          return;
        }
      }
    }

    if (!content) {
      console.error('[DeepLink] No content to clip');
      return;
    }

    // Ensure the target directory exists
    // Use Rust backend commands instead of plugin-fs to avoid FS scope restrictions
    const targetDir = `${vault}/${path}`;
    try {
      await writeManaged(targetDir, () => platform.vault.createFolder(targetDir, vault));
    } catch (err) {
      console.error('[DeepLink] Failed to create directory:', err);
    }

    // Handle duplicate filenames
    let finalPath = `${targetDir}/${filename}`;
    let counter = 1;
    while (await platform.vault.exists(finalPath)) {
      const baseName = filename.replace(/\.md$/, '');
      finalPath = `${targetDir}/${baseName} ${counter}.md`;
      counter++;
    }
    
    // Save the file
    try {
      await writeManaged(finalPath, async () => {
        if (await platform.vault.exists(finalPath)) throw new Error('Clip destination changed; retry the clip');
        await platform.vault.write(finalPath, content, vault);
      });
      console.log('[DeepLink] Clipped to:', finalPath);
      
      // Refresh sidebar to show new file
      refreshSidebar?.();
      
      // Open the new file
      await openFile(finalPath);
      
      // Rebuild note index
      rebuildNoteIndex();
    } catch (err) {
      console.error('[DeepLink] Failed to save clipped content:', err);
    }
  };

  // Handle onyx://open - Open a file in the vault
  const handleOpenDeepLink = async (params: URLSearchParams) => {
    const vault = vaultPath();
    if (!vault) {
      console.error('[DeepLink] No vault path set');
      return;
    }
    
    const path = params.get('path');
    if (!path) {
      console.error('[DeepLink] No path provided');
      return;
    }
    
    // Always sanitize path to prevent directory traversal.
    // Even if path starts with vault, it could contain ../ segments to escape (e.g. /vault/../../etc/passwd).
    // sanitizeFilePath strips traversal sequences, then we prepend the vault path.
    const relativePath = path.startsWith(vault) 
      ? sanitizeFilePath(path.slice(vault.length).replace(/^\//, ''))
      : sanitizeFilePath(path);
    const safePath = `${vault}/${relativePath}`;
    await openFile(safePath);
  };

  // Sanitize filename for saving
  const sanitizeFilename = (name: string): string => {
    return name
      .replace(/[<>:"/\\|?*\x00-\x1f]/g, '')
      .replace(/[\s_]+/g, ' ')
      .replace(/^[\s.]+|[\s.]+$/g, '')
      .substring(0, 200)
      || 'Untitled';
  };

  // Handle onboarding completion
  const handleOnboardingComplete = async (result: OnboardingResult) => {
    console.log('[App] Onboarding complete:', result);
    
    // Mark onboarding as completed
    localStorage.setItem('onboarding_completed', 'true');
    
    // Set the vault path from onboarding
    if (result.vaultPath) {
      setVaultPath(result.vaultPath);
      localStorage.setItem('vault_path', result.vaultPath);
      
      // Build note index for the new vault
      try {
        const files = await platform.vault.list(result.vaultPath);
        setNoteIndex(buildNoteIndex(files, result.vaultPath));
      } catch (err) {
        console.error('Failed to build note index after onboarding:', err);
      }

      // Build asset index
      try {
        const assets = await platform.vault.listAssets(result.vaultPath);
        setAssetIndex(buildAssetIndex(assets, result.vaultPath));
      } catch (err) {
        console.error('Failed to build asset index after onboarding:', err);
      }
    }
    
    // Apply sync settings if enabled during onboarding
    if (result.syncEnabled) {
      setSyncStatus('idle');
    }
    
    // Hide onboarding
    setShowOnboarding(false);
    
    // Create first note if requested
    if (result.createFirstNote) {
      setTimeout(() => {
        createNewNote();
      }, 100);
    }
    
    // Refresh shared documents if Nostr was set up
    if (result.nostrSetup !== 'skipped') {
      fetchSharedDocuments();
      await refreshVaultIdentity();
    }
  };

  // Fetch shared documents from relays
  const fetchSharedDocuments = async () => {
    const login = await getCurrentLogin();
    if (!login) return;

    setIsLoadingShares(true);
    try {
      const engine = getSyncEngine();
      
      // Only create signer if engine doesn't have one yet
      if (!engine.getSigner()) {
        const signer = await getSignerFromStoredLogin();
        if (signer) {
          await engine.setSigner(signer);
        }
      }
      
      if (engine.getSigner()) {
        // Fetch documents shared with me and documents I've shared
        const [receivedDocs, sentDocs] = await Promise.all([
          engine.fetchSharedWithMe(),
          engine.fetchSentShares(),
        ]);
        
        setSharedWithMe(receivedDocs);
        setSentShares(sentDocs);

        // Also fetch vault for import functionality
        const vaults = await engine.fetchVaults();
        if (vaults.length > 0) {
          setCurrentVault(vaults[0]);
        }
        
        // Fetch and merge user preferences (bookmarks, saved searches)
        await fetchPreferencesFromNostr();
      }
    } catch (err) {
      console.error('Failed to fetch shared documents:', err);
    } finally {
      setIsLoadingShares(false);
    }
  };

  // Handle previewing a shared document
  const handlePreviewSharedDoc = (doc: SharedDocument) => {
    // Mark as read
    const engine = getSyncEngine();
    engine.markShareAsRead(doc.eventId);
    
    // Update local state
    setSharedWithMe(prev => prev.map(d => 
      d.eventId === doc.eventId ? { ...d, isRead: true } : d
    ));
    
    setPreviewingDoc(doc);
    // Keep notifications panel open - user can close it manually
  };

  // Handle importing a shared document
  const handleImportSharedDoc = async (doc: SharedDocument) => {
    const vp = vaultPath();
    if (!vp) {
      console.error('No vault path available for import');
      return;
    }

    setIsImporting(true);
    try {
      // Extract safe filename from the document
      const rawFilename = doc.title || doc.data.path || 'Untitled';
      // Get just the filename part (handle Windows and Unix paths)
      let filename = rawFilename.split(/[/\\]/).pop() || 'Untitled';
      // Sanitize filename
      filename = filename
        .replace(/[<>:"|?*\x00-\x1f]/g, '_')  // Remove invalid chars
        .replace(/\.\./g, '_');  // Remove traversal attempts
      // Ensure .md extension
      if (!filename.toLowerCase().endsWith('.md')) {
        filename += '.md';
      }
      
      // Create Shared directory if it doesn't exist
      const sharedDir = `${vp}/Shared`;
      if (!legacyPath(sharedDir)) throw new Error('Document import destination intersects a shared vault');
      const dirExists = await platform.dialog.pathExists(sharedDir);
      if (!dirExists) {
        if (!legacyPath(sharedDir)) throw new Error('Document import destination is managed');
        await platform.dialog.mkdir(sharedDir, true);
      }

      // Write file to local filesystem
      const filePath = `${sharedDir}/${filename}`;
      if (!legacyPath(filePath)) throw new Error('Document import destination is managed');
      await platform.dialog.writeTextFile(filePath, doc.data.content);
      
      // Also sync to Nostr if sync is enabled
      const vault = currentVault();
      if (vault && legacyPath(filePath) && legacyPath(sharedDir)) {
        try {
          const engine = getSyncEngine();
          await engine.importSharedDocument(doc, vault);
        } catch (syncErr) {
          console.warn('Failed to sync imported document to Nostr:', syncErr);
          // Don't fail the import if sync fails - file is saved locally
        }
      }
      
      // Mark as read
      const engine = getSyncEngine();
      engine.markShareAsRead(doc.eventId);
      
      // Refresh sidebar to show new file
      refreshSidebar?.();
      
      // Open the imported file
      await openFile(filePath);
    } catch (err) {
      console.error('Failed to import shared document:', err);
    } finally {
      setIsImporting(false);
    }
  };

  // Handle dismissing a shared document (just mark as read)
  const handleDismissSharedDoc = (doc: SharedDocument) => {
    const engine = getSyncEngine();
    engine.markShareAsRead(doc.eventId);
    
    setSharedWithMe(prev => prev.map(d => 
      d.eventId === doc.eventId ? { ...d, isRead: true } : d
    ));
  };

  // Handle revoking a share
  const handleRevokeShare = async (share: SentShare) => {
    try {
      const engine = getSyncEngine();
      await engine.revokeShare(share.eventId);
      
      // Remove from local state
      setSentShares(prev => prev.filter(s => s.eventId !== share.eventId));
    } catch (err) {
      console.error('Failed to revoke share:', err);
    }
  };

  // Handle blocking a user (adds to NIP-51 mute list)
  const handleBlockUser = async (pubkey: string) => {
    try {
      const engine = getSyncEngine();
      await engine.addToMuteList(pubkey, true); // Private mute
      engine.invalidateMuteCache();
      
      // Remove all shares from this user from local state
      setSharedWithMe(prev => prev.filter(d => d.senderPubkey !== pubkey));
      
      // Close the preview
      setPreviewingDoc(null);
    } catch (err) {
      console.error('Failed to block user:', err);
      throw err; // Re-throw so the UI can show error state
    }
  };

  // Handle sharing a file
  const handleShareFile = (fullPath: string, content: string) => {
    // Extract title from path (handle both Unix and Windows paths)
    const parts = fullPath.replace(/\\/g, '/').split('/');
    const filename = parts[parts.length - 1] || 'Untitled';
    const title = filename.replace(/\.[^/.]+$/, '');
    
    // Use relative path for sharing (strip vault path)
    const relativePath = vaultPath() ? fullPath.replace(vaultPath()! + '/', '') : fullPath;
    
    setShareTarget({ path: relativePath, content, title });
    setShowShareDialog(true);
  };

  // Handle showing file info
  const handleFileInfo = (path: string) => {
    setShowFileInfo(path);
  };

  // Handle posting to Nostr
  const handlePostToNostr = (path: string, content: string, title: string) => {
    setPostToNostrTarget({ path, content, title });
  };

  // Start/stop file watcher when vault path changes
  createEffect(() => {
    const path = vaultPath();
    watcherWork = watcherWork.then(async () => {
      await platform.vault.stopWatching();
      if (!disposed && path && path === vaultPath()) await platform.vault.startWatching(path);
    }).catch(console.error);
  });

  // Save settings when vault path changes (but not before initial load)
  createEffect(() => {
    const path = vaultPath();
    const terminal = showTerminal();
    const loaded = settingsLoaded();
    
    // Don't save settings until initial load is complete to prevent race conditions
    if (!loaded) {
      console.log('[App] Settings not yet loaded, skipping save');
      return;
    }
    
    // Save settings (debounced by the effect system)
    console.log('[App] Saving settings - vault_path:', path);
    platform.settings.save({
      vault_path: path,
      show_terminal: terminal,
    }).catch(console.error);
  });

  // Persist outline panel state
  createEffect(() => {
    localStorage.setItem('show_outline', showOutline().toString());
  });
  createEffect(() => {
    localStorage.setItem('outline_width', outlineWidth().toString());
  });

  // Persist backlinks panel state
  createEffect(() => {
    localStorage.setItem('show_backlinks', showBacklinks().toString());
  });
  createEffect(() => {
    localStorage.setItem('backlinks_width', backlinksWidth().toString());
  });

  // Persist properties panel state
  createEffect(() => {
    localStorage.setItem('show_properties', showProperties().toString());
  });
  createEffect(() => {
    localStorage.setItem('properties_width', propertiesWidth().toString());
  });

  // Persist notifications panel width
  createEffect(() => {
    localStorage.setItem('notifications_width', notificationsWidth().toString());
  });

  // Persist session state (tabs, sidebar state, expanded folders)
  createEffect(() => {
    const currentTabs = tabs();
    const currentActiveIndex = activeTabIndex();
    const currentSidebarWidth = sidebarWidth();
    const currentSidebarCollapsed = sidebarCollapsed();
    const currentSidebarView = sidebarView();
    const currentExpandedFolders = expandedFolders();
    
    // Only save if we have a vault (meaning app has initialized)
    if (!vaultPath()) return;
    
    const sessionState: SessionState = {
      tabs: currentTabs.map(t => ({ path: t.path, name: t.name })),
      activeTabIndex: currentActiveIndex,
      sidebarWidth: currentSidebarWidth,
      sidebarCollapsed: currentSidebarCollapsed,
      sidebarView: currentSidebarView,
      expandedFolders: Array.from(currentExpandedFolders),
    };
    
    localStorage.setItem('session_state', JSON.stringify(sessionState));
  });

  // ---------------------------------------------------------------------
  // Incremental note graph + persistent file-content cache for backlinks
  //
  // fileContents is a persistent cache of all .md contents. Graph rebuilds
  // run from the in-memory map; disk reads (IPC) happen only for paths that
  // are new/modified. All cache mutations are serialized through a promise
  // chain so concurrent triggers (index rebuilds, file-modified events,
  // auto-saves) can't clobber each other, and a generation counter discards
  // work queued before the vault was closed/cleared.
  // ---------------------------------------------------------------------
  let graphSyncGeneration = 0;
  let graphSyncChain: Promise<void> = Promise.resolve();
  const queueGraphSync = (work: () => Promise<void>) => {
    graphSyncChain = graphSyncChain
      .then(work)
      .catch(err => console.error('Failed to build note graph:', err));
  };

  // Full sync: diff the index against the cache, read only missing files,
  // drop deleted ones, then rebuild the graph entirely from memory.
  const syncGraphWithIndex = (index: NoteIndex, vault: string) => {
    const gen = graphSyncGeneration;
    queueGraphSync(async () => {
      if (gen !== graphSyncGeneration) return;
      const cache = new Map(fileContents());

      // Drop cache entries for files no longer in the index
      for (const path of cache.keys()) {
        if (!index.allPaths.has(path)) cache.delete(path);
      }

      // Read only paths missing from the cache (16-way parallel; on initial
      // load this reads everything, afterwards just new files)
      const missing = [...index.allPaths].filter(p => !cache.has(p));
      if (missing.length > 0) {
        await readContentsParallel(missing, (path) => platform.vault.read(path, vault), cache);
      }

      if (gen !== graphSyncGeneration || vaultPath() !== vault) return;
      setFileContents(cache);
      setNoteGraph(buildNoteGraphFromContents(vault, index, cache));
    });
  };

  // Targeted refresh: re-read specific files (modified on disk), update the
  // cache, and rebuild the graph from memory — no full-vault reads.
  const refreshContentsForPaths = (paths: string[]) => {
    const gen = graphSyncGeneration;
    queueGraphSync(async () => {
      if (gen !== graphSyncGeneration) return;
      const vault = vaultPath();
      const index = noteIndex();
      if (!vault || !index) return;

      const mdPaths = paths.filter(p => /\.md$/i.test(p));
      if (mdPaths.length === 0) return;

      const cache = new Map(fileContents());
      let changed = false;
      for (const path of mdPaths) {
        try {
          const content = await platform.vault.read(path, vault);
          if (cache.get(path) !== content) {
            cache.set(path, content);
            changed = true;
          }
        } catch {
          // File may have been deleted — drop it from the cache
          if (cache.delete(path)) changed = true;
        }
      }

      if (!changed || gen !== graphSyncGeneration || vaultPath() !== vault) return;
      setFileContents(cache);
      setNoteGraph(buildNoteGraphFromContents(vault, index, cache));
    });
  };

  // Zero-IPC refresh: update the cache for a path from content we already
  // have in memory (e.g. just-saved tab content) and rebuild the graph.
  const updateCachedContent = (path: string, content: string) => {
    if (!/\.md$/i.test(path)) return;
    const gen = graphSyncGeneration;
    queueGraphSync(async () => {
      if (gen !== graphSyncGeneration) return;
      const vault = vaultPath();
      const index = noteIndex();
      if (!vault || !index) return;

      const cache = new Map(fileContents());
      if (cache.get(path) === content) return;
      cache.set(path, content);
      setFileContents(cache);
      setNoteGraph(buildNoteGraphFromContents(vault, index, cache));
    });
  };

  // Build note graph and cache file contents for backlinks
  createEffect(() => {
    const index = noteIndex();
    const vault = vaultPath();
    if (!index || !vault) {
      graphSyncGeneration++; // invalidate any queued/in-flight sync work
      setNoteGraph(null);
      setFileContents(new Map());
      return;
    }
    syncGraphWithIndex(index, vault);
  });

  // Clear headings when switching tabs
  createEffect(() => {
    activeTabIndex(); // Dependency
    setCurrentHeadings([]);
    setActiveHeadingId(null);
  });

  const currentTab = () => {
    const idx = activeTabIndex();
    return idx >= 0 ? tabs()[idx] : null;
  };

  // Resolve the active image tab's asset URL. resolveAssetUrl is synchronous on
  // Tauri but returns a Promise on web (blob URL from OPFS), so go through a
  // resource instead of casting.
  const [imageTabSrc] = createResource(
    () => {
      const tab = currentTab();
      return tab && tab.fileType === 'image' ? tab.path : null;
    },
    (path) => Promise.resolve(platform.assets.resolveAssetUrl(path))
  );

  // Word and character count for status bar
  const wordCount = () => {
    const content = currentTab()?.content || '';
    if (!content.trim()) return 0;
    return content.trim().split(/\s+/).length;
  };

  const charCount = () => {
    return (currentTab()?.content || '').length;
  };

  // Sync status for status bar
  const [syncStatus, setSyncStatus] = createSignal<'off' | 'idle' | 'syncing' | 'error'>('off');

   const openFile = async (path: string, line?: number) => {
    // Check if already open
    const existingIndex = tabs().findIndex(t => t.path === path);
    if (existingIndex >= 0) {
      setActiveTabIndex(existingIndex);
      // If line specified, scroll to it even if file is already open
      if (line) {
        setScrollToLine(line);
      }
      return;
    }

    // Determine file type from extension
    const fileType = getFileType(path);

    // Handle both Unix (/) and Windows (\) path separators
    const parts = path.split(/[/\\]/);
    const fileName = parts[parts.length - 1] || 'Untitled';
    const name = fileType === 'markdown' ? fileName.replace(/\.md$/i, '') : fileName.replace(/\.[^.]+$/, '');

    // Non-markdown files are read-only viewers -- no text content needed
    if (fileType !== 'markdown') {
      setTabs([...tabs(), { path, name, content: '', isDirty: false, fileType }]);
      setActiveTabIndex(tabs().length - 1);
      return;
    }

    // Load markdown file content
    try {
      const content = await platform.vault.read(path, vaultPath() ?? '');

      setTabs([...tabs(), { path, name, content, isDirty: false, fileType }]);
      // setTabs applies synchronously, so tabs() is already the new array here.
      setActiveTabIndex(tabs().length - 1);

      // Set line to scroll to after editor loads
      if (line) {
        setScrollToLine(line);
      }
    } catch (err) {
      console.error('Failed to open file:', err);
    }
  };

  // Fix: Update activeTabIndex after tabs update
  createEffect(() => {
    const tabList = tabs();
    const idx = activeTabIndex();
    if (idx >= tabList.length && tabList.length > 0) {
      setActiveTabIndex(tabList.length - 1);
    }
  });

  const closeTab = (index: number) => {
    const tab = tabs()[index];
    if (tab.isDirty) {
      setCloseTabConfirm({ index, name: tab.name });
      return;
    }
    doCloseTab(index);
  };

  const doCloseTab = (index: number) => {
    const newTabs = tabs().filter((_, i) => i !== index);
    setTabs(newTabs);

    if (activeTabIndex() >= newTabs.length) {
      setActiveTabIndex(Math.max(0, newTabs.length - 1));
    } else if (activeTabIndex() > index) {
      setActiveTabIndex(activeTabIndex() - 1);
    }

    if (newTabs.length === 0) {
      setActiveTabIndex(-1);
    }
  };

  const handleCloseTabSave = async () => {
    const confirm = closeTabConfirm();
    if (!confirm) return;
    await saveTab(confirm.index);
    if (tabs()[confirm.index]?.isDirty) return;
    doCloseTab(confirm.index);
    setCloseTabConfirm(null);
  };

  const handleCloseTabDiscard = () => {
    const confirm = closeTabConfirm();
    if (!confirm) return;
    doCloseTab(confirm.index);
    setCloseTabConfirm(null);
  };

  // Shared by ordinary saves and barrier flushes; a failed flush must reject.
  const persistTab = async (path: string) => {
    const tab = tabs().find(tab => tab.path === path);
    if (!tab) throw new Error('Tab closed before save');
    // Strip the serializer's escapes from literal markdown characters.
    const content = tab.content.replace(/\\([[\]_!])/g, '$1');
    await platform.vault.write(path, content, vaultPath() ?? '');
    setTabs(prev => prev.map(current => current === tab ? { ...current, content, isDirty: false } : current));
    updateCachedContent(path, content);
    return content;
  };

  const saveTab = async (index: number) => {
    const path = tabs()[index]?.path;
    if (!path) return;
    try {
      await writeManaged(path, async () => {
        // A barrier may already have flushed this save while it was queued.
        if (!managedPath(path) || tabs().find(tab => tab.path === path)?.isDirty) await persistTab(path);
      });
    } catch (err) {
      if (managedPath(path)) setVaultError(`Shared vault save failed: ${String(err)}`);
      console.error('Failed to save:', err);
    }
  };

  const updateTabContent = (content: string) => {
    const idx = activeTabIndex();
    if (idx < 0 || editorHeld(tabs()[idx]?.path ?? '') || managedReadOnly(tabs()[idx]?.path ?? '')) return;

    // Strip backslash escapes that Milkdown's remark-stringify adds to [ ] _ !
    // These characters are literal in Milkdown's WYSIWYG model (links, emphasis,
    // images are structural nodes). Without this, wikilinks like [[note]] get
    // saved to disk as \[\[note\]\].
    const cleaned = content.replace(/\\([[\]_!])/g, '$1');

    const tabPath = tabs()[idx]?.path;
    setTabs(tabs().map((t, i) => i === idx ? { ...t, content: cleaned, isDirty: true } : t));

    // Auto-save after 2 seconds of no typing
    // Capture path instead of index to avoid saving to wrong tab if tabs change
    if (autoSaveTimeout) clearTimeout(autoSaveTimeout);
    autoSaveTimeout = window.setTimeout(() => {
      if (tabPath) {
        const currentIdx = tabs().findIndex(t => t.path === tabPath);
        if (currentIdx >= 0) saveTab(currentIdx);
      }
    }, 2000);
  };

  const saveCurrentTab = () => {
    const idx = activeTabIndex();
    if (idx >= 0) saveTab(idx);
  };

  // Global keyboard shortcuts
  onMount(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isMod = e.ctrlKey || e.metaKey;

      if (isMod && e.key === 'o') {
        e.preventDefault();
        setShowQuickSwitcher(true);
      } else if (isMod && e.key === 'p') {
        e.preventDefault();
        setShowCommandPalette(true);
      } else if (isMod && e.shiftKey && e.key === 'F') {
        e.preventDefault();
        setShowSearch(true);
      } else if (isMod && e.key === 's') {
        e.preventDefault();
        saveCurrentTab();
      } else if (isMod && e.key === '`') {
        e.preventDefault();
        if (!isWeb()) setShowTerminal(!showTerminal());
      } else if (isMod && e.shiftKey && e.key === 'O') {
        e.preventDefault();
        setShowOutline(!showOutline());
      } else if (isMod && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        setShowBacklinks(!showBacklinks());
      } else if (isMod && e.shiftKey && e.key === 'P') {
        e.preventDefault();
        setShowProperties(!showProperties());
      } else if (isMod && e.key === 'd') {
        e.preventDefault();
        handleOpenDailyNote();
      } else if (isMod && e.key === 't') {
        e.preventDefault();
        handleOpenTemplatesPicker();
      } else if (e.key === 'Escape') {
        // Closing a modal with Escape must consume the event, otherwise the
        // OS default (e.g. exiting native fullscreen on macOS) also fires.
        // Only preventDefault when a modal is actually open so Escape keeps
        // its normal behavior (IME cancel, etc.) when nothing is showing.
        if (showQuickSwitcher() || showCommandPalette() || showSearch() || showTemplatesModal()) {
          e.preventDefault();
        }
        setShowQuickSwitcher(false);
        setShowCommandPalette(false);
        setShowSearch(false);
        setShowTemplatesModal(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    // Listen for AI provider toggle changes from Settings
    const handleProviderToggle = () => {
      const oc = localStorage.getItem('opencode_enabled') !== 'false';
      const ocl = localStorage.getItem('openclaw_enabled') !== 'false';
      const cp = localStorage.getItem('custom_provider_enabled') !== 'false';
      setOpenCodeEnabled(oc);
      setOpenClawEnabled(ocl);
      setCustomProviderEnabled(cp);
      // Close panels for disabled providers
      if (!oc) setShowTerminal(false);
      if (!ocl) setShowOpenClaw(false);
      if (!cp) setShowCustomProvider(false);
    };
    window.addEventListener('ai-provider-toggle', handleProviderToggle);

    onCleanup(() => {
      document.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('ai-provider-toggle', handleProviderToggle);
    });
  });

  const handleFileCreated = (path: string) => {
    openFile(path);
  };

  // Open vault - works on both mobile and desktop
  // Returns the vault path if successful, null otherwise
  const openVault = async (): Promise<string | null> => {
    try {
      await impactLight();
      
      if (isMobileApp()) {
        // On mobile, use the default vault path
        const info = await platform.refreshInfo();
        console.log('[App] openVault - platform info:', info);
        if (info.default_vault_path) {
          console.log('[App] openVault - creating folder:', info.default_vault_path);
          await writeManaged(info.default_vault_path, () => platform.vault.createFolder(info.default_vault_path!, info.default_vault_path!));
          setVaultPath(info.default_vault_path);
          localStorage.setItem('vault_path', info.default_vault_path);
          // Refresh sidebar
          if (refreshSidebar) {
            refreshSidebar();
          }
          await notificationSuccess();
          return info.default_vault_path;
        } else {
          console.error('[App] openVault - no default_vault_path returned');
          return null;
        }
      } else {
        // On desktop, use folder picker
        const selected = await platform.dialog.open({
          directory: true,
          multiple: false,
          title: 'Select Vault Folder',
        });
        if (selected && typeof selected === 'string') {
          setVaultPath(selected);
          localStorage.setItem('vault_path', selected);
          if (refreshSidebar) {
            refreshSidebar();
          }
          return selected;
        }
        return null;
      }
    } catch (err) {
      console.error('[App] Failed to open vault:', err);
      await notificationError();
      return null;
    }
  };

  const createNewNote = async () => {
    console.log('[App] createNewNote called');
    
    // On mobile, always use direct creation since the sidebar may not be mounted
    // On desktop, try the sidebar's create function first for better UX (shows rename input)
    if (createNoteFromSidebar && !isMobileApp()) {
      console.log('[App] Using sidebar create function');
      createNoteFromSidebar();
      return;
    }
    
    // Direct creation (always used on mobile, fallback on desktop)
    let vault = vaultPath();
    console.log('[App] createNewNote - vault path:', vault);
    
    if (!vault) {
      console.warn('[App] Cannot create note: no vault path, attempting to open vault first');
      // openVault returns the path directly, so we don't need to re-read from state
      vault = await openVault();
      if (!vault) {
        console.error('[App] Still no vault path after openVault, aborting');
        return;
      }
      console.log('[App] Vault opened, continuing with path:', vault);
    }
    
    // Ensure vault directory exists
    try {
      console.log('[App] Ensuring vault folder exists:', vault);
      await writeManaged(vault, () => platform.vault.createFolder(vault!, vault!));
      console.log('[App] Vault folder created/verified');
    } catch (err) {
      console.error('[App] Failed to ensure vault folder exists:', err);
      // Continue anyway - the folder might already exist
    }

    // Generate unique filename
    const timestamp = new Date().toISOString().slice(0, 10);
    let filename = `Untitled ${timestamp}.md`;
    let filepath = `${vault}/${filename}`;
    let counter = 1;

    try {
      // Check if file exists and increment counter if needed
      console.log('[App] Checking if file exists:', filepath);
      while (await platform.vault.exists(filepath)) {
        filename = `Untitled ${timestamp} ${counter}.md`;
        filepath = `${vault}/${filename}`;
        counter++;
      }

      console.log('[App] Creating note at:', filepath);

      // Create the file with some initial content
      await writeManaged(filepath, () => platform.vault.createFile(filepath, vault!));
      
      console.log('[App] Note created successfully');
      
      // Open it
      console.log('[App] Opening file...');
      await openFile(filepath);
      
      console.log('[App] File opened');
      
      // Refresh sidebar if available
      if (refreshSidebar) {
        refreshSidebar();
      }
      
      // Haptic feedback on mobile
      await impactMedium();
      console.log('[App] createNewNote complete');
    } catch (err) {
      console.error('[App] Failed to create note:', err);
      // Show error to user
      alert('Failed to create note: ' + (err as Error).message);
      await notificationError();
    }
  };

  const handleFileDeleted = async (path: string) => {
    const idx = tabs().findIndex(t => t.path === path);
    if (idx >= 0) {
      closeTab(idx);
    }
    
    // Track deletion for Nostr sync - store relative path
    const vault = vaultPath();
    if (vault && legacyPath(path)) {
      const deletedPaths = (JSON.parse(localStorage.getItem('deleted_paths') || '[]') as string[]).filter(legacyRelativePath);
      const relativePath = path.replace(vault + '/', '');
      
      // For folder deletions, track all files that were inside
      try {
        const engine = getSyncEngine();
        const signer = engine.getSigner();
        if (signer) {
          const vaults = await engine.fetchVaults();
          const vaultData = vaults[0];
          if (vaultData) {
            // Find all files in vault that start with this folder path
            const folderPrefix = relativePath + '/';
            const filesInFolder = vaultData.data.files
              .filter(f => legacyRelativePath(f.path) && (f.path === relativePath || f.path.startsWith(folderPrefix)))
              .map(f => f.path);
            
            for (const filePath of filesInFolder) {
              if (!deletedPaths.includes(filePath)) {
                deletedPaths.push(filePath);
              }
            }
          }
        }
      } catch {
        // Could not check for folder contents, will track path as-is
      }
      
      // Also track the path itself (in case it's a file, or as a fallback for folders)
      if (!deletedPaths.includes(relativePath)) {
        deletedPaths.push(relativePath);
      }
      
      localStorage.setItem('deleted_paths', JSON.stringify(deletedPaths));
    }
  };

  const handleFileMoved = (oldPath: string, newPath: string) => {
    const vault = vaultPath();
    if (!vault) return;
    
    const oldRelative = oldPath.replace(vault + '/', '');
    const newRelative = newPath.replace(vault + '/', '');
    
    if (!legacyPath(oldPath) || !legacyPath(newPath)) return;

    // Track the move for Nostr sync
    const movedPaths = (JSON.parse(localStorage.getItem('moved_paths') || '[]') as Array<{ from: string; to: string }>)
      .filter(move => legacyRelativePath(move.from) && legacyRelativePath(move.to));
    
    // If this file was previously moved (A -> B, now B -> C), update to A -> C
    const existingIdx = movedPaths.findIndex(m => m.to === oldRelative);
    if (existingIdx >= 0) {
      movedPaths[existingIdx].to = newRelative;
    } else {
      movedPaths.push({ from: oldRelative, to: newRelative });
    }
    
    localStorage.setItem('moved_paths', JSON.stringify(movedPaths));
    
    // Update the local d-tag map so we preserve file identity across the move
    const dtagMap = JSON.parse(localStorage.getItem('file_dtag_map') || '{}') as Record<string, string>;
    if (dtagMap[oldRelative]) {
      dtagMap[newRelative] = dtagMap[oldRelative];
      delete dtagMap[oldRelative];
      localStorage.setItem('file_dtag_map', JSON.stringify(dtagMap));
    }
  };

  const toggleBookmark = async (path: string) => {
    const current = bookmarks();
    let updated: string[];
    if (current.includes(path)) {
      updated = current.filter(p => p !== path);
    } else {
      updated = [...current, path];
    }
    setBookmarks(updated);
    localStorage.setItem('bookmarks', JSON.stringify(updated));
    
    // Sync to Nostr if logged in
    await syncPreferencesToNostr(updated, savedSearches());
  };

  const toggleSavedSearch = async (query: string) => {
    const current = savedSearches();
    let updated: string[];
    if (current.includes(query)) {
      updated = current.filter(q => q !== query);
    } else {
      updated = [...current, query];
    }
    setSavedSearches(updated);
    localStorage.setItem('savedSearches', JSON.stringify(updated));
    
    // Sync to Nostr if logged in
    await syncPreferencesToNostr(bookmarks(), updated);
  };
  
  // Sync preferences to Nostr (debounced)
  let syncPreferencesTimeout: ReturnType<typeof setTimeout> | null = null;
  const syncPreferencesToNostr = async (bookmarksList: string[], searchesList: string[]) => {
    // Debounce to avoid too many writes
    if (syncPreferencesTimeout) {
      clearTimeout(syncPreferencesTimeout);
    }
    
    syncPreferencesTimeout = setTimeout(async () => {
      try {
        const engine = getSyncEngine();
        const signer = engine.getSigner();
        if (!signer) return; // Not logged in, skip sync
        
        await engine.savePreferences({
          bookmarks: bookmarksList,
          savedSearches: searchesList,
          updatedAt: Math.floor(Date.now() / 1000),
        });
        console.log('[App] Preferences synced to Nostr');
      } catch (err) {
        console.error('[App] Failed to sync preferences to Nostr:', err);
      }
    }, 2000); // 2 second debounce
  };
  
  // Fetch and merge preferences from Nostr on startup
  const fetchPreferencesFromNostr = async () => {
    try {
      const engine = getSyncEngine();
      const signer = engine.getSigner();
      if (!signer) return; // Not logged in
      
      const prefs = await engine.fetchPreferences();
      if (!prefs) return; // No preferences stored
      
      // Get local timestamps
      const localBookmarksTime = parseInt(localStorage.getItem('bookmarks_updated') || '0');
      const localSearchesTime = parseInt(localStorage.getItem('savedSearches_updated') || '0');
      
      // If remote is newer, merge (union of both sets)
      if (prefs.updatedAt > localBookmarksTime || prefs.updatedAt > localSearchesTime) {
        const localBookmarks = bookmarks();
        const localSearches = savedSearches();
        
        // Merge bookmarks (union)
        const mergedBookmarks = [...new Set([...localBookmarks, ...prefs.bookmarks])];
        const mergedSearches = [...new Set([...localSearches, ...prefs.savedSearches])];
        
        setBookmarks(mergedBookmarks);
        setSavedSearches(mergedSearches);
        localStorage.setItem('bookmarks', JSON.stringify(mergedBookmarks));
        localStorage.setItem('savedSearches', JSON.stringify(mergedSearches));
        localStorage.setItem('bookmarks_updated', String(prefs.updatedAt));
        localStorage.setItem('savedSearches_updated', String(prefs.updatedAt));
        
        console.log('[App] Preferences merged from Nostr');
      }
    } catch (err) {
      console.error('[App] Failed to fetch preferences from Nostr:', err);
    }
  };

  // Handle hashtag clicks from editor
  const handleHashtagClick = (tag: string) => {
    // Switch to search view
    switchSidebarView('search');
    // Set search query with tag: prefix
    if (setSearchQuery) {
      setSearchQuery(`#${tag}`);
    }
  };

  // Build/rebuild note index for wikilink resolution and asset index for embeds
  const rebuildNoteIndex = async () => {
    const path = vaultPath();
    if (!path) return;
    try {
      const files = await platform.vault.list(path);
      setNoteIndex(buildNoteIndex(files, path));
    } catch (err) {
      console.error('Failed to build note index:', err);
    }
    // Also rebuild asset index
    try {
      const assets = await platform.vault.listAssets(path);
      setAssetIndex(buildAssetIndex(assets, path));
    } catch (err) {
      console.error('Failed to build asset index:', err);
    }
  };

  // Handle wikilink clicks from editor
  const handleWikilinkClick = async (
    target: string,
    heading?: string | null,
    blockId?: string | null
  ) => {
    const index = noteIndex();
    const vault = vaultPath();
    if (!vault) return;

    // Clear previous anchor state first (allows re-triggering same anchor)
    setScrollToHeadingText(null);
    setScrollToBlockId(null);

    // Same-note reference (empty target) - now handled directly in wikilink plugin
    // This branch is kept for any edge cases where same-note refs still come through
    if (!target) {
      // Small delay to ensure clear takes effect before setting new value
      setTimeout(() => {
        if (heading) {
          setScrollToHeadingText(heading);
        } else if (blockId) {
          setScrollToBlockId(blockId);
        }
      }, 10);
      return;
    }

    // Resolve the wikilink to a file path
    const resolved = resolveWikilink(
      target,
      currentTab()?.path || '',
      index,
      vault
    );

    if (resolved.exists && resolved.path) {
      // Open existing note
      await openFile(resolved.path);

      // After opening, navigate to anchor if specified
      // Use setTimeout to allow the editor to load the content first
      if (heading || blockId) {
        setTimeout(() => {
          if (heading) {
            setScrollToHeadingText(heading);
          } else if (blockId) {
            setScrollToBlockId(blockId);
          }
        }, 200);
      }
    } else if (resolved.path) {
      // Create new note (no anchor navigation for new notes)
      try {
        await writeManaged(resolved.path, () => platform.vault.createFile(resolved.path!, vaultPath() ?? ''));
        await openFile(resolved.path);
        refreshSidebar?.();
      } catch (err) {
        console.error('Failed to create note:', err);
      }
    }
  };

  const switchSidebarView = (view: SidebarView) => {
    if (sidebarCollapsed()) {
      setSidebarCollapsed(false);
    }
    setSidebarView(view);
  };

  // Handle sync from status bar
  const handleStatusBarSync = async () => {
    // Don't sync if already syncing or sync is disabled
    if (syncStatus() === 'syncing' || syncStatus() === 'off') {
      return;
    }

    // Check if we have a vault open
    if (!vaultPath()) {
      return;
    }

    setSyncStatus('syncing');

    try {
      const engine = getSyncEngine();

      // Only create signer if engine doesn't have one yet
      if (!engine.getSigner()) {
        const signer = await getSignerFromStoredLogin();
        if (!signer) {
          setSyncStatus('idle');
          return;
        }
        await engine.setSigner(signer);
      }

      // Fetch vaults
      const vaults = await engine.fetchVaults();
      let vault = vaults[0];

      if (!vault) {
        vault = await engine.createVault('My Notes', 'Default vault');
      }

      // Get local files with their full paths
      const entries = await platform.vault.list(vaultPath() ?? '');
      // Spelling cannot see `Alias -> Shared`: the sidebar tree follows links, so
      // entries the backend marks as links are resolved to their filesystem
      // identity, and everything listed beneath an alias is judged by that
      // identity plus its remainder (an alias to a mount's *ancestor* resolves
      // outside the mount while its descendants resolve inside it) (SV-42).
      const managed = createManagedPathResolver(mounts, platform.info.platform, platform.vault.realPath?.bind(platform.vault));

      const localFiles: { path: string; fullPath: string; content: string }[] = [];
      type WalkEntry = { name: string; path: string; isDirectory: boolean; isSymlink?: boolean; children?: unknown[] };
      const processEntries = async (entries: WalkEntry[], alias?: { spelled: string; identity: string }) => {
        for (const entry of entries) {
          let identity = alias ? alias.identity + entry.path.slice(alias.spelled.length) : undefined;
          if (entry.isSymlink) {
            // A link whose identity cannot be established is not proven unmanaged.
            const resolved = await managed.identity(entry.path);
            if (resolved === null) continue;
            identity = resolved;
          }
          if (managedPath(entry.path) || (identity !== undefined && await managed.isManagedIdentity(identity))) continue;
          if (entry.isDirectory && entry.children) {
            await processEntries(entry.children as WalkEntry[], identity !== undefined ? { spelled: entry.path, identity } : alias);
          } else if (entry.name.endsWith('.md')) {
            const content = await platform.vault.read(entry.path, vaultPath() ?? '');
            const relativePath = entry.path.replace(vaultPath()! + '/', '');
            localFiles.push({ path: relativePath, fullPath: entry.path, content });
          }
        }
      };
      await processEntries(entries);

      // Get remote files
      const remoteFiles = (await engine.fetchVaultFiles(vault)).filter(file => legacyRelativePath(file.data.path));
      const remoteFileMap = new Map(remoteFiles.map(f => [f.data.path, f]));

      // Get locally deleted files that need to be synced
      const locallyDeletedPaths = (JSON.parse(localStorage.getItem('deleted_paths') || '[]') as string[]).filter(legacyRelativePath);
      const localFilePathSet = new Set(localFiles.map(f => f.path));

      // Sync files - compare timestamps to determine which version is newer
      let downloadedCount = 0;
      let uploadedCount = 0;
      let deletedCount = 0;
      let movedCount = 0;

      // Collect local-only files (not matched by path on remote)
      const localOnlyFiles: typeof localFiles = [];

      for (const localFile of localFiles) {
        if (!legacyPath(localFile.fullPath)) continue;
        const remoteFile = remoteFileMap.get(localFile.path);
        
        if (remoteFile) {
          // File exists both locally and remotely
          if (remoteFile.data.content !== localFile.content) {
            // Content differs - compare timestamps to decide direction
            try {
              const localModifiedTime = await platform.vault.modifiedTime(localFile.fullPath);
              const remoteModifiedTime = remoteFile.data.modified;
              
              console.log(`[Sync] File ${localFile.path}: local=${localModifiedTime}, remote=${remoteModifiedTime}`);
              
              if (remoteModifiedTime > localModifiedTime) {
                // Remote is newer - download
                console.log(`[Sync] Downloading newer remote version: ${localFile.path}`);
                if (!legacyPath(localFile.fullPath)) continue;
                await platform.vault.write(localFile.fullPath, remoteFile.data.content, vaultPath() ?? '');
                downloadedCount++;
              } else {
                // Local is newer or same time - upload
                console.log(`[Sync] Uploading newer local version: ${localFile.path}`);
                if (!legacyRelativePath(localFile.path)) continue;
                const result = await engine.publishFile(vault, localFile.path, localFile.content, remoteFile);
                vault = result.vault;
                uploadedCount++;
              }
            } catch (err) {
              // If we can't get local modified time, default to uploading
              console.warn(`[Sync] Could not get modified time for ${localFile.path}, uploading:`, err);
              if (!legacyRelativePath(localFile.path)) continue;
              const result = await engine.publishFile(vault, localFile.path, localFile.content, remoteFile);
              vault = result.vault;
              uploadedCount++;
            }
          }
          // Remove from map - we've handled this file
          remoteFileMap.delete(localFile.path);
        } else {
          // Local-only file - collect for move detection before uploading
          localOnlyFiles.push(localFile);
        }
      }

      // Process local deletions - sync them to the vault
      const pathsToKeepTracking: string[] = [];
      
      for (const deletedPath of locallyDeletedPaths) {
        if (!legacyRelativePath(deletedPath)) continue;
        const inRemoteMap = remoteFileMap.has(deletedPath);
        const inLocalFiles = localFilePathSet.has(deletedPath);
        
        // Only process if the file exists on remote and not locally
        if (inRemoteMap && !inLocalFiles) {
          try {
            vault = await engine.deleteFile(vault, deletedPath);
            deletedCount++;
          } catch {
            // Keep tracking this path since deletion failed
            pathsToKeepTracking.push(deletedPath);
          }
        } else if (inLocalFiles) {
          // File still exists locally (was recreated?), keep tracking
          pathsToKeepTracking.push(deletedPath);
        }
        // Remove from remoteFileMap so we don't re-download it
        remoteFileMap.delete(deletedPath);
      }
      
      // Update the locally deleted paths - only keep those that need continued tracking
      localStorage.setItem('deleted_paths', JSON.stringify(pathsToKeepTracking));

      // --- Move detection (3 layers) ---
      // Load the local d-tag map (path -> d-tag) persisted from previous syncs
      const dtagMap = JSON.parse(localStorage.getItem('file_dtag_map') || '{}') as Record<string, string>;
      // Build a reverse lookup: d-tag -> remote file (for d-tag-based matching)
      const remoteByDtag = new Map(remoteFiles.map(f => [f.d, f]));

      // Layer 1: Explicitly tracked moves (from in-app rename/move operations)
      // These are the most reliable -- we know exactly what was moved where.
      const movedPaths = (JSON.parse(localStorage.getItem('moved_paths') || '[]') as Array<{ from: string; to: string }>)
        .filter(move => legacyRelativePath(move.from) && legacyRelativePath(move.to));
      const movesToKeep: Array<{ from: string; to: string }> = [];
      
      for (const move of movedPaths) {
        if (!legacyRelativePath(move.from) || !legacyRelativePath(move.to)) continue;
        const remoteFile = remoteFileMap.get(move.from);
        const localFile = localOnlyFiles.find(f => f.path === move.to);
        
        if (remoteFile && localFile) {
          console.log(`[Sync] Processing tracked move: ${move.from} -> ${move.to}`);
          try {
            const result = await engine.moveFile(vault, move.from, move.to, localFile.content);
            vault = result.vault;
            movedCount++;
            remoteFileMap.delete(move.from);
            const idx = localOnlyFiles.indexOf(localFile);
            if (idx >= 0) localOnlyFiles.splice(idx, 1);
          } catch (err) {
            console.error(`[Sync] Failed to process tracked move ${move.from} -> ${move.to}:`, err);
            movesToKeep.push(move);
          }
        } else if (remoteFile && !localFile) {
          // The destination file wasn't found locally - keep tracking
          movesToKeep.push(move);
        }
        // If remote file doesn't exist at old path, the move was already handled or file was deleted
      }
      
      localStorage.setItem('moved_paths', JSON.stringify(movesToKeep));

      // Layer 2: d-tag map matching
      // For local-only files that have a known d-tag from a previous sync,
      // find the remote file by d-tag. This handles move+edit correctly since
      // the identity is tracked independently of content.
      if (localOnlyFiles.length > 0) {
        const dtagMatchedIndices = new Set<number>();
        
        for (let i = 0; i < localOnlyFiles.length; i++) {
          const localFile = localOnlyFiles[i];
          const knownDtag = dtagMap[localFile.path];
          if (!knownDtag) continue;
          
          // Look up the remote file by d-tag
          const remoteFile = remoteByDtag.get(knownDtag);
          if (!remoteFile || !legacyRelativePath(remoteFile.data.path) || !legacyRelativePath(localFile.path)) continue;

          // Check if the remote file is at a different path (meaning it wasn't already matched by path)
          if (remoteFile.data.path === localFile.path) continue;
          
          // Confirm the remote file is still in the unmatched set
          if (!remoteFileMap.has(remoteFile.data.path)) continue;
          
          console.log(`[Sync] Detected move by d-tag map: ${remoteFile.data.path} -> ${localFile.path}`);
          try {
            const result = await engine.moveFile(vault, remoteFile.data.path, localFile.path, localFile.content);
            vault = result.vault;
            movedCount++;
            remoteFileMap.delete(remoteFile.data.path);
            dtagMatchedIndices.add(i);
          } catch (err) {
            console.error(`[Sync] Failed to process d-tag move ${remoteFile.data.path} -> ${localFile.path}:`, err);
          }
        }
        
        for (let i = localOnlyFiles.length - 1; i >= 0; i--) {
          if (dtagMatchedIndices.has(i)) {
            localOnlyFiles.splice(i, 1);
          }
        }
      }

      // Layer 3: SHA-256 content matching (fallback for system file manager moves)
      // Match remaining local-only files against remaining remote-only files by checksum.
      // This won't catch move+edit, but handles simple moves from outside Onyx.
      if (localOnlyFiles.length > 0 && remoteFileMap.size > 0) {
        const remoteByChecksum = new Map<string, Array<{ path: string; file: typeof remoteFiles[0] }>>();
        for (const [path, file] of remoteFileMap) {
          const cs = file.data.checksum;
          if (!remoteByChecksum.has(cs)) {
            remoteByChecksum.set(cs, []);
          }
          remoteByChecksum.get(cs)!.push({ path, file });
        }

        const matchedLocalIndices = new Set<number>();
        
        for (let i = 0; i < localOnlyFiles.length; i++) {
          const localFile = localOnlyFiles[i];
          const localChecksum = calculateChecksum(localFile.content);
          const candidates = remoteByChecksum.get(localChecksum);
          
          if (candidates && candidates.length > 0) {
            const match = candidates.shift()!;
            if (!legacyRelativePath(match.path) || !legacyRelativePath(localFile.path)) continue;
            if (candidates.length === 0) {
              remoteByChecksum.delete(localChecksum);
            }
            
            console.log(`[Sync] Detected move by SHA-256 match: ${match.path} -> ${localFile.path}`);
            try {
              const result = await engine.moveFile(vault, match.path, localFile.path, localFile.content);
              vault = result.vault;
              movedCount++;
              remoteFileMap.delete(match.path);
              matchedLocalIndices.add(i);
            } catch (err) {
              console.error(`[Sync] Failed to process checksum move ${match.path} -> ${localFile.path}:`, err);
            }
          }
        }
        
        for (let i = localOnlyFiles.length - 1; i >= 0; i--) {
          if (matchedLocalIndices.has(i)) {
            localOnlyFiles.splice(i, 1);
          }
        }
      }

      // Upload remaining local-only files (truly new files)
      for (const localFile of localOnlyFiles) {
        if (!legacyRelativePath(localFile.path)) continue;
        console.log(`[Sync] Uploading new local file: ${localFile.path}`);
        const result = await engine.publishFile(vault, localFile.path, localFile.content);
        vault = result.vault;
        uploadedCount++;
      }

      // Download remote-only files (files that exist on remote but not locally)
      // Skip files that were deleted locally or are in the vault's deleted list
      for (const [path, remoteFile] of remoteFileMap) {
        if (!legacyRelativePath(path)) continue;
        // Skip if in vault's deleted list
        if (vault.data.deleted?.some(d => d.path === path)) {
          continue;
        }
        
        // Skip if locally deleted (but not yet synced)
        // Also check for folder deletions - if any deleted path is a prefix of this file path
        const isLocallyDeleted = locallyDeletedPaths.some(deletedPath => 
          path === deletedPath || path.startsWith(deletedPath + '/')
        );
        if (isLocallyDeleted) {
          continue;
        }

        const fullPath = `${vaultPath()}/${path}`;
        // A legacy path through a local alias would land this write inside a mount.
        if (!legacyPath(fullPath) || await managed.isManaged(fullPath)) continue;
        const parentDir = fullPath.substring(0, fullPath.lastIndexOf('/'));
        if (parentDir !== vaultPath() && legacyPath(parentDir)) {
          await platform.vault.createFolder(parentDir, vaultPath() ?? '').catch(() => {});
        }
        await platform.vault.write(fullPath, remoteFile.data.content, vaultPath() ?? '');
        downloadedCount++;
      }
      
      // Persist the d-tag map from the final vault state
      // This maps each file's relative path to its stable Nostr d-tag identity
      const updatedDtagMap: Record<string, string> = {};
      for (const fileEntry of vault.data.files) {
        if (legacyRelativePath(fileEntry.path)) updatedDtagMap[fileEntry.path] = fileEntry.d;
      }
      localStorage.setItem('file_dtag_map', JSON.stringify(updatedDtagMap));

      console.log(`[Sync] Complete: ${uploadedCount} uploaded, ${downloadedCount} downloaded, ${deletedCount} deleted, ${movedCount} moved`);

      setSyncStatus('idle');

      // Refresh sidebar and reload open tabs if files were downloaded
      if (downloadedCount > 0) {
        refreshSidebar?.();
        
        // Reload any open markdown tabs that may have been updated
        const currentTabs = tabs();
        for (let i = 0; i < currentTabs.length; i++) {
          const tab = currentTabs[i];
          if (tab.fileType !== 'markdown' || managedPath(tab.path)) continue;
          try {
            const newContent = await platform.vault.read(tab.path, vaultPath() ?? '');
            if (disposed || managedPath(tab.path)) continue;
            if (newContent !== tab.content) {
              setTabs(prev => prev.map((t, idx) =>
                idx === i ? { ...t, content: newContent, isDirty: false } : t
              ));
            }
          } catch {
            // File may have been deleted or moved
          }
        }
      }
    } catch (err) {
      console.error('Sync failed:', err);
      setSyncStatus('error');
      // Reset to idle after 3 seconds
      setTimeout(() => {
        if (syncStatus() === 'error') {
          setSyncStatus('idle');
        }
      }, 3000);
    }
  };

  // Open today's daily note
  const handleOpenDailyNote = async () => {
    const vault = vaultPath();
    if (!vault) return;
    
    const config = loadDailyNotesConfig();
    if (!config.enabled) {
      console.log('[DailyNotes] Daily notes are disabled');
      return;
    }
    
    try {
      const { path, isNew } = await writeManaged(`${vault}/${config.folder}`, () => openDailyNote(vault, config));
      console.log('[DailyNotes] Opened daily note:', path, isNew ? '(new)' : '(existing)');
      
      // Open the file in a tab
      const content = await platform.vault.read(path, vaultPath() ?? '');
      const name = path.split('/').pop() || 'Daily Note';
      
      // Check if tab already exists
      const existingIndex = tabs().findIndex(t => t.path === path);
      if (existingIndex >= 0) {
        setActiveTabIndex(existingIndex);
      } else {
        setTabs([...tabs(), { path, name, content, isDirty: false, fileType: 'markdown' }]);
        setActiveTabIndex(tabs().length - 1);
      }
      
      // Refresh sidebar to show new file/folder
      if (isNew) {
        refreshSidebar?.();
      }
    } catch (err) {
      console.error('[DailyNotes] Failed to open daily note:', err);
    }
  };

  // Open templates picker
  const handleOpenTemplatesPicker = async () => {
    const vault = vaultPath();
    if (!vault) return;
    
    setTemplatesLoading(true);
    try {
      const config = loadTemplatesConfig();
      const templates = await listTemplates(vault, config);
      setAvailableTemplates(templates);
      setShowTemplatesModal(true);
    } catch (err) {
      console.error('[Templates] Failed to load templates:', err);
    } finally {
      setTemplatesLoading(false);
    }
  };

  // Create note from selected template
  const handleCreateFromTemplate = async (template: TemplateInfo) => {
    const vault = vaultPath();
    if (!vault) return;
    
    const noteName = prompt('Enter note name:');
    if (!noteName) return;
    
    const targetFolder = prompt('Enter folder (or leave empty for root):', '') || '';
    
    try {
      // The template helper creates the folder as well as the note. Do not let
      // that directory operation intersect a mount; normal editor saves can.
      if (!legacyPath(`${vault}/${targetFolder}/${noteName}.md`) || managedPath(`${vault}/${targetFolder}`)) {
        throw new Error('Template destination intersects a shared vault');
      }
      const notePath = await createNoteFromTemplate(vault, template.path, targetFolder, noteName);
      
      // Open the new note
      const content = await platform.vault.read(notePath, vaultPath() ?? '');
      const name = notePath.split('/').pop() || noteName;
      
      setTabs([...tabs(), { path: notePath, name, content, isDirty: false, fileType: 'markdown' }]);
      setActiveTabIndex(tabs().length - 1);
      setShowTemplatesModal(false);
      
      // Refresh sidebar
      refreshSidebar?.();
    } catch (err) {
      console.error('[Templates] Failed to create note from template:', err);
    }
  };

  // Insert template content at cursor (for future use)
  // @ts-expect-error Reserved for future template insertion at cursor
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const handleInsertTemplate = async (template: TemplateInfo) => {
    try {
      const content = await getTemplateContent(template.path, {}, vaultPath() || undefined);
      // TODO: Insert at cursor position in editor
      console.log('[Templates] Template content to insert:', content.substring(0, 100));
      setShowTemplatesModal(false);
    } catch (err) {
      console.error('[Templates] Failed to get template content:', err);
    }
  };

  const commands = [
    { id: 'new-file', name: 'New File', action: () => console.log('New file - use sidebar') },
    { id: 'save', name: 'Save', shortcut: 'Ctrl+S', action: saveCurrentTab },
    { id: 'quick-switcher', name: 'Quick Switcher', shortcut: 'Ctrl+O', action: () => setShowQuickSwitcher(true) },
    { id: 'search', name: 'Search in Files', shortcut: 'Ctrl+Shift+F', action: () => setShowSearch(true) },
    { id: 'toggle-terminal', name: 'Toggle Terminal', shortcut: 'Ctrl+`', action: () => { if (!isWeb()) setShowTerminal(!showTerminal()); } },
    { id: 'toggle-outline', name: 'Toggle Outline', shortcut: 'Ctrl+Shift+O', action: () => setShowOutline(!showOutline()) },
    { id: 'toggle-backlinks', name: 'Toggle Backlinks', shortcut: 'Ctrl+Shift+B', action: () => setShowBacklinks(!showBacklinks()) },
    { id: 'toggle-properties', name: 'Toggle Properties', shortcut: 'Ctrl+Shift+P', action: () => setShowProperties(!showProperties()) },
    { id: 'close-tab', name: 'Close Tab', action: () => activeTabIndex() >= 0 && closeTab(activeTabIndex()) },
    { id: 'daily-note', name: 'Open Daily Note', shortcut: 'Ctrl+D', action: handleOpenDailyNote },
    { id: 'templates', name: 'Insert Template', shortcut: 'Ctrl+T', action: handleOpenTemplatesPicker },
  ];

  // Resize handlers for panels
  const handleSidebarResizeStart = (e: MouseEvent) => {
    e.preventDefault();
    setIsResizing('sidebar');
    setResizeStartX(e.clientX);
    setResizeStartWidth(sidebarWidth());
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const handleTerminalResizeStart = (e: MouseEvent) => {
    e.preventDefault();
    setIsResizing('terminal');
    setResizeStartX(e.clientX);
    setResizeStartWidth(terminalWidth());
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const handleOutlineResizeStart = (e: MouseEvent) => {
    e.preventDefault();
    setIsResizing('outline');
    setResizeStartX(e.clientX);
    setResizeStartWidth(outlineWidth());
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const handleBacklinksResizeStart = (e: MouseEvent) => {
    e.preventDefault();
    setIsResizing('backlinks');
    setResizeStartX(e.clientX);
    setResizeStartWidth(backlinksWidth());
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const handlePropertiesResizeStart = (e: MouseEvent) => {
    e.preventDefault();
    setIsResizing('properties');
    setResizeStartX(e.clientX);
    setResizeStartWidth(propertiesWidth());
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const handleNotificationsResizeStart = (e: MouseEvent) => {
    e.preventDefault();
    setIsResizing('notifications');
    setResizeStartX(e.clientX);
    setResizeStartWidth(notificationsWidth());
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  const handleResizeMove = (e: MouseEvent) => {
    const target = isResizing();
    if (!target) return;

    if (target === 'sidebar') {
      // Sidebar: dragging right = wider sidebar
      const delta = e.clientX - resizeStartX();
      const newWidth = resizeStartWidth() + delta;
      setSidebarWidth(Math.max(200, Math.min(500, newWidth)));
    } else if (target === 'terminal') {
      // Terminal: dragging left = wider terminal
      const delta = resizeStartX() - e.clientX;
      const newWidth = resizeStartWidth() + delta;
      setTerminalWidth(Math.max(300, Math.min(800, newWidth)));
    } else if (target === 'outline') {
      // Outline: dragging left = wider panel (same as terminal)
      const delta = resizeStartX() - e.clientX;
      const newWidth = resizeStartWidth() + delta;
      setOutlineWidth(Math.max(180, Math.min(400, newWidth)));
    } else if (target === 'backlinks') {
      // Backlinks: dragging left = wider panel (same as terminal)
      const delta = resizeStartX() - e.clientX;
      const newWidth = resizeStartWidth() + delta;
      setBacklinksWidth(Math.max(180, Math.min(400, newWidth)));
    } else if (target === 'properties') {
      // Properties: dragging left = wider panel (same as terminal)
      const delta = resizeStartX() - e.clientX;
      const newWidth = resizeStartWidth() + delta;
      setPropertiesWidth(Math.max(200, Math.min(400, newWidth)));
    } else if (target === 'notifications') {
      // Notifications: dragging left = wider panel (same as terminal)
      const delta = resizeStartX() - e.clientX;
      const newWidth = resizeStartWidth() + delta;
      setNotificationsWidth(Math.max(280, Math.min(450, newWidth)));
    }
  };

  const handleResizeEnd = () => {
    if (isResizing()) {
      setIsResizing(null);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }
  };

  // Add global mouse listeners for resize
  onMount(() => {
    document.addEventListener('mousemove', handleResizeMove);
    document.addEventListener('mouseup', handleResizeEnd);
    return () => {
      document.removeEventListener('mousemove', handleResizeMove);
      document.removeEventListener('mouseup', handleResizeEnd);
    };
  });

  // Handle mobile navigation tab changes
  const handleMobileNavChange = (tab: MobileNavTab) => {
    setMobileNavTab(tab);
    if (tab === 'files' || tab === 'search' || tab === 'bookmarks') {
      setSidebarView(tab);
      setMobileDrawerOpen(true);
    } else if (tab === 'settings') {
      setShowSettings(true);
    }
  };

  // Get current file title for mobile header
  const currentFileTitle = () => {
    const tab = currentTab();
    if (showGraphView()) return 'Graph View';
    if (!tab) return 'Onyx';
    return tab.name.replace(/\.md$/, '');
  };

  return (
    <div class={`app ${isMobileApp() ? 'mobile' : ''}`}>
      {/* Mobile Header - Only shown on mobile */}
      <Show when={isMobileApp()}>
        <MobileHeader
          title={currentFileTitle()}
          isDirty={currentTab()?.isDirty}
          onMenuClick={() => setMobileDrawerOpen(true)}
          onNotificationsClick={() => setShowNotifications(!showNotifications())}
          unreadNotifications={unreadShareCount()}
          onSyncClick={() => handleStatusBarSync()}
          syncStatus={syncStatus()}
          onMoreClick={() => setMobileMoreMenu(!mobileMoreMenu())}
        />
      </Show>

      {/* Mobile More Menu - panel toggles */}
      <Show when={isMobileApp() && mobileMoreMenu()}>
        <div class="mobile-more-backdrop" onClick={() => setMobileMoreMenu(false)}>
          <div class="mobile-more-menu" onClick={(e) => e.stopPropagation()}>
            <div
              class={`mobile-more-item ${showOutline() ? 'active' : ''}`}
              onClick={() => { setShowOutline(!showOutline()); setMobileMoreMenu(false); }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="8" y1="6" x2="21" y2="6"></line>
                <line x1="8" y1="12" x2="21" y2="12"></line>
                <line x1="8" y1="18" x2="21" y2="18"></line>
                <line x1="3" y1="6" x2="3.01" y2="6"></line>
                <line x1="3" y1="12" x2="3.01" y2="12"></line>
                <line x1="3" y1="18" x2="3.01" y2="18"></line>
              </svg>
              <span>Outline</span>
            </div>
            <div
              class={`mobile-more-item ${showBacklinks() ? 'active' : ''}`}
              onClick={() => { setShowBacklinks(!showBacklinks()); setMobileMoreMenu(false); }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 17H7A5 5 0 0 1 7 7h2"></path>
                <path d="M15 7h2a5 5 0 1 1 0 10h-2"></path>
                <line x1="8" y1="12" x2="16" y2="12"></line>
              </svg>
              <span>Backlinks</span>
            </div>
            <div
              class={`mobile-more-item ${showGraphView() ? 'active' : ''}`}
              onClick={() => { setShowGraphView(!showGraphView()); setMobileMoreMenu(false); }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="6" cy="6" r="3"></circle>
                <circle cx="18" cy="6" r="3"></circle>
                <circle cx="6" cy="18" r="3"></circle>
                <circle cx="18" cy="18" r="3"></circle>
                <line x1="8.5" y1="7.5" x2="15.5" y2="16.5"></line>
                <line x1="15.5" y1="7.5" x2="8.5" y2="16.5"></line>
              </svg>
              <span>Graph View</span>
            </div>
            <div
              class={`mobile-more-item ${showProperties() ? 'active' : ''}`}
              onClick={() => { setShowProperties(!showProperties()); setMobileMoreMenu(false); }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
              </svg>
              <span>Properties</span>
            </div>
          </div>
        </div>
      </Show>

      {/* Mobile Drawer - Only shown on mobile */}
      <Show when={isMobileApp()}>
        <MobileDrawer
          isOpen={mobileDrawerOpen()}
          onClose={() => setMobileDrawerOpen(false)}
        >
          <Sidebar
            onFileSelect={(path) => {
              openFile(path);
              setMobileDrawerOpen(false);
            }}
            currentFile={currentTab()?.path || null}
            vaultPath={vaultPath()}
            onVaultOpen={setVaultPath}
            onFileCreated={handleFileCreated}
            onFileDeleted={handleFileDeleted}
            onFileMoved={handleFileMoved}
            view={sidebarView()}
            bookmarks={bookmarks()}
            onToggleBookmark={toggleBookmark}
            savedSearches={savedSearches()}
            onToggleSavedSearch={toggleSavedSearch}
            exposeCreateNote={(fn) => { createNoteFromSidebar = fn; }}
            exposeRefresh={(fn) => { refreshSidebar = fn; }}
            exposeSearchQuery={(fn) => { setSearchQuery = fn; }}
            onShareFile={handleShareFile}
            onFileInfo={handleFileInfo}
            onPostToNostr={handlePostToNostr}
            expandedFolders={expandedFolders()}
            onExpandedFoldersChange={setExpandedFolders}
            fileContents={fileContents()}
            sharedVaultMounts={sharedVaultMountsFromSnapshot(vaultSnapshot() ?? EMPTY_VAULT_SNAPSHOT)}
            canMutatePath={canMutateSharedPath}
            onCreateSharedVault={createSharedVault}
            onAttachSharedVault={attachSharedVault}
            onManageSharedVault={manageSharedVault}
            onSyncSharedVault={id => { void vaultEngine()?.sync(id).catch(err => setVaultError(String(err))); }}
          />
        </MobileDrawer>
      </Show>

      {/* Mobile Bottom Navigation - Only shown on mobile */}
      <Show when={isMobileApp()}>
        <MobileNav
          activeTab={mobileNavTab()}
          onTabChange={handleMobileNavChange}
        />
      </Show>

      {/* Left Icon Bar - Hidden on mobile via CSS */}
      <div class="icon-bar">
        <button
          class={`icon-btn ${!sidebarCollapsed() && sidebarView() === 'files' ? 'active' : ''}`}
          onClick={() => switchSidebarView('files')}
          title="Files"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
          </svg>
        </button>
        <button
          class={`icon-btn ${!sidebarCollapsed() && sidebarView() === 'search' ? 'active' : ''}`}
          onClick={() => switchSidebarView('search')}
          title="Search"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"></circle>
            <path d="m21 21-4.35-4.35"></path>
          </svg>
        </button>
        <button
          class={`icon-btn ${!sidebarCollapsed() && sidebarView() === 'bookmarks' ? 'active' : ''}`}
          onClick={() => switchSidebarView('bookmarks')}
          title="Bookmarks"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="m19 21-7-4-7 4V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16z"></path>
          </svg>
        </button>
        <button
          class={`icon-btn ${showGraphView() ? 'active' : ''}`}
          onClick={() => setShowGraphView(true)}
          title="Graph View"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="6" cy="6" r="3"></circle>
            <circle cx="18" cy="6" r="3"></circle>
            <circle cx="6" cy="18" r="3"></circle>
            <circle cx="18" cy="18" r="3"></circle>
            <line x1="8.5" y1="7.5" x2="15.5" y2="16.5"></line>
            <line x1="15.5" y1="7.5" x2="8.5" y2="16.5"></line>
          </svg>
        </button>
        <button
          class={`icon-btn ${showOutline() ? 'active' : ''}`}
          onClick={() => setShowOutline(!showOutline())}
          title="Outline (Ctrl+Shift+O)"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="8" y1="6" x2="21" y2="6"></line>
            <line x1="8" y1="12" x2="21" y2="12"></line>
            <line x1="8" y1="18" x2="21" y2="18"></line>
            <line x1="3" y1="6" x2="3.01" y2="6"></line>
            <line x1="3" y1="12" x2="3.01" y2="12"></line>
            <line x1="3" y1="18" x2="3.01" y2="18"></line>
          </svg>
        </button>
        <button
          class={`icon-btn ${showBacklinks() ? 'active' : ''}`}
          onClick={() => setShowBacklinks(!showBacklinks())}
          title="Backlinks (Ctrl+Shift+B)"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 17H7A5 5 0 0 1 7 7h2"></path>
            <path d="M15 7h2a5 5 0 1 1 0 10h-2"></path>
            <line x1="8" y1="12" x2="16" y2="12"></line>
          </svg>
        </button>
        <button
          class={`icon-btn ${showProperties() ? 'active' : ''}`}
          onClick={() => setShowProperties(!showProperties())}
          title="Properties (Ctrl+Shift+P)"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
          </svg>
        </button>
        <button
          class={`icon-btn ${showNotifications() ? 'active' : ''}`}
          onClick={() => setShowNotifications(!showNotifications())}
          title="Shared with me"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
            <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
          </svg>
          <Show when={unreadShareCount() > 0}>
            <span class="notification-badge">{unreadShareCount()}</span>
          </Show>
        </button>
        <div class="icon-bar-spacer"></div>
        {/* OpenClaw button - Hidden on mobile, only shown when enabled */}
        <Show when={!isMobileApp() && !isWeb() && openClawEnabled()}>
          <button
            class={`icon-btn openclaw-icon ${showOpenClaw() ? 'active' : ''}`}
            onClick={async () => {
              const url = localStorage.getItem('openclaw_url');
              const token = await getOpenClawToken();
              if (!url || !token) {
                setSettingsSection('openclaw');
                setShowSettings(true);
              } else {
                setShowOpenClaw(!showOpenClaw());
              }
            }}
            title="Toggle OpenClaw"
          >
            <svg width="22" height="22" viewBox="0 0 512 512" fill="currentColor">
              <path d="m175.656 22.375-48.47 82.094c-23.017 4.384-43.547 11.782-60.124 22.374-24.436 15.613-40.572 37.414-45.5 67.875-4.79 29.62 1.568 68.087 24.125 116.093 93.162 22.88 184.08-10.908 257.25-18.813 37.138-4.012 71.196-.898 96.344 22.97 22.33 21.19 36.21 56.808 41.908 113.436 29.246-35.682 44.538-69.065 49.343-99.594 5.543-35.207-2.526-66.97-20.31-95.593-8.52-13.708-19.368-26.618-32-38.626l14.217-33-41.218 10.625c-8.637-6.278-17.765-12.217-27.314-17.782l-7.03-59.782-38.157 37.406a423.505 423.505 0 0 0-38.158-13.812l-8.375-71.28-57.625 56.5c-9.344-1.316-18.625-2.333-27.812-2.97l-31.094-78.125zM222 325.345c-39.146 7.525-82.183 14.312-127.156 11.686 47.403 113.454 207.056 224.082 260.125 87-101.18 33.84-95.303-49.595-132.97-98.686z"/>
            </svg>
          </button>
        </Show>
        {/* Custom Provider button - Hidden on mobile, only shown when enabled */}
        <Show when={!isMobileApp() && !isWeb() && customProviderEnabled()}>
          <button
            class={`icon-btn custom-provider-icon ${showCustomProvider() ? 'active' : ''}`}
            onClick={() => {
              const url = localStorage.getItem('custom_provider_url');
              if (!url) {
                setSettingsSection('customprovider');
                setShowSettings(true);
              } else {
                setShowCustomProvider(!showCustomProvider());
              }
            }}
            title="Toggle Custom Provider"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
              <path d="M2 17l10 5 10-5"></path>
              <path d="M2 12l10 5 10-5"></path>
            </svg>
          </button>
        </Show>
        {/* OpenCode button - Hidden on mobile, only shown when enabled */}
        <Show when={!isMobileApp() && !isWeb() && openCodeEnabled()}>
          <button
            class={`icon-btn opencode-icon ${showTerminal() ? 'active' : ''}`}
            onClick={() => setShowTerminal(!showTerminal())}
            title="Toggle OpenCode (Ctrl+`)"
          >
            <svg width="24" height="24" viewBox="0 0 512 512" fill="currentColor">
              <path fill-rule="evenodd" clip-rule="evenodd" d="M384 416H128V96H384V416ZM320 160H192V352H320V160Z"/>
            </svg>
          </button>
        </Show>
        <button
          class={`icon-btn ${showSettings() ? 'active' : ''}`}
          onClick={() => setShowSettings(true)}
          title="Settings"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </button>
        <button
          class="icon-btn"
          onClick={() => setSidebarCollapsed(!sidebarCollapsed())}
          title={sidebarCollapsed() ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
            <line x1="9" y1="3" x2="9" y2="21"></line>
          </svg>
        </button>
      </div>

      {/* Sidebar - Hidden on mobile, use drawer instead */}
      <Show when={!sidebarCollapsed() && !isMobileApp()}>
        <div style={{ width: `${sidebarWidth()}px`, 'flex-shrink': 0 }}>
          <Sidebar
            onFileSelect={openFile}
            currentFile={currentTab()?.path || null}
            vaultPath={vaultPath()}
            onVaultOpen={setVaultPath}
            onFileCreated={handleFileCreated}
            onFileDeleted={handleFileDeleted}
            onFileMoved={handleFileMoved}
            view={sidebarView()}
            bookmarks={bookmarks()}
            onToggleBookmark={toggleBookmark}
            savedSearches={savedSearches()}
            onToggleSavedSearch={toggleSavedSearch}
            exposeCreateNote={(fn) => { createNoteFromSidebar = fn; }}
            exposeRefresh={(fn) => { refreshSidebar = fn; }}
            exposeSearchQuery={(fn) => { setSearchQuery = fn; }}
            onShareFile={handleShareFile}
            onFileInfo={handleFileInfo}
            onPostToNostr={handlePostToNostr}
            expandedFolders={expandedFolders()}
            onExpandedFoldersChange={setExpandedFolders}
            fileContents={fileContents()}
            sharedVaultMounts={sharedVaultMountsFromSnapshot(vaultSnapshot() ?? EMPTY_VAULT_SNAPSHOT)}
            canMutatePath={canMutateSharedPath}
            onCreateSharedVault={createSharedVault}
            onAttachSharedVault={attachSharedVault}
            onManageSharedVault={manageSharedVault}
            onSyncSharedVault={id => { void vaultEngine()?.sync(id).catch(err => setVaultError(String(err))); }}
          />
        </div>
        <div
          class="resize-handle"
          onMouseDown={handleSidebarResizeStart}
        />
      </Show>
      <main class="main-content">
        {/* Toolbar */}
        <div class="toolbar">
          <div class="toolbar-left">
            {/* Tab Bar */}
            <Show when={tabs().length > 0 || showGraphView()}>
              <div class="tab-bar">
                <For each={tabs()}>
                  {(tab, index) => (
                    <div
                      class={`tab ${index() === activeTabIndex() && !showGraphView() ? 'active' : ''}`}
                      onClick={() => { setShowGraphView(false); setActiveTabIndex(index()); }}
                    >
                      <span class="tab-name">{tab.isDirty ? '● ' : ''}{tab.name}</span>
                      <button
                        class="tab-close"
                        onClick={(e) => {
                          e.stopPropagation();
                          closeTab(index());
                        }}
                      >
                        ×
                      </button>
                    </div>
                  )}
                </For>
                <Show when={showGraphView()}>
                  <div class={`tab graph-tab active`}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <circle cx="6" cy="6" r="3"></circle>
                      <circle cx="18" cy="6" r="3"></circle>
                      <circle cx="6" cy="18" r="3"></circle>
                      <circle cx="18" cy="18" r="3"></circle>
                      <line x1="8.5" y1="7.5" x2="15.5" y2="16.5"></line>
                      <line x1="15.5" y1="7.5" x2="8.5" y2="16.5"></line>
                    </svg>
                    <span class="tab-name">Graph</span>
                    <button
                      class="tab-close"
                      onClick={(e) => {
                        e.stopPropagation();
                        setShowGraphView(false);
                      }}
                    >
                      ×
                    </button>
                  </div>
                </Show>
              </div>
            </Show>
          </div>
          <div class="toolbar-right">
            {/* Reserved for future toolbar actions */}
          </div>
        </div>

        {/* Editor + Terminal horizontal layout */}
        <div class="content-area">
          {/* Editor, Viewer, or Graph View */}
          <div class="editor-area" inert={!!currentTab() && (editorHeld(currentTab()!.path) || managedReadOnly(currentTab()!.path))}>
            <Show when={currentTab()?.fileType && currentTab()!.fileType !== 'markdown'} fallback={
              <Show when={showGraphView()} fallback={
                <Editor
                  content={currentTab()?.content || ''}
                  onContentChange={updateTabContent}
                  filePath={currentTab()?.path || null}
                  vaultPath={vaultPath()}
                  onCreateFile={createNewNote}
                  onOpenVault={openVault}
                  onHashtagClick={handleHashtagClick}
                  scrollToLine={scrollToLine()}
                  onScrollComplete={() => setScrollToLine(null)}
                  onWikilinkClick={handleWikilinkClick}
                  noteIndex={noteIndex()}
                  assetIndex={assetIndex()}
                  fileContents={fileContents()}
                  onHeadingsChange={setCurrentHeadings}
                  onActiveHeadingChange={setActiveHeadingId}
                  scrollToHeadingId={scrollToHeadingId()}
                  scrollToHeadingText={scrollToHeadingText()}
                  scrollToBlockId={scrollToBlockId()}
                  viewMode={editorViewMode()}
                  onFilesUploaded={async () => {
                    // Rebuild asset index after files are uploaded
                    if (vaultPath()) {
                      try {
                        const assets = await platform.vault.listAssets(vaultPath()!);
                        setAssetIndex(buildAssetIndex(assets, vaultPath()!));
                      } catch (err) {
                        console.error('Failed to rebuild asset index after upload:', err);
                      }
                    }
                  }}
                />
              }>
                <GraphView
                  vaultPath={vaultPath()}
                  noteIndex={noteIndex()}
                  noteGraph={noteGraph()}
                  currentFile={currentTab()?.path || null}
                  onNodeClick={(path) => { setShowGraphView(false); openFile(path); }}
                />
              </Show>
            }>
              {/* File viewer for non-markdown files */}
              <div class="file-viewer">
                <Show when={currentTab()?.fileType === 'image'}>
                  <div class="image-viewer">
                    <img
                      src={imageTabSrc() ?? ''}
                      alt={currentTab()!.name}
                      draggable={false}
                    />
                  </div>
                </Show>
                <Show when={currentTab()?.fileType === 'pdf'}>
                  <PdfViewer path={currentTab()!.path} vaultPath={vaultPath()} />
                </Show>
                <Show when={currentTab()?.fileType === 'docx'}>
                  <DocxViewer path={currentTab()!.path} vaultPath={vaultPath()} />
                </Show>
                <Show when={currentTab()?.fileType === 'xlsx'}>
                  <XlsxViewer path={currentTab()!.path} vaultPath={vaultPath()} />
                </Show>
                <Show when={currentTab()?.fileType === 'pptx'}>
                  <PptxViewer path={currentTab()!.path} vaultPath={vaultPath()} />
                </Show>
              </div>
            </Show>
          </div>

          {/* Outline Panel - Right Side */}
          <Show when={showOutline() && currentTab()}>
            <div
              class="resize-handle"
              onMouseDown={handleOutlineResizeStart}
            />
            <div class="outline-panel-container" style={{ width: `${outlineWidth()}px` }}>
              <OutlinePanel
                headings={currentHeadings()}
                activeHeadingId={activeHeadingId()}
                onHeadingClick={(id) => {
                  setScrollToHeadingId(id);
                  setTimeout(() => setScrollToHeadingId(null), 100);
                }}
                onClose={() => setShowOutline(false)}
              />
            </div>
          </Show>

          {/* Backlinks Panel - Right Side */}
          <Show when={showBacklinks() && currentTab()}>
            <div
              class="resize-handle"
              onMouseDown={handleBacklinksResizeStart}
            />
            <div class="backlinks-panel-container" style={{ width: `${backlinksWidth()}px` }}>
              <BacklinksPanel
                currentFilePath={currentTab()?.path || null}
                currentFileName={currentTab()?.name || null}
                graph={noteGraph()}
                fileContents={fileContents()}
                vaultPath={vaultPath()}
                onBacklinkClick={(path, line) => openFile(path, line)}
                onClose={() => setShowBacklinks(false)}
                onLinkMention={async (sourcePath) => {
                  // Re-read just the modified file, update the content cache,
                  // and rebuild the graph from memory
                  refreshContentsForPaths([sourcePath]);
                }}
              />
            </div>
          </Show>

          {/* Properties Panel - Right Side */}
          <Show when={showProperties() && currentTab()}>
            <div
              class="resize-handle"
              onMouseDown={handlePropertiesResizeStart}
            />
            <div class="properties-panel-container" style={{ width: `${propertiesWidth()}px` }}>
              <PropertiesPanel
                content={currentTab()?.content || null}
                onUpdateContent={(newContent) => {
                  const idx = activeTabIndex();
                  if (idx >= 0) {
                    setTabs(tabs().map((t, i) => i === idx ? { ...t, content: newContent, isDirty: true } : t));
                    // Trigger auto-save
                    if (autoSaveTimeout) clearTimeout(autoSaveTimeout);
                    autoSaveTimeout = window.setTimeout(() => {
                      saveTab(idx);
                    }, 2000);
                  }
                }}
                onClose={() => setShowProperties(false)}
              />
            </div>
          </Show>

          {/* Notifications Panel - Right Side */}
          <Show when={showNotifications()}>
            <div
              class="resize-handle"
              onMouseDown={handleNotificationsResizeStart}
            />
            <div class="notifications-panel-container" style={{ width: `${notificationsWidth()}px` }}>
              <NotificationsPanel
                sharedDocuments={sharedWithMe()}
                isLoading={isLoadingShares()}
                onPreview={handlePreviewSharedDoc}
                vaultInvitations={vaultSnapshot()?.invitations}
                profileRelays={defaultProfileRelays(vaultSnapshot())}
                onPreviewVaultInvitation={invitation => { setAttachFolder(undefined); setInvitationId(invitation.invitationId); }}
                onRefresh={() => { void fetchSharedDocuments(); void vaultEngine()?.refreshInbox().catch(err => setVaultError(String(err))); }}
                onClose={() => setShowNotifications(false)}
              />
            </div>
          </Show>

          {/* OpenClaw Panel - Right Side (Desktop only) */}
          <Show when={showOpenClaw() && !isMobileApp() && !isWeb()}>
            <div
              class="resize-handle"
              onMouseDown={(e: MouseEvent) => {
                e.preventDefault();
                setIsResizing('terminal');
                const startX = e.clientX;
                const startWidth = openClawWidth();
                const handleMouseMove = (e: MouseEvent) => {
                  const delta = startX - e.clientX;
                  const newWidth = Math.max(300, Math.min(startWidth + delta, window.innerWidth * 0.6));
                  setOpenClawWidth(newWidth);
                };
                const handleMouseUp = () => {
                  setIsResizing(null);
                  localStorage.setItem('openclaw_width', openClawWidth().toString());
                  document.removeEventListener('mousemove', handleMouseMove);
                  document.removeEventListener('mouseup', handleMouseUp);
                };
                document.addEventListener('mousemove', handleMouseMove);
                document.addEventListener('mouseup', handleMouseUp);
              }}
            />
            <div style={{ width: `${openClawWidth()}px` }}>
              <OpenClawChat
                onClose={() => setShowOpenClaw(false)}
                onOpenSettings={() => {
                  setSettingsSection('openclaw');
                  setShowSettings(true);
                }}
                vaultPath={vaultPath()}
                currentFile={currentTab() ? { path: currentTab()!.path, content: currentTab()!.content } : null}
                vaultFiles={noteIndex() ? Array.from(noteIndex()!.allPaths).map(path => ({
                  path,
                  name: path.replace(/\\/g, '/').split('/').pop()?.replace(/\.md$/i, '') || path
                })) : []}
              />
            </div>
          </Show>

          {/* Custom Provider Panel - Right Side (Desktop only) */}
          <Show when={showCustomProvider() && !isMobileApp() && !isWeb()}>
            <div
              class="resize-handle"
              onMouseDown={(e: MouseEvent) => {
                e.preventDefault();
                setIsResizing('terminal');
                const startX = e.clientX;
                const startWidth = customProviderWidth();
                const handleMouseMove = (e: MouseEvent) => {
                  const delta = startX - e.clientX;
                  const newWidth = Math.max(300, Math.min(startWidth + delta, window.innerWidth * 0.6));
                  setCustomProviderWidth(newWidth);
                };
                const handleMouseUp = () => {
                  setIsResizing(null);
                  localStorage.setItem('custom_provider_width', customProviderWidth().toString());
                  document.removeEventListener('mousemove', handleMouseMove);
                  document.removeEventListener('mouseup', handleMouseUp);
                };
                document.addEventListener('mousemove', handleMouseMove);
                document.addEventListener('mouseup', handleMouseUp);
              }}
            />
            <div style={{ width: `${customProviderWidth()}px` }}>
              <CustomProviderChat
                onClose={() => setShowCustomProvider(false)}
                onOpenSettings={() => {
                  setSettingsSection('customprovider');
                  setShowSettings(true);
                }}
                vaultPath={vaultPath()}
                currentFile={currentTab() ? { path: currentTab()!.path, content: currentTab()!.content } : null}
                vaultFiles={noteIndex() ? Array.from(noteIndex()!.allPaths).map(path => ({
                  path,
                  name: path.replace(/\\/g, '/').split('/').pop()?.replace(/\.md$/i, '') || path
                })) : []}
              />
            </div>
          </Show>

          {/* OpenCode Panel - Right Side (Desktop only) */}
          <Show when={showTerminal() && !isMobileApp() && !isWeb()}>
            <div
              class="resize-handle"
              onMouseDown={handleTerminalResizeStart}
            />
            <div style={{ width: `${terminalWidth()}px` }}>
              <OpenCodePanel
                vaultPath={vaultPath()}
                currentFile={currentTab() ? { path: currentTab()!.path, content: currentTab()!.content } : null}
                vaultFiles={noteIndex() ? Array.from(noteIndex()!.allPaths).map(path => ({
                  path,
                  name: path.replace(/\\/g, '/').split('/').pop()?.replace(/\.md$/i, '') || path
                })) : []}
                onClose={() => setShowTerminal(false)}
                onOpenSettings={() => {
                  setSettingsSection('opencode');
                  setShowSettings(true);
                }}
              />
            </div>
          </Show>
        </div>

        {/* Status Bar */}
        <div class="status-bar">
          <div class="status-bar-left">
            {/* Future: git branch, etc */}
          </div>
          <div class="status-bar-right">
            <Show when={currentTab()}>
              <span class="status-item">{wordCount()} words</span>
              <span class="status-item">{charCount()} characters</span>
            </Show>
            <span
              class={`status-item sync-status ${syncStatus()} ${syncStatus() !== 'off' && syncStatus() !== 'syncing' ? 'clickable' : ''}`}
              title={
                syncStatus() === 'off' ? 'Sync disabled' :
                syncStatus() === 'idle' ? 'Click to sync' :
                syncStatus() === 'syncing' ? 'Syncing...' :
                'Sync error - Click to retry'
              }
              onClick={handleStatusBarSync}
            >
              <Show when={syncStatus() === 'off'}>
                {/* Cloud with slash - sync disabled */}
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"></path>
                  <line x1="4" y1="4" x2="20" y2="20"></line>
                </svg>
              </Show>
              <Show when={syncStatus() === 'idle' || syncStatus() === 'syncing'}>
                {/* Cloud with sync arrows */}
                <svg class={syncStatus() === 'syncing' ? 'cloud-syncing' : ''} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"></path>
                  <Show when={syncStatus() === 'syncing'}>
                    <g class="sync-arrows">
                      <path d="M12 14v3m0 0l-1.5-1.5M12 17l1.5-1.5" stroke-width="1.5"></path>
                      <path d="M12 12V9m0 0l1.5 1.5M12 9l-1.5 1.5" stroke-width="1.5"></path>
                    </g>
                  </Show>
                </svg>
              </Show>
              <Show when={syncStatus() === 'error'}>
                {/* Warning triangle - error */}
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                  <line x1="12" y1="9" x2="12" y2="13"></line>
                  <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
              </Show>
            </span>
            <SharedVaultEngineStatus snapshot={vaultSnapshot()} error={vaultError()}
              onOpen={() => { setAttachFolder(undefined); setShowVaults(true); }} />
            {/* Editor view mode toggle */}
            <Show when={currentTab()}>
              <button
                class="status-item view-mode-toggle"
                onClick={async () => {
                  // Save current tab to disk before switching modes so the
                  // other editor loads the latest content from disk.
                  const idx = activeTabIndex();
                  if (idx >= 0) {
                    await saveTab(idx);
                    if (tabs()[idx]?.isDirty) return;
                    // Reload content from disk into tab state so the other
                    // editor gets the canonical disk version
                    const tab = tabs()[idx];
                    if (tab?.path) {
                      try {
                        const diskContent = await platform.vault.read(tab.path, vaultPath() ?? '');
                        setTabs(tabs().map((t, i) => i === idx ? { ...t, content: diskContent, isDirty: false } : t));
                      } catch (err) {
                        console.error('Failed to reload content on mode switch:', err);
                      }
                    }
                  }
                  const newMode = editorViewMode() === 'live' ? 'source' : 'live';
                  setEditorViewMode(newMode);
                  localStorage.setItem('editor_view_mode', newMode);
                }}
                title={editorViewMode() === 'live' ? 'Switch to Source View' : 'Switch to Live Preview'}
              >
                <Show when={editorViewMode() === 'live'} fallback={
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 19l7-7 3 3-7 7-3-3z"></path>
                    <path d="M18 13l-1.5-7.5L2 2l3.5 14.5L13 18l5-5z"></path>
                    <path d="M2 2l7.586 7.586"></path>
                    <circle cx="11" cy="11" r="2"></circle>
                  </svg>
                }>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                  </svg>
                </Show>
                <span>{editorViewMode() === 'live' ? 'Live' : 'Source'}</span>
              </button>
            </Show>
          </div>
        </div>
      </main>

      {/* Modals */}
      
      {/* Web-only: prompt for master passphrase before any secrets are touched */}
      <Show when={webLocked()}>
        <UnlockDialog onUnlocked={() => setWebLocked(false)} />
      </Show>

      {/* Onboarding Wizard - shown on first run */}
      <Show when={showOnboarding() && !webLocked()}>
        <Onboarding
          isMobile={isMobileApp()}
          onComplete={handleOnboardingComplete}
        />
      </Show>

      <Show when={showQuickSwitcher()}>
        <QuickSwitcher
          vaultPath={vaultPath()}
          onSelect={(path) => {
            openFile(path);
            setShowQuickSwitcher(false);
          }}
          onClose={() => setShowQuickSwitcher(false)}
        />
      </Show>

      <Show when={showCommandPalette()}>
        <CommandPalette
          commands={commands}
          onClose={() => setShowCommandPalette(false)}
        />
      </Show>

      {/* Templates Modal */}
      <Show when={showTemplatesModal()}>
        <div class="modal-overlay" onClick={() => setShowTemplatesModal(false)}>
          <div class="templates-modal" onClick={(e) => e.stopPropagation()}>
            <div class="templates-modal-header">
              <h3>Insert Template</h3>
              <button class="modal-close" onClick={() => setShowTemplatesModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>
            <div class="templates-modal-body">
              <Show when={templatesLoading()}>
                <div class="templates-loading">
                  <div class="spinner"></div>
                  <span>Loading templates...</span>
                </div>
              </Show>
              <Show when={!templatesLoading() && availableTemplates().length === 0}>
                <div class="templates-empty">
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="12" y1="18" x2="12" y2="12"></line>
                    <line x1="9" y1="15" x2="15" y2="15"></line>
                  </svg>
                  <p>No templates found</p>
                  <span class="templates-hint">Create templates in the "{loadTemplatesConfig().folder}" folder</span>
                </div>
              </Show>
              <Show when={!templatesLoading() && availableTemplates().length > 0}>
                <div class="templates-list">
                  <For each={availableTemplates()}>
                    {(template) => (
                      <button
                        class="template-item"
                        onClick={() => handleCreateFromTemplate(template)}
                      >
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                          <polyline points="14 2 14 8 20 8"></polyline>
                        </svg>
                        <span>{template.name}</span>
                      </button>
                    )}
                  </For>
                </div>
              </Show>
            </div>
          </div>
        </div>
      </Show>

      <Show when={showSearch()}>
        <SearchPanel
          vaultPath={vaultPath()}
          fileContents={fileContents()}
          onSelect={(path) => {
            openFile(path);
            setShowSearch(false);
          }}
          onClose={() => setShowSearch(false)}
        />
      </Show>

      <Show when={showSettings()}>
        <Settings
            vaultEngine={vaultEngine()}
            sharedVaultSettings={<Show when={vaultEngine()} fallback={<SharedVaultEngineStatus snapshot={vaultSnapshot()} error={vaultError()} onRetry={() => { void refreshVaultIdentity(); }} onRepairInbox={() => { void vaultEngine()?.repairInbox().catch(err => setVaultError(String(err))); }} />}>{engine => (
              <SharedVaultSettings engine={engine()} snapshot={vaultSnapshot()} onManageVault={manageSharedVault}
                  startupError={vaultError()} onRetry={() => { void refreshVaultIdentity(); }} onRepairInbox={() => { void vaultEngine()?.repairInbox().catch(err => setVaultError(String(err))); }}
                deviceKeys={{
                  get state() { return vaultSnapshot()?.deviceKeys ?? engine().deviceKeys.getState(); },
                  setEnabled: enabled => engine().deviceKeys.setEnabled(enabled),
                  setAllowIdentityFallback: allow => engine().deviceKeys.useIdentityFallback(allow),
                  generate: () => engine().deviceKeys.generate(),
                  import: secret => engine().deviceKeys.import(secret),
                  announce: () => engine().deviceKeys.announce(),
                  approveRecipientKey: (identity, key) => engine().deviceKeys.approveRecipientKey(identity, key),
                  resetRecipientPin: identity => engine().deviceKeys.resetRecipientPin(identity),
                }} />
            )}</Show>}
            onManageSharedVault={manageSharedVault}
          onIdentityChange={refreshVaultIdentity}
          onClose={() => {
            setShowSettings(false);
            setSettingsSection(undefined);
          }}
          vaultPath={vaultPath()}
          onSyncComplete={() => refreshSidebar?.()}
          onSyncEnabledChange={(enabled) => setSyncStatus(enabled ? 'idle' : 'off')}
          initialSection={settingsSection() as 'general' | 'editor' | 'files' | 'appearance' | 'hotkeys' | 'opencode' | 'openclaw' | 'customprovider' | 'productivity' | 'sync' | 'nostr' | 'about' | undefined}
        />
      </Show>

      {/* Close Tab Confirmation Modal */}
      <Show when={closeTabConfirm()}>
        <div class="modal-overlay" onClick={() => setCloseTabConfirm(null)}>
          <div class="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div class="modal-header">
              <h3>Unsaved Changes</h3>
              <button class="modal-close" onClick={() => setCloseTabConfirm(null)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>
            <div class="modal-body">
              <p>Do you want to save changes to "{closeTabConfirm()!.name}" before closing?</p>
            </div>
            <div class="modal-footer">
              <button class="setting-button secondary" onClick={() => setCloseTabConfirm(null)}>Cancel</button>
              <button class="setting-button secondary" onClick={handleCloseTabDiscard}>Don't Save</button>
              <button class="setting-button" onClick={handleCloseTabSave}>Save</button>
            </div>
          </div>
        </div>
      </Show>

      {/* Share Dialog */}
      <Show when={showShareDialog() && shareTarget()}>
        <ShareDialog
          filePath={shareTarget()!.path}
          content={shareTarget()!.content}
          title={shareTarget()!.title}
          onClose={() => {
            setShowShareDialog(false);
            setShareTarget(null);
          }}
          onSuccess={() => {
            fetchSharedDocuments();
          }}
        />
      </Show>

      {/* Shared Document Preview */}
      <Show when={previewingDoc()}>
        <SharedDocPreview
          document={previewingDoc()!}
          onImport={handleImportSharedDoc}
          onDismiss={handleDismissSharedDoc}
          onBlockUser={handleBlockUser}
          onClose={() => setPreviewingDoc(null)}
          isImporting={isImporting()}
        />
      </Show>

      {/* Sent Shares Panel */}
      <Show when={showSentShares()}>
        <SentSharesPanel
          sentShares={sentShares()}
          isLoading={isLoadingShares()}
          onRevoke={handleRevokeShare}
          onRefresh={fetchSharedDocuments}
          onClose={() => setShowSentShares(false)}
        />
      </Show>

      {/* File Info Dialog */}
      <Show when={showFileInfo()}>
        <FileInfoDialog
          filePath={showFileInfo()!}
          vaultPath={vaultPath() || ''}
          onClose={() => setShowFileInfo(null)}
          syncEnabled={syncStatus() !== 'off'}
          getRemoteInfo={async () => {
            const engine = getSyncEngine();
            if (!vaultPath()) return null;
            
            try {
              // Ensure signer is set
              let signer = engine.getSigner();
              if (!signer) {
                const storedSigner = await getSignerFromStoredLogin();
                if (storedSigner) {
                  await engine.setSigner(storedSigner);
                  signer = storedSigner;
                } else {
                  return null;
                }
              }
              
              // Get the relative path
              const filePath = showFileInfo()!;
              const relativePath = filePath.replace(vaultPath()! + '/', '');
              
              // Always fetch fresh vault data to ensure accuracy
              const vaults = await engine.fetchVaults();
              const vault = vaults[0];
              if (vault) {
                setCurrentVault(vault);
              }
              
              if (!vault) return null;
              
              // Look for the file in the vault's file index
              const fileEntry = vault.data.files?.find(f => f.path === relativePath);
              if (!fileEntry) return null;
              
              // We have the file entry in the index, use that info
              // Generate naddr from the d-tag
              const naddr = engine.getFileNaddr(fileEntry.d) || '';
              
              return {
                eventId: fileEntry.eventId,
                d: fileEntry.d,
                checksum: fileEntry.checksum,
                version: fileEntry.version,
                modified: fileEntry.modified,
                naddr,
                relays: engine.getConfig().relays,
              };
            } catch (err) {
              console.error('Failed to get remote file info:', err);
              return null;
            }
          }}
          onSyncFile={async () => {
            if (!legacyPath(showFileInfo()!)) throw new VaultError('POLICY', { operation: 'publish' });
            const engine = getSyncEngine();
            let signer = engine.getSigner();
            if (!signer) {
              // Try to get signer from storage
              signer = await getSignerFromStoredLogin();
              if (signer) {
                await engine.setSigner(signer);
              } else {
                throw new Error('Not logged in. Please log in to sync files.');
              }
            }
            if (!vaultPath()) {
              throw new Error('No vault selected.');
            }
            
            // Get or create vault, use cached if available
            let vault = currentVault();
            if (!vault) {
              const vaults = await engine.fetchVaults();
              vault = vaults[0];
              if (!vault) {
                vault = await engine.createVault('My Notes', 'Default vault');
              }
            }
            
            // Read the file content
            const filePath = showFileInfo()!;
            const content = await platform.vault.read(filePath, vaultPath() ?? '');
            const relativePath = filePath.replace(vaultPath()! + '/', '');
            
            // Publish the file
            const result = await engine.publishFile(vault, relativePath, content);
            
            // Update cached vault with the new file
            setCurrentVault(result.vault);
            
            // Generate naddr for the synced file
            const naddr = engine.getFileNaddr(result.file.d) || '';
            
            // Return remote info
            return {
              eventId: result.file.eventId,
              d: result.file.d,
              checksum: result.file.data.checksum,
              version: result.file.data.version,
              modified: result.file.data.modified,
              naddr,
              relays: engine.getConfig().relays,
            };
          }}
          getShareInfo={async () => {
            const filePath = showFileInfo()!;
            const relativePath = filePath.replace(vaultPath()! + '/', '');
            
            // Filter sent shares for this file
            const fileShares = sentShares().filter(s => s.path === relativePath);
            if (fileShares.length === 0) return { shares: [] };
            
            // Fetch profiles for recipients
            const engine = getSyncEngine();
            const relays = engine.getConfig().relays;
            const { fetchUserProfile } = await import('./lib/nostr/login');
            
            const recipientProfiles = new Map<string, { name?: string; picture?: string }>();
            for (const share of fileShares) {
              try {
                const profile = await fetchUserProfile(share.recipientPubkey, relays);
                if (profile) {
                  recipientProfiles.set(share.recipientPubkey, {
                    name: profile.displayName || profile.name,
                    picture: profile.picture,
                  });
                }
              } catch (err) {
                console.error('Failed to fetch profile:', err);
              }
            }
            
            return { shares: fileShares, recipientProfiles };
          }}
          onRevokeShare={async (share) => {
            await handleRevokeShare(share);
          }}
        />
      </Show>

      <Show when={showVaults()}>
        <div class="modal-overlay" onClick={() => setShowVaults(false)}>
          <section class="modal-dialog vault-dialog" role="dialog" aria-label="Shared vaults" onClick={e => e.stopPropagation()}>
            <header class="modal-header"><h3>{attachFolder() ? 'Attach owned vault' : 'Shared vaults'}</h3>
              <button onClick={() => setShowVaults(false)}>Close</button></header>
            <div class="modal-body vault-dialog__body">
              <SharedVaultEngineStatus snapshot={vaultSnapshot()} error={vaultError()} onRetry={() => { void refreshVaultIdentity(); }} onRepairInbox={() => { void vaultEngine()?.repairInbox().catch(err => setVaultError(String(err))); }} />
              <Show when={attachFolder()} fallback={<For each={vaultSnapshot()?.vaults}>{vault => (
                <button class="vault-btn" onClick={() => manageSharedVault(vault.vaultId)}>{vault.label} — {vault.authority}</button>
              )}</For>}>
                <p>Attach at {attachFolder()}. Existing differing files become conflicts; nothing is overwritten. Legacy relay copies remain.</p>
                <For each={vaultSnapshot()?.vaults.filter(v => v.authority === 'owner' && !v.mount)}>{vault => (
                  <button class="vault-btn" onClick={async () => {
                    try { await vaultEngine()?.attach(vault.vaultId, attachFolder()!); setAttachFolder(undefined); manageSharedVault(vault.vaultId); refreshSidebar?.(); }
                    catch (error) { setVaultError(String(error)); }
                  }}>Attach {vault.label}</button>
                )}</For>
                <p>If the vault is not listed, refresh the inbox for this identity's self-grant.</p>
              </Show>
              <button class="vault-btn" disabled={vaultSnapshot()?.lifecycle !== 'running'} onClick={() => { void vaultEngine()?.refreshInbox().catch(err => setVaultError(String(err))); }}>Refresh invitations</button>
              <button class="vault-btn" onClick={() => { setShowVaults(false); setSettingsSection('sync'); setShowSettings(true); }}>Shared vault settings</button>
            </div>
          </section>
        </div>
      </Show>

      <Show when={vaultEngine()}>{engine => <>
        <Show when={selectedVault()}>{vault => (
          <div class="modal-overlay" onClick={() => setSelectedVaultId(undefined)}>
            <div class="modal-dialog vault-dialog" role="dialog" aria-label="Manage shared vault" onClick={e => e.stopPropagation()}>
              <For each={vault().fileErrors}>{failure => <p class="vault-error" role="alert">{failure.path}: {failure.error.message}</p>}</For>
              <VaultPanel engine={engine()} vaultId={vault().vaultId} snapshot={vaultSnapshot()} localPubkey={vaultPubkey()}
                members={vault().members} deliveries={vault().deliveries}
                regrantHeadroom={vault().regrantHeadroomBytes === undefined ? undefined : { largestSealBytes: 65535 - vault().regrantHeadroomBytes! }}
                onShare={openVaultShare} onOpenConflicts={id => setConflictsVaultId(id)}
                onDetached={() => { setSelectedVaultId(undefined); refreshSidebar?.(); }}
                onClose={() => setSelectedVaultId(undefined)}
                onExportRecovery={exportVaultRecovery} />
            </div>
          </div>
        )}</Show>
        <Show when={conflictsVault()}>{vault => (
          <div class="modal-overlay" onClick={() => setConflictsVaultId(undefined)}>
            <div class="modal-dialog vault-dialog" role="dialog" aria-label="Vault conflicts" onClick={e => e.stopPropagation()}>
              <VaultConflictsPanel engine={engine()} vaultId={vault().vaultId} snapshot={vaultSnapshot()}
                conflicts={(vault().conflicts ?? []).map(conflict => ({ ...conflict, kind: conflict.kind === 'directory' ? 'directory' as const : 'file' as const }))}
                onOpenVersion={conflict => { if (conflict.alternatePath && vaultPath()) void openFile(conflict.alternatePath); }}
                onClose={() => setConflictsVaultId(undefined)} />
            </div>
          </div>
        )}</Show>
        <Show when={shareVault()}>{target => (
          <VaultShareDialog engine={engine()} folderPath={target().folder} vaultId={target().vaultId} localPubkey={vaultPubkey()} snapshot={vaultSnapshot()}
            deliveryOptions={vaultSnapshot()?.deviceKeys}
            profileRelays={defaultProfileRelays(vaultSnapshot(), target().vaultId)}
            existingMembers={vaultSnapshot()?.vaults.find(v => v.vaultId === target().vaultId)?.members}
            deliveries={vaultSnapshot()?.vaults.find(v => v.vaultId === target().vaultId)?.deliveries}
            onCreated={id => { refreshSidebar?.(); manageSharedVault(id); }}
            onClose={() => setShareVault(undefined)} />
        )}</Show>
        <Show when={selectedInvitation()}>{invitation => (
          <Show when={vaultPubkey()}>{pubkey => (
            <VaultInvitationDialog engine={engine()} invitation={invitation()} localPubkey={pubkey()}
              endpointHints={invitation().endpointHints ?? { readRelays: [], writeRelays: [], readBlossom: [], writeBlossom: [] }}
              defaultFolder={`Shared Vaults/${invitation().vaultId.slice(0, 12)}`} attachFolder={attachFolder()}
              existingMount={vaultSnapshot()?.vaults.find(v => v.vaultId === invitation().vaultId && v.owner === invitation().owner)?.mount ?? undefined}
              profileRelays={defaultProfileRelays(vaultSnapshot(), invitation().vaultId)}
              inspectFolder={async relative => {
                const root = vaultPath();
                if (!root) throw new Error('Notebook closed');
                const path = `${root}/${relative}`;
                if (!await platform.vault.exists(path)) return 'missing';
                return (await platform.vault.listAll(path)).length ? 'non-empty' : 'empty';
              }}
              onAccepted={mount => { setInvitationId(undefined); setAttachFolder(undefined); refreshSidebar?.(); manageSharedVault(mount.vaultId); }}
              onClose={() => { setInvitationId(undefined); setAttachFolder(undefined); }} />
          )}</Show>
        )}</Show>
      </>}</Show>

      <Show when={recoveryPrompt()}>
        <div class="modal-overlay">
          <form class="modal-dialog vault-dialog" role="dialog" aria-label="Recovery passphrase" onSubmit={async event => {
            event.preventDefault();
            if (recoveryPicking() || !recoveryPassphraseValid(recoveryPassphrase(), recoveryConfirmation(), recoveryRequest())) return;
            const generation = sessionGeneration;
            const root = vaultPath();
            if (!root) return;
            setRecoveryPicking(true);
            setRecoverySaveError(undefined);
            try {
              // Open the picker in this user gesture, before NIP-49 encryption.
              const destination = await platform.dialog.save({ title: 'Save encrypted vault recovery outside all notebooks',
                defaultPath: `onyx-vault-recovery-${selectedVaultId()?.slice(0, 8) ?? 'backup'}.json`, excludedDirectory: root,
                filters: [{ name: 'JSON', extensions: ['json'] }] });
              if (disposed || generation !== sessionGeneration || !recoveryPrompt()) {
                if (destination) platform.dialog.discardSave?.(destination);
                return;
              }
              if (!destination) { closeRecoveryPrompt(); return; }
              if (pathKey(destination) === pathKey(root) || pathKey(destination).startsWith(`${pathKey(root)}/`) || managedPath(destination)) {
                platform.dialog.discardSave?.(destination);
                throw new Error('Save recovery outside all managed and legacy-synced notebook folders.');
              }
              recoveryDestination = { path: destination, generation };
              closeRecoveryPrompt(recoveryPassphrase());
            } catch (error) { setRecoverySaveError(String(error)); }
            finally { setRecoveryPicking(false); }
          }}>
            <header class="modal-header"><h3>Protect recovery package</h3></header>
            <div class="modal-body vault-dialog__body">
              <p>Use a strong, unique passphrase. Keep it separately from the recovery file. Save the file outside every notebook or synced folder.</p>
              <RecoveryPassphraseFields request={recoveryRequest()} passphrase={recoveryPassphrase()} confirmation={recoveryConfirmation()} onPassphrase={setRecoveryPassphrase} onConfirmation={setRecoveryConfirmation} />
              <Show when={recoverySaveError()}><p class="vault-error" role="alert">{recoverySaveError()}</p></Show>
              <button type="button" onClick={() => closeRecoveryPrompt()}>Cancel</button>
              <button type="submit" disabled={recoveryPicking() || !recoveryPassphraseValid(recoveryPassphrase(), recoveryConfirmation(), recoveryRequest())}>Choose destination and encrypt</button>
            </div>
          </form>
        </div>
      </Show>

      {/* Post to Nostr Dialog */}
      <Show when={postToNostrTarget()}>
        <PostToNostrDialog
          filePath={postToNostrTarget()!.path}
          content={postToNostrTarget()!.content}
          title={postToNostrTarget()!.title}
          onClose={() => setPostToNostrTarget(null)}
          onPublish={async (options) => {
            const engine = getSyncEngine();
            const signer = engine.getSigner();
            if (!signer) {
              throw new Error('Not logged in');
            }
            
            // Publish as NIP-23 long-form article
            const result = await engine.publishArticle(
              postToNostrTarget()!.content,
              options.title,
              options.summary,
              options.image,
              options.tags,
              options.isDraft
            );
            
            return result;
          }}
        />
      </Show>
    </div>
  );
};

export default App;
