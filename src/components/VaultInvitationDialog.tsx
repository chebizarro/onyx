/**
 * VaultInvitationDialog
 *
 * Review a received vault invitation before any vault data is read: owner,
 * capability, vault id and endpoint hints. Endpoints and the mount folder
 * must be approved explicitly. The only network activity before approval is
 * the owner's profile-name lookup on the user's own configured relays; the
 * owner's avatar is never loaded here and the owner's key fingerprint is
 * always shown so names cannot stand in for identity. When the owner is the local identity (another
 * of the user's devices), the vault can be attached at an existing folder.
 */

import { Component, For, Show, createEffect, createMemo, createSignal, on } from 'solid-js';
import { formatPubkey } from '../lib/nostr/nip05';
import type {
  VaultEngine, VaultInvitationSummary, VaultNetworkDefaults,
} from '../lib/vault/engine-api';
import type { Pubkey, VaultMount } from '../lib/vault/types';
import {
  createProfileMap, defaultProfileRelays, describeVaultError, lookupProfile,
  normalizeRelative, validateMountFolder, type ProfileLookup,
} from './vault-ui';
import KeyFingerprint from './KeyFingerprint';
import './vault.css';

export type VaultFolderState = 'missing' | 'empty' | 'non-empty';

export interface VaultInvitationDialogProps {
  engine: Pick<VaultEngine, 'accept' | 'attach'>;
  invitation: VaultInvitationSummary;
  localPubkey: Pubkey;
  /** Endpoint hints carried by the grant (or proposed defaults) awaiting approval. */
  endpointHints: VaultNetworkDefaults;
  /** Default new folder, e.g. `Shared Vaults/<vault-id-prefix>`. */
  defaultFolder: string;
  /** Inspect a notebook-relative folder before accepting into it. */
  inspectFolder?: (relativePath: string) => Promise<VaultFolderState>;
  /** Existing accepted mount; a newer grant updates access in place. */
  existingMount?: VaultMount;
  /** Preselect "attach at existing path" with this folder (owner only). */
  attachFolder?: string;
  profileRelays?: readonly string[];
  lookupProfile?: ProfileLookup;
  onClose: () => void;
  onAccepted?: (mount: VaultMount) => void;
}

type EndpointKind = 'relay' | 'blossom';
interface EndpointRow {
  readonly key: string;
  readonly kind: EndpointKind;
  readonly url: string;
  readonly read: boolean;
  readonly write: boolean;
}

function endpointRows(network: VaultNetworkDefaults): EndpointRow[] {
  const rows = new Map<string, EndpointRow>();
  const add = (kind: EndpointKind, url: string, read: boolean, write: boolean) => {
    const key = `${kind}:${url}`;
    const prev = rows.get(key);
    rows.set(key, { key, kind, url, read: read || (prev?.read ?? false), write: write || (prev?.write ?? false) });
  };
  network.readRelays.forEach((url) => add('relay', url, true, false));
  network.writeRelays.forEach((url) => add('relay', url, false, true));
  network.readBlossom.forEach((url) => add('blossom', url, true, false));
  network.writeBlossom.forEach((url) => add('blossom', url, false, true));
  return [...rows.values()];
}

const VaultInvitationDialog: Component<VaultInvitationDialogProps> = (props) => {
  const isSelfOwned = () => props.invitation.owner === props.localPubkey;
  const existingMount = () => props.existingMount?.vaultId === props.invitation.vaultId ? props.existingMount : undefined;
  const [mode, setMode] = createSignal<'new' | 'attach'>(props.attachFolder && isSelfOwned() ? 'attach' : 'new');
  const [folder, setFolder] = createSignal(props.defaultFolder);
  const [folderEdited, setFolderEdited] = createSignal(false);
  const [attachPath, setAttachPath] = createSignal(props.attachFolder ?? '');
  const [label, setLabel] = createSignal('');
  const [trusted, setTrusted] = createSignal(false);
  const [endpointsApproved, setEndpointsApproved] = createSignal(false);
  const rows = createMemo(() => endpointRows(props.endpointHints));
  const [selected, setSelected] = createSignal<ReadonlySet<string>>(new Set(endpointRows(props.endpointHints).map((r) => r.key)));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  // Approvals are scoped to one invitation; never carry them over to another.
  createEffect(on(() => props.invitation.invitationId, () => {
    setMode(props.attachFolder && isSelfOwned() ? 'attach' : 'new');
    setFolder(props.defaultFolder);
    setFolderEdited(false);
    setAttachPath(props.attachFolder ?? '');
    setTrusted(false);
    setEndpointsApproved(false);
    setSelected(new Set(endpointRows(props.endpointHints).map((r) => r.key)));
    setError(null);
  }, { defer: true }));

  const profiles = createProfileMap(
    () => [props.invitation.owner],
    () => props.profileRelays ?? defaultProfileRelays(),
    props.lookupProfile ?? lookupProfile,
  );
  const ownerName = () => profiles().get(props.invitation.owner)?.name;

  const switchMode = (next: 'new' | 'attach') => {
    setMode(next);
    // Attach uses the complete recorded hint set, not the editable subset.
    setSelected(new Set(endpointRows(props.endpointHints).map(row => row.key)));
    setEndpointsApproved(false);
  };

  const toggleEndpoint = (key: string, on: boolean) => {
    const next = new Set(selected());
    if (on) next.add(key); else next.delete(key);
    setSelected(next);
    setEndpointsApproved(false);
  };

  const approvedNetwork = (): VaultNetworkDefaults => {
    const chosen = rows().filter((row) => selected().has(row.key));
    const pick = (kind: EndpointKind, field: 'read' | 'write') =>
      chosen.filter((row) => row.kind === kind && row[field]).map((row) => row.url);
    return {
      readRelays: pick('relay', 'read'),
      writeRelays: pick('relay', 'write'),
      readBlossom: pick('blossom', 'read'),
      writeBlossom: pick('blossom', 'write'),
    };
  };

  const hasReadRelay = () => approvedNetwork().readRelays.length > 0;
  const hasReadBlossom = () => approvedNetwork().readBlossom.length > 0;
  const isAttach = () => !existingMount() && mode() === 'attach' && isSelfOwned();
  const targetFolder = () => existingMount()?.relativePath ?? (isAttach() ? attachPath() : folder());
  const folderError = () => validateMountFolder(targetFolder());

  const canAccept = () => !busy() && !props.invitation.accepted && trusted() && endpointsApproved()
    && hasReadRelay() && folderError() === null;

  const accept = async () => {
    if (!canAccept()) return;
    setBusy(true);
    setError(null);
    try {
      const relativePath = normalizeRelative(targetFolder());
      if (!existingMount() && !isAttach() && folderEdited() && props.inspectFolder) {
        const state = await props.inspectFolder(relativePath);
        if (state === 'non-empty') {
          setError('That folder is not empty. Choose a new or empty folder; existing files are never merged automatically.');
          return;
        }
      }
      const mount = isAttach()
        ? await props.engine.attach(props.invitation.invitationId, relativePath)
        : await props.engine.accept(props.invitation.invitationId, {
          relativePath: !existingMount() && folderEdited() ? relativePath : undefined,
          label: label().trim() || undefined,
          trustConfirmed: true,
          endpointsConfirmed: true,
          network: approvedNetwork(),
        });
      props.onAccepted?.(mount);
    } catch (err) {
      setError(describeVaultError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="modal-overlay" onClick={() => !busy() && props.onClose()}>
      <div class="modal-dialog vault-dialog" role="dialog" aria-label="Vault invitation" onClick={(e) => e.stopPropagation()}>
        <div class="modal-header">
          <h3>Vault invitation</h3>
          <button class="modal-close" aria-label="Close" onClick={() => props.onClose()} disabled={busy()}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        <div class="modal-body vault-dialog__body">
          <dl class="vault-facts">
            <dt>Owner</dt>
            <dd>
              <div class="vault-member__identity">
                <Show when={isSelfOwned()} fallback={
                  <span class="vault-member__name">{ownerName() ?? formatPubkey(props.invitation.owner, 8)}</span>
                }>
                  <span>You (this is your own vault)</span>
                </Show>
                <KeyFingerprint pubkey={props.invitation.owner} />
              </div>
              <Show when={!isSelfOwned()}>
                <p class="vault-field__hint">
                  Names and pictures can be copied; the fingerprint cannot. Compare it with the owner over a channel you trust.
                </p>
              </Show>
            </dd>
            <dt>Access</dt>
            <dd>{props.invitation.cap === 'write' ? 'Can propose edits' : 'Read only'}</dd>
            <dt>Vault id</dt>
            <dd class="vault-mono vault-facts__id">{props.invitation.vaultId}</dd>
          </dl>

          <Show when={props.invitation.accepted}>
            <div class="vault-success" role="status">This invitation has already been accepted.</div>
          </Show>

          <section class="vault-dialog__section">
            <div class="vault-field__label">Endpoints</div>
            <Show when={isAttach()} fallback={
              <p class="vault-note">
                No vault data is fetched until you approve. Only the owner's profile name has been looked up, on your own
                configured relays; their picture is not loaded. Unchecked endpoints are never contacted.
              </p>
            }>
              <p class="vault-note">
                No vault data is fetched until you approve. Only the owner's profile name has been looked up, on your own
                configured relays. Attaching uses the endpoints recorded for this vault.
              </p>
            </Show>
            <Show when={rows().length > 0} fallback={<div class="vault-error">The invitation carries no endpoints.</div>}>
              <ul class="vault-endpoint-list">
                <For each={rows()}>
                  {(row) => (
                    <li class="vault-endpoint-list__item">
                      <label class="vault-checkbox">
                        <input
                          type="checkbox"
                          checked={selected().has(row.key)}
                          disabled={isAttach()}
                          aria-label={`Use ${row.url}`}
                          onChange={(e) => toggleEndpoint(row.key, e.currentTarget.checked)}
                        />
                        <span class="vault-tag">{row.kind}</span>
                        <span class="vault-mono">{row.url}</span>
                      </label>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
            <Show when={!hasReadRelay()}>
              <div class="vault-error">Approve at least one relay to read the vault.</div>
            </Show>
            <Show when={hasReadRelay() && !hasReadBlossom()}>
              <div class="vault-warning">No file server is approved; file contents cannot be downloaded.</div>
            </Show>
            <label class="vault-checkbox">
              <input
                type="checkbox"
                checked={endpointsApproved()}
                onChange={(e) => setEndpointsApproved(e.currentTarget.checked)}
              />
              <span>I approve connecting to the selected endpoints.</span>
            </label>
          </section>

          <section class="vault-dialog__section">
            <div class="vault-field__label">{existingMount() ? 'Existing shared folder' : 'Where to put it'}</div>
            <Show when={existingMount()}>{mount => <>
              <p class="vault-mono">{mount().relativePath}</p>
              <p class="vault-note">Access will be updated in this existing mount. Your folder and local files stay in place.</p>
            </>}</Show>
            <Show when={!existingMount() && isSelfOwned()}>
              <div class="vault-radio-group" role="radiogroup">
                <label class="vault-checkbox">
                  <input type="radio" name="vault-mount-mode" checked={mode() === 'new'} onChange={() => switchMode('new')} />
                  <span>New empty folder</span>
                </label>
                <label class="vault-checkbox">
                  <input type="radio" name="vault-mount-mode" checked={mode() === 'attach'} onChange={() => switchMode('attach')} />
                  <span>Attach at existing path</span>
                </label>
              </div>
            </Show>

            <Show when={!existingMount() && !isAttach()}>
              <label class="vault-field">
                <span class="vault-field__label">Folder</span>
                <input
                  class="vault-input"
                  type="text"
                  aria-label="Folder"
                  value={folder()}
                  onInput={(e) => { setFolder(e.currentTarget.value); setFolderEdited(true); }}
                />
                <span class="vault-field__hint">Must be new or empty. Files are never merged into a non-empty folder.</span>
              </label>
              <label class="vault-field">
                <span class="vault-field__label">Local label (optional)</span>
                <input class="vault-input" type="text" value={label()} onInput={(e) => setLabel(e.currentTarget.value)} />
              </label>
            </Show>

            <Show when={isAttach()}>
              <label class="vault-field">
                <span class="vault-field__label">Existing folder</span>
                <input
                  class="vault-input"
                  type="text"
                  aria-label="Existing folder"
                  value={attachPath()}
                  onInput={(e) => setAttachPath(e.currentTarget.value)}
                />
              </label>
              <p class="vault-note">
                The folder may already contain files. Identical files converge; every file that differs from the
                vault becomes a conflict for you to review. Nothing is overwritten or deleted.
                Legacy sync copies of this folder stay on your relays; attaching does not remove them.
              </p>
            </Show>
            <Show when={targetFolder() && folderError()}>
              <div class="vault-error">{folderError()}</div>
            </Show>
          </section>

          <section class="vault-dialog__section">
            <label class="vault-checkbox">
              <input type="checkbox" checked={trusted()} onChange={(e) => setTrusted(e.currentTarget.checked)} />
              <span>
                {isSelfOwned()
                  ? 'I created this vault on another device and want it on this one.'
                  : 'I recognise this owner and want to accept the vault.'}
              </span>
            </label>
          </section>

          <Show when={error()}>
            <div class="vault-error" role="alert">{error()}</div>
          </Show>
        </div>

        <div class="modal-footer">
          <button class="setting-button secondary" onClick={() => props.onClose()} disabled={busy()}>Cancel</button>
          <button class="setting-button" onClick={() => void accept()} disabled={!canAccept()}>
            {busy() ? 'Working...' : existingMount() ? 'Update access' : isAttach() ? 'Attach' : 'Accept'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default VaultInvitationDialog;
