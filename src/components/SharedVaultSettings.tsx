/**
 * SharedVaultSettings
 *
 * Shared-vault controls that are independent of legacy sync: the mount list,
 * per-vault network endpoints, and the experimental NIP-4E device key.
 */

import { Component, For, Show, createSignal } from 'solid-js';
import { formatPubkey } from '../lib/nostr/nip05';
import type { VaultEngine, VaultEngineSnapshot, VaultNetworkDefaults } from '../lib/vault/engine-api';
import type { VaultId } from '../lib/vault/types';
import {
  AUTHORITY_LABELS, describeVaultError, shortVaultId, useSnapshot,
  type DeviceKeySettingsController,
} from './vault-ui';
import SharedVaultEngineStatus from './SharedVaultEngineStatus';
import KeyFingerprint from './KeyFingerprint';
import './vault.css';

export interface SharedVaultSettingsProps {
  engine: Pick<VaultEngine, 'subscribe' | 'pause' | 'resume' | 'sync'>;
  snapshot?: VaultEngineSnapshot;
  startupError?: string | null;
  onRetry?: () => void;
  /** Repair action for an invitation inbox at capacity or stopped (SEC-G). */
  onRepairInbox?: () => void;
  /** Endpoints pinned per vault, keyed by vault id. */
  networks?: Readonly<Record<string, VaultNetworkDefaults>>;
  /** Defaults snapshotted into newly created vaults. */
  networkDefaults?: VaultNetworkDefaults;
  /** Experimental NIP-4E device-key controls; omitted hides the section. */
  deviceKeys?: DeviceKeySettingsController;
  onManageVault?: (vaultId: VaultId) => void;
  onEditVaultNetwork?: (vaultId: VaultId) => void;
}

const EndpointSummary: Component<{ network: VaultNetworkDefaults }> = (props) => {
  const relays = () => [...new Set([...props.network.readRelays, ...props.network.writeRelays])];
  const blossom = () => [...new Set([...props.network.readBlossom, ...props.network.writeBlossom])];
  return (
    <ul class="vault-endpoint-list">
      <For each={relays()}>
        {(url) => <li class="vault-endpoint-list__item"><span class="vault-tag">relay</span> <span class="vault-mono">{url}</span></li>}
      </For>
      <For each={blossom()}>
        {(url) => <li class="vault-endpoint-list__item"><span class="vault-tag">blossom</span> <span class="vault-mono">{url}</span></li>}
      </For>
      <Show when={relays().length + blossom().length === 0}>
        <li class="vault-endpoint-list__item vault-field__hint">No endpoints configured.</li>
      </Show>
    </ul>
  );
};

const SharedVaultSettings: Component<SharedVaultSettingsProps> = (props) => {
  const snapshot = useSnapshot(props.engine, () => props.snapshot);
  const [busy, setBusy] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const [importValue, setImportValue] = createSignal('');

  const run = async (name: string, action: () => Promise<unknown> | unknown, done?: string) => {
    if (busy()) return;
    setBusy(name);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (done) setNotice(done);
    } catch (err) {
      setError(describeVaultError(err));
    } finally {
      setBusy(null);
    }
  };

  const mounted = () => snapshot().vaults.filter((v) => v.mount);
  const keys = () => props.deviceKeys;

  return (
    <div class="vault-settings">
      <section class="vault-settings__section">
        <h4>Shared vaults</h4>
        <SharedVaultEngineStatus snapshot={snapshot()} error={props.startupError} onRetry={props.onRetry} onRepairInbox={props.onRepairInbox} />
        <p class="vault-note">
          Shared vaults sync independently of document sync above. Each vault manages one folder in this notebook.
        </p>
        <Show when={mounted().length > 0} fallback={
          <div class="vault-panel__empty">No shared vaults on this device. Right-click a folder and choose "Share folder as vault...".</div>
        }>
          <ul class="vault-mount-list">
            <For each={mounted()}>
              {(vault) => (
                <li class="vault-mount" data-vault-id={vault.vaultId}>
                  <div class="vault-mount__head">
                    <span class="vault-mount__label">{vault.label || shortVaultId(vault.vaultId)}</span>
                    <span class={`vault-badge vault-badge--${vault.authority}`}>{AUTHORITY_LABELS[vault.authority]}</span>
                    <Show when={vault.provisional}><span class="vault-badge vault-badge--provisional">Provisional</span></Show>
                    <Show when={!vault.enabled}><span class="vault-badge vault-badge--paused">Paused</span></Show>
                    <Show when={vault.conflictCount > 0}>
                      <span class="vault-badge vault-badge--conflict">{vault.conflictCount} conflict(s)</span>
                    </Show>
                  </div>
                  <div class="vault-mono vault-field__hint">{vault.mount?.relativePath}</div>
                  <Show when={vault.lastError}>
                    {(e) => <div class="vault-error">{e().message}</div>}
                  </Show>
                  <Show when={props.networks?.[vault.vaultId]}>
                    {(network) => <EndpointSummary network={network()} />}
                  </Show>
                  <div class="vault-actions">
                    <Show when={props.onManageVault}>
                      <button class="setting-button small secondary" onClick={() => props.onManageVault?.(vault.vaultId)}>Manage</button>
                    </Show>
                    <Show when={props.onEditVaultNetwork}>
                      <button class="setting-button small secondary" onClick={() => props.onEditVaultNetwork?.(vault.vaultId)}>Endpoints...</button>
                    </Show>
                    <Show when={vault.enabled} fallback={
                      <button class="setting-button small secondary" disabled={busy() !== null} onClick={() => void run(`resume:${vault.vaultId}`, () => props.engine.resume(vault.vaultId))}>Resume</button>
                    }>
                      <button class="setting-button small secondary" disabled={busy() !== null} onClick={() => void run(`pause:${vault.vaultId}`, () => props.engine.pause(vault.vaultId))}>Pause</button>
                      <button class="setting-button small secondary" disabled={busy() !== null} onClick={() => void run(`sync:${vault.vaultId}`, () => props.engine.sync(vault.vaultId))}>Sync</button>
                    </Show>
                  </div>
                </li>
              )}
            </For>
          </ul>
        </Show>
        <Show when={props.networkDefaults}>
          {(network) => (
            <>
              <div class="vault-field__label">Defaults for new vaults</div>
              <EndpointSummary network={network()} />
            </>
          )}
        </Show>
      </section>

      <Show when={keys()}>
        {(dk) => (
          <section class="vault-settings__section" aria-label="Device key">
            <h4>
              Device key <span class="vault-badge vault-badge--experimental">Experimental</span>
            </h4>
            <p class="vault-note">
              Optional NIP-4E delivery: invitations are encrypted to a key held by this device instead of your
              identity key. Provisional and off by default; other apps may not support it.
            </p>
            <p class="vault-note" data-testid="device-key-limits">
              Rotating a key cannot take back invitations already sent to the old key, so earlier keys are kept.
              Recipients' device keys are pinned once seen and used only after you approve their fingerprint;
              until then invitations go to their identity key. A relay showing no newer key is not proof a
              pinned key is still current. Verify fingerprints out of band, especially after a reset.
            </p>
            <ul class="vault-member-list" aria-label="Recipient device keys">
              <For each={dk().state.recipients}>{recipient => (
                <li class="vault-member-list__item vault-recipient-key" data-identity={recipient.identity}>
                  <div class="vault-member__identity">
                    <span>Identity</span><KeyFingerprint pubkey={recipient.identity} />
                    <Show when={recipient.observed?.encryptionKey}>{key => <><span>Pinned device key</span><KeyFingerprint pubkey={key()} /></>}</Show>
                    <Show when={recipient.approvedKey !== recipient.observed?.encryptionKey && recipient.approvedKey}>{key => <><span>Previously approved key</span><KeyFingerprint pubkey={key()} /></>}</Show>
                  </div>
                  <span class="vault-badge">{recipient.status}</span>
                  <Show when={recipient.observed?.encryptionKey && recipient.status !== 'approved' && dk().approveRecipientKey}>{approve => (
                    <button class="vault-link-button" disabled={busy() !== null} onClick={() => void run('approve-recipient', () => approve()(recipient.identity, recipient.observed!.encryptionKey!))}>Approve this key</button>
                  )}</Show>
                  <Show when={dk().resetRecipientPin}>{reset => (
                    <button class="vault-link-button vault-link-button--danger" disabled={busy() !== null} onClick={() => void run('reset-recipient', () => reset()(recipient.identity))}>Reset pin</button>
                  )}</Show>
                </li>
              )}</For>
            </ul>
            <label class="vault-checkbox">
              <input
                type="checkbox"
                checked={dk().state.enabled}
                disabled={busy() !== null}
                onChange={(e) => {
                  const on = e.currentTarget.checked;
                  void run('enable', () => dk().setEnabled(on));
                }}
              />
              <span>Use device keys for vault invitations</span>
            </label>

            <Show when={dk().state.enabled}>
              <dl class="vault-facts">
                <dt>Current key</dt>
                <dd data-testid="device-key-current">
                  <Show when={dk().state.current} fallback={<span class="vault-field__hint">None</span>}>
                    {(cur) => (
                      <>
                        <span class="vault-mono">{formatPubkey(cur().pubkey, 8)}</span>
                        <span class={`vault-badge ${cur().announced ? 'vault-badge--ok' : 'vault-badge--paused'}`}>
                          {cur().announced ? 'Announced' : 'Not announced'}
                        </span>
                      </>
                    )}
                  </Show>
                </dd>
                <Show when={dk().state.retained.length > 0}>
                  <dt>Earlier keys</dt>
                  <dd>
                    {dk().state.retained.length} kept to open older invitations. They are never deleted automatically.
                  </dd>
                </Show>
              </dl>

              <div class="vault-actions">
                <button class="setting-button secondary" disabled={busy() !== null} onClick={() => void run('generate', () => dk().generate(), 'Device key generated. Announce it so others can use it.')}>
                  {dk().state.current ? 'Generate new key' : 'Generate key'}
                </button>
                <Show when={dk().state.current}>
                  <button class="setting-button secondary" disabled={busy() !== null} onClick={() => void run('announce', () => dk().announce(), 'Device key announced.')}>
                    {dk().state.current?.announced ? 'Announce again' : 'Announce'}
                  </button>
                </Show>
              </div>

              <div class="vault-recipient-input">
                <input
                  class="vault-input"
                  type="password"
                  autocomplete="off"
                  aria-label="Import device key"
                  placeholder="nsec1... or hex secret key"
                  value={importValue()}
                  onInput={(e) => setImportValue(e.currentTarget.value)}
                />
                <button
                  class="setting-button secondary"
                  disabled={busy() !== null || !importValue().trim()}
                  onClick={() => {
                    const secret = importValue().trim();
                    setImportValue('');
                    void run('import', () => dk().import(secret), 'Device key imported.');
                  }}
                >Import</button>
              </div>

              <label class="vault-checkbox">
                <input
                  type="checkbox"
                  checked={dk().state.allowIdentityFallback}
                  disabled={busy() !== null}
                  onChange={(e) => {
                    const on = e.currentTarget.checked;
                    void run('fallback', () => dk().setAllowIdentityFallback(on));
                  }}
                />
                <span>
                  When a recipient has not announced a device key, deliver to their identity key.
                  Failures to encrypt, publish or announce never fall back silently.
                </span>
              </label>
            </Show>
          </section>
        )}
      </Show>

      <Show when={notice()}>
        <div class="vault-success" role="status">{notice()}</div>
      </Show>
      <Show when={error()}>
        <div class="vault-error" role="alert">{error()}</div>
      </Show>
    </div>
  );
};

export default SharedVaultSettings;
