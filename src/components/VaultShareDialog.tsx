/**
 * VaultShareDialog
 *
 * Create a shared vault from a folder and/or share it with recipients.
 * Each recipient gets an independently journaled delivery; failures stay
 * retryable without re-creating the vault or rolling back the policy.
 */

import { Component, For, Show, createEffect, createMemo, createSignal, on } from 'solid-js';
import { createStore, produce } from 'solid-js/store';
import { formatPubkey, parseRecipientInput } from '../lib/nostr/nip05';
import type {
  VaultCapability, VaultDeliveryOptions, VaultEngine, VaultEngineSnapshot, VaultNetworkDefaults,
} from '../lib/vault/engine-api';
import type { Pubkey, VaultId } from '../lib/vault/types';
import {
  createProfileMap, defaultProfileRelays, describeVaultError, formatBytes, lookupProfile,
  type ProfileLookup, type VaultDeliveryView, type VaultMemberView,
} from './vault-ui';
import SharedVaultEngineStatus from './SharedVaultEngineStatus';
import KeyFingerprint from './KeyFingerprint';
import VaultDeliveryEvidence from './VaultDeliveryEvidence';
import './vault.css';

export interface VaultFolderSummary {
  readonly files: number;
  readonly folders: number;
  readonly bytes?: bigint | number;
}

export interface VaultShareDialogProps {
  engine: Pick<VaultEngine, 'create' | 'share'>;
  /** Notebook-relative folder: the folder to create from, or the vault's mount. */
  folderPath: string;
  /** Existing vault to share. Omit to create a new vault from `folderPath`. */
  vaultId?: VaultId;
  folderSummary?: VaultFolderSummary;
  /** Local identity; it is always the owner and cannot be added as a recipient. */
  localPubkey?: Pubkey;
  /** Endpoints the new vault will use (informational; defaults are snapshotted). */
  network?: VaultNetworkDefaults;
  snapshot?: VaultEngineSnapshot;
  existingMembers?: readonly VaultMemberView[];
  /** Live per-recipient delivery outcomes from the delivery ledger. */
  deliveries?: readonly VaultDeliveryView[];
  /** Device-key delivery settings (experimental NIP-4E). */
  deliveryOptions?: VaultDeliveryOptions;
  defaultLabel?: string;
  profileRelays?: readonly string[];
  resolveRecipient?: typeof parseRecipientInput;
  lookupProfile?: ProfileLookup;
  onClose: () => void;
  onCreated?: (vaultId: VaultId) => void;
  onShared?: (vaultId: VaultId, recipients: readonly Pubkey[]) => void;
}

type RecipientStatus = 'ready' | 'sending' | 'sent' | 'failed';

interface RecipientRow {
  pubkey: Pubkey;
  input: string;
  cap: VaultCapability;
  status: RecipientStatus;
  error: string | null;
}

const VaultShareDialog: Component<VaultShareDialogProps> = (props) => {
  const [vaultId, setVaultId] = createSignal<VaultId | undefined>(props.vaultId);
  const [label, setLabel] = createSignal(props.defaultLabel ?? props.folderPath.split('/').pop() ?? '');
  const [input, setInput] = createSignal('');
  const [inputError, setInputError] = createSignal<string | null>(null);
  const [resolving, setResolving] = createSignal(false);
  const [rows, setRows] = createStore<RecipientRow[]>([]);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [identityFallback, setIdentityFallback] = createSignal(props.deliveryOptions?.allowIdentityFallback ?? false);

  // Recipient state belongs to one vault; reset if the dialog is pointed at another.
  createEffect(on(() => props.vaultId, (id) => {
    setVaultId(() => id);
    setRows([]);
    setError(null);
  }, { defer: true }));

  const isCreate = () => !props.vaultId;
  const deviceDelivery = () => props.deliveryOptions?.enabled === true;
  const resolve = () => props.resolveRecipient ?? parseRecipientInput;

  const profiles = createProfileMap(
    () => [...rows.map((row) => row.pubkey), ...(props.existingMembers ?? []).map((m) => m.pubkey)],
    () => props.profileRelays ?? defaultProfileRelays(),
    props.lookupProfile ?? lookupProfile,
  );
  const displayName = (pubkey: string) => profiles().get(pubkey)?.name || formatPubkey(pubkey, 8);

  const existingSet = createMemo(() => new Set((props.existingMembers ?? []).map((m) => m.pubkey as string)));

  const addRecipient = async () => {
    const raw = input().trim();
    if (!raw || resolving()) return;
    setResolving(true);
    setInputError(null);
    try {
      const result = await resolve()(raw);
      if (!result.pubkey) {
        setInputError(result.error ?? 'Invalid recipient');
        return;
      }
      const pubkey = result.pubkey.toLowerCase() as Pubkey;
      if (props.localPubkey && pubkey === props.localPubkey) {
        setInputError('You are the owner of this vault already.');
        return;
      }
      if (rows.some((row) => row.pubkey === pubkey)) {
        setInputError('That recipient is already in the list.');
        return;
      }
      setRows(rows.length, { pubkey, input: raw, cap: 'read', status: 'ready', error: null });
      setInput('');
    } catch {
      setInputError('Could not resolve that recipient.');
    } finally {
      setResolving(false);
    }
  };

  const removeRecipient = (pubkey: Pubkey) => {
    setRows((current) => current.filter((row) => row.pubkey !== pubkey));
  };

  const delivery = (): VaultDeliveryOptions => ({
    enabled: deviceDelivery(),
    allowIdentityFallback: deviceDelivery() ? identityFallback() : undefined,
  });

  const setRowState = (pubkeys: readonly Pubkey[], status: RecipientStatus, rowError: string | null) => {
    setRows(produce((list) => {
      for (const row of list) {
        if (pubkeys.includes(row.pubkey)) {
          row.status = status;
          row.error = rowError;
        }
      }
    }));
  };

  const shareGroup = async (id: VaultId, pubkeys: readonly Pubkey[], cap: VaultCapability): Promise<boolean> => {
    setRowState(pubkeys, 'sending', null);
    try {
      await props.engine.share(id, pubkeys, cap, delivery());
      setRowState(pubkeys, 'sent', null);
      props.onShared?.(id, pubkeys);
      return true;
    } catch (err) {
      setRowState(pubkeys, 'failed', describeVaultError(err));
      return false;
    }
  };

  const ensureVault = async (): Promise<VaultId | null> => {
    const existing = vaultId();
    if (existing) return existing;
    try {
      const id = await props.engine.create(props.folderPath, {
        label: label().trim() || undefined,
        network: props.network,
      });
      setVaultId(() => id);
      props.onCreated?.(id);
      return id;
    } catch (err) {
      setError(describeVaultError(err));
      return null;
    }
  };

  const submit = async () => {
    if (busy()) return;
    setBusy(true);
    setError(null);
    try {
      const id = await ensureVault();
      if (!id) return;
      for (const cap of ['write', 'read'] as const) {
        const group = unsent().filter((row) => row.cap === cap).map((row) => row.pubkey);
        if (group.length) await shareGroup(id, group, cap);
      }
    } finally {
      setBusy(false);
    }
  };

  const retry = async (row: RecipientRow) => {
    const id = vaultId();
    if (!id || busy()) return;
    setBusy(true);
    try {
      await shareGroup(id, [row.pubkey], row.cap);
    } finally {
      setBusy(false);
    }
  };

  // A recipient ledger can describe an earlier grant, not this attempt.
  const effectiveStatus = (row: RecipientRow): RecipientStatus => row.status;

  const deliveries = () => props.deliveries ?? props.snapshot?.vaults.find(v => v.vaultId === vaultId())?.deliveries ?? [];

  const outcomeText = (row: RecipientRow): string => {
    switch (effectiveStatus(row)) {
      case 'ready': return '';
      case 'sending': return 'Sending...';
      case 'failed': return row.error ?? 'Delivery failed';
      case 'sent': return 'Invitation sent';
    }
  };

  const rowNeedsRetry = (row: RecipientRow) => {
    const status = effectiveStatus(row);
    return status === 'failed';
  };

  const unsent = () => rows.filter((row) => effectiveStatus(row) !== 'sent');
  const allSent = () => rows.length > 0 && unsent().length === 0;
  const created = () => isCreate() && vaultId() !== undefined;
  const canSubmit = () => !busy() && ((isCreate() && !created()) || unsent().length > 0);
  const submitLabel = () => {
    if (busy()) return 'Working...';
    if (isCreate() && !created()) return rows.length ? 'Create and share' : 'Create vault';
    return unsent().some((r) => r.status === 'failed') ? 'Retry failed' : 'Share';
  };

  return (
    <div class="modal-overlay" onClick={() => !busy() && props.onClose()}>
      <div class="modal-dialog vault-dialog" role="dialog" aria-label={isCreate() ? 'Share folder as vault' : 'Share vault'} onClick={(e) => e.stopPropagation()}>
        <div class="modal-header">
          <h3>{isCreate() ? 'Share folder as vault' : 'Share vault'}</h3>
          <button class="modal-close" aria-label="Close" onClick={() => props.onClose()} disabled={busy()}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        <div class="modal-body vault-dialog__body">
          <Show when={props.snapshot}><SharedVaultEngineStatus snapshot={props.snapshot} /></Show>
          <section class="vault-dialog__section vault-folder-summary">
            <div class="vault-folder-summary__path"><code>{props.folderPath || '/'}</code></div>
            <Show when={props.folderSummary}>
              {(summary) => (
                <div class="vault-folder-summary__counts">
                  {summary().files} file(s), {summary().folders} folder(s)
                  <Show when={summary().bytes !== undefined}>{`, ${formatBytes(summary().bytes ?? 0)}`}</Show>
                </div>
              )}
            </Show>
            <p class="vault-note">
              The contents of this folder, not its parent folders or the rest of this notebook, will be shared.
              Write members must be able to upload to the vault’s servers. Server allowlisting and payment are managed outside Onyx.
            </p>
          </section>

          <Show when={isCreate()}>
            <section class="vault-dialog__section">
              <label class="vault-field">
                <span class="vault-field__label">Local label</span>
                <input
                  class="vault-input"
                  type="text"
                  value={label()}
                  disabled={created()}
                  onInput={(e) => setLabel(e.currentTarget.value)}
                />
                <span class="vault-field__hint">Labels stay on this device; recipients choose their own.</span>
              </label>
            </section>
          </Show>

          <Show when={isCreate() && props.network}>
            {(network) => (
              <section class="vault-dialog__section">
                <div class="vault-field__label">Endpoints</div>
                <ul class="vault-endpoint-list">
                  <For each={[...new Set([...network().writeRelays, ...network().readRelays])]}>
                    {(url) => <li class="vault-endpoint-list__item"><span class="vault-tag">relay</span> {url}</li>}
                  </For>
                  <For each={[...new Set([...network().writeBlossom, ...network().readBlossom])]}>
                    {(url) => <li class="vault-endpoint-list__item"><span class="vault-tag">blossom</span> {url}</li>}
                  </For>
                </ul>
              </section>
            )}
          </Show>

          <Show when={(props.existingMembers ?? []).length > 0}>
            <section class="vault-dialog__section">
              <div class="vault-field__label">Already has access</div>
              <ul class="vault-member-list">
                <For each={props.existingMembers}>
                  {(member) => (
                    <li class="vault-member-list__item" data-pubkey={member.pubkey}>
                      <div class="vault-member__identity">
                        <span class="vault-member__name">{displayName(member.pubkey)}</span>
                        <KeyFingerprint pubkey={member.pubkey} />
                      </div>
                      <span class={`vault-badge vault-badge--${member.role}`}>{member.role}</span>
                    </li>
                  )}
                </For>
              </ul>
            </section>
          </Show>

          <section class="vault-dialog__section">
            <label class="vault-field">
              <span class="vault-field__label">Recipients</span>
              <div class="vault-recipient-input">
                <input
                  class={`vault-input ${inputError() ? 'vault-input--error' : ''}`}
                  type="text"
                  placeholder="npub1..., hex pubkey, or user@domain.com"
                  aria-label="Recipient"
                  value={input()}
                  disabled={busy()}
                  onInput={(e) => { setInput(e.currentTarget.value); setInputError(null); }}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void addRecipient(); } }}
                />
                <button class="setting-button secondary" onClick={() => void addRecipient()} disabled={resolving() || busy() || !input().trim()}>
                  {resolving() ? 'Resolving...' : 'Add'}
                </button>
              </div>
            </label>
            <Show when={inputError()}>
              <div class="vault-error" role="alert">{inputError()}</div>
            </Show>

            <ul class="vault-recipient-list">
              <For each={rows}>
                {(row) => (
                  <li class={`vault-recipient vault-recipient--${effectiveStatus(row)}`} data-pubkey={row.pubkey}>
                    <div class="vault-recipient__identity">
                      <span class="vault-recipient__name">{displayName(row.pubkey)}</span>
                      <KeyFingerprint pubkey={row.pubkey} />
                      <Show when={existingSet().has(row.pubkey)}>
                        <span class="vault-field__hint">updates existing access</span>
                      </Show>
                    </div>
                    <select
                      class="vault-select"
                      aria-label={`Capability for ${displayName(row.pubkey)}`}
                      value={row.cap}
                      disabled={row.status === 'sent' || row.status === 'sending'}
                      onChange={(e) => {
                        const cap = e.currentTarget.value as VaultCapability;
                        setRows((r) => r.pubkey === row.pubkey, 'cap', cap);
                      }}
                    >
                      <option value="read">Can read</option>
                      <option value="write">Can propose edits</option>
                    </select>
                    <span class="vault-recipient__outcome">{outcomeText(row)}</span>
                    <Show when={rowNeedsRetry(row) && vaultId()}>
                      <button class="setting-button small secondary" onClick={() => void retry(row)} disabled={busy()}>
                        Retry
                      </button>
                    </Show>
                    <Show when={row.status === 'ready' || (row.status === 'failed' && !existingSet().has(row.pubkey))}>
                      <button class="vault-link-button" aria-label={`Remove ${displayName(row.pubkey)}`} onClick={() => removeRecipient(row.pubkey)} disabled={busy()}>
                        Remove
                      </button>
                    </Show>
                  </li>
                )}
              </For>
            </ul>
            <p class="vault-note">
              Writers can propose edits; the owner's checkpoint decides what becomes the shared view.
              Readers are listed for information only.
            </p>
          </section>

          <Show when={deliveries().length > 0}>
            <section class="vault-dialog__section" aria-label="Delivery evidence">
              <h4>Delivery evidence</h4>
              <ul class="vault-member-list"><For each={deliveries()}>{delivery => (
                <li class="vault-member-list__item" data-recipient={delivery.recipient}>
                  <KeyFingerprint pubkey={delivery.recipient} /><span>{delivery.cap}</span>
                  <VaultDeliveryEvidence delivery={delivery} />
                </li>
              )}</For></ul>
            </section>
          </Show>

          <Show when={deviceDelivery()}>
            <section class="vault-dialog__section">
              <label class="vault-checkbox">
                <input
                  type="checkbox"
                  checked={identityFallback()}
                  onChange={(e) => setIdentityFallback(e.currentTarget.checked)}
                />
                <span>
                  If a recipient has not announced a device key, deliver to their identity key instead.
                </span>
              </label>
            </section>
          </Show>

          <Show when={error()}>
            <div class="vault-error" role="alert">{error()}</div>
          </Show>
          <Show when={created() && !props.vaultId}>
            <div class="vault-success" role="status">Vault created.</div>
          </Show>
        </div>

        <div class="modal-footer">
          <button class="setting-button secondary" onClick={() => props.onClose()} disabled={busy()}>
            {allSent() || created() ? 'Done' : 'Cancel'}
          </button>
          <button class="setting-button" onClick={() => void submit()} disabled={!canSubmit()}>
            {submitLabel()}
          </button>
        </div>
      </div>
    </div>
  );
};

export default VaultShareDialog;
