/**
 * VaultPanel
 *
 * Status and management for one shared vault: observable state (§6.2),
 * members, revocation with regrant headroom, delivery retry, lazy/eager
 * re-seal, publishing-device handover, pause/resume/detach and recovery.
 */

import { Component, For, Show, createEffect, createMemo, createSignal, untrack } from 'solid-js';
import { VaultError } from '../lib/vault/errors';
import { formatPubkey } from '../lib/nostr/nip05';
import type {
  VaultCapability, VaultDeliveryOptions, VaultEngine, VaultEngineSnapshot, VaultResealBudget,
} from '../lib/vault/engine-api';
import type { Pubkey, VaultId, VaultRecoveryPackage } from '../lib/vault/types';
import {
  AUTHORITY_LABELS, createProfileMap, defaultProfileRelays, describeVaultError, formatBytes,
  formatUnixTime, headroomBytes, headroomExhausted, lookupProfile, shortVaultId, useSnapshot,
  type ProfileLookup, type VaultDeliveryView, type VaultMemberView, type VaultRegrantHeadroom,
} from './vault-ui';
import KeyFingerprint from './KeyFingerprint';
import VaultSecurityState from './VaultSecurityState';
import VaultDeliveryEvidence from './VaultDeliveryEvidence';
import './vault.css';

/** Default automatic owner budget per pass (§6.12). */
export const DEFAULT_RESEAL_BUDGET: VaultResealBudget = 8n * 1024n * 1024n;

export type VaultPanelEngine = Pick<VaultEngine,
  'subscribe' | 'sync' | 'share' | 'revoke' | 'reseal' | 'pause' | 'resume' | 'detach'
  | 'exportRecovery' | 'takeOverPublishing'>;

export interface VaultPanelProps {
  engine: VaultPanelEngine;
  vaultId: VaultId;
  /** Supply to drive the panel from an existing subscription. */
  snapshot?: VaultEngineSnapshot;
  localPubkey?: Pubkey;
  /** Owner, writers and informational readers from the owner checkpoint. */
  members?: readonly VaultMemberView[];
  deliveries?: readonly VaultDeliveryView[];
  /** Pre-flight grant-size check for the next revocation. */
  regrantHeadroom?: VaultRegrantHeadroom | null;
  deliveryOptions?: VaultDeliveryOptions;
  resealBudget?: VaultResealBudget;
  profileRelays?: readonly string[];
  lookupProfile?: ProfileLookup;
  onShare?: (vaultId: VaultId) => void;
  onOpenConflicts?: (vaultId: VaultId) => void;
  /** App-owned complete workflow, including serialization, prompting and saving. */
  onExportRecovery?: (vaultId: VaultId) => Promise<void>;
  onRecoveryExported?: (pkg: VaultRecoveryPackage) => void | Promise<void>;
  onDetached?: (vaultId: VaultId) => void;
  onClose?: () => void;
}

type Confirm =
  | { readonly kind: 'revoke'; readonly pubkey: Pubkey }
  | { readonly kind: 'detach' }
  | { readonly kind: 'eager' }
  | { readonly kind: 'recovery' }
  | { readonly kind: 'takeover' };



const VaultPanel: Component<VaultPanelProps> = (props) => {
  const snapshot = useSnapshot(props.engine, () => props.snapshot);
  const vault = createMemo(() => snapshot().vaults.find((v) => v.vaultId === props.vaultId));
  const otherProvisional = createMemo(() => new Set(vault()?.provisionalOtherPaths ?? []));
  const [busy, setBusy] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [notice, setNotice] = createSignal<string | null>(null);
  const [confirm, setConfirm] = createSignal<Confirm | null>(null);
  const [recoveryAck, setRecoveryAck] = createSignal(false);
  // "Re-seal everything now" chosen inside the revocation confirmation.
  const [revokeResealNow, setRevokeResealNow] = createSignal(false);

  // Older snapshots lack a total; use the largest locally observed remainder.
  const [observedPeak, setObservedPeak] = createSignal(0n);
  createEffect(() => {
    const remaining = vault()?.resealRemainingBytes ?? 0n;
    const peak = untrack(observedPeak);
    if (remaining === 0n) { if (peak !== 0n) setObservedPeak(0n); }
    else if (remaining > peak) setObservedPeak(remaining);
  });
  const resealTotal = (): bigint | null => {
    const v = vault();
    if (!v) return null;
    const declared = v.resealTotalBytes;
    if (typeof declared === 'bigint' && declared > 0n) return declared;
    return observedPeak() > 0n ? observedPeak() : null;
  };
  const resealPercent = (): number | null => {
    const total = resealTotal();
    const remaining = vault()?.resealRemainingBytes ?? 0n;
    if (total === null || total <= 0n) return null;
    const done = total > remaining ? total - remaining : 0n;
    return Number((done * 100n) / total);
  };

  const members = () => props.members ?? [];
  const profiles = createProfileMap(
    () => [...members().map((m) => m.pubkey), ...(vault() ? [vault()!.owner] : [])],
    () => props.profileRelays ?? defaultProfileRelays(snapshot(), props.vaultId),
    props.lookupProfile ?? lookupProfile,
  );
  const nameOf = (pubkey: string) => {
    if (props.localPubkey && pubkey === props.localPubkey) return 'You';
    return profiles().get(pubkey)?.name || formatPubkey(pubkey, 8);
  };

  const isOwner = () => vault()?.authority === 'owner';
  const isPublisher = () => vault()?.publisher?.isCurrentDevice === true;
  const canAdminister = () => isOwner() && isPublisher();
  const writers = () => members().filter((m) => m.role === 'writer');
  const readers = () => members().filter((m) => m.role === 'reader');
  const revokeBlocked = () => headroomExhausted(props.regrantHeadroom);

  const run = async (name: string, action: () => Promise<unknown>, done?: string | (() => string)) => {
    if (busy()) return;
    setBusy(name);
    setError(null);
    setNotice(null);
    try {
      await action();
      if (done) setNotice(typeof done === 'function' ? done() : done);
    } catch (err) {
      setError(describeVaultError(err));
    } finally {
      setBusy(null);
    }
  };

  const pendingDeliveries = () => (props.deliveries ?? []).filter((d) => d.pending.length > 0);

  const retryDeliveries = () => run('retry', async () => {
    const pending = pendingDeliveries();
    if (pending.length === 0) {
      await props.engine.sync(props.vaultId);
      return;
    }
    for (const cap of ['write', 'read'] as VaultCapability[]) {
      const group = pending.filter((d) => d.cap === cap).map((d) => d.recipient);
      if (group.length) await props.engine.share(props.vaultId, group, cap, props.deliveryOptions ?? {});
    }
  }, 'Delivery retry started.');

  const confirmAction = async () => {
    const current = confirm();
    if (!current) return;
    setConfirm(null);
    switch (current.kind) {
      case 'revoke': {
        const resealNow = revokeResealNow();
        setRevokeResealNow(false);
        let resealed: bigint | null = null;
        await run('revoke', async () => {
          await props.engine.revoke(props.vaultId, current.pubkey);
          if (!resealNow) return;
          // The subscription has delivered the post-revocation snapshot by now;
          // eager re-seal must be given the full remaining size.
          const remaining = vault()?.resealRemainingBytes ?? 0n;
          setNotice('Access revoked. Re-sealing all remaining content...');
          if (remaining > 0n) await props.engine.reseal(props.vaultId, remaining, 'eager');
          resealed = remaining;
        }, () => {
          if (resealed === null) return 'Access revoked. Content written before this revocation and not changed since stays readable to the removed member until re-seal completes.';
          return resealed > 0n
            ? 'Access revoked and all content re-sealed under the current key.'
            : 'Access revoked. Nothing needed re-sealing.';
        });
        break;
      }
      case 'detach':
        await run('detach', async () => {
          await props.engine.detach(props.vaultId);
          props.onDetached?.(props.vaultId);
        }, 'Vault detached. Local files were left in place.');
        break;
      case 'eager':
        await run('reseal', () => props.engine.reseal(props.vaultId, vault()?.resealRemainingBytes ?? 0n, 'eager'), 'Re-seal complete.');
        break;
      case 'recovery':
        await run('recovery', async () => {
          if (props.onExportRecovery) await props.onExportRecovery(props.vaultId);
          else {
            const pkg = await props.engine.exportRecovery(props.vaultId);
            if (props.onRecoveryExported) {
              try { await props.onRecoveryExported(pkg); }
              catch (error) {
                if (error instanceof VaultError && error.code === 'CANCELLED') throw error;
                throw new VaultError('IO', { operation: 'recover' });
              }
            }
            else throw new VaultError('IO', { operation: 'recover' });
          }
        }, 'Recovery package exported.');
        setRecoveryAck(false);
        break;
      case 'takeover':
        await run('takeover', () => props.engine.takeOverPublishing(props.vaultId), 'This device now publishes for the vault.');
        break;
    }
  };

  const confirmText = (c: Confirm): string => {
    switch (c.kind) {
      case 'revoke':
        return `Revoke access for ${nameOf(c.pubkey)}? New and changed content will be sealed under a fresh key and the remaining members receive updated grants. `
          + `Content written before this revocation that has not changed since stays readable to ${nameOf(c.pubkey)} until it is re-sealed; `
          + 're-seal runs gradually in the background unless you re-seal everything now. '
          + 'Revocation does not retract anything they have already downloaded.';
      case 'detach':
        return 'Detach this vault from this device? Syncing stops and the local folder is left as ordinary files. The vault and other members are unaffected.';
      case 'eager':
        return `Re-seal all remaining content now? This downloads and re-uploads about ${formatBytes(vault()?.resealRemainingBytes ?? 0n)}.`;
      case 'recovery':
        return 'Export an encrypted recovery package for this vault. It contains vault keys protected by your recovery passphrase; store it somewhere safe.';
      case 'takeover':
        return 'Take over publishing on this device? The current publishing device will stop publishing; its unpublished changes stay local there.';
    }
  };

  const errorDisplay = () => vault()?.lastError ?? snapshot().lastError;

  return (
    <section class="vault-panel" aria-label="Shared vault">
      <Show when={vault()} fallback={<div class="vault-panel__empty">This vault is not available on this device.</div>}>
        {(v) => (
          <>
            <header class="vault-panel__header">
              <div class="vault-panel__title">
                <h3>{v().label || shortVaultId(v().vaultId)}</h3>
                <span class={`vault-badge vault-badge--${v().authority}`}>{AUTHORITY_LABELS[v().authority]}</span>
                <Show when={v().provisional}><span class="vault-badge vault-badge--provisional">{v().provisionalCount} pending owner review</span></Show>
                <Show when={!v().enabled}><span class="vault-badge vault-badge--paused">Paused</span></Show>
              </div>
              <Show when={props.onClose}>
                <button class="modal-close" aria-label="Close" onClick={() => props.onClose?.()}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                  </svg>
                </button>
              </Show>
            </header>

            <dl class="vault-facts vault-panel__status">
              <dt>Folder</dt>
              <dd class="vault-mono">{v().mount?.relativePath ?? 'Not mounted'}</dd>
              <dt>Vault id</dt>
              <dd class="vault-mono" title={v().vaultId}>{shortVaultId(v().vaultId)}</dd>
              <dt>Engine</dt>
              <dd data-testid="vault-engine-state">{snapshot().lifecycle} / {snapshot().activity} / {snapshot().condition}</dd>
              <dt>Security state</dt>
              <dd><VaultSecurityState vault={v()} /></dd>
              <dt>Conflicts</dt>
              <dd>
                {v().conflictCount}
                <Show when={v().conflictCount > 0 && props.onOpenConflicts}>
                  <button class="vault-link-button" onClick={() => props.onOpenConflicts?.(v().vaultId)}>Review</button>
                </Show>
              </dd>
              <dt>Pending deliveries</dt>
              <dd>
                {v().pendingDeliveryCount}
                <Show when={v().pendingDeliveryCount > 0 && canAdminister()}>
                  <button class="vault-link-button" onClick={() => void retryDeliveries()} disabled={busy() !== null}>
                    Retry deliveries
                  </button>
                </Show>
              </dd>
              <dt>Re-seal</dt>
              <dd data-testid="vault-reseal-status">
                <Show when={v().resealRemainingBytes > 0n} fallback={
                  <span class="vault-reseal vault-reseal--complete">Complete. All content is sealed under the current key.</span>
                }>
                  <span class="vault-reseal vault-reseal--pending">
                    {formatBytes(v().resealRemainingBytes)} remaining
                    <Show when={resealPercent() !== null}>{` (${resealPercent()}% done)`}</Show>
                  </span>
                  <Show when={resealPercent() !== null}>
                    <progress class="vault-reseal__bar" max="100" value={resealPercent() ?? 0} aria-label="Re-seal progress" />
                  </Show>
                </Show>
              </dd>
            </dl>

            <Show when={v().provisional && !v().foldQuarantine}>
              <section aria-label="Pending owner review">
                <p class="vault-note">These paths differ from the owner's checkpoint, including additions and deletions.</p>
                <ul>
                  <For each={v().provisionalPaths}>{path => (
                    <li><span class="vault-mono">{path}</span>{' '}
                      <span class={`vault-badge vault-badge--${otherProvisional().has(path) ? 'provisional-other' : 'provisional'}`}>
                        {otherProvisional().has(path) ? "Other writer's edit" : 'Your edit'}
                      </span>
                    </li>
                  )}</For>
                </ul>
                <Show when={v().provisionalCount > v().provisionalPaths.length}>
                  <p class="vault-note">Showing {v().provisionalPaths.length} of {v().provisionalCount} paths.</p>
                </Show>
              </section>
            </Show>

            <Show when={errorDisplay()}>
              {(e) => (
                <div class="vault-error" role="alert">
                  {e().message}
                  <Show when={e().retryable}>
                    <button class="vault-link-button" onClick={() => void run('sync', () => props.engine.sync(props.vaultId))}>Retry</button>
                  </Show>
                </div>
              )}
            </Show>

            <Show when={isOwner()}>
              <section class="vault-panel__section">
                <h4>Publishing device</h4>
                <Show when={v().publisher} fallback={<p class="vault-note">No publishing device is recorded for this vault.</p>}>
                  {(p) => (
                    <p class="vault-publisher" data-testid="vault-publisher">
                      {p().deviceLabel}
                      <Show when={p().isCurrentDevice}> (this device)</Show>
                      <span class="vault-field__hint"> since {formatUnixTime(p().since)}</span>
                    </p>
                  )}
                </Show>
                <Show when={!isPublisher()}>
                  <p class="vault-note">
                    Only the publishing device publishes owner changes. Edits on this device are kept locally.
                  </p>
                  <button class="setting-button secondary" onClick={() => setConfirm({ kind: 'takeover' })} disabled={busy() !== null}>
                    Take over publishing on this device
                  </button>
                </Show>
              </section>
            </Show>

            <section class="vault-panel__section">
              <h4>Members</h4>
              <ul class="vault-member-list">
                <li class="vault-member-list__item" data-pubkey={v().owner}>
                  <div class="vault-member__identity">
                    <span class="vault-member__name">{nameOf(v().owner)}</span>
                    <KeyFingerprint pubkey={v().owner} />
                  </div>
                  <span class="vault-badge vault-badge--owner">owner</span>
                </li>
                <For each={writers()}>
                  {(member) => (
                    <li class="vault-member-list__item" data-pubkey={member.pubkey}>
                      <div class="vault-member__identity">
                        <span class="vault-member__name">{nameOf(member.pubkey)}</span>
                        <KeyFingerprint pubkey={member.pubkey} />
                      </div>
                      <span class="vault-badge vault-badge--writer">writer</span>
                      <Show when={canAdminister()}>
                        <button
                          class="vault-link-button vault-link-button--danger"
                          aria-label={`Revoke ${nameOf(member.pubkey)}`}
                          disabled={busy() !== null || revokeBlocked()}
                          onClick={() => setConfirm({ kind: 'revoke', pubkey: member.pubkey })}
                        >Revoke</button>
                      </Show>
                    </li>
                  )}
                </For>
              </ul>
              <Show when={readers().length > 0}>
                <div class="vault-field__label">Readers (informational)</div>
                <p class="vault-field__hint">
                  The readers list is informational: anyone holding a current grant can read.
                </p>
                <ul class="vault-member-list">
                  <For each={readers()}>
                    {(member) => (
                      <li class="vault-member-list__item" data-pubkey={member.pubkey}>
                        <div class="vault-member__identity">
                          <span class="vault-member__name">{nameOf(member.pubkey)}</span>
                          <KeyFingerprint pubkey={member.pubkey} />
                        </div>
                        <span class="vault-badge vault-badge--reader">reader</span>
                        <Show when={canAdminister()}>
                          <button
                            class="vault-link-button vault-link-button--danger"
                            aria-label={`Revoke ${nameOf(member.pubkey)}`}
                            disabled={busy() !== null || revokeBlocked()}
                            onClick={() => setConfirm({ kind: 'revoke', pubkey: member.pubkey })}
                          >Revoke</button>
                        </Show>
                      </li>
                    )}
                  </For>
                </ul>
              </Show>
              <Show when={isOwner() && props.regrantHeadroom}>
                {(h) => (
                  <p class={`vault-headroom ${revokeBlocked() ? 'vault-headroom--exhausted' : ''}`} data-testid="vault-headroom">
                    Grant size headroom: {formatBytes(Math.max(0, headroomBytes(h())))} left
                    <Show when={h().remainingRevocations !== undefined}>
                      {` (about ${h().remainingRevocations} more revocation(s))`}
                    </Show>
                  </p>
                )}
              </Show>
              <Show when={isOwner() && revokeBlocked()}>
                <div class="vault-error">
                  Revocation is blocked: updated grants for the remaining members would exceed the 64 KiB envelope limit.
                  Create a new vault for the remaining members instead.
                </div>
              </Show>
            </section>

            <Show when={(props.deliveries ?? v().deliveries ?? []).length > 0}>
              <section class="vault-panel__section" aria-label="Deliveries">
                <h4>Deliveries</h4>
                <ul class="vault-member-list"><For each={props.deliveries ?? v().deliveries}>{delivery => (
                  <li class="vault-member-list__item"><KeyFingerprint pubkey={delivery.recipient} />
                    <span>{delivery.acknowledged.length} acknowledged, {delivery.pending.length} pending</span>
                    <VaultDeliveryEvidence delivery={delivery} />
                  </li>
                )}</For></ul>
              </section>
            </Show>

            <Show when={isOwner() && v().resealRemainingBytes > 0n}>
              <section class="vault-panel__section">
                <h4>Re-seal</h4>
                <p class="vault-note">
                  Content written before the last revocation is re-encrypted gradually, {formatBytes(props.resealBudget ?? DEFAULT_RESEAL_BUDGET)} per pass.
                  Until it completes, content that has not changed since the revocation stays readable to removed members who kept their old keys.
                </p>
                <div class="vault-actions">
                  <button
                    class="setting-button secondary"
                    disabled={busy() !== null || !canAdminister()}
                    onClick={() => void run('reseal', () => props.engine.reseal(props.vaultId, props.resealBudget ?? DEFAULT_RESEAL_BUDGET, 'lazy'))}
                  >Continue re-seal</button>
                  <button
                    class="setting-button secondary"
                    disabled={busy() !== null || !canAdminister()}
                    onClick={() => setConfirm({ kind: 'eager' })}
                  >Re-seal everything now</button>
                </div>
              </section>
            </Show>

            <section class="vault-panel__section vault-actions">
              <button class="setting-button" disabled={busy() !== null || !v().enabled} onClick={() => void run('sync', () => props.engine.sync(props.vaultId), 'Sync requested.')}>
                {busy() === 'sync' ? 'Syncing...' : 'Sync now'}
              </button>
              <Show when={canAdminister() && props.onShare}>
                <button class="setting-button secondary" disabled={busy() !== null} onClick={() => props.onShare?.(v().vaultId)}>Share...</button>
              </Show>
              <Show when={v().enabled} fallback={
                <button class="setting-button secondary" disabled={busy() !== null} onClick={() => void run('resume', () => props.engine.resume(props.vaultId))}>Resume</button>
              }>
                <button class="setting-button secondary" disabled={busy() !== null} onClick={() => void run('pause', () => props.engine.pause(props.vaultId))}>Pause</button>
              </Show>
              <button class="setting-button secondary" disabled={busy() !== null} onClick={() => setConfirm({ kind: 'recovery' })}>Export recovery...</button>
              <button class="setting-button danger-outline" disabled={busy() !== null} onClick={() => setConfirm({ kind: 'detach' })}>Detach...</button>
            </section>

            <Show when={confirm()}>
              {(c) => (
                <div class="vault-confirm" role="alertdialog" aria-label="Confirm">
                  <p>{confirmText(c())}</p>
                  <Show when={c().kind === 'recovery'}>
                    <label class="vault-checkbox">
                      <input type="checkbox" checked={recoveryAck()} onChange={(e) => setRecoveryAck(e.currentTarget.checked)} />
                      <span>I understand anyone with this file and my recovery passphrase can read the vault.</span>
                    </label>
                  </Show>
                  <Show when={c().kind === 'revoke'}>
                    <label class="vault-checkbox">
                      <input type="checkbox" checked={revokeResealNow()} onChange={(e) => setRevokeResealNow(e.currentTarget.checked)} />
                      <span>
                        Re-seal everything now after revoking. This downloads and re-uploads all content written before this
                        revocation; nothing stays readable to the removed member once it finishes.
                      </span>
                    </label>
                  </Show>
                  <div class="vault-actions">
                    <button class="setting-button secondary" onClick={() => { setConfirm(null); setRecoveryAck(false); setRevokeResealNow(false); }}>Cancel</button>
                    <button
                      class={`setting-button ${c().kind === 'revoke' || c().kind === 'detach' ? 'danger' : ''}`}
                      disabled={c().kind === 'recovery' && !recoveryAck()}
                      onClick={() => void confirmAction()}
                    >Confirm</button>
                  </div>
                </div>
              )}
            </Show>

            <Show when={notice()}>
              <div class="vault-success" role="status">{notice()}</div>
            </Show>
            <Show when={error()}>
              <div class="vault-error" role="alert" data-testid="vault-action-error">{error()}</div>
            </Show>

            <Show when={isOwner()}>
              <p class="vault-field__hint">
                Legacy sync copies of this folder published before it became a shared vault stay on your relays.
              </p>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
};

export default VaultPanel;
