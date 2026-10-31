import { For, Show, type Component } from 'solid-js';
import type { VaultEngineSnapshot } from '../lib/vault/engine-api';
import VaultSecurityState from './VaultSecurityState';

export function sharedVaultStatus(snapshot?: VaultEngineSnapshot, error?: string | null) {
  const degraded = snapshot?.endpoints?.some(endpoint => endpoint.status !== 'usable' && endpoint.status !== 'authenticated') ?? false;
  const quarantined = snapshot?.vaults.some(vault => !!vault.foldQuarantine) ?? false;
  const inbox = snapshot?.inbox && snapshot.inbox.state !== 'active' ? snapshot.inbox : null;
  const unavailable = snapshot?.unavailableVaults?.length ?? 0;
  const attention = quarantined || !!inbox || unavailable > 0 || !!error || !snapshot || snapshot.lifecycle !== 'running' || snapshot.condition !== 'ready';
  const message = error || snapshot?.lastError?.message || inbox?.message || (unavailable ? `${unavailable} stored shared vault${unavailable === 1 ? '' : 's'} could not be opened and need${unavailable === 1 ? 's' : ''} repair.` : null) || (!snapshot ? 'Sign in and open a notebook to use shared vaults.'
    : snapshot.lifecycle !== 'running' ? `Shared vault engine is ${snapshot.lifecycle}. Retry to start it.`
    : snapshot.condition !== 'ready' ? `Shared vault engine is ${snapshot.condition}. Check the endpoints and retry.`
    : quarantined ? 'Auto-publish blocked by fold quarantine; revoke or resolve to repair.'
    : degraded ? 'Shared vaults are ready. Some endpoints are not used; healthy services remain available.' : 'Shared vaults are ready.');
  return { attention, message, inbox, label: attention ? `${snapshot?.lifecycle ?? 'stopped'} / ${snapshot?.condition ?? 'not ready'} — ${message}`
    : degraded ? 'ready (degraded endpoints)' : `ready / ${snapshot.activity}`, degraded };
}

const SharedVaultEngineStatus: Component<{
  snapshot?: VaultEngineSnapshot;
  error?: string | null;
  onRetry?: () => void;
  /** Compacts the invitation inbox replay store and resumes ingestion (SEC-G). */
  onRepairInbox?: () => void;
  onOpen?: () => void;
}> = props => {
  const status = () => sharedVaultStatus(props.snapshot, props.error);
  return <Show when={props.onOpen} fallback={
    <section class="vault-engine-status" aria-label="Shared vault engine">
      <p classList={{ 'vault-error': status().attention }} role={status().attention ? 'alert' : 'status'}>{status().message}</p>
      <Show when={status().attention && props.onRetry}><button class="vault-btn" onClick={() => props.onRetry?.()}>Retry shared vaults</button></Show>
      <Show when={status().inbox}>{inbox => <p class="vault-error" role="status">
        Invitation inbox {inbox().state === 'at-capacity' ? `at capacity (${inbox().durableIds}/${inbox().capacity} invitation records)` : 'stopped'} — new invitations are not being ingested. Your shared vaults keep syncing.
        <Show when={props.onRepairInbox}> <button class="vault-btn" onClick={() => props.onRepairInbox?.()}>Repair invitation inbox</button></Show>
      </p>}</Show>
      <For each={props.snapshot?.unavailableVaults}>{vault => <p class="vault-error" role="status">
        Shared vault {vault.vaultId.slice(0, 12)} — needs repair: {vault.error.message} Its stored data is kept unchanged.
      </p>}</For>
      <For each={props.snapshot?.vaults}>{vault => <span class="vault-engine-status__vault">{vault.label}: <VaultSecurityState vault={vault} /></span>}</For>
      <ul class="vault-endpoint-list"><For each={props.snapshot?.endpoints}>{endpoint =>
        <li class="vault-endpoint-list__item"><span class="vault-tag">{endpoint.kind}</span> {endpoint.url}: {endpoint.message}<Show when={endpoint.service}> ({endpoint.service})</Show></li>
      }</For></ul>
    </section>
  }>
    <button class="status-item shared-vault-status" classList={{ 'shared-vault-status--attention': status().attention, 'shared-vault-status--degraded': status().degraded }}
      title={status().message} onClick={() => props.onOpen?.()}>
      Shared vaults: {status().label}{props.snapshot?.vaults.some(vault => vault.conflictCount > 0) ? ' (conflicts)' : ''}
      <For each={props.snapshot?.unavailableVaults}>{vault => <span class="vault-engine-status__vault">{vault.vaultId.slice(0, 12)}: needs repair</span>}</For>
      <For each={props.snapshot?.vaults}>{vault => <span class="vault-engine-status__vault">{vault.label}: <VaultSecurityState vault={vault} /></span>}</For>
    </button>
  </Show>;
};
export default SharedVaultEngineStatus;
