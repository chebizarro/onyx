import { Show, type Component } from 'solid-js';
import type { VaultSummary } from '../lib/vault/engine-api';

const VaultSecurityState: Component<{ vault: VaultSummary }> = props => (
  <span class="vault-security-state">
    <span>Freshness: {props.vault.freshness ?? 'unverified'} (not proof of latest state). </span>
    <span>History: {props.vault.history === 'verified' ? 'complete' : props.vault.history ?? 'unavailable'}{props.vault.history === 'incomplete' ? ' (missing or behind-ring ledger)' : ''}. </span>
    <Show when={props.vault.checkpoint}>{checkpoint => (
      <span>Checkpoint: seq {String(checkpoint().seq)}, epoch {String(checkpoint().epoch)}, grantsRev {String(checkpoint().grantsRev)}. </span>
    )}</Show>
    <Show when={props.vault.foldQuarantine}>{quarantine => (
      <span class="vault-security-state__quarantine" role="alert">Fold quarantined: {quarantine().reason}, {quarantine().rows} rows, {quarantine().bytes} bytes. Auto-publish blocked; revoke or resolve to repair.</span>
    )}</Show>
  </span>
);
export default VaultSecurityState;
