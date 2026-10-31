import { For, Show, createSignal, type Component } from 'solid-js';
import { platform } from '@platform';
import type { VaultRecoveryPassphraseRequest } from '../lib/vault/engine-api';
import { RECOVERY_MIN_PASSPHRASE_LENGTH } from '../lib/vault/recovery';

export function recoveryPassphraseValid(passphrase: string, confirmation: string, request?: VaultRecoveryPassphraseRequest): boolean {
  return Array.from(passphrase.normalize('NFKC')).length >= (request?.minimumLength ?? RECOVERY_MIN_PASSPHRASE_LENGTH)
    && passphrase === confirmation;
}

const RecoveryPassphraseFields: Component<{
  request?: VaultRecoveryPassphraseRequest;
  passphrase: string;
  confirmation: string;
  onPassphrase: (value: string) => void;
  onConfirmation: (value: string) => void;
}> = props => {
  const [copyStatus, setCopyStatus] = createSignal('');
  return <div class="vault-recovery">
    <Show when={props.request}>{request => <>
      <label>Suggested high-entropy passphrase<input class="vault-mono" type="text" readonly value={request().suggested} onFocus={event => event.currentTarget.select()} /></label>
      <button type="button" onClick={async () => {
        try { await platform.clipboard.writeText(request().suggested); setCopyStatus('Suggestion copied. Keep your clipboard private.'); }
        catch { setCopyStatus('Could not copy. Select the suggestion and copy it manually.'); }
      }}>Copy suggested passphrase</button>
      <button type="button" onClick={() => { props.onPassphrase(request().suggested); props.onConfirmation(request().suggested); }}>Use suggested passphrase</button>
      <p class="vault-note">At least {request().minimumLength} characters after NFKC normalization. scrypt log2(N): {request().logn}.</p>
      <ul class="vault-recovery__notes"><For each={request().notes}>{note => <li>{note}</li>}</For></ul>
      <Show when={copyStatus()}><p role="status">{copyStatus()}</p></Show>
    </>}</Show>
    <label>Passphrase<input type="password" autocomplete="new-password" value={props.passphrase} onInput={event => props.onPassphrase(event.currentTarget.value)} /></label>
    <label>Confirm passphrase<input type="password" autocomplete="new-password" value={props.confirmation} onInput={event => props.onConfirmation(event.currentTarget.value)} /></label>
    <Show when={props.passphrase && !recoveryPassphraseValid(props.passphrase, props.confirmation, props.request)}>
      <p class="vault-field__hint">Meet the minimum length and enter the same passphrase twice.</p>
    </Show>
  </div>;
};
export default RecoveryPassphraseFields;
