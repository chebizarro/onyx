import { Show, type Component } from 'solid-js';
import type { VaultDeliveryView } from './vault-ui';

const VaultDeliveryEvidence: Component<{ delivery: VaultDeliveryView }> = props => (
  <span class="vault-delivery__evidence">
    <Show when={props.delivery.notice}>{notice => <span>Identity-key fallback: {notice()}. </span>}</Show>
    <Show when={props.delivery.evidence}>{evidence => <span>Announcement evidence: {evidence()}. This does not prove the key is still current.</span>}</Show>
  </span>
);
export default VaultDeliveryEvidence;
