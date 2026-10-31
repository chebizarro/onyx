import { finalizeEvent, generateSecretKey, nip44, verifyEvent, type Event, type Filter } from 'nostr-tools';
import type { fetchUserRelays } from '../nostr/login';
import type { NostrSigner } from '../nostr/signer';
import { hex32, paddedLength } from './crypto';
import { resolveGrantRecipient, type DeviceDeliveryOptions, type GrantRecipient } from './device-keys';
import { VaultError } from './errors';
import { buildGrantRumor, openGrantRumor } from './grant';
import { boundedEvent } from './ingress';
import {
  NIP59_MAX_PLAINTEXT, NIP59_MAX_PAYLOAD, NIP59_TIMESTAMP_RANDOM_RANGE,
  VAULT_GIFT_WRAP_KIND, VAULT_GRANT_KIND, VAULT_SEAL_KIND,
} from './protocol';
import { VaultRelay, validatePublicEndpoint, type RelayHandlers, type RelayPublishResult } from './relay';
import type { GrantRumor, Pubkey, VaultGrant } from './types';

const encoder = new TextEncoder();
export type GrantDecryptor = Pick<NostrSigner, 'getPublicKey' | 'nip44'>;
export interface WrappedGrant {
  wrap: Event;
  rumorId: string;
  recipientKey: Pubkey;
}
export interface OpenedGrant extends WrappedGrant {
  grant: VaultGrant;
  rumor: GrantRumor;
}

function plaintext(text: string): string {
  if (typeof text !== 'string' || text.includes('\0')) throw new VaultError('AUTH');
  if (encoder.encode(text).length > NIP59_MAX_PLAINTEXT) throw new VaultError('TOO_LARGE');
  return text;
}
function parsePlaintext(text: string): unknown {
  plaintext(text);
  try { return JSON.parse(text); } catch { throw new VaultError('AUTH'); }
}
function signedEvent(value: unknown, kind: number): Event {
  try {
    const { event } = boundedEvent(value);
    if (event.kind !== kind || event.content.length > NIP59_MAX_PAYLOAD || !verifyEvent(event)) throw new Error();
    return event;
  } catch { throw new VaultError('AUTH', { operation: 'open' }); }
}

/** Uniform offset in [1, 172800]; RNG failures are fatal, never real-time fallback. */
export function randomizedTimestamp(now = Math.floor(Date.now() / 1000), rng?: (length: number) => Uint8Array): number {
  if (!Number.isSafeInteger(now) || now < NIP59_TIMESTAMP_RANDOM_RANGE) throw new VaultError('ARG');
  const ceiling = Math.floor(0x100000000 / NIP59_TIMESTAMP_RANDOM_RANGE) * NIP59_TIMESTAMP_RANDOM_RANGE;
  const sample = new Uint32Array(1);
  try {
    do {
      if (rng) {
        const bytes = rng(4);
        if (bytes.length !== 4) throw new Error();
        sample[0] = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
      } else crypto.getRandomValues(sample);
    } while (sample[0] >= ceiling);
  } catch { throw new VaultError('CRYPTO', { operation: 'seal' }); }
  return now - (sample[0] % NIP59_TIMESTAMP_RANDOM_RANGE + 1);
}

export function grantWrapPlaintextSizes(grant: VaultGrant, now = Math.floor(Date.now() / 1000)): { rumorBytes: number; sealBytes: number } {
  const rumorBytes = encoder.encode(JSON.stringify(buildGrantRumor(grant))).length;
  const encryptedLength = 4 * Math.ceil((1 + 32 + 2 + paddedLength(rumorBytes) + 32) / 3);
  const sealBytes = encoder.encode(JSON.stringify({ kind: VAULT_SEAL_KIND, tags: [], created_at: now,
    content: 'A'.repeat(encryptedLength), pubkey: grant.owner, id: '0'.repeat(64), sig: '0'.repeat(128) })).length;
  return { rumorBytes, sealBytes };
}
export function assertGrantWrapFits(grant: VaultGrant, now = Math.floor(Date.now() / 1000)): void {
  const sizes = grantWrapPlaintextSizes(grant, now);
  if (sizes.rumorBytes > NIP59_MAX_PLAINTEXT || sizes.sealBytes > NIP59_MAX_PLAINTEXT) throw new VaultError('TOO_LARGE');
}

export async function buildGrantWrap(grant: VaultGrant, signer: NostrSigner, recipient: string,
  options: { clock?: () => number; rng?: (length: number) => Uint8Array } = {}): Promise<WrappedGrant> {
  const recipientKey = hex32<Pubkey>(recipient);
  if (await signer.getPublicKey() !== grant.owner) throw new VaultError('AUTH');
  if (!signer.nip44) throw new VaultError('UNSUPPORTED');
  assertGrantWrapFits(grant, options.clock?.());
  const rumor = buildGrantRumor(grant);
  const rumorJSON = plaintext(JSON.stringify(rumor));
  const template = { kind: VAULT_SEAL_KIND, tags: [] as string[][], created_at: randomizedTimestamp(options.clock?.(), options.rng),
    content: await signer.nip44.encrypt(recipientKey, rumorJSON) };
  const seal = signedEvent(await signer.signEvent(template), VAULT_SEAL_KIND);
  if (seal.pubkey !== grant.owner || seal.tags.length || seal.created_at !== template.created_at ||
      seal.content !== template.content) throw new VaultError('AUTH');
  const sealJSON = plaintext(JSON.stringify(seal));
  const ephemeral = options.rng ? options.rng(32) : generateSecretKey();
  try {
    const key = nip44.v2.utils.getConversationKey(ephemeral, recipientKey);
    try {
      const wrap = finalizeEvent({ kind: VAULT_GIFT_WRAP_KIND, created_at: randomizedTimestamp(options.clock?.(), options.rng),
        tags: [['p', recipientKey]], content: nip44.v2.encrypt(sealJSON, key) }, ephemeral);
      return { wrap, rumorId: rumor.id, recipientKey };
    } finally { key.fill(0); }
  } finally { ephemeral.fill(0); }
}

/** Verify the outer event before selecting a decryptor or asking a signer to decrypt. */
export async function openGrantWrap(
  value: unknown, identity: GrantDecryptor, devices: readonly GrantDecryptor[] = [],
): Promise<OpenedGrant | null> {
  const wrap = signedEvent(value, VAULT_GIFT_WRAP_KIND);
  const p = wrap.tags.filter(tag => tag[0] === 'p');
  if (p.length !== 1 || (p[0].length !== 2 && p[0].length !== 3))
    throw new VaultError('AUTH');
  const recipientKey = hex32<Pubkey>(p[0][1]);
  let decryptor: GrantDecryptor | undefined;
  for (const candidate of [...devices, identity]) {
    if (await candidate.getPublicKey() === recipientKey) { decryptor = candidate; break; }
  }
  if (!decryptor) throw new VaultError('AUTH');
  if (!decryptor.nip44) throw new VaultError('UNSUPPORTED');
  const decrypt = async (event: Event): Promise<unknown> => {
    let text: string;
    try { text = await decryptor.nip44!.decrypt(event.pubkey, event.content); }
    catch { throw new VaultError('CRYPTO', { operation: 'open' }); }
    return parsePlaintext(text);
  };
  const seal = signedEvent(await decrypt(wrap), VAULT_SEAL_KIND);
  if (seal.tags.length) throw new VaultError('AUTH');
  const rumor = await decrypt(seal);
  if (!rumor || typeof rumor !== 'object' || !('kind' in rumor)) throw new VaultError('AUTH');
  // Other NIP-59 applications share this inbox. They are not malformed invitations.
  if (rumor.kind !== VAULT_GRANT_KIND) return null;
  const grantRumor = rumor as GrantRumor;
  if (typeof grantRumor.content !== 'string' || grantRumor.content.includes('\0')) throw new VaultError('AUTH');
  const grant = openGrantRumor(grantRumor);
  if (seal.pubkey !== grantRumor.pubkey) throw new VaultError('AUTH');
  return { wrap, rumor: grantRumor, rumorId: grantRumor.id, recipientKey, grant };
}

export interface CarrierNetworkOptions {
  fetchRelays?: typeof fetchUserRelays;
  createRelay?: (endpoints: readonly string[]) => Pick<VaultRelay, 'publish' | 'subscribe' | 'backfill' | 'stop'>;
}

/** Unsafe advertised endpoints are ignored; configured endpoints must pass policy. */
export async function grantRelayEndpoints(
  identity: string, configured: readonly string[], options: CarrierNetworkOptions = {},
): Promise<string[]> {
  hex32<Pubkey>(identity);
  const endpoints = new Set(configured.map(url => validatePublicEndpoint(url, 'wss:')));
  const fetchRelays = options.fetchRelays ?? (await import('../nostr/login')).fetchUserRelays;
  for (const relay of await fetchRelays(identity, [...endpoints])) {
    if (!relay.read) continue;
    try { endpoints.add(validatePublicEndpoint(relay.url, 'wss:')); } catch { /* Untrusted NIP-65 hint. */ }
  }
  return [...endpoints];
}

export async function sendGrant(
  grant: VaultGrant, signer: NostrSigner, recipient: string,
  options: CarrierNetworkOptions & {
    relays: readonly string[];
    deviceDelivery?: DeviceDeliveryOptions;
    /** Must durably retain the exact wrap and recipient before any network publication. */
    persist(prepared: WrappedGrant & { recipient: GrantRecipient }): Promise<void>;
  },
): Promise<RelayPublishResult & WrappedGrant & { recipient: GrantRecipient }> {
  const endpoints = await grantRelayEndpoints(recipient, options.relays, options);
  const relay = (options.createRelay ?? (urls => new VaultRelay(urls)))(endpoints);
  try {
    const selected = await resolveGrantRecipient(recipient, relay, options.deviceDelivery);
    const prepared = { ...await buildGrantWrap(grant, signer, selected.encryptionKey), recipient: selected };
    // Keep the publication copy separate from the persistence callback's mutable object.
    const retained = structuredClone(prepared);
    await options.persist(retained);
    return { ...await relay.publish(prepared.wrap), ...prepared };
  } finally { relay.stop(); }
}

/** Live subscription plus explicit EOSE-complete until-paged backfill, no author filter. */
export async function createGrantInbox(
  identity: string, configuredRelays: readonly string[], devicePubkeys: readonly string[] = [],
  options: CarrierNetworkOptions = {},
) {
  const recipients = [...new Set([...devicePubkeys, identity].map(key => hex32<Pubkey>(key)))];
  const endpoints = await grantRelayEndpoints(identity, configuredRelays, options);
  const relay = (options.createRelay ?? (urls => new VaultRelay(urls)))(endpoints);
  const filters: Filter[] = [{ kinds: [VAULT_GIFT_WRAP_KIND], '#p': recipients }];
  return {
    endpoints, recipients,
    subscribe: (handlers: RelayHandlers) => relay.subscribe(structuredClone(filters), handlers),
    backfill: (handlers: RelayHandlers, signal?: AbortSignal) => relay.backfill(structuredClone(filters), handlers, signal),
    stop: () => relay.stop(),
  };
}
