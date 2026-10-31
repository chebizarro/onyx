import { finalizeEvent, generateSecretKey, getPublicKey, nip19, nip44, verifyEvent, type Event } from 'nostr-tools';
import type { NostrSigner } from '../nostr/signer';
import { bytesToHex, hex32, hexToBytes } from './crypto';
import { VaultError } from './errors';
import { NIP4E_ANNOUNCEMENT_KIND } from './protocol';
import type { VaultRelay } from './relay';
import type { VaultStore } from './store';
import type { Pubkey, StorageJson, StoredDeviceAnnouncement } from './types';

export interface DeviceDeliveryOptions {
  /** Provisional NIP-4E support is opt-in. */
  enabled?: boolean;
  /** Only permits fallback when no usable announcement exists, not on I/O failure. */
  allowIdentityFallback?: boolean;
  /**
   * Committed pin for callers without an account store (`sendGrant`, tests). The engine ignores
   * this field and advances its own persisted pin inside a serialised account transaction.
   */
  pin?: DeviceAnnouncementPin | null;
}
/**
 * Why identity delivery was used while device delivery was requested. `unapproved` is the
 * mandatory bootstrap notice: a recipient key is never used until its fingerprint is approved.
 */
export type IdentityFallbackNotice = 'no-announcement' | 'unapproved' | 'key-changed' | 'withdrawn';
/**
 * What the relay view proved about the pinned announcement. `stale` means the relay served an
 * announcement older than the pin and was refused; `none` means it served nothing. Neither
 * `current` nor `fresh` proves the recipient has not rotated since: relay omission is not
 * evidence of currency, pins only prevent rollback below what this account already observed.
 */
export type AnnouncementEvidence = 'none' | 'stale' | 'current' | 'fresh';
export interface GrantRecipient {
  identity: Pubkey;
  encryptionKey: Pubkey;
  mode: 'identity' | 'device' | 'identity-fallback';
  announcementId?: string;
  notice?: IdentityFallbackNotice;
}
export interface DeviceAnnouncementObservation {
  readonly eventId: string;
  readonly createdAt: number;
  /** Null when the newest identity-signed announcement withdrew or invalidated the key. */
  readonly encryptionKey: Pubkey | null;
}
export type DeviceAnnouncementPin = StoredDeviceAnnouncement;
export type RecipientKeyStatus = 'unpinned' | 'unapproved' | 'changed' | 'withdrawn' | 'approved';

function replaceableOrder(a: { created_at: number; id: string }, b: { created_at: number; id: string }): number {
  return b.created_at - a.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}
/** Newest identity-signed kind-10044 regardless of whether it carries a usable key. */
function latestSignedAnnouncement(events: readonly Event[], identity: string): Event | null {
  hex32<Pubkey>(identity);
  const valid = events.filter(event => {
    try {
      return event.kind === NIP4E_ANNOUNCEMENT_KIND && event.pubkey === identity &&
        Number.isSafeInteger(event.created_at) && event.created_at >= 0 &&
        verifyEvent(JSON.parse(JSON.stringify(event)));
    } catch { return false; }
  }).sort(replaceableOrder);
  return valid[0] ?? null;
}
/** The single usable `n` key of an announcement, or null when it withdraws/invalidates the key. */
export function announcedEncryptionKey(event: Event): Pubkey | null {
  const keys = event.tags.filter(tag => tag[0] === 'n');
  if (keys.length !== 1 || keys[0].length !== 2) return null;
  try {
    const key = hex32<Pubkey>(keys[0][1]);
    // Validate that the x-only point can actually be used for ECDH.
    const scalar = new Uint8Array(32); scalar[31] = 1;
    nip44.v2.utils.getConversationKey(scalar, key).fill(0);
    return key;
  } catch { return null; }
}

/** Latest signed replacement wins, including a replacement that withdraws the key. */
export function latestDeviceAnnouncement(events: readonly Event[], identity: string): Event | null {
  const latest = latestSignedAnnouncement(events, identity);
  return latest && announcedEncryptionKey(latest) ? latest : null;
}

/** Observation of the supplied events only; null when the identity signed no announcement at all. */
export function observeDeviceAnnouncement(events: readonly Event[], identity: string): DeviceAnnouncementObservation | null {
  const latest = latestSignedAnnouncement(events, identity);
  return latest ? { eventId: latest.id, createdAt: latest.created_at, encryptionKey: announcedEncryptionKey(latest) } : null;
}

/** Throws on I/O failure: a failed lookup is never evidence of anything. */
export async function fetchDeviceAnnouncement(identity: string, relay: Pick<VaultRelay, 'backfill'>): Promise<DeviceAnnouncementObservation | null> {
  const pubkey = hex32<Pubkey>(identity);
  const events: Event[] = [];
  await relay.backfill([{ kinds: [NIP4E_ANNOUNCEMENT_KIND], authors: [pubkey] }], {
    onevent: event => { events.push(event); },
  });
  return observeDeviceAnnouncement(events, pubkey);
}

/**
 * Monotonic pin advance. An observation older than the pin (replaceable ordering) is refused:
 * a relay that withholds the newer announcement cannot roll the recipient back to a retired key.
 * The approved fingerprint survives a newer observation so a changed key becomes `changed`, never
 * silently approved.
 */
export function advanceDeviceAnnouncementPin(
  pin: DeviceAnnouncementPin | null, observation: DeviceAnnouncementObservation | null, now: number,
): { pin: DeviceAnnouncementPin | null; evidence: AnnouncementEvidence } {
  if (!Number.isSafeInteger(now) || now < 0) throw new VaultError('ARG');
  if (!observation) return { pin, evidence: 'none' };
  if (!pin) return { pin: { ...observation, approvedKey: null, observedAt: now }, evidence: 'fresh' };
  if (observation.eventId === pin.eventId) return { pin: { ...pin, observedAt: now }, evidence: 'current' };
  if (replaceableOrder({ created_at: observation.createdAt, id: observation.eventId }, { created_at: pin.createdAt, id: pin.eventId }) > 0) return { pin, evidence: 'stale' };
  return { pin: { ...observation, approvedKey: pin.approvedKey, observedAt: now }, evidence: 'fresh' };
}

export function recipientKeyStatus(pin: DeviceAnnouncementPin | null): RecipientKeyStatus {
  if (!pin) return 'unpinned';
  if (pin.encryptionKey === null) return 'withdrawn';
  if (pin.approvedKey === null) return 'unapproved';
  return pin.approvedKey === pin.encryptionKey ? 'approved' : 'changed';
}

/**
 * Delivery gate. Device delivery requires an approved fingerprint equal to the pinned key.
 * `unapproved` always falls back to identity delivery with a notice (bootstrap rule; the
 * `allowIdentityFallback` flag does not restrict this case). `changed` and `withdrawn` fail
 * closed unless identity fallback is explicitly allowed; a key change is never auto-approved.
 */
export function selectGrantRecipient(identity: string, pin: DeviceAnnouncementPin | null, options: DeviceDeliveryOptions = {}): GrantRecipient {
  const pubkey = hex32<Pubkey>(identity);
  if (!options.enabled) return { identity: pubkey, encryptionKey: pubkey, mode: 'identity' };
  const status = recipientKeyStatus(pin);
  if (status === 'approved') return { identity: pubkey, encryptionKey: pin!.approvedKey!, mode: 'device', announcementId: pin!.eventId };
  if (status === 'unapproved') return { identity: pubkey, encryptionKey: pubkey, mode: 'identity-fallback', notice: 'unapproved' };
  if (status === 'changed') {
    if (!options.allowIdentityFallback) throw new VaultError('POLICY', { operation: 'share', reason: 'key-approval-required' });
    return { identity: pubkey, encryptionKey: pubkey, mode: 'identity-fallback', notice: 'key-changed' };
  }
  if (!options.allowIdentityFallback) throw new VaultError('INCOMPLETE', { operation: 'share' });
  return { identity: pubkey, encryptionKey: pubkey, mode: 'identity-fallback', notice: status === 'withdrawn' ? 'withdrawn' : 'no-announcement' };
}

/** Convenience composition for callers without an account store; the engine advances the stored pin itself. */
export async function resolveGrantRecipient(
  identity: string, relay: Pick<VaultRelay, 'backfill'>, options: DeviceDeliveryOptions = {},
  pin: DeviceAnnouncementPin | null = options.pin ?? null, now = () => Math.floor(Date.now() / 1000),
): Promise<GrantRecipient & { pin: DeviceAnnouncementPin | null; evidence: AnnouncementEvidence }> {
  const pubkey = hex32<Pubkey>(identity);
  if (!options.enabled) return { identity: pubkey, encryptionKey: pubkey, mode: 'identity', pin, evidence: 'none' };
  const observation = await fetchDeviceAnnouncement(pubkey, relay);
  const advanced = advanceDeviceAnnouncementPin(pin, observation, now());
  return { ...selectGrantRecipient(pubkey, advanced.pin, options), pin: advanced.pin, evidence: advanced.evidence };
}

interface LocalDeviceKey {
  pubkey: Pubkey;
  secretKey: string;
}
function readDeviceKey(value: StorageJson): LocalDeviceKey {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new VaultError('STORAGE');
  const record = value as Record<string, StorageJson>;
  try {
    if (typeof record.pubkey !== 'string' || typeof record.secretKey !== 'string') throw new Error();
    const pubkey = hex32<Pubkey>(record.pubkey);
    const secretKey = hex32(record.secretKey);
    const bytes = hexToBytes(secretKey);
    try { if (getPublicKey(bytes) !== pubkey) throw new Error(); }
    finally { bytes.fill(0); }
    return { pubkey, secretKey };
  } catch { throw new VaultError('STORAGE', { operation: 'store' }); }
}

/** The account row is encrypted by VaultStore. CAS prevents lost rotations. */
export async function retainDeviceKey(store: VaultStore, secretKey: Uint8Array): Promise<Pubkey> {
  let pubkey: Pubkey;
  try { pubkey = hex32<Pubkey>(getPublicKey(secretKey)); }
  catch { throw new VaultError('ARG'); }
  const account = await store.read('accounts', []);
  if (!account) throw new VaultError('INCOMPLETE', { operation: 'store' });
  const history = account.value.deviceKeyHistory.map(readDeviceKey);
  if (history.some(key => key.pubkey === pubkey)) return pubkey;
  await store.put('accounts', [], { ...account.value, deviceKeyHistory: [
    ...account.value.deviceKeyHistory, { pubkey, secretKey: bytesToHex(secretKey) },
  ] }, account.revision);
  return pubkey;
}

export async function importDeviceKey(store: VaultStore, value: string): Promise<Pubkey> {
  let key: Uint8Array;
  try {
    if (value.startsWith('nsec1')) {
      const decoded = nip19.decode(value);
      if (decoded.type !== 'nsec') throw new Error();
      key = decoded.data;
    } else {
      key = hexToBytes(hex32(value));
    }
  } catch { throw new VaultError('ARG'); }
  try { return await retainDeviceKey(store, key); }
  finally { key.fill(0); }
}

export async function generateDeviceKey(store: VaultStore): Promise<Pubkey> {
  const key = generateSecretKey();
  try { return await retainDeviceKey(store, key); }
  finally { key.fill(0); }
}

/** Retained keys remain available until the caller explicitly closes this session. */
export async function loadDeviceSigners(store: VaultStore): Promise<NostrSigner[]> {
  const account = await store.read('accounts', []);
  const history = (account?.value.deviceKeyHistory ?? []).map(readDeviceKey);
  return history.map(record => {
    const secret = hexToBytes(record.secretKey);
    let closed = false;
    const check = () => { if (closed) throw new VaultError('CANCELLED'); };
    const conversation = (peer: string) => { check(); return nip44.v2.utils.getConversationKey(secret, peer); };
    return {
      getType: () => 'local' as const,
      getPublicKey: async () => { check(); return record.pubkey; },
      signEvent: async event => { check(); return finalizeEvent(event, secret); },
      nip44: {
        encrypt: async (peer, text) => {
          const key = conversation(peer);
          try { return nip44.v2.encrypt(text, key); } finally { key.fill(0); }
        },
        decrypt: async (peer, text) => {
          const key = conversation(peer);
          try { return nip44.v2.decrypt(text, key); } finally { key.fill(0); }
        },
      },
      close: () => { closed = true; secret.fill(0); },
    };
  });
}

/** Persist the returned event before publishing it with the relay adapter. */
export async function buildDeviceAnnouncement(signer: NostrSigner, devicePubkey: string, clock = () => Math.floor(Date.now() / 1000)): Promise<Event> {
  const pubkey = hex32<Pubkey>(devicePubkey);
  const event = await signer.signEvent({ kind: NIP4E_ANNOUNCEMENT_KIND,
    created_at: clock(), tags: [['n', pubkey]], content: '' });
  if (!latestDeviceAnnouncement([event], await signer.getPublicKey())) throw new VaultError('AUTH');
  return event;
}
