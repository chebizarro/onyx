import { afterEach, describe, expect, it, vi } from 'vitest';
import { deleteDB, openDB } from 'idb';
import { finalizeEvent, getPublicKey, nip44, nip59, type Event } from 'nostr-tools';
import type { NostrSigner } from '../../nostr/signer';
import { buildGrantWrap, openGrantWrap, sendGrant } from '../carrier';
import { bytes32, bytesToHex, hex32 } from '../crypto';
import {
  advanceDeviceAnnouncementPin, buildDeviceAnnouncement, generateDeviceKey, latestDeviceAnnouncement, loadDeviceSigners,
  observeDeviceAnnouncement, recipientKeyStatus, resolveGrantRecipient, retainDeviceKey, selectGrantRecipient,
  type DeviceAnnouncementPin,
} from '../device-keys';
import { buildGrantRumor } from '../grant';
import { VaultError } from '../errors';
import { PROTOCOL_ID } from '../protocol';
import type { RelayHandlers, VaultRelay } from '../relay';
import { VaultStore } from '../store';
import type { Address, NodeId, Pubkey, VaultGrant, VaultId } from '../types';

const secret = (n: number) => { const bytes = new Uint8Array(32); bytes[31] = n; return bytes; };
const ownerKey = secret(1), identityKey = secret(2), deviceKey = secret(3), oldKey = secret(4);
const identity = hex32<Pubkey>(getPublicKey(identityKey)), device = getPublicKey(deviceKey);
function signer(key: Uint8Array): NostrSigner {
  return { getType: () => 'local', getPublicKey: async () => getPublicKey(key),
    signEvent: async template => finalizeEvent(template, key),
    nip44: {
      encrypt: async (peer, text) => nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(key, peer)),
      decrypt: async (peer, text) => nip44.v2.decrypt(text, nip44.v2.utils.getConversationKey(key, peer)),
    } };
}
function grant(): VaultGrant {
  return { vaultId: hex32<VaultId>('11'.repeat(32)), nodeId: hex32<NodeId>('22'.repeat(32)),
    rootManifest: hex32<Address>('33'.repeat(32)), owner: hex32<Pubkey>(getPublicKey(ownerKey)),
    cap: 'write', issuedAt: 123n, ring: { entries: [{ epoch: 1n, nodeKey: bytes32(secret(5)) }] },
    hints: { relays: ['wss://vault.example'], blossom: [] } };
}
function announcement(time: number, pubkey = device, key = identityKey): Event {
  return finalizeEvent({ kind: 10044, created_at: time, tags: [['n', pubkey]], content: '' }, key);
}
/** A pin whose fingerprint the user already approved, as the engine would persist it. */
function approvedPin(event: Event, approvedKey: string | null = device): DeviceAnnouncementPin {
  return { eventId: event.id, createdAt: event.created_at, encryptionKey: hex32<Pubkey>(event.tags[0][1]), approvedKey: approvedKey as Pubkey | null, observedAt: 100 };
}
function network(events: Event[] = []) {
  const backfill = vi.fn<VaultRelay['backfill']>(async (_filters, handlers: RelayHandlers) => {
    for (const event of events) handlers.onevent(event, 'wss://relay.example');
  });
  const relay = { backfill, publish: vi.fn(async (event: Event) => ({ event,
    outcomes: [{ relay: 'wss://relay.example', status: 'accepted' as const, reason: '' }],
    durable: true, degraded: false })),
  subscribe: vi.fn(() => ({ close: vi.fn(), reconnect: vi.fn(async () => {}) })), stop: vi.fn() };
  return { relay, createRelay: () => relay, fetchRelays: vi.fn(async () => []) };
}
const databases: { name: string; store: VaultStore }[] = [];
async function account() {
  const name = `device-keys-${crypto.randomUUID()}`;
  const values = new Map<string, string>();
  const store = new VaultStore({ accountPubkey: identity, databaseName: name,
    secrets: { get: async key => values.get(key) ?? null, set: async (key, value) => { values.set(key, value); },
      delete: async key => { values.delete(key); }, isLocked: () => false, unlock: async () => {} } });
  databases.push({ name, store });
  await store.start();
  await store.put('accounts', [], { schemaVersion: 1, protocolId: PROTOCOL_ID,
    deviceId: 'device-id', deviceLabel: 'Laptop', deviceKeyHistory: [], config: { enabled: false } });
  return { name, store };
}
afterEach(async () => {
  vi.restoreAllMocks();
  for (const { name, store } of databases.splice(0)) { store.stop(); await deleteDB(name); }
});

describe('opt-in device delivery', () => {
  it('defaults to identity without announcement lookup', async () => {
    const { relay } = network([announcement(1)]);
    expect(await resolveGrantRecipient(identity, relay)).toMatchObject({ identity, encryptionKey: identity, mode: 'identity' });
    expect(relay.backfill).not.toHaveBeenCalled();
  });

  it('selects the newest valid signed announcement with lowest-id tie breaking', () => {
    const older = announcement(1, getPublicKey(oldKey));
    const sameTime = [announcement(2), announcement(2, getPublicKey(oldKey))].sort((a, b) => a.id.localeCompare(b.id));
    const invalid = { ...announcement(3), sig: '00'.repeat(64) };
    const foreign = announcement(4, device, ownerKey);
    expect(latestDeviceAnnouncement([older, sameTime[1], invalid, foreign, sameTime[0]], identity)).toEqual(sameTime[0]);
  });

  it.each([[], [['n', device], ['n', device]], [['n', 'bad']], [['n', 'ff'.repeat(32)]], [['n', device, 'extra']]].map(tags => ({ tags })))
    ('does not resurrect an old key after a signed invalid replacement: $tags', ({ tags }) => {
      const replacement = finalizeEvent({ kind: 10044, created_at: 2, tags, content: '' }, identityKey);
      expect(latestDeviceAnnouncement([announcement(1), replacement], identity)).toBeNull();
    });

  it('requires explicit fallback when no valid announcement exists', async () => {
    const { relay } = network();
    await expect(resolveGrantRecipient(identity, relay, { enabled: true })).rejects.toMatchObject({ code: 'INCOMPLETE' });
    expect(await resolveGrantRecipient(identity, relay, { enabled: true, allowIdentityFallback: true }))
      .toEqual({ identity, encryptionKey: identity, mode: 'identity-fallback', notice: 'no-announcement', pin: null, evidence: 'none' });
    expect(relay.backfill).toHaveBeenCalledWith([{ kinds: [10044], authors: [identity] }], expect.any(Object));
  });

  it('does not treat announcement network failure as permission to downgrade', async () => {
    const { relay } = network();
    relay.backfill.mockRejectedValue(new VaultError('NETWORK'));
    await expect(resolveGrantRecipient(identity, relay, { enabled: true, allowIdentityFallback: true }))
      .rejects.toMatchObject({ code: 'NETWORK' });
  });

  it('encrypts both layers to the device while the owner identity signs the seal', async () => {
    const { store } = await account();
    await retainDeviceKey(store, deviceKey);
    const devices = await loadDeviceSigners(store);
    const net = network([announcement(1)]);
    const persist = vi.fn(async () => {});
    const result = await sendGrant(grant(), signer(ownerKey), identity, { ...net,
      relays: grant().hints.relays, deviceDelivery: { enabled: true, pin: approvedPin(announcement(1)) }, persist });
    expect(result.recipient).toMatchObject({ identity, encryptionKey: device, mode: 'device' });
    expect(result.recipientKey).toBe(device);
    expect(result.wrap.tags).toEqual([['p', device]]);
    expect(nip59.unwrapEvent(result.wrap, deviceKey)).toEqual(buildGrantRumor(grant()));
    const seal: Event = JSON.parse(nip44.v2.decrypt(result.wrap.content,
      nip44.v2.utils.getConversationKey(deviceKey, result.wrap.pubkey)));
    expect(seal.pubkey).toBe(grant().owner);
    const identitySigner = signer(identityKey);
    const identityDecrypt = vi.spyOn(identitySigner.nip44!, 'decrypt');
    expect((await openGrantWrap(result.wrap, identitySigner, devices))?.grant).toEqual(grant());
    expect(identityDecrypt).not.toHaveBeenCalled();
    expect(persist.mock.calls[0]).toEqual([expect.objectContaining({ recipientKey: device })]);
    await expect(openGrantWrap(result.wrap, identitySigner)).rejects.toMatchObject({ code: 'AUTH' });
    devices.forEach(device => device.close?.());
  });

  it('routes by p, tries matching devices first and never retries identity on decryption failure', async () => {
    const { wrap } = await buildGrantWrap(grant(), signer(ownerKey), device);
    const identitySigner = signer(identityKey);
    const decryptIdentity = vi.spyOn(identitySigner.nip44!, 'decrypt');
    const brokenDevice = signer(deviceKey);
    vi.spyOn(brokenDevice.nip44!, 'decrypt').mockRejectedValue(new Error('device locked'));
    await expect(openGrantWrap(wrap, identitySigner, [signer(oldKey), brokenDevice])).rejects.toMatchObject({ code: 'CRYPTO' });
    expect(decryptIdentity).not.toHaveBeenCalled();
    const identityWrap = await buildGrantWrap(grant(), signer(ownerKey), identity);
    expect((await openGrantWrap(identityWrap.wrap, identitySigner, [brokenDevice]))?.grant).toEqual(grant());
  });

  it('does not downgrade on device encryption failure', async () => {
    const net = network([announcement(1)]);
    const sender = signer(ownerKey);
    const encrypt = vi.spyOn(sender.nip44!, 'encrypt').mockRejectedValue(new Error('signer unavailable'));
    await expect(sendGrant(grant(), sender, identity, { ...net, relays: grant().hints.relays,
      deviceDelivery: { enabled: true, allowIdentityFallback: true, pin: approvedPin(announcement(1)) }, persist: async () => {},
    })).rejects.toThrow('signer unavailable');
    expect(encrypt).toHaveBeenCalledOnce();
    expect(encrypt.mock.calls[0][0]).toBe(device);
    expect(net.relay.publish).not.toHaveBeenCalled();
  });

  it('keeps failed publication outcomes for the selected device rather than retrying identity', async () => {
    const net = network([announcement(1)]);
    net.relay.publish.mockImplementation(async event => ({ event, outcomes: [], durable: false, degraded: true }));
    const result = await sendGrant(grant(), signer(ownerKey), identity, { ...net, relays: grant().hints.relays,
      deviceDelivery: { enabled: true, allowIdentityFallback: true, pin: approvedPin(announcement(1)) }, persist: async () => {} });
    expect(result.durable).toBe(false);
    expect(result.recipientKey).toBe(device);
    expect(net.relay.publish).toHaveBeenCalledOnce();
  });
});

describe('announcement pins (SV-33)', () => {
  const current = announcement(10), older = announcement(5, getPublicKey(oldKey)), rotated = announcement(20, getPublicKey(oldKey));
  const withdrawal = finalizeEvent({ kind: 10044, created_at: 30, tags: [], content: '' }, identityKey);

  it('observes the newest signed announcement and distinguishes withdrawal from absence', () => {
    expect(observeDeviceAnnouncement([], identity)).toBeNull();
    expect(observeDeviceAnnouncement([older, current], identity)).toEqual({ eventId: current.id, createdAt: 10, encryptionKey: device });
    expect(observeDeviceAnnouncement([current, withdrawal], identity)).toEqual({ eventId: withdrawal.id, createdAt: 30, encryptionKey: null });
    expect(observeDeviceAnnouncement([announcement(99, device, ownerKey)], identity)).toBeNull();
  });

  it('refuses an older observation and keeps the pin when the relay withholds the newer announcement', () => {
    const pin = approvedPin(current);
    expect(advanceDeviceAnnouncementPin(pin, observeDeviceAnnouncement([older], identity), 200)).toEqual({ pin, evidence: 'stale' });
    expect(advanceDeviceAnnouncementPin(pin, null, 200)).toEqual({ pin, evidence: 'none' });
    expect(advanceDeviceAnnouncementPin(pin, observeDeviceAnnouncement([current], identity), 200)).toEqual({ pin: { ...pin, observedAt: 200 }, evidence: 'current' });
    // Same timestamp, higher id is older by replaceable ordering and is refused too.
    const [first, second] = [announcement(10), announcement(10, getPublicKey(oldKey))].sort((a, b) => a.id.localeCompare(b.id));
    expect(advanceDeviceAnnouncementPin(approvedPin(first), observeDeviceAnnouncement([second], identity), 200).evidence).toBe('stale');
    expect(advanceDeviceAnnouncementPin(approvedPin(second), observeDeviceAnnouncement([first], identity), 200).evidence).toBe('fresh');
  });

  it('keeps the approved fingerprint through a rotation so a changed key is never auto-approved', () => {
    const pin = approvedPin(current);
    const advanced = advanceDeviceAnnouncementPin(pin, observeDeviceAnnouncement([current, rotated], identity), 200);
    expect(advanced).toEqual({ pin: { eventId: rotated.id, createdAt: 20, encryptionKey: getPublicKey(oldKey), approvedKey: device, observedAt: 200 }, evidence: 'fresh' });
    expect(recipientKeyStatus(advanced.pin)).toBe('changed');
    const withdrawn = advanceDeviceAnnouncementPin(advanced.pin, observeDeviceAnnouncement([withdrawal], identity), 300);
    expect(recipientKeyStatus(withdrawn.pin)).toBe('withdrawn');
    expect(recipientKeyStatus(null)).toBe('unpinned');
    expect(recipientKeyStatus(approvedPin(current, null))).toBe('unapproved');
    expect(recipientKeyStatus(pin)).toBe('approved');
  });

  it('delivers to a device key only while the approved fingerprint matches the pinned key', () => {
    expect(selectGrantRecipient(identity, approvedPin(current), { enabled: true })).toEqual({ identity, encryptionKey: device, mode: 'device', announcementId: current.id });
    // Bootstrap: an unapproved key always falls back to identity with a notice, even without the fallback flag.
    expect(selectGrantRecipient(identity, approvedPin(current, null), { enabled: true })).toEqual({ identity, encryptionKey: identity, mode: 'identity-fallback', notice: 'unapproved' });
    const changed = { ...approvedPin(rotated), approvedKey: device as Pubkey };
    expect(() => selectGrantRecipient(identity, changed, { enabled: true })).toThrow(expect.objectContaining({ code: 'POLICY' }));
    expect(selectGrantRecipient(identity, changed, { enabled: true, allowIdentityFallback: true })).toMatchObject({ mode: 'identity-fallback', encryptionKey: identity, notice: 'key-changed' });
    const withdrawn: DeviceAnnouncementPin = { eventId: withdrawal.id, createdAt: 30, encryptionKey: null, approvedKey: device as Pubkey, observedAt: 1 };
    expect(() => selectGrantRecipient(identity, withdrawn, { enabled: true })).toThrow(expect.objectContaining({ code: 'INCOMPLETE' }));
    expect(selectGrantRecipient(identity, withdrawn, { enabled: true, allowIdentityFallback: true })).toMatchObject({ mode: 'identity-fallback', notice: 'withdrawn' });
    expect(selectGrantRecipient(identity, approvedPin(current), {})).toEqual({ identity, encryptionKey: identity, mode: 'identity' });
  });

  it('resolves against a withheld relay view with the pinned key, not the retired one it serves', async () => {
    const { relay } = network([older]);
    const pin = approvedPin(current);
    expect(await resolveGrantRecipient(identity, relay, { enabled: true }, pin, () => 500)).toEqual({ identity, encryptionKey: device, mode: 'device', announcementId: current.id, pin, evidence: 'stale' });
    // Without a pin the first observation is recorded but never used until approved.
    expect(await resolveGrantRecipient(identity, network([current]).relay, { enabled: true }, null, () => 500)).toEqual({
      identity, encryptionKey: identity, mode: 'identity-fallback', notice: 'unapproved', evidence: 'fresh',
      pin: { eventId: current.id, createdAt: 10, encryptionKey: device, approvedKey: null, observedAt: 500 } });
    // A rotation the relay does serve demands a decision instead of silently wrapping to either key.
    await expect(resolveGrantRecipient(identity, network([current, rotated]).relay, { enabled: true }, pin, () => 500)).rejects.toMatchObject({ code: 'POLICY' });
  });
});

describe('encrypted local device-key history', () => {
  it('retains rotations and decrypts old and new deliveries after reopening storage', async () => {
    const { store, name } = await account();
    await retainDeviceKey(store, oldKey);
    await retainDeviceKey(store, deviceKey);
    await retainDeviceKey(store, deviceKey);
    const generated = await generateDeviceKey(store);
    const record = await store.read('accounts', []);
    expect(record?.value.deviceKeyHistory).toHaveLength(3);
    expect(record?.value.config).toEqual({ enabled: false });
    const raw = await openDB(name);
    const rows = await raw.getAll('accounts');
    raw.close();
    expect(JSON.stringify(rows)).not.toContain(bytesToHex(deviceKey));
    expect(JSON.stringify(rows)).not.toContain(device);
    store.stop();
    await store.start();
    const signers = await loadDeviceSigners(store);
    expect(await Promise.all(signers.map(s => s.getPublicKey()))).toEqual([getPublicKey(oldKey), device, generated]);
    for (const key of [oldKey, deviceKey]) {
      const { wrap } = await buildGrantWrap(grant(), signer(ownerKey), getPublicKey(key));
      expect((await openGrantWrap(wrap, signer(identityKey), signers))?.grant).toEqual(grant());
    }
    signers.forEach(s => s.close?.());
    await expect(signers[0].getPublicKey()).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('builds an identity-signed announcement for a retained key', async () => {
    const event = await buildDeviceAnnouncement(signer(identityKey), device);
    expect(event.kind).toBe(10044);
    expect(event.tags).toEqual([['n', device]]);
    expect(event.pubkey).toBe(identity);
    expect(latestDeviceAnnouncement([event], identity)?.id).toBe(event.id);
  });

  it('fails closed on malformed stored key history', async () => {
    const { store } = await account();
    const accountRow = (await store.read('accounts', []))!;
    await store.put('accounts', [], { ...accountRow.value,
      deviceKeyHistory: [{ pubkey: device, secretKey: bytesToHex(oldKey) }] }, accountRow.revision);
    await expect(loadDeviceSigners(store)).rejects.toMatchObject({ code: 'STORAGE' });
    await expect(retainDeviceKey(store, deviceKey)).rejects.toMatchObject({ code: 'STORAGE' });
  });
});
