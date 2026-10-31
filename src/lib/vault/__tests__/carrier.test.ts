import { afterEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, getEventHash, getPublicKey, nip44, nip59, verifyEvent, type Event } from 'nostr-tools';
vi.mock('nostr-tools', async importOriginal => {
  const actual = await importOriginal<typeof import('nostr-tools')>();
  return { ...actual, verifyEvent: vi.fn(actual.verifyEvent) };
});
import type { NostrSigner } from '../../nostr/signer';
import { buildGrantWrap, createGrantInbox, openGrantWrap, randomizedTimestamp, sendGrant } from '../carrier';
import { bytes32, hex32 } from '../crypto';
import { buildGrantRumor, encodeGrant } from '../grant';
import { NIP59_TIMESTAMP_RANDOM_RANGE, NIP59_MAX_TAGS, NIP59_MAX_PAYLOAD,
  VAULT_EVENT_MAX_TAG_PARTS, VAULT_EVENT_MAX_TAG_STRING_BYTES } from '../protocol';
import type { Address, NodeId, Pubkey, VaultGrant, VaultId } from '../types';

const secret = (n: number) => { const key = new Uint8Array(32); key[31] = n; return key; };
const ownerKey = secret(1), recipientKey = secret(2), otherKey = secret(3);
const owner = hex32<Pubkey>(getPublicKey(ownerKey)), recipient = getPublicKey(recipientKey);
function signer(key: Uint8Array): NostrSigner {
  return {
    getType: () => 'local', getPublicKey: async () => getPublicKey(key),
    getSecretKey: () => { throw new Error('Identity secret must not be requested'); },
    signEvent: async event => finalizeEvent(event, key),
    nip44: {
      encrypt: async (peer, text) => nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(key, peer)),
      decrypt: async (peer, text) => nip44.v2.decrypt(text, nip44.v2.utils.getConversationKey(key, peer)),
    },
  };
}
function grant(): VaultGrant {
  return { vaultId: hex32<VaultId>('11'.repeat(32)), nodeId: hex32<NodeId>('22'.repeat(32)),
    owner, rootManifest: hex32<Address>('33'.repeat(32)), cap: 'write', issuedAt: 123n,
    ring: { entries: [{ epoch: 1n, nodeKey: bytes32(secret(4)) }] },
    hints: { relays: ['wss://vault.example'], blossom: [] } };
}
function largeGrant(size: number): VaultGrant {
  const base = grant();
  const relays = Array.from({ length: Math.floor((size - 500) / 2000) }, () => 'wss://relay.example/'.padEnd(1997, 'x'));
  const partial = { ...base, hints: { relays, blossom: [] } };
  const length = size - encodeGrant(partial).length - 2;
  const result = { ...partial, hints: { relays, blossom: ['https://blob.example/'.padEnd(length, 'x')] } };
  expect(encodeGrant(result).length).toBe(size);
  return result;
}
function network() {
  const relay = {
    publish: vi.fn(async (event: Event) => ({ event, outcomes: [
      { relay: 'wss://vault.example/', status: 'accepted' as const, reason: '' },
      { relay: 'wss://inbox.example/', status: 'rejected' as const, reason: 'blocked:' },
    ], durable: true, degraded: true })),
    backfill: vi.fn(async () => {}),
    subscribe: vi.fn(() => ({ close: vi.fn(), reconnect: vi.fn(async () => {}) })), stop: vi.fn(),
  };
  return { relay, createRelay: vi.fn(() => relay), fetchRelays: vi.fn(async () => [
    { url: 'wss://inbox.example', read: true, write: false },
    { url: 'wss://vault.example/', read: true, write: true },
    { url: 'wss://write.example', read: false, write: true },
    { url: 'ws://insecure.example', read: true, write: true },
    { url: 'wss://127.0.0.1', read: true, write: false },
  ]) };
}
const wrappedSeal = (seal: Event) => nip59.createWrap(seal, recipient);
const sealText = (text: string, key = ownerKey, tags: string[][] = []) => finalizeEvent({
  kind: 13, tags, created_at: 123,
  content: nip44.v2.encrypt(text, nip44.v2.utils.getConversationKey(key, recipient)),
}, key);

afterEach(() => vi.restoreAllMocks());

describe('NIP-59 grant carrier', () => {
  it('interoperates with nostr-tools unwrapEvent using signer methods only', async () => {
    const before = Math.floor(Date.now() / 1000);
    const result = await buildGrantWrap(grant(), signer(ownerKey), recipient);
    expect(nip59.unwrapEvent(result.wrap, recipientKey)).toEqual(buildGrantRumor(grant()));
    expect(result.wrap.tags).toEqual([['p', recipient]]);
    expect(result.wrap.created_at).toBeGreaterThanOrEqual(before - NIP59_TIMESTAMP_RANDOM_RANGE);
    expect(result.wrap.created_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) - 1);
    expect((await openGrantWrap(result.wrap, signer(recipientKey)))?.grant).toEqual(grant());
  });

  it('opens a nostr-tools wrapped grant', async () => {
    const wrap = nip59.wrapEvent(buildGrantRumor(grant()), ownerKey, recipient);
    expect((await openGrantWrap(wrap, signer(recipientKey)))?.grant).toEqual(grant());
  });

  it('uses fresh ephemeral wrap keys', async () => {
    const first = await buildGrantWrap(grant(), signer(ownerKey), recipient);
    const second = await buildGrantWrap(grant(), signer(ownerKey), recipient);
    expect(first.wrap.pubkey).not.toBe(second.wrap.pubkey);
    expect(first.wrap.pubkey).not.toBe(owner);
  });

  it('persists before publishing only the wrap to vault plus safe read relays', async () => {
    const net = network();
    const persist = vi.fn(async () => { expect(net.relay.publish).not.toHaveBeenCalled(); });
    const result = await sendGrant(grant(), signer(ownerKey), recipient, {
      ...net, relays: grant().hints.relays, persist,
    });
    expect(net.fetchRelays).toHaveBeenCalledWith(recipient, ['wss://vault.example/']);
    expect(net.createRelay).toHaveBeenCalledWith(['wss://vault.example/', 'wss://inbox.example/']);
    expect(persist).toHaveBeenCalledOnce();
    expect(net.relay.publish).toHaveBeenCalledExactlyOnceWith(result.wrap);
    expect(result.wrap.kind).toBe(1059);
    expect(result.recipient.mode).toBe('identity');
    expect(result.recipientKey).toBe(recipient);
    expect(result.outcomes.map(item => item.status)).toEqual(['accepted', 'rejected']);
    expect(net.relay.stop).toHaveBeenCalledOnce();
  });

  it('does not publish when persistence fails', async () => {
    const net = network();
    await expect(sendGrant(grant(), signer(ownerKey), recipient, { ...net, relays: grant().hints.relays,
      persist: async () => { throw new Error('disk'); },
    })).rejects.toThrow('disk');
    expect(net.relay.publish).not.toHaveBeenCalled();
    expect(net.relay.stop).toHaveBeenCalledOnce();
  });

  it.each([65535, 50000])('rejects nested plaintext limit at raw size %i before publication', async size => {
    const net = network();
    const identity = signer(ownerKey);
    const encrypt = vi.spyOn(identity.nip44!, 'encrypt');
    const persist = vi.fn();
    await expect(sendGrant(largeGrant(size), identity, recipient, {
      ...net, relays: grant().hints.relays, persist,
    })).rejects.toMatchObject({ code: 'TOO_LARGE' });
    expect(encrypt).not.toHaveBeenCalled();
    expect(persist).not.toHaveBeenCalled();
    expect(net.relay.publish).not.toHaveBeenCalled();
  });

  it.each(['content', 'total', 'tag-count', 'tag-arity', 'tag-string', 'tag-utf8', 'tag-aggregate'] as const)
    ('rejects over-budget %s before any signature verification or decryption', async mode => {
    const { wrap } = await buildGrantWrap(grant(), signer(ownerKey), recipient);
    const oversized = { ...wrap };
    if (mode === 'content') oversized.content = 'x'.repeat(NIP59_MAX_PAYLOAD + 1);
    if (mode === 'total') oversized.content = '"'.repeat(70000); // JSON escaping exceeds 128 KiB
    if (mode === 'tag-count') oversized.tags = Array.from({ length: NIP59_MAX_TAGS + 1 }, () => ['x']);
    if (mode === 'tag-arity') oversized.tags = [Array(VAULT_EVENT_MAX_TAG_PARTS + 1).fill('x')];
    if (mode === 'tag-string') oversized.tags = [['x'.repeat(VAULT_EVENT_MAX_TAG_STRING_BYTES + 1)]];
    if (mode === 'tag-utf8') oversized.tags = [['é'.repeat(VAULT_EVENT_MAX_TAG_STRING_BYTES)]];
    if (mode === 'tag-aggregate') oversized.tags = Array.from({ length: 9 }, () => ['x'.repeat(VAULT_EVENT_MAX_TAG_STRING_BYTES)]);
    const receiver = signer(recipientKey), decrypt = vi.spyOn(receiver.nip44!, 'decrypt');
    vi.mocked(verifyEvent).mockClear();
    await expect(openGrantWrap(oversized, receiver)).rejects.toMatchObject({ code: 'AUTH' });
    expect(verifyEvent).not.toHaveBeenCalled(); expect(decrypt).not.toHaveBeenCalled();
  });

  it('copies only recognised fields without traversing unknown data or toJSON hooks', async () => {
    const { wrap } = await buildGrantWrap(grant(), signer(ownerKey), recipient);
    const toJSON = vi.fn(() => { throw new Error('untrusted hook'); });
    const opened = await openGrantWrap({ ...wrap, toJSON, unknown: { toJSON } }, signer(recipientKey));
    expect(opened?.grant).toEqual(grant()); expect(toJSON).not.toHaveBeenCalled();
    expect(opened?.wrap).not.toHaveProperty('unknown'); expect(opened?.wrap).not.toHaveProperty('toJSON');
  });

  it('rejects outer signature or id changes before decryption, even after cached verification', async () => {
    const { wrap } = await buildGrantWrap(grant(), signer(ownerKey), recipient);
    const receiver = signer(recipientKey);
    const decrypt = vi.spyOn(receiver.nip44!, 'decrypt');
    for (const change of [{ content: wrap.content + 'x' }, { id: '00'.repeat(32) }, { sig: '00'.repeat(64) }]) {
      await expect(openGrantWrap({ ...wrap, ...change }, receiver)).rejects.toMatchObject({ code: 'AUTH' });
    }
    expect(decrypt).not.toHaveBeenCalled();
  });

  it.each([
    [], [['p', getPublicKey(otherKey)]], [['p', recipient], ['p', recipient]], [['p', recipient, '', 'extra']],
  ].map(tags => ({ tags })))('rejects absent, wrong, duplicate or malformed p tags: $tags', async ({ tags }) => {
    const { wrap } = await buildGrantWrap(grant(), signer(ownerKey), recipient);
    const changed = finalizeEvent({ ...wrap, tags }, otherKey);
    const receiver = signer(recipientKey);
    const decrypt = vi.spyOn(receiver.nip44!, 'decrypt');
    await expect(openGrantWrap(changed, receiver)).rejects.toMatchObject({ code: 'AUTH' });
    expect(decrypt).not.toHaveBeenCalled();
  });

  it('accepts the permitted three-element p tag and rejects too many outer tags', async () => {
    const rumor = buildGrantRumor(grant());
    const seal = sealText(JSON.stringify(rumor));
    const original = wrappedSeal(seal);
    const rewrap = (tags: string[][]) => finalizeEvent({ kind: 1059, created_at: 123, tags,
      content: nip44.v2.encrypt(JSON.stringify(seal), nip44.v2.utils.getConversationKey(otherKey, recipient)),
    }, otherKey);
    expect((await openGrantWrap(rewrap([['p', recipient, 'wss://relay.example']]), signer(recipientKey)))?.grant).toEqual(grant());
    await expect(openGrantWrap(rewrap([...original.tags, ...Array.from({ length: 128 }, () => ['x'])]), signer(recipientKey)))
      .rejects.toMatchObject({ code: 'AUTH' });
  });

  it('rejects a bare rumor, including one encrypted directly inside a wrap', async () => {
    const rumor = buildGrantRumor(grant());
    await expect(openGrantWrap(rumor, signer(recipientKey))).rejects.toMatchObject({ code: 'AUTH' });
    const wrap = finalizeEvent({ kind: 1059, created_at: 123, tags: [['p', recipient]],
      content: nip44.v2.encrypt(JSON.stringify(rumor), nip44.v2.utils.getConversationKey(otherKey, recipient)),
    }, otherKey);
    await expect(openGrantWrap(wrap, signer(recipientKey))).rejects.toMatchObject({ code: 'AUTH' });
  });

  it('rejects mismatched seal/rumor authors', async () => {
    const seal = sealText(JSON.stringify(buildGrantRumor(grant())), otherKey);
    await expect(openGrantWrap(wrappedSeal(seal), signer(recipientKey))).rejects.toMatchObject({ code: 'AUTH' });
  });

  it('rejects nonempty seal tags and invalid seal signatures', async () => {
    const text = JSON.stringify(buildGrantRumor(grant()));
    for (const seal of [sealText(text, ownerKey, [['x']]), { ...sealText(text), sig: '00'.repeat(64) }]) {
      await expect(openGrantWrap(wrappedSeal(seal), signer(recipientKey))).rejects.toMatchObject({ code: 'AUTH' });
    }
  });

  it.each(['owner', 'time', 'id', 'sig', 'tags'])('rejects invalid rumor %s', async field => {
    let rumor = buildGrantRumor(grant());
    if (field === 'owner') rumor = { ...rumor, pubkey: getPublicKey(otherKey) };
    if (field === 'time') rumor = { ...rumor, created_at: 124 };
    if (field === 'sig') rumor = { ...rumor, sig: 'aa'.repeat(64) };
    if (field === 'tags') rumor = { ...rumor, tags: [['x']] };
    rumor = { ...rumor, id: field === 'id' ? '00'.repeat(32) : getEventHash(rumor) };
    await expect(openGrantWrap(wrappedSeal(sealText(JSON.stringify(rumor))), signer(recipientKey)))
      .rejects.toMatchObject({ code: 'AUTH' });
  });

  it('silently ignores other rumor kinds after validating their seal', async () => {
    const wrap = nip59.wrapEvent({ kind: 14, content: 'a private message', tags: [] }, ownerKey, recipient);
    await expect(openGrantWrap(wrap, signer(recipientKey))).resolves.toBeNull();
  });

  it.each(['raw-nul', 'escaped-nul', 'oversize-seal', 'oversize-rumor'])('rejects %s plaintext on receive', async mode => {
    const { wrap } = await buildGrantWrap(grant(), signer(ownerKey), recipient);
    const rumor = buildGrantRumor(grant());
    const seal = sealText(JSON.stringify(rumor));
    const receiver = signer(recipientKey);
    const decrypt = vi.spyOn(receiver.nip44!, 'decrypt');
    decrypt.mockResolvedValueOnce(mode === 'oversize-seal' ? 'x'.repeat(65536) : JSON.stringify(seal));
    decrypt.mockResolvedValueOnce(mode === 'oversize-rumor' ? 'x'.repeat(65536) :
      mode === 'raw-nul' ? JSON.stringify(rumor) + '\0' : JSON.stringify({ ...rumor, content: rumor.content + '\0' }));
    await expect(openGrantWrap(wrap, receiver)).rejects.toMatchObject({
      code: mode.startsWith('oversize') ? 'TOO_LARGE' : 'AUTH',
    });
  });

  it('uses device and identity p filters for live and paged inbox history', async () => {
    const net = network();
    const device = getPublicKey(otherKey);
    const inbox = await createGrantInbox(recipient, ['wss://vault.example'], [device, device], net);
    const handlers = { onevent: vi.fn() };
    inbox.subscribe(handlers);
    const abort = new AbortController();
    await inbox.backfill(handlers, abort.signal);
    const filters = [{ kinds: [1059], '#p': [device, recipient] }];
    expect(net.relay.subscribe).toHaveBeenCalledWith(filters, handlers);
    expect(net.relay.backfill).toHaveBeenCalledWith(filters, handlers, abort.signal);
    expect(inbox.endpoints).toEqual(['wss://vault.example/', 'wss://inbox.example/']);
    inbox.stop();
    expect(net.relay.stop).toHaveBeenCalledOnce();
  });
});

describe('timestamp randomization', () => {
  it('rejects biased samples and includes both offset endpoints', () => {
    const values = [0xffffffff, 0, NIP59_TIMESTAMP_RANDOM_RANGE - 1];
    const random = vi.spyOn(crypto, 'getRandomValues').mockImplementation(array => {
      if (array instanceof Uint32Array) array[0] = values.shift()!;
      return array;
    });
    expect(randomizedTimestamp(200000)).toBe(199999);
    expect(randomizedTimestamp(200000)).toBe(27200);
    expect(random).toHaveBeenCalledTimes(3);
  });
  it('fails closed on RNG failure', async () => {
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(() => { throw new Error('rng'); });
    expect(() => randomizedTimestamp(200000)).toThrow(expect.objectContaining({ code: 'CRYPTO' }));
    await expect(buildGrantWrap(grant(), signer(ownerKey), recipient)).rejects.toMatchObject({ code: 'CRYPTO' });
  });
});
