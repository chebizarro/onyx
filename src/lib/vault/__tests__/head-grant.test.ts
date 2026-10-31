import { describe, expect, it } from 'vitest';
import { finalizeEvent, getEventHash, getPublicKey, verifiedSymbol } from 'nostr-tools';
import type { Event as NostrEvent, UnsignedEvent } from 'nostr-tools';
import fixture from '../../../../tests/fixtures/vault/head.json';
import derivation from '../../../../tests/fixtures/vault/ring-derivation.json';
import seals from '../../../../tests/fixtures/vault/seal-v2.json';
import {
  bytes32, bytesToHex, deriveHeadConversationKey, encryptNip44, hex32, hexToBytes,
} from '../crypto';
import { buildGrantRumor, decodeGrant, encodeGrant, openGrantRumor, validateHintUrl, validateKeyRing } from '../grant';
import { buildHeadEvent, decodeHead, encodeHead, headDTag, openHead, openHeadEvent, sealHead } from '../head';
import { VaultError } from '../errors';
import {
  INT64_MAX, NIP59_MAX_PLAINTEXT, PORTHOME_HEAD_MAX_JSON, PORTHOME_HEAD_MAX_PARENTS,
  PORTHOME_HEAD_MAX_PAYLOAD, UINT64_MAX, VAULT_GRANT_MAX_JSON, VAULT_MAX_EPOCHS,
  VAULT_MAX_HINTS, VAULT_MAX_URL,
} from '../protocol';
import type { Address, GrantRumor, KeyRing, NodeId, Pubkey, VaultGrant, VaultHead, VaultId } from '../types';

const key = bytes32(hexToBytes(derivation.keys.child));
const rootKey = bytes32(hexToBytes(derivation.keys.root));
const ring: KeyRing = { entries: [{ epoch: 1n, nodeKey: rootKey }, { epoch: 3n, nodeKey: key }] };
const sk = hexToBytes(fixture.signerSecretHex), writer = hex32<Pubkey>(getPublicKey(sk));
const nonce = new Uint8Array(32);
const full = (): VaultHead => decodeHead(fixture.fullJson);

function sign(event: UnsignedEvent): NostrEvent {
  return finalizeEvent({ ...event, tags: event.tags.map(tag => [...tag]) }, sk);
}

function rumorWith(event: GrantRumor, change: Partial<GrantRumor>): GrantRumor {
  const result = { ...event, ...change };
  return { ...result, id: getEventHash(result) };
}

function grant(): VaultGrant {
  return {
    vaultId: hex32<VaultId>('09' + '00'.repeat(31)), nodeId: hex32<NodeId>(derivation.childNodeIdHex),
    ring, cap: 'write', owner: writer, rootManifest: hex32<Address>(seals.chunks[0].address),
    hints: { relays: ['wss://nos.lol'], blossom: ['https://blossom.example'] }, issuedAt: 123n,
  };
}

// Encoder order is from codec.c; ring gaps are legal on decode.
const expectedGrantJson = `{"vault_id":"${grant().vaultId}","node_id":"${grant().nodeId}","ring":[{"epoch":1,"node_key":"${derivation.keys.root}"},{"epoch":3,"node_key":"${derivation.keys.child}"}],"cap":"write","owner":"${writer}","root_manifest":"${seals.chunks[0].address}","hints":{"relays":["wss://nos.lol"],"blossom":["https://blossom.example"]},"issued_at":123}`;

describe('strict head JSON C fixtures', () => {
  it('matches compact, reordered and full uint64 C samples byte-for-byte', () => {
    expect(encodeHead(decodeHead(fixture.simpleJson))).toBe(fixture.simpleJson);
    expect(encodeHead(decodeHead(fixture.reorderedJson))).toBe(fixture.simpleJson);
    expect(encodeHead(full())).toBe(fixture.fullJson);
    expect(full().seq).toBe(UINT64_MAX);
    expect(full().parents[0].seq).toBe(UINT64_MAX);
    expect(full().grantsRev).toBe(UINT64_MAX);
    expect(headDTag(full().vaultId)).toBe(fixture.dTag);
    expect(fixture.dTag.length).toBe(76);
  });

  it.each(fixture.malformed)('rejects the pinned head JSON case $name', v => {
    expect(() => decodeHead(v.json)).toThrow(VaultError);
  });

  it('places optional ref_state then key_override before seq, regardless of input order', () => {
    const head = { ...full(), keyOverride: key };
    const expected = fixture.fullJson.replace(',"seq":18446744073709551615,', `,"key_override":"${bytesToHex(key)}","seq":18446744073709551615,`);
    expect(encodeHead(head)).toBe(expected);
    const reordered = fixture.fullJson.replace('"written_at":123456789}', `"written_at":123456789,"key_override":"${bytesToHex(key)}"}`);
    expect(decodeHead(reordered)).toEqual(head);
    expect(encodeHead(decodeHead(reordered))).toBe(expected);
  });

  it('preserves integers above Number.MAX_SAFE_INTEGER and all protocol uint64 boundaries', () => {
    const head = { ...full(), epoch: UINT64_MAX, seq: 9007199254740993n, writtenAt: INT64_MAX };
    expect(decodeHead(encodeHead(head))).toEqual(head);
    expect(encodeHead(head)).toContain('"seq":9007199254740993');
    expect(() => encodeHead({ ...head, writtenAt: INT64_MAX + 1n })).toThrow(VaultError);
    expect(() => encodeHead({ ...head, seq: UINT64_MAX + 1n })).toThrow(VaultError);
  });

  it.each(['-1', '+1', '1.0', '1e0', '01', '18446744073709551616', '"1"', 'true', 'null', '[]'])('rejects noncanonical integer token %s in every numeric field', token => {
    for (const [field, value] of [['epoch', '1'], ['seq', '0'], ['grants_rev', '0'], ['written_at', '0']]) {
      expect(() => decodeHead(fixture.simpleJson.replace(`"${field}":${value}`, `"${field}":${token}`))).toThrow(VaultError);
    }
  });

  it('rejects unknown/duplicate/missing fields, escapes, uppercase hex and trailing/NUL data', () => {
    for (const json of [
      fixture.simpleJson.replace('"seq":0', '"writer":"' + writer + '","seq":0'),
      fixture.simpleJson.replace('"epoch":1', '"epoch":1,"epoch":1'),
      fixture.simpleJson.replace('"epoch":1,', ''),
      fixture.simpleJson.replace('"vault_id"', '"vault_\\u0069d"'),
      fixture.simpleJson.replace('"vault_id":"' + '00'.repeat(32), '"vault_id":"' + 'AB'.repeat(32)),
      fixture.simpleJson + 'junk', fixture.simpleJson + '\0ignored', '\ufeff' + fixture.simpleJson,
      fixture.simpleJson.replace('"parents":[]', '"parents":[{"writer":"' + writer + '","seq":0,"root_manifest":"' + '00'.repeat(32) + '","unknown":0}]'),
    ]) expect(() => decodeHead(json)).toThrow(VaultError);
  });

  it('enforces the parent and JSON bounds, without sorting/deduping parents', () => {
    const parent = full().parents[0];
    const max = { ...full(), parents: Array.from({ length: PORTHOME_HEAD_MAX_PARENTS }, () => parent) };
    expect(decodeHead(encodeHead(max))).toEqual(max);
    expect(() => encodeHead({ ...max, parents: [...max.parents, parent] })).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    const tooMany = encodeHead(max).replace('"parents":[', `"parents":[{"writer":"${parent.writer}","seq":0,"root_manifest":"${parent.rootManifest}"},`);
    expect(() => decodeHead(tooMany)).toThrow(VaultError);
    expect(() => decodeHead(' '.repeat(PORTHOME_HEAD_MAX_JSON + 1))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    expect(decodeHead(' '.repeat(PORTHOME_HEAD_MAX_JSON - fixture.simpleJson.length) + fixture.simpleJson)).toEqual(decodeHead(fixture.simpleJson));
  });
});

describe('head NIP-44 sealing and signed event boundary', () => {
  it('builds unsigned kind-30078 with exactly d, writer and created_at=written_at', () => {
    const head = full(), event = buildHeadEvent(head, key, writer, nonce);
    expect(event).toEqual({ kind: 30078, pubkey: writer, created_at: Number(head.writtenAt), tags: [['d', fixture.dTag]], content: sealHead(head, key, nonce) });
    expect('sig' in event).toBe(false);
    expect(openHeadEvent(sign(event), head.vaultId, ring, 3n)).toEqual(head);
  });

  it('accepts unrelated tags and imposes NO written_at equality or receive-time/skew rule', () => {
    const head = full();
    for (const created_at of [0, 1, 2147483647, 4102444800]) {
      const event = sign({ ...buildHeadEvent(head, key, writer, nonce), created_at, tags: [['client', 'test'], ['d', fixture.dTag], ['e', 'note']] });
      expect(openHeadEvent(event, head.vaultId, ring, 3n)).toEqual(head);
    }
  });

  it('does not retry any historical epoch on authentication failure', () => {
    const head = full(), payload = sealHead(head, key, nonce);
    expect(openHead(ring, 3n, payload)).toEqual(head);
    expect(() => openHead(ring, 1n, payload)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
    expect(() => openHead(ring, 2n, payload)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    // Same key at another epoch isolates the authenticated body-epoch binding.
    expect(() => openHead({ entries: [{ epoch: 1n, nodeKey: key }] }, 1n, payload)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    expect(() => openHead(ring, 3n, 'x'.repeat(PORTHOME_HEAD_MAX_PAYLOAD + 1))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    // Below the UTF-16 limit but above the UTF-8 byte cap: reject before decrypt.
    expect(() => openHead(ring, 3n, 'é'.repeat(Math.floor(PORTHOME_HEAD_MAX_PAYLOAD / 2) + 1))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
  });

  it('never discloses a different override under the selected old key', () => {
    const head = { ...full(), keyOverride: key };
    expect(openHead(ring, 3n, sealHead(head, key, nonce))).toEqual(head);
    expect(() => sealHead({ ...head, keyOverride: rootKey }, key, nonce)).toThrowError(expect.objectContaining({ code: 'ARG' }));
    const convKey = deriveHeadConversationKey(key);
    const forged = encryptNip44(encodeHead({ ...head, keyOverride: rootKey }), convKey, nonce);
    expect(() => openHead(ring, 3n, forged)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
  });

  it.each([
    [], [['d', fixture.dTag], ['d', fixture.dTag]], [['d']], [['d', fixture.dTag, 'extra']],
    [['d', 'porthome/v2/' + '00'.repeat(32)]],
  ].map(tags => ({ tags })))('refuses missing/ambiguous/wrong-shaped d tag $tags', ({ tags }) => {
    const event = sign({ ...buildHeadEvent(full(), key, writer, nonce), tags });
    expect(() => openHeadEvent(event, full().vaultId, ring, 3n)).toThrow(VaultError);
  });

  it('checks outer kind/content/id/signature before opening and binds vault id inside', () => {
    const event = sign(buildHeadEvent(full(), key, writer, nonce));
    for (const changed of [
      { ...event, kind: 1 }, { ...event, content: '' }, { ...event, content: 'x'.repeat(PORTHOME_HEAD_MAX_PAYLOAD + 1) },
      { ...event, id: '00'.repeat(32) }, { ...event, sig: '00'.repeat(64) },
    ]) {
      // Even a verifiedSymbol carried by finalizeEvent must not bypass validation.
      expect(changed[verifiedSymbol]).toBe(true);
      expect(() => openHeadEvent(changed, full().vaultId, ring, 3n)).toThrow(VaultError);
    }
    const otherVault = hex32<VaultId>('00'.repeat(32));
    const wrongBody = sign({ ...buildHeadEvent({ ...full(), vaultId: otherVault }, key, writer, nonce), tags: [['d', fixture.dTag]] });
    expect(() => openHeadEvent(wrongBody, full().vaultId, ring, 3n)).toThrowError(expect.objectContaining({ code: 'ARG' }));
  });

  it('refuses lossy conversion to the number-based event timestamp API', () => {
    expect(() => buildHeadEvent({ ...full(), writtenAt: 9007199254740992n }, key, writer)).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
  });
});

describe('strict grant JSON and ring', () => {
  it('matches codec.c compact field order and permits reordered fields/whitespace', () => {
    expect(encodeGrant(grant())).toBe(expectedGrantJson);
    expect(decodeGrant(expectedGrantJson)).toEqual(grant());
    const reordered = ` { "issued_at":123,"hints":{"blossom":["https://blossom.example"],"relays":["wss://nos.lol"]},"root_manifest":"${grant().rootManifest}","owner":"${writer}","cap":"write","ring":[{"node_key":"${derivation.keys.root}","epoch":1},{"node_key":"${derivation.keys.child}","epoch":3}],"node_id":"${grant().nodeId}","vault_id":"${grant().vaultId}" }\n`;
    expect(decodeGrant(reordered)).toEqual(grant());
    expect(encodeGrant(decodeGrant(reordered))).toBe(expectedGrantJson);
  });

  it('preserves full uint64 epochs, accepts gaps, and caps issued_at at INT64_MAX', () => {
    const g = { ...grant(), issuedAt: INT64_MAX, ring: { entries: [{ epoch: UINT64_MAX, nodeKey: key }] } };
    expect(decodeGrant(encodeGrant(g))).toEqual(g);
    expect(() => encodeGrant({ ...g, issuedAt: INT64_MAX + 1n })).toThrow(VaultError);
    expect(() => decodeGrant(expectedGrantJson.replace('"issued_at":123', '"issued_at":9223372036854775808'))).toThrow(VaultError);
    expect(encodeGrant({ ...grant(), cap: 'read' })).toBe(expectedGrantJson.replace('"cap":"write"', '"cap":"read"'));
  });

  it('rejects every truncated grant prefix from the C codec-style fixture', () => {
    for (let i = 0; i < expectedGrantJson.length; i++) expect(() => decodeGrant(expectedGrantJson.slice(0, i))).toThrow(VaultError);
  });

  it.each([
    ['"cap":"write"', '"cap":"admin"'], ['"issued_at":123', '"issued_at":123,"issued_at":123'],
    ['"issued_at":123', '"unknown":123'], ['"epoch":1', '"epoch":0'], ['"epoch":3', '"epoch":1'],
    ['wss://nos.lol', 'file://nos.lol'], ['"issued_at":123', '"issued_at":18446744073709551616'],
    ['"issued_at":123', '"issued_at":-1'], ['"issued_at":123', '"issued_at":1e2'],
    ['"issued_at":123', '"issued_at":01'], ['"issued_at":123', '"issued_at":1.5'],
    ['"vault_id"', '"vault_\\u0069d"'], [derivation.keys.root, derivation.keys.root.toUpperCase()],
    ['"epoch":1', '"epoch":1,"epoch":1'], ['"node_key"', '"unknown"'],
    ['"hints":{', '"hints":{"relays":[],'], ['"blossom":["https://blossom.example"]', '"unknown":[]'],
    ['"relays":["wss://nos.lol"]', '"relays":[] ,"extra":0'],
  ])('rejects adversarial grant replacement %s -> %s', (find, replace) => {
    expect(expectedGrantJson).toContain(find);
    expect(() => decodeGrant(expectedGrantJson.replace(find, replace))).toThrow(VaultError);
  });

  it('requires every top-level, ring and hint field with no escaped strings or trailing input', () => {
    const parsed = JSON.parse(expectedGrantJson) as Record<string, unknown>;
    for (const field of Object.keys(parsed)) {
      const missing = { ...parsed }; delete missing[field];
      expect(() => decodeGrant(JSON.stringify(missing))).toThrow(VaultError);
    }
    for (const json of [
      expectedGrantJson + '{}', expectedGrantJson + '\0ignored',
      expectedGrantJson.replace('wss://nos.lol', 'wss://nos\\u002elol'),
      expectedGrantJson.replace('wss://nos.lol', 'wss://nös.lol'),
      expectedGrantJson.replace('"ring":[', '"ring":[{},'),
      expectedGrantJson.replace('"hints":{', '"hints":{"unknown":[], '),
    ]) expect(() => decodeGrant(json)).toThrow(VaultError);
  });

  it('rejects empty/unordered/zero/duplicate-key rings while retaining distinct historical keys', () => {
    const invalid: KeyRing[] = [
      { entries: [] }, { entries: [{ epoch: 0n, nodeKey: key }] },
      { entries: [...ring.entries].reverse() }, { entries: [ring.entries[0], { epoch: 1n, nodeKey: key }] },
      { entries: [{ epoch: 1n, nodeKey: key }, { epoch: 3n, nodeKey: bytes32(key) }] },
    ];
    for (const bad of invalid) {
      expect(() => validateKeyRing(bad)).toThrow(VaultError);
      expect(() => encodeGrant({ ...grant(), ring: bad })).toThrow(VaultError);
    }
    expect(() => decodeGrant(expectedGrantJson.replace(derivation.keys.child, derivation.keys.root))).toThrow(VaultError);
    expect(() => decodeGrant(expectedGrantJson.replace(/"ring":\[.*?\],"cap"/, '"ring":[],"cap"'))).toThrow(VaultError);
    expect(() => validateKeyRing({ entries: new Array(VAULT_MAX_EPOCHS + 1) })).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    const owned = decodeGrant(expectedGrantJson);
    owned.ring.entries[0].nodeKey[0] ^= 1;
    expect(bytesToHex(ring.entries[0].nodeKey)).toBe(derivation.keys.root);
  });

  it('enforces hint count, URL bytes, and raw JSON bounds before oversized envelopes escape', () => {
    const g = grant();
    const max = { ...g, hints: { relays: Array.from({ length: VAULT_MAX_HINTS }, () => 'wss://r'), blossom: [] } };
    expect(decodeGrant(encodeGrant(max))).toEqual(max);
    expect(() => encodeGrant({ ...max, hints: { ...max.hints, relays: [...max.hints.relays, 'wss://r'] } })).toThrow(VaultError);
    const tooManyUrls = expectedGrantJson.replace('["wss://nos.lol"]', JSON.stringify(Array.from({ length: VAULT_MAX_HINTS + 1 }, () => 'wss://r')));
    expect(() => decodeGrant(tooManyUrls)).toThrow(VaultError);
    const maxUrl = 'wss://' + 'x'.repeat(VAULT_MAX_URL - 6);
    expect(() => validateHintUrl(maxUrl, true)).not.toThrow();
    expect(() => validateHintUrl(maxUrl + 'x', true)).toThrow(VaultError);
    expect(() => decodeGrant(' '.repeat(VAULT_GRANT_MAX_JSON + 1))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    expect(decodeGrant(' '.repeat(VAULT_GRANT_MAX_JSON - expectedGrantJson.length) + expectedGrantJson)).toEqual(g);
    expect(() => encodeGrant({ ...g, hints: { relays: Array(VAULT_MAX_HINTS).fill(maxUrl), blossom: [] } })).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
  });

  it.each(['ws://localhost', 'wss://relay.example/path?query#fragment'])('keeps protocol hints separate from network endpoint policy: %s', url => {
    expect(() => validateHintUrl(url, true)).not.toThrow();
  });

  it.each(['', 'wss://', 'wss:///path', 'WSS://r', 'https://r', 'wss://a b', 'wss://a\tb', 'wss://a\nb', 'wss://a"b', 'wss://a\\b', 'wss://é', 'wss://a\u007f', 'wss://a\0b'])('refuses non-C relay hint %j', url => {
    expect(() => validateHintUrl(url, true)).toThrow(VaultError);
    expect(() => decodeGrant(expectedGrantJson.replace('wss://nos.lol', url))).toThrow(VaultError);
  });

  it('accepts http(s) Blossom hints but not ws(s), and raw printable ASCII only', () => {
    for (const url of ['http://localhost', 'https://example.test/path']) expect(() => validateHintUrl(url, false)).not.toThrow();
    for (const url of ['wss://r', 'https://', 'https:///x', 'https://x y', 'https://é']) expect(() => validateHintUrl(url, false)).toThrow(VaultError);
  });
});

describe('unsigned kind-30804 grant rumor', () => {
  it('builds the canonical id with owner, empty tags, issued_at and no signature', () => {
    const g = grant(), rumor = buildGrantRumor(g);
    expect(rumor).toEqual({ kind: 30804, pubkey: writer, created_at: 123, tags: [], content: expectedGrantJson, id: getEventHash(rumor) });
    expect('sig' in rumor).toBe(false);
    expect(openGrantRumor(rumor)).toEqual(g);
    expect(openGrantRumor({ ...rumor, sig: '' })).toEqual(g);
  });

  it('rejects bare signed rumors, bad ids/kinds/tags, mismatched owner/timestamp and negative time', () => {
    const rumor = buildGrantRumor(grant());
    const other = hex32<Pubkey>(getPublicKey(hexToBytes('00'.repeat(31) + '02')));
    const bad: GrantRumor[] = [
      { ...rumor, sig: '01' }, { ...rumor, id: '00'.repeat(32) }, rumorWith(rumor, { kind: 1 }),
      rumorWith(rumor, { tags: [['p', writer]] }), rumorWith(rumor, { pubkey: other }),
      rumorWith(rumor, { created_at: 124 }), rumorWith(rumor, { created_at: -1 }),
      rumorWith(rumor, { created_at: 1.5 }), { ...rumor, content: 'x'.repeat(VAULT_GRANT_MAX_JSON + 1) },
      sign(rumor),
    ];
    for (const event of bad) expect(() => openGrantRumor(event)).toThrowError(expect.objectContaining({ code: 'AUTH' }));
    expect(() => buildGrantRumor({ ...grant(), issuedAt: 9007199254740992n })).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
  });

  it('enforces the same 65535-byte bound at each nested NIP-44 plaintext boundary', () => {
    const convKey = deriveHeadConversationKey(key);
    const atLimit = 'x'.repeat(NIP59_MAX_PLAINTEXT);
    expect(() => encryptNip44(atLimit, convKey, nonce)).not.toThrow();
    expect(() => encryptNip44(atLimit + 'x', convKey, nonce)).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    // A raw grant that fits can still produce a seal/wrap plaintext that does not.
    // Carrier orchestration is P5; this portable primitive checks each call itself.
    const ciphertext = encryptNip44(atLimit, convKey, nonce);
    const sealJson = JSON.stringify({ kind: 13, pubkey: writer, created_at: 0, tags: [], content: ciphertext, id: '00'.repeat(32), sig: '00'.repeat(64) });
    expect(() => encryptNip44(sealJson, convKey, nonce)).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
  });
});
