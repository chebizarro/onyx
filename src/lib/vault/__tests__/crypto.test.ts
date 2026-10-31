import { describe, expect, it } from 'vitest';
import { getPublicKey, nip44 } from 'nostr-tools';
import { chacha20 } from '@noble/ciphers/chacha.js';
import { expand } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import derivation from '../../../../tests/fixtures/vault/ring-derivation.json';
import seals from '../../../../tests/fixtures/vault/seal-v2.json';
import padding from '../../../../tests/fixtures/vault/pad-buckets.json';
import nip44Vectors from '../../../../tests/fixtures/vault/nip44.vectors.json';
import {
  bytes32, bytesToHex, decryptNip44, deriveChildNodeKey, deriveHeadConversationKey,
  deriveHeadKey, deriveNameKey, deriveRootNodeKey, encryptName, encryptNip44, hashAddress,
  hex32, hexToBytes, openChunk, openManifest, paddedLength, safeNumber,
  reduceHeadScalar, sealChunk, sealManifest, selectEpochKey, verifyAddress,
} from '../crypto';
import { VaultError } from '../errors';
import { SECP256K1_ORDER, UINT64_MAX } from '../protocol';
import type { KeyRing, NodeId } from '../types';

const key = bytes32(hexToBytes(seals.nodeKeyHex));
const ring = (epoch = 3n): KeyRing => ({ entries: [{ epoch, nodeKey: key }] });
const utf8 = new TextEncoder();
const vectors = nip44Vectors.v2;

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) { result.set(p, offset); offset += p.length; }
  return result;
}

function base64(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)); }

// These are C fixtures, not TS self-round-trips.
describe('PCS v2 derivation and epoch selection', () => {
  it('matches every pinned root/child/name/head hex and report.pdf tag', () => {
    const root = deriveRootNodeKey(hexToBytes(derivation.seedHex));
    const child = deriveChildNodeKey(root, hex32<NodeId>(derivation.childNodeIdHex));
    expect(bytesToHex(root)).toBe(derivation.keys.root);
    expect(bytesToHex(child)).toBe(derivation.keys.child);
    expect(bytesToHex(deriveNameKey(child))).toBe(derivation.keys.name);
    expect(bytesToHex(deriveHeadKey(child))).toBe(derivation.keys.head);
    expect(encryptName(child, derivation.name.plaintext)).toBe(derivation.name.nameEnc);
    const headKey = deriveHeadKey(child);
    // A self-ECDH key, not head_key itself and not a second HKDF expand.
    expect(deriveHeadConversationKey(child)).toEqual(nip44.v2.utils.getConversationKey(headKey, getPublicKey(headKey)));
  });

  it('reduces big-endian scalars modulo n and rejects zero without a curve import', () => {
    const scalarBytes = (n: bigint) => hexToBytes(n.toString(16).padStart(64, '0'));
    for (const value of [1n, SECP256K1_ORDER - 1n, SECP256K1_ORDER + 1n, (1n << 256n) - 1n]) {
      const input = scalarBytes(value), copy = input.slice();
      expect(reduceHeadScalar(input)).toEqual(scalarBytes(value % SECP256K1_ORDER));
      expect(input).toEqual(copy);
    }
    for (const value of [0n, SECP256K1_ORDER])
      expect(() => reduceHeadScalar(scalarBytes(value))).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
  });

  it('uses an override verbatim and returns an owned copy', () => {
    const override = bytes32(hexToBytes(derivation.override.keyHex));
    const child = deriveChildNodeKey(key, hex32<NodeId>(derivation.override.nodeIdHex), override);
    expect(bytesToHex(child)).toBe(derivation.override.expectedChildHex);
    child[0] ^= 255;
    expect(bytesToHex(override)).toBe(derivation.override.keyHex);
  });

  it.each([...derivation.unsafeNames, '', '.', 'a/b', 'a\\b', 'a\0b', 'x'.repeat(256), '\ud800'])('refuses unsafe basename %j', name => {
    expect(() => encryptName(key, name)).toThrow(VaultError);
  });

  it('selects only the requested epoch and scans the whole ring for ordering', () => {
    const other = bytes32(hexToBytes(derivation.override.keyHex));
    const historical: KeyRing = { entries: [{ epoch: 1n, nodeKey: key }, { epoch: 3n, nodeKey: other }] };
    const plain = hexToBytes(derivation.ring.plaintextHex);
    const chunk = sealChunk(key, plain).sealed;
    const manifest = sealManifest(key, plain).sealed;
    expect(openChunk(historical, 1n, chunk, BigInt(plain.length))).toEqual(plain);
    expect(() => openChunk(historical, 3n, chunk, BigInt(plain.length))).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
    expect(() => openManifest(historical, 3n, manifest)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
    for (const epoch of [2n, 4n]) {
      expect(() => openChunk(historical, epoch, chunk, BigInt(plain.length))).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
      expect(() => openManifest(historical, epoch, manifest)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    }
    expect(() => openChunk({ entries: [historical.entries[1]] }, 1n, chunk, BigInt(plain.length)))
      .toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    expect(() => selectEpochKey({ entries: [] }, 1n)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    for (const epochs of derivation.ring.invalidEpochs) {
      expect(() => selectEpochKey({ entries: epochs.map(epoch => ({ epoch: BigInt(epoch), nodeKey: key })) }, 1n))
        .toThrowError(expect.objectContaining({ code: 'ARG' }));
    }
    expect(() => selectEpochKey(historical, 0n)).toThrow(VaultError);
    expect(() => selectEpochKey({ entries: [...historical.entries, historical.entries[0]] }, 1n)).toThrow(VaultError);
  });

  it('checks uint64-to-number conversion and owned key sizes', () => {
    expect(safeNumber(9007199254740991n)).toBe(Number.MAX_SAFE_INTEGER);
    expect(() => safeNumber(9007199254740992n)).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    for (const value of [-1n, UINT64_MAX + 1n]) expect(() => safeNumber(value)).toThrow(VaultError);
    expect(() => bytes32(new Uint8Array(31))).toThrow(VaultError);
  });
});


describe('PCS v2 sealed C vectors', () => {
  it.each(seals.chunks)('matches all bytes and address for $name', vector => {
    const plain = hexToBytes(vector.plaintextHex);
    const sealed = sealChunk(key, plain);
    expect(bytesToHex(sealed.sealed)).toBe(vector.sealedHex);
    expect(sealed.address).toBe(vector.address);
    expect(hashAddress(sealed.sealed)).toBe(vector.address);
    expect(openChunk(ring(BigInt(vector.epoch)), BigInt(vector.epoch), hexToBytes(vector.sealedHex), BigInt(plain.length))).toEqual(plain);
    expect(() => openManifest(ring(), 3n, sealed.sealed)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
  });

  it.each(seals.chunks)('refuses every truncation and authenticated-byte mutation for $name', vector => {
    const sealed = hexToBytes(vector.sealedHex);
    const size = BigInt(vector.plaintextHex.length / 2);
    for (let length = 0; length < sealed.length; length++)
      expect(() => openChunk(ring(), 3n, sealed.subarray(0, length), size)).toThrow(VaultError);
    for (let i = 1; i < sealed.length; i++) {
      const changed = sealed.slice(); changed[i] ^= 1;
      expect(() => openChunk(ring(), 3n, changed, size)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
    }
  });

  it('matches the unpadded manifest vector and refuses chunk-domain opening', () => {
    const v = seals.manifest, plain = hexToBytes(v.plaintextHex);
    const sealed = sealManifest(key, plain);
    expect(bytesToHex(sealed.sealed)).toBe(v.sealedHex);
    expect(sealed.address).toBe(v.address);
    expect(sealed.sealed.length).toBe(plain.length + 29);
    expect(openManifest(ring(1n), 1n, hexToBytes(v.sealedHex))).toEqual(plain);
    const changed = sealed.sealed.slice(); changed[changed.length - 1] ^= 1;
    expect(() => openManifest(ring(1n), 1n, changed)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
    // Matching padded size reaches authentication, rather than just bucket refusal.
    const fullBucket = sealManifest(key, new Uint8Array(32));
    expect(() => openChunk(ring(), 3n, fullBucket.sealed, 32n)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
  });

  it('refuses PCS v1 and every unsupported version before epoch lookup', () => {
    const legacy = hexToBytes(seals.legacyRefusal.sealedHex);
    for (const version of [0, 1, 3, 255]) {
      legacy[0] = version;
      expect(() => openManifest({ entries: [] }, 3n, legacy)).toThrowError(expect.objectContaining({ code: 'VERSION' }));
      expect(() => openChunk({ entries: [] }, 3n, legacy, 0n)).toThrowError(expect.objectContaining({ code: 'VERSION' }));
    }
  });

  it('hash-verifies the whole stored envelope before caller-owned decoding', () => {
    const sealed = hexToBytes(seals.chunks[0].sealedHex);
    const expected = sealChunk(key, new Uint8Array()).address;
    expect(() => verifyAddress(sealed, expected)).not.toThrow();
    sealed[1] ^= 1;
    expect(() => verifyAddress(sealed, expected)).toThrowError(expect.objectContaining({ code: 'HASH_MISMATCH' }));
  });
});

describe('PCS zero padding without a length prefix', () => {
  const nonzero = Uint8Array.from({ length: padding.plaintextGenerator.length }, (_, i) => i % 255 + 1);
  it.each(padding.cases)('matches bucket $plain -> $padded and authenticates the complete tail', v => {
    expect(paddedLength(v.plain)).toBe(v.padded);
    expect(paddedLength(BigInt(v.plain))).toBe(v.padded);
    const plain = nonzero.subarray(0, v.plain), sealed = sealChunk(key, plain).sealed;
    expect(sealed.length).toBe(v.padded + 29);
    expect(openChunk(ring(), 3n, sealed, BigInt(v.plain))).toEqual(plain);
    if (v.plain) expect(() => openChunk(ring(), 3n, sealed, BigInt(v.plain - 1))).toThrow(VaultError);
    expect(() => openChunk(ring(), 3n, sealed, BigInt(v.padded + 1))).toThrow(VaultError);
  });

  it('hashes true bytes, including trailing zero, before zero padding', () => {
    const one = sealChunk(key, hexToBytes(padding.adversarial.distinctPlaintextsHex[0]));
    const two = sealChunk(key, hexToBytes(padding.adversarial.distinctPlaintextsHex[1]));
    expect(one.sealed.length).toBe(two.sealed.length);
    expect(one.address).not.toBe(two.address);
    expect(openChunk(ring(), 3n, two.sealed, 2n)).toEqual(new Uint8Array([120, 0]));
    // The true length comes from the authenticated manifest. A zero tail alone
    // cannot distinguish appended plaintext zeros; reseal must compare canonically.
    expect(openChunk(ring(), 3n, two.sealed, 1n)).toEqual(new Uint8Array([120]));
    expect(sealChunk(key, openChunk(ring(), 3n, two.sealed, 1n)).address).not.toBe(two.address);
  });

  it.each([-1, 1.5, NaN, Infinity, 2147483648])('refuses invalid/oversized length %s', size => {
    expect(() => paddedLength(size)).toThrow(VaultError);
  });
});

describe('official pinned NIP-44 v2 vectors', () => {
  it.each(vectors.valid.get_conversation_key)('matches conversation key for $sec1 / $pub2', v => {
    expect(bytesToHex(nip44.v2.utils.getConversationKey(hexToBytes(v.sec1), v.pub2))).toBe(v.conversation_key);
  });

  it.each(vectors.valid.get_message_keys.keys)('matches 76-byte expand for $nonce', v => {
    const keys = expand(sha256, hexToBytes(vectors.valid.get_message_keys.conversation_key), hexToBytes(v.nonce), 76);
    expect(bytesToHex(keys.subarray(0, 32))).toBe(v.chacha_key);
    expect(bytesToHex(keys.subarray(32, 44))).toBe(v.chacha_nonce);
    expect(bytesToHex(keys.subarray(44))).toBe(v.hmac_key);
  });

  it.each(vectors.valid.calc_padded_len)('matches official bucket %s -> %s', (plain, padded) => {
    expect(paddedLength(plain)).toBe(padded);
  });

  it.each(vectors.valid.encrypt_decrypt)('matches complete NIP-44 payload for $nonce', v => {
    const conversationKey = hexToBytes(v.conversation_key);
    expect(encryptNip44(v.plaintext, conversationKey, hexToBytes(v.nonce))).toBe(v.payload);
    expect(decryptNip44(v.payload, conversationKey)).toBe(v.plaintext);
  });

  it.each(vectors.valid.encrypt_decrypt_long_msg)('matches long-message SHA-256 for $repeat repetitions', v => {
    const plain = v.pattern.repeat(v.repeat), conversationKey = hexToBytes(v.conversation_key);
    const payload = encryptNip44(plain, conversationKey, hexToBytes(v.nonce));
    expect(hashAddress(utf8.encode(plain))).toBe(v.plaintext_sha256);
    expect(hashAddress(utf8.encode(payload))).toBe(v.payload_sha256);
    expect(decryptNip44(payload, conversationKey)).toBe(plain);
  });

  it.each(vectors.invalid.get_conversation_key)('rejects invalid ECDH: $note', v => {
    expect(() => nip44.v2.utils.getConversationKey(hexToBytes(v.sec1), v.pub2)).toThrow();
  });

  it.each(vectors.invalid.encrypt_msg_lengths)('rejects invalid plaintext length %s', length => {
    expect(() => encryptNip44('x'.repeat(length), key)).toThrow(VaultError);
  });

  it.each(vectors.invalid.decrypt)('rejects invalid NIP-44 payload: $note', v => {
    expect(() => decryptNip44(v.payload, hexToBytes(v.conversation_key))).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
  });

  it('closes the installed nostr-tools nonzero-padding gap exactly as C unpad', () => {
    const v = vectors.valid.encrypt_decrypt[0], conversationKey = hexToBytes(v.conversation_key);
    const nonce = hexToBytes(v.nonce), keys = expand(sha256, conversationKey, nonce, 76);
    const padded = new Uint8Array(34); padded[1] = 1; padded[2] = 97; padded[33] = 1;
    const cipher = chacha20(keys.subarray(0, 32), keys.subarray(32, 44), padded);
    const mac = hmac(sha256, keys.subarray(44), concat(nonce, cipher));
    const malicious = base64(concat(new Uint8Array([2]), nonce, cipher, mac));
    expect(nip44.v2.decrypt(malicious, conversationKey)).toBe('a');
    expect(() => decryptNip44(malicious, conversationKey)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
  });
});
