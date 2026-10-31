import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { getPublicKey, nip44 } from 'nostr-tools';
import { VaultError } from './errors';
import {
  HKDF_DOMAINS, PORTHOME_NAME_TAG_LEN, PORTHOME_NONCE_LEN,
  PORTHOME_SEAL_OVERHEAD, PORTHOME_WIRE_VERSION_V2, SECP256K1_ORDER,
  UINT64_MAX, NIP59_MAX_PLAINTEXT, PORTHOME_NAME_PLAIN_MIN_BYTES, PORTHOME_NAME_PLAIN_MAX_BYTES,
} from './protocol';
import type {
  Address, Bytes32, EntryDigest, EventId, HeadHash, KeyRing, NameEnc,
  NodeId, Pubkey, RecordId, RefState, VaultId,
} from './types';

const utf8 = new TextEncoder();
const empty = new Uint8Array();
// crypto.c caps every AEAD input at INT_MAX, including padded chunks.
const maxSealBytes = 0x7fffffff;
type Hex32 = Address | EntryDigest | EventId | HeadHash | NodeId | Pubkey | RecordId | RefState | VaultId;

export function assertUint64(value: bigint, nonzero = false): void {
  if (typeof value !== 'bigint' || value < (nonzero ? 1n : 0n) || value > UINT64_MAX)
    throw new VaultError('ARG');
}

/** Only use for buffer lengths/indices and the number-based Nostr event API. */
export function safeNumber(value: bigint): number {
  assertUint64(value);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new VaultError('TOO_LARGE');
  return Number(value);
}

export function bytes32(value: Uint8Array): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new VaultError('ARG');
  return new Uint8Array(value) as Bytes32;
}

export function bytesToHex(value: Uint8Array): string {
  let result = '';
  for (const byte of value) result += byte.toString(16).padStart(2, '0');
  return result;
}

export function hexToBytes(value: string): Uint8Array {
  if (typeof value !== 'string' || value.length % 2 || /[^0-9a-f]/.test(value))
    throw new VaultError('ARG');
  const result = new Uint8Array(value.length / 2);
  for (let i = 0; i < result.length; i++) result[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return result;
}

export function hex32<T extends Hex32>(value: string): T {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new VaultError('ARG');
  return value as T;
}

export function nameEnc(value: string): NameEnc {
  if (typeof value !== 'string' || !/^[0-9a-f]{48}$/.test(value)) throw new VaultError('ARG');
  return value as NameEnc;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a[i] ^ b[i];
  return different === 0;
}

/** Refuse lone UTF-16 surrogates rather than silently replacing remote names. */
export function encodeUtf8(value: string): Uint8Array {
  if (typeof value !== 'string') throw new VaultError('ARG');
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new VaultError('ARG');
    } else if (c >= 0xdc00 && c <= 0xdfff) throw new VaultError('ARG');
  }
  return utf8.encode(value);
}

export function validateBasename(value: string): void {
  const length = encodeUtf8(value).length;
  if (length < PORTHOME_NAME_PLAIN_MIN_BYTES || length > PORTHOME_NAME_PLAIN_MAX_BYTES || value === '.' || value === '..' || /[/\\\0]/.test(value))
    throw new VaultError('ARG');
}

export function hashAddress(value: Uint8Array): Address {
  return hex32<Address>(bytesToHex(sha256(value)));
}

export function verifyAddress(value: Uint8Array, expected: Address): void {
  hex32<Address>(expected);
  if (hashAddress(value) !== expected) throw new VaultError('HASH_MISMATCH');
}

function derive(domain: string, key: Uint8Array, info: Uint8Array = empty, length = 32): Uint8Array {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new VaultError('ARG');
  return hkdf(sha256, key, utf8.encode(domain), info, length);
}

export function deriveRootNodeKey(seed: Uint8Array): Bytes32 {
  return derive(HKDF_DOMAINS.home, seed) as Bytes32;
}

export function deriveChildNodeKey(parent: Uint8Array, childNodeId: NodeId, override?: Uint8Array): Bytes32 {
  // The override replaces the derivation; it is not another HKDF input.
  if (override !== undefined) return bytes32(override);
  hex32<NodeId>(childNodeId);
  return derive(HKDF_DOMAINS.node, parent, hexToBytes(childNodeId)) as Bytes32;
}

export function deriveNameKey(nodeKey: Uint8Array): Bytes32 {
  return derive(HKDF_DOMAINS.name, nodeKey) as Bytes32;
}

/** Big-endian reduction used by head.c, including the rare raw >= n case. */
export function reduceHeadScalar(raw: Uint8Array): Bytes32 {
  if (!(raw instanceof Uint8Array) || raw.length !== 32) throw new VaultError('ARG');
  let scalar = 0n;
  for (const byte of raw) scalar = (scalar << 8n) | BigInt(byte);
  scalar %= SECP256K1_ORDER;
  if (scalar === 0n) throw new VaultError('CRYPTO');
  const result = new Uint8Array(32);
  for (let i = 31; i >= 0; i--, scalar >>= 8n) result[i] = Number(scalar & 255n);
  return result as Bytes32;
}

export function deriveHeadKey(nodeKey: Uint8Array): Bytes32 {
  const raw = derive(HKDF_DOMAINS.head, nodeKey);
  try { return reduceHeadScalar(raw); }
  finally { raw.fill(0); }
}

export function deriveHeadConversationKey(nodeKey: Uint8Array): Bytes32 {
  const key = deriveHeadKey(nodeKey);
  try { return bytes32(nip44.v2.utils.getConversationKey(key, getPublicKey(key))); }
  catch { throw new VaultError('CRYPTO'); }
  finally { key.fill(0); }
}

export function encryptName(nodeKey: Uint8Array, basename: string): NameEnc {
  validateBasename(basename);
  const key = deriveNameKey(nodeKey);
  let mac: Uint8Array | undefined;
  try {
    mac = hmac(sha256, key, encodeUtf8(basename));
    return nameEnc(bytesToHex(mac.subarray(0, PORTHOME_NAME_TAG_LEN)));
  } finally { key.fill(0); mac?.fill(0); }
}

/** porthome_ring_key, not vault_ring_valid: an empty ring means EPOCH. */
export function selectEpochKey(ring: KeyRing, epoch: bigint): Bytes32 {
  assertUint64(epoch, true);
  let previous = 0n;
  let selected: Uint8Array | undefined;
  for (const entry of ring.entries) {
    assertUint64(entry.epoch, true);
    if (entry.epoch <= previous || !(entry.nodeKey instanceof Uint8Array) || entry.nodeKey.length !== 32)
      throw new VaultError('ARG');
    previous = entry.epoch;
    if (entry.epoch === epoch) selected = entry.nodeKey;
  }
  if (!selected) throw new VaultError('EPOCH');
  return bytes32(selected);
}

/** PCS uses this bucket without NIP-44's two-byte length prefix. */
export function paddedLength(sizePlain: number | bigint): number {
  const n = typeof sizePlain === 'bigint' ? safeNumber(sizePlain) : sizePlain;
  if (!Number.isSafeInteger(n) || n < 0) throw new VaultError('ARG');
  if (n > maxSealBytes) throw new VaultError('TOO_LARGE');
  if (n <= 32) return 32;
  let power = 32;
  while (power < n) power *= 2;
  const bucket = power <= 256 ? 32 : power / 8;
  const padded = Math.ceil(n / bucket) * bucket;
  if (padded > maxSealBytes) throw new VaultError('TOO_LARGE');
  return padded;
}

export interface SealedObject {
  readonly sealed: Uint8Array;
  readonly address: Address;
}

function checkVersion(sealed: Uint8Array): void {
  if (!(sealed instanceof Uint8Array)) throw new VaultError('ARG');
  if (sealed.length < PORTHOME_SEAL_OVERHEAD || sealed[0] !== PORTHOME_WIRE_VERSION_V2)
    throw new VaultError('VERSION');
}

function seal(nodeKey: Uint8Array, domain: string, plaintext: Uint8Array, plainHash: Uint8Array): SealedObject {
  if (plaintext.length > maxSealBytes) throw new VaultError('TOO_LARGE');
  const nonce = derive(domain, nodeKey, plainHash, PORTHOME_NONCE_LEN);
  const key = derive(domain, nodeKey, nonce);
  try {
    // Deliberately no AAD: the version is checked before opening, not authenticated as AAD.
    const ciphertext = chacha20poly1305(key, nonce).encrypt(plaintext);
    const sealed = new Uint8Array(1 + nonce.length + ciphertext.length);
    sealed[0] = PORTHOME_WIRE_VERSION_V2;
    sealed.set(nonce, 1);
    sealed.set(ciphertext, 1 + nonce.length);
    return { sealed, address: hashAddress(sealed) };
  } catch { throw new VaultError('CRYPTO'); }
  finally { key.fill(0); nonce.fill(0); }
}

function open(nodeKey: Uint8Array, domain: string, sealed: Uint8Array): Uint8Array {
  checkVersion(sealed);
  if (sealed.length - PORTHOME_SEAL_OVERHEAD > maxSealBytes) throw new VaultError('TOO_LARGE');
  const nonce = sealed.subarray(1, 1 + PORTHOME_NONCE_LEN);
  const key = derive(domain, nodeKey, nonce);
  try { return chacha20poly1305(key, nonce).decrypt(sealed.subarray(1 + PORTHOME_NONCE_LEN)); }
  catch { throw new VaultError('CRYPTO'); }
  finally { key.fill(0); }
}

export function sealChunk(nodeKey: Uint8Array, plaintext: Uint8Array): SealedObject {
  if (!(plaintext instanceof Uint8Array)) throw new VaultError('ARG');
  const padded = new Uint8Array(paddedLength(plaintext.length));
  padded.set(plaintext);
  const hash = sha256(plaintext);
  try { return seal(nodeKey, HKDF_DOMAINS.chunk, padded, hash); }
  finally { padded.fill(0); hash.fill(0); }
}

export function openChunk(ring: KeyRing, epoch: bigint, sealed: Uint8Array, sizePlain: bigint): Uint8Array {
  checkVersion(sealed);
  const key = selectEpochKey(ring, epoch);
  let padded: Uint8Array | undefined;
  try {
    const expected = paddedLength(sizePlain);
    if (sealed.length - PORTHOME_SEAL_OVERHEAD !== expected) throw new VaultError('ARG');
    padded = open(key, HKDF_DOMAINS.chunk, sealed);
    const length = safeNumber(sizePlain);
    let tail = 0;
    for (let i = length; i < padded.length; i++) tail |= padded[i];
    if (tail) throw new VaultError('CRYPTO');
    return padded.slice(0, length);
  } finally { key.fill(0); padded?.fill(0); }
}

export function sealManifest(nodeKey: Uint8Array, plaintext: Uint8Array): SealedObject {
  if (!(plaintext instanceof Uint8Array)) throw new VaultError('ARG');
  if (plaintext.length > maxSealBytes) throw new VaultError('TOO_LARGE');
  const hash = sha256(plaintext);
  try { return seal(nodeKey, HKDF_DOMAINS.manifest, plaintext, hash); }
  finally { hash.fill(0); }
}

export function openManifest(ring: KeyRing, epoch: bigint, sealed: Uint8Array): Uint8Array {
  checkVersion(sealed);
  const key = selectEpochKey(ring, epoch);
  try { return open(key, HKDF_DOMAINS.manifest, sealed); }
  finally { key.fill(0); }
}

/** Shared by head and carrier codecs; a nonce is injectable for official vectors. */
export function encryptNip44(plaintext: string, conversationKey: Uint8Array, nonce?: Uint8Array): string {
  if (typeof plaintext !== 'string') throw new VaultError('ARG');
  if (plaintext.length > NIP59_MAX_PLAINTEXT) throw new VaultError('TOO_LARGE');
  const length = encodeUtf8(plaintext).length;
  if (length > NIP59_MAX_PLAINTEXT) throw new VaultError('TOO_LARGE');
  if (!length || conversationKey.length !== 32 || (nonce !== undefined && nonce.length !== 32))
    throw new VaultError('ARG');
  try { return nip44.v2.encrypt(plaintext, conversationKey, nonce); }
  catch { throw new VaultError('CRYPTO'); }
}

export function decryptNip44(payload: string, conversationKey: Uint8Array): string {
  try {
    const plaintext = nip44.v2.decrypt(payload, conversationKey);
    // nostr-tools 2.19.4 unpad omits the C zero-tail check. Re-encrypt with the
    // authenticated nonce to require canonical padding, UTF-8 and base64 bytes.
    const raw = atob(payload);
    const nonce = Uint8Array.from(raw.slice(1, 33), c => c.charCodeAt(0));
    if (nip44.v2.encrypt(plaintext, conversationKey, nonce) !== payload) throw new VaultError('CRYPTO');
    return plaintext;
  } catch { throw new VaultError('CRYPTO'); }
}
