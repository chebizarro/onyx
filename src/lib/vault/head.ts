import { getEventHash, verifyEvent } from 'nostr-tools';
import type { Event as NostrEvent, UnsignedEvent } from 'nostr-tools';
import {
  assertUint64, bytes32, bytesToHex, decryptNip44, deriveHeadConversationKey,
  encryptNip44, encodeUtf8, equalBytes, hex32, hexToBytes, safeNumber, selectEpochKey,
} from './crypto';
import { VaultError } from './errors';
import {
  INT64_MAX, PORTHOME_HEAD_D_PREFIX, PORTHOME_HEAD_KIND, PORTHOME_HEAD_MAX_JSON,
  PORTHOME_HEAD_MAX_PARENTS, PORTHOME_HEAD_MAX_PAYLOAD,
} from './protocol';
import { StrictJsonReader } from './strict-json';
import type { Address, Bytes32, HeadParent, KeyRing, Pubkey, RefState, VaultHead, VaultId } from './types';

export function validateHead(head: VaultHead): void {
  hex32<VaultId>(head.vaultId); hex32<Address>(head.rootManifest);
  assertUint64(head.epoch, true); assertUint64(head.seq); assertUint64(head.grantsRev); assertUint64(head.writtenAt);
  if (head.writtenAt > INT64_MAX) throw new VaultError('ARG');
  if (head.refState !== undefined) hex32<RefState>(head.refState);
  if (head.keyOverride !== undefined && (!(head.keyOverride instanceof Uint8Array) || head.keyOverride.length !== 32))
    throw new VaultError('ARG');
  if (head.parents.length > PORTHOME_HEAD_MAX_PARENTS) throw new VaultError('TOO_LARGE');
  for (const p of head.parents) {
    hex32<Pubkey>(p.writer); hex32<Address>(p.rootManifest); assertUint64(p.seq);
  }
}

export function encodeHead(head: VaultHead): string {
  validateHead(head);
  let json = `{"vault_id":"${head.vaultId}","epoch":${head.epoch},"root_manifest":"${head.rootManifest}"`;
  if (head.refState !== undefined) json += `,"ref_state":"${head.refState}"`;
  if (head.keyOverride !== undefined) json += `,"key_override":"${bytesToHex(head.keyOverride)}"`;
  json += `,"seq":${head.seq},"parents":[`;
  json += head.parents.map(p => `{"writer":"${p.writer}","seq":${p.seq},"root_manifest":"${p.rootManifest}"}`).join(',');
  json += `],"grants_rev":${head.grantsRev},"written_at":${head.writtenAt}}`;
  if (json.length > PORTHOME_HEAD_MAX_JSON) throw new VaultError('TOO_LARGE');
  return json;
}

function readParent(r: StrictJsonReader): HeadParent {
  let writer!: Pubkey, seq!: bigint, rootManifest!: Address;
  r.object({
    writer: () => { writer = hex32<Pubkey>(r.hex()); },
    seq: () => { seq = r.uint(); },
    root_manifest: () => { rootManifest = hex32<Address>(r.hex()); },
  });
  return { writer, seq, rootManifest };
}

export function decodeHead(json: string | Uint8Array): VaultHead {
  const r = new StrictJsonReader(json, PORTHOME_HEAD_MAX_JSON);
  let vaultId!: VaultId, epoch!: bigint, rootManifest!: Address, seq!: bigint;
  let grantsRev!: bigint, writtenAt!: bigint, parents!: HeadParent[];
  let refState: RefState | undefined, keyOverride: Bytes32 | undefined;
  r.object({
    vault_id: () => { vaultId = hex32<VaultId>(r.hex()); },
    epoch: () => { epoch = r.uint(); },
    root_manifest: () => { rootManifest = hex32<Address>(r.hex()); },
    ref_state: () => { refState = hex32<RefState>(r.hex()); },
    key_override: () => { keyOverride = bytes32(hexToBytes(r.hex())); },
    seq: () => { seq = r.uint(); },
    parents: () => { parents = r.array(PORTHOME_HEAD_MAX_PARENTS, () => readParent(r)); },
    grants_rev: () => { grantsRev = r.uint(); },
    written_at: () => { writtenAt = r.uint(); },
  }, ['ref_state', 'key_override']);
  r.end();
  const head: VaultHead = {
    vaultId, epoch, rootManifest, seq, parents, grantsRev, writtenAt,
    ...(refState === undefined ? {} : { refState }), ...(keyOverride === undefined ? {} : { keyOverride }),
  };
  validateHead(head);
  return head;
}

export function headDTag(vaultId: VaultId): string {
  return PORTHOME_HEAD_D_PREFIX + hex32<VaultId>(vaultId);
}

export function sealHead(head: VaultHead, nodeKey: Uint8Array, nonce?: Uint8Array): string {
  const json = encodeHead(head);
  if (head.keyOverride !== undefined && !equalBytes(head.keyOverride, nodeKey)) throw new VaultError('ARG');
  const key = deriveHeadConversationKey(nodeKey);
  try { return encryptNip44(json, key, nonce); }
  finally { key.fill(0); }
}

export function openHead(ring: KeyRing, epoch: bigint, payload: string): VaultHead {
  const nodeKey = selectEpochKey(ring, epoch);
  let key: Bytes32 | undefined;
  try {
    if (typeof payload !== 'string') throw new VaultError('ARG');
    if (encodeUtf8(payload).length > PORTHOME_HEAD_MAX_PAYLOAD) throw new VaultError('TOO_LARGE');
    key = deriveHeadConversationKey(nodeKey);
    const head = decodeHead(decryptNip44(payload, key));
    if (head.epoch !== epoch || (head.keyOverride !== undefined && !equalBytes(head.keyOverride, nodeKey)))
      throw new VaultError('EPOCH');
    return head;
  } finally { nodeKey.fill(0); key?.fill(0); }
}

/** No identity secret is needed: the caller signs the returned event. */
export function buildHeadEvent(head: VaultHead, nodeKey: Uint8Array, writer: Pubkey, nonce?: Uint8Array): UnsignedEvent {
  hex32<Pubkey>(writer);
  const created_at = safeNumber(head.writtenAt);
  return {
    kind: PORTHOME_HEAD_KIND, pubkey: writer, created_at,
    tags: [['d', headDTag(head.vaultId)]], content: sealHead(head, nodeKey, nonce),
  };
}

export function openHeadEvent(event: NostrEvent, vaultId: VaultId, ring: KeyRing, epoch: bigint): VaultHead {
  if (event.kind !== PORTHOME_HEAD_KIND || typeof event.content !== 'string' || !event.content ||
      encodeUtf8(event.content).length > PORTHOME_HEAD_MAX_PAYLOAD || !Array.isArray(event.tags)) throw new VaultError('ARG');
  const expected = headDTag(vaultId);
  let found = 0;
  for (const tag of event.tags) {
    if (!Array.isArray(tag)) throw new VaultError('ARG');
    if (tag[0] !== 'd') continue;
    if (++found !== 1 || tag.length !== 2 || tag[1] !== expected) throw new VaultError('ARG');
  }
  if (found !== 1) throw new VaultError('CRYPTO');
  // Do not trust nostr-tools' mutable verifiedSymbol cache on caller-owned events.
  const checked: NostrEvent = {
    kind: event.kind, pubkey: event.pubkey, created_at: event.created_at,
    tags: event.tags.map(tag => [...tag]), content: event.content, id: event.id, sig: event.sig,
  };
  try {
    if (getEventHash(checked) !== checked.id || !verifyEvent(checked)) throw new VaultError('CRYPTO');
  } catch { throw new VaultError('CRYPTO'); }
  const head = openHead(ring, epoch, checked.content);
  if (head.vaultId !== vaultId) throw new VaultError('ARG');
  // Intentionally no created_at == written_at or future-skew check on receive.
  return head;
}
