import { getEventHash } from 'nostr-tools';
import {
  assertUint64, bytes32, bytesToHex, equalBytes, hex32, hexToBytes, safeNumber,
} from './crypto';
import { VaultError } from './errors';
import {
  INT64_MAX, VAULT_GRANT_KIND, VAULT_GRANT_MAX_JSON, VAULT_MAX_EPOCHS,
  VAULT_MAX_HINTS, VAULT_MAX_URL,
} from './protocol';
import { StrictJsonReader } from './strict-json';
import type { Address, EpochKey, GrantRumor, KeyRing, NodeId, Pubkey, VaultGrant, VaultId } from './types';

/** libvault/ring.c validation; primitive PCS selection deliberately differs. */
export function validateKeyRing(ring: KeyRing): void {
  if (!ring.entries.length) throw new VaultError('ARG');
  if (ring.entries.length > VAULT_MAX_EPOCHS) throw new VaultError('TOO_LARGE');
  let previous = 0n;
  for (let i = 0; i < ring.entries.length; i++) {
    const entry = ring.entries[i];
    assertUint64(entry.epoch, true);
    if (entry.epoch <= previous || !(entry.nodeKey instanceof Uint8Array) || entry.nodeKey.length !== 32)
      throw new VaultError('ARG');
    previous = entry.epoch;
    for (let j = 0; j < i; j++)
      if (equalBytes(entry.nodeKey, ring.entries[j].nodeKey)) throw new VaultError('ARG');
  }
}

/** Protocol hints only. Public/secure endpoint approval belongs to the I/O layer. */
export function validateHintUrl(url: string, relay: boolean): void {
  if (typeof url !== 'string' || !url.length || url.length > VAULT_MAX_URL || /[^\x21-\x7e]|["\\]/.test(url))
    throw new VaultError('ARG');
  const prefixes = relay ? ['wss://', 'ws://'] : ['https://', 'http://'];
  const prefix = prefixes.find(p => url.startsWith(p));
  if (!prefix || url.length === prefix.length || url[prefix.length] === '/') throw new VaultError('ARG');
}

export function validateGrant(grant: VaultGrant): void {
  hex32<VaultId>(grant.vaultId); hex32<NodeId>(grant.nodeId);
  hex32<Pubkey>(grant.owner); hex32<Address>(grant.rootManifest);
  assertUint64(grant.issuedAt);
  if (grant.issuedAt > INT64_MAX || (grant.cap !== 'read' && grant.cap !== 'write')) throw new VaultError('ARG');
  validateKeyRing(grant.ring);
  for (const [urls, relay] of [[grant.hints.relays, true], [grant.hints.blossom, false]] as const) {
    if (urls.length > VAULT_MAX_HINTS) throw new VaultError('ARG');
    for (const url of urls) validateHintUrl(url, relay);
  }
}

export function encodeGrant(grant: VaultGrant): string {
  validateGrant(grant);
  let json = '';
  function append(text: string): void {
    if (text.length > VAULT_GRANT_MAX_JSON - json.length) throw new VaultError('TOO_LARGE');
    json += text;
  }
  append(`{"vault_id":"${grant.vaultId}","node_id":"${grant.nodeId}","ring":[`);
  grant.ring.entries.forEach((entry, i) => {
    append(`${i ? ',' : ''}{"epoch":${entry.epoch},"node_key":"${bytesToHex(entry.nodeKey)}"}`);
  });
  append(`],"cap":"${grant.cap}","owner":"${grant.owner}","root_manifest":"${grant.rootManifest}","hints":{"relays":[`);
  grant.hints.relays.forEach((url, i) => append(`${i ? ',' : ''}"${url}"`));
  append('],"blossom":[');
  grant.hints.blossom.forEach((url, i) => append(`${i ? ',' : ''}"${url}"`));
  append(`]},"issued_at":${grant.issuedAt}}`);
  return json;
}

function readEpoch(r: StrictJsonReader): EpochKey {
  let epoch!: bigint, nodeKey!: EpochKey['nodeKey'];
  r.object({
    epoch: () => { epoch = r.uint(); },
    node_key: () => { nodeKey = bytes32(hexToBytes(r.hex())); },
  });
  return { epoch, nodeKey };
}

function readUrls(r: StrictJsonReader, relay: boolean): string[] {
  return r.array(VAULT_MAX_HINTS, () => {
    const url = r.string(VAULT_MAX_URL);
    validateHintUrl(url, relay);
    return url;
  });
}

export function decodeGrant(json: string | Uint8Array): VaultGrant {
  const r = new StrictJsonReader(json, VAULT_GRANT_MAX_JSON);
  let vaultId!: VaultId, nodeId!: NodeId, owner!: Pubkey, rootManifest!: Address;
  let ring!: KeyRing, cap!: VaultGrant['cap'], relays!: string[], blossom!: string[], issuedAt!: bigint;
  r.object({
    vault_id: () => { vaultId = hex32<VaultId>(r.hex()); },
    node_id: () => { nodeId = hex32<NodeId>(r.hex()); },
    ring: () => { ring = { entries: r.array(VAULT_MAX_EPOCHS, () => readEpoch(r), true) }; },
    cap: () => {
      const value = r.string(7);
      if (value !== 'read' && value !== 'write') throw new VaultError('ARG');
      cap = value;
    },
    owner: () => { owner = hex32<Pubkey>(r.hex()); },
    root_manifest: () => { rootManifest = hex32<Address>(r.hex()); },
    hints: () => {
      r.object({ relays: () => { relays = readUrls(r, true); }, blossom: () => { blossom = readUrls(r, false); } });
    },
    issued_at: () => { issuedAt = r.uint(); },
  });
  r.end();
  const grant: VaultGrant = { vaultId, nodeId, ring, cap, owner, rootManifest, hints: { relays, blossom }, issuedAt };
  validateGrant(grant);
  return grant;
}

/** An unsigned kind-30804 rumor with a canonical id; never publish it bare. */
export function buildGrantRumor(grant: VaultGrant): GrantRumor {
  const content = encodeGrant(grant);
  const event = {
    kind: VAULT_GRANT_KIND, pubkey: grant.owner, created_at: safeNumber(grant.issuedAt), tags: [], content,
  };
  return { ...event, id: getEventHash(event) };
}

export function openGrantRumor(event: GrantRumor): VaultGrant {
  if (event.kind !== VAULT_GRANT_KIND || (event.sig !== undefined && event.sig !== '') ||
      !Array.isArray(event.tags) || event.tags.length || typeof event.content !== 'string' || !event.content ||
      event.content.length > VAULT_GRANT_MAX_JSON || !Number.isSafeInteger(event.created_at) || event.created_at < 0)
    throw new VaultError('AUTH');
  try {
    if (getEventHash(event) !== event.id) throw new VaultError('AUTH');
  } catch { throw new VaultError('AUTH'); }
  const grant = decodeGrant(event.content);
  if (event.pubkey !== grant.owner || BigInt(event.created_at) !== grant.issuedAt) throw new VaultError('AUTH');
  return grant;
}
