import { getEventHash, verifyEvent, type Event, type UnsignedEvent } from 'nostr-tools';
import { assertUint64, bytesToHex, decryptNip44, deriveHeadConversationKey, encodeUtf8, encryptNip44, hex32, safeNumber, selectEpochKey } from './crypto';
import { VaultError } from './errors';
import { encodeHead } from './head';
import { validateKeyRing } from './ring';
import { INT64_MAX, ONYX_VAULT_HISTORY_D_PREFIX, ONYX_VAULT_HISTORY_KIND, ONYX_VAULT_HISTORY_MAX_JSON, ONYX_VAULT_HISTORY_VERSION, PORTHOME_HEAD_MAX_PAYLOAD, VAULT_MAX_EPOCHS } from './protocol';
import { StrictJsonReader } from './strict-json';
import type { Address, KeyRing, Pubkey, VaultHead, VaultId } from './types';

export interface EpochLedgerEntry {
  readonly epoch: bigint;
  readonly rootManifest: Address;
  readonly keyOverride: string | null;
  readonly writtenAt: bigint;
}
export interface EpochLedger {
  readonly v: 1;
  readonly vaultId: VaultId;
  readonly epochs: readonly EpochLedgerEntry[];
}
export const historyDTag = (id: VaultId): string => ONYX_VAULT_HISTORY_D_PREFIX + hex32<VaultId>(id);

function validateLedger(ledger: EpochLedger): void {
  if (ledger.v !== ONYX_VAULT_HISTORY_VERSION) throw new VaultError('VERSION');
  hex32<VaultId>(ledger.vaultId);
  if (!ledger.epochs.length || ledger.epochs.length > VAULT_MAX_EPOCHS) throw new VaultError('ARG');
  for (const [i, entry] of ledger.epochs.entries()) {
    assertUint64(entry.epoch, true); assertUint64(entry.writtenAt);
    if (entry.epoch !== BigInt(i + 1) || entry.writtenAt > INT64_MAX) throw new VaultError('EPOCH');
    hex32<Address>(entry.rootManifest);
    if (entry.keyOverride !== null) hex32(entry.keyOverride);
  }
}

export function encodeEpochLedger(ledger: EpochLedger): string {
  validateLedger(ledger);
  const entries = ledger.epochs.map(e => `{"epoch":${e.epoch},"root_manifest":"${e.rootManifest}","key_override":${e.keyOverride === null ? 'null' : `"${e.keyOverride}"`},"written_at":${e.writtenAt}}`);
  const json = `{"v":1,"vault_id":"${ledger.vaultId}","epochs":[${entries.join(',')}]}`;
  if (encodeUtf8(json).length > ONYX_VAULT_HISTORY_MAX_JSON) throw new VaultError('TOO_LARGE', { operation: 'revoke', reason: 'ledger-too-large' });
  return json;
}

export function decodeEpochLedger(json: string | Uint8Array): EpochLedger {
  const r = new StrictJsonReader(json, ONYX_VAULT_HISTORY_MAX_JSON);
  let v!: bigint, vaultId!: VaultId, epochs!: EpochLedgerEntry[];
  r.object({
    v: () => { v = r.uint(); }, vault_id: () => { vaultId = hex32<VaultId>(r.hex()); },
    epochs: () => { epochs = r.array(VAULT_MAX_EPOCHS, () => {
      let epoch!: bigint, rootManifest!: Address, keyOverride!: string | null, writtenAt!: bigint;
      r.object({ epoch: () => { epoch = r.uint(); }, root_manifest: () => { rootManifest = hex32<Address>(r.hex()); },
        key_override: () => { keyOverride = r.nullableHex(); }, written_at: () => { writtenAt = r.uint(); } });
      return { epoch, rootManifest, keyOverride, writtenAt };
    }, true); },
  });
  r.end();
  if (v !== 1n) throw new VaultError('VERSION');
  const ledger: EpochLedger = { v: 1, vaultId, epochs }; validateLedger(ledger); return ledger;
}

/** Owner checkpoints replace only the last checkpoint of an epoch. Never infer a
 * missing epoch from an address, ring key, or a head's parent tuple. */
export function ledgerWithHeads(vaultId: VaultId, previous: EpochLedger | undefined, heads: readonly VaultHead[]): EpochLedger {
  if (previous && previous.vaultId !== vaultId) throw new VaultError('POLICY');
  const epochs = new Map((previous?.epochs ?? []).map(e => [e.epoch, e]));
  const outgoing = previous?.epochs[previous.epochs.length - 1]?.epoch ?? 1n;
  const selected = new Map<bigint, VaultHead>();
  for (const head of heads) {
    if (head.vaultId !== vaultId) throw new VaultError('POLICY');
    if (head.epoch < outgoing) continue; // Completed epochs are frozen, not reselected from cache.
    const old = selected.get(head.epoch);
    if (old?.seq === head.seq && encodeHead(old) !== encodeHead(head)) throw new VaultError('CONFLICT');
    if (!old || head.seq > old.seq) selected.set(head.epoch, head);
  }
  for (const head of selected.values()) epochs.set(head.epoch, { epoch: head.epoch, rootManifest: head.rootManifest,
    keyOverride: head.keyOverride ? bytesToHex(head.keyOverride) : null, writtenAt: head.writtenAt });
  const ledger: EpochLedger = { v: 1, vaultId, epochs: [...epochs.values()].sort((a, b) => a.epoch < b.epoch ? -1 : 1) };
  // Includes the complete proposed plaintext before any publication or rotation intent.
  encodeEpochLedger(ledger); return ledger;
}

export function buildEpochLedgerEvent(ledger: EpochLedger, ring: KeyRing, owner: Pubkey, writtenAt: bigint, nonce?: Uint8Array): UnsignedEvent {
  hex32<Pubkey>(owner);
  const json = encodeEpochLedger(ledger); validateKeyRing(ring);
  const newest = ring.entries[ring.entries.length - 1];
  if (ledger.epochs[ledger.epochs.length - 1].epoch !== newest.epoch) throw new VaultError('EPOCH');
  const key = deriveHeadConversationKey(newest.nodeKey);
  try { return { kind: ONYX_VAULT_HISTORY_KIND, pubkey: owner, created_at: safeNumber(writtenAt),
    tags: [['d', historyDTag(ledger.vaultId)], ['epoch', String(newest.epoch)]], content: encryptNip44(json, key, nonce) }; }
  finally { key.fill(0); }
}

/** The signed public epoch tag selects exactly one key, before decrypting. */
export function openEpochLedgerEvent(event: Event, vaultId: VaultId, owner: Pubkey, ring: KeyRing, decrypt = decryptNip44): EpochLedger {
  if (event.kind !== ONYX_VAULT_HISTORY_KIND || event.pubkey !== owner || typeof event.content !== 'string' ||
    !event.content || encodeUtf8(event.content).length > PORTHOME_HEAD_MAX_PAYLOAD || !Array.isArray(event.tags) ||
    event.tags.some(t => !Array.isArray(t) || t.some(value => typeof value !== 'string'))) throw new VaultError('AUTH');
  const d = event.tags.filter(t => t[0] === 'd'), epochTags = event.tags.filter(t => t[0] === 'epoch');
  if (event.tags.length !== 2 || d.length !== 1 || d[0].length !== 2 || d[0][1] !== historyDTag(vaultId) ||
    epochTags.length !== 1 || epochTags[0].length !== 2 || !/^[1-9][0-9]*$/.test(epochTags[0][1]) || epochTags[0][1].length > 20) throw new VaultError('ARG');
  const checked = { ...event, tags: event.tags.map(t => [...t]) };
  // Strip nostr-tools' mutable verification-cache symbol.
  try { if (getEventHash(checked) !== checked.id || !verifyEvent(JSON.parse(JSON.stringify(checked)))) throw new VaultError('CRYPTO'); }
  catch { throw new VaultError('CRYPTO'); }
  const epoch = BigInt(epochTags[0][1]); assertUint64(epoch, true);
  const nodeKey = selectEpochKey(ring, epoch);
  let key: Uint8Array | undefined;
  try {
    key = deriveHeadConversationKey(nodeKey);
    const ledger = decodeEpochLedger(decrypt(event.content, key));
    if (ledger.vaultId !== vaultId || ledger.epochs[ledger.epochs.length - 1].epoch !== epoch) throw new VaultError('EPOCH');
    for (const entry of ledger.epochs) {
      const selected = selectEpochKey(ring, entry.epoch);
      try { if (entry.keyOverride !== null && entry.keyOverride !== bytesToHex(selected)) throw new VaultError('EPOCH'); }
      finally { selected.fill(0); }
    }
    return ledger;
  } finally { nodeKey.fill(0); key?.fill(0); }
}
