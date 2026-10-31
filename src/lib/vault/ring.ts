import { assertUint64, bytes32, deriveChildNodeKey, equalBytes, selectEpochKey } from './crypto';
import { VaultError } from './errors';
import { validateKeyRing } from './grant';
import { UINT64_MAX, VAULT_MAX_EPOCHS } from './protocol';
import type { Bytes32, EpochKey, KeyRing, NodeEntry } from './types';

// P2 already exposes the pinned ring.c validator at the grant boundary.
export { validateKeyRing, selectEpochKey };

export function copyRing(ring: KeyRing): KeyRing {
  validateKeyRing(ring);
  return { entries: ring.entries.map(e => ({ epoch: e.epoch, nodeKey: bytes32(e.nodeKey) })) };
}

export function initRing(epoch: bigint, nodeKey: Uint8Array): KeyRing {
  assertUint64(epoch, true);
  return { entries: [{ epoch, nodeKey: bytes32(nodeKey) }] };
}

export function latestEpochKey(ring: KeyRing): EpochKey {
  validateKeyRing(ring);
  const last = ring.entries[ring.entries.length - 1];
  return { epoch: last.epoch, nodeKey: bytes32(last.nodeKey) };
}

export function appendRing(ring: KeyRing, nodeKey: Uint8Array): KeyRing {
  validateKeyRing(ring);
  const epoch = ring.entries[ring.entries.length - 1].epoch;
  if (epoch === UINT64_MAX || ring.entries.length === VAULT_MAX_EPOCHS) throw new VaultError('TOO_LARGE');
  const key = bytes32(nodeKey);
  if (ring.entries.some(e => equalBytes(e.nodeKey, key))) throw new VaultError('ARG');
  return { entries: [...copyRing(ring).entries, { epoch: epoch + 1n, nodeKey: key }] };
}

/** Explicit only: neither revoke nor re-seal drops historical keys. */
export function dropRingBefore(ring: KeyRing, epoch: bigint): KeyRing {
  validateKeyRing(ring);
  const at = ring.entries.findIndex(e => e.epoch === epoch);
  if (at < 0) throw new VaultError('EPOCH');
  return copyRing({ entries: ring.entries.slice(at) });
}

/** Grant updates may add history, but may never replace a known epoch's key. */
export function mergeRings(held: KeyRing, received: KeyRing): KeyRing {
  validateKeyRing(held); validateKeyRing(received);
  const entries = new Map<bigint, EpochKey>();
  for (const e of [...held.entries, ...received.entries]) {
    const previous = entries.get(e.epoch);
    if (previous && !equalBytes(previous.nodeKey, e.nodeKey)) throw new VaultError('EPOCH');
    entries.set(e.epoch, e);
  }
  return copyRing({ entries: [...entries.values()].sort((a, b) => a.epoch < b.epoch ? -1 : 1) });
}

/** fetch.c:selected_ring: keep held history <= epoch, then install the authenticated
 * current key. Unlike grant merging, a directory override is authoritative here. */
export function selectedRing(held: KeyRing | undefined, epoch: bigint, nodeKey: Uint8Array): KeyRing {
  assertUint64(epoch, true);
  if (held) validateKeyRing(held);
  return copyRing({ entries: [
    ...(held?.entries.filter(e => e.epoch < epoch) ?? []),
    { epoch, nodeKey: bytes32(nodeKey) },
  ] });
}

/** No trials and no invented old keys. Root history does not encode independently
 * rotated descendant history. Only the current override/held key/derivation is used. */
export function resolveChildRing(parent: KeyRing, parentEpoch: bigint,
  entry: Extract<NodeEntry, { kind: 'directory' }>, held?: KeyRing): KeyRing {
  validateKeyRing(parent);
  if (held) validateKeyRing(held);
  const parentKey = selectEpochKey(parent, parentEpoch);
  let current: Bytes32 | undefined;
  try {
    const known = held?.entries.find(e => e.epoch === entry.childEpoch);
    current = entry.keyOverride !== undefined ? bytes32(entry.keyOverride)
      : known ? bytes32(known.nodeKey) : deriveChildNodeKey(parentKey, entry.childNodeId);
    return selectedRing(held, entry.childEpoch, current);
  } finally { parentKey.fill(0); current?.fill(0); }
}
