import type { Event as NostrEvent } from 'nostr-tools';
import { encodeUtf8, hashAddress, hex32, selectEpochKey, verifyAddress } from './crypto';
import { encodeDirectoryNode, openDirectoryNode } from './dir-node';
import { VaultError } from './errors';
import { encodeHead, openHeadEvent } from './head';
import {
  PORTHOME_MAX_CBOR_BYTES, PORTHOME_MAX_ENTRIES, PORTHOME_MAX_PATH_LEN, PORTHOME_SEAL_OVERHEAD,
  VAULT_MAX_MANIFEST_RECEPTION_BYTES, VAULT_MAX_OBJECTS,
} from './protocol';
import { copyRing, resolveChildRing, selectedRing } from './ring';
import { createTree } from './tree';
import type {
  DirectoryNode, EntryDigest, EventId, HeadHash, KeyRing, ManifestObject, NodeEntry, NodeId,
  Pubkey, RecordId, RecordPath, VaultBlobIO, VaultGrant, VaultId, VaultTree, VerifiedRecord, Address,
} from './types';

const zeroNodeId = hex32<NodeId>('00'.repeat(32));

/** snapshot.c:path_add: only the synthetic node metadata is zeroed; the entire
 * entry (including basename, directory address/override and file metadata) stays. */
export function entryDigest(entry: NodeEntry): EntryDigest {
  const bytes = encodeDirectoryNode({ version: 2, nodeId: zeroNodeId, epoch: 1n, entries: [entry] });
  try { return hex32<EntryDigest>(hashAddress(bytes)); }
  finally { bytes.fill(0); }
}

export function recordId(record: VerifiedRecord): RecordId {
  return hex32<RecordId>(record.eventId);
}

function ownEvent(event: NostrEvent): NostrEvent {
  return { id: event.id, sig: event.sig, pubkey: event.pubkey, kind: event.kind,
    created_at: event.created_at, content: event.content, tags: event.tags.map(tag => [...tag]) };
}

/** snapshot.c:vault_record_open. Supplied unrelated inventory is allowed, but
 * repeated reachable objects are not. No chunks or parent heads are fetched. */
export function openRecord(event: NostrEvent, vaultId: VaultId, rootRing: KeyRing, epoch: bigint,
  objects: readonly ManifestObject[], expectedRoot?: { readonly nodeId?: NodeId; readonly owner?: Pubkey }): VerifiedRecord {
  if (objects.length > VAULT_MAX_OBJECTS) throw new VaultError('TOO_LARGE');
  const head = openHeadEvent(event, vaultId, rootRing, epoch);
  const signedEvent = ownEvent(event);
  if (!objects.length) throw new VaultError('INCOMPLETE');
  // Hash the complete inventory before opening any manifest. Inventory lookup is
  // by computed address, never by a caller's claim about the bytes.
  const inventory = new Map<Address, ManifestObject>();
  for (const object of objects) {
    if (!(object.sealed instanceof Uint8Array) || object.sealed.length > PORTHOME_MAX_CBOR_BYTES + PORTHOME_SEAL_OVERHEAD)
      throw new VaultError('ARG');
    const address = hashAddress(object.sealed);
    if (object.address !== undefined && object.address !== address) throw new VaultError('HASH_MISMATCH');
    if (inventory.has(address)) throw new VaultError('ARG');
    inventory.set(address, object);
  }
  const seen = new Set<Address>();
  const nodesById = new Map<NodeId, DirectoryNode>();
  const paths: RecordPath[] = [];
  function walk(address: Address, nodeId: NodeId | undefined, selectedEpoch: bigint,
    ring: KeyRing | undefined, prefix: string, depth: number): DirectoryNode {
    if (depth > 128) throw new VaultError('TOO_LARGE');
    const object = inventory.get(address);
    if (!object) throw new VaultError('INCOMPLETE');
    if (seen.has(address)) throw new VaultError('CONFLICT');
    seen.add(address);
    if (object.epoch !== selectedEpoch) throw new VaultError('EPOCH');
    const node = openDirectoryNode(ring ?? object.ring, selectedEpoch, object.sealed);
    if (nodeId !== undefined && node.nodeId !== nodeId) throw new VaultError('ARG');
    // fetch.c and tree.c reject repeated node IDs; a Map must not hide one.
    if (nodesById.has(node.nodeId)) throw new VaultError('CONFLICT');
    nodesById.set(node.nodeId, node);
    for (let i = 0; i < node.entries.length; i++) {
      const entry = node.entries[i];
      const pathEnc = prefix ? `${prefix}/${entry.nameEnc}` : entry.nameEnc;
      if (pathEnc.length > PORTHOME_MAX_PATH_LEN || paths.length === PORTHOME_MAX_ENTRIES)
        throw new VaultError('TOO_LARGE');
      paths.push({ pathEnc, entryDigest: entryDigest(entry), nodeId: node.nodeId, entryIndex: i });
      if (entry.kind === 'directory') walk(entry.manifestAddress, entry.childNodeId, entry.childEpoch, undefined, pathEnc, depth + 1);
    }
    return node;
  }
  const root = walk(head.rootManifest, expectedRoot?.nodeId, epoch, rootRing, '', 0);
  if (!root.vault || root.vault.vaultId !== vaultId || root.vault.grantsRev !== head.grantsRev ||
      (expectedRoot?.owner !== undefined && root.vault.owner !== expectedRoot.owner)) throw new VaultError('ARG');
  paths.sort((a, b) => a.pathEnc < b.pathEnc ? -1 : a.pathEnc > b.pathEnc ? 1 : 0);
  return { eventId: hex32<EventId>(signedEvent.id), signedEvent, writer: hex32<Pubkey>(signedEvent.pubkey),
    head, canonicalHeadHash: hex32<HeadHash>(hashAddress(encodeUtf8(encodeHead(head)))), root, nodesById, paths };
}

/** Merge the already sorted digest tables; never inspect file bytes. */
export function* differingPaths(left: readonly RecordPath[], right: readonly RecordPath[]): Generator<{ pathEnc: string; inLeft: boolean; inRight: boolean }> {
  let a = 0, b = 0;
  while (a < left.length || b < right.length) {
    const x = left[a], y = right[b];
    const c = !x ? 1 : !y ? -1 : x.pathEnc < y.pathEnc ? -1 : x.pathEnc > y.pathEnc ? 1 : 0;
    if (c === 0) {
      if (x.entryDigest !== y.entryDigest) yield { pathEnc: x.pathEnc, inLeft: true, inRight: true };
      a++; b++;
    } else if (c < 0) { yield { pathEnc: x.pathEnc, inLeft: true, inRight: false }; a++; }
    else { yield { pathEnc: y.pathEnc, inLeft: false, inRight: true }; b++; }
  }
}

export type HeldNodeRings = (nodeId: NodeId, epoch: bigint) => KeyRing | undefined;

/** fetch.c addressed walk. Held exact history is optional, NOT reconstructed
 * from a root grant. EPOCH/INCOMPLETE from the held lookup means no held history. */
export async function fetchRecord(event: NostrEvent, grant: Pick<VaultGrant, 'vaultId' | 'nodeId' | 'owner'>,
  rootRing: KeyRing, epoch: bigint, io: Pick<VaultBlobIO, 'read'>, held?: HeldNodeRings): Promise<{ record: VerifiedRecord; tree: VaultTree }> {
  const head = openHeadEvent(event, grant.vaultId, rootRing, epoch);
  const signedEvent = ownEvent(event);
  const key = selectEpochKey(rootRing, epoch);
  let root: KeyRing;
  try { root = selectedRing(rootRing, epoch, key); }
  finally { key.fill(0); }
  const objects: ManifestObject[] = [];
  const nodes: { node: DirectoryNode; ring: KeyRing }[] = [];
  const addresses = new Set<Address>(), ids = new Set<NodeId>();
  let total = 0;
  async function fetch(address: Address, id: NodeId, selectedEpoch: bigint, ring: KeyRing, depth: number): Promise<void> {
    if (depth > 128 || objects.length === VAULT_MAX_OBJECTS) throw new VaultError('TOO_LARGE');
    if (addresses.has(address) || ids.has(id)) throw new VaultError('CONFLICT');
    addresses.add(address); ids.add(id);
    const received = await io.read(address);
    if (!(received instanceof Uint8Array)) throw new VaultError('IO');
    const sealed = received.slice();
    if (sealed.length > PORTHOME_MAX_CBOR_BYTES + PORTHOME_SEAL_OVERHEAD ||
        sealed.length > VAULT_MAX_MANIFEST_RECEPTION_BYTES - total) throw new VaultError('TOO_LARGE');
    total += sealed.length;
    verifyAddress(sealed, address);
    const node = openDirectoryNode(ring, selectedEpoch, sealed);
    if (node.nodeId !== id) throw new VaultError('ARG');
    objects.push({ sealed, address, epoch: selectedEpoch, ring: copyRing(ring) });
    nodes.push({ node, ring });
    for (const entry of node.entries) if (entry.kind === 'directory') {
      let history: KeyRing | undefined;
      try { history = held?.(entry.childNodeId, entry.childEpoch); }
      catch (error) {
        if (!(error instanceof VaultError) || !['EPOCH', 'INCOMPLETE'].includes(error.code)) throw error;
      }
      const childRing = resolveChildRing(ring, selectedEpoch, entry, history);
      await fetch(entry.manifestAddress, entry.childNodeId, entry.childEpoch, childRing, depth + 1);
    }
  }
  await fetch(head.rootManifest, grant.nodeId, epoch, root, 0);
  const record = openRecord(signedEvent, grant.vaultId, root, epoch, objects, { nodeId: grant.nodeId, owner: grant.owner });
  return { record, tree: createTree(nodes) };
}
