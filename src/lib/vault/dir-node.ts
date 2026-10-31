import { CborReader, CborWriter } from './cbor';
import {
  assertUint64, bytes32, bytesToHex, encodeUtf8, hex32, hexToBytes, nameEnc,
  openManifest, sealManifest, validateBasename,
} from './crypto';
import type { SealedObject } from './crypto';
import { VaultError } from './errors';
import {
  PORTHOME_DIR_NODE_VERSION, PORTHOME_MAX_CBOR_BYTES, PORTHOME_MAX_ENTRIES,
  PORTHOME_MAX_SYMLINK_LEN, PORTHOME_NODE_MAX_CHUNKS, PORTHOME_SEAL_OVERHEAD,
  PORTHOME_VAULT_MAX_MEMBERS, PORTHOME_NAME_HEX_CHARS, PORTHOME_NAME_PLAIN_MAX_BYTES,
  UINT32_MAX, UINT64_MAX,
} from './protocol';
import type { Address, ChunkRef, DirectoryNode, EntryMeta, KeyRing, NodeEntry, NodeId, Pubkey, VaultId, VaultPolicy } from './types';

function limit(length: number, max: number): void {
  if (length > max) throw new VaultError('TOO_LARGE');
}

function absent(entry: NodeEntry, fields: readonly string[]): void {
  if (fields.some(field => field in entry)) throw new VaultError('ARG');
}

export function validateSymlinkTarget(target: string): void {
  const size = encodeUtf8(target).length;
  if (!size || size > PORTHOME_MAX_SYMLINK_LEN || /[\\\0]/.test(target) ||
      target.split('/').some(part => !part || part === '.' || part === '..'))
    throw new VaultError('ARG');
}

export function validateDirectoryNode(node: DirectoryNode): void {
  if (node.version !== PORTHOME_DIR_NODE_VERSION) throw new VaultError('VERSION');
  hex32<NodeId>(node.nodeId);
  assertUint64(node.epoch, true);
  limit(node.entries.length, PORTHOME_MAX_ENTRIES);
  if (node.vault) {
    const v = node.vault;
    hex32<VaultId>(v.vaultId); hex32<Pubkey>(v.owner); assertUint64(v.grantsRev);
    for (const members of [v.writers, v.readers]) {
      limit(members.length, PORTHOME_VAULT_MAX_MEMBERS);
      for (const member of members) hex32<Pubkey>(member);
    }
  }
  const indexes = new Set<string>(), names = new Set<string>();
  for (const entry of node.entries) {
    nameEnc(entry.nameEnc); validateBasename(entry.namePlain);
    if (indexes.has(entry.nameEnc) || names.has(entry.namePlain)) throw new VaultError('ARG');
    indexes.add(entry.nameEnc); names.add(entry.namePlain);
    if (!Number.isInteger(entry.mode) || entry.mode < 0 || entry.mode > UINT32_MAX) throw new VaultError('ARG');
    assertUint64(entry.mtimeNs); assertUint64(entry.sizePlain);
    if (entry.kind === 'file') {
      absent(entry, ['target', 'childNodeId', 'childEpoch', 'manifestAddress', 'keyOverride']);
      limit(entry.chunks.length, PORTHOME_NODE_MAX_CHUNKS);
      let total = 0n;
      for (const chunk of entry.chunks) {
        hex32<Address>(chunk.address);
        assertUint64(chunk.chunkKeyId, true); assertUint64(chunk.sizeSealed); assertUint64(chunk.sizePlain);
        if (chunk.sizeSealed < BigInt(PORTHOME_SEAL_OVERHEAD) || total > UINT64_MAX - chunk.sizePlain)
          throw new VaultError('ARG');
        total += chunk.sizePlain;
      }
      if (total !== entry.sizePlain) throw new VaultError('ARG');
    } else if (entry.kind === 'directory') {
      absent(entry, ['chunks', 'target']);
      if (entry.sizePlain !== 0n) throw new VaultError('ARG');
      hex32<NodeId>(entry.childNodeId); hex32<Address>(entry.manifestAddress);
      assertUint64(entry.childEpoch, true);
      if (entry.keyOverride !== undefined && (!(entry.keyOverride instanceof Uint8Array) || entry.keyOverride.length !== 32))
        throw new VaultError('ARG');
    } else if (entry.kind === 'symlink') {
      absent(entry, ['chunks', 'childNodeId', 'childEpoch', 'manifestAddress', 'keyOverride']);
      if (entry.sizePlain !== 0n) throw new VaultError('ARG');
      validateSymlinkTarget(entry.target);
    } else throw new VaultError('ARG');
  }
}

export function encodeDirectoryNode(node: DirectoryNode): Uint8Array {
  validateDirectoryNode(node);
  const w = new CborWriter();
  try {
    w.map(node.vault ? 5 : 4).uint(0n).uint(BigInt(PORTHOME_DIR_NODE_VERSION));
    w.uint(1n).bytes(hexToBytes(node.nodeId)).uint(2n).uint(node.epoch);
    w.uint(3n).array(node.entries.length);
    for (const entry of node.entries) {
      const kind = entry.kind === 'file' ? 1n : entry.kind === 'directory' ? 2n : 3n;
      w.map(7).uint(0n).text(entry.nameEnc).uint(1n).uint(kind);
      w.uint(2n).uint(BigInt(entry.mode)).uint(3n).uint(entry.mtimeNs).uint(4n).uint(entry.sizePlain).uint(5n);
      if (entry.kind === 'directory') {
        w.map(entry.keyOverride === undefined ? 3 : 4).uint(0n).bytes(hexToBytes(entry.childNodeId));
        w.uint(1n).uint(entry.childEpoch).uint(2n).bytes(hexToBytes(entry.manifestAddress));
        if (entry.keyOverride !== undefined) w.uint(3n).bytes(entry.keyOverride);
      } else if (entry.kind === 'file') {
        w.array(entry.chunks.length);
        for (const chunk of entry.chunks) {
          w.map(4).uint(0n).bytes(hexToBytes(chunk.address)).uint(1n).uint(chunk.sizeSealed);
          w.uint(2n).uint(chunk.chunkKeyId).uint(3n).uint(chunk.sizePlain);
        }
      } else w.text(entry.target);
      w.uint(6n).text(entry.namePlain);
    }
    if (node.vault) {
      const v = node.vault;
      w.uint(4n).map(5).uint(0n).bytes(hexToBytes(v.vaultId)).uint(1n).bytes(hexToBytes(v.owner));
      w.uint(2n).array(v.writers.length);
      for (const member of v.writers) w.bytes(hexToBytes(member));
      w.uint(3n).array(v.readers.length);
      for (const member of v.readers) w.bytes(hexToBytes(member));
      w.uint(4n).uint(v.grantsRev);
    }
    return w.finish();
  } finally { w.dispose(); }
}

function map(r: CborReader, allowed: readonly number[]): number {
  const size = r.map(Math.max(...allowed));
  if (!allowed.includes(size)) throw new VaultError('ARG');
  return size;
}

function readHex(r: CborReader): string { return bytesToHex(r.bytes(32)); }

function readMembers(r: CborReader): Pubkey[] {
  const count = r.array(PORTHOME_VAULT_MAX_MEMBERS, 34);
  const result: Pubkey[] = [];
  for (let i = 0; i < count; i++) result.push(hex32<Pubkey>(readHex(r)));
  return result;
}

function readVault(r: CborReader): VaultPolicy {
  map(r, [5]);
  r.key(0); const vaultId = hex32<VaultId>(readHex(r));
  r.key(1); const owner = hex32<Pubkey>(readHex(r));
  r.key(2); const writers = readMembers(r);
  r.key(3); const readers = readMembers(r);
  r.key(4); const grantsRev = r.uint();
  return { vaultId, owner, writers, readers, grantsRev };
}

function readEntry(r: CborReader): NodeEntry {
  map(r, [7]);
  r.key(0); const index = nameEnc(r.text(PORTHOME_NAME_HEX_CHARS));
  r.key(1); const kind = r.uint();
  if (kind < 1n || kind > 3n) throw new VaultError('ARG');
  r.key(2); const mode = r.uint();
  if (mode > BigInt(UINT32_MAX)) throw new VaultError('ARG');
  r.key(3); const mtimeNs = r.uint();
  r.key(4); const sizePlain = r.uint();
  r.key(5);
  let payload: Omit<Extract<NodeEntry, { kind: 'directory' }>, keyof EntryMeta>
    | { kind: 'file'; chunks: ChunkRef[] } | { kind: 'symlink'; target: string };
  if (kind === 2n) {
    const count = map(r, [3, 4]);
    r.key(0); const childNodeId = hex32<NodeId>(readHex(r));
    r.key(1); const childEpoch = r.uint();
    r.key(2); const manifestAddress = hex32<Address>(readHex(r));
    let keyOverride;
    if (count === 4) { r.key(3); keyOverride = bytes32(r.bytes(32)); }
    payload = { kind: 'directory', childNodeId, childEpoch, manifestAddress, ...(keyOverride === undefined ? {} : { keyOverride }) };
  } else if (kind === 1n) {
    const count = r.array(PORTHOME_NODE_MAX_CHUNKS, 40);
    const chunks: ChunkRef[] = [];
    for (let i = 0; i < count; i++) {
      map(r, [4]);
      r.key(0); const address = hex32<Address>(readHex(r));
      r.key(1); const sizeSealed = r.uint();
      r.key(2); const chunkKeyId = r.uint();
      r.key(3); const sizePlain = r.uint();
      chunks.push({ address, sizeSealed, chunkKeyId, sizePlain });
    }
    payload = { kind: 'file', chunks };
  } else payload = { kind: 'symlink', target: r.text(PORTHOME_MAX_SYMLINK_LEN) };
  r.key(6); const namePlain = r.text(PORTHOME_NAME_PLAIN_MAX_BYTES);
  return { nameEnc: index, namePlain, mode: Number(mode), mtimeNs, sizePlain, ...payload };
}

export function decodeDirectoryNode(cbor: Uint8Array): DirectoryNode {
  const r = new CborReader(cbor);
  const count = map(r, [4, 5]);
  r.key(0);
  if (r.uint() !== BigInt(PORTHOME_DIR_NODE_VERSION)) throw new VaultError('VERSION');
  r.key(1); const nodeId = hex32<NodeId>(readHex(r));
  r.key(2); const epoch = r.uint();
  r.key(3); const entriesLength = r.array(PORTHOME_MAX_ENTRIES, 48);
  const entries: NodeEntry[] = [];
  for (let i = 0; i < entriesLength; i++) entries.push(readEntry(r));
  let vault;
  if (count === 5) { r.key(4); vault = readVault(r); }
  r.end();
  const node: DirectoryNode = { version: PORTHOME_DIR_NODE_VERSION, nodeId, epoch, entries, ...(vault ? { vault } : {}) };
  validateDirectoryNode(node);
  return node;
}

export function sealDirectoryNode(node: DirectoryNode, nodeKey: Uint8Array): SealedObject {
  const cbor = encodeDirectoryNode(node);
  try { return sealManifest(nodeKey, cbor); }
  finally { cbor.fill(0); }
}

export function openDirectoryNode(ring: KeyRing, epoch: bigint, sealed: Uint8Array): DirectoryNode {
  if (sealed.length > PORTHOME_MAX_CBOR_BYTES + PORTHOME_SEAL_OVERHEAD) throw new VaultError('TOO_LARGE');
  const cbor = openManifest(ring, epoch, sealed);
  try {
    const node = decodeDirectoryNode(cbor);
    if (node.epoch !== epoch) throw new VaultError('EPOCH');
    return node;
  } finally { cbor.fill(0); }
}
