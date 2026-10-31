import { finalizeEvent, getPublicKey } from 'nostr-tools';
import { bytes32, deriveRootNodeKey, encryptName, hashAddress, hex32, sealChunk } from '../crypto';
import { sealDirectoryNode } from '../dir-node';
import { VaultError } from '../errors';
import { buildHeadEvent } from '../head';
import { openRecord } from '../record';
import { initRing } from '../ring';
import { captureTree, createTree, newOwnerHead, sealTree } from '../tree';
import type {
  Address, ChunkRef, DirectoryNode, HeadParent, KeyRing, ManifestObject, NodeEntry, NodeId,
  Pubkey, VaultBlobIO, VaultGrant, VaultHead, VaultId, VaultPolicy,
} from '../types';

export function cBytes(first: number): Uint8Array { const b = new Uint8Array(32); b[0] = first; return b; }
export const id = (first: number): NodeId => hex32<NodeId>(Array.from(cBytes(first), b => b.toString(16).padStart(2, '0')).join(''));
export const address = (first: number): Address => hex32<Address>(id(first));

export class BlobMemory implements VaultBlobIO {
  readonly blobs = new Map<Address, Uint8Array>();
  readonly reads: Address[] = [];
  readonly puts: Address[] = [];
  failPut = false;
  corrupt = false;
  read(address: Address): Uint8Array {
    this.reads.push(address);
    const blob = this.blobs.get(address);
    if (!blob) throw new VaultError('INCOMPLETE');
    const result = blob.slice();
    if (this.corrupt) result[0] ^= 1;
    return result;
  }
  put(bytes: Uint8Array, address: Address): void {
    if (hashAddress(bytes) !== address) throw new Error('fixture put hash');
    this.puts.push(address);
    this.blobs.set(address, bytes.slice());
    if (this.failPut) throw new Error('durable PUT response lost');
  }
}

export function world() {
  const secrets = [1, 2, 3, 4].map(n => bytes32(cBytes(n)));
  const pub = secrets.map(sk => hex32<Pubkey>(getPublicKey(sk)));
  const key = deriveRootNodeKey(cBytes(7));
  const ring = initRing(1n, key);
  const vaultId = hex32<VaultId>(id(0x44)), nodeId = id(9);
  const policy: VaultPolicy = { vaultId, owner: pub[0], writers: [pub[0], pub[1]], readers: [pub[2]], grantsRev: 8n };
  const io = new BlobMemory();
  const grant: VaultGrant = { vaultId, nodeId, owner: pub[0], ring, cap: 'write', rootManifest: address(0),
    hints: { relays: [], blossom: [] }, issuedAt: 1n };
  return { secrets, pub, key, ring, vaultId, nodeId, policy, grant, io };
}
export type World = ReturnType<typeof world>;

export function fileEntry(key: Uint8Array, name: string, chunks: readonly ChunkRef[], extra: Partial<NodeEntry> = {}): NodeEntry {
  return { kind: 'file', namePlain: name, nameEnc: encryptName(key, name), mode: 0o644, mtimeNs: 0n,
    sizePlain: chunks.reduce((n, c) => n + c.sizePlain, 0n), chunks, ...extra } as NodeEntry;
}
export function chunk(w: World, key: Uint8Array, epoch: bigint, data: Uint8Array | string): ChunkRef {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const sealed = sealChunk(key, bytes);
  w.io.blobs.set(sealed.address, sealed.sealed);
  return { address: sealed.address, sizeSealed: BigInt(sealed.sealed.length), chunkKeyId: epoch, sizePlain: BigInt(bytes.length) };
}
export function signHead(w: World, head: VaultHead, writer = 0, key: Uint8Array = w.key) {
  return finalizeEvent(buildHeadEvent(head, key, w.pub[writer], cBytes(0x42)), w.secrets[writer]);
}

export function makeRecord(w: World, options: {
  writer?: number; seq?: bigint; revision?: bigint; text?: string | null; entries?: readonly NodeEntry[];
  policy?: VaultPolicy; parents?: readonly HeadParent[]; ring?: KeyRing; nodeId?: NodeId; writtenAt?: bigint;
  extraObjects?: readonly ManifestObject[];
} = {}) {
  const ring = options.ring ?? w.ring;
  const latest = ring.entries[ring.entries.length - 1];
  const policy = { ...(options.policy ?? w.policy), grantsRev: options.revision ?? (options.policy ?? w.policy).grantsRev };
  const entries = options.entries ?? (options.text === null ? [] : [fileEntry(latest.nodeKey, 'root-file',
    [chunk(w, latest.nodeKey, latest.epoch, options.text ?? 'base')])]);
  const node: DirectoryNode = { version: 2, nodeId: options.nodeId ?? w.nodeId, epoch: latest.epoch, entries, vault: policy };
  const sealed = sealDirectoryNode(node, latest.nodeKey);
  w.io.blobs.set(sealed.address, sealed.sealed);
  const head: VaultHead = { vaultId: policy.vaultId, epoch: node.epoch, rootManifest: sealed.address,
    seq: options.seq ?? 1n, parents: options.parents ?? [], grantsRev: policy.grantsRev, writtenAt: options.writtenAt ?? 1n };
  const event = signHead(w, head, options.writer ?? 0, latest.nodeKey);
  return openRecord(event, policy.vaultId, ring, node.epoch,
    [{ ...sealed, epoch: node.epoch, ring }, ...(options.extraObjects ?? [])]);
}

export function tuple(record: { writer: Pubkey; head: VaultHead }): HeadParent {
  return { writer: record.writer, seq: record.head.seq, rootManifest: record.head.rootManifest };
}

export async function nestedTree(w: World, override = true) {
  const childKey = override ? bytes32(cBytes(0x55)) : undefined;
  const rootFile = chunk(w, w.key, 1n, new Uint8Array([114, 111, 111, 116, 0, 0, 0]));
  const meta = { mode: 0o755, mtimeNs: 0n };
  const tree = captureTree({ nodeId: w.nodeId, epoch: 1n, vault: w.policy, entries: [
    { ...meta, kind: 'file', namePlain: 'root-file', chunks: [rootFile] },
    { ...meta, kind: 'directory', namePlain: 'directory', ...(childKey ? { keyOverride: childKey } : {}),
      child: { nodeId: id(10), epoch: 1n, entries: [
        { ...meta, kind: 'directory', namePlain: 'grandchild', child: { nodeId: id(11), epoch: 1n, entries: [] } },
      ] } },
  ] }, w.ring);
  const child = tree.nodes[1], key = child.ring.entries[0].nodeKey;
  const childFile = fileEntry(key, 'child-file', [chunk(w, key, 1n, new Uint8Array([99, 104, 105, 108, 100, 0, 0]))]);
  const sealed = await sealTree(createTree(tree.nodes.map((v, i) => i === 1
    ? { ...v, node: { ...v.node, entries: [childFile, ...v.node.entries] } } : v)), w.io);
  const head = newOwnerHead(sealed.tree, null, w.pub[0], sealed.rootManifest, 1n);
  return { ...sealed, head, event: signHead(w, head), rootFile, childFile };
}

export function errorCode(action: () => unknown): string {
  try { action(); }
  catch (error) { if (error instanceof VaultError) return error.code; throw error; }
  throw new Error('Expected a vault refusal');
}
