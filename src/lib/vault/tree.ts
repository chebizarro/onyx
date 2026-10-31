import {
  assertUint64, bytes32, deriveChildNodeKey, encodeUtf8, encryptName, equalBytes, hex32,
} from './crypto';
import { decodeDirectoryNode, encodeDirectoryNode, sealDirectoryNode } from './dir-node';
import { VaultError } from './errors';
import { decodeHead, encodeHead } from './head';
import { includeHead } from './parents';
import {
  INT64_MAX, PORTHOME_MAX_ENTRIES, PORTHOME_MAX_PATH_LEN, PORTHOME_SEAL_OVERHEAD,
  PORTHOME_VAULT_MAX_MEMBERS, UINT64_MAX, VAULT_MAX_MANIFEST_RECEPTION_BYTES, VAULT_MAX_OBJECTS,
} from './protocol';
import { appendRing, copyRing, initRing, latestEpochKey } from './ring';
import type {
  Address, Bytes32, ChunkRef, DirectoryNode, EntryMeta, KeyRing, ManifestObject, NodeEntry, NodeId,
  Pubkey, VaultBlobIO, VaultHead, VaultPolicy, VaultTree, VaultTreeNode, VerifiedRecord,
} from './types';

export function cloneNode(node: DirectoryNode): DirectoryNode {
  const cbor = encodeDirectoryNode(node);
  try { return decodeDirectoryNode(cbor); }
  finally { cbor.fill(0); }
}

function validateGraph(tree: VaultTree, publicationLimits: boolean): void {
  if (!tree.nodes.length || !tree.nodes[0].node.vault) throw new VaultError('ARG');
  if (tree.nodes.length > VAULT_MAX_OBJECTS) throw new VaultError('TOO_LARGE');
  if (publicationLimits && tree.nodes.reduce((count, v) => count + v.node.entries.length, 0) > PORTHOME_MAX_ENTRIES)
    throw new VaultError('TOO_LARGE');
  let sealedBytes = 0;
  const byId = new Map<NodeId, VaultTreeNode>();
  for (const item of tree.nodes) {
    const last = latestEpochKey(item.ring);
    try { if (last.epoch !== item.node.epoch) throw new VaultError('EPOCH'); }
    finally { last.nodeKey.fill(0); }
    if (byId.has(item.node.nodeId)) throw new VaultError('CONFLICT');
    byId.set(item.node.nodeId, item);
    const encoded = encodeDirectoryNode(item.node);
    try {
      // sealTree changes only fixed-width child addresses, never encoded lengths.
      sealedBytes += encoded.length + PORTHOME_SEAL_OVERHEAD;
      if (publicationLimits && sealedBytes > VAULT_MAX_MANIFEST_RECEPTION_BYTES) throw new VaultError('TOO_LARGE');
    } finally { encoded.fill(0); }
  }
  const seen = new Set<NodeId>();
  function visit(node: DirectoryNode, depth: number): void {
    if (depth > 128 || depth * 49 > PORTHOME_MAX_PATH_LEN ||
        (node.entries.length && (depth + 1) * 49 - 1 > PORTHOME_MAX_PATH_LEN)) throw new VaultError('TOO_LARGE');
    if (seen.has(node.nodeId)) throw new VaultError('CONFLICT');
    seen.add(node.nodeId);
    for (const entry of node.entries) if (entry.kind === 'directory') {
      const child = byId.get(entry.childNodeId);
      if (!child) throw new VaultError('INCOMPLETE');
      if (child.node.epoch !== entry.childEpoch) throw new VaultError('EPOCH');
      visit(child.node, depth + 1);
    }
  }
  visit(tree.nodes[0].node, 0);
  if (seen.size !== tree.nodes.length) throw new VaultError('ARG');
}

/** tree.c: closed rooted graph, no aliases/cycles/orphans, exact latest epochs. */
export function validateTree(tree: VaultTree): void { validateGraph(tree, false); }

/** Onyx publication safety: C producers omit these aggregate reader limits.
 * Every path is one entry in a closed tree; final child addresses are bytes32. */
export function validatePublicationTree(tree: VaultTree): void { validateGraph(tree, true); }

export function createTree(nodes: readonly VaultTreeNode[]): VaultTree {
  if (!nodes.length) throw new VaultError('ARG');
  if (nodes.length > VAULT_MAX_OBJECTS) throw new VaultError('TOO_LARGE');
  const tree = { nodes: nodes.map(v => ({ node: cloneNode(v.node), ring: copyRing(v.ring) })) };
  validateTree(tree);
  return tree;
}

export function treeFromRecord(record: VerifiedRecord,
  rings: (nodeId: NodeId, epoch: bigint) => KeyRing): VaultTree {
  const nodes = [record.root, ...[...record.nodesById.values()].filter(n => n.nodeId !== record.root.nodeId)];
  return createTree(nodes.map(node => ({ node, ring: rings(node.nodeId, node.epoch) })));
}

type CaptureMeta = Pick<EntryMeta, 'namePlain' | 'mode' | 'mtimeNs'>;
export type CaptureEntry = CaptureMeta & (
  | { readonly kind: 'file'; readonly chunks: readonly ChunkRef[] }
  | { readonly kind: 'directory'; readonly child: CaptureDirectory; readonly keyOverride?: Bytes32 }
  | { readonly kind: 'symlink'; readonly target: string }
);
export interface CaptureDirectory {
  readonly nodeId: NodeId;
  readonly epoch: bigint;
  readonly entries: readonly CaptureEntry[];
  readonly vault?: VaultPolicy;
  /** Required when holding independently rotated keys/history. */
  readonly ring?: KeyRing;
}

/** Capture's semantic model supplies stable IDs and authenticated chunk refs.
 * New nodes sort by UTF-8 basename bytes; createTree preserves imported order. */
export function captureTree(root: CaptureDirectory, rootRing: KeyRing): VaultTree {
  const nodes: VaultTreeNode[] = [];
  const seen = new Set<NodeId>();
  function build(model: CaptureDirectory, ring: KeyRing, depth: number): { node: DirectoryNode; address: Address } {
    if (depth > 128 || nodes.length === VAULT_MAX_OBJECTS) throw new VaultError('TOO_LARGE');
    if (seen.has(model.nodeId)) throw new VaultError('CONFLICT');
    seen.add(model.nodeId);
    const index = nodes.length;
    const key = latestEpochKey(ring);
    if (model.epoch !== key.epoch) { key.nodeKey.fill(0); throw new VaultError('EPOCH'); }
    // Reserve the parent slot before recursion so root is always index zero.
    nodes.push({ node: { version: 2, nodeId: model.nodeId, epoch: model.epoch, entries: [] }, ring });
    try {
      const sorted = model.entries.map(entry => ({ entry, name: encodeUtf8(entry.namePlain) })).sort((a, b) => {
        for (let i = 0; i < Math.min(a.name.length, b.name.length); i++)
          if (a.name[i] !== b.name[i]) return a.name[i] - b.name[i];
        return a.name.length - b.name.length;
      });
      const entries = sorted.map(({ entry: e }): NodeEntry => {
        const meta = { namePlain: e.namePlain, nameEnc: encryptName(key.nodeKey, e.namePlain), mode: e.mode, mtimeNs: e.mtimeNs };
        if (e.kind === 'file') return { ...meta, kind: 'file', sizePlain: e.chunks.reduce((n, c) => n + c.sizePlain, 0n), chunks: e.chunks };
        if (e.kind === 'symlink') return { ...meta, kind: 'symlink', sizePlain: 0n, target: e.target };
        const derived = deriveChildNodeKey(key.nodeKey, e.child.nodeId);
        let current: Bytes32 | undefined;
        try {
          const childRing = e.child.ring ? copyRing(e.child.ring)
            : initRing(e.child.epoch, e.keyOverride ?? derived);
          current = latestEpochKey(childRing).nodeKey;
          if (e.keyOverride && !equalBytes(e.keyOverride, current)) throw new VaultError('EPOCH');
          const child = build(e.child, childRing, depth + 1);
          return { ...meta, kind: 'directory', sizePlain: 0n, childNodeId: child.node.nodeId,
            childEpoch: child.node.epoch, manifestAddress: child.address,
            ...(!equalBytes(current, derived) || e.keyOverride ? { keyOverride: bytes32(current) } : {}) };
        } finally { derived.fill(0); current?.fill(0); }
      });
      const node: DirectoryNode = { version: 2, nodeId: model.nodeId, epoch: model.epoch, entries,
        ...(model.vault ? { vault: model.vault } : {}) };
      nodes[index] = { node, ring };
      return { node, address: sealDirectoryNode(node, key.nodeKey).address };
    } finally { key.nodeKey.fill(0); }
  }
  build(root, copyRing(rootRing), 0);
  return createTree(nodes);
}

export function addTreeMember(tree: VaultTree, actor: Pubkey, member: Pubkey, cap: 'read' | 'write'): VaultTree {
  validateTree(tree); hex32<Pubkey>(actor); hex32<Pubkey>(member);
  if (cap !== 'read' && cap !== 'write') throw new VaultError('ARG');
  const policy = tree.nodes[0].node.vault!;
  if (actor !== policy.owner) throw new VaultError('AUTH');
  const field = cap === 'write' ? 'writers' : 'readers';
  if (policy[field].includes(member)) return createTree(tree.nodes);
  if (policy[field].length === PORTHOME_VAULT_MAX_MEMBERS || policy.grantsRev === UINT64_MAX) throw new VaultError('TOO_LARGE');
  return createTree(tree.nodes.map((v, i) => i ? v : { ...v, node: { ...v.node,
    vault: { ...policy, [field]: [...policy[field], member], grantsRev: policy.grantsRev + 1n } } }));
}

export type RandomNodeKey = () => Uint8Array;
const randomNodeKey: RandomNodeKey = () => globalThis.crypto.getRandomValues(new Uint8Array(32));
export interface NodeRevocation {
  readonly node: DirectoryNode;
  readonly ring: KeyRing;
  readonly sealed: Uint8Array;
  readonly address: Address;
  readonly parent?: Extract<NodeEntry, { kind: 'directory' }>;
  readonly head?: VaultHead;
}

/** revoke.c's atomic share-boundary rotation; the root administrative path
 * deliberately preserves includeHead coverage instead of replacing parents. */
export function revokeNode(node: DirectoryNode, ring: KeyRing, actor: Pubkey, member: Pubkey,
  reference: { readonly parent: Extract<NodeEntry, { kind: 'directory' }> } | { readonly head: VaultHead },
  writtenAt: bigint, random: RandomNodeKey = randomNodeKey): NodeRevocation {
  if (('parent' in reference) === ('head' in reference)) throw new VaultError('ARG');
  const last = latestEpochKey(ring);
  try {
    assertUint64(writtenAt);
    hex32<Pubkey>(actor); hex32<Pubkey>(member);
    if (!node.vault || writtenAt > INT64_MAX) throw new VaultError('ARG');
    if (node.vault.owner !== actor || actor === member) throw new VaultError('AUTH');
    if (node.epoch !== last.epoch) throw new VaultError('EPOCH');
    const previous = 'head' in reference ? reference.head : undefined;
    if (last.epoch === UINT64_MAX || node.vault.grantsRev === UINT64_MAX || previous?.seq === UINT64_MAX)
      throw new VaultError('TOO_LARGE');
    if ('parent' in reference) {
      const p = reference.parent;
      if (p.kind !== 'directory' || p.childNodeId !== node.nodeId || p.childEpoch !== node.epoch) throw new VaultError('ARG');
    } else if (previous!.vaultId !== node.vault.vaultId || previous!.epoch !== node.epoch ||
               previous!.grantsRev !== node.vault.grantsRev) throw new VaultError('ARG');
    const expected = 'parent' in reference ? reference.parent.manifestAddress : previous!.rootManifest;
    if (sealDirectoryNode(node, last.nodeKey).address !== expected) throw new VaultError('HASH_MISMATCH');
    const fresh = random();
    let nextRing: KeyRing;
    try { nextRing = appendRing(ring, fresh); }
    finally { fresh.fill(0); }
    const key = nextRing.entries[nextRing.entries.length - 1];
    const next: DirectoryNode = cloneNode({ ...node, epoch: key.epoch, vault: { ...node.vault,
      writers: node.vault.writers.filter(p => p !== member), readers: node.vault.readers.filter(p => p !== member),
      grantsRev: node.vault.grantsRev + 1n } });
    const sealed = sealDirectoryNode(next, key.nodeKey);
    const parent = 'parent' in reference ? { ...reference.parent, keyOverride: bytes32(key.nodeKey),
      childEpoch: key.epoch, manifestAddress: sealed.address } : undefined;
    const head = previous ? includeHead({ ...decodeHead(encodeHead(previous)), epoch: key.epoch,
      seq: previous.seq + 1n, grantsRev: next.vault!.grantsRev, writtenAt, rootManifest: sealed.address,
      keyOverride: bytes32(key.nodeKey), parents: [] }, previous, actor) : undefined;
    return { node: next, ring: nextRing, ...sealed, ...(parent ? { parent } : {}), ...(head ? { head } : {}) };
  } finally { last.nodeKey.fill(0); }
}

/** Rotate EVERY descendant, but keep chunks and their exact historical epochs. */
export function revokeTree(old: VaultTree, head: VaultHead, actor: Pubkey, member: Pubkey,
  writtenAt: bigint, random: RandomNodeKey = randomNodeKey): VaultTree {
  validateTree(old);
  if (head.refState !== undefined) throw new VaultError('INCOMPLETE');
  if (old.nodes.slice(1).some(v => v.node.vault)) throw new VaultError('CONFLICT');
  const root = revokeNode(old.nodes[0].node, old.nodes[0].ring, actor, member, { head }, writtenAt, random);
  const rotated = [ { node: root.node, ring: root.ring }, ...old.nodes.slice(1).map(v => {
    const fresh = random();
    let ring: KeyRing;
    try { ring = appendRing(v.ring, fresh); }
    finally { fresh.fill(0); }
    return { ring, node: { ...v.node, epoch: ring.entries[ring.entries.length - 1].epoch } };
  }) ];
  const byId = new Map(rotated.map(v => [v.node.nodeId, v]));
  return createTree(rotated.map(v => ({ ...v, node: { ...v.node, entries: v.node.entries.map(e => {
    const nameEnc = encryptName(v.ring.entries[v.ring.entries.length - 1].nodeKey, e.namePlain);
    if (e.kind !== 'directory') return { ...e, nameEnc };
    const child = byId.get(e.childNodeId)!;
    const last = child.ring.entries[child.ring.entries.length - 1];
    return { ...e, nameEnc, childEpoch: last.epoch, keyOverride: bytes32(last.nodeKey) };
  }) } })));
}

export interface SealedTree {
  readonly tree: VaultTree;
  readonly rootManifest: Address;
  readonly objects: readonly ManifestObject[];
}

/** Bottom-up durable puts; the input and committed tree never change. An
 * uncertain put is caller-journaled (there are no retries or deletes here). */
export async function sealTree(input: VaultTree, io: Pick<VaultBlobIO, 'put'>): Promise<SealedTree> {
  validatePublicationTree(input);
  const tree = createTree(input.nodes);
  const byId = new Map(tree.nodes.map((v, i) => [v.node.nodeId, i]));
  const nodes = [...tree.nodes];
  const objects: ManifestObject[] = [];
  async function seal(index: number): Promise<Address> {
    const item = nodes[index];
    const entries: NodeEntry[] = [];
    for (const entry of item.node.entries) entries.push(entry.kind === 'directory'
      ? { ...entry, manifestAddress: await seal(byId.get(entry.childNodeId)!) } : entry);
    const node = { ...item.node, entries };
    const key = item.ring.entries[item.ring.entries.length - 1].nodeKey;
    const sealed = sealDirectoryNode(node, key);
    await io.put(sealed.sealed.slice(), sealed.address);
    nodes[index] = { ...item, node };
    objects.push({ ...sealed, epoch: node.epoch, ring: copyRing(item.ring) });
    return sealed.address;
  }
  const rootManifest = await seal(0);
  return { tree: createTree(nodes), rootManifest, objects };
}

/** tree.c:vault_tree_head_new; previous is the owner's verified head. */
export function newOwnerHead(tree: VaultTree, previous: VaultHead | null, actor: Pubkey,
  rootManifest: Address, writtenAt: bigint): VaultHead {
  validatePublicationTree(tree); assertUint64(writtenAt); hex32<Address>(rootManifest); hex32<Pubkey>(actor);
  if (writtenAt > INT64_MAX) throw new VaultError('ARG');
  const root = tree.nodes[0];
  const policy = root.node.vault!;
  if (actor !== policy.owner) throw new VaultError('AUTH');
  if (previous?.seq === UINT64_MAX) throw new VaultError('TOO_LARGE');
  if (previous?.refState !== undefined) throw new VaultError('INCOMPLETE');
  if (previous && (previous.vaultId !== policy.vaultId || previous.epoch > root.node.epoch || previous.grantsRev > policy.grantsRev))
    throw new VaultError('ARG');
  const key = root.ring.entries[root.ring.entries.length - 1].nodeKey;
  if (sealDirectoryNode(root.node, key).address !== rootManifest) throw new VaultError('HASH_MISMATCH');
  const head: VaultHead = { vaultId: policy.vaultId, epoch: root.node.epoch, rootManifest,
    seq: previous ? previous.seq + 1n : 1n, parents: [], grantsRev: policy.grantsRev, writtenAt,
    ...(previous && (previous.keyOverride !== undefined || previous.epoch !== root.node.epoch) ? { keyOverride: bytes32(key) } : {}) };
  return previous ? includeHead(head, previous, actor) : head;
}
