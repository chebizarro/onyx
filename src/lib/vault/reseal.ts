import {
  assertUint64, bytes32, equalBytes, hex32, openChunk, paddedLength, sealChunk, selectEpochKey, verifyAddress,
} from './crypto';
import { VaultError } from './errors';
import { PORTHOME_SEAL_OVERHEAD, UINT64_MAX } from './protocol';
import { copyRing, latestEpochKey, validateKeyRing } from './ring';
import { cloneNode, createTree, validateTree } from './tree';
import type { Address, Bytes32, ChunkRef, DirectoryNode, KeyRing, NodeId, VaultBlobIO, VaultTree } from './types';

export interface ResealItem {
  readonly node: DirectoryNode;
  readonly ring: KeyRing;
  readonly entry: number;
  readonly chunk: number;
}
interface Job {
  readonly source: ResealItem;
  readonly old: ChunkRef;
  readonly ring: KeyRing;
  readonly target: bigint;
  readonly key: Bytes32;
  readonly cost: bigint;
}
export interface ResealProgress {
  readonly completed: number;
  readonly remaining: number;
  readonly reserved: bigint;
  readonly pendingAddress: Address | null;
  readonly candidateNodes: readonly DirectoryNode[];
}

function sameChunk(a: ChunkRef | undefined, b: ChunkRef): boolean {
  return !!a && a.address === b.address && a.sizeSealed === b.sizeSealed && a.chunkKeyId === b.chunkKeyId && a.sizePlain === b.sizePlain;
}
function descriptor(item: ResealItem): ChunkRef {
  if (!Number.isSafeInteger(item.entry) || item.entry < 0 || !Number.isSafeInteger(item.chunk) || item.chunk < 0)
    throw new VaultError('ARG');
  const entry = item.node.entries[item.entry];
  if (!entry || entry.kind !== 'file' || !entry.chunks[item.chunk]) throw new VaultError('ARG');
  return entry.chunks[item.chunk];
}
function validLength(chunk: ChunkRef): void {
  hex32<Address>(chunk.address); assertUint64(chunk.chunkKeyId, true);
  assertUint64(chunk.sizePlain); assertUint64(chunk.sizeSealed);
  if (chunk.sizePlain > 0x7fffffffn || chunk.sizeSealed > 0x7fffffffn + BigInt(PORTHOME_SEAL_OVERHEAD) ||
      chunk.sizeSealed < BigInt(PORTHOME_SEAL_OVERHEAD)) throw new VaultError('TOO_LARGE');
}

export function resealCost(chunk: ChunkRef): bigint {
  validLength(chunk);
  return chunk.sizeSealed + BigInt(paddedLength(chunk.sizePlain)) + BigInt(PORTHOME_SEAL_OVERHEAD);
}

/** Exact-epoch gate before I/O; authenticate length/hash, then canonical old-key
 * re-seal binds the true length even when a truncated suffix consists of zeros.
 * C also reads PCS v1 here. Onyx intentionally refuses it with VERSION. */
export async function readChunk(chunk: ChunkRef, ring: KeyRing, io: Pick<VaultBlobIO, 'read'>): Promise<Uint8Array> {
  validateKeyRing(ring); validLength(chunk);
  const oldKey = selectEpochKey(ring, chunk.chunkKeyId);
  let plain: Uint8Array | undefined;
  try {
    let sealed: Uint8Array;
    try { sealed = await io.read(chunk.address); }
    catch (error) { throw error instanceof VaultError ? error : new VaultError('IO'); }
    if (!(sealed instanceof Uint8Array) || BigInt(sealed.length) !== chunk.sizeSealed) throw new VaultError('IO');
    verifyAddress(sealed, chunk.address);
    plain = openChunk(ring, chunk.chunkKeyId, sealed, chunk.sizePlain);
    const check = sealChunk(oldKey, plain);
    if (check.sealed.length !== sealed.length || check.address !== chunk.address) throw new VaultError('ARG');
    const result = plain;
    plain = undefined;
    return result;
  } finally { oldKey.fill(0); plain?.fill(0); }
}

/** reseal.c task with an owned candidate instead of mutating borrowed nodes.
 * BUDGET is resumable; every job error is terminal. Reconcile pendingAddress
 * externally, then construct a new task. Never drops keys or deletes objects. */
export class ResealTask {
  private readonly jobs: Job[] = [];
  private readonly candidates = new Map<DirectoryNode, DirectoryNode>();
  private readonly rings = new Map<KeyRing, KeyRing>();
  private done = 0;
  private reservedBytes = 0n;
  private pending: Address | null = null;
  private failure: VaultError | null = null;
  private running = false;
  private disposed = false;

  constructor(items: readonly ResealItem[], readonly eager = false) {
    if (typeof eager !== 'boolean') throw new VaultError('ARG');
    const duplicates = new Map<DirectoryNode, Set<string>>();
    try { for (const item of items) {
      const latest = latestEpochKey(item.ring);
      try {
        if (latest.epoch !== item.node.epoch) throw new VaultError('ARG');
        const old = descriptor(item);
        const held = selectEpochKey(item.ring, old.chunkKeyId);
        held.fill(0);
        if (old.chunkKeyId > latest.epoch) throw new VaultError('EPOCH');
        validLength(old);
        let candidate = this.candidates.get(item.node);
        if (!candidate) { candidate = cloneNode(item.node); this.candidates.set(item.node, candidate); }
        if (old.chunkKeyId === latest.epoch) continue;
        const identity = `${item.entry}:${item.chunk}`;
        let seen = duplicates.get(item.node);
        if (!seen) { seen = new Set(); duplicates.set(item.node, seen); }
        if (seen.has(identity)) throw new VaultError('ARG');
        seen.add(identity);
        let ring = this.rings.get(item.ring);
        if (!ring) { ring = copyRing(item.ring); this.rings.set(item.ring, ring); }
        this.jobs.push({ source: { ...item }, old: { ...old }, ring, target: latest.epoch,
          key: bytes32(latest.nodeKey), cost: resealCost(old) });
      } finally { latest.nodeKey.fill(0); }
    } } catch (error) { this.dispose(); throw error; }
  }

  get completed(): number { return this.done; }
  get remaining(): number { return this.jobs.length - this.done; }
  get reserved(): bigint { return this.reservedBytes; }
  get pendingAddress(): Address | null { return this.pending; }
  /** Fresh owned snapshots; mutating one cannot change this task. */
  snapshot(): ResealProgress {
    return { completed: this.done, remaining: this.remaining, reserved: this.reservedBytes, pendingAddress: this.pending,
      candidateNodes: [...this.candidates.values()].map(cloneNode) };
  }
  candidateFor(source: DirectoryNode): DirectoryNode {
    const node = this.candidates.get(source);
    if (!node || this.disposed) throw new VaultError('ARG');
    for (const job of this.jobs) if (job.source.node === source) this.checkUnchanged(job);
    return cloneNode(node);
  }

  private checkUnchanged(job: Job): void {
    const latest = latestEpochKey(job.source.ring);
    try {
      if (latest.epoch !== job.target || !equalBytes(latest.nodeKey, job.key) || !sameChunk(descriptor(job.source), job.old))
        throw new VaultError('ARG');
    } finally { latest.nodeKey.fill(0); }
  }

  async run(budget: bigint, io: VaultBlobIO): Promise<ResealProgress> {
    assertUint64(budget);
    if (this.disposed || this.running) throw new VaultError('ARG');
    if (this.failure) throw this.failure;
    if (this.eager) {
      let needed = 0n;
      for (const job of this.jobs.slice(this.done)) {
        if (needed > UINT64_MAX - job.cost) throw new VaultError('TOO_LARGE');
        needed += job.cost;
      }
      if (needed > budget) throw new VaultError('BUDGET');
    }
    this.running = true;
    try {
      while (this.done < this.jobs.length) {
        const job = this.jobs[this.done];
        if (job.cost > budget) throw new VaultError('BUDGET');
        if (this.reservedBytes > UINT64_MAX - job.cost) throw new VaultError('TOO_LARGE');
        budget -= job.cost;
        this.reservedBytes += job.cost;
        let plain: Uint8Array | undefined;
        try {
          this.checkUnchanged(job);
          plain = await readChunk(job.old, job.ring, io);
          this.checkUnchanged(job);
          const fresh = sealChunk(job.key, plain);
          if (BigInt(fresh.sealed.length) + job.old.sizeSealed !== job.cost) throw new VaultError('ARG');
          this.pending = fresh.address;
          await io.put(fresh.sealed, fresh.address);
          this.checkUnchanged(job);
          const candidate = this.candidates.get(job.source.node)!;
          this.candidates.set(job.source.node, { ...candidate, entries: candidate.entries.map((entry, i) => {
            if (i !== job.source.entry) return entry;
            if (entry.kind !== 'file') throw new VaultError('ARG');
            return { ...entry, chunks: entry.chunks.map((chunk, k) => k !== job.source.chunk ? chunk
              : { ...job.old, address: fresh.address, sizeSealed: BigInt(fresh.sealed.length), chunkKeyId: job.target }) };
          }) });
          this.pending = null;
          this.done++;
        } catch (error) {
          this.failure = error instanceof VaultError ? error : new VaultError('IO');
          throw this.failure;
        } finally { plain?.fill(0); }
      }
      return this.snapshot();
    } finally { this.running = false; }
  }

  dispose(): void {
    if (this.running) throw new VaultError('ARG');
    for (const job of this.jobs) job.key.fill(0);
    for (const ring of this.rings.values()) for (const entry of ring.entries) entry.nodeKey.fill(0);
    this.disposed = true;
  }
}

/** Stable Onyx ordering: slash-joined encrypted path, then chunk index. */
export function treeResealItems(tree: VaultTree): readonly ResealItem[] {
  validateTree(tree);
  const byId = new Map(tree.nodes.map(v => [v.node.nodeId, v]));
  const files: { path: string; items: ResealItem[] }[] = [];
  function walk(nodeId: NodeId, prefix: string): void {
    const item = byId.get(nodeId)!;
    item.node.entries.forEach((entry, i) => {
      const path = prefix ? `${prefix}/${entry.nameEnc}` : entry.nameEnc;
      if (entry.kind === 'directory') walk(entry.childNodeId, path);
      else if (entry.kind === 'file') files.push({ path, items: entry.chunks.map((_, chunk) =>
        ({ node: item.node, ring: item.ring, entry: i, chunk })) });
    });
  }
  walk(tree.nodes[0].node.nodeId, '');
  return files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0).flatMap(f => f.items);
}

export async function checkTreeChunks(tree: VaultTree, io: Pick<VaultBlobIO, 'read'>): Promise<{
  readonly nodes: number; readonly chunks: number; readonly sizePlain: bigint; readonly sizeSealed: bigint;
}> {
  validateTree(tree);
  const items = treeResealItems(tree);
  // An absent historical epoch is a refusal before any chunk I/O.
  for (const item of items) { const key = selectEpochKey(item.ring, descriptor(item).chunkKeyId); key.fill(0); }
  let sizePlain = 0n, sizeSealed = 0n;
  for (const item of items) {
    const chunk = descriptor(item);
    const plain = await readChunk(chunk, item.ring, io);
    plain.fill(0);
    if (sizePlain > UINT64_MAX - chunk.sizePlain || sizeSealed > UINT64_MAX - chunk.sizeSealed) throw new VaultError('TOO_LARGE');
    sizePlain += chunk.sizePlain; sizeSealed += chunk.sizeSealed;
  }
  return { nodes: tree.nodes.length, chunks: items.length, sizePlain, sizeSealed };
}

/** Install acknowledged chunk changes into a NEW graph; manifests still need
 * sealing/uploading and a head before this candidate becomes committed state. */
export function resealCandidate(tree: VaultTree, task: ResealTask): VaultTree {
  const candidates = new Set(task.snapshot().candidateNodes.map(node => node.nodeId));
  const targets = new Set(tree.nodes.map(v => v.node.nodeId));
  if ([...candidates].some(nodeId => !targets.has(nodeId))) throw new VaultError('ARG');
  return createTree(tree.nodes.map(v => ({ ...v,
    node: candidates.has(v.node.nodeId) ? task.candidateFor(v.node) : v.node })));
}
