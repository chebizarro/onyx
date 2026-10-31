import type { VaultFS } from '../../platform/types';
import type { VaultEditorBarrier } from './engine-api';
import { encodeUtf8, hashAddress, hex32 } from './crypto';
import { VaultError } from './errors';
import { absolutePath, compareBaseline, diskStat, ExpectedHashes, isReservedPath, nowSeconds, validateRelativePath } from './filesystem';
import { PROTOCOL_ID } from './protocol';
import { retainedRootAddresses } from './retained-roots';
import { VaultStore, toStorage } from './store';
import type { Address, PathConflict, RecordId, StoredBaselineEntry, StoredConflict, StoredOperation, StoredVault, Pubkey } from './types';

export interface MaterializeTarget {
  readonly path: string;
  readonly baseline: StoredBaselineEntry;
  /** Complete authenticated bytes; no downloading is allowed inside the barrier. */
  readonly bytes?: Uint8Array;
  /** Entry digest equals the vault baseline's: no bytes were fetched or hashed. */
  readonly unchanged?: boolean;
  /** Fetches authenticated bytes on demand (conflict artifacts only; never inside the barrier). */
  readonly load?: () => Promise<Uint8Array>;
}
/** Journal 'done' marks in batches; replaying an unsaved mark is a verified no-op. */
export const MATERIALIZE_JOURNAL_BATCH = 16;
interface PathOperation {
  path: string;
  expected: Address | null;
  desired: Address | null;
  kind: 'file' | 'directory' | 'delete';
  staged: string;
  preimage: string;
}
export interface MaterializeContext {
  readonly fs: VaultFS;
  readonly store: VaultStore;
  readonly barrier: VaultEditorBarrier;
  readonly echoes: ExpectedHashes;
  readonly signal: AbortSignal;
  readonly check: () => void;
  readonly operationId: () => string;
  readonly hash?: (bytes: Uint8Array) => Promise<Address>;
  readonly localWriter?: Pubkey;
  readonly pinnedAddresses?: readonly Address[];
}
const version = { schemaVersion: 1, protocolId: PROTOCOL_ID } as const;
const digest = (ctx: MaterializeContext, bytes: Uint8Array): Promise<Address> => ctx.hash?.(bytes) ?? Promise.resolve(hashAddress(bytes));
const directoryHash = hashAddress(encodeUtf8('onyx:directory'));
export async function diskHash(fs: VaultFS, notebook: string, path: string, digest: (bytes: Uint8Array) => Promise<Address> = async bytes => hashAddress(bytes)): Promise<Address | null> {
  if (!await fs.exists(path)) return null;
  // Avoid treating a failed read (permissions, wrong type) as an absent file.
  const parent = path.slice(0, path.lastIndexOf('/'));
  const entry = (await fs.listAll(parent)).find(e => e.path === path);
  if (!entry) throw new VaultError('IO');
  return entry.isDirectory ? directoryHash : await digest(await fs.readBinary(path, notebook));
}
export function baselineHash(entry: StoredBaselineEntry | undefined): Address | null {
  return !entry ? null : entry.kind === 'directory' ? directoryHash : entry.byteHash;
}
export async function ensureDirectory(fs: VaultFS, notebook: string, path: string): Promise<void> {
  if (await fs.exists(path)) {
    if (path !== notebook && !(await fs.listAll(path.slice(0, path.lastIndexOf('/')))).some(e => e.path === path && e.isDirectory)) throw new VaultError('CONFLICT');
    return;
  }
  const parent = path.slice(0, path.lastIndexOf('/'));
  if (parent && parent !== notebook) await ensureDirectory(fs, notebook, parent);
  await fs.createFolder(path, notebook);
}
export async function persistLocalConflict(ctx: MaterializeContext, vault: StoredVault, path: string,
  localHash: Address | null, remote: MaterializeTarget | undefined, remoteId: RecordId): Promise<string> {
  ctx.check();
  const identity = hashAddress(encodeUtf8(JSON.stringify([vault.vaultId, path, localHash, remote?.baseline.byteHash, remoteId])));
  const conflict: PathConflict = {
    pathEnc: path, otherRecordId: remoteId, inView: !!remote, inOther: localHash !== null,
    writer: ctx.localWriter ?? vault.owner, seq: BigInt(vault.lastOwnSeq), rootManifest: retainedRootAddresses(vault.retainedRoots)[0] ?? hex32<Address>('00'.repeat(32)),
  };
  const artifactRoot = absolutePath(absolutePath(vault.mount.notebookPath, vault.mount.relativePath), `.onyx-vault-conflicts/${identity}`);
  const artifacts: string[] = [];
  // Metadata is durable before any sibling write. Existing content stays in place.
  const value: StoredConflict = { ...version, vaultId: vault.vaultId, conflictId: identity, displayPath: path,
    kind: remote?.baseline.kind === 'directory' || localHash === directoryHash ? 'directory' : !remote ? 'deletion-only' : 'file',
    conflict: toStorage(conflict), retainedVersions: retainedRootAddresses(vault.retainedRoots), artifactRefs: [], resolution: 'unresolved' };
  const held = await ctx.store.read('conflicts', [vault.vaultId, identity]);
  if (held) return identity;
  // A lazy download must complete before the row exists: a persisted row is never revisited.
  const remoteBytes = remote?.bytes ?? (remote?.load && remote.baseline.kind === 'file' ? await remote.load() : undefined);
  ctx.check();
  await ctx.store.put('conflicts', [vault.vaultId, identity], value, 0);
  ctx.check();
  await ensureDirectory(ctx.fs, vault.mount.notebookPath, artifactRoot);
  if (localHash && localHash !== directoryHash) {
    const bytes = await ctx.fs.readBinary(absolutePath(absolutePath(vault.mount.notebookPath, vault.mount.relativePath), path), vault.mount.notebookPath);
    ctx.check();
    const sibling = `${artifactRoot}/local`;
    await ctx.fs.writeBinary(sibling, bytes, vault.mount.notebookPath); artifacts.push(sibling);
  }
  if (remoteBytes) {
    ctx.check();
    const sibling = `${artifactRoot}/remote`;
    await ctx.fs.writeBinary(sibling, remoteBytes, vault.mount.notebookPath); artifacts.push(sibling);
  }
  ctx.check();
  await ctx.fs.write(`${artifactRoot}/metadata.json`, JSON.stringify({ path, localHash, remoteHash: remote?.baseline.byteHash ?? null, remoteId }), vault.mount.notebookPath);
  await ctx.store.put('conflicts', [vault.vaultId, identity], { ...value, artifactRefs: artifacts });
  return identity;
}

/** Staging and per-path completion are replayable. VaultFS is NOT a transaction. */
export async function materialize(ctx: MaterializeContext, vault: StoredVault, targets: readonly MaterializeTarget[], viewId: RecordId,
  options: { preserveExisting?: boolean; resolvedPaths?: readonly string[] } = {}): Promise<void> {
  const root = absolutePath(vault.mount.notebookPath, vault.mount.relativePath);
  const byPath = new Map<string, MaterializeTarget>(), canonical = new Map<string, string>(), blocked = new Set<string>();
  for (const target of targets) {
    try { validateRelativePath(target.path); if (isReservedPath(target.path) || target.baseline.kind === 'symlink') blocked.add(target.path); }
    catch { blocked.add(target.path); }
    const key = target.path.normalize('NFC').toLowerCase(), previous = canonical.get(key);
    if (previous !== undefined) { blocked.add(previous); blocked.add(target.path); }
    canonical.set(key, target.path);
    if (target.baseline.kind === 'file' && !target.unchanged && (!target.bytes || await digest(ctx, target.bytes) !== target.baseline.byteHash)) throw new VaultError('HASH_MISMATCH');
    if (target.unchanged && (target.baseline.kind === 'symlink' || baselineHash(target.baseline) !== baselineHash(vault.baseline[target.path]))) throw new VaultError('ARG');
    byPath.set(target.path, target);
  }
  for (const target of targets) if ([...blocked].some(path => target.path === path || target.path.startsWith(path + '/'))) {
    blocked.add(target.path);
    const id = hashAddress(encodeUtf8(JSON.stringify([vault.vaultId, target.path, viewId, 'unsupported'])));
    ctx.check();
    if (!await ctx.store.read('conflicts', [vault.vaultId, id])) {
      await ctx.store.put('conflicts', [vault.vaultId, id], { ...version, vaultId: vault.vaultId, conflictId: id, displayPath: target.path, blockedMaterialization: true,
        kind: target.baseline.kind === 'directory' ? 'directory' : 'file',
        conflict: toStorage({ pathEnc: target.path, otherRecordId: viewId, inView: true, inOther: false, writer: ctx.localWriter ?? vault.owner, seq: BigInt(vault.lastOwnSeq), rootManifest: retainedRootAddresses(vault.retainedRoots)[0] ?? hex32<Address>('00'.repeat(32)) }),
        retainedVersions: retainedRootAddresses(vault.retainedRoots), artifactRefs: [], resolution: 'unresolved' });
    }
    byPath.delete(target.path);
  }
  ctx.check();
  const id = ctx.operationId(), staging = absolutePath(root, `.onyx-vault-staging/${id}`);
  const paths = [...new Set([...Object.keys(vault.baseline), ...byPath.keys()])].sort();
  const operations: PathOperation[] = [];
  const baseline = { ...vault.baseline };
  for (const path of paths) {
    if (blocked.has(path)) continue;
    validateRelativePath(path);
    const target = byPath.get(path);
    const desired = baselineHash(target?.baseline), prior = baselineHash(vault.baseline[path]);
    const explicitlyResolved = options.resolvedPaths?.some(p => path === p || path.startsWith(p + '/'));
    // Unchanged entry (desired === prior): whether the disk still matches the
    // baseline ('converge') or diverged locally ('preserve'), the baseline entry
    // is kept and nothing is written, so the disk is not read or hashed.
    if (target?.unchanged && !explicitlyResolved && !options.preserveExisting) { baseline[path] = target.baseline; continue; }
    const local = await diskHash(ctx.fs, vault.mount.notebookPath, absolutePath(root, path), ctx.hash);
    ctx.check();
    const action = compareBaseline(explicitlyResolved ? local : prior, local, desired);
    if (target?.baseline.kind === 'symlink' || action === 'conflict' || options.preserveExisting && local !== null && local !== desired) {
      await persistLocalConflict(ctx, vault, path, local, target, viewId); continue;
    }
    if (action === 'preserve') continue;
    if (action === 'converge') { if (target) baseline[path] = target.baseline; else delete baseline[path]; continue; }
    operations.push({ path, expected: local, desired, kind: !target ? 'delete' : target.baseline.kind === 'directory' ? 'directory' : 'file',
      staged: `${staging}/${operations.length}.new`, preimage: `${staging}/${operations.length}.old` });
    if (target) baseline[path] = target.baseline; else delete baseline[path];
  }
  const operation: StoredOperation = { ...version, vaultId: vault.vaultId, operationId: id, kind: 'materialize', stage: 'prepared',
    candidate: { paths: toStorage(operations), baseline: toStorage(baseline), viewId }, signedEvent: null, pinnedAddresses: [...(ctx.pinnedAddresses ?? [])], pendingAddress: null, uploadOutcomes: {}, relayOutcomes: {} };
  const row = await ctx.store.read('vaults', [vault.vaultId]);
  if (!row || row.value.pendingCandidateId) throw new VaultError('CONFLICT');
  await ctx.store.saveJournal(operation, { ...row.value, pendingCandidateId: id }, { vault: row.revision, operation: 0 });
  await ensureDirectory(ctx.fs, vault.mount.notebookPath, staging);
  for (const op of operations) {
    ctx.check();
    if (op.kind === 'file') {
      const target = byPath.get(op.path)!, bytes = target.bytes ?? await target.load?.();
      if (!bytes || await digest(ctx, bytes) !== target.baseline.byteHash) throw new VaultError('HASH_MISMATCH');
      await ctx.fs.writeBinary(op.staged, bytes, vault.mount.notebookPath);
    }
  }
  await resumeMaterialization(ctx, operation);
}

export async function resumeMaterialization(ctx: MaterializeContext, original: StoredOperation): Promise<void> {
  const opRow = await ctx.store.read('operations', [original.vaultId, original.operationId]);
  let operation = opRow!.value, opRevision = opRow!.revision;
  if (operation.stage === 'needs-recovery') {
    if (!operation.recoveryStage) throw new VaultError('STORAGE', { operation: 'recover' });
    operation = { ...operation, stage: operation.recoveryStage };
  }
  let row = (await ctx.store.read('vaults', [original.vaultId]))!;
  let vault = row.value, revision = row.revision;
  const root = absolutePath(vault.mount.notebookPath, vault.mount.relativePath);
  const operations = operation.candidate.paths as unknown as readonly PathOperation[];
  const planned = operation.candidate.baseline as unknown as Readonly<Record<string, StoredBaselineEntry>>;
  const baseline = { ...planned };
  for (const op of operations) {
    if (vault.baseline[op.path]) baseline[op.path] = vault.baseline[op.path]; else delete baseline[op.path];
  }
  const viewId = operation.candidate.viewId as RecordId;
  let unsaved = 0;
  const save = async (stage: StoredOperation['stage']) => {
    ctx.check(); operation = { ...operation, stage };
    const next = await ctx.store.saveJournal(operation, { ...vault, pendingCandidateId: stage === 'committed' ? null : operation.operationId,
      ...(stage === 'committed' ? { baseline, materializedViewId: viewId } : {}) }, { vault: revision, operation: opRevision });
    revision = next.vault; opRevision = next.operation; unsaved = 0;
  };
  if (operation.stage === 'prepared') {
    for (const op of operations) if (op.kind === 'file' && !await ctx.fs.exists(op.staged)) {
      ctx.check();
      await ctx.store.saveJournal({ ...operation, stage: 'committed' }, { ...vault, pendingCandidateId: null }, { vault: revision, operation: opRevision });
      const abandoned = absolutePath(root, `.onyx-vault-staging/${operation.operationId}`);
      if (await ctx.fs.exists(abandoned)) await ctx.fs.remove(abandoned, vault.mount.notebookPath);
      return;
    }
  }
  await save('ready-to-publish');
  const barrierPaths = operations.map(op => absolutePath(vault.mount.relativePath, validateRelativePath(op.path)));
  const deadline = new AbortController();
  const abort = () => deadline.abort();
  ctx.signal.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, 5000);
  let barrier: Awaited<ReturnType<VaultEditorBarrier['enter']>> | undefined;
  try {
    const entering = ctx.barrier.enter(barrierPaths, deadline.signal);
    // An integration that resolves late must not strand editors read-only.
    void entering.then(held => { if (deadline.signal.aborted) held.release(); }, () => {});
    barrier = await new Promise<Awaited<typeof entering>>((resolve, reject) => {
      const cancel = () => reject(new VaultError('CONFLICT', { operation: 'materialize', retryable: true }));
      deadline.signal.addEventListener('abort', cancel, { once: true });
      if (deadline.signal.aborted) cancel();
      entering.then(value => { deadline.signal.removeEventListener('abort', cancel); resolve(value); }, error => { deadline.signal.removeEventListener('abort', cancel); reject(error); });
    });
    ctx.check();
    const conflictPath = async (op: PathOperation, current: Address | null) => {
      let remote: MaterializeTarget | undefined;
      if (planned[op.path]) remote = { path: op.path, baseline: planned[op.path], ...(op.kind === 'file' && await ctx.fs.exists(op.staged) ? { bytes: await ctx.fs.readBinary(op.staged, vault.mount.notebookPath) } : {}) };
      const id = await persistLocalConflict(ctx, vault, op.path, current, remote, viewId);
      if (await ctx.fs.exists(op.preimage)) {
        const bytes = await ctx.fs.readBinary(op.preimage, vault.mount.notebookPath);
        if (await digest(ctx, bytes) !== op.expected) throw new VaultError('HASH_MISMATCH');
        const artifact = absolutePath(root, `.onyx-vault-conflicts/${id}/preimage`);
        ctx.check(); await ctx.fs.writeBinary(artifact, bytes, vault.mount.notebookPath);
        const row = (await ctx.store.read('conflicts', [vault.vaultId, id]))!;
        await ctx.store.put('conflicts', [vault.vaultId, id], { ...row.value, artifactRefs: [...new Set([...row.value.artifactRefs, artifact])] }, row.revision);
      }
    };
    const transitions = operations.filter(op => op.kind === 'file' && op.expected === directoryHash);
    const priority = (op: PathOperation) => op.kind === 'delete' && transitions.some(parent => op.path.startsWith(parent.path + '/')) ? 0 : op.kind === 'delete' ? 2 : 1;
    // Directory-to-file dependencies must be removed before the parent transition.
    const ordered = [...operations].sort((a, b) => priority(a) - priority(b) ||
      (a.kind === 'delete' ? b.path.length - a.path.length : a.path.length - b.path.length));
    for (const op of ordered) {
      ctx.check();
      if (deadline.signal.aborted) throw new VaultError('CONFLICT', { operation: 'materialize', retryable: true });
      const path = absolutePath(root, op.path);
      const current = await diskHash(ctx.fs, vault.mount.notebookPath, path, ctx.hash);
      ctx.check();
      const transitioning = operation.uploadOutcomes[op.path] === 'transition-started' && current === null;
      if (current !== op.desired && current !== op.expected && !transitioning) {
        await conflictPath(op, current); continue;
      }
      if (current !== op.desired) {
        if (current && current !== directoryHash && !await ctx.fs.exists(op.preimage)) {
          const preimage = await ctx.fs.readBinary(path, vault.mount.notebookPath);
          ctx.check();
          await ctx.fs.writeBinary(op.preimage, preimage, vault.mount.notebookPath);
        }
        ctx.check();
        if (await diskHash(ctx.fs, vault.mount.notebookPath, path, ctx.hash) !== current) {
          await conflictPath(op, await diskHash(ctx.fs, vault.mount.notebookPath, path, ctx.hash)); continue;
        }
        ctx.check();
        const typeTransition = op.kind === 'file' && op.expected === directoryHash || op.kind === 'directory' && op.expected !== null && op.expected !== directoryHash;
        if (typeTransition && current !== null) {
          if (current === directoryHash && (await ctx.fs.listAll(path)).length) { await conflictPath(op, current); continue; }
          operation = { ...operation, uploadOutcomes: { ...operation.uploadOutcomes, [op.path]: 'transition-started' } };
          await save('ready-to-publish'); ctx.check();
          if (await diskHash(ctx.fs, vault.mount.notebookPath, path, ctx.hash) !== current) { await conflictPath(op, await diskHash(ctx.fs, vault.mount.notebookPath, path, ctx.hash)); continue; }
          if (deadline.signal.aborted) throw new VaultError('CONFLICT', { operation: 'materialize', retryable: true });
          await ctx.fs.remove(path, vault.mount.notebookPath); ctx.check();
        }
        if (op.kind === 'delete') {
          if (current === directoryHash && (await ctx.fs.listAll(path)).length) {
            await conflictPath(op, current); continue;
          }
          await ctx.fs.remove(path, vault.mount.notebookPath);
        } else if (op.kind === 'directory') await ensureDirectory(ctx.fs, vault.mount.notebookPath, path);
        else {
          const bytes = await ctx.fs.readBinary(op.staged, vault.mount.notebookPath);
          if (await digest(ctx, bytes) !== op.desired) throw new VaultError('HASH_MISMATCH');
          await ensureDirectory(ctx.fs, vault.mount.notebookPath, path.slice(0, path.lastIndexOf('/')));
          ctx.check(); if (deadline.signal.aborted) throw new VaultError('CONFLICT', { operation: 'materialize', retryable: true });
          await ctx.fs.writeBinary(path, bytes, vault.mount.notebookPath);
        }
      }
      ctx.check();
      // The observation second starts before the verifying hash: an edit after it moves the mtime past it.
      const observedAt = nowSeconds();
      if (await diskHash(ctx.fs, vault.mount.notebookPath, path, ctx.hash) !== op.desired) throw new VaultError('IO');
      if (planned[op.path]) {
        // Record the written file's stat so the next capture can skip reading it.
        baseline[op.path] = op.kind === 'file' ? { ...planned[op.path], disk: diskStat(await ctx.fs.stats(path), observedAt) } : planned[op.path];
      } else delete baseline[op.path];
      ctx.echoes.expect(path, op.desired);
      operation = { ...operation, uploadOutcomes: { ...operation.uploadOutcomes, [op.path]: 'done' } };
      if (++unsaved >= MATERIALIZE_JOURNAL_BATCH) await save('ready-to-publish');
    }
    // Include paths which converged without needing a write.
    for (const [path, entry] of Object.entries(planned)) if (!operations.some(op => op.path === path)) baseline[path] = entry;
    await save('committed');
  } finally {
    barrier?.release(); clearTimeout(timer); ctx.signal.removeEventListener('abort', abort);
  }
  ctx.check();
  const staging = absolutePath(root, `.onyx-vault-staging/${operation.operationId}`);
  if (await ctx.fs.exists(staging)) await ctx.fs.remove(staging, vault.mount.notebookPath);
}

export async function cleanStagingOrphans(ctx: MaterializeContext, vault: StoredVault, pending: readonly StoredOperation[]): Promise<void> {
  const root = absolutePath(absolutePath(vault.mount.notebookPath, vault.mount.relativePath), '.onyx-vault-staging');
  if (!await ctx.fs.exists(root)) return;
  const keep = new Set(pending.filter(op => op.vaultId === vault.vaultId && op.stage !== 'committed').map(op => op.operationId));
  for (const entry of await ctx.fs.listAll(root)) {
    ctx.check(); if (!keep.has(entry.name)) await ctx.fs.remove(entry.path, vault.mount.notebookPath);
  }
}
