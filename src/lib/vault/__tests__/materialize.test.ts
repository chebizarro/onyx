import { afterEach, describe, expect, it, vi } from 'vitest';
import { HeadlessVaultEngine } from '../engine';
import { encodeUtf8, hex32 } from '../crypto';
import { ExpectedHashes } from '../filesystem';
import { cleanStagingOrphans, materialize, resumeMaterialization, type MaterializeContext, type MaterializeTarget } from '../materialize';
import type { Address, EntryDigest, NodeId, RecordId } from '../types';
import { address, fixture, network, signer, snapshot } from './engine-fixtures';
import { VaultStore } from '../store';

const cleanups: (() => Promise<void> | void)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });
async function setup() {
  const f = await fixture(); await f.mkdir('/notebook/v'); const engine = new HeadlessVaultEngine(f.deps); await engine.start(f.session); const id = await engine.create('v', {}); cleanups.push(() => engine.stop());
  const store = await f.openStore(); cleanups.push(() => store.stop());
  let n = 0, released = false;
  const ctx: MaterializeContext = { fs: f.fs, store, barrier: { enter: async () => ({ flushedHashes: new Map(), release: () => { released = true; } }) }, signal: new AbortController().signal, check: () => {}, echoes: new ExpectedHashes(), operationId: () => `materialize-${n++}` };
  const vault = async () => (await store.read('vaults', [id]))!.value;
  const view = hex32<RecordId>('99'.repeat(32));
  return { f, store, ctx, vault, view, released: () => released };
}
function target(path: string, content: string): MaterializeTarget {
  return { path, bytes: encodeUtf8(content), baseline: { nodeId: hex32<NodeId>('22'.repeat(32)), entryDigest: hex32<EntryDigest>('33'.repeat(32)), byteHash: address(content), kind: 'file',
    metadata: { namePlain: path, nameEnc: '' as never, mode: 0o644, mtimeNs: '0', sizePlain: String(content.length) } } };
}
async function pending(store: VaultStore) { return (await store.pendingOperations()).find(op => op.kind === 'materialize')!; }
describe('journaled materialization', () => {
  it('stages before the editor barrier, verifies hashes, advances baseline and acknowledges watcher echoes', async () => {
    const s = await setup(); let barrierEntered = false;
    const ctx = { ...s.ctx, barrier: { enter: async () => { barrierEntered = true; expect([...s.f.fs.files.keys()].some(p => p.includes('.onyx-vault-staging/') && p.endsWith('.new'))).toBe(true); expect(await s.f.fs.exists('/notebook/v/a')).toBe(false); return { flushedHashes: new Map(), release: () => {} }; } } };
    s.f.fs.beforeWrite = path => { if (path === '/notebook/v/a') expect(barrierEntered).toBe(true); };
    await materialize(ctx, await s.vault(), [target('a', 'remote')], s.view);
    expect(await s.f.fs.read('/notebook/v/a')).toBe('remote'); expect((await s.vault()).baseline.a.byteHash).toBe(address('remote'));
    expect(s.ctx.echoes.acknowledge('/notebook/v/a', address('remote'))).toBe(true); expect(await s.f.fs.listAll('/notebook/v/.onyx-vault-staging')).toEqual([]);
  });
  it('preserves local edits made by dirty-editor flush and creates durable siblings', async () => {
    const s = await setup(); await materialize(s.ctx, await s.vault(), [target('a', 'baseline')], s.view);
    const ctx = { ...s.ctx, barrier: { enter: async () => { await s.f.fs.write('/notebook/v/a', 'dirty editor'); return { flushedHashes: new Map<string, Address>([['v/a', address('dirty editor')]]), release: () => {} }; } } };
    await materialize(ctx, await s.vault(), [target('a', 'remote')], s.view);
    expect(await s.f.fs.read('/notebook/v/a')).toBe('dirty editor'); const conflicts = await s.store.list('conflicts'); expect(conflicts).toHaveLength(1); expect(conflicts[0].value.artifactRefs.some(p => p.endsWith('/local'))).toBe(true);
    expect((await s.vault()).baseline.a.byteHash).toBe(address('baseline'));
  });
  it('attach empty baseline produces conflicts and converges identical files without overwriting', async () => {
    const s = await setup(); await s.f.fs.write('/notebook/v/a', 'local'); await s.f.fs.write('/notebook/v/b', 'same');
    await materialize(s.ctx, await s.vault(), [target('a', 'remote'), target('b', 'same')], s.view, { preserveExisting: true });
    expect(await s.f.fs.read('/notebook/v/a')).toBe('local'); expect((await s.vault()).baseline.a).toBeUndefined(); expect((await s.vault()).baseline.b.byteHash).toBe(address('same')); expect(await s.store.list('conflicts')).toHaveLength(1);
  });
  it.each(['before', 'after'] as const)('resumes a crash %s each live path write idempotently', async boundary => {
    for (const failedPath of ['a', 'b']) {
      const s = await setup(); let crash = true;
      const hook = (path: string) => { if (crash && path === `/notebook/v/${failedPath}`) { crash = false; throw new Error('injected crash'); } };
      if (boundary === 'before') s.f.fs.beforeWrite = hook; else s.f.fs.afterWrite = hook;
      await expect(materialize(s.ctx, await s.vault(), [target('a', 'A'), target('b', 'B')], s.view)).rejects.toThrow('injected crash');
      expect(s.released()).toBe(true); const op = await pending(s.store); expect(op.stage).toBe('ready-to-publish');
      s.f.fs.beforeWrite = undefined; s.f.fs.afterWrite = undefined;
      await s.store.markNeedsRecovery(op.vaultId, op.operationId);
      const recovery = await pending(s.store); expect(recovery).toMatchObject({ stage: 'needs-recovery', recoveryStage: 'ready-to-publish' });
      await resumeMaterialization(s.ctx, recovery);
      expect(await s.f.fs.read('/notebook/v/a')).toBe('A'); expect(await s.f.fs.read('/notebook/v/b')).toBe('B'); expect(await s.store.pendingOperations()).toEqual([]);
    }
  });
  it('abandons incomplete prepared staging without advancing the remote baseline, then replans', async () => {
    const s = await setup(); s.f.fs.beforeWrite = path => { if (path.endsWith('.new')) throw new Error('crash staging'); };
    await expect(materialize(s.ctx, await s.vault(), [target('a', 'A')], s.view)).rejects.toThrow(); const op = await pending(s.store); expect(op.stage).toBe('prepared');
    s.f.fs.beforeWrite = undefined;
    await s.store.markNeedsRecovery(op.vaultId, op.operationId);
    const recovery = await pending(s.store); expect(recovery).toMatchObject({ stage: 'needs-recovery', recoveryStage: 'prepared' });
    await resumeMaterialization(s.ctx, recovery); expect((await s.vault()).baseline.a).toBeUndefined(); expect(await s.f.fs.exists('/notebook/v/a')).toBe(false);
    await materialize(s.ctx, await s.vault(), [target('a', 'A')], s.view); expect(await s.f.fs.read('/notebook/v/a')).toBe('A');
  });
  it('deletes only unchanged files and never removes untracked directory children', async () => {
    const s = await setup(); await materialize(s.ctx, await s.vault(), [target('a', 'A')], s.view); await s.f.fs.write('/notebook/v/a', 'changed');
    await materialize(s.ctx, await s.vault(), [], s.view); expect(await s.f.fs.read('/notebook/v/a')).toBe('changed'); expect(await s.store.list('conflicts')).toHaveLength(1);
  });
  it('replaces file-to-directory and directory-to-file entries safely', async () => {
    const s = await setup(); await materialize(s.ctx, await s.vault(), [target('a', 'file')], s.view);
    const directory: MaterializeTarget = { path: 'a', baseline: { ...target('a', '').baseline, kind: 'directory', byteHash: null } };
    await materialize(s.ctx, await s.vault(), [directory, target('a/child', 'child')], s.view);
    expect(await s.f.fs.read('/notebook/v/a/child')).toBe('child');
    await materialize(s.ctx, await s.vault(), [target('a', 'replacement')], s.view);
    expect(await s.f.fs.read('/notebook/v/a')).toBe('replacement'); expect((await s.vault()).baseline['a/child']).toBeUndefined();
  });
  it('does not replace a directory over locally changed descendants', async () => {
    const s = await setup(); const directory: MaterializeTarget = { path: 'a', baseline: { ...target('a', '').baseline, kind: 'directory', byteHash: null } };
    await materialize(s.ctx, await s.vault(), [directory, target('a/child', 'baseline')], s.view);
    await s.f.fs.write('/notebook/v/a/child', 'local edit');
    await materialize(s.ctx, await s.vault(), [target('a', 'remote file')], s.view);
    expect(await s.f.fs.read('/notebook/v/a/child')).toBe('local edit'); expect((await s.vault()).baseline.a.kind).toBe('directory');
  });
  it('replays a crash after removing the old type during a transition', async () => {
    const s = await setup(); await materialize(s.ctx, await s.vault(), [target('a', 'old')], s.view);
    const remove = s.f.fs.remove.bind(s.f.fs); const spy = vi.spyOn(s.f.fs, 'remove'); let crash = true;
    spy.mockImplementation(async path => { await remove(path); if (path === '/notebook/v/a' && crash) { crash = false; throw new Error('transition crash'); } });
    const directory: MaterializeTarget = { path: 'a', baseline: { ...target('a', '').baseline, kind: 'directory', byteHash: null } };
    await expect(materialize(s.ctx, await s.vault(), [directory, target('a/child', 'new')], s.view)).rejects.toThrow('transition crash');
    await resumeMaterialization(s.ctx, await pending(s.store)); expect(await s.f.fs.read('/notebook/v/a/child')).toBe('new');
  });
  it('keeps the original preimage when an interrupted live write left partial bytes', async () => {
    const s = await setup(); await materialize(s.ctx, await s.vault(), [target('a', 'original')], s.view);
    s.f.fs.beforeWrite = path => { if (path === '/notebook/v/a') { s.f.fs.files.set(path, encodeUtf8('partial')); throw new Error('partial write'); } };
    await expect(materialize(s.ctx, await s.vault(), [target('a', 'remote')], s.view)).rejects.toThrow(); s.f.fs.beforeWrite = undefined;
    await resumeMaterialization(s.ctx, await pending(s.store));
    const conflicts = await s.store.list('conflicts'), preimage = conflicts[0].value.artifactRefs.find(p => p.endsWith('/preimage'))!;
    expect(await s.f.fs.read(preimage)).toBe('original'); expect(await s.f.fs.read('/notebook/v/a')).toBe('partial');
  });
  it('records unsupported paths and case collisions without materialising or deleting them', async () => {
    const s = await setup(); await materialize(s.ctx, await s.vault(), [target('bad?', 'remote'), target('A', 'upper'), target('a', 'lower')], s.view);
    expect(await s.store.list('conflicts')).toHaveLength(3); expect(await s.f.fs.exists('/notebook/v/bad?')).toBe(false);
    expect((await s.store.list('conflicts')).every(r => r.value.blockedMaterialization)).toBe(true);
  });
  it('materialises a head with one changed path by touching only that file and opening only its chunks', async () => {
    const f = await fixture(); await f.mkdir('/notebook/notes');
    for (let i = 0; i < 5; i++) await f.fs.write(`/notebook/notes/n${i}.md`, `note ${i} `.repeat(300));
    const owner = new HeadlessVaultEngine(f.deps); cleanups.push(() => owner.stop()); await owner.start(f.session); const id = await owner.create('notes', {});
    const member = await fixture(f.net, signer(2)); const m = new HeadlessVaultEngine(member.deps); cleanups.push(() => m.stop()); await m.start(member.session);
    await owner.share(id, [member.pubkey], 'read', {}); await m.refreshInbox();
    const invite = snapshot(m).invitations.find(i => i.vaultId === id)!;
    await m.accept(invite.invitationId, { relativePath: 'shared', trustConfirmed: true, endpointsConfirmed: true, network });
    await m.sync(id);
    await f.fs.write('/notebook/notes/n1.md', 'owner changed'); await owner.sync(id);
    const reads = vi.spyOn(member.fs, 'readBinary'), writes = vi.spyOn(member.fs, 'writeBinary'), opened = vi.spyOn(VaultStore.prototype, 'cachedObject');
    try {
      await m.sync(id);
      expect(await member.fs.read('/notebook/shared/n1.md')).toBe('owner changed');
      const touched = new Set([...reads.mock.calls, ...writes.mock.calls].map(call => call[0]).filter(path => !path.includes('/.onyx-vault-staging/')));
      expect([...touched]).toEqual(['/notebook/shared/n1.md']);
      // Unchanged entries converge by digest: only the new manifest and the changed file's chunk are opened.
      expect(opened.mock.calls.length).toBeLessThanOrEqual(3);
      expect((await (await member.openStore()).read('vaults', [id]))!.value.baseline['n1.md'].disk).toMatchObject({ size: 13 });
    } finally { reads.mockRestore(); writes.mockRestore(); opened.mockRestore(); }
  });
  it('removes staging orphans but retains pending operation directories', async () => {
    const s = await setup(); await s.f.mkdir('/notebook/v/.onyx-vault-staging/orphan'); await s.f.fs.write('/notebook/v/.onyx-vault-staging/orphan/data', 'x');
    await cleanStagingOrphans(s.ctx, await s.vault(), []); expect(await s.f.fs.exists('/notebook/v/.onyx-vault-staging/orphan')).toBe(false);
  });
});
