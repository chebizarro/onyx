import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createManagedPathResolver, filterLegacyPaths, intersectsManagedMount, isManagedPath } from '../legacy-exclusion';
import type { MountRegistry, VaultId } from '../types';

function registry(notebookPath = '/notes', relativePath = 'shared/project'): MountRegistry {
  return { getMounts: () => [{ vaultId: '00'.repeat(32) as VaultId, notebookPath, relativePath }] };
}

const mounts = registry();
const empty: MountRegistry = { getMounts: () => [] };

describe('legacy managed-path exclusion', () => {
  it.each([
    ['/notes/shared/project', true],
    ['/notes/shared/project/', true],
    ['/notes/shared/project/nested/note.md', true],
    ['/notes/shared/project-extra/note.md', false],
    ['/notes/shared/project.md', false],
    ['/notes-extra/shared/project/note.md', false],
    ['/notes/shared', false],
    ['/notes/Shared/project', false],
  ])('matches whole path components: %s', (path, expected) => {
    expect(isManagedPath(path, mounts)).toBe(expected);
  });

  it('accepts mixed separators and trailing separators in mounts and paths', () => {
    const mixed = registry('/notes\\', 'shared\\project/');
    expect(isManagedPath('\\notes/shared\\project\\nested/file.txt', mixed)).toBe(true);
    expect(isManagedPath('/notes/shared/project-other', mixed)).toBe(false);
  });

  it('normalizes dot components before comparison', () => {
    expect(isManagedPath('/notes/other/../shared/./project/note.txt', mounts)).toBe(true);
    expect(isManagedPath('/notes/shared/project/../outside.md', mounts)).toBe(false);
  });

  it('compares Windows drives and components without case', () => {
    const windows = registry('C:\\Notes\\', 'Shared\\Project');
    expect(isManagedPath('c:/NOTES/shared/PROJECT/file.bin', windows)).toBe(true);
    expect(isManagedPath('D:/Notes/Shared/Project/file.bin', windows)).toBe(false);
    expect(isManagedPath('C:/Notes/Shared/Project-extra', windows)).toBe(false);
    expect(isManagedPath('c:/notes/shared/project', windows, 'linux')).toBe(false);
  });

  it.each(['macos', 'windows', 'linux', 'web'] as const)('normalises both sides to NFC on %s', platform => {
    const composed = registry('/notes', 'Café');
    const decomposed = registry('/notes', 'Cafe\u0301');
    expect(isManagedPath('/notes/Cafe\u0301/file', composed, platform)).toBe(true);
    expect(isManagedPath('/notes/Café/file', decomposed, platform)).toBe(true);
    expect(intersectsManagedMount('/notes', decomposed, platform)).toBe(true);
    expect(isManagedPath('/notes/CAFÉ/file', composed, platform)).toBe(['macos', 'windows'].includes(platform));
    expect(isManagedPath('/notes/Café-sibling/file', composed, platform)).toBe(false);
  });

  it('handles UNC shares without confusing another server or share', () => {
    const unc = registry('\\\\server\\Notes\\', 'Shared');
    expect(isManagedPath('//SERVER/notes/shared/file', unc)).toBe(true);
    expect(isManagedPath('//other/Notes/Shared/file', unc)).toBe(false);
    expect(isManagedPath('//server/Notes2/Shared/file', unc)).toBe(false);
  });

  it('supports OPFS notebook-qualified paths and explicit Windows platform', () => {
    const web = registry('onyx-vault/', 'Shared/');
    expect(isManagedPath('onyx-vault/Shared/file.txt', web, 'web')).toBe(true);
    expect(isManagedPath('other/Shared/file.txt', web, 'web')).toBe(false);
    expect(isManagedPath('/NOTES/SHARED/PROJECT/file', mounts, 'windows')).toBe(true);
    expect(isManagedPath('/NOTES/SHARED/PROJECT/file', mounts, 'macos')).toBe(true);
  });

  it.each(['.onyx-vault-conflicts', '.onyx-vault-staging'])('excludes reserved component %s independently of mounts', name => {
    expect(isManagedPath(`/notes/${name}/id/file.md`, empty)).toBe(true);
    expect(isManagedPath(`notes\\nested\\${name}\\`, empty)).toBe(true);
    expect(intersectsManagedMount(`/notes/${name}`, empty)).toBe(true);
    expect(isManagedPath(`/notes/${name}-user/file.md`, empty)).toBe(false);
    expect(isManagedPath(`/notes/prefix${name}/file.md`, empty)).toBe(false);
  });

  it('does not exclude arbitrary dotfiles or unreserved .onyx-vault-* names', () => {
    expect(filterLegacyPaths(['/notes/.config/file', '/notes/.onyx-vault-user/note'], empty))
      .toEqual(['/notes/.config/file', '/notes/.onyx-vault-user/note']);
  });

  it.each([
    ['/notes', true],
    ['/notes/shared/', true],
    ['/notes/shared/project', true],
    ['/notes/shared/project/nested', true],
    ['/notes/shared/project-extra', false],
    ['/notes/other', false],
    ['/notes-extra', false],
  ])('guards intersecting directory operations: %s', (path, expected) => {
    expect(intersectsManagedMount(path, mounts)).toBe(expected);
  });

  it('filters multiple mounts without changing retained path order or spelling', () => {
    const multiple: MountRegistry = {
      getMounts: () => [...mounts.getMounts(), ...registry('/notes', 'second').getMounts()],
    };
    const paths = ['/notes/keep.md', '/notes/shared/project/a', '/notes/second/b', '/notes/keep2.md'];
    expect(filterLegacyPaths(paths, multiple)).toEqual(['/notes/keep.md', '/notes/keep2.md']);
    expect(paths).toHaveLength(4);
  });

  it('handles a notebook mounted at filesystem root', () => {
    expect(isManagedPath('/shared/note', registry('/', 'shared'))).toBe(true);
    expect(intersectsManagedMount('/', registry('/', 'shared'))).toBe(true);
  });
});

describe('filesystem identity resolver (SV-42)', () => {
  /** Mirrors native `resolve_real_path`: the canonical path, or the canonical nearest existing ancestor plus the remainder. */
  const realPath = async (path: string): Promise<string | null> => {
    let existing = path; const missing: string[] = [];
    while (!existsSync(existing)) { missing.unshift(basename(existing)); const parent = dirname(existing); if (parent === existing) return null; existing = parent; }
    return [realpathSync(existing), ...missing].join('/');
  };

  it('reproduces the report fixture: an alias into a mount is managed by identity where spelling says otherwise', async () => {
    const root = mkdtempSync(join(tmpdir(), 'onyx-alias-'));
    try {
      const notebook = join(root, 'notebook');
      mkdirSync(join(notebook, 'Shared'), { recursive: true }); mkdirSync(join(notebook, 'Other'));
      writeFileSync(join(notebook, 'Shared/private.md'), 'secret'); writeFileSync(join(notebook, 'Other/note.md'), 'public');
      symlinkSync(join(notebook, 'Shared'), join(notebook, 'Alias'));
      const mountRegistry = registry(notebook, 'Shared');
      const resolver = createManagedPathResolver(mountRegistry, 'linux', realPath);
      // The lexical gap the report demonstrated.
      expect(isManagedPath(join(notebook, 'Alias/private.md'), mountRegistry, 'linux')).toBe(false);
      expect(intersectsManagedMount(join(notebook, 'Alias/private.md'), mountRegistry, 'linux')).toBe(false);
      // Closed by identity, for the alias itself, its contents and paths not created yet.
      expect(await resolver.isManaged(join(notebook, 'Alias/private.md'))).toBe(true);
      expect(await resolver.isManaged(join(notebook, 'Alias'))).toBe(true);
      expect(await resolver.isManaged(join(notebook, 'Alias/new/deeper.md'))).toBe(true);
      // Unrelated paths and the mount's own spelling behave as before.
      expect(await resolver.isManaged(join(notebook, 'Other/note.md'))).toBe(false);
      expect(await resolver.isManaged(join(notebook, 'Shared/private.md'))).toBe(true);
      expect(await resolver.isManaged(join(notebook, 'Missing/note.md'))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('judges descendants of an alias to a mount ancestor by the alias identity plus remainder', async () => {
    const root = mkdtempSync(join(tmpdir(), 'onyx-alias-ancestor-'));
    try {
      const notebook = join(root, 'notebook');
      mkdirSync(join(notebook, 'Parent/Shared'), { recursive: true });
      writeFileSync(join(notebook, 'Parent/Shared/private.md'), 'secret'); writeFileSync(join(notebook, 'Parent/plain.md'), 'public');
      symlinkSync(join(notebook, 'Parent'), join(notebook, 'Alias'));
      const resolver = createManagedPathResolver(registry(notebook, 'Parent/Shared'), 'linux', realPath);
      // The alias itself is not managed: it resolves to the mount's parent.
      expect(await resolver.isManaged(join(notebook, 'Alias'))).toBe(false);
      const identity = await resolver.identity(join(notebook, 'Alias'));
      expect(identity).toBe(realpathSync(join(notebook, 'Parent')));
      // What a walker does for the alias's listed children, without resolving each.
      expect(await resolver.isManagedIdentity(`${identity}/Shared`)).toBe(true);
      expect(await resolver.isManagedIdentity(`${identity}/Shared/private.md`)).toBe(true);
      expect(await resolver.isManagedIdentity(`${identity}/plain.md`)).toBe(false);
      // Full resolution of the spelled path agrees.
      expect(await resolver.isManaged(join(notebook, 'Alias/Shared/private.md'))).toBe(true);
      expect(await resolver.isManaged(join(notebook, 'Alias/plain.md'))).toBe(false);
      expect(await createManagedPathResolver(registry(notebook, 'Parent/Shared'), 'linux').identity(join(notebook, 'Alias'))).toBeNull();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('is the lexical check without an identity helper and fails closed when the helper cannot answer', async () => {
    const lexical = createManagedPathResolver(mounts);
    expect(await lexical.isManaged('/notes/alias/file.md')).toBe(false);
    expect(await lexical.isManaged('/notes/shared/project/file.md')).toBe(true);
    expect(await lexical.identity('/notes/alias')).toBeNull();
    const failing = createManagedPathResolver(mounts, undefined, async () => { throw new Error('ipc'); });
    expect(await failing.isManaged('/notes/alias/file.md')).toBe(true);
    expect(await failing.identity('/notes/alias')).toBeNull();
    const unknown = createManagedPathResolver(mounts, undefined, async () => null);
    expect(await unknown.isManaged('/notes/alias/file.md')).toBe(true);
    expect(await unknown.isManaged('/notes/other.md')).toBe(true);
  });

  it('retries a mount identity that failed to resolve instead of caching the failure', async () => {
    const calls: string[] = [];
    let failures = 1;
    // The mount is spelled `/notes/link` but lives at `/real/project`; the alias resolves straight there.
    const resolver = createManagedPathResolver(registry('/notes', 'link'), 'linux', async path => {
      calls.push(path);
      if (path === '/notes/link' && failures-- > 0) throw new Error('ipc');
      return path.replace(/^\/notes\/(?:link|alias)(?=\/|$)/, '/real/project');
    });
    expect(await resolver.isManaged('/notes/alias/file.md')).toBe(false);
    expect(await resolver.isManaged('/notes/alias/file.md')).toBe(true);
    expect(await resolver.isManaged('/notes/alias/other.md')).toBe(true);
    expect(calls.filter(path => path === '/notes/link')).toHaveLength(2);
  });

  it('compares identities with the platform rules and resolves each mount once', async () => {
    const calls: string[] = [];
    // The alias resolves into the mount, but spelled in upper case; mounts resolve to themselves.
    const shouting = async (path: string) => { calls.push(path); return path.replace(/^\/notes\/alias(?=\/|$)/, '/NOTES/SHARED/PROJECT'); };
    const macos = createManagedPathResolver(mounts, 'macos', shouting);
    expect(await macos.isManaged('/notes/alias/file.md')).toBe(true);
    expect(await macos.isManaged('/notes/alias-other/file.md')).toBe(false);
    expect(await macos.isManaged('/notes/other/.onyx-vault-conflicts/x')).toBe(true);
    expect(calls.filter(path => path === '/notes/shared/project')).toHaveLength(1);
    const linux = createManagedPathResolver(mounts, 'linux', shouting);
    expect(await linux.isManaged('/notes/alias/file.md')).toBe(false);
  });
});
