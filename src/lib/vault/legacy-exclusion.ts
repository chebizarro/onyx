import type { PlatformName } from '../../platform/types';
import type { MountRegistry } from './types';

const RESERVED_NAMES = ['.onyx-vault-conflicts', '.onyx-vault-staging'];

interface ComponentPath {
  root: string;
  components: string[];
}

function componentPath(path: string, platform?: PlatformName): ComponentPath {
  const slashes = path.normalize('NFC').replace(/\\/g, '/');
  const windows = platform === 'windows' || (platform === undefined && /^(?:[a-z]:|\/\/)/i.test(slashes));
  const normalized = windows || platform === 'macos' ? slashes.toLowerCase() : slashes;
  const drive = /^[a-z]:/i.exec(normalized)?.[0];
  const root = drive ? `${drive}${normalized[2] === '/' ? '/' : ''}`
    : normalized.startsWith('//') ? '//' : normalized.startsWith('/') ? '/' : '';
  const tail = drive ? normalized.slice(drive.length) : normalized;
  const components: string[] = [];
  for (const component of tail.split('/')) {
    if (!component || component === '.') continue;
    if (component === '..' && components.length && components[components.length - 1] !== '..') {
      components.pop();
    } else if (component !== '..' || !root) {
      components.push(component);
    }
  }
  return { root, components };
}

function contains(parent: ComponentPath, child: ComponentPath): boolean {
  return parent.root === child.root && parent.components.length <= child.components.length
    && parent.components.every((component, index) => component === child.components[index]);
}

function reserved(path: ComponentPath): boolean {
  return path.components.some(component => RESERVED_NAMES.includes(component));
}

function mountStrings(registry: MountRegistry): string[] {
  return registry.getMounts().map(mount => `${mount.notebookPath.replace(/[\\/]+$/, '')}/${mount.relativePath}`);
}

function mountPaths(registry: MountRegistry, platform?: PlatformName): ComponentPath[] {
  return mountStrings(registry).map(mount => componentPath(mount, platform));
}

/**
 * Paths are notebook-qualified (absolute on desktop, OPFS-qualified on web).
 * Both separator spellings are accepted and Unicode is NFC-normalised.
 * Windows and macOS compare without case; other platforms preserve case. Drive/UNC paths infer Windows when omitted.
 * Reserved artifact components are excluded even before a mount is registered.
 */
export function isManagedPath(path: string, registry: MountRegistry, platform?: PlatformName): boolean {
  const candidate = componentPath(path, platform);
  return reserved(candidate) || mountPaths(registry, platform).some(mount => contains(mount, candidate));
}

/** Preserve the order and spelling of paths that legacy orchestration may use. */
export function filterLegacyPaths(paths: readonly string[], registry: MountRegistry, platform?: PlatformName): string[] {
  return paths.filter(path => !isManagedPath(path, registry, platform));
}

/** Guard directory operations too: an ancestor of a managed mount intersects it. */
export function intersectsManagedMount(path: string, registry: MountRegistry, platform?: PlatformName): boolean {
  const candidate = componentPath(path, platform);
  return reserved(candidate) || mountPaths(registry, platform).some(mount =>
    contains(mount, candidate) || contains(candidate, mount));
}

/** Filesystem identity of a path (see `VaultFS.realPath`), or null when unknown. */
export type RealPath = (path: string) => Promise<string | null>;

export interface ManagedPathResolver {
  /** The lexical check first; then, where the backend can answer, identity. */
  isManaged(path: string): Promise<boolean>;
  /** Filesystem identity of `path`, or null when the backend cannot say. */
  identity(path: string): Promise<string | null>;
  /** Whether an already-resolved identity lies in a mount; no further resolution.
   * Lets a walker that resolved an aliased directory once decide for every
   * descendant by spelling (`identity + remainder`) instead of one call each. */
  isManagedIdentity(identity: string): Promise<boolean>;
}

/**
 * Spelling cannot see `notebook/Alias -> notebook/Shared`: `isManagedPath` says
 * `Alias/private.md` is unmanaged while reading or writing it reaches the mount
 * (H6, SV-42). This resolver keeps the lexical check as the fast path and, when
 * it says no, compares the path's canonical form with each mount's canonical
 * form, caching the latter for the resolver's lifetime — create one per sync
 * run. An alias may also point at an *ancestor* of a mount (`Alias -> Parent`
 * with the mount at `Parent/Shared`): the alias itself resolves outside every
 * mount while its ordinary descendants resolve inside one, so a walker must
 * carry the alias identity down and ask `isManagedIdentity` per descendant.
 * A path whose identity the backend cannot establish is not proven unmanaged, so
 * it is treated as managed (fail closed); only without any `realPath` helper
 * (OPFS has no aliases) is the check purely lexical. Mount identities are cached
 * once resolved; a failed lookup is retried, never cached.
 * Hard links are out of scope: they share an inode, not a path.
 */
export function createManagedPathResolver(registry: MountRegistry, platform?: PlatformName, realPath?: RealPath): ManagedPathResolver {
  const resolve = async (path: string): Promise<string | null> => {
    try { return (await realPath?.(path)) ?? null; } catch { return null; }
  };
  const mountIdentities = new Map<string, Promise<string | null>>();
  const mountIdentity = (mount: string): Promise<string | null> => {
    let pending = mountIdentities.get(mount);
    if (!pending) {
      pending = resolve(mount).then(identity => { if (identity === null) mountIdentities.delete(mount); return identity; });
      mountIdentities.set(mount, pending);
    }
    return pending;
  };
  const isManagedIdentity = async (identity: string): Promise<boolean> => {
    const candidate = componentPath(identity, platform);
    if (reserved(candidate)) return true;
    for (const mount of mountStrings(registry)) {
      if (contains(componentPath(mount, platform), candidate)) return true;
      const target = await mountIdentity(mount);
      if (target !== null && contains(componentPath(target, platform), candidate)) return true;
    }
    return false;
  };
  return {
    identity: path => (realPath ? resolve(path) : Promise.resolve(null)),
    isManagedIdentity,
    async isManaged(path) {
      if (isManagedPath(path, registry, platform)) return true;
      if (!realPath) return false;
      const identity = await resolve(path);
      return identity === null || isManagedIdentity(identity);
    },
  };
}
