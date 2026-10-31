import { hex32 } from './crypto';
import { VaultError } from './errors';
import { UINT64_MAX } from './protocol';
import type { Address, RetainedRoot, StoredRetainedRoot, VaultHead } from './types';

/** Parent tuples and legacy rows carry no epoch authority. Callers may retain
 * verified heads or authenticated owner-ledger evidence, never order/ring guesses. */
export function retainRootEvidence(previous: readonly StoredRetainedRoot[] | null, heads: readonly VaultHead[] = []): RetainedRoot[] {
  const roots = new Map<Address, string | null>();
  const add = (address: Address, epoch: string | null) => {
    hex32<Address>(address);
    if (epoch !== null && (!/^[1-9][0-9]*$/.test(epoch) || BigInt(epoch) > UINT64_MAX)) throw new VaultError('EPOCH');
    const held = roots.get(address);
    if (held != null && epoch !== null && held !== epoch) throw new VaultError('EPOCH');
    roots.set(address, epoch ?? held ?? null);
  };
  for (const entry of previous ?? []) {
    if (!entry) continue;
    if (typeof entry === 'string') add(entry, null);
    else add(entry.address, entry.epoch ?? null);
  }
  for (const head of heads) {
    add(head.rootManifest, String(head.epoch));
    for (const parent of head.parents) add(parent.rootManifest, null);
  }
  return [...roots].sort(([a], [b]) => a.localeCompare(b)).map(([address, epoch]) => ({ address, epoch }));
}

export function retainedRootAddresses(roots: readonly StoredRetainedRoot[] | null): Address[] {
  return retainRootEvidence(roots).map(root => root.address);
}
