import { assertUint64, hex32 } from './crypto';
import { VaultError } from './errors';
import { PORTHOME_HEAD_MAX_PARENTS, VAULT_MAX_HEADS } from './protocol';
import type { Address, HeadParent, Pubkey, VaultHead, VaultId } from './types';

type HeadRecord = { readonly writer: Pubkey; readonly head: VaultHead };

/** parents.c: check every equal-sequence fork BEFORE highest-sequence reduction. */
export function mergeParents(parents: readonly HeadParent[]): readonly HeadParent[] {
  const sorted = parents.map(p => {
    hex32<Pubkey>(p.writer); hex32<Address>(p.rootManifest); assertUint64(p.seq);
    return { ...p };
  }).sort((a, b) => a.writer < b.writer ? -1 : a.writer > b.writer ? 1
    : a.seq > b.seq ? -1 : a.seq < b.seq ? 1
    : a.rootManifest < b.rootManifest ? -1 : a.rootManifest > b.rootManifest ? 1 : 0);
  for (let i = 1; i < sorted.length; i++) {
    const a = sorted[i - 1], b = sorted[i];
    if (a.writer === b.writer && a.seq === b.seq && a.rootManifest !== b.rootManifest)
      throw new VaultError('CONFLICT');
  }
  const result = sorted.filter((p, i) => i === 0 || p.writer !== sorted[i - 1].writer);
  if (result.length > PORTHOME_HEAD_MAX_PARENTS) throw new VaultError('TOO_LARGE');
  return result;
}

/** Only pass records actually incorporated by the publisher. Immutable on failure. */
export function coverHead(head: VaultHead, records: readonly HeadRecord[]): VaultHead {
  if (records.length > VAULT_MAX_HEADS) throw new VaultError('ARG');
  hex32<VaultId>(head.vaultId);
  const parents: HeadParent[] = [];
  for (const [h, writer] of [[head, undefined], ...records.map(r => [r.head, r.writer] as const)] as const) {
    if (h.vaultId !== head.vaultId || h.parents.length > PORTHOME_HEAD_MAX_PARENTS) throw new VaultError('ARG');
    parents.push(...h.parents);
    if (writer !== undefined) parents.push({ writer, seq: h.seq, rootManifest: h.rootManifest });
  }
  return { ...head, parents: mergeParents(parents) };
}

export function includeHead(head: VaultHead, previous: VaultHead, writer: Pubkey): VaultHead {
  return coverHead(head, [{ head: previous, writer }]);
}

/** Onyx §6.8: two direct tuples, not the member's whole cached history. Include
 * semantics also carry their explicit coverage; no higher-seq implicit edge. */
export function memberHeadParents(writer: Pubkey, previous: VaultHead | null,
  checkpoint: HeadRecord): readonly HeadParent[] {
  if (previous && previous.vaultId !== checkpoint.head.vaultId) throw new VaultError('ARG');
  const records: HeadRecord[] = [...(previous ? [{ writer, head: previous }] : []), checkpoint];
  return coverHead({ ...checkpoint.head, parents: [] }, records).parents;
}
