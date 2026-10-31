import { encodeUtf8 } from './crypto';
import type { StoredConflict } from './types';

/** Onyx resource budgets (SV-30). These are local admission/persistence gates,
 * not protocol constants: they decide what enters the fold and what may be
 * persisted, never the disposition of an admitted record. Overflow fails closed
 * (quarantine, explicit repair), it never selects a silent winner. Initial
 * values; calibrate on supported devices. */

/** Records (distinct canonical bodies or re-signed wrappers) admitted per (author, seq).
 * Honest writers publish one; nostrc keeps member forks as explicit frontier candidates,
 * so a small plural preserves that evidence without unbounded fetch/persist work. */
export const VAULT_MAX_RECORDS_PER_AUTHOR_SEQ = 4;
/** Owner records held below the owner's durable sequence high-water. Historical
 * owner rows are audit evidence (plan §6.8), but a relay replaying old signed
 * owner heads must not drive unbounded manifest fetches: beyond this many held
 * historical rows, further below-high-water owner heads are skipped before fetch. */
export const VAULT_MAX_OWNER_AUDIT_RECORDS = 256;
/** Unresolved fold conflict rows per vault, also the fold's own conflict-enumeration cap. */
export const VAULT_MAX_CONFLICT_ROWS = 10_000;
/** Serialized bytes of all persisted conflict rows (resolved or not) per vault. */
export const VAULT_MAX_CONFLICT_BYTES = 16 * 1024 * 1024;
/** Aggregate plaintext bytes of alternate-version artifacts written under
 * `.onyx-vault-conflicts/` per vault. Beyond this, rows are still recorded and
 * resolvable from the record tree; only the readable sibling copy is deferred. */
export const VAULT_MAX_CONFLICT_ARTIFACT_BYTES = 256 * 1024 * 1024;

export interface VaultBudgets {
  readonly recordsPerAuthorSeq: number;
  readonly ownerAuditRecords: number;
  readonly conflictRows: number;
  readonly conflictBytes: number;
  readonly conflictArtifactBytes: number;
}
export const DEFAULT_VAULT_BUDGETS: VaultBudgets = {
  recordsPerAuthorSeq: VAULT_MAX_RECORDS_PER_AUTHOR_SEQ, ownerAuditRecords: VAULT_MAX_OWNER_AUDIT_RECORDS, conflictRows: VAULT_MAX_CONFLICT_ROWS,
  conflictBytes: VAULT_MAX_CONFLICT_BYTES, conflictArtifactBytes: VAULT_MAX_CONFLICT_ARTIFACT_BYTES,
};

export function conflictRowBytes(row: StoredConflict): number {
  return encodeUtf8(JSON.stringify(row)).length;
}
