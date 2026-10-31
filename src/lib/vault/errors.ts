export const VAULT_ERROR_MESSAGES = {
  ARG: 'Invalid vault data or argument',
  VERSION: 'Unsupported vault protocol version',
  AUTH: 'Service authorisation required',
  CRYPTO: 'Vault data could not be authenticated',
  HASH_MISMATCH: 'Downloaded data does not match its address',
  EPOCH: 'Updated access key required',
  POLICY: 'Vault policy does not permit this operation',
  CONFLICT: 'Vault changes require conflict resolution',
  INCOMPLETE: 'Required vault data is unavailable',
  BUDGET: 'Vault operation reached its bandwidth budget',
  TOO_LARGE: 'Vault data exceeds a supported limit',
  IO: 'Vault file operation failed',
  NETWORK: 'Vault service could not be reached',
  UNSUPPORTED: 'This vault operation is not supported',
  STORAGE: 'Vault storage is unavailable',
  CANCELLED: 'Vault operation was cancelled',
} as const;

export type VaultErrorCode = keyof typeof VAULT_ERROR_MESSAGES;
export type VaultOperation =
  | 'validate' | 'derive' | 'encode' | 'decode' | 'seal' | 'open'
  | 'fetch' | 'upload' | 'publish' | 'subscribe' | 'store' | 'recover'
  | 'start' | 'stop' | 'create' | 'capture' | 'share' | 'accept' | 'attach'
  | 'sync' | 'fold' | 'materialize' | 'revoke' | 'reseal' | 'resolve'
  | 'detach' | 'handover';

export interface VaultErrorDisplay {
  readonly code: VaultErrorCode;
  readonly operation: VaultOperation | null;
  readonly retryable: boolean;
  readonly message: string;
}

/** Fixed display text only: never attach keys, grant/head bodies, paths or headers. */
export class VaultError extends Error {
  readonly code: VaultErrorCode;
  readonly operation: VaultOperation | null;
  readonly retryable: boolean;

  constructor(code: VaultErrorCode, options: {
    operation?: VaultOperation;
    retryable?: boolean;
    reason?: 'history-unavailable' | 'history-incomplete' | 'ledger-too-large' | 'fork-budget' | 'conflict-budget' | 'stale-checkpoint'
      | 'key-approval-required' | 'weak-passphrase' | 'kdf-cost' | 'recovery-vault-mismatch' | 'inbox-capacity';
  } = {}) {
    super(options.reason === 'history-unavailable' ? 'History unavailable from this owner. Ask the owner for historical access data.' :
      options.reason === 'history-incomplete' ? 'The newest access-history record for this vault has not been received; historical content stays unavailable until it arrives.' :
      options.reason === 'ledger-too-large' ? 'Vault epoch history exceeds the 65535-byte limit. Create a new vault before rotating access again.' :
      options.reason === 'fork-budget' ? 'A writer published more competing versions at one sequence than this vault admits. The extra version was quarantined.' :
      options.reason === 'conflict-budget' ? 'Competing proposals exceed this vault\'s conflict budget. The last verified view is kept; resolve conflicts or revoke the writer before syncing again.' :
      options.reason === 'stale-checkpoint' ? 'A newer owner checkpoint is known to exist but was not served. Refusing to roll the vault back.' :
      options.reason === 'key-approval-required' ? 'The recipient announced a different device key. Verify its fingerprint out of band and approve it before sharing.' :
      options.reason === 'weak-passphrase' ? 'Recovery passphrase is too weak. Use the generated passphrase or at least 12 characters that are not a common pattern.' :
      options.reason === 'kdf-cost' ? 'Recovery package requests an unsupported key-derivation cost and was not opened.' :
      options.reason === 'recovery-vault-mismatch' ? 'Recovery package belongs to a different vault than expected.' :
      options.reason === 'inbox-capacity' ? 'Invitation inbox at capacity — new invitations are not being ingested. Shared vaults keep syncing. Use "Repair invitation inbox" to compact replay storage; no invitation decision is evicted.' : VAULT_ERROR_MESSAGES[code]);
    this.name = 'VaultError';
    this.code = code;
    this.operation = options.operation ?? null;
    this.retryable = options.retryable ?? ['IO', 'NETWORK', 'STORAGE', 'INCOMPLETE'].includes(code);
  }

  toDisplay(): VaultErrorDisplay {
    return {
      code: this.code,
      operation: this.operation,
      retryable: this.retryable,
      message: this.message,
    };
  }
}
