/**
 * Recovery-package key protection (SV-34).
 *
 * Byte-compatible with NIP-49 (`ncryptsec`, version 0x02, scrypt r=8 p=1 dkLen=32,
 * XChaCha20-Poly1305 with the key-security byte as AAD) but owned here so that:
 *  - exports use a pinned cost at or above the OWASP scrypt floor (N=2^17) instead of the
 *    dependency default (2^16), calibrated up to 2^18 on fast devices;
 *  - imports parse the wrapper and enforce an application cost ceiling (256 MiB) *before*
 *    any key derivation, instead of inheriting the dependency's 1 GiB bound;
 *  - derivation runs through `scryptAsync`, which yields to the event loop every ~10 ms, so
 *    a 128-256 MiB derive does not freeze the UI thread.
 *
 * Caveat that must stay in user-facing copy: a stolen export can be guessed offline forever;
 * changing the passphrase later does not protect a package that already leaked.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { nip19 } from 'nostr-tools';
import { VaultError } from './errors';

/** Export floor: scrypt N=2^17, r=8, p=1 (128 MiB) — the OWASP scrypt profile. */
export const RECOVERY_EXPORT_LOGN = 17;
/** Chosen by calibration when the device derives 2^18 in under the budget (256 MiB). */
export const RECOVERY_CALIBRATED_LOGN = 18;
/** Import ceiling: 128 * 8 * 2^18 = 256 MiB working memory. Anything above is refused unopened. */
export const RECOVERY_MAX_LOGN = 18;
/** Packages exported before SV-34 used the dependency default and still open. */
export const RECOVERY_MIN_LOGN = 16;
export const RECOVERY_MIN_PASSPHRASE_LENGTH = 12;
/** Default calibration budget: pick 2^18 only when it is expected to finish within this many ms. */
export const RECOVERY_CALIBRATION_BUDGET_MS = 1000;
export const RECOVERY_NOTES: readonly string[] = [
  'Anyone holding the file can guess the passphrase offline without limit; use the generated passphrase or one you have never used elsewhere.',
  'Changing the passphrase later does not protect a copy that has already been stolen.',
  'The package contains this vault\'s keys only, never your device-key history.',
];

const SCRYPT_R = 8, SCRYPT_P = 1, SCRYPT_DKLEN = 32;
const SALT_LENGTH = 16, NONCE_LENGTH = 24, KSB_LENGTH = 1, TAG_LENGTH = 16;
/** version || logn || salt || nonce || ksb || ciphertext(32 + tag). */
const WRAPPER_LENGTH = 1 + 1 + SALT_LENGTH + NONCE_LENGTH + KSB_LENGTH + SCRYPT_DKLEN + TAG_LENGTH;
const NCRYPTSEC_MAX_CHARS = 256;
const PASSPHRASE_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789'; // 32 symbols, 5 bits each
const PASSPHRASE_GROUPS = 6, PASSPHRASE_GROUP_LENGTH = 5;      // 150 bits
const WEAK_PASSPHRASES = new Set(['password', 'passphrase', 'passw0rd', 'qwertyuiop', 'letmein', 'recovery', 'onyxvault', 'vaultrecovery', 'iloveyou', 'trustno1', 'welcome', 'admin']);

export function scryptMemoryBytes(logn: number): number { return 128 * SCRYPT_R * 2 ** logn; }

// --- bech32 (BIP-173) decode; encoding reuses nostr-tools so the format stays identical. ---
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function bech32Polymod(values: readonly number[]): number {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= BECH32_GENERATOR[i];
  }
  return chk >>> 0;
}
function bech32Decode(text: string, maxLength: number): { prefix: string; bytes: Uint8Array } {
  if (typeof text !== 'string' || text.length < 8 || text.length > maxLength) throw new VaultError('ARG');
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) throw new VaultError('ARG');
  const lower = text.toLowerCase(), split = lower.lastIndexOf('1');
  if (split < 1 || split + 7 > lower.length) throw new VaultError('ARG');
  const prefix = lower.slice(0, split);
  for (const char of prefix) { const code = char.charCodeAt(0); if (code < 33 || code > 126) throw new VaultError('ARG'); }
  const words = [...lower.slice(split + 1)].map(char => BECH32_CHARSET.indexOf(char));
  if (words.includes(-1)) throw new VaultError('ARG');
  const expanded = [...[...prefix].map(c => c.charCodeAt(0) >>> 5), 0, ...[...prefix].map(c => c.charCodeAt(0) & 31)];
  if (bech32Polymod([...expanded, ...words]) !== 1) throw new VaultError('ARG');
  const out: number[] = [];
  let acc = 0, bits = 0;
  for (const word of words.slice(0, -6)) {
    acc = ((acc << 5) | word) & 0xfff; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((acc >>> bits) & 0xff); }
  }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xff) !== 0) throw new VaultError('ARG');
  return { prefix, bytes: Uint8Array.from(out) };
}

export interface ParsedNcryptsec {
  readonly logn: number;
  readonly salt: Uint8Array;
  readonly nonce: Uint8Array;
  readonly keySecurityByte: number;
  readonly ciphertext: Uint8Array;
}
/**
 * Structural parse only — performs no key derivation. Throws `UNSUPPORTED` (reason `kdf-cost`)
 * for a cost outside [RECOVERY_MIN_LOGN, RECOVERY_MAX_LOGN] and `ARG` for any other malformation.
 */
export function parseNcryptsec(ncryptsec: string): ParsedNcryptsec {
  const { prefix, bytes } = bech32Decode(ncryptsec, NCRYPTSEC_MAX_CHARS);
  if (prefix !== 'ncryptsec' || bytes.length !== WRAPPER_LENGTH || bytes[0] !== 0x02) throw new VaultError('ARG', { operation: 'recover' });
  const logn = bytes[1];
  if (logn < RECOVERY_MIN_LOGN || logn > RECOVERY_MAX_LOGN) throw new VaultError('UNSUPPORTED', { operation: 'recover', reason: 'kdf-cost', retryable: false });
  let offset = 2;
  const salt = bytes.slice(offset, offset += SALT_LENGTH);
  const nonce = bytes.slice(offset, offset += NONCE_LENGTH);
  const keySecurityByte = bytes[offset++];
  return { logn, salt, nonce, keySecurityByte, ciphertext: bytes.slice(offset) };
}

/** Raw derive; `maxmem` is a second fence below the dependency default (1 GiB), the wrapper parse is the first. */
function scryptDerive(passphrase: string, salt: Uint8Array, logn: number): Promise<Uint8Array> {
  return scryptAsync(passphrase.normalize('NFKC'), salt, { N: 2 ** logn, r: SCRYPT_R, p: SCRYPT_P, dkLen: SCRYPT_DKLEN,
    maxmem: 128 * SCRYPT_R * (2 ** RECOVERY_MAX_LOGN + SCRYPT_P) + 1024, asyncTick: 10 });
}
async function deriveWrapperKey(passphrase: string, salt: Uint8Array, logn: number): Promise<Uint8Array> {
  if (!Number.isInteger(logn) || logn < RECOVERY_MIN_LOGN || logn > RECOVERY_MAX_LOGN) throw new VaultError('UNSUPPORTED', { operation: 'recover', reason: 'kdf-cost', retryable: false });
  return scryptDerive(passphrase, salt, logn);
}

/** NIP-49 compatible wrapper around a 32-byte secret; the caller wipes `secret`. */
export async function encryptNcryptsec(secret: Uint8Array, passphrase: string, logn = RECOVERY_EXPORT_LOGN, rng: (length: number) => Uint8Array = n => crypto.getRandomValues(new Uint8Array(n))): Promise<string> {
  if (secret.length !== SCRYPT_DKLEN) throw new VaultError('ARG');
  if (!Number.isInteger(logn) || logn < RECOVERY_EXPORT_LOGN || logn > RECOVERY_MAX_LOGN) throw new VaultError('ARG', { operation: 'recover' });
  const salt = rng(SALT_LENGTH), nonce = rng(NONCE_LENGTH), ksb = 0x02;
  const key = await deriveWrapperKey(passphrase, salt, logn);
  try {
    const ciphertext = xchacha20poly1305(key, nonce, Uint8Array.of(ksb)).encrypt(secret);
    const wrapper = new Uint8Array(WRAPPER_LENGTH);
    wrapper.set([0x02, logn], 0); wrapper.set(salt, 2); wrapper.set(nonce, 2 + SALT_LENGTH); wrapper[2 + SALT_LENGTH + NONCE_LENGTH] = ksb;
    wrapper.set(ciphertext, 2 + SALT_LENGTH + NONCE_LENGTH + KSB_LENGTH);
    return nip19.encodeBytes('ncryptsec' as never, wrapper) as unknown as string;
  } finally { key.fill(0); }
}

/** Parses and bounds the wrapper before deriving. Wrong passphrase or tampering → `CRYPTO`. */
export async function decryptNcryptsec(ncryptsec: string, passphrase: string): Promise<Uint8Array> {
  const parsed = parseNcryptsec(ncryptsec);
  const key = await deriveWrapperKey(passphrase, parsed.salt, parsed.logn);
  try { return xchacha20poly1305(key, parsed.nonce, Uint8Array.of(parsed.keySecurityByte)).decrypt(parsed.ciphertext); }
  catch { throw new VaultError('CRYPTO', { operation: 'recover', retryable: false }); }
  finally { key.fill(0); }
}

/** Rejects clearly weak input; never logs or stores the passphrase. */
export function assertRecoveryPassphrase(passphrase: string): void {
  if (typeof passphrase !== 'string') throw new VaultError('ARG', { operation: 'recover', reason: 'weak-passphrase' });
  const normalized = passphrase.normalize('NFKC'), points = [...normalized];
  const weak = () => new VaultError('ARG', { operation: 'recover', reason: 'weak-passphrase', retryable: false });
  if (points.length < RECOVERY_MIN_PASSPHRASE_LENGTH) throw weak();
  if (new Set(points).size < 5) throw weak();
  const codes = points.map(p => p.codePointAt(0)!);
  if (codes.every((c, i) => i === 0 || c === codes[i - 1] + 1) || codes.every((c, i) => i === 0 || c === codes[i - 1] - 1)) throw weak();
  const stripped = normalized.toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
  // A common word padded with digits ("password1234") is the common word.
  if (WEAK_PASSPHRASES.has(stripped) || WEAK_PASSPHRASES.has(stripped.replace(/^\d+/, '').replace(/\d+$/, '')) || /^(\d+)$/.test(stripped) && stripped.length < 16) throw weak();
  // A short unit repeated to length (e.g. "abcabcabcabc") is one unit of entropy.
  for (let unit = 1; unit <= Math.floor(points.length / 2); unit++) {
    if (points.length % unit === 0 && points.every((p, i) => p === points[i % unit])) throw weak();
  }
}

/** 150-bit passphrase in six groups of five lowercase symbols; passes `assertRecoveryPassphrase`. */
export function generateRecoveryPassphrase(rng: (length: number) => Uint8Array = n => crypto.getRandomValues(new Uint8Array(n))): string {
  const bytes = rng(PASSPHRASE_GROUPS * PASSPHRASE_GROUP_LENGTH);
  if (bytes.length !== PASSPHRASE_GROUPS * PASSPHRASE_GROUP_LENGTH) throw new VaultError('CRYPTO');
  const groups: string[] = [];
  for (let g = 0; g < PASSPHRASE_GROUPS; g++) {
    let group = '';
    for (let i = 0; i < PASSPHRASE_GROUP_LENGTH; i++) group += PASSPHRASE_ALPHABET[bytes[g * PASSPHRASE_GROUP_LENGTH + i] & 31];
    groups.push(group);
  }
  bytes.fill(0);
  return groups.join('-');
}

let calibrated: Promise<number> | undefined;
/**
 * Picks 2^18 when a quick probe predicts it finishes within the budget, else the 2^17 floor.
 * The probe derives at 2^15 (one eighth of 2^18) and extrapolates; the result is memoised.
 */
export function calibrateRecoveryLogn(options: { probe?: (logn: number) => Promise<number>; budgetMs?: number; fresh?: boolean } = {}): Promise<number> {
  const probe = options.probe ?? (async (logn: number) => {
    const started = performance.now();
    (await scryptDerive('calibration-probe', new Uint8Array(SALT_LENGTH), logn)).fill(0);
    return performance.now() - started;
  });
  const run = async () => {
    const probeLogn = 15, probed = await probe(probeLogn);
    const predicted = probed * 2 ** (RECOVERY_CALIBRATED_LOGN - probeLogn);
    return Number.isFinite(predicted) && predicted < (options.budgetMs ?? RECOVERY_CALIBRATION_BUDGET_MS) ? RECOVERY_CALIBRATED_LOGN : RECOVERY_EXPORT_LOGN;
  };
  if (options.probe || options.fresh) return run();
  return calibrated ??= run().catch(error => { calibrated = undefined; throw error; });
}
