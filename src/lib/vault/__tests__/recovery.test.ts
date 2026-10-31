import { afterEach, describe, expect, it, vi } from 'vitest';
import { nip19 } from 'nostr-tools';
import * as nip49 from 'nostr-tools/nip49';
import * as scryptModule from '@noble/hashes/scrypt.js';
import { openRecovery } from '../store';
import {
  assertRecoveryPassphrase, calibrateRecoveryLogn, decryptNcryptsec, encryptNcryptsec, generateRecoveryPassphrase, parseNcryptsec,
  RECOVERY_CALIBRATED_LOGN, RECOVERY_EXPORT_LOGN, RECOVERY_MAX_LOGN, RECOVERY_MIN_PASSPHRASE_LENGTH, scryptMemoryBytes,
} from '../recovery';
import type { VaultId, VaultRecoveryPackage } from '../types';

vi.mock('@noble/hashes/scrypt.js', async importOriginal => {
  const actual = await importOriginal<typeof import('@noble/hashes/scrypt.js')>();
  return { ...actual, scryptAsync: vi.fn(actual.scryptAsync) };
});
const scryptAsync = vi.mocked(scryptModule.scryptAsync);
afterEach(() => { scryptAsync.mockClear(); });

const secret = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const vaultId = 'b'.repeat(64) as VaultId;
/** A syntactically valid wrapper advertising an arbitrary cost; its ciphertext is garbage. */
function craftedWrapper(logn: number): string {
  const bytes = new Uint8Array(91); bytes[0] = 2; bytes[1] = logn;
  for (let i = 2; i < bytes.length; i++) bytes[i] = (i * 7) & 0xff;
  return nip19.encodeBytes('ncryptsec' as never, bytes) as unknown as string;
}
function packageWith(ncryptsec: string): VaultRecoveryPackage {
  return { format: 'onyx-vault-recovery', version: 1, ncryptsec, payload: { nonce: '00'.repeat(12), ciphertext: '00'.repeat(48) } };
}

describe('NIP-49 compatible recovery wrapper (SV-34)', () => {
  it('exports at logn 17 by default, interoperates with nostr-tools and refuses sub-floor export costs', async () => {
    const wrapped = await encryptNcryptsec(secret, 'strong export passphrase');
    expect(parseNcryptsec(wrapped)).toMatchObject({ logn: RECOVERY_EXPORT_LOGN, keySecurityByte: 2 });
    expect(nip49.decrypt(wrapped, 'strong export passphrase')).toEqual(secret);
    expect(await decryptNcryptsec(wrapped, 'strong export passphrase')).toEqual(secret);
    await expect(decryptNcryptsec(wrapped, 'wrong passphrase 123')).rejects.toMatchObject({ code: 'CRYPTO' });
    // Packages written by the dependency default (2^16) still open.
    expect(await decryptNcryptsec(nip49.encrypt(secret, 'legacy passphrase xyz'), 'legacy passphrase xyz')).toEqual(secret);
    await expect(encryptNcryptsec(secret, 'strong export passphrase', 16)).rejects.toMatchObject({ code: 'ARG' });
    await expect(encryptNcryptsec(secret, 'strong export passphrase', RECOVERY_MAX_LOGN + 1)).rejects.toMatchObject({ code: 'ARG' });
    expect(scryptMemoryBytes(RECOVERY_MAX_LOGN)).toBe(256 * 1024 * 1024);
  }, 30000);

  it('refuses costs above the 256 MiB ceiling before any key derivation', async () => {
    for (const logn of [19, 20, 21, 31, 255]) {
      expect(() => parseNcryptsec(craftedWrapper(logn))).toThrow(expect.objectContaining({ code: 'UNSUPPORTED', message: expect.stringContaining('key-derivation cost') }));
      await expect(openRecovery(packageWith(craftedWrapper(logn)), 'any passphrase at all', { vaultId })).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    }
    expect(() => parseNcryptsec(craftedWrapper(15))).toThrow(expect.objectContaining({ code: 'UNSUPPORTED' }));
    expect(scryptAsync).not.toHaveBeenCalled();
    // In range: parse succeeds without deriving; the derive happens only in decrypt and then fails authentication.
    expect(parseNcryptsec(craftedWrapper(17)).logn).toBe(17);
    expect(scryptAsync).not.toHaveBeenCalled();
    await expect(openRecovery(packageWith(craftedWrapper(16)), 'any passphrase at all', { vaultId })).rejects.toMatchObject({ code: 'CRYPTO' });
    expect(scryptAsync).toHaveBeenCalledTimes(1);
    expect(scryptAsync.mock.calls[0][2]).toMatchObject({ N: 2 ** 16, r: 8, p: 1, dkLen: 32 });
    expect(scryptAsync.mock.calls[0][2].maxmem).toBeLessThan(1024 ** 3);
  }, 30000);

  it('rejects malformed wrappers, oversized payloads and a missing expected vault without deriving', async () => {
    for (const bad of ['', 'npub1xyz', 'ncryptsec1' + 'q'.repeat(50), 'NCRYPTSEC1Qq' + 'q'.repeat(150), craftedWrapper(17).slice(0, -1) + (craftedWrapper(17).endsWith('q') ? 'p' : 'q')]) {
      expect(() => parseNcryptsec(bad)).toThrow(expect.objectContaining({ code: 'ARG' }));
    }
    const wrapped = await encryptNcryptsec(secret, 'strong export passphrase');
    await expect(openRecovery({ ...packageWith(wrapped), payload: { nonce: '00'.repeat(12), ciphertext: '0'.repeat(2 * 4 * 1024 * 1024 + 2) } }, 'strong export passphrase', { vaultId })).rejects.toMatchObject({ code: 'TOO_LARGE' });
    await expect(openRecovery(packageWith(wrapped), 'strong export passphrase', { vaultId: 'nope' as VaultId })).rejects.toMatchObject({ code: 'ARG' });
    await expect(openRecovery({ ...packageWith(wrapped), format: 'other' } as unknown as VaultRecoveryPackage, 'strong export passphrase', { vaultId })).rejects.toMatchObject({ code: 'VERSION' });
    expect(scryptAsync).toHaveBeenCalledTimes(1); // only the export above derived
  }, 30000);
});

describe('recovery passphrase policy', () => {
  it('accepts generated and reasonable passphrases and rejects weak patterns', () => {
    const generated = generateRecoveryPassphrase();
    expect(generated).toMatch(/^[a-z2-9]{5}(-[a-z2-9]{5}){5}$/);
    expect(generated).not.toBe(generateRecoveryPassphrase());
    expect(() => assertRecoveryPassphrase(generated)).not.toThrow();
    expect(() => assertRecoveryPassphrase('correct horse battery staple')).not.toThrow();
    expect(() => assertRecoveryPassphrase('Tr0ub4dor&3 is fine')).not.toThrow();
    for (const weak of ['', 'x'.repeat(RECOVERY_MIN_PASSPHRASE_LENGTH - 1), 'aaaaaaaaaaaaaaaaaaaa', 'abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlk', '123456789012', 'password-1234', 'PassPhrase!!', 'abcabcabcabcabcabc', 'ababababababab']) {
      expect(() => assertRecoveryPassphrase(weak)).toThrow(expect.objectContaining({ code: 'ARG', message: expect.stringContaining('too weak') }));
    }
    // Deterministic rng: the output is a pure function of the random bytes.
    expect(generateRecoveryPassphrase(n => new Uint8Array(n))).toBe('aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa');
    expect(generateRecoveryPassphrase(n => Uint8Array.from({ length: n }, (_, i) => i))).toBe('abcde-fghij-kmnpq-rstuv-wxyz2-34567');
  });

  it('calibrates to logn 18 only when the probe predicts the derive fits the budget', async () => {
    expect(await calibrateRecoveryLogn({ probe: async () => 50 })).toBe(RECOVERY_CALIBRATED_LOGN);   // 50 ms * 8 = 400 ms
    expect(await calibrateRecoveryLogn({ probe: async () => 200 })).toBe(RECOVERY_EXPORT_LOGN);     // 1.6 s
    expect(await calibrateRecoveryLogn({ probe: async () => Number.NaN })).toBe(RECOVERY_EXPORT_LOGN);
    const probe = vi.fn(async (logn: number) => { expect(logn).toBe(15); return 10; });
    expect(await calibrateRecoveryLogn({ probe, budgetMs: 50 })).toBe(RECOVERY_EXPORT_LOGN);
    const real = await calibrateRecoveryLogn({ fresh: true });
    expect([RECOVERY_EXPORT_LOGN, RECOVERY_CALIBRATED_LOGN]).toContain(real);
  });
});
