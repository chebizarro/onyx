import { describe, expect, it, vi } from 'vitest';
import { finalizeEvent, getPublicKey, type UnsignedEvent } from 'nostr-tools';
import { bytes32, decryptNip44, deriveHeadConversationKey, encryptNip44, hex32 } from '../crypto';
import { buildEpochLedgerEvent, decodeEpochLedger, encodeEpochLedger, ledgerWithHeads, openEpochLedgerEvent, type EpochLedger } from '../epoch-ledger';
import { appendRing, initRing } from '../ring';
import type { Address, Pubkey, VaultHead, VaultId } from '../types';

const secret = bytes32(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
const owner = hex32<Pubkey>(getPublicKey(secret)), vaultId = hex32<VaultId>('ab'.repeat(32));
const key1 = bytes32(new Uint8Array(32).fill(0x11)), key2 = bytes32(new Uint8Array(32).fill(0x22));
const ring = appendRing(initRing(1n, key1), key2);
const ledger: EpochLedger = { v: 1, vaultId, epochs: [
  { epoch: 1n, rootManifest: hex32<Address>('01'.repeat(32)), keyOverride: null, writtenAt: 1n },
  { epoch: 2n, rootManifest: hex32<Address>('02'.repeat(32)), keyOverride: '22'.repeat(32), writtenAt: 2n },
] };
const sign = (event: UnsignedEvent) => finalizeEvent(event, secret);

describe('Onyx-private owner epoch ledger', () => {
  it('round-trips strict bigint JSON and a signed head-key-encrypted record', () => {
    const json = encodeEpochLedger(ledger);
    expect(json).toBe(`{"v":1,"vault_id":"${vaultId}","epochs":[{"epoch":1,"root_manifest":"${'01'.repeat(32)}","key_override":null,"written_at":1},{"epoch":2,"root_manifest":"${'02'.repeat(32)}","key_override":"${'22'.repeat(32)}","written_at":2}]}`);
    expect(decodeEpochLedger(json)).toEqual(ledger);
    expect(decodeEpochLedger(` ${json} \n`)).toEqual(ledger);
    const event = sign(buildEpochLedgerEvent(ledger, ring, owner, 2n));
    expect(event.tags).toEqual([['d', `onyx/vault-history/${vaultId}`], ['epoch', '2']]);
    expect(event.kind).toBe(30078);
    expect(openEpochLedgerEvent(event, vaultId, owner, ring)).toEqual(ledger);
  });
  it.each([
    (s: string) => s.replace('"v":1', '"v":1,"v":1'),
    (s: string) => s.replace('"v":1', '"v":1,"unknown":0'),
    (s: string) => s.replace('"v":1,', ''),
    (s: string) => s.replace('"epoch":1', '"epoch":0'),
    (s: string) => s.replace('"epoch":1', '"epoch":01'),
    (s: string) => s.replace('"epoch":1', '"epoch":1e0'),
    (s: string) => s.replace('"epoch":1', '"epoch":1.0'),
    (s: string) => s.replace('"epoch":1', '"epoch":-1'),
    (s: string) => s.replace('"epoch":2', '"epoch":1'),
    (s: string) => s.replace('"epoch":2', '"epoch":3'),
    (s: string) => s.replace('"written_at":1', '"written_at":9223372036854775808'),
    (s: string) => s.replace('"written_at":1', '"written_at":18446744073709551616'),
    (s: string) => s.replace('"key_override":null,', ''),
    (s: string) => s.replace('null', 'nullx'),
    (s: string) => s.replace('null', '"bad"'),
    (s: string) => s.replace('abab', 'ABAB'),
    (s: string) => s.replace('abab', '\\u0061bab'),
    (s: string) => s + '{}',
    (s: string) => s + '\u0000',
  ])('rejects malformed or non-strict JSON (%#)', mutate => {
    expect(() => decodeEpochLedger(mutate(encodeEpochLedger(ledger)))).toThrow();
  });
  it('preserves uint64 parsing and refuses unsupported versions and empty histories', () => {
    expect(() => decodeEpochLedger(encodeEpochLedger(ledger).replace('"v":1', '"v":2'))).toThrowError(expect.objectContaining({ code: 'VERSION' }));
    expect(() => decodeEpochLedger(`{"v":1,"vault_id":"${vaultId}","epochs":[]}`)).toThrow();
  });
  it('decrypts exactly once using only the declared epoch; never falls back', () => {
    const unsigned = buildEpochLedgerEvent(ledger, ring, owner, 2n), decrypt = vi.fn(decryptNip44);
    expect(openEpochLedgerEvent(sign(unsigned), vaultId, owner, ring, decrypt)).toEqual(ledger);
    expect(decrypt).toHaveBeenCalledTimes(1);
    decrypt.mockClear();
    const wrongEpoch = sign({ ...unsigned, tags: [unsigned.tags[0], ['epoch', '1']] });
    expect(() => openEpochLedgerEvent(wrongEpoch, vaultId, owner, ring, decrypt)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
    expect(decrypt).toHaveBeenCalledTimes(1);
    decrypt.mockClear();
    const unknownEpoch = sign({ ...unsigned, tags: [unsigned.tags[0], ['epoch', '3']] });
    expect(() => openEpochLedgerEvent(unknownEpoch, vaultId, owner, ring, decrypt)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    expect(decrypt).not.toHaveBeenCalled();
  });
  it('rejects a declared epoch/body mismatch after one decryption', () => {
    const unsigned = buildEpochLedgerEvent(ledger, ring, owner, 2n), key = deriveHeadConversationKey(key1);
    const event = sign({ ...unsigned, tags: [unsigned.tags[0], ['epoch', '1']], content: encryptNip44(encodeEpochLedger(ledger), key) }); key.fill(0);
    const decrypt = vi.fn(decryptNip44);
    expect(() => openEpochLedgerEvent(event, vaultId, owner, ring, decrypt)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    expect(decrypt).toHaveBeenCalledTimes(1);
  });
  it('rejects a non-owner author even with the correct head key, before decryption', () => {
    const other = bytes32(new Uint8Array(32).fill(3)), unsigned = buildEpochLedgerEvent(ledger, ring, owner, 2n);
    const event = finalizeEvent(unsigned, other), decrypt = vi.fn(decryptNip44);
    expect(() => openEpochLedgerEvent(event, vaultId, owner, ring, decrypt)).toThrowError(expect.objectContaining({ code: 'AUTH' }));
    expect(decrypt).not.toHaveBeenCalled();
  });
  it('rejects a mutated cached signature and missing/duplicate/noncanonical epoch tags before decryption', () => {
    const unsigned = buildEpochLedgerEvent(ledger, ring, owner, 2n), decrypt = vi.fn(decryptNip44);
    const event = sign(unsigned); event.content += 'a';
    expect(() => openEpochLedgerEvent(event, vaultId, owner, ring, decrypt)).toThrow();
    for (const tags of [[unsigned.tags[0]], [...unsigned.tags, ['epoch', '2']], [unsigned.tags[0], ['epoch', '02']], [unsigned.tags[0], ['epoch', '18446744073709551616']]])
      expect(() => openEpochLedgerEvent(sign({ ...unsigned, tags }), vaultId, owner, ring, decrypt)).toThrow();
    expect(decrypt).not.toHaveBeenCalled();
  });
  it('rejects wrong vault ids and overrides instead of importing their root evidence', () => {
    const bad = { ...ledger, epochs: ledger.epochs.map(e => ({ ...e, keyOverride: '33'.repeat(32) })) };
    expect(() => openEpochLedgerEvent(sign(buildEpochLedgerEvent(bad, ring, owner, 2n)), vaultId, owner, ring)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    const badVault = { ...ledger, vaultId: hex32<VaultId>('cd'.repeat(32)) }, unsigned = buildEpochLedgerEvent(badVault, ring, owner, 2n);
    expect(() => openEpochLedgerEvent(sign({ ...unsigned, tags: [['d', `onyx/vault-history/${vaultId}`], ['epoch', '2']] }), vaultId, owner, ring)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
  });
  it.each([2n, 1n])('selects the outgoing checkpoint by owner sequence, not written_at=%s; freezes completed epochs', writtenAt => {
    const head = (epoch: bigint, seq: bigint, time: bigint, root: number): VaultHead => ({ vaultId, epoch, seq, writtenAt: time, rootManifest: hex32<Address>(root.toString(16).padStart(2, '0').repeat(32)), grantsRev: 1n, parents: [] });
    const selected = head(2n, 9n, writtenAt, 9), earlier = head(2n, 8n, 2n, 8), next = head(3n, 10n, 3n, 10);
    for (const heads of [[earlier, selected, next], [selected, earlier, next]]) {
      const result = ledgerWithHeads(vaultId, ledger, [head(1n, 100n, 100n, 100), ...heads]);
      expect(result.epochs[0]).toEqual(ledger.epochs[0]);
      expect(result.epochs[1].rootManifest).toBe(selected.rootManifest);
      const frozen = ledgerWithHeads(vaultId, result, [head(2n, 101n, 101n, 101)]);
      expect(frozen.epochs[1]).toEqual(result.epochs[1]);
    }
  });
  it('rejects conflicting same-sequence checkpoint evidence', () => {
    const head: VaultHead = { vaultId, epoch: 2n, seq: 1n, writtenAt: 1n, rootManifest: ledger.epochs[1].rootManifest, grantsRev: 1n, parents: [] };
    expect(() => ledgerWithHeads(vaultId, ledger, [head, { ...head, rootManifest: ledger.epochs[0].rootManifest }])).toThrowError(expect.objectContaining({ code: 'CONFLICT' }));
  });
  it('preflights the entire proposed history before encryption, signing or publication', () => {
    const oversized: EpochLedger = { v: 1, vaultId, epochs: Array.from({ length: 400 }, (_, i) => ({ ...ledger.epochs[1], epoch: BigInt(i + 1) })) };
    expect(() => encodeEpochLedger(oversized)).toThrowError(expect.objectContaining({ code: 'TOO_LARGE', message: expect.stringContaining('Create a new vault') }));
    expect(() => ledgerWithHeads(vaultId, oversized, [])).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    expect(() => buildEpochLedgerEvent(oversized, ring, owner, 2n)).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
  });
});
