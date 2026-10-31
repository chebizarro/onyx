import { createHash } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import * as protocol from '../protocol';
import lock from '../protocol-lock.json';
import { VaultError, VAULT_ERROR_MESSAGES } from '../errors';
import helpers from '../../../../tests/fixtures/vault/helpers.json';
import ring from '../../../../tests/fixtures/vault/ring-derivation.json';
import seals from '../../../../tests/fixtures/vault/seal-v2.json';
import padding from '../../../../tests/fixtures/vault/pad-buckets.json';
import chunker from '../../../../tests/fixtures/vault/chunker.json';
import directory from '../../../../tests/fixtures/vault/dir-node.json';
import head from '../../../../tests/fixtures/vault/head.json';
import nip44 from '../../../../tests/fixtures/vault/nip44.vectors.json';
import references from '../../../../tests/fixtures/vault/reference-tests.json';

const fixtureRoot = new URL('../../../../tests/fixtures/vault/', import.meta.url);

describe('pinned shared-vault foundation (no codec implementation)', () => {
  it('exports exactly the locked constants, with bigint constants losslessly represented', () => {
    const serializable = JSON.parse(JSON.stringify(protocol, (_key, value: unknown) =>
      typeof value === 'bigint' ? value.toString() : value));
    expect(serializable).toEqual(lock.constants);
    expect(protocol.PORTHOME_HEAD_D_PREFIX + '0'.repeat(64)).toHaveLength(protocol.PORTHOME_HEAD_D_LEN - 1);
    expect(protocol.PORTHOME_NAME_TAG_LEN * 2).toBe(protocol.PORTHOME_NAME_HEX_LEN - 1);
    expect(lock.provisionalOnyxBehaviours.every((behaviour) => !behaviour.pinned)).toBe(true);
  });

  it('loads complete fixture families and verifies every imported file hash', () => {
    for (const [name, expected] of Object.entries(lock.fixtureProvenance.files)) {
      const bytes = readFileSync(new URL(name, fixtureRoot));
      expect(createHash('sha256').update(bytes).digest('hex'), name).toBe(expected);
      expect(JSON.parse(bytes.toString())).toBeTruthy();
    }
    expect(helpers.seedHex).toBe(Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join(''));
    expect(ring.keys.child).toHaveLength(64);
    expect(seals.chunks).toHaveLength(4);
    for (const vector of [...seals.chunks, seals.manifest]) {
      expect(createHash('sha256').update(Buffer.from(vector.sealedHex, 'hex')).digest('hex')).toBe(vector.address);
    }
    expect(padding.cases).toHaveLength(26);
    expect(chunker.input.generator.operations.map((op) => op.bits)).toEqual([13, 17, 5]);
    expect(chunker.cutEnds).toHaveLength(15);
    expect(chunker.insertion.cutEnds).toEqual(chunker.cutEnds.map((end) => end + 38));
    expect(directory.valid[0].cborHex.length / 2).toBe(42);
    expect(directory.valid[1].cborHex.length / 2).toBe(153);
    expect(directory.malformed).toHaveLength(824);
    const mixed = directory.valid[2].cborHex;
    const prefixes = directory.malformed.slice(19, 19 + mixed.length / 2);
    expect(prefixes.map((v) => v.cborHex)).toEqual(
      Array.from({ length: mixed.length / 2 }, (_, n) => mixed.slice(0, n * 2)),
    );
    expect(directory.malformed.every((v) => v.returnCode < 0)).toBe(true);
    expect(head.fullJson).toContain('18446744073709551615');
    expect(nip44.v2.valid.encrypt_decrypt.length).toBeGreaterThan(0);
    expect(nip44.v2.valid.encrypt_decrypt_long_msg.length).toBeGreaterThan(0);
    expect(nip44.v2.invalid.decrypt.length).toBeGreaterThan(0);
    expect(Object.keys(references.files)).toHaveLength(13);
    expect(references.commit).toBe(protocol.NOSTRC_COMMIT);
  });

  it('checks fixtures and explicitly skips an unavailable reference checkout', () => {
    const temp = mkdtempSync(join(tmpdir(), 'onyx-protocol-lock-'));
    try {
      const result = spawnSync(process.execPath, [
        fileURLToPath(new URL('../../../../scripts/verify-protocol-lock.mjs', import.meta.url)),
        join(temp, 'no-nostrc-checkout'),
      ], { encoding: 'utf8' });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain('Verified 9 fixture hashes.');
      expect(result.stdout).toContain('SKIP nostrc source hashes: checkout not found');
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('exposes only safe, fixed error display metadata', () => {
    expect(Object.keys(VAULT_ERROR_MESSAGES)).toHaveLength(16);
    expect(new VaultError('EPOCH', { operation: 'open' }).toDisplay()).toEqual({
      code: 'EPOCH', operation: 'open', retryable: false, message: 'Updated access key required',
    });
    expect(new VaultError('NETWORK').retryable).toBe(true);
  });
});
