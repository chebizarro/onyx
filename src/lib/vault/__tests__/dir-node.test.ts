import { describe, expect, it } from 'vitest';
import fixture from '../../../../tests/fixtures/vault/dir-node.json';
import derivation from '../../../../tests/fixtures/vault/ring-derivation.json';
import { CborReader, CborWriter } from '../cbor';
import { bytes32, bytesToHex, hex32, hexToBytes, nameEnc, sealManifest } from '../crypto';
import { decodeDirectoryNode, encodeDirectoryNode, openDirectoryNode, sealDirectoryNode } from '../dir-node';
import { VaultError } from '../errors';
import {
  PORTHOME_MAX_CBOR_BYTES, PORTHOME_MAX_ENTRIES, PORTHOME_MAX_SYMLINK_LEN,
  PORTHOME_NODE_MAX_CHUNKS, PORTHOME_VAULT_MAX_MEMBERS, UINT32_MAX, UINT64_MAX,
} from '../protocol';
import type { Address, DirectoryNode, KeyRing, NodeEntry, NodeId, Pubkey, VaultId } from '../types';

const zero = '00'.repeat(32);
const empty: DirectoryNode = { version: 2, nodeId: hex32<NodeId>(zero), epoch: 1n, entries: [] };
const oneFile: NodeEntry = {
  nameEnc: nameEnc('a'.repeat(48)), namePlain: 'file', kind: 'file', mode: 0, mtimeNs: 0n, sizePlain: 3n,
  chunks: [{ address: hex32<Address>('11' + '00'.repeat(31)), sizeSealed: 61n, chunkKeyId: 1n, sizePlain: 3n }],
};

function mixedNode(): DirectoryNode {
  const f = fixture.mixedNode;
  return {
    version: 2, nodeId: hex32<NodeId>(f.nodeIdHex), epoch: BigInt(f.epoch),
    vault: {
      vaultId: hex32<VaultId>(f.vault.vaultIdHex), owner: hex32<Pubkey>(f.vault.ownerHex),
      writers: f.vault.writersHex.map(p => hex32<Pubkey>(p)), readers: f.vault.readersHex.map(p => hex32<Pubkey>(p)),
      grantsRev: BigInt(f.vault.grantsRev),
    },
    entries: f.entries.map((e): NodeEntry => {
      const meta = { nameEnc: nameEnc(e.nameEnc), namePlain: e.namePlain, mode: e.mode, mtimeNs: BigInt(e.mtimeNs), sizePlain: BigInt(e.sizePlain) };
      if (e.kind === 'directory') return {
        ...meta, kind: 'directory', childNodeId: hex32<NodeId>(e.nodeIdHex!), childEpoch: BigInt(e.childEpoch!),
        manifestAddress: hex32<Address>(e.manifestAddress!),
        ...(e.keyOverrideHex === undefined ? {} : { keyOverride: bytes32(hexToBytes(e.keyOverrideHex)) }),
      };
      if (e.kind === 'file') return {
        ...meta, kind: 'file', chunks: e.chunks!.map(c => ({
          address: hex32<Address>(c.address), sizeSealed: BigInt(c.sizeSealed), chunkKeyId: BigInt(c.chunkKeyId), sizePlain: BigInt(c.sizePlain),
        })),
      };
      return { ...meta, kind: 'symlink', target: e.target! };
    }),
  };
}

function withEntry(entry: NodeEntry): DirectoryNode { return { ...empty, entries: [entry] }; }

function expectedNode(name: string): DirectoryNode {
  if (name === 'empty') return empty;
  if (name === 'one-file-one-chunk') return withEntry(oneFile);
  const node = mixedNode();
  if (name === 'utf8-symlink') return { ...node, entries: node.entries.map(e => e.kind === 'symlink' ? { ...e, target: fixture.validUnicode.symlink } : e) };
  if (name === 'utf8-basename') return { ...node, entries: node.entries.map((e, i) => i === 0 ? { ...e, namePlain: fixture.validUnicode.basename } : e) };
  return node;
}

describe('canonical directory-node C vectors', () => {
  it.each(fixture.valid)('matches all CBOR bytes and semantics for $name', v => {
    const expected = expectedNode(v.name);
    const bytes = hexToBytes(v.cborHex);
    expect(bytesToHex(encodeDirectoryNode(expected))).toBe(v.cborHex);
    expect(decodeDirectoryNode(bytes)).toEqual(expected);
    expect(encodeDirectoryNode(decodeDirectoryNode(bytes))).toEqual(bytes);
    if (v.name === 'one-file-one-chunk') expect(bytes.length).toBe(153);
    if (v.name === 'empty') expect(bytes.length).toBe(42);
  });

  it.each(fixture.malformed.map((v, index) => ({ ...v, index })))('refuses pinned malformed/truncated CBOR #$index', v => {
    expect(() => decodeDirectoryNode(hexToBytes(v.cborHex))).toThrow(VaultError);
  });

  it('preserves all uint64 metadata and uint32 mode without rounding', () => {
    const node = withEntry({
      ...oneFile, mode: UINT32_MAX, mtimeNs: UINT64_MAX, sizePlain: UINT64_MAX,
      chunks: [{ address: hex32<Address>(zero), sizeSealed: UINT64_MAX, chunkKeyId: UINT64_MAX, sizePlain: UINT64_MAX }],
    });
    const huge: DirectoryNode = { ...node, epoch: UINT64_MAX, vault: { ...mixedNode().vault!, grantsRev: UINT64_MAX } };
    expect(decodeDirectoryNode(encodeDirectoryNode(huge))).toEqual(huge);
  });

  it('preserves supplied entry/member order, including repeated informational members', () => {
    const node = mixedNode();
    const reversed = { ...node, entries: [...node.entries].reverse(), vault: { ...node.vault!, writers: [node.vault!.writers[1], node.vault!.writers[0], node.vault!.writers[1]] } };
    const result = decodeDirectoryNode(encodeDirectoryNode(reversed));
    expect(result).toEqual(reversed);
    expect(encodeDirectoryNode(reversed)).not.toEqual(encodeDirectoryNode(node));
  });

  it('does not normalise Unicode names or strip a UTF-8 BOM', () => {
    const entries = [
      { ...oneFile, namePlain: '\ufeffcafé' },
      { ...oneFile, nameEnc: nameEnc('b'.repeat(48)), namePlain: '\ufeffcafe\u0301' },
    ];
    expect(decodeDirectoryNode(encodeDirectoryNode({ ...empty, entries })).entries).toEqual(entries);
  });

  it('retains historical chunk sizes above the writer chunker maximum', () => {
    const f = fixture.remainingSemanticCases.historicalChunks;
    const chunks = Array.from({ length: f.count }, () => ({
      address: hex32<Address>(zero), sizeSealed: BigInt(f.sizeSealed), chunkKeyId: BigInt(f.chunkKeyId), sizePlain: BigInt(f.sizePlain),
    }));
    const node = withEntry({ ...oneFile, kind: 'file', sizePlain: BigInt(f.fileSizePlain), chunks });
    expect(decodeDirectoryNode(encodeDirectoryNode(node))).toEqual(node);
  });
});

describe('directory-node encoder validation and resource bounds', () => {
  it.each(['', '.', '..', 'a/b', 'a\\b', 'a\0b', 'x'.repeat(256), '\ud800', '\udc00'])('refuses unsafe basename %j', namePlain => {
    expect(() => encodeDirectoryNode(withEntry({ ...oneFile, namePlain }))).toThrow(VaultError);
  });

  it('refuses duplicate encrypted and plaintext names independently', () => {
    expect(() => encodeDirectoryNode({ ...empty, entries: [oneFile, { ...oneFile, namePlain: 'different' }] })).toThrow(VaultError);
    expect(() => encodeDirectoryNode({ ...empty, entries: [oneFile, { ...oneFile, nameEnc: nameEnc('b'.repeat(48)) }] })).toThrow(VaultError);
  });

  it.each(['', '/absolute', 'trailing/', './file', '../file', 'a/../b', 'a//b', 'a/./b', 'a\\b', 'a\0b', '\ud800', 'x'.repeat(PORTHOME_MAX_SYMLINK_LEN + 1)])('refuses unsafe symlink %j', target => {
    const link = mixedNode().entries[2] as Extract<NodeEntry, { kind: 'symlink' }>;
    expect(() => encodeDirectoryNode(withEntry({ ...link, target }))).toThrow(VaultError);
  });

  it('accepts maximum UTF-8 basename/symlink lengths without imposing platform policy', () => {
    const { chunks: _chunks, ...meta } = oneFile as Extract<NodeEntry, { kind: 'file' }>;
    const node = withEntry({ ...meta, namePlain: 'é'.repeat(127) + 'x', kind: 'symlink', sizePlain: 0n, target: 'x'.repeat(PORTHOME_MAX_SYMLINK_LEN) });
    expect(decodeDirectoryNode(encodeDirectoryNode(node))).toEqual(node);
  });

  it('rejects file sum mismatch and uint64 overflow', () => {
    const file = oneFile as Extract<NodeEntry, { kind: 'file' }>;
    expect(() => encodeDirectoryNode(withEntry({ ...file, sizePlain: 4n }))).toThrow(VaultError);
    expect(() => encodeDirectoryNode(withEntry({ ...file, sizePlain: UINT64_MAX, chunks: [{ ...file.chunks[0], sizePlain: UINT64_MAX }, file.chunks[0]] }))).toThrow(VaultError);
  });

  it('requires nonzero node, child and chunk epochs; directory/symlink size zero', () => {
    const node = mixedNode();
    expect(() => encodeDirectoryNode({ ...node, epoch: 0n })).toThrow(VaultError);
    const directory = node.entries[0] as Extract<NodeEntry, { kind: 'directory' }>;
    const file = node.entries[1] as Extract<NodeEntry, { kind: 'file' }>;
    const link = node.entries[2];
    for (const entry of [
      { ...directory, childEpoch: 0n }, { ...directory, sizePlain: 1n }, { ...link, sizePlain: 1n },
      { ...file, chunks: [{ ...file.chunks[0], chunkKeyId: 0n }, file.chunks[1]] },
      { ...file, chunks: [{ ...file.chunks[0], sizeSealed: 28n }, file.chunks[1]] },
    ]) expect(() => encodeDirectoryNode(withEntry(entry))).toThrow(VaultError);
  });

  it('requires variant-specific absence, not just an ignored extra payload', () => {
    const node = mixedNode();
    for (const entry of [
      { ...node.entries[0], chunks: [] }, { ...node.entries[1], keyOverride: bytes32(new Uint8Array(32)) },
      { ...node.entries[2], childEpoch: 1n }, { ...node.entries[1], target: 'x' },
    ]) expect(() => encodeDirectoryNode(withEntry(entry))).toThrow(VaultError);
  });

  it('checks entry/member/chunk counts and CBOR bytes before unbounded allocation', () => {
    expect(() => encodeDirectoryNode({ ...empty, entries: new Array<NodeEntry>(PORTHOME_MAX_ENTRIES + 1) })).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    const file = oneFile as Extract<NodeEntry, { kind: 'file' }>;
    expect(() => encodeDirectoryNode(withEntry({ ...file, chunks: new Array(PORTHOME_NODE_MAX_CHUNKS + 1) }))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    const node = mixedNode();
    for (const which of ['writers', 'readers'] as const) {
      expect(() => encodeDirectoryNode({ ...node, vault: { ...node.vault!, [which]: new Array(PORTHOME_VAULT_MAX_MEMBERS + 1) } }))
        .toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    }
    expect(() => decodeDirectoryNode(new Uint8Array(PORTHOME_MAX_CBOR_BYTES + 1))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    expect(() => new CborWriter().bytes(new Uint8Array(PORTHOME_MAX_CBOR_BYTES))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
    const large = { ...file, chunks: Array.from({ length: PORTHOME_NODE_MAX_CHUNKS }, () => ({ ...file.chunks[0], sizePlain: 0n })), sizePlain: 0n };
    expect(() => encodeDirectoryNode(withEntry(large))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
  });

  it('permits empty files and does not confuse a C-accepted zero-size chunk with an empty array', () => {
    const file = oneFile as Extract<NodeEntry, { kind: 'file' }>;
    for (const chunks of [[], [{ ...file.chunks[0], sizePlain: 0n }]]) {
      const node = withEntry({ ...file, sizePlain: 0n, chunks });
      expect(decodeDirectoryNode(encodeDirectoryNode(node))).toEqual(node);
    }
  });

  it.each([-1, 1.5, UINT32_MAX + 1, NaN])('refuses non-uint32 mode %s', mode => {
    expect(() => encodeDirectoryNode(withEntry({ ...oneFile, mode }))).toThrow(VaultError);
  });
});

describe('sealed directory nodes', () => {
  const key = bytes32(hexToBytes(derivation.keys.child));
  const rootKey = bytes32(hexToBytes(derivation.keys.root));
  const ring: KeyRing = { entries: [{ epoch: 1n, nodeKey: rootKey }, { epoch: 3n, nodeKey: key }] };

  it('seals CBOR in the manifest domain, binds the authenticated node epoch, and owns overrides', () => {
    const node = mixedNode();
    const sealed = sealDirectoryNode(node, key);
    expect(sealed).toEqual(sealManifest(key, encodeDirectoryNode(node)));
    const opened = openDirectoryNode(ring, 3n, sealed.sealed);
    expect(opened).toEqual(node);
    const dir = opened.entries[0] as Extract<NodeEntry, { kind: 'directory' }>;
    dir.keyOverride![0] ^= 1;
    expect(openDirectoryNode(ring, 3n, sealed.sealed)).toEqual(node);
    expect(() => openDirectoryNode(ring, 2n, sealed.sealed)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
    expect(() => openDirectoryNode(ring, 1n, sealed.sealed)).toThrowError(expect.objectContaining({ code: 'CRYPTO' }));
    const wrongEpoch = sealDirectoryNode({ ...node, epoch: 1n }, key);
    expect(() => openDirectoryNode(ring, 3n, wrongEpoch.sealed)).toThrowError(expect.objectContaining({ code: 'EPOCH' }));
  });

  it('refuses v1 before decoding and bounds sealed CBOR bytes', () => {
    expect(() => openDirectoryNode(ring, 3n, new Uint8Array([1]))).toThrowError(expect.objectContaining({ code: 'VERSION' }));
    expect(() => openDirectoryNode(ring, 3n, new Uint8Array(PORTHOME_MAX_CBOR_BYTES + 30))).toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }));
  });
});

describe('strict CBOR subset', () => {
  it('copies byte strings on write/read and never wipes a caller-owned key', () => {
    const source = new Uint8Array([1, 2, 3]);
    const w = new CborWriter().bytes(source);
    source[0] = 9;
    const encoded = w.finish();
    expect(bytesToHex(encoded)).toBe('43010203');
    expect(source).toEqual(new Uint8Array([9, 2, 3]));
    const decoded = new CborReader(encoded).bytes(3);
    encoded.fill(0);
    expect(decoded).toEqual(new Uint8Array([1, 2, 3]));
    expect(w.finish()).toEqual(new Uint8Array());
  });

  it.each([
    [0n, '00'], [23n, '17'], [24n, '1818'], [255n, '18ff'], [256n, '190100'],
    [65535n, '19ffff'], [65536n, '1a00010000'], [0xffffffffn, '1affffffff'],
    [0x100000000n, '1b0000000100000000'], [UINT64_MAX, '1bffffffffffffffff'],
  ] as const)('uses the shortest uint encoding for %s', (value, hex) => {
    expect(bytesToHex(new CborWriter().uint(value).finish())).toBe(hex);
    const r = new CborReader(hexToBytes(hex)); expect(r.uint()).toBe(value); r.end();
  });

  it.each(['1817', '1900ff', '1a0000ffff', '1b00000000ffffffff', '1c', '1d', '1e', '1f', '20', 'c000', 'f4', 'f5', 'f6', 'fa00000000', 'fb0000000000000000'])('rejects non-shortest/reserved/unsupported scalar %s', hex => {
    expect(() => new CborReader(hexToBytes(hex)).uint()).toThrow(VaultError);
  });

  it.each(['7f', '61ff', '62c0af', '63eda080', '64f4908080', '62c3', '780178'])('rejects indefinite/non-shortest/truncated/invalid UTF-8 text %s', hex => {
    expect(() => new CborReader(hexToBytes(hex)).text(255)).toThrow(VaultError);
  });

  it('bounds malicious collection lengths without allocating and refuses trailing bytes', () => {
    expect(() => new CborReader(hexToBytes('9bffffffffffffffff')).array(PORTHOME_MAX_ENTRIES)).toThrow(VaultError);
    expect(() => new CborReader(hexToBytes('5bffffffffffffffff')).bytes(32)).toThrow(VaultError);
    expect(() => new CborReader(hexToBytes('9f')).array(10)).toThrow(VaultError);
    expect(() => new CborReader(hexToBytes('bf')).map(10)).toThrow(VaultError);
    const r = new CborReader(hexToBytes('0000')); r.uint(); expect(() => r.end()).toThrow(VaultError);
    expect(() => new CborWriter().text('\ud800')).toThrow(VaultError);
    expect(() => new CborWriter().uint(UINT64_MAX + 1n)).toThrow(VaultError);
    expect(() => new CborWriter().uint(-1n)).toThrow(VaultError);
  });
});
