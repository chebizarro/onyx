# Shared-vault fixture provenance

Reference: nostrc commit `4d5ed193a0307139d34c80d31db46abd99141224`.
All inputs were read with `git -C "$NOSTRC_PATH" show <commit>:<path>`,
not copied from its newer working tree. SHA-256 values for the original inputs
and these JSON files are in `src/lib/vault/protocol-lock.json`.

## Inventory

| JSON | Pinned source | Representation |
| --- | --- | --- |
| `helpers.json` | `libporthome/tests/test_helpers.h` | Complete seed and child node id |
| `ring-derivation.json` | `libporthome/tests/test_ring_derivation.c` | Full derived keys, name tag, override and exact-epoch cases |
| `seal-v2.json` | `libporthome/tests/test_seal_v2.c` | All four complete chunk envelopes/addresses and the unpadded manifest; v1 vector explicitly labelled refusal-only |
| `pad-buckets.json` | `libporthome/tests/test_pad_buckets.c` | All 26 boundaries through 1 MiB, nonzero input generator and negative cases |
| `dir-node.json` | `libporthome/tests/test_dir_node.c` | Six successful C encodings, all 824 concrete malformed/truncated CBOR inputs, encoder refusals and complete mixed-node metadata |
| `chunker.json` | `libporthome/tests/test_chunker.c` | Exact xorshift32 parameters, all 15 cut ends, inserted bytes and all edited cut ends, degenerate inputs |
| `head.json` | `libporthome/tests/test_head.c` | Complete compact/reordered/full JSON, every simple-head prefix and malformed JSON mutation, signer and ring parameters |
| `nip44.vectors.json` | `nips/nip44/tests/nip44.vectors.json` | Original file copied byte-for-byte, including invalid and long-message vectors |
| `reference-tests.json` | All seven sources above plus the six `libvault/tests/` files named in plan §4.12 | Lossless complete source text, retaining all assertions, policy cases, mutation recipes and SPDX notices |

Protocol uint64 values in semantic fixture objects are decimal strings. Raw head
JSON is stored as a string so its integer tokens are not rounded. Hex strings
are complete bytes, not abbreviated hashes. C initialisers such as `{0x31}` mean
one nonzero byte followed by 31 zero bytes, **not** 32 repeated bytes.

## CBOR extraction

The pinned `cbor.c` and codec portion of `dir-node.c` were compiled with Clang and
Homebrew OpenSSL. The pinned `test_dir_node.c` was instrumented to emit each
successful encoding and every `refuse(bytes, length)` input. Its codec assertions
ran successfully. The unrelated seal/open tail beginning with
`uint8_t root[32], key[32]; fixture(root,key);` was not executed by this extraction;
its cases remain in `reference-tests.json` and `remainingSemanticCases`.
The codec source was unchanged; only the unused seal/open functions were omitted
for linking. A generated `porthome/export.h` defined `PORTHOME_API` as empty.
`instrumentedLine` refers to the instrumented test, not an upstream source line.

The malformed array preserves C execution order: 10 empty-node byte mutations,
non-shortest version, trailing byte, seven one-file mutations, all 800 strict
prefixes of the mixed node, trailing byte, duplicate encrypted name, uppercase
name, duplicate plaintext name, and unknown kind. Every input was actually
rejected by the pinned decoder. The mixed node carries `UINT64_MAX` grants_rev.

The 4 MiB chunker input is reproducible without storing megabytes of random
bytes: start at `0x12345678`, perform xor-left-13, xor-logical-right-17,
xor-left-5 with unsigned 32-bit reduction after each operation, then emit the
low byte of the **updated** state. Insert exactly 38 bytes at offset 1024 for
the locality test; all original cut ends shift by 38.

## Verification and scope

Run `node scripts/verify-protocol-lock.mjs "$NOSTRC_PATH"`. This always checks
the fixture hashes and, when the path exists, checks actual checkout file bytes
against the pinned source hashes. With no checkout it prints an explicit SKIP.
A mismatch fails and requires compatibility review; it does not update the lock.
For a newer checkout, export the locked files with `git show <commit>:<path>` to
a temporary directory to check the original pin separately from working-tree drift.

This is fixture import and foundation smoke coverage, not a TypeScript codec,
cryptographic interoperability, hosted CI, or release-acceptance result. The head
C test uses random NIP-44 nonces and contains no pinned head ciphertext.

## Licences

The imported C tests declare `SPDX-License-Identifier: MIT`; their original
notices are preserved in `reference-tests.json`. The NIP-44 vector JSON is
retained verbatim from nostrc's NIP-44 tests. Its `SPEC_SOURCE` points to
`docs/nips/44.md`; consult that document and the pinned nostrc tree for upstream
licensing and attribution.
