import { describe, expect, it } from 'vitest';
import fixture from '../../../../tests/fixtures/vault/chunker.json';
import { chunkEnds, chunkNext } from '../chunker';
import { hexToBytes } from '../crypto';
import { PORTHOME_CHUNK_MIN, PORTHOME_CHUNK_MAX } from '../protocol';

function xorshiftInput(): Uint8Array {
  let state = Number(fixture.input.generator.seed);
  return Uint8Array.from({ length: fixture.input.length }, () => {
    state = (state ^ (state << 13)) >>> 0;
    state = (state ^ (state >>> 17)) >>> 0;
    state = (state ^ (state << 5)) >>> 0;
    return state & 255;
  });
}

describe('pinned SplitMix64/buzhash chunker', () => {
  const input = xorshiftInput();

  it('reproduces every cut end for the 4 MiB xorshift32 input', () => {
    expect(chunkEnds(input)).toEqual(fixture.cutEnds);
    let previous = 0;
    for (const end of fixture.cutEnds) {
      expect(end - previous).toBeLessThanOrEqual(PORTHOME_CHUNK_MAX);
      if (end !== input.length) expect(end - previous).toBeGreaterThanOrEqual(PORTHOME_CHUNK_MIN);
      previous = end;
    }
  }, 30000);

  it('reproduces insertion locality, resetting rolling state at each chunk', () => {
    const insertion = hexToBytes(fixture.insertion.bytesHex);
    expect(insertion.length).toBe(fixture.insertion.length);
    const edited = new Uint8Array(input.length + insertion.length);
    const at = fixture.insertion.offset;
    edited.set(input.subarray(0, at));
    edited.set(insertion, at);
    edited.set(input.subarray(at), at + insertion.length);
    expect(chunkEnds(edited)).toEqual(fixture.insertion.cutEnds);
    for (let i = 0; i < fixture.cutEnds.length; i++)
      expect(fixture.insertion.cutEnds[i]).toBe(fixture.cutEnds[i] + insertion.length);
    // Every chunk after the edited first chunk is byte-identical.
    for (let i = 1; i < fixture.cutEnds.length; i++) {
      expect(edited.subarray(fixture.insertion.cutEnds[i - 1], fixture.insertion.cutEnds[i]))
        .toEqual(input.subarray(fixture.cutEnds[i - 1], fixture.cutEnds[i]));
    }
  }, 30000);

  it.each(fixture.degenerate)('matches degenerate input $input, length $length', v => {
    const data = v.input === null ? null : v.input === 'zero' ? new Uint8Array(v.length)
      : Uint8Array.from({ length: v.length }, (_, i) => i % 64);
    expect(chunkNext(data)).toBe(v.firstCut);
  });

  it('encodes an empty file as zero chunk references and never mutates input', () => {
    expect(chunkEnds(new Uint8Array())).toEqual([]);
    const bytes = Uint8Array.from({ length: PORTHOME_CHUNK_MIN + 1 }, (_, i) => i % 255);
    const copy = bytes.slice();
    chunkEnds(bytes);
    expect(bytes).toEqual(copy);
  });
});
