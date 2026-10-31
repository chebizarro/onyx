import {
  PORTHOME_CHUNK_MIN, PORTHOME_CHUNK_MAX, PORTHOME_CHUNK_TARGET,
  PORTHOME_CHUNK_WINDOW, PORTHOME_CHUNK_TABLE_ENTRIES, PORTHOME_CHUNK_TABLE_SEED,
  SPLITMIX64_INCREMENT, SPLITMIX64_MIX1, SPLITMIX64_MIX2, UINT64_MAX,
} from './protocol';

const table = (() => {
  let state = PORTHOME_CHUNK_TABLE_SEED;
  return Array.from({ length: PORTHOME_CHUNK_TABLE_ENTRIES }, () => {
    state = (state + SPLITMIX64_INCREMENT) & UINT64_MAX;
    let z = state;
    z = ((z ^ (z >> 30n)) * SPLITMIX64_MIX1) & UINT64_MAX;
    z = ((z ^ (z >> 27n)) * SPLITMIX64_MIX2) & UINT64_MAX;
    return z ^ (z >> 31n);
  });
})();

/** Next chunk length. Rolling state starts afresh for every chunk, as in C. */
export function chunkNext(data: Uint8Array | null): number {
  if (!data?.length) return 0;
  if (data.length <= PORTHOME_CHUNK_MIN) return data.length;
  const limit = Math.min(data.length, PORTHOME_CHUNK_MAX);
  const mask = BigInt(PORTHOME_CHUNK_TARGET - 1);
  let hash = 0n;
  for (let i = 0; i < limit; i++) {
    hash = (((hash << 1n) | (hash >> 63n)) & UINT64_MAX) ^ table[data[i]];
    // Rotating the outgoing table entry by the 64-byte window is identity.
    if (i >= PORTHOME_CHUNK_WINDOW) hash ^= table[data[i - PORTHOME_CHUNK_WINDOW]];
    if (i + 1 >= PORTHOME_CHUNK_MIN && (hash & mask) === 0n) return i + 1;
  }
  return limit;
}

/** End offsets only; empty files have no chunks. Does not copy file bytes. */
export function chunkEnds(data: Uint8Array): number[] {
  const ends: number[] = [];
  for (let offset = 0; offset < data.length;) {
    offset += chunkNext(data.subarray(offset));
    ends.push(offset);
  }
  return ends;
}
