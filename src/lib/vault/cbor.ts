import { VaultError } from './errors';
import { PORTHOME_MAX_CBOR_BYTES, UINT64_MAX } from './protocol';

const encoder = new TextEncoder();
// ignoreBOM means preserve U+FEFF as data, not strip a basename's first character.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** The bounded unsigned/bstr/tstr/definite-array/map subset in porthome/cbor.c. */
export class CborWriter {
  private readonly parts: Uint8Array[] = [];
  private length = 0;

  private append(bytes: Uint8Array, copy = false): void {
    if (bytes.length > PORTHOME_MAX_CBOR_BYTES - this.length) throw new VaultError('TOO_LARGE');
    this.parts.push(copy ? new Uint8Array(bytes) : bytes);
    this.length += bytes.length;
  }

  private head(major: number, argument: bigint): this {
    if (typeof argument !== 'bigint' || argument < 0n || argument > UINT64_MAX) throw new VaultError('ARG');
    const count = argument < 24n ? 0 : argument <= 0xffn ? 1 : argument <= 0xffffn ? 2 : argument <= 0xffffffffn ? 4 : 8;
    const result = new Uint8Array(1 + count);
    result[0] = (major << 5) | (count === 0 ? Number(argument) : count === 1 ? 24 : count === 2 ? 25 : count === 4 ? 26 : 27);
    for (let i = count; i > 0; i--, argument >>= 8n) result[i] = Number(argument & 255n);
    this.append(result);
    return this;
  }

  uint(value: bigint): this { return this.head(0, value); }
  array(length: number): this { return this.collection(4, length); }
  map(length: number): this { return this.collection(5, length); }

  private collection(major: number, length: number): this {
    if (!Number.isSafeInteger(length) || length < 0) throw new VaultError('ARG');
    return this.head(major, BigInt(length));
  }

  bytes(value: Uint8Array): this {
    this.head(2, BigInt(value.length));
    this.append(value, true);
    return this;
  }

  text(value: string): this {
    if (value.length > PORTHOME_MAX_CBOR_BYTES) throw new VaultError('TOO_LARGE');
    const bytes = encoder.encode(value);
    if (decoder.decode(bytes) !== value) throw new VaultError('ARG');
    this.head(3, BigInt(bytes.length));
    this.append(bytes);
    return this;
  }

  /** Takes an owned encoding and wipes the writer's temporary buffers. */
  finish(): Uint8Array {
    const result = new Uint8Array(this.length);
    let offset = 0;
    for (const part of this.parts) { result.set(part, offset); offset += part.length; }
    this.dispose();
    return result;
  }

  dispose(): void {
    for (const part of this.parts) part.fill(0);
    this.parts.length = 0;
    this.length = 0;
  }
}

export class CborReader {
  private offset = 0;

  constructor(private readonly data: Uint8Array) {
    if (!(data instanceof Uint8Array)) throw new VaultError('ARG');
    if (data.length > PORTHOME_MAX_CBOR_BYTES) throw new VaultError('TOO_LARGE');
  }

  get remaining(): number { return this.data.length - this.offset; }

  private head(major: number): bigint {
    if (!this.remaining) throw new VaultError('ARG');
    const initial = this.data[this.offset++];
    if (initial >> 5 !== major) throw new VaultError('ARG');
    const extra = initial & 31;
    if (extra < 24) return BigInt(extra);
    if (extra > 27) throw new VaultError('ARG'); // reserved or indefinite
    const count = 2 ** (extra - 24);
    if (this.remaining < count) throw new VaultError('ARG');
    let value = 0n;
    for (let i = 0; i < count; i++) value = (value << 8n) | BigInt(this.data[this.offset++]);
    const minimum = count === 1 ? 24n : 1n << BigInt((count / 2) * 8);
    if (value < minimum) throw new VaultError('ARG');
    return value;
  }

  uint(): bigint { return this.head(0); }

  key(expected: number): void {
    if (this.uint() !== BigInt(expected)) throw new VaultError('ARG');
  }

  private collection(major: number, max: number, minimumItemBytes: number): number {
    const count = this.head(major);
    // Reject impossible lengths before conversion/allocation, including uint64 counts.
    if (count > BigInt(max) || count > BigInt(Math.floor(this.remaining / minimumItemBytes)))
      throw new VaultError('ARG');
    return Number(count);
  }

  array(max: number, minimumItemBytes = 1): number { return this.collection(4, max, minimumItemBytes); }
  map(max: number): number { return this.collection(5, max, 2); }

  private stringBytes(major: number, max: number): Uint8Array {
    const length = this.head(major);
    if (length > BigInt(max) || length > BigInt(this.remaining)) throw new VaultError('ARG');
    const start = this.offset;
    this.offset += Number(length);
    return this.data.subarray(start, this.offset);
  }

  bytes(expectedLength: number): Uint8Array {
    const bytes = this.stringBytes(2, expectedLength);
    if (bytes.length !== expectedLength) throw new VaultError('ARG');
    return new Uint8Array(bytes);
  }

  text(maxBytes: number): string {
    const bytes = this.stringBytes(3, maxBytes);
    try { return decoder.decode(bytes); }
    catch { throw new VaultError('ARG'); }
  }

  end(): void {
    if (this.remaining) throw new VaultError('ARG');
  }
}
