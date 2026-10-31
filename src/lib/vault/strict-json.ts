import { VaultError } from './errors';
import { UINT64_MAX } from './protocol';

/** Bounded schema-driven tokens, never a generic JSON AST or JSON.parse. */
export class StrictJsonReader {
  private readonly data: Uint8Array;
  private offset = 0;

  constructor(input: string | Uint8Array, maximumBytes: number) {
    if (typeof input !== 'string' && !(input instanceof Uint8Array)) throw new VaultError('ARG');
    if (input.length > maximumBytes) throw new VaultError('TOO_LARGE');
    this.data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    if (this.data.length > maximumBytes) throw new VaultError('TOO_LARGE');
    if (this.data.includes(0)) throw new VaultError('ARG');
  }

  private whitespace(): void {
    while ([0x20, 0x09, 0x0a, 0x0d].includes(this.data[this.offset])) this.offset++;
  }

  private consume(character: string): boolean {
    this.whitespace();
    if (this.data[this.offset] !== character.charCodeAt(0)) return false;
    this.offset++;
    return true;
  }

  private take(character: string): void {
    if (!this.consume(character)) throw new VaultError('ARG');
  }

  /** vj_string's unescaped printable ASCII; cap excludes the C NUL. */
  string(maximumBytes: number): string {
    this.take('"');
    const start = this.offset;
    while (this.offset < this.data.length && this.data[this.offset] !== 0x22) {
      const c = this.data[this.offset++];
      if (c < 0x20 || c > 0x7e || c === 0x5c || this.offset - start > maximumBytes)
        throw new VaultError('ARG');
    }
    if (this.offset === this.data.length) throw new VaultError('ARG');
    const result = String.fromCharCode(...this.data.subarray(start, this.offset));
    this.offset++;
    return result;
  }

  hex(): string {
    const result = this.string(64);
    if (!/^[0-9a-f]{64}$/.test(result)) throw new VaultError('ARG');
    return result;
  }

  nullableHex(): string | null {
    this.whitespace();
    if (this.data[this.offset] === 0x6e) {
      for (const c of 'null') if (this.data[this.offset++] !== c.charCodeAt(0)) throw new VaultError('ARG');
      return null;
    }
    return this.hex();
  }

  uint(): bigint {
    this.whitespace();
    const start = this.offset;
    let result = 0n;
    while (this.offset < this.data.length) {
      const c = this.data[this.offset];
      if (c < 0x30 || c > 0x39) break;
      if (this.offset > start && this.data[start] === 0x30) throw new VaultError('ARG');
      const digit = BigInt(c - 0x30);
      if (result > (UINT64_MAX - digit) / 10n) throw new VaultError('ARG');
      result = result * 10n + digit;
      this.offset++;
    }
    if (this.offset === start) throw new VaultError('ARG');
    return result;
  }

  object(fields: Readonly<Record<string, () => void>>, optional: readonly string[] = []): void {
    this.take('{');
    const seen = new Set<string>();
    for (;;) {
      // json.c uses a 64-byte field buffer including NUL. Head names fit too.
      const field = this.string(63);
      this.take(':');
      if (!Object.prototype.hasOwnProperty.call(fields, field) || seen.has(field)) throw new VaultError('ARG');
      seen.add(field);
      fields[field]();
      if (this.consume('}')) break;
      this.take(',');
    }
    for (const field of Object.keys(fields))
      if (!optional.includes(field) && !seen.has(field)) throw new VaultError('ARG');
  }

  array<T>(maximum: number, read: () => T, nonempty = false): T[] {
    this.take('[');
    const result: T[] = [];
    if (this.consume(']')) {
      if (nonempty) throw new VaultError('ARG');
      return result;
    }
    for (;;) {
      if (result.length === maximum) throw new VaultError('ARG');
      result.push(read());
      if (this.consume(']')) return result;
      this.take(',');
    }
  }

  end(): void {
    this.whitespace();
    if (this.offset !== this.data.length) throw new VaultError('ARG');
  }
}
