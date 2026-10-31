import type { Event } from 'nostr-tools';
import { VaultError } from './errors';
import { NIP59_MAX_PAYLOAD, NIP59_MAX_TAGS, VAULT_GIFT_WRAP_KIND, VAULT_SEAL_KIND, VAULT_EVENT_MAX_BYTES, VAULT_EVENT_MAX_CONTENT_BYTES,
  VAULT_EVENT_MAX_TAG_BYTES, VAULT_EVENT_MAX_TAG_PARTS, VAULT_EVENT_MAX_TAG_STRING_BYTES } from './protocol';

const encoder = new TextEncoder();
/** The cheap UTF-16 check also bounds the allocation used to count UTF-8 bytes. */
export function boundedTextBytes(text: string, cap: number): number {
  if (text.length > cap) throw new VaultError('TOO_LARGE');
  const bytes = encoder.encode(text).length;
  if (bytes > cap) throw new VaultError('TOO_LARGE');
  return bytes;
}

/** Bound before hashing/copying. Never traverse unknown properties or carry the
 * SDK's mutable verification-cache symbol across this trust boundary. */
export function boundedEvent(value: unknown): { event: Event; bytes: number } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new VaultError('AUTH');
  const { id, pubkey, sig, kind, created_at, content, tags } = value as Event;
  if (typeof id !== 'string' || !/^[0-9a-f]{64}$/.test(id) ||
      typeof pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(pubkey) ||
      typeof sig !== 'string' || !/^[0-9a-f]{128}$/.test(sig) ||
      !Number.isSafeInteger(kind) || kind < 0 || !Number.isSafeInteger(created_at) || created_at < 0 ||
      typeof content !== 'string' || !Array.isArray(tags)) throw new VaultError('AUTH');
  // Count and arity are checked before visiting any tag fields.
  if (tags.length > NIP59_MAX_TAGS) throw new VaultError('TOO_LARGE');
  boundedTextBytes(content, kind === VAULT_GIFT_WRAP_KIND || kind === VAULT_SEAL_KIND ? NIP59_MAX_PAYLOAD : VAULT_EVENT_MAX_CONTENT_BYTES);
  if (content.includes('\0')) throw new VaultError('AUTH');
  let tagBytes = 2; // surrounding JSON array
  for (let i = 0; i < tags.length; i++) {
    const tag = tags[i];
    if (!Array.isArray(tag)) throw new VaultError('AUTH');
    if (tag.length > VAULT_EVENT_MAX_TAG_PARTS) throw new VaultError('TOO_LARGE');
    tagBytes += 2 + (i ? 1 : 0);
    for (let j = 0; j < tag.length; j++) {
      const part = tag[j];
      if (typeof part !== 'string') throw new VaultError('AUTH');
      boundedTextBytes(part, VAULT_EVENT_MAX_TAG_STRING_BYTES);
      if (part.includes('\0')) throw new VaultError('AUTH');
      tagBytes += encoder.encode(JSON.stringify(part)).length + (j ? 1 : 0);
      if (tagBytes > VAULT_EVENT_MAX_TAG_BYTES) throw new VaultError('TOO_LARGE');
    }
  }
  // Count the fixed envelope/content separately, so even a caller-supplied
  // tags.toJSON hook is never visited. Include JSON escaping in the total cap.
  const base = boundedTextBytes(JSON.stringify({ id, pubkey, sig, kind, created_at, content, tags: [] }), VAULT_EVENT_MAX_BYTES);
  const bytes = base + tagBytes - 2;
  if (bytes > VAULT_EVENT_MAX_BYTES) throw new VaultError('TOO_LARGE');
  const event: Event = { id, pubkey, sig, kind, created_at, content, tags: tags.map(tag => [...tag]) };
  return { event, bytes };
}
