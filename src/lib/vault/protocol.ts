import { KIND_APP_DATA, KIND_SEAL, KIND_GIFT_WRAP } from '../nostr/types';

/** Draft protocol assignments pinned by protocol-lock.json; not settings. */
export const PROTOCOL_ID = 'porthome/v2';
export const NOSTRC_COMMIT = '4d5ed193a0307139d34c80d31db46abd99141224';
export const PORTHOME_HEAD_KIND = KIND_APP_DATA;
export const VAULT_GRANT_KIND = 30804;
export const VAULT_SERVICE_LIST_KIND = 10319;
export const VAULT_SEAL_KIND = KIND_SEAL;
export const VAULT_GIFT_WRAP_KIND = KIND_GIFT_WRAP;
export const BLOSSOM_AUTH_KIND = 24242;
export const NIP4E_ANNOUNCEMENT_KIND = 10044;
export const NIP65_RELAY_LIST_KIND = 10002;
export const ONYX_VAULT_PUBLISHER_KIND = KIND_APP_DATA;
export const PORTHOME_HEAD_D_PREFIX = 'porthome/v2/';
/** Onyx-private application record, not a nostrc wire-format extension. */
export const ONYX_VAULT_PUBLISHER_D_PREFIX = 'onyx/vault-publisher/';
export const ONYX_VAULT_PUBLISHER_VERSION = 1;
/** Provisional Onyx-private history discovery; nostrc consumers ignore this record. */
export const ONYX_VAULT_HISTORY_KIND = KIND_APP_DATA;
export const ONYX_VAULT_HISTORY_D_PREFIX = 'onyx/vault-history/';
export const ONYX_VAULT_HISTORY_VERSION = 1;
export const ONYX_VAULT_HISTORY_MAX_JSON = 65535;

export const HKDF_DOMAINS = {
  home: 'porthome/v2/home',
  node: 'porthome/v2/node',
  chunk: 'porthome/v2/chunk',
  manifest: 'porthome/v2/manifest',
  name: 'porthome/v2/name',
  head: 'porthome/v2/head',
  nip44: 'nip44-v2',
} as const;

export const PORTHOME_KEY_LEN = 32;
export const PORTHOME_NONCE_LEN = 12;
export const PORTHOME_TAG_LEN = 16;
export const PORTHOME_SHA256_LEN = 32;
export const PORTHOME_WIRE_VERSION_V2 = 2;
export const PORTHOME_SEAL_OVERHEAD = 29;
export const PORTHOME_NAME_TAG_LEN = 24;
/** C buffer capacity including NUL; the wire text is 48 hex characters. */
export const PORTHOME_NAME_HEX_LEN = 49;
export const PORTHOME_NAME_HEX_CHARS = 48;
export const PORTHOME_NAME_PLAIN_MIN_BYTES = 1;
export const PORTHOME_NAME_PLAIN_MAX_BYTES = 255;
export const PORTHOME_DIR_NODE_VERSION = 2;
export const PORTHOME_VAULT_MAX_MEMBERS = 4096;
export const PORTHOME_NODE_MAX_CHUNKS = 32768;
/** Inherited by dir-node v2 from manifest.h, not the legacy 64-chunk cap. */
export const PORTHOME_MAX_ENTRIES = 500000;
export const PORTHOME_MAX_PATH_LEN = 4096;
export const PORTHOME_MAX_SYMLINK_LEN = 4096;
export const PORTHOME_MAX_CBOR_BYTES = 1048576;
export const PORTHOME_HEAD_MAX_PARENTS = 64;
export const PORTHOME_HEAD_MAX_JSON = 65535;
export const PORTHOME_HEAD_MAX_PAYLOAD = 90000;
/** C buffer capacity including NUL; the d-tag value is 76 bytes. */
export const PORTHOME_HEAD_D_LEN = 77;
export const PORTHOME_CHUNK_MIN = 65536;
export const PORTHOME_CHUNK_TARGET = 262144;
export const PORTHOME_CHUNK_MAX = 1048576;
export const PORTHOME_CHUNK_WINDOW = 64;
export const PORTHOME_CHUNK_TABLE_ENTRIES = 256;
export const PORTHOME_CHUNK_TABLE_SEED = 0x706f7274686f6d65n;
export const SPLITMIX64_INCREMENT = 0x9e3779b97f4a7c15n;
export const SPLITMIX64_MIX1 = 0xbf58476d1ce4e5b9n;
export const SPLITMIX64_MIX2 = 0x94d049bb133111ebn;
export const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const UINT64_MAX = 0xffffffffffffffffn;
export const INT64_MAX = 0x7fffffffffffffffn;
export const UINT32_MAX = 0xffffffff;
export const VAULT_MAX_HEADS = 256;
export const VAULT_MAX_OBJECTS = 4096;
/** fetch.c aggregate sealed-manifest reception cap. */
export const VAULT_MAX_MANIFEST_RECEPTION_BYTES = 64 * 1024 * 1024;
export const VAULT_MAX_HINTS = 32;
export const VAULT_MAX_URL = 2048;
export const VAULT_MAX_EPOCHS = 4096;
export const VAULT_GRANT_MAX_JSON = 65535;
export const NIP59_MAX_PLAINTEXT = 65535;
/** NIP-44 v2 wrapping the maximum NIP-59 plaintext, including padding/MAC/base64. */
export const NIP59_MAX_PAYLOAD = 4 * Math.ceil((1 + 32 + 2 + 65536 + 32) / 3);
export const NIP59_MAX_TAGS = 128;
/** Local ingress policy, not wire-format changes. 128 KiB accommodates the
 * 90,000-byte head payload and 87,472-byte NIP-59 payload plus tags/JSON. */
export const VAULT_EVENT_MAX_BYTES = 128 * 1024;
export const VAULT_EVENT_MAX_CONTENT_BYTES = Math.max(PORTHOME_HEAD_MAX_PAYLOAD, NIP59_MAX_PAYLOAD);
export const VAULT_EVENT_MAX_TAG_PARTS = 8;
export const VAULT_EVENT_MAX_TAG_STRING_BYTES = VAULT_MAX_URL;
export const VAULT_EVENT_MAX_TAG_BYTES = 16 * 1024;
/** Event envelope plus 16 KiB for relay framing; text frames only. */
export const VAULT_RELAY_MAX_FRAME_BYTES = VAULT_EVENT_MAX_BYTES + 16 * 1024;
/** One SDK consumer per connection; one asynchronous grant opener per engine. */
export const VAULT_INGRESS_MAX_QUEUED_ITEMS = 64;
export const VAULT_INGRESS_MAX_QUEUED_BYTES = 1024 * 1024;
/** Backfill keeps only bounded ID/timestamp metadata, not full event batches. */
export const VAULT_RELAY_MAX_PAGE_EVENTS = 4096;
/** Durable replay decisions are never evicted, including terminally invalid
 * wraps. Stop the inbox when either count or serialized-ID budget is exhausted. */
export const VAULT_INBOX_MAX_REPLAY_IDS = 4096;
export const VAULT_INBOX_MAX_REPLAY_BYTES = 256 * 1024;
export const NIP59_TIMESTAMP_RANDOM_RANGE = 172800;
export const BLOSSOM_AUTH_EXPIRATION_SECONDS = 300;
/** Adapter-owned deadlines include signing, authentication retry and body I/O. */
export const BLOSSOM_TOTAL_TIMEOUT_MS = 30000;
export const BLOSSOM_BODY_IDLE_TIMEOUT_MS = 5000;
