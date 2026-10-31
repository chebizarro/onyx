# Shared vaults

Shared vaults let you share one folder of your notebook with other Nostr
users, end-to-end encrypted. Members can read it, and members you allow can
propose edits. Files are stored as encrypted, content-addressed blobs on
[Blossom](https://github.com/hzrd149/blossom) servers. Each writer publishes
a signed, encrypted "head" event to Nostr relays, and access grants are
delivered as NIP-59 gift wraps. Relays and Blossom servers only ever see
ciphertext.

Onyx implements the shared-vault protocol from
[nostrc](https://github.com/chebizarro/nostrc) (protocol id `porthome/v2`),
written entirely in TypeScript. It is pinned to nostrc commit
`4d5ed193a0307139d34c80d31db46abd99141224`. The wire format is the same as
nostrc's C implementation and its `vaultctl` CLI; see [Interoperability](#6-interoperability).

> **Status.** The protocol is still a draft. Kind numbers and the `d`-tag
> prefix may change before nostrc's first tagged release. If they do, Onyx
> will ship a compatibility release, and there is no plan to support both
> formats at once. Device keys (NIP-4E) are experimental and off by default.

Contents

1. [What it is](#1-what-it-is)
2. [Using shared vaults](#2-using-shared-vaults)
3. [How it works](#3-how-it-works)
4. [Security model](#4-security-model)
5. [Developer guide](#5-developer-guide)
6. [Interoperability](#6-interoperability)
7. [References](#7-references)

---

## 1. What it is

A **shared vault** is one folder inside your notebook that Onyx keeps in sync
with an encrypted copy on relays and Blossom servers. You choose who can read
it and who can write to it:

- **Owner**: the account that created the vault. The owner decides who has
  access, publishes the authoritative state of the vault (the *owner
  checkpoint*), resolves conflicts and revokes access.
- **Writer** ("Can propose edits"): can publish their own changes. Those
  changes stay *provisional* until the owner's next checkpoint includes them.
- **Reader** ("Can read"): gets the files. Nothing a reader does is ever
  published.

A vault covers exactly one folder. Vaults cannot be nested or overlap. To
share a subfolder of an existing vault separately, make it a separate vault
somewhere else. Sharing a vault never gives anyone access to the rest of your
notebook.

### Relationship to Onyx's existing Nostr sync

Onyx already has two Nostr features. Shared vaults sit alongside both and
change neither of them:

| Feature | Kinds | What it does | Effect of shared vaults |
| --- | --- | --- | --- |
| Self-sync | 30800 (file), 30801 (index) | Syncs your whole notebook between your own devices, encrypted to yourself | Unchanged. Vault folders are **excluded** from it: they are not uploaded, downloaded, deleted, moved or used as an import destination by legacy sync |
| Document sharing | 30802 | Sends someone a one-off encrypted snapshot of a document | Unchanged and separate from vault membership |
| Shared vaults | 30078 heads, 30804 grants (in 1059 wraps), Blossom blobs | Live, multi-member, per-folder sync | New |

The shared-vault engine has its own relay connections and lifecycle. It does
not touch the legacy `SyncEngine` (`src/lib/nostr/sync.ts`).

If legacy self-sync already published copies of a folder before it became a
vault, those copies **stay on your relays**. Excluding the folder from now on
does not take them back, and the UI says so.

---

## 2. Using shared vaults

### 2.1 Before you start

- **Log in.** Shared vaults use your Nostr identity, through the same local
  signer as the rest of Onyx. The engine starts once you are logged in and a
  notebook is open.
- **Configure endpoints.** Under **Settings > Nostr**, the **Relays** list (with
  its read and write flags) and the **Blossom Servers** list are the *defaults
  for new vaults*.
  Creating a vault takes a snapshot of them. Changing your settings later does
  not change the endpoints of existing vaults.
- **Use secure, public endpoints only.** Relays must use `wss://` and Blossom
  servers `https://`. Onyx refuses URLs that carry credentials, a query string
  or a fragment. It also refuses loopback, private, link-local and documentation
  addresses, and names ending in `.local`, `.lan`, `.internal`, `.onion`, etc.
- **Authenticated services work.** Relays that require NIP-42 AUTH and
  Blossom servers that require BUD-02 authorisation are fully supported (see
  [4.4](#44-authenticated-endpoints)). Write members must be able to upload to
  the vault's Blossom servers. Allowlisting and payment happen outside Onyx.

The status bar has a **Shared vaults** item showing engine state. Click it
for details on endpoints, the invitation inbox and per-vault security state.
**Settings > Sync > Shared vaults** lists the vaults on this device, with
Manage, Pause/Resume and Sync buttons.

### 2.2 Create a vault and share it

1. Right-click a folder in the sidebar and choose **Shared vault > Share
   folder as vault...**. This option only appears for folders that are not
   inside, and do not contain, another vault.
2. Check the dialog. It shares the folder's *contents*, not its parent
   folders or the rest of the notebook. The **Local label** is only shown on
   your devices.
3. Optionally add recipients now: an npub, a NIP-05 address or a hex pubkey,
   each set to **Can read** or **Can propose edits**.
4. Confirm. Onyx captures the whole folder (including empty folders, binary
   files and dotfiles), encrypts and uploads it, then publishes the first owner
   head. It also publishes two Onyx-private records (history and publishing
   device, see [3.7](#37-onyx-private-records)) and an encrypted grant to
   yourself, which lets your other devices find the vault.

To share later, open the vault (**right-click > Shared vault > Manage shared
vault**) and choose **Share...**. Only the owner can
share, and only from the vault's publishing device. Invitations are sent only
after the relays have accepted the updated policy. Each recipient's delivery
is tracked separately. **Pending deliveries** shows any that have not been
acknowledged, and **Retry deliveries** sends them again. A failed delivery
never undoes the policy change.

Changing a member from write to read takes away their write authority and
counts as a policy change. It does not take away read access; use **Revoke**
for that.

### 2.3 Accept an invitation

Invitations appear in the **Notifications** panel. Receiving one never
mounts the vault and never writes any files.

Opening an invitation shows:

- the owner's name and **key fingerprint**. Onyx does not load the owner's
  avatar before you accept, so an untrusted host cannot see that you opened
  the invitation.
- the access level (read or propose edits) and the full vault id.
- the exact relays and Blossom servers named in the grant, each of which you
  can select or deselect.

To accept, tick **I recognise this owner and want to accept the vault** and
**I approve connecting to the selected endpoints**, then pick a destination.
The default is a new folder `Shared Vaults/<first 12 hex characters of the vault
id>`. Any other folder must be **new or empty**: files are never merged into a
non-empty folder. Onyx contacts nothing from the grant's endpoints before you
approve them. The owner's display name is looked up from your own configured
relays.

After acceptance, Onyx checks the grant against the owner's signed tree, folds
the current heads ([3.5](#35-owner-sequenced-fold)), and writes files only once
the whole selected tree has downloaded and verified. If you are later upgraded
from read to write, the new invitation updates access **in place** in the
existing mount.

### 2.4 Attach a vault you own on another device

If you created a vault on one device and want it on another device with the
same identity:

1. On the second device, right-click the folder that should hold the vault and
   choose **Shared vault > Attach existing vault...**. Typically this is the
   same folder, already populated by legacy self-sync.
2. Choose the vault from the list of vaults you own that are not mounted
   on this device. If it is missing, click **Refresh invitations** so Onyx can
   find your self-grant.

Attaching works from an *empty baseline*: files identical to the vault's view
converge, files that differ become conflicts, and nothing is overwritten or
deleted. The folder is excluded from legacy sync on this device from then on.

### 2.5 Badges and states

Sidebar badges on a vault's folder tree:

| Badge | Where | Meaning |
| --- | --- | --- |
| **Vault** | Mount folder | This folder is a shared vault. Hover for the label and your role (Owner, Writer, Read-only). |
| **Read-only** | Mount and its contents | You are a reader. Onyx refuses saves, new files, renames, moves and deletions here. |
| *N* (number) | Mount folder | Unresolved conflicts. |
| **Paused** | Mount folder | Syncing is paused on this device. |
| **Provisional** | File (or *N* provisional on a folder) | **Your** changes that are not yet in the owner checkpoint. |
| **Pending owner review** | File (or *N* pending owner review on a folder) | **Another writer's** changes that you can see but the owner has not yet included in a checkpoint. |
| *N* **pending owner review** | Mount folder | Total number of paths that differ from the owner checkpoint (yours and other writers'). |

Provisional state is tracked **per path**. A path is provisional when the
materialised content (or your own unpublished candidate) differs from the
owner's latest checkpoint, including additions and deletions. The vault panel
lists these paths, marking each **Your edit** or **Other writer's edit**. The
snapshot carries at most 2,000 paths, and the total count is always exact.
When your own edit and another writer's edit touch the same path, the path
counts as yours.

**How a proposal reaches the owner.** A writer's sync publishes a writer head
signed by that writer. When the owner syncs, the proposal shows up as
conflicts, because Onyx never auto-merges changes that differ. For each path
the owner picks **Use other version** (adopt the writer's change) or **Keep
selected view** (keep the owner's version). Either choice produces a new owner
checkpoint that covers the writer's head, and the provisional badges clear on
every device. Folds that introduce no unresolved differences are published
automatically.

Other states shown in the vault panel's **Security state** line and in the
status-bar details:

- **Freshness: verified / unverified (not proof of latest state).**
  `verified` means the current owner checkpoint provably is, or comes after,
  the checkpoint your grant was issued for (or one you verified earlier).
  `unverified` means it cannot yet be linked to that anchor. Neither one proves
  that no newer checkpoint exists, because a relay can withhold one. See
  [3.8](#38-freshness-contract).
- **History: complete / incomplete / unavailable.** Shows whether the owner's
  epoch history (needed to read content sealed before a revocation) is
  available and up to date.
- **Fold quarantined.** Competing proposals exceeded a local resource budget.
  The last verified view is kept, automatic publication is blocked, and the
  owner can repair it by resolving conflicts or revoking the writer.
- **Invitation inbox at capacity / stopped.** New invitations are not being
  taken in, but existing vaults keep syncing. **Repair invitation inbox**
  compacts the stored replay data. No invitation decision is ever dropped.
- **Needs repair.** A stored vault record could not be opened. It stays
  listed and its encrypted data is kept unchanged. It is never silently
  removed.

### 2.6 Conflicts

Conflicts arise when versions of the same path differ: two writers' proposals,
an owner edit against a member edit, a deletion against an edit, or a local
file that differs from what the vault wants to write.

- Each conflict is stored in Onyx's local database, so it survives restarts.
  Where bytes exist, Onyx also writes a readable copy of the other version
  under `.onyx-vault-conflicts/` inside the mount. That folder is hidden in
  the sidebar and never captured or synced.
- **Only the owner resolves conflicts** in the shared view, from the vault's
  publishing device. The available choices are **Keep selected view**, **Use
  other version**, **Delete**, **Keep both** (under a new name) and **Save a
  merged file** (for files). You can also choose **Decide later**. Choosing a
  version for a folder also decides everything inside it.
- Members can open the other versions and publish a revised proposal.
- Losing versions are kept: nothing is removed from the servers.
- If a local file differs from the vault's view, Onyx keeps your local
  version and records a conflict. It never overwrites unsaved or locally
  changed content.

### 2.7 Revoke access and re-seal

On the owner's publishing device, **Revoke** next to a member does the
following:

1. Removes the member from the vault's policy.
2. Rotates the keys of the whole folder tree to a new *epoch*, so new and
   changed content is sealed under keys the removed member does not have.
3. Sends updated grants to the remaining members.

Two caveats are spelled out in the confirmation dialog:

- **Revocation does not take back anything already downloaded.** The removed
  member keeps whatever files and keys they already had.
- **Unchanged older content stays readable to the removed member until it is
  re-sealed.** Re-sealing re-encrypts old chunks under the new key. It runs
  gradually: the publishing owner device re-seals up to **8 MiB per sync pass**
  automatically. You can also click **Continue re-seal** (another 8 MiB pass)
  or **Re-seal everything now**, which downloads and re-uploads everything that
  is left. The revoke dialog has a checkbox to re-seal everything right after
  revoking. The panel shows the bytes remaining and a progress bar until it
  reads *Complete*.

Every revocation adds a key to each remaining member's grant, and a grant has
to fit in a 64 KiB gift wrap. The panel therefore shows the remaining **grant
size headroom**. When another revocation would not fit, revoking is blocked
and you should create a new vault for the remaining members. The owner's epoch
history has its own 65,535-byte limit and is checked before any rotation
starts.

### 2.8 Publishing device and handover

Exactly one device per owned vault publishes owner changes: heads, folds,
shares, revocations and re-seals. This is the **publishing device**. The vault
panel shows its label and since when it has held that role. On your other
devices:

- local edits are captured but kept on that device;
- **Take over publishing on this device** makes the current device the
  publisher. The previous publisher stops publishing as soon as it sees the
  handover, and keeps its own unpublished changes locally.

Before any owner publication, the device catches up with the relays and checks
that it is still the designated publisher. If two handovers race, the newer
record wins and the other device refuses to publish.

A non-owner writer has no publishing designation. Use one active device per
writer identity.

### 2.9 Device keys (experimental, opt-in)

**Settings > Sync > Shared vaults > Device key** turns on NIP-4E delivery.
Invitations sent to you are then encrypted to a key held by this device
instead of your identity key. You can generate or import a device key and
**Announce** it (a kind-10044 event). Earlier device keys are kept so that
older invitations still open, and they are never deleted automatically.

When you share with someone who has announced a device key:

- the first key Onyx sees is **pinned**, and is used only after you
  **Approve this key** next to its fingerprint. Until you do, invitations go to
  their identity key and the delivery record notes the fallback;
- if their announced key later **changes** or is **withdrawn**, delivery to
  them fails rather than switching keys silently. You can approve the new
  fingerprint, **Reset pin**, or allow identity-key fallback;
- a relay showing no newer announcement does not prove that the pinned key is
  still current. Verify fingerprints out of band, especially after a reset.

Rotating your own device key cannot take back invitations already sent to the
old key.

### 2.10 Recovery export

Vault keys are random. They cannot be derived from your Nostr identity, so
losing every device's local state, together with your self-grant, would lose
the vault. **Export recovery...** in the vault panel writes an encrypted
recovery package for **that vault only**: its key rings, grant and endpoints,
but never your device keys.

- The prompt suggests a randomly generated passphrase (about 150 bits) and
  rejects weak ones (fewer than 12 characters, repetition, sequences, common
  words).
- The package key is protected by scrypt in NIP-49 `ncryptsec` format, with
  cost log2(N) = 17 (128 MiB), or 18 when a quick probe shows this device can
  do it in about one second. The payload is AES-256-GCM.
- Save it **outside every notebook and synced folder**. On desktop Onyx
  refuses destinations inside the current notebook, including through
  symlinks. It cannot know about your other notebooks or sync folders.
- Anyone holding the file can try passphrases offline without limit, and
  changing the passphrase later does not protect a copy that has already been
  stolen.

There is no recovery **import** in the UI yet. The decoder (`openRecovery` in
`src/lib/vault/store.ts`) checks the package, its cost parameters and the
expected vault id before running the KDF, but it is not wired into a workflow.

### 2.11 Pause, detach, endpoints

- **Pause / Resume** stops and restarts syncing for one vault on this device.
- **Detach...** stops managing the folder on this device. The files stay as
  ordinary files, and the vault and the other members are unaffected.
- The endpoints of an existing vault are fixed when it is created (owner) or
  accepted (member). Changing your settings changes only the defaults for new
  vaults.
- While a folder is a vault, the sidebar refuses to rename, move or delete the
  mount folder or any folder containing it. Detach first.

### 2.12 What is and is not private

| Visible to relays / Blossom servers | Hidden from them |
| --- | --- |
| Your pubkey as author of your head events (kind 30078) and of the history and publishing-device records | File names, folder structure, file contents and sizes (chunks are padded) |
| The vault id, in the head's `d` tag (`porthome/v2/<vault_id>`) | Membership lists and capabilities (inside the encrypted tree) |
| When and how often each writer publishes | Grant contents (keys, endpoints): sealed twice in NIP-59 |
| Recipient pubkey on each invitation gift wrap (`p` tag). The sender is an ephemeral key and timestamps are randomised up to two days back | Which vault an invitation is for |
| Blob addresses, upload/download timing, approximate chunk sizes (padding buckets), and the pubkey that signs Blossom authorisations | Conflict details, local labels, mount paths |
| The epoch number in the history record's `epoch` tag | |
| With NIP-42 AUTH or Blossom auth: your pubkey, for those connections | |

Revocation is not retroactive ([2.7](#27-revoke-access-and-re-seal)). Your
local state (keys, journals, conflicts) is encrypted at rest in IndexedDB
under a key kept in the OS keyring (desktop) or the passphrase-sealed secret
store (web). It is never written into the shared folder or into
`localStorage`.

---

## 3. How it works

This section summarises the protocol as Onyx implements it. nostrc's design
documents are normative for the wire format ([References](#7-references));
the pinned C source and tests take precedence over prose.

### 3.1 Pipeline

```
files on disk
  -> content-defined chunks (buzhash)       chunker.ts
  -> PCS v2 sealed chunks (ChaCha20-Poly1305) crypto.ts      -> Blossom (address = SHA-256 of sealed bytes)
  -> encrypted directory nodes (strict CBOR)  dir-node.ts    -> Blossom
  -> signed, NIP-44 encrypted head            head.ts        -> relays, kind 30078
  -> verified records -> owner-checkpoint fold                 record.ts, fold.ts
  -> journaled, staged materialisation back to disk            materialize.ts
```

### 3.2 Keys, chunks and directory nodes

- **Key hierarchy (HKDF-SHA256).** A random 32-byte seed derives the root
  node key (salt `porthome/v2/home`). Each child directory key derives from its
  parent's key and the child's node id (`porthome/v2/node`), unless the
  parent's entry carries a `key_override`, in which case those 32 bytes are the
  child's key verbatim. Per node key there are derived chunk, manifest and
  name keys (`porthome/v2/chunk`, `/manifest`, `/name`), and a head key
  (`porthome/v2/head`, reduced mod the secp256k1 order). The head key's
  self-ECDH NIP-44 conversation key encrypts head bodies. Chunk
  keys are *convergent*: the nonce and key derive from the SHA-256 of the
  unpadded plaintext, so identical chunks under the same node key deduplicate.
- **Sealed object v2.** `0x02 || nonce[12] || ciphertext || tag[16]`,
  ChaCha20-Poly1305 with no AAD, 29 bytes of overhead. The Blossom address is
  the SHA-256 of the whole sealed object. Chunk plaintext is zero-padded to the
  NIP-44 bucket size before sealing, and directory manifests are not padded.
  PCS v1 objects (`0x01`) are refused with `VERSION`.
- **Chunker.** buzhash with a 64-byte window, a SplitMix64-seeded 256-entry
  table (seed `0x706f7274686f6d65`), 64 KiB minimum, 256 KiB target mask and
  1 MiB forced cut, matching nostrc byte for byte so that chunks deduplicate
  across implementations.
- **Directory node (CBOR, version 2).** Definite-length, shortest-form
  encoding, integer keys in ascending order. A node has `version`, `node_id`,
  `epoch`, `entries`, and on the root a `vault` map (`vault_id`, `owner`,
  `writers`, `readers`, `grants_rev`). Entries carry a keyed-hash name
  (`name_enc`, first 24 bytes of HMAC-SHA256 as 48 hex characters), the
  plaintext name, kind (file, directory or symlink), mode, `mtime_ns`, size and
  payload. The payload is a list of chunk references for a file; the child node
  id, epoch, manifest address and optional `key_override` for a directory; and
  the target for a symlink. Onyx never creates or follows symlinks: it keeps
  symlink entries in protocol state and shows them as unsupported.
- **`readers` is informational.** Anyone holding a current grant can read.
  Write authority comes from `writers` in the owner checkpoint, never from the
  grant's `cap` field.

### 3.3 Heads: kind 30078, `d = porthome/v2/<vault_id>`

Every writer, the owner included, publishes a parameterised-replaceable
kind-30078 event with exactly one tag, `["d", "porthome/v2/<64 hex vault id>"]`.
The content is NIP-44 v2, encrypted under a conversation key derived from the
current root epoch's head key. The body is strict compact JSON:

```
{"vault_id", "epoch", "root_manifest", ["ref_state"], ["key_override"],
 "seq", "parents": [{"writer","seq","root_manifest"}], "grants_rev", "written_at"}
```

The writer is identified by the event's `pubkey`; there is no `writer` field.
The reader verifies the id and signature, decrypts with **only** the requested
epoch's key, decodes strictly, then fetches the root manifest by address and
checks every hash before opening anything. Onyx never creates `ref_state` but
keeps it when reading.

Parents: the owner's successor head covers its previous head plus every record
it incorporates, transitively, up to 64 parents. Publication fails rather than
truncating. A member's head covers its own previous head and the owner
checkpoint it built on. This parent rule for member heads is an **Onyx
decision**, because nostrc has no member-head constructor. It is recorded as
provisional in the protocol lock, and nostrc's `vaultctl fold` folds such
heads identically ([6](#6-interoperability)).

### 3.4 Grants: kind-30804 rumors in NIP-59 wraps

A grant is strict JSON:

```
{"vault_id", "node_id", "ring": [{"epoch","node_key"}], "cap": "read"|"write",
 "owner", "root_manifest", "hints": {"relays": [...], "blossom": [...]}, "issued_at"}
```

It is carried as an **unsigned** kind-30804 rumor (`pubkey = owner`,
`created_at = issued_at`, no tags), inside a kind-13 seal signed by the owner,
inside a kind-1059 gift wrap signed by an ephemeral key with exactly
`[["p", <recipient>]]`. Seal and wrap timestamps are randomised up to 172,800
seconds into the past. Only the wrap is published: to the vault's relays and
to the recipient's NIP-65 read relays.

Before decrypting, the receiver verifies the wrap. It then verifies the seal,
requires the seal author, rumor author and grant owner to be the same key,
checks the canonical rumor id, and enforces every size limit. Each nested
plaintext must fit in 65,535 bytes. Onyx checks this before publishing and
never invents a multi-part format.

The inbox subscribes to `{"kinds":[1059], "#p":[you, ...retained device keys]}`
on your relays plus your NIP-65 read relays. Backfill pages with `until` and
starts from each relay's completed checkpoint minus two days. A grant never
auto-accepts. A newer grant for the same vault updates keys in place. Older
grants cannot roll back known policy or epoch state, and two grants that give
different keys for the same epoch are a security error.

### 3.5 Owner-sequenced fold

Onyx ports nostrc's `vault_fold_checkpoint` exactly. Head filter:
`{"kinds":[30078], "authors":[owner, ...writers], "#d":["porthome/v2/<vault_id>"]}`.

1. The **checkpoint** is the owner's highest-`seq` verified head.
2. Every other head gets a disposition, in this order: author not in the
   checkpoint's `writers` gives `NONWRITER`; a lower `grants_rev` gives
   `STALE`; a policy mismatch gives `POLICY`; an identical body gives
   `DUPLICATE`; anything else is `ACCEPTED`. The owner gets no bypass.
3. Coverage: a parent tuple `(W, s, root)` dominates every accepted head by
   `W` with `seq <= s`. The **frontier** is the set of accepted heads that
   nothing dominates.
4. The **view** is: none if the frontier is empty; the single record if there
   is one (even a non-owner's, which Onyx labels provisional); otherwise the
   highest-`seq` accepted owner record. Missing or ambiguous owner authority
   gives no view, never last-writer-wins. Two different owner bodies at the same
   `seq` count as equivocation, and Onyx refuses to use either.
5. Per-path conflicts compare the view with every other frontier record by
   encrypted path.

Kind 30078 is replaceable, so relays keep only each author's latest head.
Onyx therefore caches verified signed heads and feeds the fold the latest
head per author from relays **and** cache, so a cold start and a warm cache
give the same `FoldResult`.

**Owner publication policy (Onyx).** A fold is published automatically only
when it introduces no unresolved path differences. Anything else waits for an
explicit owner resolution ([2.6](#26-conflicts)).

### 3.6 Epochs, revocation and lazy re-seal

- **Revoke** (owner only, never yourself): remove the member from `writers`
  and `readers`, increment `grants_rev`, add a fresh random root key at
  `epoch + 1`, and rotate **every descendant directory**, rehashing names and
  giving each child a new `key_override`. Then rebuild and upload the
  manifests and publish a new-epoch owner head carrying `key_override`. After
  the relays accept it, publish the history record, then regrant the remaining
  members. The whole rotation is journaled. If regranting fails after
  publication, the revocation stays committed and retrying never rotates again.
- **Exact-epoch keys.** Every object names its epoch (`chunk_key_id`, node
  `epoch`, head epoch). Opening selects exactly that key and **never tries
  another** after an authentication failure. A missing key gives `EPOCH`
  ("Updated access key required").
- **Lazy re-seal.** Chunks keep their old epoch until re-sealed. Each job
  reserves `old size_sealed + padded(old size_plain) + 29` bytes. Lazy mode
  runs as many jobs, in order, as fit the budget. Eager mode checks that the
  whole remaining total fits before doing any I/O. Each job verifies and opens
  the old chunk under its exact epoch, re-seals it under the newest key and
  uploads it, and changes the reference only after a confirmed upload. Old
  objects are never deleted and old keys never discarded.

### 3.7 Onyx-private records

These records are specific to Onyx and are not part of nostrc's wire format.
nostrc consumers ignore them. Both are kind 30078 on the vault's relays.

| Record | `d` tag | Tags | Content |
| --- | --- | --- | --- |
| Epoch history | `onyx/vault-history/<vault_id>` | `["d",...]`, `["epoch","<newest root epoch>"]` | NIP-44 under that epoch's **head** conversation key: `{"v":1,"vault_id","epochs":[{"epoch","root_manifest","key_override"|null,"written_at"}...]}`, covering every epoch from 1, at most 65,535 bytes |
| Publishing device | `onyx/vault-publisher/<vault_id>` | `["d",...]` only | NIP-44 to yourself: `{"v":1,"vault_id","device_id","device_label","since"}` |

The history record lets a member who joined later, or who has just been
regranted, read chunks sealed under earlier epochs. It works even under
descendant directories that have since been rotated, because the record gives
the authenticated old root address for each epoch. The public `epoch` tag picks
exactly one ring key before decryption. Onyx persists a high-water mark
`{epoch, eventId}` and never selects a ledger older than one it has already
seen. A ledger behind your newest ring epoch reports `history: incomplete`.
Reads that need it then fail with `EPOCH` (`history-incomplete`), never with
partial success. Vaults owned by non-Onyx clients have no ledger. For those,
historical reads that need one fail with "History unavailable from this owner".

### 3.8 Freshness contract

A signature proves who wrote a head, not that it is the newest one, and relays
can withhold newer heads. Onyx keeps a compact freshness record per vault,
encrypted and separate from cached blobs:

- **Per-author sequence high-water marks**, plus the body hashes seen at each
  sequence (more than one hash is evidence of equivocation). A member head
  below its author's high-water mark is skipped before any manifest fetch.
  Older owner heads are kept as audit evidence, up to a budget.
- **Checkpoint floor.** If the selected owner checkpoint's epoch or `seq` is
  below the last accepted checkpoint, Onyx refuses it with `INCOMPLETE`
  (`stale-checkpoint`, retryable). The materialised view, baseline and pointers
  stay as they were. The same `seq` with a different body gives `CONFLICT`.
- **Granted-root binding.** A grant fixes a minimum `(root, epoch, grants_rev)`.
  A checkpoint with a lower epoch or revision is a known rollback and is
  refused: acceptance and attach abort without writing files. A checkpoint is
  **verified** if it has a higher epoch or revision, or it is the granted root,
  names it as an owner parent, or follows a verified owner head with that root.
  Otherwise it is admitted as **unverified** until a later checkpoint, held head
  or grant verifies it.

`verified` means verified against known owner-authenticated anchors. It never
means "up to date".

### 3.9 Network behaviour

- **Relays.** The engine has its own `nostr-tools` relay connections: one
  socket per URL, shared by all subscriptions. Live REQs stay open after EOSE
  and are replaced only when their author or recipient filter changes. Event ids
  are deduplicated before any decryption. A backfill wave completes when the
  first relay finishes, and later relays still deliver. Connection deadline is
  10 s, publish OK 10 s, backfill EOSE 15 s. Failed relays retry with
  exponential backoff from 5 s, capped at 5 min. A publication counts as durable
  at the **first positive OK**, and the remaining relays continue in the
  background. The exact signed event is journaled and retried as-is, never
  re-signed. A timeout is an unknown outcome, never success.
- **Blossom.** A small `fetch` client: `GET`/`HEAD /<sha256>` and `PUT /upload`
  (`application/octet-stream`, `X-SHA-256`), with `credentials: 'omit'` and
  `redirect: 'error'`. Every downloaded body is hashed before use. Each request
  has a 30 s total deadline and a 5 s idle-body deadline. Uploads are skipped
  for objects a server has already confirmed. Every object must have a
  confirmed copy on one of the vault's own grant-hinted servers before any
  head that references it is published.
- **Concurrency.** At most four network requests at a time across all vaults,
  one CPU job at a time in the worker, and one serialised lane of mutations per
  vault.
- **Local edits.** Watcher notifications are coalesced and capture runs
  750 ms after the last change. A capture reads only the files whose
  size or mtime changed. Remote changes arrive on the live subscriptions. An
  explicit **Sync** runs a full backfill, reconcile, capture and publish pass.

### 3.10 Local state and crash safety

- **Store.** One IndexedDB database, `onyx-shared-vaults` (version 2), with
  stores `accounts`, `vaults`, `invitations`, `records`, `operations`,
  `conflicts` (AES-256-GCM rows), plus `objects`, `objectIndex` and `meta`. The
  storage key lives in the platform secret store under
  `onyx:vault-store:v1:<pubkey>`. Verified ciphertext is cached in an LRU,
  512 MiB by default. Addresses pinned by pending work are never evicted.
- **Journals.** Each mutating operation records its intent, builds an
  immutable candidate, uploads dependencies, stores the exact signed event,
  publishes, records acknowledgements and only then advances committed state.
  After a crash the operation resumes from its journal.
- **Materialisation.** Verified content is staged under
  `.onyx-vault-staging/<operation-id>/` and dirty editors are flushed through a
  short editor barrier (5 s maximum). Files are checked against their expected
  prior hashes, and only then are they replaced. On desktop each file is
  installed through `managedVault` ([4.5](#45-write-confinement-desktop)), which
  writes a temporary file and renames it over the target. A replacement is
  atomic for that file. The journal across files is a replayable log, not a
  transaction.
- **Ownership.** On the web, an exclusive Web Lock
  (`onyx-vault-engine:<pubkey>`) makes sure only one window runs the engine
  for an account. Other windows show the engine as unavailable.

### 3.11 Budgets and fail-closed states

**Protocol limits** (`src/lib/vault/protocol.ts`, pinned to nostrc):

| Constant | Value |
| --- | --- |
| `PORTHOME_CHUNK_MIN` / `TARGET` / `MAX` | 65,536 / 262,144 / 1,048,576 bytes |
| `PORTHOME_HEAD_MAX_PARENTS` | 64 |
| `PORTHOME_HEAD_MAX_JSON` / `PORTHOME_HEAD_MAX_PAYLOAD` | 65,535 / 90,000 bytes |
| `PORTHOME_VAULT_MAX_MEMBERS` | 4,096 (writers and readers each) |
| `PORTHOME_NODE_MAX_CHUNKS` | 32,768 per file |
| `PORTHOME_MAX_ENTRIES` | 500,000 |
| `PORTHOME_MAX_PATH_LEN` / `PORTHOME_MAX_SYMLINK_LEN` | 4,096 bytes |
| `PORTHOME_MAX_CBOR_BYTES` | 1,048,576 |
| `PORTHOME_NAME_PLAIN_MIN/MAX_BYTES` | 1 / 255 |
| `VAULT_MAX_HEADS` | 256 fold inputs |
| `VAULT_MAX_OBJECTS` | 4,096 |
| `VAULT_MAX_MANIFEST_RECEPTION_BYTES` | 64 MiB sealed manifests per tree |
| `VAULT_MAX_EPOCHS` | 4,096 |
| `VAULT_MAX_HINTS` / `VAULT_MAX_URL` | 32 per list / 2,048 characters |
| `VAULT_GRANT_MAX_JSON`, `NIP59_MAX_PLAINTEXT` | 65,535 bytes |
| `NIP59_TIMESTAMP_RANDOM_RANGE` | 172,800 s |
| `BLOSSOM_AUTH_EXPIRATION_SECONDS` | 300 |

**Onyx ingress and local budgets** (`protocol.ts`, `budgets.ts`, and others).
These are local admission gates, not wire changes. They decide what gets
fetched, stored and offered to the fold. They never change the disposition of
a record that has been admitted. Overflowing one fails closed.

| Budget | Value | On overflow |
| --- | --- | --- |
| Event size (`VAULT_EVENT_MAX_BYTES`) | 128 KiB; tags at most 8 parts, 2,048 bytes per string, 16 KiB total | Rejected before signature verification; that relay connection is closed and retried with backoff |
| Relay frame (`VAULT_RELAY_MAX_FRAME_BYTES`) | 144 KiB, text frames only | Rejected before JSON parsing; connection closed and retried with backoff |
| Ingress queue | 64 items / 1 MiB (per relay connection and for the invitation lane) | Relay: connection closed and retried. Invitation lane: inbox stops until **Repair invitation inbox**; vaults keep syncing |
| Backfill page metadata | 4,096 events | Paged |
| Durable invitation replay ids | 3,912 grant wraps (4,096 ids / 256 KiB); transient rejects in a separate 2,048-id LRU | Inbox `at-capacity`; vaults keep syncing; **Repair invitation inbox** |
| Records per (author, seq) | 4 | `TOO_LARGE` `fork-budget`, extra head quarantined before fetch |
| Owner audit records below high-water mark | 256 | Further old owner heads skipped before fetch |
| Unresolved conflict rows per vault | 10,000 | `TOO_LARGE` `conflict-budget`: fold quarantined, previous view kept, no auto-publish; revoke still works as repair |
| Persisted conflict bytes per vault | 16 MiB | As above |
| Conflict sibling copies per vault | 256 MiB plaintext | Rows still recorded; readable copy deferred |
| File size for capture and materialise | 128 MiB | `TOO_LARGE` for that file only, shown per file and never published as a deletion |
| Object cache | 512 MiB LRU | Evicts unpinned objects |
| Automatic re-seal | 8 MiB per sync pass | Continues on next pass |

Other fail-closed rules: a missing or ambiguous owner checkpoint never
appears as an empty vault. A head that fails to decrypt is quarantined and the
last verified view kept. A vault root that disappears pauses the mount and is
never read as a remote deletion. An unknown PUT or relay outcome keeps the
candidate for verification. Paths that cannot be represented locally, or that
collide by case or Unicode form, block that path's materialisation and appear
as conflicts. Onyx never silently renames them.

---

## 4. Security model

### 4.1 Trust boundaries

- **Relays and Blossom servers are untrusted** for confidentiality and
  integrity. They can drop, delay, replay or withhold events and blobs, but
  cannot forge a signed head or grant, substitute a blob (all bytes are
  hash-verified), or read content. Their power over *availability* and
  *freshness* is real; see [4.3](#43-residual-risks-and-known-limitations).
- **Membership means holding keys.** A grant hands over symmetric keys.
  Anyone with a key ring can decrypt the objects it covers. Write authority is
  enforced by the fold: a head from a key outside the checkpoint's `writers`
  is `NONWRITER`.
- **Names and avatars are claims.** Profile names, NIP-05 and avatars are not
  identity proof. Invitations, share rows and members always show a key
  fingerprint next to the name. Onyx fetches no avatar for an invitation you
  have not accepted.
- **Inbound data is bounded before work.** Frame, event, tag and queue limits
  apply before parsing or verifying signatures. Wrap signatures are checked
  before any decryption. CBOR and JSON decoders reject unknown, duplicate and
  non-canonical input, and check lengths before allocating.

### 4.2 Revocation

Revocation stops removed members from decrypting **new or changed** content
and from publishing accepted heads. It does not take back anything already
obtained. Unchanged pre-revocation chunks stay decryptable with the old key
until re-sealed ([2.7](#27-revoke-access-and-re-seal)). A removed member's new
heads are `NONWRITER`, and objects sealed for new epochs fail with `EPOCH`
for them.

### 4.3 Residual risks and known limitations

- **Relay withholding.** A client that has never synced a vault cannot tell
  whether a relay is withholding a newer checkpoint. The freshness contract
  refuses *known* rollbacks and labels unanchored checkpoints `unverified`, but
  it cannot prove the latest state. In the same way, a relay that hides a
  device-key rotation cannot be detected; pins only prevent rollback below what
  you have already seen.
- **Lazy re-seal window.** See above. Re-seal everything now closes it.
- **Availability under hostile input.** Ingress budgets fail closed. An
  over-budget frame or event closes that relay's connection, which is then
  retried with backoff. The invitation lane stops at its queue or replay
  budget until **Repair invitation inbox**. A hostile relay or sender can
  degrade availability this way, but not confidentiality or integrity.
- **Key handling in JavaScript.** Wiping secrets from typed arrays is best
  effort. Identity secrets never enter the worker or the snapshot, but devtools
  access or an XSS in the webview would expose in-memory keys.
- **Native confinement on non-Unix platforms.** The descriptor-relative,
  no-follow write path is Unix-only (Linux, macOS, Android). Other platforms
  verify and then operate, which leaves a documented check-to-use window.
  `list_files_all` walks by path, but returns metadata only, and a link swapped
  in afterwards is refused by the no-follow read.
- **Configuration IPC.** Native file commands check paths against the
  notebook path held in Rust state, not against an argument. But
  `set_vault_scope` and `save_settings` are still callable over IPC, so a
  compromised webview could *reconfigure* the notebook root, through the same
  settings surface the user sees.
- **Legacy exclusion.** Symlink aliases into a mount are excluded by
  filesystem identity, and a path whose identity cannot be determined counts as
  managed. Hard links are out of scope, and the decision is a separate pathname
  operation from the legacy read or write that follows it, so this is not
  race-resistant legacy I/O.
- **Non-atomic multi-file updates.** Each file install is atomic. A
  materialisation spanning several files is a journal, not a transaction, and
  other processes writing to the folder at the same moment can race it.
- **One publishing device per writer.** Owners have an explicit designation.
  Non-owner writers do not, so two devices of the same writer publishing at
  once can fork that writer's heads. The fold keeps such forks as explicit
  frontier candidates within the per-(author, seq) budget.
- **Draft protocol.** Kinds 30804 and 10319 and the `porthome/v2/` prefix may
  be renumbered upstream. NIP-4E is a draft, and the way Onyx layers device
  keys (both the seal and the wrap encrypted to the device key, the seal still
  signed by the identity) is recorded as provisional.
- **Historical access needs evidence.** Reading old-epoch content needs the
  owner's history record (Onyx owners) or authenticated old heads. Without
  them, reads fail closed.
- **Endpoint policy is URL-based.** Private addresses and local names are
  refused by URL, but DNS resolution and rebinding depend on the runtime.
- **Same-second edits.** Capture trusts a size-and-mtime observation only once
  its mtime second is strictly older than the start of the observing stat. An
  edit that keeps the same size and restores an older mtime (for example
  `touch -t`) is not detected until the bytes or mtime change again.
- **No remote garbage collection.** Old ciphertext stays on Blossom servers.
- **Web storage.** Clearing site or webview data erases IndexedDB. Keep a
  self-grant and a recovery export. On the web the engine stays in `needs-key`
  until the secret store is unlocked and the engine is started again.
- **Downgrade.** An older Onyx ignores the vault database and would legacy-sync
  vault folders. Turn off legacy self-sync for such notebooks before
  downgrading.
- **Pinned SDK internals.** The relay adapter wraps parts of `nostr-tools`
  2.19.4's `Relay` class (`_onmessage`, `send`, `prepareSubscription`) to
  observe AUTH and OK frames precisely, and checks for them at start-up.
  Re-audit before upgrading `nostr-tools`.
- **Uncalibrated budgets.** The budget values in [3.11](#311-budgets-and-fail-closed-states)
  are initial values. They have not been calibrated on low-end devices.

### 4.4 Authenticated endpoints

NIP-42 relay AUTH and Blossom BUD-02 authorisation are first-class features.
No relay or server is excluded because it requires authentication.

- **Relays.** A NIP-42 challenge is answered with a kind-22242 event signed
  by your session signer. A pending REQ is re-issued once per successful
  authentication, and an EVENT refused with `auth-required:` is re-sent
  unchanged once after a positive AUTH. A `restricted:` refusal marks that
  endpoint "not allowlisted, ask the operator" and skips it. It is never treated
  as an account-wide failure.
- **Blossom.** Uploads always carry a kind-24242 `t=upload` authorisation
  scoped to the blob hash and expiring after 300 s. GET and HEAD are tried
  anonymously first, and a 401 triggers exactly one retry with a fresh
  `t=get` authorisation. HTTP 401 after the retry, 402 (payment or
  authorisation required) and 403 (not allowlisted) map to `AUTH`. 413 maps to
  `TOO_LARGE`. 404 means missing, never deleted.
- **VSP.** A relay whose NIP-11 document advertises `vault: true` with
  `limitation.auth_required: true` is labelled "private vault service". The
  label is informational. Operator allowlists (nostrc VSP) add access control,
  but Onyx does not depend on them: confidentiality comes from encryption, and
  write authority from the fold. Publishing kind-10319 service lists and
  managing allowlists are not implemented.

### 4.5 Write confinement (desktop)

Remote writers choose the names that get written into your mount, so the
shared-vault engine writes through a separate filesystem, `platform.managedVault`.
Its native commands are `managed_write_binary`, `managed_read_binary`,
`managed_mkdir` and `managed_delete`.

- On Unix, every path component below the canonicalised notebook root is
  opened relative to the previous directory handle with `O_NOFOLLOW`
  (`openat`/`mkdirat`/`renameat`/`unlinkat`, via `rustix`). A symlink at the
  mount root or along a destination therefore fails instead of redirecting the
  write, and there is no `realpath`-then-write race. The notebook root itself
  may be a symlink you created.
- Files are installed by writing an `O_EXCL` temporary file
  (`.onyx-vault-tmp-*`, which capture skips and no remote name may use), then
  renaming it over the target. Durability: `fsync(file)` and `fsync(dir)` on
  Linux; `F_FULLFSYNC(file)` and `fsync(dir)` on macOS.
- All native file commands check paths against the notebook path held in Rust
  state (`SharedVaultScope`), not against a path sent by the caller.
- The ordinary editor keeps following symlinks you create inside your notebook.
  That is unchanged.

### 4.6 Recovery KDF

Exports use scrypt (`r = 8`, `p = 1`, log2(N) of 17, or 18 after calibration)
in NIP-49 `ncryptsec` format, run asynchronously so the UI thread is not
blocked. Weak passphrases are rejected. The decoder checks the outer format,
caps the ciphertext at 4 MiB and refuses log2(N) outside 16–18 (`UNSUPPORTED`,
`kdf-cost`) **before** running the KDF. It also binds the authenticated vault
id to the vault the caller expects (`POLICY`, `recovery-vault-mismatch`).

---

## 5. Developer guide

### 5.1 Module layout (`src/lib/vault/`)

Lower layers never import higher ones.

| Layer | Modules | Notes |
| --- | --- | --- |
| Protocol constants and types | `protocol.ts`, `protocol-lock.json`, `types.ts`, `errors.ts`, `budgets.ts` | Every kind, prefix, HKDF domain and limit lives in `protocol.ts`. Nothing is user-configurable. Protocol uint64 values are `bigint`. |
| Portable codecs | `crypto.ts` (HKDF tree, PCS v2, NIP-44 wrappers, names), `chunker.ts`, `cbor.ts`, `dir-node.ts`, `strict-json.ts`, `head.ts`, `grant.ts`, `epoch-ledger.ts` | Depend only on `@noble/*` and `nostr-tools`. No platform, UI or network code. |
| Policy | `ring.ts`, `tree.ts`, `record.ts`, `fold.ts`, `parents.ts`, `reseal.ts`, `freshness.ts`, `retained-roots.ts` | Blob access is injected. |
| Application I/O | `relay.ts`, `blossom.ts`, `carrier.ts` (NIP-59), `device-keys.ts` (NIP-4E), `ingress.ts`, `inbox-replay.ts`, `store.ts`, `recovery.ts`, `filesystem.ts`, `materialize.ts`, `legacy-exclusion.ts`, `worker-client.ts`, `vault.worker.ts` | The worker handles CPU-heavy portable work (chunk, seal, open, hash). It never receives the identity secret and has no network access. |
| Orchestration | `engine.ts`, `engine-api.ts`, `useVaultEngine.ts` | The engine is the only owner of mutable vault state. |

UI lives in `src/components/`: `VaultShareDialog`, `VaultInvitationDialog`,
`VaultPanel`, `VaultConflictsPanel`, `SharedVaultSettings`,
`SharedVaultEngineStatus`, `VaultSecurityState`, `KeyFingerprint`,
`RecoveryPassphraseFields`, `VaultDeliveryEvidence`, plus `vault-ui.ts` and
`vault.css`. Sidebar badges and mutation guards are in `Sidebar.tsx`, and App
wiring (session, watcher forwarding, editor barrier, legacy exclusion) is in
`App.tsx` and `Settings.tsx`.

Platform additions (`src/platform/types.ts`): `VaultFS.listAll` returns the
complete subtree without following symlinks, `VaultFS.realPath` gives
filesystem identity for legacy exclusion, `platform.managedVault` is the
confined filesystem, and `dialog.save` selects the recovery destination.
Native commands are in `src-tauri/src/lib.rs`: `list_files_all`, the
`managed_*` commands (`mod confined`), `resolve_real_path`,
`resolve_recovery_destination` and `set_vault_scope`.

### 5.2 Engine API

`getVaultEngine()` returns the singleton. `resetVaultEngine()` waits for
`stop()` to finish. The interface is `VaultEngine` in `engine-api.ts`:

```ts
start(session, deps?)            // open state, take the account lock, resume journals
stop()                           // idempotent; aborts work, wipes owned key buffers
subscribe(listener)              // emits the current immutable snapshot immediately
updateNetworkDefaults(network)   // defaults for new vaults only
create(folder, { label?, network? })                    -> VaultId
share(vaultId, pubkeys, 'read' | 'write', delivery)     // owner, publishing device
accept(invitationId, { relativePath?, label?, trustConfirmed: true,
                       endpointsConfirmed: true, network })  -> VaultMount
attach(invitationIdOrVaultId, existingFolder)           // owner identity; empty baseline
takeOverPublishing(vaultId)
sync(vaultId?)                   // backfill, reconcile, capture, eligible publication
revoke(vaultId, pubkey)
resolveConflicts(vaultId, resolutions)  // keep-view | use-other | delete | keep-both | manual-merge
reseal(vaultId, budgetBytes, 'lazy' | 'eager')
pause(vaultId) / resume(vaultId) / detach(vaultId)
notifyFilesChanged(paths?)       // coalesced invalidation, no immediate I/O
refreshInbox() / repairInbox()
exportRecovery(vaultId)          // needs deps.requestRecoveryPassphrase
deviceKeys: { getState, setEnabled, generate, import, announce, useIdentityFallback,
              observeRecipient, approveRecipientKey, resetRecipientPin }
```

The `session` holds `{ accountPubkey, signer, notebookPath, fs, secrets,
networkDefaults, editorBarrier }`. The optional `deps` inject relay and Blossom
factories, a clock, an RNG, a lock provider, a worker factory, an IndexedDB
factory, the recovery passphrase prompt and lower budgets. Tests use these to
run everything headless without sleeps.

**Snapshot** (`VaultEngineSnapshot`). Each snapshot is replaced immutably and
never contains rings, grants, secret-store values or device private keys:

- `lifecycle`: `stopped | starting | running | stopping`; `activity`: `idle |
  capturing | uploading | publishing | fetching | folding | materializing |
  revoking | resealing`; `condition`: `ready | offline | needs-key | blocked |
  error`.
- `vaults[]` (`VaultSummary`): `authority`, `enabled`, `provisional`,
  `provisionalPaths` (at most 2,000), `provisionalCount`,
  `provisionalOtherPaths`, `freshness`, `checkpoint {seq, epoch, grantsRev}`,
  `history`, `foldQuarantine`, `conflictCount`, `conflicts[]`,
  `pendingDeliveryCount`, `deliveries[]` (actual envelope key and per-relay
  outcomes), `members[]`, `resealRemainingBytes`, `resealTotalBytes`,
  `regrantHeadroomBytes`, `publisher`, `mount`, `network`, `lastError`,
  `fileErrors[]`.
- `invitations[]` (key-free, with `endpointHints`), `endpoints[]`
  (`usable | authenticated | unsupported | offline`, plus the optional
  "private vault service" label), `deviceKeys`, `inbox`, `unavailableVaults[]`,
  `lastError`.

Errors are `VaultError` instances with a fixed `code` (`ARG`, `VERSION`,
`AUTH`, `CRYPTO`, `HASH_MISMATCH`, `EPOCH`, `POLICY`, `CONFLICT`,
`INCOMPLETE`, `BUDGET`, `TOO_LARGE`, `IO`, `NETWORK`, `UNSUPPORTED`,
`STORAGE`, `CANCELLED`), an `operation`, `retryable`, and a fixed display
message. Messages never contain keys, bodies, paths or headers.

### 5.3 Running tests

```sh
npm install
npm test                                  # all Vitest projects
npx vitest run --project vault            # src/lib/vault/**/*.test.ts (node + fake-indexeddb)
npx vitest run --project components       # src/components/**/*.test.tsx (jsdom)
npx vitest run src/lib/vault/__tests__/fold.test.ts   # one file
npm run typecheck                         # tsc --noEmit
(cd src-tauri && cargo test)              # native path/confinement tests
```

The tests drive relays with explicit EVENT, EOSE, OK and CLOSED frames and use
injected clocks, with no sleeps. Notable suites: `acceptance.two-account.test.ts`
(independent A/B/C engines through the public API: create, share, accept,
write upgrade, conflicts, revoke, fresh-member history, crash or restart,
owner attach and handover), `engine.test.ts`, `store.test.ts` (crash
injection at every journal commit), `worker.test.ts` (runs the actual Vite
worker bundles for both targets), `legacy-exclusion*.test.*` and `compat.test.ts`.
CI (`.github/workflows/test.yml`) runs `npm ci && npm test` on Node 22.

### 5.4 Protocol lock and test vectors

`src/lib/vault/protocol-lock.json` records the protocol id, the nostrc commit,
the SHA-256 of every nostrc source, header and test file the port relies on
(52 files), the imported limits and kinds, the behaviours flagged as
provisional or Onyx-only, and the hashes of the 9 fixture files in
`tests/fixtures/vault/`. Those fixtures were extracted from the pinned C tests;
`tests/fixtures/vault/PROVENANCE.md` documents how. The codec tests compare
against **C-produced bytes** (sealed chunks and addresses, CBOR encodings, the
824 C-rejected malformed CBOR inputs, chunk boundaries, head JSON, NIP-44
vectors), not TypeScript round-trips.

Verify the lock:

```sh
# Fixture hashes always; source hashes when a nostrc checkout at the pin is found
node scripts/verify-protocol-lock.mjs /path/to/nostrc

# Against a newer nostrc checkout: export the pinned files first
PIN=$(node -p "require('./src/lib/vault/protocol-lock.json').nostrcCommit")
SNAP=$(mktemp -d)
node -p "Object.keys(require('./src/lib/vault/protocol-lock.json').sources).join('\n')" |
  while read -r p; do mkdir -p "$SNAP/$(dirname "$p")"; git -C /path/to/nostrc show "$PIN:$p" > "$SNAP/$p"; done
node scripts/verify-protocol-lock.mjs "$SNAP"; rm -rf "$SNAP"
```

A mismatch exits non-zero with "Explicit compatibility review required; do
not regenerate silently."

**Re-pinning to a newer nostrc commit** is a compatibility change, not a
refresh. `protocol-lock.json` and `scripts/verify-protocol-lock.mjs` are the
gate:

1. **Find what moved.** Run
   `git -C /path/to/nostrc diff <old> <new> -- <every key of protocol-lock.json "sources">`.
   Pointing the verifier at a `git show` export of the *new* commit (the
   snapshot loop above, with `PIN=<new>`) fails on the first locked file that
   changed. Review every change against `protocol.ts`, the codecs and the policy
   modules. If the port now relies on a nostrc file that is not yet locked, add
   it to `sources`.
2. **Re-extract fixtures** whose C tests changed, following
   `tests/fixtures/vault/PROVENANCE.md`. Always read with
   `git show <commit>:<path>`, never from a working tree.
3. **Update the lock and constants together.**
   - In `protocol.ts`, set `NOSTRC_COMMIT` and any changed constant.
   - In `protocol-lock.json`:
     - set `nostrcCommit`;
     - set every `sources` hash to the SHA-256 of that file at the new commit
       (`git -C nostrc show <new>:<path> | shasum -a 256`);
     - update `constants`, `inheritedLimits` and `provisionalOnyxBehaviours`
       wherever they changed;
     - set the hashes in `fixtureProvenance.files`.
4. **Verify.** Run `node scripts/verify-protocol-lock.mjs <snapshot of the new commit>`.
   It must report every fixture and source hash with no mismatch. Then run
   `npm test`: `protocol.test.ts` asserts that `protocol.ts` exports exactly
   `lock.constants` and that every fixture hash matches, and the codec suites
   re-check the C vectors.
5. **Re-verify against the real C implementation** before shipping. Exchange
   grants, heads, folds, revocations and re-seals with nostrc's libraries and
   `vaultctl` at the new commit, as described in [6](#6-interoperability).
6. If kinds or the `d` prefix changed, the release is a breaking
   compatibility release. There is no dual-format support.

### 5.5 Persisted-state compatibility fixtures

`tests/fixtures/vault/compat/<commit>/` holds raw persisted state produced
**by that build**: every IndexedDB store, secret-store entries, notebook files
and relay and Blossom contents. `compat.test.ts` loads each generation on the
current build and checks that every vault is listed with the right authority
and that `sync()` works. The current generation is `900bf6f`, which includes
an over-capacity invitation inbox from before the inbox budget existed.

**Policy:** whenever a persisted shape changes, generate a fixture at the last
commit *before* the change, using `compat-dump.test.ts`. Add the commit to
`GENERATIONS` in `compat.test.ts`. Never re-encode old fixtures through current
types. The procedure is in `tests/fixtures/vault/compat/README.md`. New stored
fields must be additive, and readers must treat a missing field as the old
behaviour.

### 5.6 Performance measurements

The CPU and IO numbers below come from a benchmark script kept on the fork's
working branch, not in this repository. It can be shared on request.

The benchmark bundles the real TypeScript with esbuild. It drives the real
engine, store, worker transport and Blossom client against an in-memory relay
and Blossom server, using a deterministic 52-file, 11.9 MB notebook: 50
Markdown notes of 2–10 KB, a 1.6 MB incompressible image-like file and a
10 MB binary. The measured scenarios are:

- create, capture, upload and publish;
- a sync after one note changes;
- an owner sync with nothing to do;
- a member accepting and materialising the vault;
- a member sync with nothing to do;
- a member receiving a one-file remote update;
- engine start-up to `running`, with relays that answer EOSE either at once
  or after 2 s.

It also times the primitives: chunking, hashing, sealing, opening, directory
nodes and cache writes.

Medians of three runs on an Apple M4 Max with Node 26.8.1. "Before" is the
first complete implementation. "After" is this code.

| Scenario | Before (ms) | After (ms) | Files read | Blossom PUT/GET/HEAD | Relay REQs |
| --- | ---: | ---: | --- | --- | --- |
| Create, capture, upload, publish | 1,818 | 1,341 | 104 / 23.8 MB → 52 / 11.9 MB | 91/0/92 → 91/0/92 | 15 → 4 |
| One note changed, `sync` | 758 | 96 | 104 / 23.8 MB → 1 / 2 KB | 2/89/91 → 2/0/2 | 14 → 4 |
| Owner no-op `sync` | 68 | 18 | 104 / 23.8 MB → 0 | 0 | 10 → 4 |
| Member accept and materialise | 659 | 467 | 104 / 23.8 MB (unchanged) | 0/91/0 → 0/91/0 | 9 → 5 |
| Member unchanged `sync` | 38 | 18 | 104 / 23.8 MB → 0 | 0 | 5 → 3 |
| Member, one path updated remotely | 295 | 24 | 161 / 35.7 MB → 6 / 13 KB | 0/1/0 → 0/1/0 | 9 → 3 |

Publishing a share or policy change dropped from 768 to 98 ms. Start-up with
a 2 s EOSE delay dropped from 4,004 to 2,003 ms. Twenty cache writes against
a 5,000-object cache dropped from 285 to 2.8 ms, because cache cost no longer
grows with the inventory.

These measure Node CPU and in-memory IO. They are not WebView, Tauri IPC,
real-disk or live-network figures. Some of these properties are asserted in
the shipped tests:

- `engine.test.ts`: a no-op sync reads nothing, and a one-note sync reads only
  that note and writes at most ten journal entries;
- `materialize.test.ts`: a one-path update touches only that file;
- `store.test.ts`: cache cost is the same at 50 and 5,000 objects.

---

## 6. Interoperability

Onyx and nostrc share the wire format: heads, grants, sealed objects and
directory nodes are interchangeable. nostrc consumers ignore Onyx's two
private records, and Onyx refuses only the exclusions listed under *Not
covered* below.

**Verified locally against the real, unmodified nostrc C libraries and
`vaultctl` 0.3.1 at the pinned commit `4d5ed193a0307139d34c80d31db46abd99141224`.**

Steps 1 and 2 (codecs) ship in this repository's test suite:
`crypto.test.ts`, `chunker.test.ts`, `dir-node.test.ts` and
`head-grant.test.ts` compare against the C-produced vectors.

Steps 3–6 used an interop harness kept on the fork's working branch, not in
this repository; it can be shared on request. The harness:

1. builds the pinned nostrc tree out of tree as static libraries, with the
   CLI and test targets enabled;
2. runs nostrc's 14 libporthome and libvault reference tests;
3. imports Onyx's unchanged production modules;
4. exchanges real signed events and blobs between the two implementations
   through loopback relay and Blossom fixtures. The relay fixture verifies
   BIP340 signatures and answers with real `OK` and `EOSE` frames. The Blossom
   fixture requires a matching BUD-02 `x` hash before storing anything, and
   answers 401 to mismatched-hash probes.

The harness uses no sleeps and no external services. `vaultctl` was driven
with its `share`, `grant`, `fold`, `fsck` and `revoke` (including
`--budget 0` and `--resume`) commands. `vaultctl` 0.3.1 has no accept or import
command, so a small test-only C program linked against the real libraries
called `vault_grant_receive`, `vault_record_fetch`, `vault_tree_check` and
`vault_fold_checkpoint` directly. The CLI's `fold` output omits dispositions
and retained addresses, so every field of the C `vault_fold_checkpoint` result
was compared with Onyx's `FoldResult`. Only collection order was normalised.

| Check | Result |
| --- | --- |
| 1–2. Codecs | TypeScript reproduces every C sealed chunk, address and CBOR encoding byte for byte, and rejects all 824 malformed inputs the C decoder rejects |
| 3. NIP-59 grants, both ways | A `vaultctl grant` wrap opens in Onyx. Onyx read and write wraps open in C `vault_grant_receive` with an identical decoded grant. Both reject the wrong recipient |
| 4. Mixed writers and fold | Six C and Onyx signed records (C owner, C member, Onyx member heads with Onyx-built parents). `vaultctl fold` and every `FoldResult` field (dispositions, frontier, conflicts, retained roots) agree |
| 5. Revoke and regrant, both ways | C revoke lets Onyx accept the new-epoch regrant; Onyx revoke lets C verify the new tree and chunks. Old rings fail `EPOCH` / `PORTHOME_ERR_EPOCH` |
| 6. Historical overrides and lazy re-seal | Both read old chunks under twice-rotated descendant overrides from authenticated historical heads. Onyx re-seals part, `vaultctl revoke --resume` re-seals the rest, and `vaultctl fsck` passes |

Result: 14/14 C reference tests, 12/12 interop checks, no protocol
divergence. Last run on 2026-10-31 against this code, on macOS arm64 with
Node 26.

This is local fixture interoperability. It is not a test against deployed
relays or Blossom servers, a UI or device test, or a nostrc release
acceptance. At the pin, nostrc's shared-library build of `nip42` fails to link
on macOS (missing curl symbols), so the libraries were built statically. No C
source was patched.

**Not covered:** importing a foreign head through the `vaultctl` CLI itself,
which version 0.3.1 cannot do (see above). Grant `created_at` values are limited to JavaScript safe
integers, while C accepts the full int64 range. PCS v1 objects and the PNG
upload shim are not supported. Kind-10319 service lists and VSP configuration
are not produced. NIP-4E device delivery is an Onyx-provisional layering that
has not been tested against nostrc.

---

## 7. References

- nostrc shared-vault composition (normative design):
  [`docs/designs/shared-vault-composition.md` at the pin](https://github.com/chebizarro/nostrc/blob/4d5ed193a0307139d34c80d31db46abd99141224/docs/designs/shared-vault-composition.md)
- nostrc interop alignment notes (A1 kind registry, A3 NIP-4E, A5 VSP):
  [`docs/designs/shared-vault-interop-alignment.md`](https://github.com/chebizarro/nostrc/blob/master/docs/designs/shared-vault-interop-alignment.md)
  (added after the pin)
- nostrc sources the port is pinned to: `libporthome/`, `libvault/`,
  `libblossom/`, `tools/vaultctl/` (the exact list and hashes are in
  `src/lib/vault/protocol-lock.json`)
- Onyx legacy sync protocol: [`docs/NIP-XX-encrypted-file-sync.md`](NIP-XX-encrypted-file-sync.md)
- NIP-44, NIP-59, NIP-42, NIP-65: <https://github.com/nostr-protocol/nips>
- NIP-4E draft (device keys): <https://github.com/nostr-protocol/nips/pull/1647>
- Blossom BUD-01/02: <https://github.com/hzrd149/blossom>
