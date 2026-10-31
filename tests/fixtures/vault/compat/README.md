# Shared-vault persisted-state compatibility fixtures (SEC-G)

Each `<commit>/` directory holds raw persisted state produced **by that build**:
every IndexedDB store (encrypted rows, meta, object index, schema and indexes),
secret-store entries, notebook files and the scripted relay/Blossom contents.
`src/lib/vault/__tests__/compat.test.ts` loads them on the current build and
asserts every vault is listed with the right authority and that `sync()` works.

- `two-account.json` — device A1 owns `notes`; device B owns `mine` and has accepted
  A1's `notes` as a writer (mounted at `shared`).
- `over-capacity-inbox.json` — the same B account after the pre-SEC-A unbounded
  inbox replay store accumulated 4,205 wrap IDs (above the 3,912 durable capacity):
  the state that made `start()` fail with "Grant inbox replay storage is full".

## Adding a generation

Whenever a persisted shape changes, generate fixtures at the last commit before it:

```sh
git worktree add /tmp/onyx-old <commit>
ln -s "$PWD/node_modules" /tmp/onyx-old/node_modules
cp src/lib/vault/__tests__/compat-codec.ts /tmp/onyx-old/src/lib/vault/__tests__/
cp tests/fixtures/vault/compat/900bf6f/compat-dump.test.ts /tmp/onyx-old/src/lib/vault/__tests__/
mkdir -p tests/fixtures/vault/compat/<commit>
(cd /tmp/onyx-old && COMPAT_OUT="$OLDPWD/tests/fixtures/vault/compat/<commit>" npx vitest run src/lib/vault/__tests__/compat-dump.test.ts)
git worktree remove --force /tmp/onyx-old
```

Then add `<commit>` to `GENERATIONS` in `compat.test.ts`. The generator may need
small adjustments to the old build's fixture API; never re-encode fixtures through
current types.
