import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { VaultEngine } from '../engine-api';
import type { VaultId } from '../types';
import { VAULT_INBOX_DURABLE_CAPACITY } from '../inbox-replay';
import { signer, snapshot } from './engine-fixtures';
import { AcceptanceNetwork, device, type AcceptanceDevice } from './acceptance-two-account-fixtures';
import { loadDatabase, loadFs, loadNetwork, type DumpedDevice, type DumpedNetwork } from './compat-codec';

/**
 * Backward compatibility of persisted shared-vault state (SEC-G).
 *
 * Each fixture directory under tests/fixtures/vault/compat/<commit>/ is the raw
 * persisted state an older build left behind: every IndexedDB store (encrypted
 * rows, meta, object index, schema), secret-store entries, the notebook files and
 * the relay/Blossom contents. It was generated *by that build* (see
 * `generatedBy`), never re-encoded through current types.
 *
 * This suite must stay permanently. Whenever a persisted shape changes (store
 * schema, StoredVault/StoredAccount/invitation/record/operation fields, secret-store
 * keys, inbox replay layout), generate a fixture at the last commit before the change
 * with `compat-codec.ts` and add its directory to GENERATIONS.
 */
const GENERATIONS = ['900bf6f'] as const;
const ROOT = fileURLToPath(new URL('../../../../tests/fixtures/vault/compat/', import.meta.url));

interface ExpectedVault { vaultId: VaultId; label: string; authority: 'owner' | 'writer' | 'reader'; mount: string | null }
interface CompatFixture {
  commit: string; generatedBy: string; ownedVaultId: VaultId; memberOwnVaultId: VaultId; inboxSeenCount: number;
  expected: Record<string, ExpectedVault[]>; network: DumpedNetwork; devices: Record<string, DumpedDevice>;
}
const load = (generation: string, file: string): CompatFixture => JSON.parse(readFileSync(`${ROOT}${generation}/${file}`, 'utf8'));

const devices: AcceptanceDevice[] = [];
afterEach(async () => { await Promise.all(devices.splice(0).map(d => d.stop())); });

const identities: Record<string, number> = { A1: 1, B: 2 };
/** Same session as the old build (account, notebook path, network defaults); fresh RNG stream. */
async function restore(net: AcceptanceNetwork, fx: CompatFixture, name: string) {
  const dump = fx.devices[name];
  const d = await device(net, name, signer(identities[name]), 7000 + identities[name]); devices.push(d);
  expect(d.pubkey).toBe(dump.pubkey); expect(d.databaseName).toBe(dump.databaseName);
  await loadDatabase(net.database, dump.idb, dump.databaseName);
  for (const [key, value] of Object.entries(dump.secrets)) d.secretValues.set(key, value);
  loadFs(d.fs, dump.fs);
  return d;
}
function network(fx: CompatFixture) {
  const net = new AcceptanceNetwork(); loadNetwork(net, fx.network); net.tick(); return net;
}
const views = (engine: VaultEngine) => snapshot(engine).vaults.map(v => ({ vaultId: v.vaultId, label: v.label, authority: v.authority, mount: v.mount?.relativePath ?? null }))
  .sort((x, y) => x.vaultId.localeCompare(y.vaultId));
function expectHealthy(engine: VaultEngine, expected: ExpectedVault[]) {
  const state = snapshot(engine);
  expect(state.lifecycle).toBe('running');
  expect(views(engine)).toEqual(expected);
  expect(state.unavailableVaults ?? []).toEqual([]);
  for (const vault of state.vaults) expect({ vaultId: vault.vaultId, lastError: vault.lastError, foldQuarantine: vault.foldQuarantine, fileErrors: vault.fileErrors })
    .toEqual({ vaultId: vault.vaultId, lastError: null, foldQuarantine: null, fileErrors: [] });
}

describe.each(GENERATIONS)('persisted state from %s loads on this build (SEC-G)', generation => {
  it('lists the owned and accepted member vaults with their authority, and sync() works both ways', async () => {
    const fx = load(generation, 'two-account.json');
    expect(fx.commit.startsWith(generation)).toBe(true);
    const net = network(fx);
    const a = await restore(net, fx, 'A1'), b = await restore(net, fx, 'B');
    const ae = await a.start(), be = await b.start();
    expectHealthy(ae, fx.expected.A1); expectHealthy(be, fx.expected.B);
    expect(snapshot(be).inbox).toMatchObject({ state: 'active' });
    expect(await b.fs.read('/notebook/shared/note.md')).toBe('# Initial\n');

    await ae.sync(fx.ownedVaultId); await be.sync(fx.ownedVaultId); await be.sync(fx.memberOwnVaultId);
    expectHealthy(ae, fx.expected.A1); expectHealthy(be, fx.expected.B);

    // Owner edit reaches the member; member (writer) edit reaches the owner.
    net.tick(); await a.fs.write('/notebook/notes/note.md', '# Edited after upgrade\n');
    await ae.sync(fx.ownedVaultId); await be.sync(fx.ownedVaultId);
    expect(await b.fs.read('/notebook/shared/note.md')).toBe('# Edited after upgrade\n');
    net.tick(); await b.fs.write('/notebook/shared/from-b.md', 'writer change');
    await be.sync(fx.ownedVaultId); await ae.sync(fx.ownedVaultId);
    expect(await a.fs.read('/notebook/notes/from-b.md')).toBe('writer change');
    // The member's own vault still publishes.
    net.tick(); await b.fs.write('/notebook/mine/mine.md', 'B still owns this'); await be.sync(fx.memberOwnVaultId);
    expectHealthy(be, fx.expected.B);

    // Restart on the migrated state: still listed, still healthy.
    await a.stop(); await b.stop();
    const ae2 = await a.start(), be2 = await b.start();
    expectHealthy(ae2, fx.expected.A1); expectHealthy(be2, fx.expected.B);
  }, 60000);

  it('an over-capacity legacy inbox (every kind-1059 ID) starts, keeps both vaults, and migrates to grant IDs only', async () => {
    const fx = load(generation, 'over-capacity-inbox.json');
    expect(fx.inboxSeenCount).toBeGreaterThan(VAULT_INBOX_DURABLE_CAPACITY);
    const net = network(fx), b = await restore(net, fx, 'B');
    const be = await b.start();
    expectHealthy(be, fx.expected.B);
    const store = await b.openStore();
    const invitationWrapIds = (await store.list('invitations')).flatMap(row => row.value.wrapIds);
    const config = (await store.read('accounts', []))!.value.config;
    expect(snapshot(be).inbox).toMatchObject({ state: 'active', durableIds: invitationWrapIds.length });
    expect([...(config.inboxSeen as string[])].sort()).toEqual([...invitationWrapIds].sort());
    expect((config.inboxRejected as string[]).length).toBeGreaterThan(0);
    // Decisions survive: the accepted invitation is still accepted.
    expect((await store.list('invitations')).every(row => row.value.accepted)).toBe(true); store.stop();
    await be.sync(); expectHealthy(be, fx.expected.B);
    await be.refreshInbox(); expect(snapshot(be).inbox).toMatchObject({ state: 'active' });
  }, 60000);
});
