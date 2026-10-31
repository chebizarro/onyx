import { writeFileSync } from 'node:fs';
import { finalizeEvent } from 'nostr-tools';
import { describe, expect, it } from 'vitest';
import { execSync } from 'node:child_process';
import { encodeUtf8, hashAddress } from '../crypto';
import type { VaultEngine } from '../engine-api';
import type { VaultId } from '../types';
import { network, signer, snapshot } from './engine-fixtures';
import { AcceptanceNetwork, device, type AcceptanceDevice } from './acceptance-two-account-fixtures';
import { dumpDatabase, dumpFs, dumpNetwork, type DumpedDevice } from './compat-codec';

const OUT = process.env.COMPAT_OUT!;
async function accept(engine: VaultEngine, id: VaultId, cap: 'read' | 'write', path: string) {
  await engine.refreshInbox();
  const invite = snapshot(engine).invitations.find(i => i.vaultId === id && i.cap === cap && !i.accepted)!;
  expect(invite).toBeDefined();
  return engine.accept(invite.invitationId, { relativePath: path, trustConfirmed: true, endpointsConfirmed: true, network });
}
async function dumpDevice(net: AcceptanceNetwork, d: AcceptanceDevice): Promise<DumpedDevice> {
  return { name: d.name, pubkey: d.pubkey, databaseName: d.databaseName, notebookPath: '/notebook',
    idb: await dumpDatabase(net.database, d.databaseName), secrets: Object.fromEntries(d.secretValues), fs: dumpFs(d.fs) };
}
const views = (engine: VaultEngine) => snapshot(engine).vaults.map(v => ({ vaultId: v.vaultId, label: v.label, authority: v.authority, mount: v.mount?.relativePath ?? null }))
  .sort((x, y) => x.vaultId.localeCompare(y.vaultId));

describe('compat fixture generator (run at 900bf6f only)', () => {
  it('dumps an owned vault and an accepted member vault, plus an over-capacity legacy inbox', async () => {
    const commit = execSync('git rev-parse HEAD', { cwd: __dirname }).toString().trim();
    const net = new AcceptanceNetwork();
    const a = await device(net, 'A1', signer(1), 101), b = await device(net, 'B', signer(2), 202);
    await a.mkdir('/notebook/notes/sub');
    await a.fs.write('/notebook/notes/note.md', '# Initial\n'); await a.fs.write('/notebook/notes/sub/inner.md', 'inner');
    await b.mkdir('/notebook/mine'); await b.fs.write('/notebook/mine/mine.md', 'B owns this');
    const ae = await a.start(), be = await b.start();
    const owned = await ae.create('notes', {}), mine = await be.create('mine', {});
    await ae.share(owned, [b.pubkey], 'write', {}); await accept(be, owned, 'write', 'shared');
    expect(await b.fs.read('/notebook/shared/note.md')).toBe('# Initial\n');
    // Non-grant kind-1059 traffic (DMs/spam): the pre-SEC-A inbox persisted every ID.
    for (let i = 0; i < 3; i++) {
      const spam = finalizeEvent({ kind: 1059, created_at: net.now - i, tags: [['p', b.pubkey]], content: `not ciphertext ${i}` }, new Uint8Array(32).fill(9));
      net.events.set(spam.id, spam);
    }
    await be.refreshInbox(); await ae.refreshInbox();
    await ae.sync(owned); await be.sync(owned); await be.sync(mine);
    const expected = { A1: views(ae), B: views(be) };
    expect(expected.A1.map(v => v.authority)).toEqual(['owner']);
    expect(expected.B.map(v => v.authority).sort()).toEqual(['owner', 'writer']);
    const seenBefore = (await (async () => { const s = await b.openStore(); const v = (await s.read('accounts', []))!.value.config.inboxSeen; s.stop(); return v as string[]; })());
    await a.stop(); await b.stop();
    const meta = { commit, generatedBy: 'src/lib/vault/__tests__/compat-dump.test.ts at 900bf6f', network, ownedVaultId: owned, memberOwnVaultId: mine, expected };
    const netDump = dumpNetwork(net);
    const devices = { A1: await dumpDevice(net, a), B: await dumpDevice(net, b) };
    writeFileSync(`${OUT}/two-account.json`, JSON.stringify({ ...meta, inboxSeenCount: seenBefore.length, network: netDump, networkDefaults: network, devices }, null, 1));
    // Over-capacity legacy inbox: the same B account after the unbounded pre-SEC-A
    // store accumulated >3,912 unique wrap IDs (NIP-17 DMs, other NIP-59 apps, spam).
    const store = await b.openStore(), row = (await store.read('accounts', []))!;
    const flood = Array.from({ length: 4200 }, (_, i) => hashAddress(encodeUtf8(`legacy kind-1059 wrap ${i}`)));
    await store.put('accounts', [], { ...row.value, config: { ...row.value.config, inboxSeen: [...seenBefore, ...flood] } }, row.revision); store.stop();
    writeFileSync(`${OUT}/over-capacity-inbox.json`, JSON.stringify({ ...meta, inboxSeenCount: seenBefore.length + flood.length, network: netDump, networkDefaults: network,
      devices: { B: await dumpDevice(net, b) } }, null, 1));
  }, 120000);
});
