import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const lock = JSON.parse(readFileSync(resolve(root, 'src/lib/vault/protocol-lock.json'), 'utf8'));
const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

function verifyFiles(base, files) {
  for (const [path, expected] of Object.entries(files)) {
    const actual = sha256(resolve(base, path));
    if (actual !== expected) {
      throw new Error(`Protocol lock mismatch: ${path}\nExpected ${expected}\nActual   ${actual}\nExplicit compatibility review required; do not regenerate silently.`);
    }
  }
}

try {
  verifyFiles(resolve(root, lock.fixtureProvenance.directory), lock.fixtureProvenance.files);
  console.log(`Verified ${Object.keys(lock.fixtureProvenance.files).length} fixture hashes.`);

  const git = spawnSync('git', ['rev-parse', '--path-format=absolute', '--git-common-dir'], {
    cwd: root, encoding: 'utf8',
  });
  const candidates = [resolve(root, '../nostrc')];
  if (git.status === 0) candidates.push(resolve(dirname(git.stdout.trim()), '../nostrc'));
  const nostrc = process.argv[2] ?? process.env.NOSTRC_PATH ?? candidates.find(existsSync);
  if (!nostrc || !existsSync(nostrc)) {
    console.log('SKIP nostrc source hashes: checkout not found (set NOSTRC_PATH or pass its path).');
  } else {
    verifyFiles(nostrc, lock.sources);
    console.log(`Verified ${Object.keys(lock.sources).length} nostrc source hashes against ${lock.nostrcCommit}.`);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Protocol lock verification failed');
  process.exitCode = 1;
}
