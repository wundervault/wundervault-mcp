import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'vitest';
import { fileURLToPath } from 'node:url';
import { REQUIRED_APP_FILES } from '../src/updater.js';
import { tarGzip } from './helpers/tar-write.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const version = '9.8.7';
const keyId = 'release-scripts-test';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicJwk = publicKey.export({ format: 'jwk' });
assert.ok(publicJwk.x);
const testKey = Buffer.from(publicJwk.x, 'base64url').toString('base64');
const keyArgs = ['--test-key', testKey, '--test-key-id', keyId];

function run(script: string, args: string[]) {
  const result = spawnSync(process.execPath, [
    path.join(root, 'scripts', script),
    ...args,
  ], {
    cwd: root,
    encoding: 'utf8',
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `Script terminated by ${result.signal}`);
  return {
    status: result.status,
    output: result.stdout + result.stderr,
  };
}

function refused(result: ReturnType<typeof run>, message?: RegExp): void {
  assert.notEqual(result.status, null, result.output);
  assert.notEqual(result.status, 0, result.output);
  assert.doesNotMatch(result.output, /^\s*OK(?:\s|$)/m);
  if (message) assert.match(result.output, message);
}

function signature(bytes: Buffer): string {
  return sign(null, bytes, privateKey).toString('base64');
}

function withFixture(fn: (dir: string) => void, omit?: string): void {
  const dir = mkdtempSync(path.join(tmpdir(), 'wundervault-release-scripts-'));
  try {
    const archive = tarGzip(REQUIRED_APP_FILES
      .filter(name => name !== omit)
      .map(name => ({ name: `app/${name}`, data: `fixture: ${name}\n` })));
    writeFileSync(path.join(dir, `wundervault-app-${version}.tar.gz`), archive);
    const record = Buffer.from(JSON.stringify({
      format: 'wundervault-release-1',
      version,
      app: {
        url: `https://github.com/wundervault/mcp-server/releases/download/v${version}/wundervault-app-${version}.tar.gz`,
        sha256: createHash('sha256').update(archive).digest('hex'),
      },
      node: { version: '22.20.0' },
      notes_url: `https://github.com/wundervault/mcp-server/releases/tag/v${version}`,
    }));
    writeFileSync(path.join(dir, 'release.json'), record);
    writeFileSync(path.join(dir, 'release.json.sigs'), JSON.stringify([
      { key_id: keyId, sig: signature(record) },
    ]));
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function verifyRelease(dir: string, expectedVersion = version) {
  return run('verify-release.mjs', [
    '--dir', dir,
    '--version', expectedVersion,
    ...keyArgs,
  ]);
}

function addSignature(dir: string, id: string, sig: string) {
  return run('add-signature.mjs', [
    '--dir', dir,
    '--key-id', id,
    '--sig', sig,
    ...keyArgs,
  ]);
}

test('verify-release accepts a signed release containing every required app file', () => {
  withFixture(dir => {
    const result = verifyRelease(dir);
    assert.equal(result.status, 0, result.output);
    assert.match(result.output, /^OK 9\.8\.7\b/m);
  });
});

test('verify-release refuses a tampered record byte', () => {
  withFixture(dir => {
    const recordPath = path.join(dir, 'release.json');
    const bytes = readFileSync(recordPath);
    const index = bytes.indexOf(Buffer.from(version));
    assert.notEqual(index, -1);
    bytes[index] = '8'.charCodeAt(0);
    writeFileSync(recordPath, bytes);
    refused(verifyRelease(dir), /do not verify/);
  });
});

test('verify-release refuses a signature from an unknown key', () => {
  withFixture(dir => {
    const other = generateKeyPairSync('ed25519');
    const bytes = readFileSync(path.join(dir, 'release.json'));
    writeFileSync(path.join(dir, 'release.json.sigs'), JSON.stringify([
      {
        key_id: 'unknown-key',
        sig: sign(null, bytes, other.privateKey).toString('base64'),
      },
    ]));
    refused(verifyRelease(dir), /do not verify/);
  });
});

test('verify-release refuses a bad signature by the trusted key', () => {
  withFixture(dir => {
    const bytes = readFileSync(path.join(dir, 'release.json'));
    const bad = Buffer.from(signature(bytes), 'base64');
    bad[0] = bad[0]! ^ 1;
    writeFileSync(path.join(dir, 'release.json.sigs'), JSON.stringify([
      { key_id: keyId, sig: bad.toString('base64') },
    ]));
    refused(verifyRelease(dir), /do not verify/);
  });
});

test('verify-release refuses a signed record for a different version', () => {
  withFixture(dir => {
    refused(verifyRelease(dir, '9.8.8'), /refused.*version mismatch/i);
  });
});

test('verify-release refuses an archive with a different SHA-256', () => {
  withFixture(dir => {
    const archivePath = path.join(dir, `wundervault-app-${version}.tar.gz`);
    const bytes = readFileSync(archivePath);
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    writeFileSync(archivePath, bytes);
    refused(verifyRelease(dir), /SHA-256 differs/);
  });
});

test('verify-release refuses a correctly hashed archive missing a required file', () => {
  assert.ok(REQUIRED_APP_FILES.length > 0);
  const missing = REQUIRED_APP_FILES[0]!;
  withFixture(dir => {
    refused(verifyRelease(dir), /archive: missing required file app\//);
  }, missing);
});

test('add-signature appends a good signature without changing existing entries', () => {
  withFixture(dir => {
    const sigsPath = path.join(dir, 'release.json.sigs');
    const existing = {
      key_id: 'previous-key',
      sig: Buffer.alloc(64, 1).toString('base64'),
    };
    writeFileSync(sigsPath, JSON.stringify([existing]));
    const sig = signature(readFileSync(path.join(dir, 'release.json')));
    const result = addSignature(dir, keyId, sig);
    assert.equal(result.status, 0, result.output);
    assert.deepEqual(JSON.parse(readFileSync(sigsPath, 'utf8')), [
      existing,
      { key_id: keyId, sig },
    ]);
    const verified = verifyRelease(dir);
    assert.equal(verified.status, 0, verified.output);
  });
});

test('add-signature refuses a bad signature even beside an existing good signature', () => {
  withFixture(dir => {
    const sigsPath = path.join(dir, 'release.json.sigs');
    const before = readFileSync(sigsPath);
    // The existing signature is trusted. An ANY-signature check would incorrectly accept
    // this append; the new signature must verify by the distinct key it names.
    const result = addSignature(dir, 'untrusted-new-key', Buffer.alloc(64).toString('base64'));
    refused(result, /new signature does not verify/);
    assert.deepEqual(readFileSync(sigsPath), before);
  });
});

test('add-signature refuses a bad signature naming the trusted key', () => {
  withFixture(dir => {
    const sigsPath = path.join(dir, 'release.json.sigs');
    writeFileSync(sigsPath, '[]');
    const before = readFileSync(sigsPath);
    refused(
      addSignature(dir, keyId, Buffer.alloc(64).toString('base64')),
      /new signature does not verify/,
    );
    assert.deepEqual(readFileSync(sigsPath), before);
  });
});

test('add-signature refuses a duplicate key_id without changing the signatures file', () => {
  withFixture(dir => {
    const sigsPath = path.join(dir, 'release.json.sigs');
    const before = readFileSync(sigsPath);
    const sig = signature(readFileSync(path.join(dir, 'release.json')));
    refused(addSignature(dir, keyId, sig), /Duplicate key_id/);
    assert.deepEqual(readFileSync(sigsPath), before);
  });
});

// check-release-keys.mjs reads ../dist/release-keys.js, so each case runs a copy of the script
// beside a stub key list: the shipped list holds the owner's key and must not be edited by a test.
function checkKeys(keys: unknown[], args: string[] = []) {
  const dir = mkdtempSync(path.join(tmpdir(), 'wv-keys-'));
  try {
    mkdirSync(path.join(dir, 'scripts', 'lib'), { recursive: true });
    mkdirSync(path.join(dir, 'dist'));
    copyFileSync(path.join(root, 'scripts', 'check-release-keys.mjs'), path.join(dir, 'scripts', 'check-release-keys.mjs'));
    copyFileSync(path.join(root, 'scripts', 'lib', 'release-cli.mjs'), path.join(dir, 'scripts', 'lib', 'release-cli.mjs'));
    writeFileSync(path.join(dir, 'dist', 'release-keys.js'), `export const RELEASE_KEYS = ${JSON.stringify(keys)};\n`);
    const r = spawnSync(process.execPath, [path.join(dir, 'scripts', 'check-release-keys.mjs'), ...args],
      { encoding: 'utf8', timeout: 30000 });
    return { status: r.status, output: `${r.stdout}${r.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const KEY32 = Buffer.alloc(32, 7).toString('base64');

test('check-release-keys refuses the empty configured key list', () => {
  refused(checkKeys([]), /RELEASE_KEYS is empty/);
});

test('check-release-keys allows the empty configured key list explicitly', () => {
  const result = checkKeys([], ['--allow-empty']);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /Release keys OK \(0\)/);
});

test('check-release-keys refuses a test key and a duplicate id', () => {
  refused(checkKeys([{ id: 't', publicKey: KEY32, test: true }]), /TEST release key refused/);
  refused(checkKeys([{ id: 'a', publicKey: KEY32 }, { id: 'a', publicKey: KEY32 }]), /Duplicate/);
});

test('the shipped key list passes the release check', () => {
  const result = run('check-release-keys.mjs', []);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /Release keys OK \(1\)/);
});
