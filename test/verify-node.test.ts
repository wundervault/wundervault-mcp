import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createCipheriv, createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, test } from 'vitest';
import { openOrder } from '../src/broker-update.js';
import { REQUIRED_APP_FILES } from '../src/updater.js';
import { tarGzip } from './helpers/tar-write.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const version = '9.8.7';
const nodeVersion = '22.23.4';
const nodeFilename = `node-v${nodeVersion}-linux-x64.tar.gz`;
const member = `node-v${nodeVersion}-linux-x64/bin/node`;
const keyId = 'verify-node-test';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicJwk = publicKey.export({ format: 'jwk' });
assert.ok(publicJwk.x);
const testKey = Buffer.from(publicJwk.x, 'base64url').toString('base64');

beforeAll(() => {
  const result = spawnSync('npm', ['run', 'build'], {
    cwd: root,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    timeout: 120000,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
}, 130000);

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function withFixture(
  fn: (dir: string) => void,
  options: { missingMember?: boolean; absent?: boolean; windows?: boolean } = {},
): void {
  const dir = mkdtempSync(path.join(tmpdir(), 'wundervault-verify-node-'));
  try {
    const app = tarGzip(REQUIRED_APP_FILES.map(name => ({
      name: `app/${name}`,
      data: `fixture: ${name}\n`,
    })));
    writeFileSync(path.join(dir, `wundervault-app-${version}.tar.gz`), app);
    const node = options.windows
      ? Buffer.from('fake node.exe')
      : tarGzip([{
        name: options.missingMember
          ? `node-v${nodeVersion}-linux-x64/bin/not-node`
          : member,
        data: 'fake node executable\n',
      }]);
    if (!options.absent) {
      writeFileSync(path.join(dir, options.windows ? 'win-x64-node.exe' : nodeFilename), node);
    }
    const record = Buffer.from(JSON.stringify({
      format: 'wundervault-release-1',
      version,
      app: {
        url: `https://github.com/wundervault/mcp-server/releases/download/v${version}/wundervault-app-${version}.tar.gz`,
        sha256: sha256(app),
      },
      node: {
        version: nodeVersion,
        ...(options.windows ? {
          'win-x64': {
            url: `https://nodejs.org/dist/v${nodeVersion}/win-x64/node.exe`,
            sha256: sha256(node),
          },
        } : {
          'linux-x64': {
            url: `https://nodejs.org/dist/v${nodeVersion}/${nodeFilename}`,
            sha256: sha256(node),
            member,
          },
        }),
      },
      notes_url: `https://github.com/wundervault/mcp-server/releases/tag/v${version}`,
    }));
    writeFileSync(path.join(dir, 'release.json'), record);
    writeFileSync(path.join(dir, 'release.json.sigs'), JSON.stringify([{
      key_id: keyId,
      sig: sign(null, record, privateKey).toString('base64'),
    }]));
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function verify(dir: string) {
  const result = spawnSync(process.execPath, [
    path.join(root, 'scripts', 'verify-release.mjs'),
    '--dir', dir,
    '--version', version,
    '--test-key', testKey,
    '--test-key-id', keyId,
  ], {
    cwd: root,
    encoding: 'utf8',
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return { status: result.status, output: result.stdout + result.stderr };
}

test('verify-release verifies a signed Node archive and its expected member', () => {
  withFixture(dir => {
    const result = verify(dir);
    assert.equal(result.status, 0, result.output);
    assert.match(result.output, /^node linux-x64: verified$/m);
    assert.match(result.output, /^OK 9\.8\.7\b/m);
  });
});

test('verify-release refuses a tampered Node archive', () => {
  withFixture(dir => {
    writeFileSync(path.join(dir, nodeFilename), 'tampered archive');
    const result = verify(dir);
    assert.notEqual(result.status, null, result.output);
    assert.notEqual(result.status, 0, result.output);
    assert.match(result.output, /SHA-256 differs/);
    assert.doesNotMatch(result.output, /^node linux-x64: verified$/m);
  });
});

test('verify-release refuses a correctly hashed Node archive missing its member', () => {
  withFixture(dir => {
    const result = verify(dir);
    assert.notEqual(result.status, null, result.output);
    assert.notEqual(result.status, 0, result.output);
    assert.doesNotMatch(result.output, /SHA-256 differs/);
    assert.doesNotMatch(result.output, /^node linux-x64: verified$/m);
    assert.doesNotMatch(result.output, /^OK /m);
  }, { missingMember: true });
});

test('verify-release allows a listed Node archive to be absent', () => {
  withFixture(dir => {
    const result = verify(dir);
    assert.equal(result.status, 0, result.output);
    assert.match(result.output, /^node linux-x64: not present$/m);
    assert.match(result.output, /^OK 9\.8\.7\b/m);
  }, { absent: true });
});

test('verify-release finds Windows Node by its platform-prefixed filename', () => {
  withFixture(dir => {
    const result = verify(dir);
    assert.equal(result.status, 0, result.output);
    assert.match(result.output, /^node win-x64: verified$/m);
    writeFileSync(path.join(dir, 'win-x64-node.exe'), 'tampered executable');
    const tampered = verify(dir);
    assert.notEqual(tampered.status, null, tampered.output);
    assert.notEqual(tampered.status, 0, tampered.output);
    assert.match(tampered.output, /SHA-256 differs/);
  }, { windows: true });
});

test('openOrder accepts a 23-hour lifetime and refuses a 25-hour lifetime', () => {
  const key = randomBytes(32);
  const fingerprint = 'verify-node-broker';
  const issued = Date.parse('2026-10-30T00:00:00Z');
  const now = issued + 22 * 60 * 60_000;

  function openWithLifetime(hours: number) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(`wv-broker-order-v1|${fingerprint}`, 'utf8'));
    const plaintext = JSON.stringify({
      v: 1,
      type: 'update',
      broker: fingerprint,
      version: '9.8.7',
      order_id: 'sleeping-laptop',
      issued_at: new Date(issued).toISOString(),
      expires_at: new Date(issued + hours * 60 * 60_000).toISOString(),
    });
    const sealed = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    return openOrder(
      sealed.toString('base64'), nonce.toString('base64'), key,
      fingerprint, now, '9.8.6',
    );
  }

  assert.deepEqual(openWithLifetime(23), {
    ok: true,
    order: { version: '9.8.7', order_id: 'sleeping-laptop' },
  });
  assert.deepEqual(openWithLifetime(25), { ok: false, reason: 'malformed' });
});
