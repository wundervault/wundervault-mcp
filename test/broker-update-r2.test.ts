import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createCipheriv } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'vitest';
import { pollOnce } from '../src/broker-update.js';
import type { BrokerUpdateDeps, OrderState } from '../src/broker-update.js';

const now = Date.parse('2026-10-30T12:00:00Z');
const key = Buffer.alloc(32, 7);
const fingerprint = 'broker-test';

function envelope(id: string, changes: Record<string, unknown> = {}) {
  const nonce = Buffer.alloc(12, 3);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(`wv-broker-order-v1|${fingerprint}`));
  const plaintext = JSON.stringify({
    v: 1,
    type: 'update',
    broker: fingerprint,
    version: '2.2.0',
    order_id: id,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 60 * 60_000).toISOString(),
    ...changes,
  });
  const ciphertext = Buffer.concat([
    cipher.update(plaintext), cipher.final(), cipher.getAuthTag(),
  ]).toString('base64');
  return { id, agent_id: 'agent-test', ciphertext, nonce: nonce.toString('base64') };
}

function dependencies(dir: string, order = envelope('order-test')) {
  const posts: { id: string; state: OrderState; detail: string }[] = [];
  let failPost = true;
  const deps: BrokerUpdateDeps = {
    fingerprint,
    version: '2.1.0',
    client: {
      async getOrders() { return { orders: [order] }; },
      async postState(id, state, detail) {
        posts.push({ id, state, detail });
        if (failPost) throw new Error('offline');
      },
    },
    async vaultKeyFor() { return key; },
    seenPath: join(dir, 'seen.json'),
    requestPath: join(dir, 'request.json'),
    statusPath: join(dir, 'status.json'),
    now: () => now,
    log() {},
  };
  return { deps, posts, allowPosts() { failPost = false; } };
}

const refusals = [
  'no key', 'bad seal', 'wrong broker', 'expired', 'not newer',
  'malformed', 'replay', 'id mismatch',
];

for (const reason of refusals) {
  test(`refusal ${reason} is remembered only after a successful post`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'wv-order-r2-'));
    try {
      const changes: Record<string, unknown> = {};
      if (reason === 'wrong broker') changes.broker = 'other-broker';
      if (reason === 'expired') {
        changes.issued_at = new Date(now - 2 * 60 * 60_000).toISOString();
        changes.expires_at = new Date(now - 60 * 60_000).toISOString();
      }
      if (reason === 'not newer') changes.version = '2.1.0';
      if (reason === 'malformed') changes.v = 2;
      if (reason === 'replay' || reason === 'id mismatch') changes.order_id = 'other-order';
      const order = envelope('order-test', changes);
      if (reason === 'bad seal') order.ciphertext = 'AAAA';
      const fixture = dependencies(dir, order);
      if (reason === 'no key') fixture.deps.vaultKeyFor = async () => null;
      const initial = reason === 'replay' ? ['other-order'] : [];
      await writeFile(fixture.deps.seenPath, JSON.stringify(initial));

      await pollOnce(fixture.deps);
      assert.deepEqual(fixture.posts, [{ id: order.id, state: 'refused', detail: reason }]);
      assert.deepEqual(JSON.parse(await readFile(fixture.deps.seenPath, 'utf8')), initial);

      fixture.allowPosts();
      await pollOnce(fixture.deps);
      assert.equal(fixture.posts.length, 2);
      assert.deepEqual(fixture.posts[1], fixture.posts[0]);
      assert.deepEqual(JSON.parse(await readFile(fixture.deps.seenPath, 'utf8')), [...initial, order.id]);

      await pollOnce({ ...fixture.deps });
      assert.equal(fixture.posts.length, 2);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
}

test('accepted order is not handed over again after a failed received post', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wv-order-r2-'));
  try {
    const fixture = dependencies(dir);
    await writeFile(fixture.deps.requestPath, '');
    await pollOnce(fixture.deps);
    assert.deepEqual(fixture.posts, [{ id: 'order-test', state: 'received', detail: '' }]);
    assert.deepEqual(JSON.parse(await readFile(fixture.deps.seenPath, 'utf8')), ['order-test']);
    assert.deepEqual(JSON.parse(await readFile(fixture.deps.requestPath, 'utf8')), {
      version: '2.2.0', order_id: 'order-test',
    });

    await writeFile(fixture.deps.requestPath, 'already consumed');
    fixture.allowPosts();
    await pollOnce(fixture.deps);
    await pollOnce({ ...fixture.deps });
    assert.equal(await readFile(fixture.deps.requestPath, 'utf8'), 'already consumed');
    assert.equal(fixture.posts.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('no spool is remembered only after a successful failed post', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wv-order-r2-'));
  try {
    const fixture = dependencies(dir);
    await pollOnce(fixture.deps);
    assert.deepEqual(JSON.parse(await readFile(fixture.deps.seenPath, 'utf8')), []);
    fixture.allowPosts();
    await pollOnce(fixture.deps);
    assert.deepEqual(fixture.posts, [
      { id: 'order-test', state: 'failed', detail: 'no spool' },
      { id: 'order-test', state: 'failed', detail: 'no spool' },
    ]);
    await pollOnce({ ...fixture.deps });
    assert.equal(fixture.posts.length, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verify-release reports Node coverage and --require-node rejects missing files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wv-verify-r2-'));
  try {
    // Isolate CLI reporting from signature and archive validation, which have their own tests.
    await mkdir(join(dir, 'scripts', 'lib'), { recursive: true });
    await mkdir(join(dir, 'dist'));
    await mkdir(join(dir, 'files'));
    await writeFile(join(dir, 'package.json'), '{"type":"module"}');
    await copyFile(new URL('../scripts/verify-release.mjs', import.meta.url), join(dir, 'scripts', 'verify-release.mjs'));
    await writeFile(join(dir, 'scripts', 'lib', 'release-cli.mjs'), `
import { parseArgs } from 'node:util';
export const args = options => parseArgs({ options }).values;
export function required(values, names) {
  for (const name of names) if (!values[name]) throw new Error(name);
}
export const testKeyOptions = {};
export const verificationKeys = () => [];
export function main(run) {
  run().catch(error => { console.error(error.message); process.exitCode = 1; });
}
`);
    await writeFile(join(dir, 'dist', 'release-verify.js'), `
export const verifySignatures = () => ({ ok: true });
export const parseRecord = bytes => ({ ok: true, record: JSON.parse(bytes) });
export const sha256File = async () => 'fixture-hash';
`);
    await writeFile(join(dir, 'dist', 'release-keys.js'), 'export const RELEASE_KEYS = [];');
    await writeFile(join(dir, 'dist', 'tar-read.js'), `
export async function extractApp() {}
export async function extractNodeMember() {}
`);
    await writeFile(join(dir, 'dist', 'updater.js'), 'export const REQUIRED_APP_FILES = [];');
    const files = join(dir, 'files');
    await writeFile(join(files, 'release.json'), JSON.stringify({
      app: { sha256: 'fixture-hash' },
      node: {
        version: '22.0.0',
        'win-x64': { url: 'https://nodejs.org/dist/v22.0.0/win-x64/node.exe', sha256: 'fixture-hash' },
        'win-arm64': { url: 'https://nodejs.org/dist/v22.0.0/win-arm64/node.exe', sha256: 'fixture-hash' },
      },
    }));
    await writeFile(join(files, 'release.json.sigs'), '[]');
    await writeFile(join(files, 'win-x64-node.exe'), 'fixture');
    const run = (requireNode: boolean) => spawnSync(process.execPath, [
      join(dir, 'scripts', 'verify-release.mjs'),
      '--dir', files, '--version', '2.2.0',
      ...(requireNode ? ['--require-node'] : []),
    ], { encoding: 'utf8' });
    const summary = (verified: number, missing: number) =>
      `OK 2.2.0: app verified; node files: ${verified} verified, ${missing} not present (their hashes come from Node's signed SHASUMS256 when the record is built)`;

    const optional = run(false);
    assert.equal(optional.status, 0, optional.stderr);
    assert.equal(optional.stdout.trim().split('\n').at(-1), summary(1, 1));

    const required = run(true);
    assert.equal(required.status, 1, required.stderr);
    assert.match(required.stderr, /--require-node/);
    assert.equal(required.stdout.trim().split('\n').at(-1), summary(1, 1));

    await writeFile(join(files, 'win-arm64-node.exe'), 'fixture');
    const complete = run(true);
    assert.equal(complete.status, 0, complete.stderr);
    assert.equal(complete.stdout.trim().split('\n').at(-1), summary(2, 0));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
