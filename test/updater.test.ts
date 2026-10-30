import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  RELEASE_BASE, REQUIRED_APP_FILES, checkEnv, runOnce, selfTestMain, type UpdaterDeps,
} from '../src/updater.js';
import { DEFAULT_LIMITS, type ReleaseRecord } from '../src/release-verify.js';
import type { ReleaseKey } from '../src/release-keys.js';
import { tarGz, type TarEntry } from './helpers/tar-write.js';

const directories: string[] = [];
const OLD = '1.0.0';
const NEW = '1.1.0';
const ID = 'order_1';
const hash = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const keypair = generateKeyPairSync('ed25519');
const keys: ReleaseKey[] = [{
  id: 'updater-test',
  publicKey: Buffer.from(keypair.publicKey.export({ format: 'jwk' }).x as string, 'base64url').toString('base64'),
  test: true,
}];

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(k =>
      `${JSON.stringify(k)}:${canonical(record[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function json(file: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown>;
}

function put(file: string, value: unknown): void {
  fs.writeFileSync(file, JSON.stringify(value));
}

function appEntries(): TarEntry[] {
  return REQUIRED_APP_FILES.map(file => ({
    name: `app/${file}`,
    data: file === 'package.json' ? '{"name":"updater-fixture"}' : `fixture: ${file}\n`,
  }));
}

function fixture() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-updater-test-'));
  directories.push(base);
  const root = path.join(base, 'install');
  const spool = path.join(base, 'spool');
  const state = path.join(root, 'state');
  const versions = path.join(root, 'versions');
  fs.mkdirSync(state, { recursive: true });
  fs.mkdirSync(versions);
  fs.mkdirSync(spool);
  fs.mkdirSync(path.join(versions, OLD));
  put(path.join(state, 'highest.json'), { version: OLD });
  put(path.join(state, 'history.json'), [OLD]);
  fs.writeFileSync(path.join(spool, 'request.json'), JSON.stringify({ version: NEW, order_id: ID }));

  const app = tarGz(appEntries());
  const nodeBytes = Buffer.from('fake node executable');
  const appUrl = `${RELEASE_BASE}/v${NEW}/wundervault-app-${NEW}.tar.gz`;
  const nodeVersion = '22.23.4';
  const node: ReleaseRecord['node'] = { version: nodeVersion };
  for (const platform of [
    'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'win-x64', 'win-arm64',
  ] as const) {
    const windows = platform.startsWith('win-');
    node[platform] = {
      url: `https://nodejs.org/dist/v${nodeVersion}/${windows ?
        `${platform}/node.exe` : `node-v${nodeVersion}-${platform}.tar.gz`}`,
      sha256: hash(nodeBytes),
      ...(windows ? {} : { member: `node-v${nodeVersion}-${platform}/bin/node` }),
    };
  }
  const record: ReleaseRecord = {
    format: 'wundervault-release-1',
    version: NEW,
    app: {
      url: appUrl, sha256: hash(app),
    },
    node,
    notes_url: `${RELEASE_BASE}/v${NEW}/release.json`,
  };
  const responses = new Map<string, Buffer>([
    [appUrl, app],
    [node['linux-x64']!.url, nodeBytes],
  ]);
  const calls = {
    fetch: [] as string[],
    download: [] as string[],
    restart: 0,
    selfTest: 0,
    installNode: 0,
    ping: 0,
    descriptors: [] as string[],
    logs: [] as string[],
  };
  let running: string | null = OLD;
  let now = 1_800_000_000_000;
  let disk = 2 * 1024 * 1024 * 1024;
  let selfTest = true;
  let ping: () => { version: string; store_ok: boolean } | null =
    () => ({ version: running ?? '', store_ok: true });

  const d: UpdaterDeps = {
    root, spool, platform: 'linux-x64', keys, limits: DEFAULT_LIMITS,
    expectRequestOwner: null,
    openRequest(file) {
      try {
        return { fd: fs.openSync(file, 'r') };
      } catch (error) {
        return { refused: (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'missing' : 'request file' };
      }
    },
    async fetchBytes(url) {
      calls.fetch.push(url);
      const bytes = responses.get(url);
      if (!bytes) throw new Error('missing fake response');
      return bytes;
    },
    async download(url, dest) {
      calls.download.push(url);
      const bytes = responses.get(url);
      if (!bytes) throw new Error('missing fake response');
      fs.writeFileSync(dest, bytes, { flag: 'wx' });
    },
    freeBytes: () => disk,
    readDescriptor: () => running,
    writeDescriptor(v) {
      calls.descriptors.push(v);
      running = v;
    },
    async installNode(dir) {
      calls.installNode++;
      fs.writeFileSync(path.join(dir, 'node'), nodeBytes, { flag: 'wx' });
    },
    async restartBroker() {
      calls.restart++;
    },
    async ping() {
      calls.ping++;
      return ping();
    },
    async selfTest() {
      calls.selfTest++;
      return selfTest;
    },
    now: () => now,
    async sleep(ms) {
      now += ms;
    },
    log: message => calls.logs.push(message),
  };
  const resign = (): void => {
    const bytes = Buffer.from(canonical(record));
    responses.set(`${RELEASE_BASE}/v${NEW}/release.json`, bytes);
    responses.set(`${RELEASE_BASE}/v${NEW}/release.json.sigs`, Buffer.from(JSON.stringify([{
      key_id: keys[0]!.id,
      sig: sign(null, bytes, keypair.privateKey).toString('base64'),
    }])));
  };
  resign();

  return {
    d, root, spool, state, versions, calls, responses, record, resign,
    status: () => json(path.join(spool, 'status.json')),
    running: () => running,
    setDisk: (value: number) => { disk = value; },
    setSelfTest: (value: boolean) => { selfTest = value; },
    setPing: (value: typeof ping) => { ping = value; },
    setRunning: (value: string | null) => { running = value; },
    request: (value: unknown) => put(path.join(spool, 'request.json'), value),
    journal(phase: 'switching' | 'switched', from: string | null = OLD) {
      put(path.join(state, 'journal.json'), {
        phase, from, to: NEW, order_id: ID, at: new Date(now).toISOString(),
      });
    },
    makeVersion(v: string) {
      fs.mkdirSync(path.join(versions, v), { recursive: true });
    },
  };
}

afterEach(() => {
  for (const dir of directories.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('updater flow', () => {
  it('installs a signed release, commits history, and prunes old versions', async () => {
    const f = fixture();
    for (const v of ['0.7.0', '0.8.0', '0.9.0']) f.makeVersion(v);
    put(path.join(f.state, 'history.json'), ['0.7.0', '0.8.0', '0.9.0', OLD]);
    expect(await runOnce(f.d)).toBe('done');
    expect(f.running()).toBe(NEW);
    expect(json(path.join(f.state, 'highest.json'))).toEqual({ version: NEW });
    expect(f.status()).toMatchObject({ state: 'installed', version: NEW, order_id: ID });
    expect(JSON.parse(fs.readFileSync(path.join(f.state, 'history.json'), 'utf8'))).toEqual([
      '0.7.0', '0.8.0', '0.9.0', OLD, NEW,
    ]);
    expect(fs.readdirSync(f.versions).sort()).toEqual(['0.9.0', OLD, NEW].sort());
    expect(fs.readFileSync(path.join(f.versions, NEW, 'app', 'package.json'), 'utf8'))
      .toBe('{"name":"updater-fixture"}');
    for (const file of REQUIRED_APP_FILES) {
      expect(fs.statSync(path.join(f.versions, NEW, 'app', file)).isFile()).toBe(true);
    }
    expect(f.calls.restart).toBe(1);
    expect(f.calls.selfTest).toBe(1);
    expect(f.calls.installNode).toBe(1);
    expect(json(path.join(f.state, 'journal.json')).phase).toBe('committed');
    expect(fs.existsSync(path.join(f.root, `tmp-${ID}`))).toBe(false);
    expect(fs.existsSync(path.join(f.state, 'lock'))).toBe(false);
  });

  it.each(['missing', 'empty'])('does nothing for a %s request', async kind => {
    const f = fixture();
    const file = path.join(f.spool, 'request.json');
    if (kind === 'missing') fs.unlinkSync(file);
    else fs.writeFileSync(file, '');
    expect(await runOnce(f.d)).toBe('idle');
    expect(f.calls.fetch).toEqual([]);
    expect(f.calls.restart).toBe(0);
  });

  it('refuses a 4097-byte request', async () => {
    const f = fixture();
    fs.writeFileSync(path.join(f.spool, 'request.json'), Buffer.alloc(4097, 32));
    expect(await runOnce(f.d)).toBe('done');
    expect(f.status()).toMatchObject({ state: 'refused', detail: 'request file' });
    expect(f.calls.fetch).toEqual([]);
  });

  it('uses the request opener refusal without trying to read a path itself', async () => {
    const f = fixture();
    f.d.openRequest = () => ({ refused: 'request file' });
    expect(await runOnce(f.d)).toBe('done');
    expect(f.status()).toMatchObject({ state: 'refused', detail: 'request file' });
  });

  it('counts three consecutive malformed requests and resets after an empty tick', async () => {
    const f = fixture();
    fs.writeFileSync(path.join(f.spool, 'request.json'), '{"version":');
    expect(await runOnce(f.d)).toBe('idle');
    fs.writeFileSync(path.join(f.spool, 'request.json'), '');
    expect(await runOnce(f.d)).toBe('idle');
    fs.writeFileSync(path.join(f.spool, 'request.json'), '{"version":');
    expect(await runOnce(f.d)).toBe('idle');
    expect(await runOnce(f.d)).toBe('idle');
    expect(await runOnce(f.d)).toBe('done');
    expect(f.status()).toMatchObject({ state: 'refused', detail: 'request' });
  });

  it.each([
    '{"version":"1.1.0","version":"1.1.0","order_id":"order_1"}',
    '{"version":"1.1.0","order_id":"order_1","extra":true}',
    '{"version":"../1.1.0","order_id":"order_1"}',
    '{"version":"1.1.0","order_id":"../outside"}',
  ])('rejects non-strict request %s', async text => {
    const f = fixture();
    fs.writeFileSync(path.join(f.spool, 'request.json'), text);
    await runOnce(f.d);
    await runOnce(f.d);
    await runOnce(f.d);
    expect(f.status()).toMatchObject({ state: 'refused', detail: 'request' });
    expect(f.calls.fetch).toEqual([]);
  });

  it.each(['installed', 'rolled back', 'rollback failed', 'refused', 'failed'])(
    'never repeats a terminal %s order', async state => {
      const f = fixture();
      put(path.join(f.spool, 'status.json'), {
        order_id: ID, state, version: NEW, detail: '', at: new Date().toISOString(),
      });
      expect(await runOnce(f.d)).toBe('idle');
      expect(f.calls.fetch).toEqual([]);
      expect(f.calls.restart).toBe(0);
    },
  );

  it('refuses an older version', async () => {
    const f = fixture();
    f.request({ version: '0.9.0', order_id: ID });
    await runOnce(f.d);
    expect(f.status()).toMatchObject({ state: 'refused', detail: 'older version' });
    expect(f.calls.fetch).toEqual([]);
  });

  it('reports the running version installed without downloading', async () => {
    const f = fixture();
    f.request({ version: OLD, order_id: ID });
    await runOnce(f.d);
    expect(f.status()).toMatchObject({ state: 'installed', version: OLD });
    expect(f.calls.fetch).toEqual([]);
  });

  it('does not lower the high-water mark after a rollback', async () => {
    const f = fixture();
    put(path.join(f.state, 'highest.json'), { version: '1.2.0' });
    await runOnce(f.d);
    expect(f.status()).toMatchObject({ state: 'refused', detail: 'older version' });
    expect(json(path.join(f.state, 'highest.json')).version).toBe('1.2.0');
    expect(f.calls.fetch).toEqual([]);
  });

  it('refuses insufficient disk space before fetching', async () => {
    const f = fixture();
    f.setDisk(600 * 1024 * 1024 - 1);
    await runOnce(f.d);
    expect(f.status()).toMatchObject({ state: 'failed', detail: 'disk space' });
    expect(f.calls.fetch).toEqual([]);
  });

  it('rejects a bad signature before downloading archives', async () => {
    const f = fixture();
    f.responses.set(`${RELEASE_BASE}/v${NEW}/release.json.sigs`, Buffer.from(JSON.stringify([{
      key_id: keys[0]!.id, sig: Buffer.alloc(64).toString('base64'),
    }])));
    await runOnce(f.d);
    expect(f.status().state).toBe('failed');
    expect(f.calls.download).toEqual([]);
    expect(f.running()).toBe(OLD);
  });

  it('rejects a signature by an unknown key before downloading archives', async () => {
    const f = fixture();
    const bytes = f.responses.get(`${RELEASE_BASE}/v${NEW}/release.json`)!;
    f.responses.set(`${RELEASE_BASE}/v${NEW}/release.json.sigs`, Buffer.from(JSON.stringify([{
      key_id: 'unknown-key', sig: sign(null, bytes, keypair.privateKey).toString('base64'),
    }])));
    await runOnce(f.d);
    expect(f.status().state).toBe('failed');
    expect(f.calls.download).toEqual([]);
    expect(f.running()).toBe(OLD);
  });

  it('rejects a correctly signed record for a different version', async () => {
    const f = fixture();
    f.record.version = '1.2.0';
    f.resign();
    await runOnce(f.d);
    expect(f.status().state).toBe('failed');
    expect(f.calls.download).toEqual([]);
    expect(f.running()).toBe(OLD);
  });

  it('rejects the obsolete app.files key even in a correctly signed record', async () => {
    const f = fixture();
    Object.assign(f.record.app, { files: [] });
    f.resign();
    await runOnce(f.d);
    expect(f.status()).toMatchObject({
      state: 'failed', detail: 'record: unknown key app.files',
    });
    expect(f.calls.download).toEqual([]);
    expect(f.running()).toBe(OLD);
  });

  it('rejects a correctly signed record with an off-host archive URL', async () => {
    const f = fixture();
    f.record.app.url = 'https://example.com/app.tar.gz';
    f.resign();
    await runOnce(f.d);
    expect(f.status().state).toBe('failed');
    expect(f.calls.download).toEqual([]);
    expect(f.running()).toBe(OLD);
  });

  it.each(['app', 'node'])('checks the %s archive hash before parsing', async which => {
    const f = fixture();
    const url = which === 'app' ? f.record.app.url : f.record.node['linux-x64']!.url;
    f.responses.set(url, Buffer.from('corrupt'));
    await runOnce(f.d);
    expect(f.status()).toMatchObject({ state: 'failed', detail: 'hash mismatch' });
    expect(f.calls.installNode).toBe(0);
    expect(f.calls.selfTest).toBe(0);
    expect(f.running()).toBe(OLD);
    expect(fs.existsSync(path.join(f.versions, `${NEW}.staging`))).toBe(false);
  });

  it.each(REQUIRED_APP_FILES)('refuses a signed archive missing required file %s', async missing => {
    const f = fixture();
    const outside = path.join(path.dirname(f.root), 'sentinel');
    fs.writeFileSync(outside, 'sentinel');
    const bad = tarGz(appEntries().filter(entry => entry.name !== `app/${missing}`));
    f.responses.set(f.record.app.url, bad);
    f.record.app.sha256 = hash(bad);
    f.resign();
    expect(await runOnce(f.d)).toBe('done');
    expect(f.status()).toMatchObject({
      state: 'failed', detail: `archive: missing required file app/${missing}`,
    });
    expect(f.running()).toBe(OLD);
    expect(f.calls.installNode).toBe(0);
    expect(f.calls.selfTest).toBe(0);
    expect(f.calls.restart).toBe(0);
    expect(fs.existsSync(path.join(f.versions, `${NEW}.staging`))).toBe(false);
    expect(fs.existsSync(path.join(f.root, `tmp-${ID}`))).toBe(false);
    expect(fs.readFileSync(outside, 'utf8')).toBe('sentinel');
  });

  it.each([
    ['symlink', [{ name: 'app/link', type: '2', linkname: '/outside' }]],
    ['hard link', [{ name: 'app/link', type: '1', linkname: 'app/package.json' }]],
    ['device', [{ name: 'app/device', type: '3' }]],
    ['FIFO', [{ name: 'app/fifo', type: '6' }]],
    ['GNU long name', [{ name: 'app/long', type: 'L', data: 'app/other\0' }]],
    ['parent traversal', [{ name: 'app/../../../sentinel', data: 'changed' }]],
    ['absolute path', [{ name: '/sentinel', data: 'changed' }]],
    ['outside app', [{ name: 'other/file', data: 'changed' }]],
    ['dotfile', [{ name: 'app/.hidden', data: 'changed' }]],
    ['duplicate file', [{ name: 'app/PACKAGE.JSON', data: '{}' }]],
    ['file/directory collision', [{ name: 'app/package.json/', type: '5' }]],
    ['file ancestor', [
      { name: 'app/parent', data: 'file' },
      { name: 'app/parent/child', data: 'child' },
    ]],
  ] as [string, TarEntry[]][])('removes staging after a signed archive contains %s', async (_kind, entries) => {
    const f = fixture();
    const outside = path.join(path.dirname(f.root), 'sentinel');
    fs.writeFileSync(outside, 'sentinel');
    const bad = tarGz([...appEntries(), ...entries]);
    f.responses.set(f.record.app.url, bad);
    f.record.app.sha256 = hash(bad);
    f.resign();
    expect(await runOnce(f.d)).toBe('done');
    expect(f.status().state).toBe('failed');
    expect(f.running()).toBe(OLD);
    expect(f.calls.descriptors).toEqual([]);
    expect(f.calls.installNode).toBe(0);
    expect(f.calls.selfTest).toBe(0);
    expect(f.calls.restart).toBe(0);
    expect(fs.existsSync(path.join(f.versions, `${NEW}.staging`))).toBe(false);
    expect(fs.existsSync(path.join(f.root, `tmp-${ID}`))).toBe(false);
    expect(fs.readFileSync(outside, 'utf8')).toBe('sentinel');
  });

  it('does not switch a release that fails self-test', async () => {
    const f = fixture();
    f.setSelfTest(false);
    await runOnce(f.d);
    expect(f.status()).toMatchObject({ state: 'failed', detail: 'self-test' });
    expect(f.running()).toBe(OLD);
    expect(fs.existsSync(path.join(f.versions, `${NEW}.staging`))).toBe(false);
    expect(f.calls.restart).toBe(0);
  });

  it('rolls back an unhealthy new broker and retains its failed folder', async () => {
    const f = fixture();
    f.setPing(() => ({ version: f.running() ?? '', store_ok: f.running() === OLD }));
    await runOnce(f.d);
    expect(f.status()).toMatchObject({
      state: 'rolled back', detail: 'new version not healthy', version: NEW,
    });
    expect(f.running()).toBe(OLD);
    expect(f.calls.restart).toBe(2);
    expect(json(path.join(f.state, 'highest.json')).version).toBe(OLD);
    expect(JSON.parse(fs.readFileSync(path.join(f.state, 'failed.json'), 'utf8'))).toEqual([NEW]);
    expect(fs.existsSync(path.join(f.versions, NEW))).toBe(true);
    const count = f.calls.fetch.length;
    expect(await runOnce(f.d)).toBe('idle');
    expect(f.calls.fetch.length).toBe(count);
  });

  it('reports rollback failure when neither broker is healthy', async () => {
    const f = fixture();
    f.setPing(() => null);
    await runOnce(f.d);
    expect(f.status()).toMatchObject({ state: 'rollback failed', detail: 'new version not healthy' });
    expect(f.calls.restart).toBe(2);
    // Round 1 (A-F5): a failed rollback is committed, so later ticks don't restart the broker again.
    expect(json(path.join(f.state, 'journal.json')).phase).toBe('committed');
  });

  it('resumes switching when the descriptor already points at the new folder', async () => {
    const f = fixture();
    f.makeVersion(NEW);
    f.setRunning(NEW);
    f.journal('switching');
    expect(await runOnce(f.d)).toBe('done');
    expect(f.status().state).toBe('installed');
    expect(json(path.join(f.state, 'highest.json')).version).toBe(NEW);
    expect(f.calls.fetch).toEqual([]);
    expect(f.calls.restart).toBe(1);
  });

  it.each([false, true])('undoes interrupted switching without a switched descriptor (folder=%s)', async exists => {
    const f = fixture();
    if (exists) f.makeVersion(NEW);
    f.journal('switching');
    await runOnce(f.d);
    expect(f.running()).toBe(OLD);
    expect(f.status()).toMatchObject({ state: 'failed', detail: 'interrupted' });
    expect(json(path.join(f.state, 'journal.json'))).toMatchObject({ phase: 'committed', to: OLD });
    expect(f.calls.fetch).toEqual([]);
    // Round 3 (A-F3): a version renamed into place but never switched to is not left behind.
    expect(fs.existsSync(path.join(f.versions, NEW))).toBe(false);
  });

  it('resumes switched by restarting and committing a healthy broker', async () => {
    const f = fixture();
    f.makeVersion(NEW);
    f.setRunning(NEW);
    f.journal('switched');
    await runOnce(f.d);
    expect(f.status().state).toBe('installed');
    expect(f.calls.restart).toBe(1);
    expect(f.calls.fetch).toEqual([]);
    expect(json(path.join(f.state, 'highest.json')).version).toBe(NEW);
  });

  it('resumes switched by rolling back an unhealthy broker', async () => {
    const f = fixture();
    f.makeVersion(NEW);
    f.setRunning(NEW);
    f.journal('switched');
    f.setPing(() => ({ version: f.running() ?? '', store_ok: f.running() === OLD }));
    await runOnce(f.d);
    expect(f.status().state).toBe('rolled back');
    expect(f.running()).toBe(OLD);
    expect(f.calls.restart).toBe(2);
    expect(f.calls.fetch).toEqual([]);
  });

  it('breaks an old lock even if its pid is alive', async () => {
    const f = fixture();
    fs.writeFileSync(path.join(f.state, 'lock'), `${process.pid} ${f.d.now() - 20 * 60_000 - 1}`);
    await runOnce(f.d);
    expect(f.status().state).toBe('installed');
    expect(fs.existsSync(path.join(f.state, 'lock'))).toBe(false);
  });

  it('leaves a live lock and returns busy', async () => {
    const f = fixture();
    const content = `${process.pid} ${f.d.now()}`;
    fs.writeFileSync(path.join(f.state, 'lock'), content);
    expect(await runOnce(f.d)).toBe('busy');
    expect(f.calls.fetch).toEqual([]);
    expect(fs.readFileSync(path.join(f.state, 'lock'), 'utf8')).toBe(content);
  });

  it('keeps three good versions and one failed version without following links', async () => {
    const f = fixture();
    for (const v of ['0.7.0', '0.8.0', '0.9.0', '1.0.1']) f.makeVersion(v);
    put(path.join(f.state, 'history.json'), ['0.7.0', '0.8.0', '0.9.0', OLD]);
    put(path.join(f.state, 'failed.json'), ['1.0.1']);
    const outside = path.join(path.dirname(f.root), 'sentinel');
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'keep'), 'sentinel');
    fs.symlinkSync(outside, path.join(f.versions, 'unlisted'), process.platform === 'win32' ? 'junction' : 'dir');
    await runOnce(f.d);
    expect(fs.readdirSync(f.versions).sort()).toEqual(['0.9.0', OLD, '1.0.1', NEW].sort());
    expect(fs.readFileSync(path.join(outside, 'keep'), 'utf8')).toBe('sentinel');
  });

  it('keeps only the newest failed folder after another failed update', async () => {
    const f = fixture();
    f.makeVersion('1.0.1');
    put(path.join(f.state, 'failed.json'), ['1.0.1']);
    f.setPing(() => ({ version: f.running() ?? '', store_ok: f.running() === OLD }));
    await runOnce(f.d);
    expect(fs.existsSync(path.join(f.versions, '1.0.1'))).toBe(false);
    expect(fs.existsSync(path.join(f.versions, NEW))).toBe(true);
    expect(JSON.parse(fs.readFileSync(path.join(f.state, 'failed.json'), 'utf8'))).toEqual([NEW]);
  });
});

describe('updater entry checks', () => {
  it.each([
    'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_REPL_EXTERNAL_MODULE',
    'WUNDERVAULT_ROOT', 'WUNDERVAULT_ANYTHING',
  ])('rejects %s even when empty', name => {
    expect(checkEnv({ [name]: 'value' })).not.toBeNull();
    expect(checkEnv({ [name]: '' })).not.toBeNull();
  });

  it('allows ordinary environment variables and unset unsafe variables', () => {
    expect(checkEnv({ PATH: '/usr/bin', NODE_OPTIONS: undefined })).toBeNull();
  });

  it('verifies and extracts its in-process self-test fixture', async () => {
    expect(await selfTestMain()).toBe(true);
  });
});
