import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  RELEASE_BASE, REQUIRED_APP_FILES, runOnce, type UpdaterDeps,
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
  id: 'updater-r1-test',
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
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-updater-r1-test-'));
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
  put(path.join(spool, 'request.json'), { version: NEW, order_id: ID });

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
  const bytes = Buffer.from(canonical(record));
  const responses = new Map<string, Buffer>([
    [appUrl, app],
    [node['linux-x64']!.url, nodeBytes],
    [`${RELEASE_BASE}/v${NEW}/release.json`, bytes],
    [`${RELEASE_BASE}/v${NEW}/release.json.sigs`, Buffer.from(JSON.stringify([{
      key_id: keys[0]!.id,
      sig: sign(null, bytes, keypair.privateKey).toString('base64'),
    }]))],
  ]);
  const calls = {
    fetch: [] as string[],
    download: [] as string[],
    restart: 0,
    descriptors: [] as string[],
    logs: [] as string[],
  };
  let running: string | null = OLD;
  let now = 1_800_000_000_000;
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
      const response = responses.get(url);
      if (!response) throw new Error('missing fake response');
      return response;
    },
    async download(url, dest) {
      calls.download.push(url);
      const response = responses.get(url);
      if (!response) throw new Error('missing fake response');
      fs.writeFileSync(dest, response, { flag: 'wx' });
    },
    freeBytes: () => 2 * 1024 * 1024 * 1024,
    readDescriptor: () => running,
    writeDescriptor(v) {
      calls.descriptors.push(v);
      running = v;
    },
    async installNode(dir) {
      fs.writeFileSync(path.join(dir, 'node'), nodeBytes, { flag: 'wx' });
    },
    async restartBroker() {
      calls.restart++;
    },
    async ping() {
      return ping();
    },
    async selfTest() {
      return selfTest;
    },
    now: () => now,
    async sleep(ms) {
      now += ms;
    },
    log: message => calls.logs.push(message),
  };

  return {
    d, root, spool, state, versions, calls,
    status: () => json(path.join(spool, 'status.json')),
    running: () => running,
    setSelfTest: (value: boolean) => { selfTest = value; },
    setPing: (value: typeof ping) => { ping = value; },
    request: (value: unknown) => put(path.join(spool, 'request.json'), value),
  };
}

afterEach(() => {
  for (const dir of directories.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function umaskSettable(): boolean {
  try { const was = process.umask(0o022); process.umask(was); return true; } catch { return false; }
}

describe('updater round 1 regressions', () => {
  it('does not refetch an earlier failed order after a later order replaces status.json', async () => {
    const f = fixture();
    f.setSelfTest(false);
    expect(await runOnce(f.d)).toBe('done');
    expect(f.status()).toMatchObject({ order_id: ID, state: 'failed', detail: 'self-test' });
    const firstFetches = f.calls.fetch.length;
    expect(firstFetches).toBe(2);

    f.request({ version: NEW, order_id: 'order_2' });
    expect(await runOnce(f.d)).toBe('done');
    expect(f.status()).toMatchObject({ order_id: 'order_2', state: 'failed', detail: 'self-test' });
    expect(f.calls.fetch.length).toBe(firstFetches + 2);
    expect(JSON.parse(fs.readFileSync(path.join(f.state, 'orders.json'), 'utf8'))).toEqual([
      ID, 'order_2',
    ]);

    const fetches = f.calls.fetch.length;
    const downloads = f.calls.download.length;
    f.request({ version: NEW, order_id: ID });
    expect(await runOnce(f.d)).toBe('idle');
    expect(f.calls.fetch.length).toBe(fetches);
    expect(f.calls.download.length).toBe(downloads);
    expect(f.calls.restart).toBe(0);
    expect(f.status()).toMatchObject({ order_id: 'order_2', state: 'failed' });
  });

  it('honours a malformed young lock as busy', async () => {
    const f = fixture();
    const lock = path.join(f.state, 'lock');
    fs.writeFileSync(lock, '');
    const at = new Date(f.d.now());
    fs.utimesSync(lock, at, at);

    expect(await runOnce(f.d)).toBe('busy');
    expect(f.calls.fetch).toEqual([]);
    expect(f.calls.restart).toBe(0);
    expect(fs.readFileSync(lock, 'utf8')).toBe('');
    expect(fs.readdirSync(f.state).filter(name => name.startsWith('lock.tmp-'))).toEqual([]);
  });

  it('breaks a malformed lock only after twenty minutes', async () => {
    const f = fixture();
    const lock = path.join(f.state, 'lock');
    fs.writeFileSync(lock, 'incomplete lock');
    const at = new Date(f.d.now() - 21 * 60_000);
    fs.utimesSync(lock, at, at);

    expect(await runOnce(f.d)).toBe('done');
    expect(f.status()).toMatchObject({ order_id: ID, state: 'installed' });
    expect(f.running()).toBe(NEW);
    expect(fs.existsSync(lock)).toBe(false);
    expect(fs.readdirSync(f.state).filter(name => name.startsWith('lock.tmp-'))).toEqual([]);
  });

  it('commits a failed rollback and does not restart the broker on the next tick', async () => {
    const f = fixture();
    f.setPing(() => null);

    expect(await runOnce(f.d)).toBe('done');
    expect(f.status()).toMatchObject({
      order_id: ID, state: 'rollback failed', detail: 'new version not healthy',
    });
    expect(f.running()).toBe(OLD);
    expect(f.calls.restart).toBe(2);
    expect(f.calls.descriptors).toEqual([NEW, OLD]);
    expect(json(path.join(f.state, 'journal.json'))).toMatchObject({
      phase: 'committed', from: OLD, to: OLD, order_id: ID,
    });

    const fetches = f.calls.fetch.length;
    expect(await runOnce(f.d)).toBe('idle');
    expect(f.calls.restart).toBe(2);
    expect(f.calls.descriptors).toEqual([NEW, OLD]);
    expect(f.calls.fetch.length).toBe(fetches);
    expect(f.status()).toMatchObject({ order_id: ID, state: 'rollback failed' });
  });

  // vitest runs files in worker threads, where process.umask() can't be set; the real-machine run
  // (systemd container) checks the modes of an installed update instead.
  (process.platform === 'win32' || !umaskSettable() ? it.skip : it)(
    'sets public and private modes explicitly under a restrictive umask',
    async () => {
      const f = fixture();
      const previous = process.umask(0o077);
      try {
        expect(await runOnce(f.d)).toBe('done');
      } finally {
        process.umask(previous);
      }

      expect(f.status()).toMatchObject({ state: 'installed', version: NEW });
      for (const dir of [
        f.versions,
        path.join(f.versions, NEW),
        path.join(f.versions, NEW, 'app'),
        path.join(f.versions, NEW, 'app', 'bin'),
        path.join(f.versions, NEW, 'app', 'dist'),
      ]) {
        expect(fs.statSync(dir).mode & 0o777).toBe(0o755);
      }
      expect(fs.statSync(path.join(f.spool, 'status.json')).mode & 0o777).toBe(0o644);
      expect(fs.statSync(path.join(f.versions, NEW, 'app', 'package.json')).mode & 0o777).toBe(0o644);
      expect(fs.statSync(f.state).mode & 0o777).toBe(0o700);
      for (const file of ['orders.json', 'highest.json', 'journal.json', 'malformed.json']) {
        expect(fs.statSync(path.join(f.state, file)).mode & 0o777).toBe(0o600);
      }
    },
  );
});
