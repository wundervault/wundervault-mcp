import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type { ReleaseKey } from './release-keys.js';
import {
  DEFAULT_LIMITS,
  compareVersions,
  parseVersion,
  verifySignatures,
  parseRecord,
  sha256File,
  type Platform,
  type ReleaseRecord,
} from './release-verify.js';
import { extractApp } from './tar-read.js';

/** A release missing any of these can't start, update or hand over, so it fails before the switch. */
export const REQUIRED_APP_FILES: readonly string[] = [
  'package.json', 'dist/index.js', 'dist/agent.js', 'dist/updater.js',
  'bin/package.json', 'bin/_handover.js', 'bin/wundervault-mcp', 'bin/wundervault-agent',
];

export const RELEASE_BASE = 'https://github.com/wundervault/wundervault-mcp/releases/download';

export interface UpdaterDeps {
  root: string;
  spool: string;
  platform: Platform;
  keys: readonly ReleaseKey[];
  limits: typeof DEFAULT_LIMITS;
  expectRequestOwner: { uid: number; gid: number } | null;
  openRequest(path: string): { fd: number } | { refused: string };
  fetchBytes(url: string, maxBytes: number, timeoutMs: number): Promise<Buffer>;
  download(url: string, dest: string, maxBytes: number, deadlineMs: number): Promise<void>;
  freeBytes(dir: string): number;
  readDescriptor(): string | null;
  writeDescriptor(version: string): void;
  installNode(versionDir: string, record: ReleaseRecord, tmpDir: string): Promise<void>;
  restartBroker(): Promise<void>;
  ping(): Promise<{ version: string; store_ok: boolean } | null>;
  selfTest(versionDir: string): Promise<boolean>;
  now(): number;
  sleep(ms: number): Promise<void>;
  log(msg: string): void;
}

type State = 'working' | 'installed' | 'rolled back' | 'rollback failed' | 'refused' | 'failed';
interface Order {
  version: string;
  order_id: string;
}
interface Journal {
  phase: 'switching' | 'switched' | 'committed';
  from: string | null;
  to: string | null;
  order_id: string;
  at: string;
}
interface Status extends Order {
  state: State;
  detail: string;
  at: string;
}

const TERMINAL = new Set<State>(['installed', 'rolled back', 'rollback failed', 'refused', 'failed']);
const ORDER_ID = /^[A-Za-z0-9_-]{1,64}$/;
const UNSPECIFIED: Order = { version: '', order_id: '' };

function version(value: unknown): value is string {
  return typeof value === 'string' && parseVersion(value) !== null;
}

function readJson(file: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function syncDirectory(dir: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(dir, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (!['EINVAL', 'ENOTSUP', 'EPERM', 'EISDIR', 'EBADF'].includes(code ?? '')) throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function atomicJson(file: string, value: unknown, mode = 0o600): void {
  const temp = `${file}.tmp-${process.pid}`;
  let fd: number | undefined;
  try {
    fs.rmSync(temp, { force: true });
    fd = fs.openSync(temp, 'wx', mode);
    fs.fchmodSync(fd, mode);
    fs.writeFileSync(fd, JSON.stringify(value));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temp, file);
    syncDirectory(path.dirname(file));
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(temp, { force: true });
  }
}

function removeTree(file: string): void {
  try {
    // Unlink a top-level link rather than ever descending through it.
    if (fs.lstatSync(file).isSymbolicLink()) fs.unlinkSync(file);
    else fs.rmSync(file, { recursive: true, force: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

function acquireLock(file: string, startedAt: number): (() => void) | null {
  const temp = `${file}.tmp-${process.pid}`;
  const contents = `${process.pid} ${startedAt}`;
  let fd: number | undefined;
  try {
    fs.rmSync(temp, { force: true });
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, contents);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        // Publish only a complete lock; another process never sees an empty one.
        fs.linkSync(temp, file);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        let stale = false;
        try {
          const stat = fs.statSync(file);
          const text = fs.readFileSync(file, 'utf8');
          const match = /^(\d+) (\d+)$/.exec(text);
          const pid = match ? Number(match[1]) : NaN;
          const at = match ? Number(match[2]) : NaN;
          if (!Number.isSafeInteger(pid) || pid <= 0 ||
              !Number.isSafeInteger(at) || at < 0) {
            stale = startedAt - stat.mtimeMs > 20 * 60_000;
          } else {
            stale = startedAt - at > 20 * 60_000;
            if (!stale) {
              try {
                process.kill(pid, 0);
              } catch (probeError) {
                stale = (probeError as NodeJS.ErrnoException).code === 'ESRCH';
              }
            }
          }
        } catch (readError) {
          if ((readError as NodeJS.ErrnoException).code === 'ENOENT') continue;
          throw readError;
        }
        if (!stale) return null;
        fs.rmSync(file, { force: true });
        continue;
      }
      return () => {
        // A run older than twenty minutes must not remove its successor's lock.
        try {
          if (fs.readFileSync(file, 'utf8') === contents) fs.unlinkSync(file);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
      };
    }
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(temp, { force: true });
  }
}

function readJournal(file: string): Journal | null {
  const value = readJson(file);
  if (value === null) return null;
  if (!object(value) ||
      !['switching', 'switched', 'committed'].includes(String(value.phase)) ||
      !(value.from === null || version(value.from)) ||
      !(version(value.to) || (value.phase === 'committed' && value.to === null)) ||
      typeof value.order_id !== 'string' || !ORDER_ID.test(value.order_id) ||
      typeof value.at !== 'string') {
    throw new Error('journal');
  }
  return value as unknown as Journal;
}

function ordersIn(file: string): string[] {
  const value = readJson(file);
  if (value === null) return [];
  if (!Array.isArray(value) || value.length > 200 ||
      !value.every(id => typeof id === 'string' && ORDER_ID.test(id))) {
    throw new Error('order history');
  }
  return value;
}

function rememberOrder(file: string, id: string): void {
  if (!ORDER_ID.test(id)) return;
  const orders = ordersIn(file);
  if (!orders.includes(id)) {
    orders.push(id);
    atomicJson(file, orders.slice(-200));
  }
}

function versionsIn(file: string): string[] {
  const value = readJson(file);
  if (value === null) return [];
  if (!Array.isArray(value) || !value.every(version)) throw new Error('version history');
  return value;
}

function appendHistory(stateDir: string, values: (string | null)[]): void {
  const file = path.join(stateDir, 'history.json');
  const history = versionsIn(file);
  for (const value of values) {
    if (value !== null && !history.includes(value)) history.push(value);
  }
  atomicJson(file, history);
}

function prune(d: UpdaterDeps, running: string | null): void {
  const stateDir = path.join(d.root, 'state');
  const history = versionsIn(path.join(stateDir, 'history.json'));
  const failed = versionsIn(path.join(stateDir, 'failed.json'));
  const previous = history.filter(v => v !== running &&
    (running === null || compareVersions(v, running) < 0)).reverse().slice(0, 2);
  const keep = new Set([running, ...previous, ...failed.slice(-1)]);
  const dir = path.join(d.root, 'versions');
  for (const name of fs.readdirSync(dir)) {
    if (!keep.has(name)) removeTree(path.join(dir, name));
  }
}

function b1Reason(error: unknown): string {
  // B1 errors are fixed-form messages, not remote response bodies or request text.
  if (error instanceof Error &&
      /^[A-Za-z0-9 .,:;_()/@+-]{1,200}$/.test(error.message)) return error.message;
  return 'invalid archive';
}

async function healthy(d: UpdaterDeps, expected: string): Promise<boolean> {
  const end = d.now() + 60_000;
  while (d.now() < end) {
    try {
      const reply = await d.ping();
      if (reply?.version === expected && reply.store_ok === true) return true;
    } catch {
      // A restarting broker can close the socket before replying.
    }
    const left = end - d.now();
    if (left > 0) await d.sleep(Math.min(2_000, left));
  }
  return false;
}

async function restartAndCheck(d: UpdaterDeps, expected: string): Promise<boolean> {
  try {
    await d.restartBroker();
  } catch {
    return false;
  }
  return healthy(d, expected);
}

function parseOrder(text: string): Order | null {
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return null;
  }
  if (!object(value) || Object.keys(value).length !== 2 ||
      !version(value.version) ||
      typeof value.order_id !== 'string' || !ORDER_ID.test(value.order_id)) return null;
  // JSON.parse alone accepts duplicate keys. Orders have only these two literal fields.
  const v = '"version"\\s*:\\s*"\\d+\\.\\d+\\.\\d+"';
  const id = '"order_id"\\s*:\\s*"[A-Za-z0-9_-]{1,64}"';
  if (!new RegExp(`^\\s*\\{\\s*(?:${v}\\s*,\\s*${id}|${id}\\s*,\\s*${v})\\s*\\}\\s*$`).test(text)) {
    return null;
  }
  return { version: value.version, order_id: value.order_id };
}

export async function runOnce(d: UpdaterDeps): Promise<'idle' | 'done' | 'busy'> {
  const stateDir = path.join(d.root, 'state');
  const versionsDir = path.join(d.root, 'versions');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(stateDir, 0o700);
  fs.mkdirSync(versionsDir, { recursive: true, mode: 0o755 });
  fs.chmodSync(versionsDir, 0o755);
  const unlock = acquireLock(path.join(stateDir, 'lock'), d.now());
  if (!unlock) return 'busy';

  const journalFile = path.join(stateDir, 'journal.json');
  const highestFile = path.join(stateDir, 'highest.json');
  const ordersFile = path.join(stateDir, 'orders.json');
  const statusFile = path.join(d.spool, 'status.json');
  let active = UNSPECIFIED;
  let temp: string | null = null;
  let staging: string | null = null;

  const status = (order: Order, state: State, detail: string): void => {
    const value: Status = {
      ...order, state, detail: detail.slice(0, 200), at: new Date(d.now()).toISOString(),
    };
    // Persist deduplication before making a terminal status visible.
    if (TERMINAL.has(state)) rememberOrder(ordersFile, order.order_id);
    atomicJson(statusFile, value, 0o644);
  };
  const journal = (phase: Journal['phase'], from: string | null, to: string | null, order: Order): void => {
    atomicJson(journalFile, {
      phase, from, to, order_id: order.order_id, at: new Date(d.now()).toISOString(),
    } satisfies Journal);
  };
  const finish = (order: Order, from: string | null): void => {
    const highest = readJson(highestFile);
    if (!object(highest) || !version(highest.version)) throw new Error('highest version');
    if (compareVersions(order.version, highest.version) > 0) {
      atomicJson(highestFile, { version: order.version });
    }
    appendHistory(stateDir, [from, order.version]);
    journal('committed', order.version, order.version, order);
    const failed = versionsIn(path.join(stateDir, 'failed.json')).filter(v => v !== order.version);
    atomicJson(path.join(stateDir, 'failed.json'), failed.slice(-1));
    prune(d, order.version);
    status(order, 'installed', '');
  };
  const rollback = async (order: Order, from: string | null): Promise<void> => {
    let ok = false;
    if (from !== null) {
      try {
        d.writeDescriptor(from);
        syncDirectory(d.root);
        ok = await restartAndCheck(d, from);
      } catch {
        ok = false;
      }
    }
    if (ok) appendHistory(stateDir, [from]);
    journal('committed', from, from, order);
    atomicJson(path.join(stateDir, 'failed.json'), [order.version]);
    prune(d, from);
    status(order, ok ? 'rolled back' : 'rollback failed', 'new version not healthy');
  };

  try {
    const journalNow = readJournal(journalFile);
    // Only an UNcommitted journal is work this run did; a committed one is history.
    const pending = journalNow && journalNow.phase !== 'committed' ? journalNow : null;
    if (pending) {
      if (pending.to === null) throw new Error('journal');
      const order = { version: pending.to, order_id: pending.order_id };
      active = order;
      let switched = pending.phase === 'switched';
      if (!switched) {
        const target = path.join(versionsDir, pending.to);
        switched = fs.existsSync(target) && !fs.lstatSync(target).isSymbolicLink() &&
          d.readDescriptor() === pending.to;
        if (switched) journal('switched', pending.from, pending.to, order);
      }
      if (switched) {
        if (await restartAndCheck(d, order.version)) finish(order, pending.from);
        else await rollback(order, pending.from);
      } else {
        if (pending.from !== null) {
          d.writeDescriptor(pending.from);
          syncDirectory(d.root);
        }
        journal('committed', pending.from, pending.from, order);
        removeTree(path.join(versionsDir, `${order.version}.staging`));
        status(order, 'failed', 'interrupted');
      }
    }

    active = UNSPECIFIED;
    const opened = d.openRequest(path.join(d.spool, 'request.json'));
    if ('refused' in opened) {
      if (opened.refused === 'missing') return pending ? 'done' : 'idle';
      status(UNSPECIFIED, 'refused', 'request file');
      return 'done';
    }
    let bytes: Buffer;
    try {
      const before = fs.fstatSync(opened.fd);
      const buffer = Buffer.alloc(4097);
      let used = 0;
      while (used < buffer.length) {
        const count = fs.readSync(opened.fd, buffer, used, buffer.length - used, used);
        if (count === 0) break;
        used += count;
      }
      const after = fs.fstatSync(opened.fd);
      if (used > 4096 || before.size !== used || after.size !== used ||
          before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
        status(UNSPECIFIED, 'refused', 'request file');
        return 'done';
      }
      bytes = buffer.subarray(0, used);
    } finally {
      fs.closeSync(opened.fd);
    }
    const malformedFile = path.join(stateDir, 'malformed.json');
    if (bytes.length === 0) {
      atomicJson(malformedFile, { count: 0 });
      return pending ? 'done' : 'idle';
    }
    const order = parseOrder(bytes.toString('utf8'));
    if (!order) {
      const previous = readJson(malformedFile);
      const count = object(previous) && typeof previous.count === 'number' ?
        Math.min(3, previous.count + 1) : 1;
      atomicJson(malformedFile, { count });
      if (count >= 3) {
        status(UNSPECIFIED, 'refused', 'request');
        return 'done';
      }
      return 'idle';
    }
    atomicJson(malformedFile, { count: 0 });
    active = order;
    if (ordersIn(ordersFile).includes(order.order_id)) return pending ? 'done' : 'idle';
    const previousStatus = readJson(statusFile);
    if (object(previousStatus) && previousStatus.order_id === order.order_id &&
        TERMINAL.has(previousStatus.state as State)) {
      rememberOrder(ordersFile, order.order_id);
      return pending ? 'done' : 'idle';
    }

    const running = d.readDescriptor();
    const highest = readJson(highestFile);
    if (!object(highest) || !version(highest.version)) throw new Error('highest version');
    if (compareVersions(order.version, highest.version) <= 0) {
      status(order, order.version === running ? 'installed' : 'refused',
        order.version === running ? '' : 'older version');
      return 'done';
    }
    if (d.freeBytes(d.root) < 600 * 1024 * 1024) {
      status(order, 'failed', 'disk space');
      return 'done';
    }
    status(order, 'working', '');
    const base = `${RELEASE_BASE}/v${order.version}/`;
    let recordBytes: Buffer;
    let sigBytes: Buffer;
    try {
      recordBytes = await d.fetchBytes(`${base}release.json`, 64 * 1024, 30_000);
      sigBytes = await d.fetchBytes(`${base}release.json.sigs`, 64 * 1024, 30_000);
      if (recordBytes.length > 64 * 1024 || sigBytes.length > 64 * 1024) {
        throw new Error('record size');
      }
    } catch {
      status(order, 'failed', 'release download');
      return 'done';
    }
    const signatures = verifySignatures(recordBytes, sigBytes, d.keys);
    if (!signatures.ok) {
      status(order, 'failed', signatures.reason);
      return 'done';
    }
    const parsed = parseRecord(recordBytes, order.version, d.limits);
    if (!parsed.ok) {
      status(order, 'failed', parsed.reason);
      return 'done';
    }
    const record = parsed.record;
    const node = record.node[d.platform];
    if (!node) {
      status(order, 'failed', 'platform');
      return 'done';
    }
    temp = path.join(d.root, `tmp-${order.order_id}`);
    removeTree(temp);
    fs.mkdirSync(temp, { mode: 0o700 });
    fs.chmodSync(temp, 0o700);
    const appArchive = path.join(temp, 'app.tar.gz');
    const nodeArchive = path.join(temp, d.platform.startsWith('win-') ? 'node.exe' : 'node.tar.gz');
    const deadline = d.now() + 10 * 60_000;
    try {
      await d.download(record.app.url, appArchive, d.limits.maxArchiveBytes, deadline);
      await d.download(node.url, nodeArchive, d.limits.maxArchiveBytes, deadline);
    } catch {
      status(order, 'failed', 'download');
      return 'done';
    }
    if (d.now() > deadline) {
      status(order, 'failed', 'download');
      return 'done';
    }
    if (await sha256File(appArchive) !== record.app.sha256 ||
        await sha256File(nodeArchive) !== node.sha256) {
      status(order, 'failed', 'hash mismatch');
      return 'done';
    }
    staging = path.join(versionsDir, `${order.version}.staging`);
    removeTree(staging);
    fs.mkdirSync(staging, { mode: 0o755 });
    fs.chmodSync(staging, 0o755);
    try {
      await extractApp(appArchive, staging, REQUIRED_APP_FILES, d.limits);
      await d.installNode(staging, record, temp);
    } catch (error) {
      status(order, 'failed', b1Reason(error));
      return 'done';
    }
    let tested = false;
    try {
      tested = await d.selfTest(staging);
    } catch {
      tested = false;
    }
    if (!tested) {
      status(order, 'failed', 'self-test');
      return 'done';
    }
    journal('switching', running, order.version, order);
    const destination = path.join(versionsDir, order.version);
    removeTree(destination);
    fs.renameSync(staging, destination);
    staging = null;
    syncDirectory(versionsDir);
    d.writeDescriptor(order.version);
    syncDirectory(d.root);
    journal('switched', running, order.version, order);
    if (await restartAndCheck(d, order.version)) finish(order, running);
    else await rollback(order, running);
    return 'done';
  } catch {
    // Filesystem and service errors must not turn arbitrary OS text into vault text.
    d.log('updater: operation failed');
    status(active, 'failed', 'operation failed');
    return 'done';
  } finally {
    try {
      if (staging !== null) removeTree(staging);
      if (temp !== null) removeTree(temp);
    } finally {
      unlock();
    }
  }
}

export function checkEnv(env: NodeJS.ProcessEnv): string | null {
  for (const name of Object.keys(env)) {
    if (env[name] !== undefined &&
        (['NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_REPL_EXTERNAL_MODULE'].includes(name) ||
         name.startsWith('WUNDERVAULT_'))) return `unsafe environment: ${name}`;
  }
  return null;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sampleTar(name: string, data: Buffer): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  const octal = (offset: number, width: number, value: number): void => {
    header.write(`${value.toString(8).padStart(width - 1, '0')}\0`, offset, width, 'ascii');
  };
  octal(100, 8, 0o644);
  octal(108, 8, 0);
  octal(116, 8, 0);
  octal(124, 12, data.length);
  octal(136, 12, 0);
  header.fill(32, 148, 156);
  header.write('0', 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return gzipSync(Buffer.concat([
    header, data, Buffer.alloc((512 - data.length % 512) % 512), Buffer.alloc(1024),
  ]), { mtime: 0 } as Parameters<typeof gzipSync>[1]);
}

export async function selfTestMain(): Promise<boolean> {
  let dir: string | undefined;
  try {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const data = Buffer.from('{}');
    const archive = sampleTar('app/package.json', data);
    const hash = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
    const nodeVersion = '22.23.4';
    const node: Record<string, unknown> = { version: nodeVersion };
    for (const platform of ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'win-x64', 'win-arm64']) {
      const windows = platform.startsWith('win-');
      node[platform] = {
        url: `https://nodejs.org/dist/v${nodeVersion}/${windows ?
          `${platform}/node.exe` : `node-v${nodeVersion}-${platform}.tar.gz`}`,
        sha256: hash(Buffer.from('node')),
        ...(windows ? {} : { member: `node-v${nodeVersion}-${platform}/bin/node` }),
      };
    }
    const bytes = Buffer.from(canonical({
      format: 'wundervault-release-1', version: '0.0.1',
      app: {
        url: `${RELEASE_BASE}/v0.0.1/wundervault-app-0.0.1.tar.gz`,
        sha256: hash(archive),
      },
      node,
      notes_url: `${RELEASE_BASE}/v0.0.1/release.json`,
    }));
    const keys: ReleaseKey[] = [{
      id: 'self-test',
      publicKey: Buffer.from(publicKey.export({ format: 'jwk' }).x as string, 'base64url').toString('base64'),
      test: true,
    }];
    const sigs = Buffer.from(JSON.stringify([{
      key_id: 'self-test', sig: sign(null, bytes, privateKey).toString('base64'),
    }]));
    if (!verifySignatures(bytes, sigs, keys).ok) return false;
    const parsed = parseRecord(bytes, '0.0.1');
    if (!parsed.ok) return false;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-updater-self-test-'));
    fs.chmodSync(dir, 0o700);
    const input = path.join(dir, 'sample.tar.gz');
    const output = path.join(dir, 'version');
    fs.writeFileSync(input, archive, { mode: 0o600 });
    fs.mkdirSync(output, { mode: 0o755 });
    await extractApp(input, output, ['package.json']);
    return await sha256File(path.join(output, 'app', 'package.json')) === hash(data);
  } catch {
    return false;
  } finally {
    if (dir !== undefined) removeTree(dir);
  }
}

export async function main(argv: string[], env: NodeJS.ProcessEnv): Promise<number> {
  process.umask(0o022);
  const problem = checkEnv(env);
  if (problem) {
    console.error(`updater: ${problem}`);
    return 2;
  }
  if (argv.includes('--self-test')) return await selfTestMain() ? 0 : 1;
  try {
    // Importing the flow in a test must never load the real service controls.
    const { defaultDeps } = await import('./updater-platform.js');
    await runOnce(defaultDeps());
    return 0;
  } catch {
    console.error('updater: initialization failed');
    return 2;
  }
}

// Am I the program that was started? Compared by REAL path: systemd, launchd and the Windows task
// start this file through /opt/wundervault/current (a link), and Node resolves that link for
// import.meta.url, so comparing the unresolved argv[1] said "no" and the scheduled updater exited
// having done nothing (found on a real systemd install, 2026-10-30).
function startedAsProgram(): boolean {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (startedAsProgram()) {
  void main(process.argv.slice(2), process.env).then(
    code => process.exit(code),
    () => process.exit(2),
  );
}
