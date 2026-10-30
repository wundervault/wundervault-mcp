import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'vitest';
import { gzipSync } from 'node:zlib';
import { acquireLock, runOnce, writeStatus, type UpdaterDeps } from '../src/updater.js';
import { windowsNode, writeWindowsDescriptor } from '../src/updater-platform.js';
import { DEFAULT_LIMITS, safeAppPath } from '../src/release-verify.js';
import { extractApp } from '../src/tar-read.js';

function temporary(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'wv-updater-r2-'));
}

function deps(root: string, spool: string): UpdaterDeps {
  return {
    root,
    spool,
    platform: 'linux-x64',
    keys: [],
    limits: DEFAULT_LIMITS,
    expectRequestOwner: null,
    openRequest(file) {
      try {
        return { fd: fs.openSync(file, 'r') };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { refused: 'missing' };
        throw error;
      }
    },
    async fetchBytes() {
      assert.fail('unexpected release fetch');
    },
    async download() {
      assert.fail('unexpected download');
    },
    freeBytes: () => 1024 * 1024 * 1024,
    readDescriptor: () => '1.0.0',
    writeDescriptor() {
      assert.fail('unexpected descriptor switch');
    },
    async installNode() {
      assert.fail('unexpected node install');
    },
    async restartBroker() {
      assert.fail('unexpected broker restart');
    },
    async ping() {
      assert.fail('unexpected health check');
    },
    async selfTest() {
      assert.fail('unexpected self-test');
    },
    now: () => Date.now(),
    async sleep() {
      assert.fail('unexpected sleep');
    },
    log() {},
  };
}

function tar(entries: readonly { name: string; directory?: boolean; data?: string }[]): Buffer {
  const blocks: Buffer[] = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? '');
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, 'ascii');
    const octal = (offset: number, width: number, value: number): void => {
      header.write(`${value.toString(8).padStart(width - 1, '0')}\0`, offset, width, 'ascii');
    };
    octal(100, 8, entry.directory ? 0o755 : 0o644);
    octal(108, 8, 0);
    octal(116, 8, 0);
    octal(124, 12, data.length);
    octal(136, 12, 0);
    header.fill(32, 148, 156);
    header.write(entry.directory ? '5' : '0', 156, 1, 'ascii');
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    const sum = header.reduce((total, byte) => total + byte, 0);
    header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    blocks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

test('two inspectors racing to break one stale lock leave exactly one holder', () => {
  const dir = temporary();
  let winner: (() => void) | null = null;
  try {
    const file = path.join(dir, 'lock');
    const now = Date.now();
    fs.writeFileSync(file, `${process.pid} ${now - 21 * 60_000}`);
    let inspections = 0;

    const loser = acquireLock(file, now, () => {
      inspections++;
      // The first inspector pauses before taking lock.break. The second inspector
      // breaks the same stale lock and publishes its own live lock during that pause.
      winner = acquireLock(file, now + 1);
      assert.ok(winner);
    });

    assert.equal(inspections, 1);
    assert.equal(loser, null);
    assert.ok(winner);
    assert.equal(fs.readFileSync(file, 'utf8'), `${process.pid} ${now + 1}`);
    assert.equal(acquireLock(file, now + 2), null);
    assert.equal(fs.existsSync(`${file}.break`), false);
    winner();
    winner = null;
    assert.equal(fs.existsSync(file), false);
  } finally {
    winner?.();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a fresh break lock is busy; an abandoned break lock is removed once', () => {
  const dir = temporary();
  let unlock: (() => void) | null = null;
  try {
    const file = path.join(dir, 'lock');
    const now = Date.now();
    const old = `${process.pid} ${now - 21 * 60_000}`;
    fs.writeFileSync(file, old);
    fs.writeFileSync(`${file}.break`, `${process.pid} ${now}`);
    assert.equal(acquireLock(file, now), null);
    assert.equal(fs.readFileSync(file, 'utf8'), old);

    const abandoned = new Date(now - 61_000);
    fs.utimesSync(`${file}.break`, abandoned, abandoned);
    unlock = acquireLock(file, now);
    assert.ok(unlock);
    assert.equal(fs.readFileSync(file, 'utf8'), `${process.pid} ${now}`);
    assert.equal(fs.existsSync(`${file}.break`), false);
  } finally {
    unlock?.();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('an unparseable lock is held until its mtime is older than twenty minutes', () => {
  const dir = temporary();
  let unlock: (() => void) | null = null;
  try {
    const file = path.join(dir, 'lock');
    const now = Date.now();
    fs.writeFileSync(file, 'interrupted');
    assert.equal(acquireLock(file, now), null);
    const old = new Date(now - 21 * 60_000);
    fs.utimesSync(file, old, old);
    unlock = acquireLock(file, now);
    assert.ok(unlock);
  } finally {
    unlock?.();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('an old holder cannot release a successor lock with identical content', () => {
  const dir = temporary();
  let unlock: (() => void) | null = null;
  try {
    const file = path.join(dir, 'lock');
    const now = Date.now();
    unlock = acquireLock(file, now);
    assert.ok(unlock);
    // Keep the first inode allocated so the replacement cannot reuse it.
    fs.linkSync(file, path.join(dir, 'old'));
    fs.unlinkSync(file);
    fs.writeFileSync(file, `${process.pid} ${now}`);
    unlock();
    unlock = null;
    assert.equal(fs.existsSync(file), true);
  } finally {
    unlock?.();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a crash after status publication but before remembering never refetches the order', async () => {
  const dir = temporary();
  try {
    const root = path.join(dir, 'root');
    const spool = path.join(dir, 'spool');
    const state = path.join(root, 'state');
    fs.mkdirSync(state, { recursive: true });
    fs.mkdirSync(spool);
    const orders = path.join(state, 'orders.json');
    const status = path.join(spool, 'status.json');
    const order = { version: '2.0.0', order_id: 'crash-window' };
    fs.writeFileSync(path.join(spool, 'request.json'), JSON.stringify(order));

    // Force remembering to stop after the real writer has durably published status.
    fs.writeFileSync(orders, 'interrupted history');
    assert.throws(() => writeStatus(status, orders, {
      ...order, state: 'failed', detail: 'download', at: new Date().toISOString(),
    }));
    assert.equal(JSON.parse(fs.readFileSync(status, 'utf8')).state, 'failed');
    fs.unlinkSync(orders);

    const d = deps(root, spool);
    let fetched = 0;
    d.fetchBytes = async () => {
      fetched++;
      throw new Error('must not fetch');
    };
    assert.equal(await runOnce(d), 'idle');
    assert.equal(fetched, 0);
    assert.deepEqual(JSON.parse(fs.readFileSync(orders, 'utf8')), [order.order_id]);
    assert.equal(JSON.parse(fs.readFileSync(status, 'utf8')).detail, 'download');
    assert.equal(await runOnce(d), 'idle');
    assert.equal(fetched, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('terminal order history retains the latest 2000 ids', () => {
  const dir = temporary();
  try {
    const orders = path.join(dir, 'orders.json');
    const status = path.join(dir, 'status.json');
    const ids = Array.from({ length: 2000 }, (_, i) => `order-${i}`);
    fs.writeFileSync(orders, JSON.stringify(ids));
    writeStatus(status, orders, {
      version: '2.0.0', order_id: 'new-order', state: 'failed',
      detail: 'download', at: new Date().toISOString(),
    });
    const stored = JSON.parse(fs.readFileSync(orders, 'utf8')) as string[];
    assert.equal(stored.length, 2000);
    assert.equal(stored[0], 'order-1');
    assert.equal(stored[1999], 'new-order');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Windows rollback resolves the old version node.path, not the current bundled node', () => {
  const root = temporary();
  try {
    const oldDir = path.join(root, 'versions', '1.0.0');
    const newDir = path.join(root, 'versions', '2.0.0');
    fs.mkdirSync(oldDir, { recursive: true });
    fs.mkdirSync(newDir);
    fs.mkdirSync(path.join(root, 'bin'));
    const systemNode = 'C:\\Program Files\\nodejs\\node.exe';
    const mockSystemNode = path.join(root, 'system-node.exe');
    fs.writeFileSync(mockSystemNode, 'validated system node');
    fs.writeFileSync(path.join(oldDir, 'node.path'), systemNode, 'ascii');
    fs.writeFileSync(path.join(newDir, 'node.exe'), 'bundled node');
    const stat = (file: string): fs.Stats =>
      fs.lstatSync(file === systemNode ? mockSystemNode : file);

    writeWindowsDescriptor(root, '2.0.0', stat);
    assert.equal(fs.readFileSync(path.join(root, 'bin', 'active.cmd'), 'utf8'),
      `set "WV_NODE=${path.join(newDir, 'node.exe')}"\r\nset "WV_APP=${path.join(newDir, 'app')}"\r\n`);

    writeWindowsDescriptor(root, '1.0.0', stat);
    assert.equal(fs.readFileSync(path.join(root, 'bin', 'active.cmd'), 'utf8'),
      `set "WV_NODE=${systemNode}"\r\nset "WV_APP=${path.join(oldDir, 'app')}"\r\n`);

    fs.unlinkSync(path.join(oldDir, 'node.path'));
    assert.throws(() => writeWindowsDescriptor(root, '1.0.0', stat), /no node for version/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('Windows node.path rejects invalid, oversized, missing and reparse targets', () => {
  const dir = temporary();
  try {
    const file = path.join(dir, 'node.path');
    const target = 'C:\\Node\\NODE.EXE';
    const backing = path.join(dir, 'validated-node.exe');
    fs.writeFileSync(backing, 'node');
    const stat = (name: string): fs.Stats => fs.lstatSync(name === target ? backing : name);

    fs.writeFileSync(file, target, 'ascii');
    assert.equal(windowsNode(dir, stat), target);

    for (const invalid of [
      `${target}\n`, `${target}\r\n`, 'node.exe', '\\Node\\node.exe',
      'C:\\Node\\other.exe', 'C:\\Node\\node.exe ', 'C:\\Nöde\\node.exe',
      'C:\\Node\\%PATH%\\node.exe', 'x'.repeat(1025),
    ]) {
      fs.writeFileSync(file, invalid);
      assert.throws(() => windowsNode(dir, stat), /no node for version/);
    }

    fs.writeFileSync(file, target, 'ascii');
    fs.unlinkSync(backing);
    assert.throws(() => windowsNode(dir, stat), /no node for version/);

    fs.writeFileSync(backing, 'node');
    const reparseStat = (name: string): fs.Stats => {
      const info = stat(name);
      if (name !== target) return info;
      return Object.assign(Object.create(Object.getPrototypeOf(info)), info, {
        isSymbolicLink: () => true,
      }) as fs.Stats;
    };
    assert.throws(() => windowsNode(dir, reparseStat), /no node for version/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('app directory claims reject case aliases, including implicit parents', async () => {
  const dir = temporary();
  try {
    const cases = [
      [
        { name: 'app/Foo/', directory: true },
        { name: 'app/foo/', directory: true },
      ],
      [
        { name: 'app/Foo/a.js', data: 'a' },
        { name: 'app/foo/', directory: true },
      ],
      [
        { name: 'app/Foo/child/', directory: true },
        { name: 'app/foo/other/', directory: true },
      ],
    ];
    for (let i = 0; i < cases.length; i++) {
      const archive = path.join(dir, `${i}.tar.gz`);
      const staging = path.join(dir, `staging-${i}`);
      fs.writeFileSync(archive, tar(cases[i]!));
      fs.mkdirSync(staging);
      await assert.rejects(extractApp(archive, staging, []), /duplicate entry/);
    }

    const archive = path.join(dir, 'same.tar.gz');
    const staging = path.join(dir, 'same');
    fs.writeFileSync(archive, tar([
      { name: 'app/Foo/a.js', data: 'a' },
      { name: 'app/Foo/', directory: true },
      { name: 'app/Foo/b.js', data: 'b' },
    ]));
    fs.mkdirSync(staging);
    await extractApp(archive, staging, ['Foo/a.js', 'Foo/b.js']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('safeAppPath rejects Windows reserved names and trailing dots or spaces in every segment', () => {
  const reserved = ['CON', 'PRN', 'AUX', 'NUL'];
  for (let i = 1; i <= 9; i++) reserved.push(`COM${i}`, `LPT${i}`);
  for (const name of reserved) {
    for (const spelling of [name, name.toLowerCase(), `${name}.js`, `${name.toLowerCase()}.a.b`]) {
      assert.equal(safeAppPath(spelling), false, spelling);
      assert.equal(safeAppPath(`node_modules/${spelling}/index.js`), false, spelling);
    }
  }
  for (const name of ['foo.', 'foo ', 'foo./bar.js', 'foo /bar.js', 'a/b./c', '.', '..']) {
    assert.equal(safeAppPath(name), false, name);
  }
  for (const name of ['console.js', 'CONSOLE', 'COM0', 'COM10.js', 'LPT0', 'LPT10.js',
    'bin/_handover.js', 'node_modules/@noble/hashes/_blake.js']) {
    assert.equal(safeAppPath(name), true, name);
  }
});

test('app extraction applies reserved-name rules before writing the entry', async () => {
  const dir = temporary();
  try {
    const archive = path.join(dir, 'reserved.tar.gz');
    const staging = path.join(dir, 'staging');
    fs.mkdirSync(staging);
    fs.writeFileSync(archive, tar([{ name: 'app/NUL.js', data: 'bad' }]));
    await assert.rejects(extractApp(archive, staging, []), /invalid app path/);
    assert.deepEqual(fs.readdirSync(staging), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('startup removes leftover private temp and staging directories before journal resume', async () => {
  const dir = temporary();
  try {
    const root = path.join(dir, 'root');
    const spool = path.join(dir, 'spool');
    const versions = path.join(root, 'versions');
    const state = path.join(root, 'state');
    fs.mkdirSync(versions, { recursive: true });
    fs.mkdirSync(state);
    fs.mkdirSync(spool);
    const temp = path.join(root, 'tmp-x');
    const staging = path.join(versions, '9.9.9.staging');
    fs.mkdirSync(temp, { mode: 0o700 });
    fs.chmodSync(temp, 0o700);
    fs.mkdirSync(staging);
    fs.writeFileSync(path.join(temp, 'partial'), 'partial');
    fs.writeFileSync(path.join(staging, 'partial'), 'partial');
    fs.mkdirSync(path.join(versions, '1.0.0'));
    fs.mkdirSync(path.join(versions, '2.0.0'));
    fs.writeFileSync(path.join(state, 'highest.json'), JSON.stringify({ version: '1.0.0' }));
    fs.writeFileSync(path.join(state, 'journal.json'), JSON.stringify({
      phase: 'switched', from: '1.0.0', to: '2.0.0',
      order_id: 'resume', at: new Date().toISOString(),
    }));

    const d = deps(root, spool);
    let restarted = false;
    d.readDescriptor = () => '2.0.0';
    d.restartBroker = async () => {
      assert.equal(fs.existsSync(temp), false);
      assert.equal(fs.existsSync(staging), false);
      restarted = true;
    };
    d.ping = async () => ({ version: '2.0.0', store_ok: true });
    assert.equal(await runOnce(d), 'done');
    assert.equal(restarted, true);
    assert.equal(JSON.parse(fs.readFileSync(path.join(spool, 'status.json'), 'utf8')).state, 'installed');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('startup cleanup does not descend through temp or staging links', {
  skip: process.platform === 'win32',
}, async () => {
  const dir = temporary();
  try {
    const root = path.join(dir, 'root');
    const spool = path.join(dir, 'spool');
    const versions = path.join(root, 'versions');
    const outside = path.join(dir, 'outside');
    fs.mkdirSync(versions, { recursive: true });
    fs.mkdirSync(spool);
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'sentinel'), 'keep');
    fs.symlinkSync(outside, path.join(root, 'tmp-link'));
    fs.symlinkSync(outside, path.join(versions, '9.9.9.staging'));
    assert.equal(await runOnce(deps(root, spool)), 'idle');
    assert.equal(fs.readFileSync(path.join(outside, 'sentinel'), 'utf8'), 'keep');
    assert.equal(fs.lstatSync(path.join(root, 'tmp-link')).isSymbolicLink(), true);
    assert.equal(fs.lstatSync(path.join(versions, '9.9.9.staging')).isSymbolicLink(), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
