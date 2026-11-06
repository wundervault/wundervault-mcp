// The root updater's health check on Windows: the broker listens on a loopback port named in
// mgmt.port and proves itself with a signed hello. Before 2026-11-05 the updater dialled a socket
// path that never exists on Windows, so every update (and its rollback) was judged unhealthy.
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const saved: Record<string, string | undefined> = {};
const keys = ['ProgramData', 'ProgramFiles', 'SystemRoot', 'WUNDERVAULT_PLATFORM_SHAPE'];
let dir = '';
let realChdir: typeof process.chdir = process.chdir;
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;

function identity(): { priv: string; pubB64: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    pubB64: (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64'),
  };
}

async function broker(signWith: string, publish: string): Promise<net.Server> {
  const endpoint = await import('../src/endpoint.js');
  const run = path.join(dir, 'data', 'wundervault', 'run');
  fs.mkdirSync(path.join(run, 'mgmt'), { recursive: true });
  fs.writeFileSync(path.join(run, 'broker.pub'), publish);
  const signer = endpoint.helloSignerFrom(signWith);
  const srv: net.Server = net.createServer(endpoint.withHello((socket) => {
    socket.on('data', () => {
      socket.write(JSON.stringify({ broker_version: '9.0.1', store_ok: true }) + '\n');
    });
  }, signer, () => (srv.address() as net.AddressInfo).port));
  await new Promise<void>((res, rej) => endpoint.listenOn(srv,
    { kind: 'port', file: path.join(run, 'mgmt', 'mgmt.port') }, signer, () => res(), (m) => rej(new Error(m))));
  return srv;
}

describe('updater ping on Windows', () => {
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-upd-win-'));
    for (const k of keys) saved[k] = process.env[k];
    process.env.ProgramData = path.join(dir, 'data');
    process.env.ProgramFiles = path.join(dir, 'pf');
    process.env.SystemRoot = 'C:\\Windows';
    process.env.WUNDERVAULT_PLATFORM_SHAPE = 'windows';
    fs.mkdirSync(path.join(dir, 'pf', 'Wundervault', 'bin'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'data', 'wundervault-update'), { recursive: true });
    realChdir = process.chdir;
    // defaultDeps() chdirs to the install root; vitest workers can't, and ping doesn't need it.
    process.chdir = (() => {}) as typeof process.chdir;
    Object.defineProperty(process, 'platform', { value: 'win32' });
  });
  afterEach(() => {
    Object.defineProperty(process, 'platform', platform);
    process.chdir = realChdir;
    for (const k of keys) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('reaches the broker through mgmt.port and its signed hello', async () => {
    const id = identity();
    const srv = await broker(id.priv, id.pubB64);
    const { defaultDeps } = await import('../src/updater-platform.js');
    const reply = await defaultDeps().ping();
    expect(reply).toEqual({ version: '9.0.1', store_ok: true });
    await new Promise<void>((r) => srv.close(() => r()));
  });

  it('treats a listener that cannot prove it is the broker as no answer', async () => {
    const real = identity();
    const stranger = identity();
    const srv = await broker(stranger.priv, real.pubB64);
    const { defaultDeps } = await import('../src/updater-platform.js');
    expect(await defaultDeps().ping()).toBeNull();
    await new Promise<void>((r) => srv.close(() => r()));
  });

  it('answers null, not an error, when no broker is listening', async () => {
    const { defaultDeps } = await import('../src/updater-platform.js');
    expect(await defaultDeps().ping()).toBeNull();
  });
});
