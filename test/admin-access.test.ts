import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { BrokerOps } from '../src/broker-ops.js';
import { ADMIN_ACCESS_REQUIRED, adminAccessRequiredMessage } from '../src/api-client.js';
import { watchAdminSession, adminTimeoutMs, ADMIN_ENDED } from '../src/server.js';

/**
 * Admin access (site SPEC-admin-access-2026-11-10), helper half: a signing session for an
 * admin key never outlives the owner's approval (D7, checks 4-5), and "done" with the
 * setting "end" closes this agent's sessions (D6, check 6).
 */

const VAULT_KEY = Buffer.alloc(32, 9);
const ENC_KEY_B64 = Buffer.alloc(32, 7).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const HOST = 'host.example';

let base: string;
const saved: Record<string, string | undefined> = {};
const savedPoll = BrokerOps.ADMIN_POLL_MS;

function setEnv(k: string, v: string) {
  if (!(k in saved)) saved[k] = process.env[k];
  process.env[k] = v;
}

function gcm(plaintext: Buffer): { ct: string; nonce: string } {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, nonce);
  const body = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { ct: body.toString('base64'), nonce: nonce.toString('base64') };
}

type Api = {
  status: () => Promise<{ admin: boolean; open: boolean; until: string | null }>;
  secret: Record<string, unknown> | (() => never);
  done: { ended: number; setting: 'end' | 'keep' };
};

function broker(api: Partial<Api> & { secret: Api['secret'] }): BrokerOps {
  const keyFile = path.join(base, `k${crypto.randomBytes(3).toString('hex')}`);
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', keyFile]);
  const enc = gcm(fs.readFileSync(keyFile));
  const ops = new BrokerOps('Tester', 'k', ENC_KEY_B64, 'http://127.0.0.1:1', null);
  (ops as unknown as { api: unknown }).api = {
    getSecret: async () => {
      if (typeof api.secret === 'function') return api.secret();
      return {
        name: 'Oracle admin', entry_mode: 'BROKER_SSH_AGENT', access_tier: '2',
        encrypted_content: enc.ct, content_nonce: enc.nonce,
        exec_config: JSON.stringify({ delivery: 'ssh', ssh_hosts: [HOST] }),
        ...api.secret,
      };
    },
    adminAccessStatus: api.status ?? (async () => ({ admin: true, open: true, until: null })),
    agentDone: async () => api.done ?? { ended: 1, setting: 'end' },
    ensureVaultKey: async () => VAULT_KEY,
  };
  return ops;
}

function open(ops: BrokerOps, ttlSeconds = 300) {
  return ops.sshAgentOpen({
    entryId: 'ssh1', purpose: 'test', ttlSeconds,
    op: { kind: 'ssh', destination: `opc@${HOST}`, remoteArgv: ['true'] },
  });
}

const inMs = (ms: number) => new Date(Date.now() + ms).toISOString();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const connectable = (p: string) => new Promise<boolean>((resolve) => {
  const s = net.connect(p);
  s.once('connect', () => { s.destroy(); resolve(true); });
  s.once('error', () => resolve(false));
});

beforeEach(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-admin-'));
  const run = path.join(base, 'run');
  fs.mkdirSync(run, { recursive: true });
  fs.chmodSync(run, 0o755);
  setEnv('WUNDERVAULT_RUNTIME_DIR', run);
  setEnv('WUNDERVAULT_SYSTEM_ROOT', path.join(base, 'state'));
  setEnv('WUNDERVAULT_USER_ROOT', path.join(base, 'home', '.wundervault'));
});

afterEach(() => {
  BrokerOps.ADMIN_POLL_MS = savedPoll;
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  fs.rmSync(base, { recursive: true, force: true });
});

describe('admin SSH sessions end with admin access', () => {
  it('closes at admin_until, not at its own ttl (measured)', async () => {
    const ops = broker({ secret: { admin_access: true, admin_until: inMs(800) } });
    const r = await open(ops, 300);
    if ('error' in r) throw new Error(JSON.stringify(r));
    expect(Date.parse(r.admin_until!)).toBeGreaterThan(Date.now());
    expect(await connectable(r.socket_path)).toBe(true);
    const t0 = Date.now();
    while (ops.sshSessionOpen(r.session_id).open && Date.now() - t0 < 3000) await sleep(20);
    const took = Date.now() - t0;
    expect(ops.sshSessionOpen(r.session_id)).toEqual({ open: false, ended_by: 'admin_access_ended' });
    expect(took).toBeLessThan(1200);
    // No signature after expiry: the socket is gone.
    expect(await connectable(r.socket_path)).toBe(false);
  });

  it('closes within one poll when the owner ends it', async () => {
    BrokerOps.ADMIN_POLL_MS = 50;
    let on = true;
    const ops = broker({
      secret: { admin_access: true, admin_until: inMs(60_000) },
      status: async () => ({ admin: true, open: on, until: on ? inMs(60_000) : null }),
    });
    const r = await open(ops);
    if ('error' in r) throw new Error(JSON.stringify(r));
    await sleep(150);
    expect(ops.sshSessionOpen(r.session_id).open).toBe(true);
    on = false;
    await sleep(200);
    expect(ops.sshSessionOpen(r.session_id)).toEqual({ open: false, ended_by: 'admin_access_ended' });
  });

  it('fails closed after two unanswered polls, not one', async () => {
    BrokerOps.ADMIN_POLL_MS = 60;
    let fails = 0;
    const ops = broker({
      secret: { admin_access: true, admin_until: inMs(60_000) },
      status: async () => { fails++; throw new Error('offline'); },
    });
    const r = await open(ops);
    if ('error' in r) throw new Error(JSON.stringify(r));
    while (fails < 1) await sleep(10);
    expect(ops.sshSessionOpen(r.session_id).open).toBe(true);
    await sleep(200);
    expect(ops.sshSessionOpen(r.session_id)).toEqual({ open: false, ended_by: 'admin_access_unconfirmed' });
  });

  it('refuses an admin key with no end time, or one already past', async () => {
    for (const until of [undefined, null, 'soon', inMs(-1000)]) {
      const ops = broker({ secret: { admin_access: true, admin_until: until } });
      const r = await open(ops);
      expect('error' in r && r.code).toBe(ADMIN_ACCESS_REQUIRED);
    }
  });

  it('passes the server refusal on in plain words', async () => {
    const msg = adminAccessRequiredMessage('"Oracle admin"', 'req1');
    const ops = broker({ secret: () => { throw Object.assign(new Error(msg), { code: ADMIN_ACCESS_REQUIRED }); } });
    const r = await open(ops);
    expect('error' in r).toBe(true);
    if (!('error' in r)) return;
    expect(r.code).toBe(ADMIN_ACCESS_REQUIRED);
    expect(String(r.error)).toContain('needs admin access');
    expect(String(r.error).toLowerCase()).not.toContain('window');
  });

  it('leaves a plain key on its own ttl', async () => {
    const ops = broker({ secret: {} });
    const r = await open(ops, 300);
    if ('error' in r) throw new Error(JSON.stringify(r));
    expect(r.admin_until).toBeUndefined();
    await sleep(100);
    expect(ops.sshSessionOpen(r.session_id).open).toBe(true);
    ops.reset();
  });
});

describe('vault_done', () => {
  it('"end" closes this agent\'s sessions', async () => {
    const ops = broker({ secret: { admin_access: true, admin_until: inMs(60_000) }, done: { ended: 1, setting: 'end' } });
    const a = await open(ops);
    const b = await open(ops);
    if ('error' in a || 'error' in b) throw new Error('open failed');
    const d = await ops.done();
    expect(d).toEqual({ ended: 1, setting: 'end', ssh_closed: 2 });
    expect(ops.sshSessionOpen(a.session_id)).toEqual({ open: false, ended_by: 'done' });
    expect(await connectable(b.socket_path)).toBe(false);
  });

  it('"keep" leaves them running', async () => {
    const ops = broker({ secret: { admin_access: true, admin_until: inMs(60_000) }, done: { ended: 0, setting: 'keep' } });
    const a = await open(ops);
    if ('error' in a) throw new Error('open failed');
    expect(await ops.done()).toEqual({ ended: 0, setting: 'keep' });
    expect(ops.sshSessionOpen(a.session_id).open).toBe(true);
    ops.reset();
  });
});

describe('the agent process stops an admin command when access ends', () => {
  it('aborts when the helper says the session is closed', async () => {
    let open = true;
    const w = watchAdminSession({ send: async () => ({ open }) }, { admin_until: inMs(60_000) }, 's', 20);
    await sleep(60);
    expect(w.signal!.aborted).toBe(false);
    open = false;
    await sleep(60);
    expect(w.signal!.aborted).toBe(true);
    expect(w.signal!.reason).toBe(ADMIN_ENDED);
    w.stop();
  });

  it('aborts at admin_until even if the helper cannot be reached', async () => {
    const w = watchAdminSession({ send: async () => { throw new Error('gone'); } }, { admin_until: inMs(100) }, 's', 20);
    await sleep(160);
    expect(w.signal!.aborted).toBe(true);
    w.stop();
  });

  it('does nothing for a plain session, and caps the timeout only for admin', () => {
    expect(watchAdminSession({ send: async () => ({}) }, {}, 's').signal).toBeUndefined();
    expect(adminTimeoutMs({}, 120_000)).toBe(120_000);
    const t = adminTimeoutMs({ admin_until: inMs(5_000) }, 120_000);
    expect(t).toBeGreaterThan(4_000);
    expect(t).toBeLessThanOrEqual(5_000);
  });
});
