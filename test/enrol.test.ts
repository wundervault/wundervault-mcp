/**
 * Enrolment, end to end, against a real HTTP server speaking the real protocol.
 *
 * The point of this file is that the daemon — not the calling process — redeems the setup
 * link. That is what replaced `register_profile`, which accepted a profile from whoever
 * asked and so handed every agent on the machine the ability to register a name with a
 * token it chose and then read that agent's credentials. A local permission could not fix
 * it, because agents run as the owner; only a credential the agent cannot obtain can, and
 * the setup link is issued by the server to someone logged in to the website.
 *
 * The blob format here is not invented for the test: it is built exactly as onboard.py
 * expects to find it — PBKDF2-SHA256 over the passphrase with the salt "wv-agent-setup-v1"
 * at 100,000 rounds, AES-256-GCM, nonce first and tag last, base64url. A test that made up
 * its own format would prove the code agrees with the test and nothing about the server.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { AgentDaemon } from '../src/agent.js';
import { parseSetupUrl } from '../src/enrol.js';

let dir: string;
let daemon: any;
let server: http.Server;
let baseUrl: string;
let burned: string[] = [];

const PASSPHRASE = 'correct horse battery staple';

function makeBlob(creds: object, passphrase = PASSPHRASE): string {
  const key = crypto.pbkdf2Sync(passphrase, 'wv-agent-setup-v1', 100_000, 32, 'sha256');
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([c.update(JSON.stringify(creds), 'utf8'), c.final()]);
  return Buffer.concat([nonce, body, c.getAuthTag()])
    .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Stands in for the website. Answers the two endpoints onboard.py uses, and no others. */
function startServer(tokens: Record<string, { name: string; blob: string; used?: boolean; gone?: boolean }>) {
  return new Promise<void>((resolve) => {
    server = http.createServer((req, res) => {
      const m = String(req.url).match(/^\/api\/setup\/agent\/([^/]+)(\/burn)?$/);
      if (!m) { res.writeHead(404).end('{}'); return; }
      const entry = tokens[m[1]];
      if (!entry) { res.writeHead(404).end(JSON.stringify({ detail: 'Invalid setup token' })); return; }
      if (m[2]) { entry.used = true; burned.push(m[1]); res.writeHead(200).end(JSON.stringify({ status: 'burned' })); return; }
      if (entry.used || entry.gone) { res.writeHead(410).end(JSON.stringify({ detail: 'used' })); return; }
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        agent_id: 'ag_' + entry.name, agent_name: entry.name, encrypted_blob: entry.blob,
      }));
    });
    server.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
      resolve();
    });
  });
}

async function freshDaemon() {
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'state');
  process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'home', '.wundervault');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  const d = new AgentDaemon();
  d.start();
  return d;
}

function speak(sockPath: string, payload: unknown, timeoutMs = 20_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockPath);
    let buf = '';
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutMs);
    const fin = (fn: () => void) => { clearTimeout(t); s.destroy(); fn(); };
    s.on('connect', () => s.write(JSON.stringify(payload) + '\n'));
    s.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      try { fin(() => resolve(JSON.parse(buf.trim()))); } catch { fin(() => resolve({ raw: buf })); }
    });
    s.on('error', (e) => fin(() => reject(e)));
  });
}

const mgmt = () => path.join(dir, 'run', 'mgmt', 'agent.sock');

beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-enrol-')); burned = []; });
afterEach(async () => {
  try { daemon?.shutdown(); } catch { /* down already */ }
  daemon = undefined;
  await new Promise<void>((r) => server ? server.close(() => r()) : r());
  fs.rmSync(dir, { recursive: true, force: true });
  for (const k of ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR']) {
    delete process.env[k];
  }
});

describe('the setup link is the authorisation', () => {
  it('enrols an agent the daemon fetched and decrypted itself', async () => {
    const blob = makeBlob({ api_key: 'wv_agent_A|secret', encryption_key: 'enc_A' });
    await startServer({ tok1: { name: 'Byte', blob } });
    daemon = await freshDaemon();

    const socketToken = crypto.randomBytes(32).toString('hex');
    const res = await speak(mgmt(), {
      action: 'enrol',
      setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
      socket_token: socketToken,
    });

    expect(res.ok).toBe(true);
    expect(res.agent_name).toBe('Byte');
    expect(burned).toEqual(['tok1']);

    // And the agent can now collect them with its token — the daemon really filed them.
    const got = await speak(path.join(dir, 'run', 'Byte.sock'), { token: socketToken });
    expect(got.api_key).toBe('wv_agent_A|secret');
    expect(got.enc_key).toBe('enc_A');
  });

  it('refuses without a setup link — there is no other way in', async () => {
    await startServer({});
    daemon = await freshDaemon();
    // The action that used to accept a profile outright is gone, not merely guarded.
    const res = await speak(mgmt(), {
      action: 'register_profile',
      profile: { agent_name: 'X', api_key: 'k', enc_key: 'e', vault_url: 'u', socket_token: 'aa'.repeat(32) },
    });
    expect(res.ok).toBeUndefined();
    expect(res.error).toBe('unknown action');
    expect(fs.existsSync(path.join(dir, 'run', 'X.sock'))).toBe(false);
  });

  it('refuses a used link, and says how to get another', async () => {
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: 'Byte', blob, used: true } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
      socket_token: crypto.randomBytes(32).toString('hex'),
    });
    expect(res.error).toMatch(/already been used|expired/i);
    expect(res.error).toMatch(/[Rr]epair/);
  });

  it('does not burn the link when the passphrase is wrong', async () => {
    // Burning first would consume a single-use link on a typo and send the owner back to
    // the dashboard for a new one.
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: 'Byte', blob } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#wrong-passphrase`,
      socket_token: crypto.randomBytes(32).toString('hex'),
    });
    expect(res.error).toMatch(/decrypt/i);
    expect(burned).toEqual([]);
  });

  it('refuses a traversing agent name, even from the server', async () => {
    // The name becomes a path segment and now arrives from the SERVER rather than the
    // caller. That is a better source, not a trusted one: a compromised or confused
    // server must not be able to make the daemon write a file wherever it likes.
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: '../../etc/cron.d/x', blob } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
      socket_token: crypto.randomBytes(32).toString('hex'),
    });
    expect(res.ok).toBeUndefined();
    expect(res.error).toMatch(/Invalid agent name/);
  });

  it('refuses an enrolment with no socket token', async () => {
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: 'Byte', blob } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
    });
    expect(res.error).toMatch(/socket_token/);
  });
});

describe('parsing a setup link', () => {
  it('takes the token from the path and the passphrase from the fragment', () => {
    const p = parseSetupUrl('https://wundervault.com/setup/agent/abc123#hunter2');
    expect(p).toEqual({ baseUrl: 'https://wundervault.com', token: 'abc123', passphrase: 'hunter2' });
  });

  it('refuses a link with no fragment, and explains why it matters', () => {
    // A link without the fragment looks complete and cannot possibly work: the passphrase
    // is the only thing that decrypts the blob and the server never had it.
    expect(() => parseSetupUrl('https://wundervault.com/setup/agent/abc123'))
      .toThrow(/after the #/);
  });

  it('refuses plaintext http', () => {
    // The blob is encrypted, but the token is a bearer credential.
    expect(() => parseSetupUrl('http://wundervault.com/setup/agent/abc#p')).toThrow(/https/);
  });

  it('refuses something that is not a setup link at all', () => {
    expect(() => parseSetupUrl('https://wundervault.com/dashboard#p')).toThrow(/no setup token/);
    expect(() => parseSetupUrl('not a url')).toThrow(/does not look like/);
  });
});
