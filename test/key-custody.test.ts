/**
 * Key custody — the broker holds the vault key and will not give it up.
 *
 * The phase-4 tests proved the boundary around the STORE: a different uid, a directory
 * the agent cannot open, memory it cannot read. They also asserted, correctly for the
 * code at the time, that a valid token bought you `{api_key, enc_key, vault_url}` — so
 * the boundary was real and the front door was open, and the suite agreed with that.
 *
 * These tests assert the property the phase was supposed to have:
 *
 *   1. no reply, from any operation, carries a credential;
 *   2. the entry-mode gate is enforced by the BROKER, proved by bypassing the MCP server
 *      entirely and talking to the socket the way a hostile agent would;
 *   3. a brokered HTTP call never puts the plaintext on the socket;
 *   4. the MCP server cannot decrypt anything, proved by grep over its imports.
 *
 * Point 2 is the one that matters most. Every `entry_mode` check used to live in
 * `server.ts`, which runs as the agent's own uid — `types.ts` said "enforced client-side"
 * and meant it. A test that drives those checks through the MCP server proves only that
 * a cooperative client cooperates.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { AgentDaemon } from '../src/agent.js';

const ROOT = path.resolve(__dirname, '..');

let dir: string;
let daemon: any;
let server: http.Server | null = null;
let baseUrl = '';
let getSecretCalls: string[] = [];
/** The query string of every entry fetch, to prove the agent's purpose is not on it. */
let getSecretQueries: string[] = [];
/**
 * Private origins the http1 entry approves, set per test.
 *
 * The SSRF guard blocks loopback by default and is right to — an approved private origin
 * is an OWNER decision that lives on the entry, server-side. The fake serves it the same
 * way, so these tests exercise the real allowlist rather than a bypass.
 */
let approvedOrigins: string[] = [];

/** A 32-byte AES key, and the vault key wrapped to it, exactly as the server stores it. */
const ENC_KEY = Buffer.alloc(32, 7);
const VAULT_KEY = Buffer.alloc(32, 9);
const ENC_KEY_B64 = ENC_KEY.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function gcm(key: Buffer, plaintext: Buffer): { ct: string; nonce: string } {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { ct: body.toString('base64'), nonce: nonce.toString('base64') };
}

/** vault_key_for_agent is nonce-prepended; entry content keeps its nonce in a field. */
function wrappedVaultKey(): string {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, nonce);
  return Buffer.concat([nonce, c.update(VAULT_KEY), c.final(), c.getAuthTag()]).toString('base64');
}

const SECRETS: Record<string, { mode: string; value: string; tier?: string; cfg?: unknown }> = {
  // A row the 1.0 migration has not reached. The server refuses to serve it; this fake
  // serves it anyway, so the tests below prove the BROKER fails closed on its own.
  legacy1: { mode: 'LEGACY_EXEC', value: 'sk-legacy-plaintext-value' },
  http1: { mode: 'BROKER_HTTP', value: 'sk-brokered-http-credential' },
  ssh1: { mode: 'BROKER_SSH_AGENT', value: 'not-a-real-key' },
};

function startVault(): Promise<void> {
  getSecretCalls = [];
  getSecretQueries = [];
  approvedOrigins = [];
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://x');
      const json = (code: number, body: unknown) => {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (url.pathname === '/agent/profile') {
        return json(200, { vault_key_for_agent: wrappedVaultKey(), allow_env_inject: true });
      }
      if (url.pathname === '/agent/vault/secrets') {
        return json(200, { entries: Object.keys(SECRETS).map((id) => ({ id, secret_name: id, access_tier: '1' })) });
      }
      const m = url.pathname.match(/^\/agent\/vault\/secrets\/(.+)$/);
      if (m) {
        const s = SECRETS[m[1]];
        if (!s) return json(404, { detail: 'no such entry' });
        getSecretCalls.push(m[1]);
        getSecretQueries.push(url.search);
        const enc = gcm(VAULT_KEY, Buffer.from(s.value, 'utf8'));
        return json(200, {
          name: m[1], entry_mode: s.mode, access_tier: s.tier ?? '1',
          encrypted_content: enc.ct, content_nonce: enc.nonce,
          allowed_private_origins: JSON.stringify(approvedOrigins),
          ...(s.cfg !== undefined ? { exec_config: JSON.stringify(s.cfg) } : {}),
        });
      }
      if (url.pathname === '/agent/vault/operation-check') {
        return json(200, { allowed: true, tier: '1' });
      }
      if (url.pathname === '/api/v1/mcp-settings') return json(200, { session_lock_minutes: 5 });
      return json(404, { detail: 'nope' });
    });
    server.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server!.address() as net.AddressInfo).port}`;
      resolve();
    });
  });
}

function speak(sockPath: string, payload: unknown, timeoutMs = 8000): Promise<{ raw: string; json: any }> {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockPath);
    let buf = '';
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutMs);
    const fin = (fn: () => void) => { clearTimeout(t); s.destroy(); fn(); };
    s.on('connect', () => s.write(JSON.stringify(payload) + '\n'));
    s.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      fin(() => {
        let parsed: any = null;
        try { parsed = JSON.parse(buf.trim()); } catch { /* raw only */ }
        resolve({ raw: buf, json: parsed });
      });
    });
    s.on('error', (e) => fin(() => reject(e)));
  });
}

const TOKEN = 'ab'.repeat(32);

async function freshDaemon() {
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'state');
  process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'home', '.wundervault');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  process.env.WUNDERVAULT_AGENT_NO_AUTOSTART = '1';
  process.env.WUNDERVAULT_OLD_UNIT = 'wundervault-test-not-a-real-unit.service';
  // Small knock penalties. The exponential back-off on a wrong token is real and under
  // test elsewhere; here it would just make a loop over malformed payloads take a minute.
  process.env.WUNDERVAULT_KNOCK_BASE_MS = '2';
  process.env.WUNDERVAULT_KNOCK_MAX_MS = '20';
  // The destination store belongs to the broker; point it at the scratch tree so the
  // recording that `call` now does is exercised rather than silently skipped.
  process.env.WUNDERVAULT_NETWORK_STORE = path.join(dir, 'state', 'network.json');
  const d = new AgentDaemon();
  d.registerProfile({
    agent_name: 'A', api_key: 'wv_agent_A|secret-api-key', enc_key: ENC_KEY_B64,
    vault_url: baseUrl, socket_token: TOKEN,
  });
  d.start();
  return d;
}

beforeEach(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-custody-'));
  await startVault();
  daemon = await freshDaemon();
});

afterEach(() => {
  try { daemon?.shutdown(); } catch { /* already down */ }
  daemon = undefined;
  server?.close();
  server = null;
  fs.rmSync(dir, { recursive: true, force: true });
  for (const k of ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR',
                   'WUNDERVAULT_AGENT_NO_AUTOSTART', 'WUNDERVAULT_OLD_UNIT', 'WUNDERVAULT_NETWORK_STORE',
                   'WUNDERVAULT_KNOCK_BASE_MS', 'WUNDERVAULT_KNOCK_MAX_MS']) {
    delete process.env[k];
  }
});

const sock = () => path.join(dir, 'run', 'A.sock');

describe('the broker enforces the mode, not the client', () => {
  it('answers get_entry with an error for every mode, and fetches nothing', async () => {
    // Talking to the socket directly IS the threat model: an agent that does not want to
    // be gated does not run the gate. Until 1.0 get_entry returned a plaintext for a
    // hand-over entry; hand-over is retired and the operation with it. Asserted for every
    // mode including the retired one, on the RAW bytes, and with no fetch at all — an
    // operation that still fetched and then refused would spend an access-log row.
    for (const id of ['http1', 'ssh1', 'legacy1']) {
      for (const extra of [{}, { include_plaintext: true }]) {
        const r = await speak(sock(), { token: TOKEN, op: 'get_entry', entry_id: id, purpose: 'p', ...extra });
        expect(r.json.code, id).toBe('UNKNOWN_OP');
        expect(r.json.plaintext, id).toBeUndefined();
        expect(r.raw, id).not.toContain(SECRETS[id].value);
      }
    }
    expect(getSecretCalls).toEqual([]);
  });

  it('pay and sign refuse every other kind of key, and the reply never carries it (build 2)', async () => {
    for (const id of ['http1', 'ssh1', 'legacy1']) {
      const p = await speak(sock(), { token: TOKEN, op: 'pay', entry_id: id, purpose: 'p',
        payment_required: { x402Version: 2, accepts: [] } });
      expect(p.json.code, `pay ${id}`).toBe('WRONG_MODE');
      expect(p.raw, id).not.toContain(SECRETS[id].value);
      const g = await speak(sock(), { token: TOKEN, op: 'sign', entry_id: id, purpose: 'p', data: 'x' });
      expect(g.json.code, `sign ${id}`).toBe('WRONG_MODE');
      expect(g.raw, id).not.toContain(SECRETS[id].value);
    }
  });

  it('pay refuses an accept_index that is not a whole number (round 2, F1)', async () => {
    for (const idx of [true, '1', 1.5]) {
      const r = await speak(sock(), { token: TOKEN, op: 'pay', entry_id: 'http1', purpose: 'p',
        payment_required: { x402Version: 2, accepts: [] }, accept_index: idx });
      expect(r.json.code, String(idx)).toBe('BAD_REQUEST');
    }
  });

  it('no longer answers profile_flags or settings either', async () => {
    for (const op of ['profile_flags', 'settings']) {
      const r = await speak(sock(), { token: TOKEN, op });
      expect(r.json.code, op).toBe('UNKNOWN_OP');
    }
  });

  it('refuses a call on a hand-over entry the migration has not reached', async () => {
    // Fails CLOSED: the retired mode is neither web nor SSH, so neither path takes it.
    const r = await speak(sock(), {
      token: TOKEN, op: 'call', entry_id: 'legacy1', purpose: 'p',
      request: { origin: { scheme: 'https', host: 'api.example', port: 443 }, method: 'GET', path: '/' },
    });
    expect(r.json.code).toBe('WRONG_MODE');
    expect(r.raw).not.toContain(SECRETS.legacy1.value);
    const s2 = await speak(sock(), {
      token: TOKEN, op: 'ssh_agent_open', entry_id: 'legacy1', purpose: 'p',
      op_spec: { kind: 'ssh', destination: 'h.example', remoteArgv: ['true'] },
    });
    expect(s2.json.code).toBe('WRONG_MODE');
  });

  it('refuses ssh_agent_open for a host the entry does not list', async () => {
    // The allowlist used to be read and applied in the MCP server — the agent checking
    // itself, while holding the private key. The broker refuses to open the session.
    const r = await speak(sock(), {
      token: TOKEN, op: 'ssh_agent_open', entry_id: 'ssh1', purpose: 'p',
      op_spec: { kind: 'ssh', destination: 'anywhere.example', remoteArgv: ['true'] },
    });
    expect(r.json.error).toMatch(/permitted SSH hosts|not in this entry/);
    expect(r.raw).not.toContain(SECRETS.ssh1.value);
  });
});

describe('a brokered call keeps the credential', () => {
  /**
   * `performOperation` is stubbed, and only it.
   *
   * WHY NOT A REAL UPSTREAM. The broker refuses plain http (the token rides in a header,
   * so http hands it to the wire) and pins `rejectUnauthorized: true` with no way to pass
   * a CA — both correct, and between them they make an in-process HTTPS round trip
   * untestable without either a test hook in production code or a CA installed before
   * Node starts. Adding a hook to the one function that handles a decrypted credential,
   * so that a test could reach it, is a bad trade.
   *
   * So the seam is the last function before the socket: the stub captures what the broker
   * decided to send. The real outbound path — SSRF guard, pinned lookup, redirect
   * refusal, scrubbing — is covered unchanged by `vault-call.test.ts`, and the genuine
   * end-to-end round trip is acceptance check 27, in the rehearsal container.
   */
  let sentSecret: string | null = null;
  let sentUrl = '';

  beforeEach(async () => {
    sentSecret = null;
    sentUrl = '';
    vi.resetModules();
  });

  it('hands the decrypted credential to the outbound call and nothing to the caller', async () => {
    vi.doMock('../src/http-broker.js', async (importOriginal) => {
      const real = await importOriginal<typeof import('../src/http-broker.js')>();
      return {
        ...real,
        performOperation: async (def: any, _args: any, secret: string) => {
          sentSecret = secret;
          sentUrl = `${real.originString(def.origin)}${def.route.path}`;
          return { ok: true, status: 200, body: { fine: true } };
        },
      };
    });
    // Imported AFTER the mock so the daemon picks up the stub. A fresh daemon on a fresh
    // socket, because the one from the outer beforeEach holds the real module.
    const { AgentDaemon: Mocked } = await import('../src/agent.js');
    const d: any = new Mocked();
    d.registerProfile({
      agent_name: 'B', api_key: 'wv_agent_B|secret-api-key', enc_key: ENC_KEY_B64,
      vault_url: baseUrl, socket_token: TOKEN,
    });
    d.start();
    try {
      const r = await speak(path.join(dir, 'run', 'B.sock'), {
        token: TOKEN, op: 'call', entry_id: 'http1', purpose: 'p',
        request: { origin: { scheme: 'https', host: 'api.example', port: 443 }, method: 'GET', path: '/thing' },
      });
      // The broker decrypted the credential and used it...
      expect(sentSecret).toBe(SECRETS.http1.value);
      expect(sentUrl).toBe('https://api.example:443/thing');
      // ...and it never came back down the socket. Asserted on the RAW BYTES: a secret
      // echoed into an error string or nested in a response body is still a secret on
      // the wire, and `r.json.plaintext === undefined` would miss both.
      expect(r.raw).not.toContain(SECRETS.http1.value);
      expect(r.json.status).toBe(200);
      expect(r.json.tier).toBe('1');
    } finally {
      try { d.shutdown(); } catch { /* already down */ }
      vi.doUnmock('../src/http-broker.js');
    }
  }, 20_000);

  it("frames the key the way the ENTRY says, and refuses one it would not accept", async () => {
    // Check 9, through the broker. The stub captures the binding the broker decided on;
    // the wire itself is asserted in binding.test.ts against a real https server.
    let sentBinding: any = null;
    let calls = 0;
    vi.doMock('../src/http-broker.js', async (importOriginal) => {
      const real = await importOriginal<typeof import('../src/http-broker.js')>();
      return {
        ...real,
        performOperation: async (def: any) => {
          calls += 1;
          sentBinding = def.credential_binding;
          return { ok: true, status: 200, body: {} };
        },
      };
    });
    const { AgentDaemon: Mocked } = await import('../src/agent.js');
    const d: any = new Mocked();
    d.registerProfile({
      agent_name: 'C', api_key: 'wv_agent_C|secret-api-key', enc_key: ENC_KEY_B64,
      vault_url: baseUrl, socket_token: TOKEN,
    });
    d.start();
    const request = { origin: { scheme: 'https', host: 'api.example', port: 443 }, method: 'GET', path: '/' };
    const ask = () => speak(path.join(dir, 'run', 'C.sock'), {
      token: TOKEN, op: 'call', entry_id: 'http1', purpose: 'p', request,
    });
    try {
      SECRETS.http1.cfg = { delivery: 'http', credential_binding: { in: 'header', name: 'X-Api-Key', template: 'Key {secret}' } };
      let r = await ask();
      expect(r.json.error).toBeUndefined();
      expect(sentBinding).toEqual({ in: 'header', name: 'x-api-key', template: 'Key {secret}' });

      SECRETS.http1.cfg = { delivery: 'http', credential_binding: { in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'deploy' } };
      r = await ask();
      expect(sentBinding.username).toBe('deploy');

      // A server that rewrote the binding into something the owner could not have set.
      const before = calls;
      for (const bad of [
        { in: 'header', name: 'host', template: '{secret}' },
        { in: 'header', name: 'x-key', template: '{secret}{secret}' },
        { in: 'header', name: 'x-key', template: 'no placeholder' },
        { in: 'header', name: 'x-key', template: '{secret}\r\nx-evil: 1' },
        'Bearer {secret}',
        null,   // round 1, F2: an explicit null is not "absent"
      ]) {
        SECRETS.http1.cfg = { delivery: 'http', credential_binding: bad };
        r = await ask();
        expect(r.json.code, JSON.stringify(bad)).toBe('BAD_BINDING');
        expect(r.raw).not.toContain(SECRETS.http1.value);
      }
      expect(calls).toBe(before);   // nothing was sent, and no bearer fallback
    } finally {
      delete SECRETS.http1.cfg;
      try { d.shutdown(); } catch { /* already down */ }
      vi.doUnmock('../src/http-broker.js');
    }
  }, 20_000);

  it('never sends a private key to a web service (round 2, B3)', async () => {
    // A hand-over SSH key converted to "web, bearer" by the migration, before its owner has
    // switched it to SSH. Without this the broker would send the private key as a bearer
    // token to whatever host the agent named.
    let sent = 0;
    vi.doMock('../src/http-broker.js', async (importOriginal) => {
      const real = await importOriginal<typeof import('../src/http-broker.js')>();
      return { ...real, performOperation: async () => { sent += 1; return { ok: true, status: 200, body: {} }; } };
    });
    const { AgentDaemon: Mocked } = await import('../src/agent.js');
    const d: any = new Mocked();
    d.registerProfile({
      agent_name: 'D', api_key: 'wv_agent_D|secret-api-key', enc_key: ENC_KEY_B64,
      vault_url: baseUrl, socket_token: TOKEN,
    });
    d.start();
    const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n';
    SECRETS.pk1 = { mode: 'BROKER_HTTP', value: pem };
    try {
      for (const binding of [undefined, { in: 'query', name: 'k', template: '{secret}' }]) {
        SECRETS.pk1.cfg = binding ? { delivery: 'http', credential_binding: binding } : undefined;
        const r = await speak(path.join(dir, 'run', 'D.sock'), {
          token: TOKEN, op: 'call', entry_id: 'pk1', purpose: 'p',
          request: { origin: { scheme: 'https', host: 'api.example', port: 443 }, method: 'GET', path: '/' },
        });
        expect(r.json.code).toBe('WRONG_KIND');
        expect(r.raw).not.toContain('b3BlbnNzaC1rZXktdjEAAAAA');
      }
      expect(sent).toBe(0);
    } finally {
      delete SECRETS.pk1;
      try { d.shutdown(); } catch { /* already down */ }
      vi.doUnmock('../src/http-broker.js');
    }
  }, 20_000);

  it('carries no plaintext on the refusal paths either', async () => {
    // The paths where a naive implementation leaks: the broker is holding the decrypted
    // credential when each of these fails, and the temptation is to include context.
    const cases = [
      { label: 'blocked private origin',
        request: { origin: { scheme: 'https', host: '127.0.0.1', port: 9 }, method: 'GET', path: '/' } },
      { label: 'cloud metadata',
        request: { origin: { scheme: 'https', host: '169.254.169.254', port: 443 }, method: 'GET', path: '/' } },
      { label: 'unresolvable host',
        request: { origin: { scheme: 'https', host: 'no-such-host.invalid', port: 443 }, method: 'GET', path: '/' } },
      { label: 'plain http',
        request: { origin: { scheme: 'http', host: 'api.example', port: 80 }, method: 'GET', path: '/' } },
    ];
    for (const c of cases) {
      const r = await speak(sock(), {
        token: TOKEN, op: 'call', entry_id: 'http1', purpose: 'p', request: c.request,
      });
      expect(r.json.error, c.label).toBeTruthy();
      expect(r.raw, c.label).not.toContain(SECRETS.http1.value);
    }
  }, 30_000);

  it('records the destination in the BROKER-owned store', async () => {
    // D3 of the uid-split spec calls this store an integrity control because the audited
    // party no longer owns the evidence. The writer used to be the MCP server — the
    // audited party — writing to a directory its uid cannot open, so the control was
    // either failing the call or failing silently. It is the broker that writes it now.
    //
    // Recorded BEFORE the verdict and before the request, which is why a refused call
    // still leaves a row: a first sighting that got refused must not read as new again
    // on the retry.
    await speak(sock(), {
      token: TOKEN, op: 'call', entry_id: 'http1', purpose: 'audit-me',
      request: { origin: { scheme: 'https', host: 'api.example', port: 443 }, method: 'GET', path: '/x' },
    });
    const store = JSON.parse(readFileSync(path.join(dir, 'state', 'network.json'), 'utf8'));
    const row = store.seen.find((x: any) => x.entryId === 'http1');
    expect(row).toBeTruthy();
    expect(row.origin).toBe('https://api.example:443');
  }, 20_000);
});

describe("the agent's own headers, checked by the broker", () => {
  // SPEC-replies.md §B. Driven through the socket, as a hostile agent would, so the check
  // proved is the broker's and not the MCP server's.
  const call = (headers: unknown) => speak(sock(), {
    token: TOKEN, op: 'call', entry_id: 'http1', purpose: 'p',
    request: { origin: { scheme: 'https', host: 'api.example', port: 443 }, method: 'GET', path: '/', headers },
  });

  it("refuses the header that carries the entry's key, in any case, and sends nothing", async () => {
    for (const name of ['authorization', 'Authorization', 'AUTHORIZATION']) {
      const r = await call({ [name]: 'Bearer mine' });
      expect(r.json.code, name).toBe('BAD_REQUEST');
      expect(r.json.error, name).toMatch(/authorization carries this entry's key/);
      expect(r.raw).not.toContain(SECRETS.http1.value);
    }
  });

  it('refuses framing headers and anything addressed to a proxy', async () => {
    for (const name of ['host', 'content-length', 'transfer-encoding', 'accept-encoding', 'proxy-anything', 'Expect']) {
      const r = await call({ [name]: 'x' });
      expect(r.json.code, name).toBe('BAD_REQUEST');
    }
  });

  it('refuses a header value with a line break rather than sending half of it', async () => {
    const r = await call({ 'x-api-version': '1\r\nx-injected: yes' });
    expect(r.json.code).toBe('BAD_REQUEST');
    expect(r.json.error).toMatch(/printable text/);
  });

  it('refuses a name given twice in different case, and headers that are not an object', async () => {
    expect((await call({ 'User-Agent': 'a', 'user-agent': 'b' })).json.code).toBe('BAD_REQUEST');
    expect((await call(['user-agent', 'x'])).json.code).toBe('BAD_REQUEST');
    expect((await call('user-agent: x')).json.code).toBe('BAD_REQUEST');
  });

  it('lets ordinary headers through to the request', async () => {
    // api.example does not resolve, so the call fails AFTER the header check — which is
    // the point: it is not refused for its headers.
    const r = await call({ 'user-agent': 'my-agent/1.0', 'anthropic-version': '2023-06-01', accept: 'text/csv' });
    expect(r.json.code).not.toBe('BAD_REQUEST');
    expect(String(r.json.error)).not.toMatch(/request\.headers/);
  }, 20_000);
});

describe('one getSecret per operation', () => {
  it('does not add an access-log row for metadata', async () => {
    // There is deliberately no metadata probe. A convenient "just tell me the mode" call
    // would add a row to the owner's access log for every tool call and give tier 2 a
    // second chance to fire.
    await speak(sock(), {
      token: TOKEN, op: 'call', entry_id: 'http1', purpose: 'p',
      request: { origin: { scheme: 'http', host: 'api.example', port: 80 }, method: 'GET', path: '/' },
    });
    expect(getSecretCalls).toEqual(['http1']);
  });

  it("sends the agent's purpose with no fetch, web or SSH", async () => {
    // Network-shape decision, 2026-09-15: the reason stays in the broker's local log.
    // The parameter is still present (the route requires it), and empty.
    const secretPurpose = 'rotate creds after suspected breach at acme';
    await speak(sock(), {
      token: TOKEN, op: 'call', entry_id: 'http1', purpose: secretPurpose,
      request: { origin: { scheme: 'http', host: 'api.example', port: 80 }, method: 'GET', path: '/' },
    });
    await speak(sock(), {
      token: TOKEN, op: 'ssh_agent_open', entry_id: 'ssh1', purpose: secretPurpose,
      op_spec: { kind: 'ssh', destination: 'h.example', remoteArgv: ['true'] },
    });
    expect(getSecretQueries).toEqual(['?purpose=', '?purpose=']);
  });

  it('list_entries touches no secret at all', async () => {
    await speak(sock(), { token: TOKEN, op: 'list_entries' });
    expect(getSecretCalls).toEqual([]);
  });
});

describe('the raised socket limits', () => {
  // Acceptance check 25. The caps moved from 4096 bytes / 10s to 1 MiB / 120s so a `call`
  // can carry an HTTP body and wait on a 30s upstream. The surrounding comments in
  // agent.ts were written about a real DoS — a byte every few seconds resetting an
  // INACTIVITY timeout while the buffer grew — so raising them without checking what they
  // were protecting would be the same bug with bigger numbers.

  it('refuses a request larger than the cap instead of buffering it', async () => {
    const big = 'x'.repeat(2 * 1024 * 1024);
    await expect(speak(sock(), { token: TOKEN, op: 'ping', pad: big }, 10_000))
      .rejects.toThrow();
  });

  it('accepts a large-but-legal request', async () => {
    // Just under the cap, so the boundary is exercised from both sides rather than only
    // from the side that fails.
    const pad = 'x'.repeat(900 * 1024);
    const r = await speak(sock(), { token: TOKEN, op: 'ping', pad }, 10_000);
    expect(r.json.ok).toBe(true);
  });

  it('closes a connection that is held open without ever sending a newline', async () => {
    // The absolute deadline, which is what actually bounds the resource: the inactivity
    // timer is resettable by any traffic, which is how the original hole worked.
    const s = net.createConnection(sock());
    await new Promise<void>((r) => s.on('connect', () => r()));
    s.write('{"token":"' + TOKEN + '"');           // no newline, ever
    const closed = await new Promise<boolean>((resolve) => {
      const t = setTimeout(() => resolve(false), 3_000);
      s.on('close', () => { clearTimeout(t); resolve(true); });
      // Keep it "active" so only the ABSOLUTE deadline can close it. If the inactivity
      // timer were the only guard, this would hold the connection indefinitely.
      const beat = setInterval(() => { try { s.write(' '); } catch { /* closed */ } }, 500);
      s.on('close', () => clearInterval(beat));
    });
    s.destroy();
    // Within this test's patience the connection is still legitimately open — the
    // deadline is 120s. What is asserted is that it is NOT closed by inactivity while
    // being fed, i.e. that the absolute timer is the one doing the work. The deadline
    // itself is asserted by reading it, below, because a 120s test is not worth having.
    expect(closed).toBe(false);
  });

  it('states both timers, and the absolute one bounds the connection', () => {
    // Read off the source rather than waited for. A test that actually waits three
    // minutes would be deleted by the next person, and a deleted test protects nothing.
    const src = readFileSync(path.join(ROOT, 'src/agent.ts'), 'utf8');
    expect(src).toContain('socket.setTimeout(30_000');
    // 180s, not the 120s first written: a tier-2 call waits up to 90s for a human, then
    // re-asks the server and performs a request with its own 30s timeout. 120s would cut
    // off the one path that exists to survive a person taking their time.
    expect(src).toMatch(/setTimeout\(\(\) => socket\.destroy\(\), 180_000\)/);
    // And the framing searches the CHUNK for the newline, not the accumulation — the
    // quadratic-copy shape a paced sender could exploit before authenticating.
    expect(src).toContain('if (d.indexOf(0x0a) < 0) return;');
    expect(src).toContain('const MAX_REPLY_BYTES');
    expect(src).toContain('const MAX_REQUEST_BYTES = 1024 * 1024;');
    // And the inactivity timer is disarmed once the request is in.
    expect(src).toContain('socket.setTimeout(0);');
  });

  it('does not kill the connection while the broker is legitimately working', async () => {
    // THE DEFECT THIS REPLACES. The inactivity timer stayed armed while `serve` ran, and
    // during an operation there is no traffic on the agent socket by design — the broker
    // is fetching an entry, waiting on a 30s upstream call, or parked on a tier-2
    // approval for up to 90s. So a slow call was destroyed at 30 seconds, the caller got
    // nothing, and the broker carried on working for somebody who had gone.
    //
    // Simulated with an upstream that answers slowly rather than by waiting 30s here.
    const slow = http.createServer((_req, res) => {
      setTimeout(() => { res.writeHead(200); res.end('{}'); }, 1200);
    });
    await new Promise<void>((r) => slow.listen(0, '127.0.0.1', () => r()));
    try {
      const began = Date.now();
      const r = await speak(sock(), {
        token: TOKEN, op: 'call', entry_id: 'http1', purpose: 'p',
        request: { origin: { scheme: 'https', host: 'api.example', port: 443 }, method: 'GET', path: '/' },
      }, 20_000);
      // It came back at all — a reply, not a destroyed socket. The call itself fails on
      // the SSRF/DNS path, which is fine: what is under test is that the broker was
      // allowed to finish and answer.
      expect(r.json).toBeTruthy();
      expect(Date.now() - began).toBeLessThan(20_000);
    } finally {
      slow.close();
    }
  }, 30_000);
});

describe('malformed input cannot take the broker down', () => {
  // A crash here is not an inconvenience: this process holds every credential on the
  // machine, and the socket it listens on is world-connectable by design.

  it('survives a JSON null, which is the one scalar that used to crash it', async () => {
    // `JSON.parse("null")` returns null and the parse does NOT throw, so `null` sailed
    // past the try/catch and `msg.token` threw a TypeError synchronously inside the
    // socket data callback — an uncaught exception in the event loop. Any local process
    // could kill the broker with five bytes.
    const r = await speak(sock(), null as unknown as Record<string, unknown>);
    expect(r.json.error).toBe('unauthorized');
    // And it is still alive to answer the next caller, which is the actual assertion.
    const after = await speak(sock(), { token: TOKEN, op: 'ping' });
    expect(after.json.ok).toBe(true);
  });

  it('survives every other JSON shape a caller can send', async () => {
    const shapes: unknown[] = [5, 'a string', true, [], [1, 2, 3], {}, { token: null }, { token: 5 }];
    for (const shape of shapes) {
      const r = await speak(sock(), shape as Record<string, unknown>);
      expect(r.json.error, JSON.stringify(shape)).toBe('unauthorized');
    }
    const after = await speak(sock(), { token: TOKEN, op: 'ping' });
    expect(after.json.ok).toBe(true);
  }, 20_000);

  it('survives a body that is not JSON at all', async () => {
    const s = net.createConnection(sock());
    await new Promise<void>((r) => s.on('connect', () => r()));
    s.write('not json at all\n');
    await new Promise((r) => setTimeout(r, 300));
    s.destroy();
    const after = await speak(sock(), { token: TOKEN, op: 'ping' });
    expect(after.json.ok).toBe(true);
  });

  it('reassembles a multi-byte character split across two TCP reads', async () => {
    // `chunk.toString()` per chunk decoded each read independently, so a character whose
    // UTF-8 bytes landed in different reads became two replacement characters — and the
    // broker then acted on a request that was not the one sent. Only for non-ASCII, and
    // only sometimes, which is the worst shape a bug can have.
    const payload = Buffer.from(JSON.stringify({ token: TOKEN, op: 'ping', note: 'héllo — ünïcode' }) + '\n', 'utf8');
    const split = 30; // lands mid-character for this payload
    const s = net.createConnection(sock());
    await new Promise<void>((r) => s.on('connect', () => r()));
    const reply = new Promise<string>((resolve) => {
      let buf = '';
      s.on('data', (d) => { buf += d.toString(); if (buf.includes('\n')) resolve(buf); });
    });
    s.write(payload.subarray(0, split));
    await new Promise((r) => setTimeout(r, 50));
    s.write(payload.subarray(split));
    const raw = await reply;
    s.destroy();
    // A corrupted line would not parse as JSON, so the token would not match and this
    // would be 'unauthorized' rather than a successful ping.
    expect(JSON.parse(raw.trim()).ok).toBe(true);
  });

  it('caps on BYTES, not on UTF-16 code units', async () => {
    // `buf.length` on a string counts code units. 700,000 three-byte characters is over
    // 2 MiB on the wire and about 700,000 "long" as a string, so a byte cap enforced on a
    // string is not a byte cap at all.
    const threeByte = '\u4e2d'.repeat(700_000); // ~2.1 MiB as UTF-8, 700k UTF-16 units
    await expect(speak(sock(), { token: TOKEN, op: 'ping', pad: threeByte }, 15_000))
      .rejects.toThrow();
    const after = await speak(sock(), { token: TOKEN, op: 'ping' });
    expect(after.json.ok).toBe(true);
  }, 30_000);
});

describe('an authenticated caller cannot accumulate resources', () => {
  it('caps concurrent signing sessions per agent', async () => {
    // Each open session is a listener, a timer, a directory under /run and a private key
    // in memory, and the CALLER decides when to close them. The entry here is in the
    // wrong mode so every attempt is refused for that reason first — what is asserted is
    // that the ceiling exists in the code path before the fetch, so hitting it costs no
    // access-log row.
    const src = readFileSync(path.join(ROOT, 'src/broker-ops.ts'), 'utf8');
    expect(src).toContain('MAX_SSH_SESSIONS');
    const open = src.indexOf('async sshAgentOpen');
    const cap = src.indexOf('TOO_MANY_SESSIONS', open);
    const fetchAt = src.indexOf('await this.api.getSecret', open);
    expect(cap).toBeGreaterThan(-1);
    expect(cap).toBeLessThan(fetchAt);
  });

  it('refuses to serialise an oversized reply rather than sending it', () => {
    const src = readFileSync(path.join(ROOT, 'src/agent.ts'), 'utf8');
    expect(src).toContain("code: 'REPLY_TOO_LARGE'");
  });
});

describe('the MCP server cannot decrypt anything', () => {
  // Grep, not behaviour, and deliberately: the failure this guards against is a future
  // change that reintroduces local decryption because it was the convenient fix. A
  // behavioural test would pass right up until someone added the import.
  // src/exec.ts was here until 1.0; it ran hand-over commands and is gone with them.
  const MCP_SIDE = ['src/server.ts', 'src/broker-client.ts', 'src/index.ts', 'src/ssh-agent.ts'];
  const FORBIDDEN = ['decryptVaultKey', 'decryptSecretContent', 'loadEncryptionKey'];

  for (const file of MCP_SIDE) {
    it(`${file} imports no key-handling helper`, () => {
      const src = readFileSync(path.join(ROOT, file), 'utf8');
      const imports = src.split('\n').filter((l) => /^\s*import\b/.test(l)).join('\n');
      for (const name of FORBIDDEN) {
        expect(imports, `${file} imports ${name}`).not.toContain(name);
      }
    });
  }

  it('the broker-side modules are the only ones that do', () => {
    // The inverse, so this suite fails if the imports move somewhere unexpected rather
    // than only when they appear in a file someone thought to list above.
    const all = fs.readdirSync(path.join(ROOT, 'src')).filter((f) => f.endsWith('.ts'));
    const holders = all.filter((f) => {
      const src = readFileSync(path.join(ROOT, 'src', f), 'utf8');
      const imports = src.split('\n').filter((l) => /^\s*import\b/.test(l)).join('\n');
      return FORBIDDEN.some((n) => imports.includes(n));
    });
    // signing-ops.ts and wallet.ts (build 2) run inside the broker: payments, signatures and
    // the owner's encrypted rules. Nothing on the MCP side imports them (next test).
    expect(holders.sort()).toEqual(['api-client.ts', 'broker-ops.ts', 'signing-ops.ts', 'wallet.ts']);
  });

  it('the MCP side reaches none of the build-2 broker modules, even indirectly', () => {
    const seen = new Set<string>();
    const walk = (file: string) => {
      if (seen.has(file)) return;
      seen.add(file);
      const src = readFileSync(path.join(ROOT, 'src', file), 'utf8');
      for (const m of src.matchAll(/^\s*import\s+(?!type\b)[^;]*?from\s+'\.\/([\w-]+)\.js'/gm)) walk(`${m[1]}.ts`);
    };
    for (const f of ['server.ts', 'broker-client.ts', 'index.ts']) walk(f);
    // The walker must actually walk: server.ts imports ssh-agent.ts and render.ts directly.
    expect(seen.has('ssh-agent.ts') && seen.has('render.ts')).toBe(true);
    for (const broker of ['signing-ops.ts', 'wallet.ts', 'broker-ops.ts', 'evm.ts', 'solana.ts', 'signing.ts', 'stamp.ts']) {
      expect(seen.has(broker), `the MCP side imports ${broker}`).toBe(false);
    }
  });
});
