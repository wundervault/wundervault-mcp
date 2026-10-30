/**
 * Drive the real broker request path: a local vault serves sealed entries, and a
 * trusted local HTTPS service echoes the credentials that actually reached the wire.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { BrokerOps } from '../src/broker-ops.js';
import { sealSetup, openT2Detail, t2MatchMac } from '../src/setup-seal.js';

type CheckBody = Record<string, unknown>;
type Verdict = { allowed: boolean; tier?: string; request_id?: string };
type Placement = {
  in: 'header' | 'query' | 'path';
  name: string;
  template: string;
};
type TestBinding = (Placement & { v: 1 }) | { v: 2; placements: Placement[] };
type Echo = { headers: http.IncomingHttpHeaders; url: string };
type CallResult = Awaited<ReturnType<BrokerOps['call']>>;

const vaultKey = crypto.randomBytes(32);
const encKey = crypto.randomBytes(32);
const apiKey = `test-${crypto.randomBytes(16).toString('hex')}`;
const agentId = crypto.randomBytes(16).toString('hex');
const keyIdEntryId = crypto.randomBytes(16).toString('hex');

const keyIdBinding: TestBinding = {
  v: 2,
  placements: [
    { in: 'header', name: 'apca-api-key-id', template: '{part:id}' },
    { in: 'header', name: 'apca-api-secret-key', template: '{part:secret}' },
  ],
};
const apiKeyBinding: TestBinding = {
  v: 1, in: 'header', name: 'x-api-key', template: '{secret}',
};

let dir = '';
let savedCAs: string[] | undefined;
let vaultServer: http.Server | undefined;
let echoServer: https.Server | undefined;
let vaultUrl = '';
let port = 0;
let broker: BrokerOps;
let entries = new Map<string, Record<string, unknown>>();
let wire: (Echo & { method: string })[] = [];
let checks: CheckBody[] = [];
let polls: string[] = [];
let unexpected: string[] = [];
let answerCheck: (body: CheckBody, index: number) => Verdict;

function encrypt(key: Buffer, plaintext: Buffer): { nonce: Buffer; ciphertext: Buffer } {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { nonce, ciphertext };
}

function origin(): string {
  return `https://127.0.0.1:${port}`;
}

function newBroker(): BrokerOps {
  return new BrokerOps('Test', apiKey, encKey.toString('base64url'), vaultUrl, null, undefined, {}, {
    pinsPath: path.join(dir, 'setup-pins.json'),
  });
}

function sendJson(res: http.ServerResponse, body: unknown, status = 200): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function listen(server: http.Server | https.Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  return (server.address() as net.AddressInfo).port;
}

async function close(server: http.Server | https.Server | undefined): Promise<void> {
  if (!server?.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}

function entry(options: {
  id?: string;
  shape: 'api_key' | 'key_id' | 'password';
  format: 'raw' | 'parts-1';
  plaintext: string;
  binding: TestBinding;
  knownAddresses?: string[];
  locked?: boolean;
  tier?: '1' | '2';
  valueSha256?: string;
}): Record<string, unknown> & { id: string } {
  const id = options.id ?? crypto.randomBytes(16).toString('hex');
  const rev = 1;
  const value = encrypt(vaultKey, Buffer.from(options.plaintext, 'utf8'));
  const setup = {
    v: 1,
    rev,
    value_sha256: options.valueSha256
      ?? crypto.createHash('sha256').update(value.ciphertext).digest('hex'),
    value_format: options.format,
    name: 'Test credential',
    shape: options.shape,
    service: null,
    delivery: 'http',
    binding: options.binding,
    ssh_hosts: [],
    private_origins: [origin()],
    known_addresses: options.knownAddresses ?? [],
    approval: null,
    operations: {},
    chain: null,
  };
  const sealed = sealSetup(
    vaultKey, agentId, id, rev,
    setup as unknown as Parameters<typeof sealSetup>[4],
  );
  if (!sealed.ok) throw new Error(`Could not seal test setup: ${JSON.stringify(sealed)}`);
  return {
    id,
    agent_id: agentId,
    rev,
    encrypted_content: value.ciphertext.toString('base64'),
    content_nonce: value.nonce.toString('base64'),
    setup_ciphertext: sealed.ciphertext,
    setup_nonce: sealed.nonce,
    access_tier: options.tier ?? '1',
    vault_locked: options.locked ?? false,
  };
}

function keyIdEntry(): Record<string, unknown> & { id: string } {
  return entry({
    id: keyIdEntryId,
    shape: 'key_id',
    format: 'parts-1',
    plaintext: JSON.stringify({ parts: { id: 'PKID123456', secret: 'sek-abcdef' } }),
    binding: keyIdBinding,
  });
}

function call(
  id: string,
  requestPath = '/',
  extra: Partial<NonNullable<Parameters<BrokerOps['call']>[0]['request']>> = {},
): Promise<CallResult> {
  return broker.call({
    entryId: id,
    purpose: 'Exercise the broker request path',
    request: {
      origin: { scheme: 'https', host: '127.0.0.1', port },
      method: 'GET',
      path: requestPath,
      ...extra,
    },
  });
}

function success(result: CallResult) {
  expect(result).toMatchObject({ status: 200 });
  if ('error' in result) throw new Error(result.error);
  return result;
}

function reply(result: CallResult): Echo {
  const r = success(result);
  const body: unknown = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
  expect(body).toMatchObject({ headers: expect.any(Object), url: expect.any(String) });
  return body as Echo;
}

function expectScrubbed(value: unknown, secrets: string[]): void {
  const text = JSON.stringify(value);
  for (const secret of secrets) {
    expect(text).not.toContain(secret);
    expect(text).not.toContain(encodeURIComponent(secret));
  }
  expect(text).toContain('[REDACTED]');
}

// Every machine path the broker writes (destination log, activity log, signing state) goes to
// this test's temp dir; the real /var/lib/wundervault is never touched.
const redirected = ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR',
  'WUNDERVAULT_NETWORK_STORE'] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeAll(async () => {
  vi.useRealTimers();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-brokerparts-'));
  for (const name of redirected) savedEnv[name] = process.env[name];
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'system');
  process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'user');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  process.env.WUNDERVAULT_NETWORK_STORE = path.join(dir, 'system', 'network.json');
  for (const sub of ['system', 'user', 'run']) fs.mkdirSync(path.join(dir, sub), { recursive: true, mode: 0o700 });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  const cert = fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8');
  savedCAs = tls.getCACertificates('default');
  tls.setDefaultCACertificates([...savedCAs, cert]);

  echoServer = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert }, (req, res) => {
    req.resume();
    req.on('end', () => {
      const received = { headers: { ...req.headers }, url: req.url ?? '/' };
      wire.push({ ...received, method: req.method ?? '' });
      sendJson(res, received);
    });
  });
  port = await listen(echoServer);

  const wrappedKey = encrypt(encKey, vaultKey);
  const vaultKeyForAgent = Buffer.concat([wrappedKey.nonce, wrappedKey.ciphertext]).toString('base64');
  vaultServer = http.createServer((req, res) => {
    const pathname = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
    if (req.method === 'GET' && pathname === '/agent/profile') {
      sendJson(res, { vault_key_for_agent: vaultKeyForAgent });
      return;
    }
    if (req.method === 'GET' && pathname.startsWith('/agent/vault/secrets/')) {
      const id = pathname.slice('/agent/vault/secrets/'.length);
      const found = entries.get(id);
      if (found) {
        sendJson(res, found);
        return;
      }
    }
    if (req.method === 'POST' && pathname === '/agent/vault/operation-check') {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as CheckBody;
          checks.push(body);
          sendJson(res, answerCheck(body, checks.length - 1));
        } catch {
          sendJson(res, { error: 'Invalid operation-check JSON' }, 400);
        }
      });
      return;
    }
    if (req.method === 'GET' && pathname === '/agent/vault/tier2-requests/r1') {
      polls.push(pathname);
      sendJson(res, { status: 'approved' });
      return;
    }
    unexpected.push(`${req.method} ${pathname}`);
    sendJson(res, { error: 'Not found' }, 404);
  });
  vaultUrl = `http://127.0.0.1:${await listen(vaultServer)}`;
}, 20_000);

beforeEach(() => {
  entries = new Map();
  wire = [];
  checks = [];
  polls = [];
  unexpected = [];
  answerCheck = () => ({ allowed: true, tier: '1' });
  broker = newBroker();
});

afterEach(() => {
  broker?.reset();
  expect(unexpected).toEqual([]);
});

afterAll(async () => {
  try {
    await Promise.all([close(vaultServer), close(echoServer)]);
  } finally {
    for (const name of redirected) {
      if (savedEnv[name] === undefined) delete process.env[name];
      else process.env[name] = savedEnv[name];
    }
    if (savedCAs !== undefined) tls.setDefaultCACertificates(savedCAs);
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
}, 20_000);

describe('BrokerOps.call with sealed parts', () => {
  it('places both key_id parts in their headers and scrubs both from the reply', async () => {
    const e = keyIdEntry();
    entries.set(e.id, e);

    const result = await call(e.id, '/two-headers');

    expect(wire).toHaveLength(1);
    expect(wire[0].url).toBe('/two-headers');
    expect(wire[0].headers['apca-api-key-id']).toBe('PKID123456');
    expect(wire[0].headers['apca-api-secret-key']).toBe('sek-abcdef');
    expect(wire[0].headers.authorization).toBeUndefined();
    expect(reply(result).headers).toMatchObject({
      'apca-api-key-id': '[REDACTED]',
      'apca-api-secret-key': '[REDACTED]',
    });
    expect(success(result)).toMatchObject({
      tier: '1', label: `GET ${origin()}/two-headers`,
    });
    expectScrubbed(result, ['PKID123456', 'sek-abcdef']);
  });

  it('accepts the vault page v:1 marker on a sealed raw api_key binding', async () => {
    const secret = 'raw-api-key-654321';
    const e = entry({
      shape: 'api_key', format: 'raw', plaintext: secret, binding: apiKeyBinding,
    });
    entries.set(e.id, e);

    const result = await call(e.id, '/v1-marker');

    expect(wire).toHaveLength(1);
    expect(wire[0].url).toBe('/v1-marker');
    expect(wire[0].headers['x-api-key']).toBe(secret);
    expect(wire[0].headers.authorization).toBeUndefined();
    expect(reply(result).headers['x-api-key']).toBe('[REDACTED]');
    expectScrubbed(result, [secret]);
  });

  it('composes basic auth from password parts and scrubs the token and both parts', async () => {
    const username = 'parts-user-9876';
    const password = 'parts-password+42/=long';
    const token = Buffer.from(`${username}:${password}`).toString('base64');
    const e = entry({
      shape: 'password',
      format: 'parts-1',
      plaintext: JSON.stringify({ parts: { username, password } }),
      binding: {
        v: 2,
        placements: [{
          in: 'header', name: 'authorization', template: 'Basic {basic:username:password}',
        }],
      },
    });
    entries.set(e.id, e);

    // The echo URL also exposes each individual part, not just the composed token.
    const result = await call(e.id, '/basic', { query: { u: username, p: password } });

    expect(wire).toHaveLength(1);
    expect(wire[0].headers.authorization).toBe(`Basic ${token}`);
    const sentUrl = new URL(wire[0].url, origin());
    expect(sentUrl.searchParams.get('u')).toBe(username);
    expect(sentUrl.searchParams.get('p')).toBe(password);
    expect(reply(result).headers.authorization).toContain('[REDACTED]');
    expectScrubbed(result, [token, username, password]);
  });

  it('places a Telegram-style key in the path without leaking it in the result or address', async () => {
    const key = 'tg-123456789_secret';
    const e = entry({
      shape: 'api_key',
      format: 'parts-1',
      plaintext: JSON.stringify({ parts: { key } }),
      binding: {
        v: 2,
        placements: [{ in: 'path', name: '', template: '/bot{part:key}' }],
      },
    });
    entries.set(e.id, e);
    const activity: { address?: string }[] = [];
    broker.activity = { record: (record) => activity.push({ ...record }) };

    const result = await call(e.id, '/getMe');

    expect(wire).toHaveLength(1);
    expect(wire[0].url).toBe(`/bot${key}/getMe`);
    expect(wire[0].headers.authorization).toBeUndefined();
    expect(reply(result).url).toBe('/bot[REDACTED]/getMe');
    expect(success(result).label).toBe(`GET ${origin()}/getMe`);
    expect(activity).toHaveLength(1);
    expect(activity[0].address).toBe(`${origin()}/getMe`);
    expectScrubbed(result, [key]);
    expect(JSON.stringify(activity)).not.toContain(key);
  });

  it('suppresses first_sighting only for an entry with the origin in known_addresses', async () => {
    const secret = 'known-address-key-2468';
    const known = entry({
      shape: 'api_key', format: 'raw', plaintext: secret, binding: apiKeyBinding,
      knownAddresses: [origin()],
    });
    const unknown = entry({
      shape: 'api_key', format: 'raw', plaintext: secret, binding: apiKeyBinding,
    });
    entries.set(known.id, known);
    entries.set(unknown.id, unknown);

    const first = await call(known.id, '/known');
    const second = await call(unknown.id, '/unknown');

    expect(wire).toHaveLength(2);
    expect(wire.map((request) => request.url)).toEqual(['/known', '/unknown']);
    for (const request of wire) expect(request.headers['x-api-key']).toBe(secret);
    expect(checks).toHaveLength(2);
    expect(checks[0]).toMatchObject({ entry_id: known.id, first_sighting: false });
    expect(checks[1]).toMatchObject({ entry_id: unknown.id, first_sighting: true });
    expect(reply(first).headers['x-api-key']).toBe('[REDACTED]');
    expect(reply(second).headers['x-api-key']).toBe('[REDACTED]');
    expectScrubbed(first, [secret]);
    expectScrubbed(second, [secret]);
  });

  it('seals locked tier-2 details and reuses the request id after approval polling', async () => {
    const secret = 'locked-tier-two-key-2468';
    const e = entry({
      shape: 'api_key', format: 'raw', plaintext: secret, binding: apiKeyBinding,
      locked: true, tier: '2',
    });
    entries.set(e.id, e);
    answerCheck = (_body, index) => {
      if (index === 0) return { allowed: false, request_id: 'r1' };
      // Even after approval, no credential may travel before the second check.
      expect(wire).toHaveLength(0);
      return { allowed: true, tier: '2' };
    };

    const result = await call(e.id, '/approval', { method: 'POST', body: { probe: true } });

    expect(checks).toHaveLength(2);
    expect(polls).toEqual(['/agent/vault/tier2-requests/r1']);
    const first = checks[0];
    expect(first).toMatchObject({
      entry_id: e.id,
      request_id: expect.stringMatching(/^[0-9a-f]{32}$/),
      detail_ciphertext: expect.any(String),
      detail_nonce: expect.any(String),
      match_mac: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    for (const check of checks) {
      for (const field of ['origin', 'method', 'path', 'purpose', 'body_sha256']) {
        expect(check).not.toHaveProperty(field);
      }
    }
    expect(checks[1]).toEqual(first);
    expect(first.match_mac).toBe(t2MatchMac(vaultKey, {
      kind: 'web', origin: origin(), method: 'POST', path: '/approval', entry_id: e.id,
    }));

    const opened = openT2Detail(
      vaultKey, agentId, String(first.request_id),
      String(first.detail_ciphertext), String(first.detail_nonce),
    );
    expect(opened).toMatchObject({ ok: true });
    const plaintext = JSON.stringify(opened);
    for (const [field, value] of Object.entries({
      name: 'Test credential',
      kind: 'web',
      origin: origin(),
      method: 'POST',
      path: '/approval',
      reason: 'Exercise the broker request path',
    })) {
      expect(plaintext).toContain(`${JSON.stringify(field)}:${JSON.stringify(value)}`);
    }

    expect(wire).toHaveLength(1);
    expect(wire[0]).toMatchObject({ method: 'POST', url: '/approval' });
    expect(wire[0].headers['x-api-key']).toBe(secret);
    expect(success(result).tier).toBe('2');
    expect(reply(result).headers['x-api-key']).toBe('[REDACTED]');
    expectScrubbed(result, [secret]);
  }, 20_000);

  it('refuses a plaintext downgrade of the key_id entry after opening its sealed setup', async () => {
    // Prime this case independently too, so it remains meaningful when run by itself.
    const e = keyIdEntry();
    entries.set(e.id, e);
    const initial = await call(e.id, '/before-downgrade');
    expect(wire).toHaveLength(1);
    expect(wire[0].headers['apca-api-key-id']).toBe('PKID123456');
    expect(wire[0].headers['apca-api-secret-key']).toBe('sek-abcdef');
    expect(reply(initial).headers['apca-api-key-id']).toBe('[REDACTED]');

    const downgraded = { ...e };
    delete downgraded.setup_ciphertext;
    delete downgraded.setup_nonce;
    downgraded.name = 'Untrusted plaintext name';
    downgraded.entry_mode = 'http';
    downgraded.exec_config = { credential_binding: apiKeyBinding };
    downgraded.allowed_private_origins = [origin()];
    entries.set(e.id, downgraded);
    wire = [];
    checks = [];
    // A fresh broker must honor the on-disk pin, not just an in-memory observation.
    broker = newBroker();

    await expect(call(e.id, '/after-downgrade')).rejects.toThrow('Sealed setup refused');

    expect(wire).toEqual([]);
    expect(checks).toEqual([]);
  });

  it('refuses a setup bound to a different value ciphertext', async () => {
    const otherValue = encrypt(vaultKey, Buffer.from('a different encrypted value', 'utf8'));
    const e = entry({
      shape: 'api_key',
      format: 'raw',
      plaintext: 'actual-value-2468',
      binding: apiKeyBinding,
      valueSha256: crypto.createHash('sha256').update(otherValue.ciphertext).digest('hex'),
    });
    entries.set(e.id, e);

    await expect(call(e.id, '/mismatch')).rejects.toThrow('Sealed setup refused');

    expect(wire).toEqual([]);
    expect(checks).toEqual([]);
  });

  it('refuses an agent header colliding with any part placement before sending anything', async () => {
    const e = keyIdEntry();
    entries.set(e.id, e);

    const result = await call(e.id, '/collision', {
      headers: { 'apca-api-key-id': 'agent-supplied-value' },
    });

    expect(result).toMatchObject({
      code: 'BAD_REQUEST',
      error: expect.stringContaining('Refused:'),
    });
    expect(wire).toEqual([]);
    expect(checks).toEqual([]);
  });
});
