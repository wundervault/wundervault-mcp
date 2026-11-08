/**
 * Drive Batch B approvals through the real broker: metadata before approval,
 * a grant-bound value fetch afterwards, and credentials only on the HTTPS wire.
 */
import { SetupPins } from '../src/setup-seal.js';
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
import { AgentVaultAPI } from '../src/api-client.js';
import { BrokerOps } from '../src/broker-ops.js';
import { sealSetup, openT2Detail, t2MatchMac, t2OriginMac } from '../src/setup-seal.js';

type CheckBody = Record<string, unknown>;
type Verdict = {
  allowed: boolean;
  tier?: string;
  request_id?: string;
  fetch_grant?: string;
};
type Echo = { headers: http.IncomingHttpHeaders; url: string; method: string };
type Event = {
  kind: 'meta' | 'value' | 'check' | 'poll' | 'done';
  url: string;
  headers: http.IncomingHttpHeaders;
  allowed?: boolean;
  body?: CheckBody;
};
type CallResult = Awaited<ReturnType<BrokerOps['call']>>;

const vaultKey = crypto.randomBytes(32);
const encKey = crypto.randomBytes(32);
const apiKey = `test-${crypto.randomBytes(16).toString('hex')}`;
const agentId = crypto.randomBytes(16).toString('hex');

let dir = '';
let savedCAs: string[] | undefined;
let vaultServer: http.Server | undefined;
let echoServer: https.Server | undefined;
let vaultUrl = '';
let port = 0;
let broker: BrokerOps;
let entries = new Map<string, Record<string, unknown>>();
let valueEntries = new Map<string, Record<string, unknown>>();
let wire: Echo[] = [];
let checks: CheckBody[] = [];
let events: Event[] = [];
let unexpected: string[] = [];
let pollStatus: 'approved' | 'denied';
let answerCheck: (body: CheckBody, index: number) => Verdict;
let doneReply: { ended: number; setting: 'end' | 'keep' };

function encrypt(key: Buffer, plaintext: Buffer): { nonce: Buffer; ciphertext: Buffer } {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { nonce, ciphertext };
}

function origin(): string {
  return `https://127.0.0.1:${port}`;
}

function otherPort(): number {
  return port === 65535 ? port - 1 : port + 1;
}

function otherOrigin(): string {
  return `https://127.0.0.1:${otherPort()}`;
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
  rev?: number;
  locked?: boolean;
} = {}): Record<string, unknown> & { id: string } {
  const id = options.id ?? crypto.randomBytes(16).toString('hex');
  const rev = options.rev ?? 1;
  const value = encrypt(vaultKey, Buffer.from('batch-b-test-credential', 'utf8'));
  const setup = {
    v: 1,
    rev,
    value_sha256: crypto.createHash('sha256').update(value.ciphertext).digest('hex'),
    value_format: 'raw',
    name: 'Test credential',
    shape: 'api_key',
    service: null,
    delivery: 'http',
    binding: { v: 1, in: 'header', name: 'x-api-key', template: '{secret}' },
    ssh_hosts: [],
    private_origins: [origin(), otherOrigin()],
    known_addresses: [],
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
    access_tier: '2',
    vault_locked: options.locked ?? false,
  };
}

function call(
  id: string,
  requestPath = '/approval',
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

function success(result: CallResult): void {
  expect(result).toMatchObject({ status: 200, tier: '2' });
  if ('error' in result) throw new Error(result.error);
}

// Keep every broker-written machine path inside this test's temporary directory.
const redirected = ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR',
  'WUNDERVAULT_NETWORK_STORE'] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeAll(async () => {
  vi.useRealTimers();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-batch-b-approve-'));
  for (const name of redirected) savedEnv[name] = process.env[name];
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'system');
  process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'user');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  process.env.WUNDERVAULT_NETWORK_STORE = path.join(dir, 'system', 'network.json');
  for (const sub of ['system', 'user', 'run']) {
    fs.mkdirSync(path.join(dir, sub), { recursive: true, mode: 0o700 });
  }
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  const cert = fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8');
  savedCAs = tls.getCACertificates('default');
  tls.setDefaultCACertificates([...savedCAs, cert]);

  echoServer = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert }, (req, res) => {
    req.resume();
    req.on('end', () => {
      const received = { headers: { ...req.headers }, url: req.url ?? '/', method: req.method ?? '' };
      wire.push(received);
      sendJson(res, received);
    });
  });
  port = await listen(echoServer);

  const wrappedKey = encrypt(encKey, vaultKey);
  const vaultKeyForAgent = Buffer.concat([wrappedKey.nonce, wrappedKey.ciphertext]).toString('base64');
  vaultServer = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const pathname = url.pathname;
    if (req.method === 'GET' && pathname === '/agent/profile') {
      sendJson(res, { vault_key_for_agent: vaultKeyForAgent });
      return;
    }
    if (req.method === 'GET' && pathname === '/agent/vault/secrets') {
      sendJson(res, { entries: [] });
      return;
    }
    if (req.method === 'GET' && pathname.startsWith('/agent/vault/secrets/')) {
      const id = pathname.slice('/agent/vault/secrets/'.length);
      const meta = url.searchParams.get('meta') === '1';
      events.push({
        kind: meta ? 'meta' : 'value',
        url: req.url ?? '',
        headers: { ...req.headers },
      });
      const found = meta ? entries.get(id) : valueEntries.get(id) ?? entries.get(id);
      if (found) {
        const response = { ...found };
        if (meta) {
          delete response.encrypted_content;
          delete response.content_nonce;
        }
        sendJson(res, response);
        return;
      }
    }
    if (req.method === 'POST'
      && (pathname === '/agent/vault/operation-check' || pathname === '/agent/vault/done')) {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as CheckBody;
          if (pathname === '/agent/vault/done') {
            events.push({ kind: 'done', url: req.url ?? '', headers: { ...req.headers }, body });
            sendJson(res, doneReply);
            return;
          }
          checks.push(body);
          const verdict = answerCheck(body, checks.length - 1);
          events.push({
            kind: 'check',
            url: req.url ?? '',
            headers: { ...req.headers },
            body,
            allowed: verdict.allowed,
          });
          sendJson(res, verdict);
        } catch {
          sendJson(res, { error: 'Invalid JSON' }, 400);
        }
      });
      return;
    }
    if (req.method === 'GET' && pathname === '/agent/vault/tier2-requests/r1') {
      events.push({ kind: 'poll', url: req.url ?? '', headers: { ...req.headers } });
      sendJson(res, { status: pollStatus });
      return;
    }
    unexpected.push(`${req.method} ${pathname}`);
    sendJson(res, { error: 'Not found' }, 404);
  });
  vaultUrl = `http://127.0.0.1:${await listen(vaultServer)}`;
}, 20_000);

beforeEach(() => {
  fs.rmSync(path.join(dir, 'setup-pins.json'), { force: true });
  SetupPins.resetSharedForTests();
  entries = new Map();
  valueEntries = new Map();
  wire = [];
  checks = [];
  events = [];
  unexpected = [];
  pollStatus = 'approved';
  answerCheck = () => ({ allowed: true, tier: '2', fetch_grant: 'GRANT123' });
  doneReply = { ended: 3, setting: 'end' };
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

describe('Batch B approve', () => {
  it('reads metadata first and fetches the value only after the call check is allowed', async () => {
    const e = entry();
    entries.set(e.id, e);
    answerCheck = (_body, index) => index === 0
      ? { allowed: false, tier: '2', request_id: 'r1' }
      : { allowed: true, tier: '2', fetch_grant: 'GRANT123' };

    const result = await call(e.id);

    success(result);
    expect(events.map((event) => event.kind)).toEqual(['meta', 'check', 'poll', 'check', 'value']);
    expect(events[0].url).toBe(`/agent/vault/secrets/${e.id}?purpose=&meta=1`);
    expect(events[1].allowed).toBe(false);
    expect(events[3].allowed).toBe(true);
    expect(events[4].url).toBe(`/agent/vault/secrets/${e.id}?purpose=`);
    expect(checks).toHaveLength(2);
    expect(checks[0]).toMatchObject({
      entry_id: e.id, origin: origin(), method: 'GET', path: '/approval',
    });
    expect(wire).toHaveLength(1);
    expect(wire[0].headers['x-api-key']).toBe('batch-b-test-credential');
  }, 20_000);

  it('never fetches the value or sends credentials when the owner denies the call', async () => {
    const e = entry();
    entries.set(e.id, e);
    pollStatus = 'denied';
    answerCheck = () => ({ allowed: false, tier: '2', request_id: 'r1' });

    const result = await call(e.id);

    expect(result).toMatchObject({ error: expect.stringContaining('declined') });
    expect(events.map((event) => event.kind)).toEqual(['meta', 'check', 'poll']);
    expect(events.filter((event) => event.kind === 'meta' || event.kind === 'value')).toEqual([
      expect.objectContaining({
        kind: 'meta',
        url: `/agent/vault/secrets/${e.id}?purpose=&meta=1`,
      }),
    ]);
    expect(checks).toHaveLength(1);
    expect(wire).toEqual([]);
  }, 20_000);

  it('requests a fetch grant and carries it on the subsequent value GET', async () => {
    const e = entry();
    entries.set(e.id, e);

    const result = await call(e.id);

    success(result);
    expect(events.map((event) => event.kind)).toEqual(['meta', 'check', 'value']);
    expect(events[1].allowed).toBe(true);
    expect(events[1].headers['x-wv-want-fetch-grant']).toBe('1');
    expect(events[2].headers['x-wv-fetch-grant']).toBe('GRANT123');
    expect(events[0].headers['x-wv-fetch-grant']).toBeUndefined();
    expect(wire).toHaveLength(1);
  });

  it('refuses a newly sealed revision returned after approval instead of sending it', async () => {
    const e = entry({ rev: 7 });
    const changed = entry({ id: e.id, rev: 8 });
    entries.set(e.id, e);
    valueEntries.set(e.id, changed);
    answerCheck = (_body, index) => index === 0
      ? { allowed: false, tier: '2', request_id: 'r1' }
      : { allowed: true, tier: '2', fetch_grant: 'GRANT123' };

    const result = await call(e.id);

    expect(result).toMatchObject({ code: 'CHANGED', error: expect.any(String) });
    expect(events.map((event) => event.kind)).toEqual(['meta', 'check', 'poll', 'check', 'value']);
    expect(events[4].headers['x-wv-fetch-grant']).toBe('GRANT123');
    expect(wire).toEqual([]);
  }, 20_000);

  it('binds locked web checks to both the exact call and the key plus origin', async () => {
    const e = entry({ locked: true });
    entries.set(e.id, e);

    const result = await call(e.id, '/locked', { method: 'POST', body: { probe: true } });

    success(result);
    expect(checks).toHaveLength(1);
    const first = checks[0];
    expect(first).toMatchObject({
      entry_id: e.id,
      request_id: expect.stringMatching(/^[0-9a-f]{32}$/),
      detail_ciphertext: expect.any(String),
      detail_nonce: expect.any(String),
      match_mac: t2MatchMac(vaultKey, {
        kind: 'web', origin: origin(), method: 'POST', path: '/locked', entry_id: e.id,
      }),
      origin_mac: t2OriginMac(vaultKey, { origin: origin(), entry_id: e.id }),
    });
    const opened = openT2Detail(
      vaultKey, agentId, String(first.request_id),
      String(first.detail_ciphertext), String(first.detail_nonce),
    );
    expect(opened).toMatchObject({ ok: true });
    expect(JSON.stringify(opened)).toContain(`"origin":${JSON.stringify(origin())}`);

    // The other destination is approved for private-network preflight, but the
    // owner declines it, so no connection to that port is attempted.
    pollStatus = 'denied';
    answerCheck = () => ({ allowed: false, tier: '2', request_id: 'r1' });
    const denied = await call(e.id, '/locked', {
      origin: { scheme: 'https', host: '127.0.0.1', port: otherPort() },
      method: 'POST',
      body: { probe: true },
    });

    expect(denied).toMatchObject({ error: expect.stringContaining('declined') });
    expect(checks).toHaveLength(2);
    expect(checks[1].origin_mac).toBe(t2OriginMac(vaultKey, {
      origin: otherOrigin(), entry_id: e.id,
    }));
    expect(checks[1].origin_mac).not.toBe(first.origin_mac);
    expect(checks[1].match_mac).toBe(t2MatchMac(vaultKey, {
      kind: 'web', origin: otherOrigin(), method: 'POST', path: '/locked', entry_id: e.id,
    }));
    for (const check of checks) {
      for (const field of ['origin', 'method', 'path', 'purpose', 'body_sha256']) {
        expect(check).not.toHaveProperty(field);
      }
    }
    expect(wire).toHaveLength(1);
    expect(wire[0]).toMatchObject({ method: 'POST', url: '/locked' });
  }, 20_000);

  it.each([
    { ended: 3, setting: 'end' as const },
    { ended: 0, setting: 'keep' as const },
  ])('agentDone posts an empty body and returns $setting results', async (response) => {
    doneReply = response;
    const api = new AgentVaultAPI(apiKey, encKey, vaultUrl);

    const result = await api.agentDone();

    expect(result).toEqual(response);
    expect(events).toEqual([
      expect.objectContaining({
        kind: 'done',
        url: '/agent/vault/done',
        body: {},
      }),
    ]);
    expect(events[0].headers.authorization).toBe(`Bearer ${apiKey}`);
    expect(events[0].headers['content-type']).toBe('application/json');
    expect(wire).toEqual([]);
    expect(checks).toEqual([]);
  });
});
