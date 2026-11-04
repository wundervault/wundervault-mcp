/**
 * Drive stamped credentials through the real broker: a local vault serves encrypted
 * entries and policies, and a trusted HTTPS service records what reached the wire.
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
import { sealSetup } from '../src/setup-seal.js';
import { recipeSha256, validateRecipe, type HmacRecipe, type Recipe } from '../src/stamp.js';
import { readPolicy } from '../src/wallet.js';

type CheckBody = Record<string, unknown>;
type Verdict = { allowed: boolean; tier?: string; request_id?: string };
type Echo = {
  headers: http.IncomingHttpHeaders;
  method: string;
  url: string;
  body: string;
};
type CallResult = Awaited<ReturnType<BrokerOps['call']>>;
type RequestExtra = Partial<NonNullable<Parameters<BrokerOps['call']>[0]['request']>>;
type TestEntry = Record<string, unknown> & { id: string };
type ApprovalRequest = { path: string; body: CheckBody };

const vaultKey = crypto.randomBytes(32);
const encKey = crypto.randomBytes(32);
const apiKey = `test-${crypto.randomBytes(16).toString('hex')}`;
const agentId = crypto.randomBytes(16).toString('hex');

const stampBinding = {
  v: 2,
  placements: [{ in: 'stamp', name: '', template: '' }],
} as const;
const oauthStamp = { builtin: 'oauth1' } as const;
const oauthParts = {
  consumer_key: 'consumer-key-123',
  consumer_secret: 'consumer-secret+42&',
  token: 'token-456',
  token_secret: 'token-secret/43=',
};
const hmacRecipe: HmacRecipe = {
  mac: 'hmac-sha256',
  key: 'utf8',
  message: [{ var: 'body' }],
  encoding: 'hex',
  place: [
    { in: 'header', name: 'x-sig', value: '{stamp}' },
    { in: 'header', name: 'x-key', value: '{key_id}' },
  ],
};
const hmacBody = { message: 'stamp parts', count: 2 };

let dir = '';
let savedCAs: string[] | undefined;
let vaultServer: http.Server | undefined;
let echoServer: https.Server | undefined;
let vaultUrl = '';
let port = 0;
let broker: BrokerOps;
let entries = new Map<string, Record<string, unknown>>();
let wire: Echo[] = [];
let checks: CheckBody[] = [];
let approvalRequests: ApprovalRequest[] = [];
let denyStampApproval = false;
let unexpected: string[] = [];

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

function checkedRecipe(raw: unknown): Recipe {
  const checked = validateRecipe(raw);
  if (!checked.ok) throw new Error(`Invalid test recipe: ${checked.reason}`);
  return checked.recipe;
}

function sealedPolicy(id: string, approved: unknown[]): {
  policy_ciphertext: string;
  policy_nonce: string;
} {
  const policy = encrypt(vaultKey, Buffer.from(JSON.stringify({
    v: 1,
    entry_id: id,
    version: 1,
    kind: 'stamped',
    stamped: {
      approved: approved.map((raw) => ({
        recipe_sha256: recipeSha256(checkedRecipe(raw)),
        origin: origin(),
      })),
    },
  }), 'utf8'));
  const ciphertext = policy.ciphertext.toString('base64');
  const nonce = policy.nonce.toString('base64');
  const opened = readPolicy({
    ciphertext, nonce, vaultKey, entryId: id, kind: 'stamped',
  });
  if (!opened.ok) throw new Error(`Invalid test policy: ${opened.reason}`);
  expect(opened.policy?.stamped?.approved).toEqual(approved.map((raw) => ({
    recipe_sha256: recipeSha256(checkedRecipe(raw)),
    origin: origin(),
  })));
  return { policy_ciphertext: ciphertext, policy_nonce: nonce };
}

function entry(options: {
  shape: 'signed_set' | 'key_id';
  parts: Record<string, string>;
  approved: unknown[];
}): TestEntry {
  const id = crypto.randomBytes(16).toString('hex');
  const rev = 1;
  const value = encrypt(vaultKey, Buffer.from(JSON.stringify({ parts: options.parts }), 'utf8'));
  const setup = {
    v: 1,
    rev,
    value_sha256: crypto.createHash('sha256').update(value.ciphertext).digest('hex'),
    value_format: 'parts-1',
    name: 'Test stamped credential',
    shape: options.shape,
    service: null,
    delivery: 'http',
    binding: stampBinding,
    ssh_hosts: [],
    private_origins: [origin()],
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
    access_tier: '1',
    vault_locked: false,
    ...sealedPolicy(id, options.approved),
  };
}

function legacyEntry(): TestEntry {
  const id = crypto.randomBytes(16).toString('hex');
  const value = encrypt(vaultKey, Buffer.from('{"id":"AKID123","secret":"s3cr3t"}', 'utf8'));
  return {
    id,
    agent_id: agentId,
    rev: 1,
    name: 'Legacy stamped credential',
    // As the real server sends a pre-release entry: the mode name and a JSON string.
    entry_mode: 'BROKER_HTTP',
    exec_config: JSON.stringify({ credential_binding: { in: 'stamp' } }),
    allowed_private_origins: [origin()],
    encrypted_content: value.ciphertext.toString('base64'),
    content_nonce: value.nonce.toString('base64'),
    access_tier: '1',
    vault_locked: false,
    ...sealedPolicy(id, [hmacRecipe]),
  };
}

function call(id: string, requestPath = '/', extra: RequestExtra = {}): Promise<CallResult> {
  return broker.call({
    entryId: id,
    purpose: 'Exercise stamped credentials through the broker',
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
  expect(body).toMatchObject({
    headers: expect.any(Object),
    method: expect.any(String),
    url: expect.any(String),
    body: expect.any(String),
  });
  return body as Echo;
}

function expectNoSecrets(value: unknown, secrets: string[]): void {
  const text = JSON.stringify(value);
  for (const secret of secrets) {
    expect(text).not.toContain(secret);
    expect(text).not.toContain(encodeURIComponent(secret));
  }
}

async function refusal(id: string, requestPath: string, extra: RequestExtra = {}): Promise<string> {
  let result: CallResult;
  try {
    result = await call(id, requestPath, extra);
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    return (error as Error).message;
  }
  expect(result).toHaveProperty('error');
  expect(result).not.toHaveProperty('status', 200);
  if (!('error' in result)) throw new Error('Expected the broker to refuse the request');
  expect(result.error).not.toBe('');
  return result.error;
}

// stamp.ts's RFC 3986 encoder is not exported; copy its logic for the independent
// verifier below rather than calling the production signer to verify its own output.
function uriEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function oauthFields(header: string): Record<string, string> {
  expect(header).toMatch(/^OAuth /);
  const fields: Record<string, string> = {};
  for (const field of header.slice('OAuth '.length).split(/,\s*/)) {
    const match = /^([^=\s]+)="([^"]*)"$/.exec(field);
    if (!match) throw new Error(`Malformed OAuth header field: ${field}`);
    const name = decodeURIComponent(match[1]);
    expect(Object.prototype.hasOwnProperty.call(fields, name)).toBe(false);
    fields[name] = decodeURIComponent(match[2]);
  }
  return fields;
}

function verifyOAuth(received: Echo): void {
  const header = received.headers.authorization;
  expect(typeof header).toBe('string');
  if (typeof header !== 'string') throw new Error('Missing OAuth Authorization header');
  const fields = oauthFields(header);
  expect(fields).toMatchObject({
    oauth_consumer_key: oauthParts.consumer_key,
    oauth_token: oauthParts.token,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_version: '1.0',
  });
  expect(fields.oauth_nonce).toMatch(/^[0-9a-f]{32}$/);
  expect(fields.oauth_timestamp).toMatch(/^[0-9]+$/);
  expect(fields.oauth_signature).not.toBe('');

  expect(typeof received.headers.host).toBe('string');
  // A non-default port is part of Host (RFC 9110), and part of what OAuth signs.
  expect(received.headers.host).toBe(new URL(origin()).host);
  const url = new URL(received.url, `https://${received.headers.host}`);
  const pairs: Array<[string, string]> = [...url.searchParams.entries()];
  const contentType = String(received.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType === 'application/x-www-form-urlencoded') {
    pairs.push(...new URLSearchParams(received.body).entries());
  }
  for (const [name, value] of Object.entries(fields)) {
    if (name !== 'realm' && name !== 'oauth_signature') pairs.push([name, value]);
  }
  const encoded = pairs.map(([name, value]) => [uriEncode(name), uriEncode(value)]);
  encoded.sort((a, b) => (
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0
  ));
  const normalized = encoded.map(([name, value]) => `${name}=${value}`).join('&');
  // The address the broker was asked to call (the Host header it sends omits a non-default port).
  const baseUri = `${origin()}${url.pathname || '/'}`;
  const base = [received.method.toUpperCase(), uriEncode(baseUri), uriEncode(normalized)].join('&');
  const key = `${uriEncode(oauthParts.consumer_secret)}&${uriEncode(oauthParts.token_secret)}`;
  const expected = crypto.createHmac('sha1', key).update(base, 'utf8').digest('base64');
  expect(fields.oauth_signature).toBe(expected);
}

function expectHmacCall(result: CallResult, requestPath: string): void {
  expect(wire).toHaveLength(1);
  const received = wire[0];
  expect(received).toMatchObject({
    method: 'POST',
    url: requestPath,
    body: JSON.stringify(hmacBody),
  });
  expect(received.headers['x-key']).toBe('AKID123');
  expect(received.headers['x-sig']).toBe(
    crypto.createHmac('sha256', 's3cr3t').update(received.body, 'utf8').digest('hex'),
  );
  expect(received.headers.authorization).toBeUndefined();
  expect(reply(result)).toMatchObject({ method: 'POST', url: requestPath, body: received.body });
  expectNoSecrets(wire, ['s3cr3t']);
  expectNoSecrets(result, ['s3cr3t']);
  expect(approvalRequests).toEqual([]);
}

// Every machine path the broker writes (destination log, activity log, signing state) goes to
// this test's temp dir; the real /var/lib/wundervault is never touched.
const redirected = ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR',
  'WUNDERVAULT_NETWORK_STORE'] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeAll(async () => {
  vi.useRealTimers();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-brokerstamp-'));
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
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const received: Echo = {
        headers: { ...req.headers },
        method: req.method ?? '',
        url: req.url ?? '/',
        body: Buffer.concat(chunks).toString('utf8'),
      };
      wire.push(received);
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
          if ((body as { kind?: string }).kind === 'recipe') {
            // The owner's answer to a new way to stamp: this test owner declines.
            approvalRequests.push({ path: pathname, body });
            sendJson(res, { allowed: false, tier: '1', message: 'Stamp approval denied by test owner' });
            return;
          }
          const verdict: Verdict = { allowed: true, tier: '1' };
          sendJson(res, verdict);
        } catch {
          sendJson(res, { error: 'Invalid operation-check JSON' }, 400);
        }
      });
      return;
    }
    if (req.method === 'POST' && denyStampApproval) {
      // Observe approveStamp at its HTTP boundary, without depending on a private
      // broker method or an approval endpoint name. The test checks the payload.
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as CheckBody;
          approvalRequests.push({ path: pathname, body });
          sendJson(res, { error: 'Stamp approval denied by test owner' }, 403);
        } catch {
          sendJson(res, { error: 'Invalid approval JSON' }, 400);
        }
      });
      return;
    }
    unexpected.push(`${req.method} ${pathname}`);
    sendJson(res, { error: 'Not found' }, 404);
  });
  vaultUrl = `http://127.0.0.1:${await listen(vaultServer)}`;
}, 20_000);

beforeEach(() => {
  // Each test is a fresh machine: the downgrade pins of one test's sealed setups must not
  // refuse the next test's legacy entry (that refusal is the guard working, tested elsewhere).
  fs.rmSync(path.join(dir, 'setup-pins.json'), { force: true });
  entries = new Map();
  wire = [];
  checks = [];
  approvalRequests = [];
  denyStampApproval = false;
  unexpected = [];
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

describe('BrokerOps.call with stamped parts', () => {
  it('K-1 signs an OAuth request with signed_set parts without sending either secret', async () => {
    const e = entry({ shape: 'signed_set', parts: oauthParts, approved: [oauthStamp] });
    entries.set(e.id, e);

    const result = await call(e.id, '/oauth/resource', {
      query: { note: 'a b+c', punctuation: "!'()*" },
      stamp: oauthStamp,
    });

    expect(wire).toHaveLength(1);
    expect(wire[0].method).toBe('GET');
    const url = new URL(wire[0].url, origin());
    expect(url.pathname).toBe('/oauth/resource');
    expect(url.searchParams.get('note')).toBe('a b+c');
    expect(url.searchParams.get('punctuation')).toBe("!'()*");
    verifyOAuth(wire[0]);
    expect(reply(result)).toMatchObject({ method: 'GET', url: wire[0].url, body: '' });
    const secrets = [oauthParts.consumer_secret, oauthParts.token_secret];
    expectNoSecrets(wire, secrets);
    expectNoSecrets(result, secrets);
    expect(approvalRequests).toEqual([]);
  });

  it('K-2 signs the body with the key_id secret part and places only the id and stamp', async () => {
    const e = entry({
      shape: 'key_id',
      parts: { id: 'AKID123', secret: 's3cr3t' },
      approved: [hmacRecipe],
    });
    entries.set(e.id, e);

    const result = await call(e.id, '/hmac/parts', {
      method: 'POST',
      body: hmacBody,
      stamp: hmacRecipe,
    });

    expectHmacCall(result, '/hmac/parts');
  });

  it('K-3 preserves raw pre-release stamped values with no sealed setup on an unlocked account', async () => {
    const e = legacyEntry();
    expect(e).not.toHaveProperty('setup_ciphertext');
    expect(e).not.toHaveProperty('setup_nonce');
    expect(e).toMatchObject({
      vault_locked: false,
      exec_config: JSON.stringify({ credential_binding: { in: 'stamp' } }),
    });
    entries.set(e.id, e);

    const result = await call(e.id, '/hmac/legacy', {
      method: 'POST',
      body: hmacBody,
      stamp: hmacRecipe,
    });

    expectHmacCall(result, '/hmac/legacy');
  });

  it('K-4a refuses signed_set parts without request.stamp before contacting the service', async () => {
    const e = entry({ shape: 'signed_set', parts: oauthParts, approved: [oauthStamp] });
    entries.set(e.id, e);

    const error = await refusal(e.id, '/missing-stamp');

    expect(error).toMatch(/stamp|oauth|signed_set/i);
    expect(wire).toHaveLength(0);
    expect(approvalRequests).toEqual([]);
    expectNoSecrets(error, [oauthParts.consumer_secret, oauthParts.token_secret]);
  });

  it('K-4b asks for approval of an unapproved recipe and sends nothing when approval is denied', async () => {
    const e = entry({
      shape: 'key_id',
      parts: { id: 'AKID123', secret: 's3cr3t' },
      approved: [hmacRecipe],
    });
    entries.set(e.id, e);
    const unapproved: HmacRecipe = {
      ...hmacRecipe,
      message: [{ text: 'not-approved:' }, { var: 'body' }],
    };
    const hash = recipeSha256(checkedRecipe(unapproved));
    expect(hash).not.toBe(recipeSha256(checkedRecipe(hmacRecipe)));
    denyStampApproval = true;

    const error = await refusal(e.id, '/unapproved-stamp', {
      method: 'POST',
      body: hmacBody,
      stamp: unapproved,
    });

    expect(approvalRequests).toHaveLength(1);
    const ask = JSON.stringify(approvalRequests[0].body);
    expect(ask).toContain(e.id);
    expect(ask).toContain(hash);
    expect(ask).toContain(origin());
    expect(wire).toHaveLength(0);
    expectNoSecrets(approvalRequests, ['s3cr3t']);
    expectNoSecrets(error, ['s3cr3t']);
  }, 20_000);
});
