/**
 * Drive first-use placements through the real broker: a local vault serves encrypted
 * entries and policies, and a trusted HTTPS service records what reached the wire.
 */
import { SetupPins, sealSetup } from '../src/setup-seal.js';
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
import { canonicalJson } from '../src/opdef.js';
import { normalizeOrigin, placementSha, type SendAs } from '../src/placement.js';
import { readPolicy } from '../src/wallet.js';

type CheckBody = Record<string, unknown>;
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
type ApprovedPlacement = {
  recipe_sha256: string;
  origin: string;
  placement: SendAs;
};

const vaultKey = crypto.randomBytes(32);
const encKey = crypto.randomBytes(32);
const apiKey = `test-${crypto.randomBytes(16).toString('hex')}`;
const agentId = crypto.randomBytes(16).toString('hex');
const keyValue = `key-${crypto.randomBytes(24).toString('hex')}`;

// Header names are normalised before approval. Exercise mixed-case agent input,
// but hash and seal the lower-case spelling that the owner's page receives.
const sendAs: SendAs = { in: 'header', name: 'x-api-key', template: '{secret}' };
const requestedSendAs: SendAs = { ...sendAs, name: 'X-Api-Key' };

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
let ownerAnswer: 'approve' | 'deny' | null = null;
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

function normalizedOrigin(): string {
  const normalized = normalizeOrigin(origin());
  if (!normalized) throw new Error('Invalid test service origin');
  return normalized;
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

function approvedPlacement(placement: SendAs = sendAs): ApprovedPlacement {
  const address = normalizedOrigin();
  return {
    recipe_sha256: placementSha(address, placement),
    origin: address,
    placement,
  };
}

function sealedPolicy(id: string, approved: ApprovedPlacement[], check = true): {
  policy_ciphertext: string;
  policy_nonce: string;
} {
  const policy = encrypt(vaultKey, Buffer.from(JSON.stringify({
    v: 1,
    entry_id: id,
    version: 1,
    kind: 'stamped',
    stamped: { approved },
  }), 'utf8'));
  const ciphertext = policy.ciphertext.toString('base64');
  const nonce = policy.nonce.toString('base64');
  if (check) {
    const opened = readPolicy({
      ciphertext, nonce, vaultKey, entryId: id, kind: 'stamped',
    });
    if (!opened.ok) throw new Error(`Invalid test policy: ${opened.reason}`);
    expect(opened.policy?.stamped?.approved).toEqual(approved);
  }
  return { policy_ciphertext: ciphertext, policy_nonce: nonce };
}

function entry(options: {
  ask?: boolean;
  execAsk?: boolean;
  approved?: ApprovedPlacement[];
  uncheckedPolicy?: boolean;
} = {}): TestEntry {
  const id = crypto.randomBytes(16).toString('hex');
  const rev = 1;
  const value = encrypt(vaultKey, Buffer.from(keyValue, 'utf8'));
  const setup = {
    v: 1,
    rev,
    value_sha256: crypto.createHash('sha256').update(value.ciphertext).digest('hex'),
    value_format: 'raw',
    name: 'Test API key',
    shape: 'api_key',
    service: null,
    delivery: 'http',
    binding: options.ask === false ? null : { ask: true },
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
    name: setup.name,
    entry_mode: 'BROKER_HTTP',
    exec_config: JSON.stringify(options.execAsk ? { credential_binding: { ask: true } } : {}),
    allowed_private_origins: [origin()],
    encrypted_content: value.ciphertext.toString('base64'),
    content_nonce: value.nonce.toString('base64'),
    setup_ciphertext: sealed.ciphertext,
    setup_nonce: sealed.nonce,
    access_tier: '1',
    vault_locked: false,
    ...(options.approved === undefined
      ? {}
      : sealedPolicy(id, options.approved, !options.uncheckedPolicy)),
  };
}

function call(id: string, requestPath = '/', extra: RequestExtra = {}): Promise<CallResult> {
  return broker.call({
    entryId: id,
    purpose: 'Exercise first-use placements through the broker',
    request: {
      origin: { scheme: 'https', host: '127.0.0.1', port },
      method: 'GET',
      path: requestPath,
      ...extra,
    },
  });
}

function expectNoSecret(value: unknown): void {
  const text = JSON.stringify(value);
  expect(text).not.toContain(keyValue);
  expect(text).not.toContain(encodeURIComponent(keyValue));
}

function success(result: CallResult): void {
  expect(result).toMatchObject({ status: 200 });
  if ('error' in result) throw new Error(result.error);
  expectNoSecret(result);
}

async function refusal(
  id: string,
  requestPath: string,
  extra: RequestExtra = {},
  code?: string,
): Promise<string> {
  let result: CallResult;
  try {
    result = await call(id, requestPath, extra);
  } catch (error) {
    // A denied approval may surface as the approval endpoint's HTTP error. Codes
    // from the broker itself must still be returned and checked, not thrown.
    if (code !== undefined) throw error;
    expect(error).toBeInstanceOf(Error);
    const message = (error as Error).message;
    expectNoSecret(message);
    return message;
  }
  expect(result).toHaveProperty('error');
  expect(result).not.toHaveProperty('status', 200);
  if (!('error' in result)) throw new Error('Expected the broker to refuse the request');
  expect(result.error).not.toBe('');
  if (code !== undefined) expect(result.code).toBe(code);
  expectNoSecret(result);
  return result.error;
}

function expectPlacementApproval(id: string, placement: SendAs): void {
  expect(approvalRequests).toHaveLength(1);
  const body = approvalRequests[0].body;
  const address = normalizedOrigin();
  expect(body).toMatchObject({
    kind: 'recipe',
    detail: {
      recipe: { type: 'placement', v: 1, origin: address, send_as: placement },
    },
  });
  const recipe = (body.detail as { recipe: unknown }).recipe;
  expect(recipe).toEqual({
    type: 'placement', v: 1, origin: address, send_as: placement,
  });
  const hash = crypto.createHash('sha256').update(canonicalJson(recipe)).digest('hex');
  expect(hash).toBe(placementSha(address, placement));
  expect(JSON.stringify(body)).toContain(id);
  expect(JSON.stringify(body)).toContain(hash);
  expectNoSecret(approvalRequests);
}

function answerApproval(
  pathname: string,
  body: CheckBody,
  res: http.ServerResponse,
  operationCheck: boolean,
): void {
  approvalRequests.push({ path: pathname, body });
  if (ownerAnswer === null) unexpected.push(`Unexpected approval POST ${pathname}`);
  if (ownerAnswer === 'approve') {
    sendJson(res, { allowed: true, tier: '1' });
  } else if (operationCheck) {
    sendJson(res, {
      allowed: false, tier: '1', message: 'Placement approval denied by test owner',
    });
  } else {
    sendJson(res, { error: 'Placement approval denied by test owner' }, 403);
  }
}

// Every machine path the broker writes goes to this test's temp dir; the real
// /var/lib/wundervault is never touched.
const redirected = ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR',
  'WUNDERVAULT_NETWORK_STORE'] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeAll(async () => {
  vi.useRealTimers();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-brokerplacement-'));
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
          if (body.kind === 'recipe') {
            answerApproval(pathname, body, res, true);
            return;
          }
          sendJson(res, { allowed: true, tier: '1' });
        } catch {
          sendJson(res, { error: 'Invalid operation-check JSON' }, 400);
        }
      });
      return;
    }
    if (req.method === 'POST' && ownerAnswer !== null) {
      // Observe approveStamp at its HTTP boundary without depending on a private
      // broker method or an approval endpoint name, as in the stamped-parts harness.
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as CheckBody;
          answerApproval(pathname, body, res, false);
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
  // Each test is a fresh machine, including its sealed-setup downgrade pins.
  fs.rmSync(path.join(dir, 'setup-pins.json'), { force: true });
  SetupPins.resetSharedForTests();
  entries = new Map();
  wire = [];
  checks = [];
  approvalRequests = [];
  ownerAnswer = null;
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

describe.each([
  { label: 'without exec_config.credential_binding', execAsk: false },
  { label: 'with exec_config.credential_binding {ask:true}', execAsk: true },
])('BrokerOps.call with an ask placement $label', ({ execAsk }) => {
  it('refuses a missing send_as without a policy, without asking or sending', async () => {
    const e = entry({ execAsk });
    entries.set(e.id, e);

    const error = await refusal(e.id, '/missing-placement', {}, 'NEEDS_PLACEMENT');

    expect(error).toContain('request.send_as');
    expect(wire).toEqual([]);
    expect(checks).toEqual([]);
    expect(approvalRequests).toEqual([]);
  });

  it('asks the owner for the exact placement recipe and sends only the approved header', async () => {
    const e = entry({ execAsk });
    entries.set(e.id, e);
    // 1. The first proposal asks the owner with exactly the hashed object; nothing is sent
    //    until the owner's sealed approval exists (a server "allowed" alone is refused).
    ownerAnswer = 'deny';
    await refusal(e.id, '/approved-header', { send_as: requestedSendAs });
    expectPlacementApproval(e.id, sendAs);
    expect(wire).toHaveLength(0);
    // 2. The owner approves: the page adds the item to the sealed approved list.
    //    (A fresh entry carrying the approved list stands in for the same key after approval.)
    const approvedEntry = entry({ execAsk, approved: [approvedPlacement()] });
    entries.set(approvedEntry.id, approvedEntry);
    approvalRequests.length = 0;
    const result = await call(approvedEntry.id, '/approved-header', { send_as: requestedSendAs });

    success(result);
    expect(approvalRequests).toEqual([]);
    expect(wire).toHaveLength(1);
    expect(wire[0]).toMatchObject({ method: 'GET', url: '/approved-header', body: '' });
    expect(wire[0].headers['x-api-key']).toBe(keyValue);
    expect(wire[0].headers.authorization).toBeUndefined();
  }, 20_000);

  it('uses a sealed approved placement without send_as or another approval', async () => {
    const e = entry({ execAsk, approved: [approvedPlacement()] });
    entries.set(e.id, e);

    const result = await call(e.id, '/stored-placement');

    success(result);
    expect(wire).toHaveLength(1);
    expect(wire[0]).toMatchObject({ method: 'GET', url: '/stored-placement', body: '' });
    expect(wire[0].headers['x-api-key']).toBe(keyValue);
    expect(wire[0].headers.authorization).toBeUndefined();
    expect(approvalRequests).toEqual([]);
  });

  it.each([
    { label: 'query api_key', proposal: { in: 'query', name: 'api_key', template: '{secret}' } },
    { label: 'header X-Other', proposal: { in: 'header', name: 'X-Other', template: '{secret}' } },
  ] as const)('asks again for $label and sends nothing when denied', async ({ proposal }) => {
    const e = entry({ execAsk, approved: [approvedPlacement()] });
    entries.set(e.id, e);
    ownerAnswer = 'deny';

    const error = await refusal(e.id, '/different-placement', { send_as: proposal });

    expect(error).toMatch(/approv|denied|refus/i);
    const normalized: SendAs = {
      ...proposal,
      name: proposal.in === 'header' ? proposal.name.toLowerCase() : proposal.name,
    };
    expect(placementSha(normalizedOrigin(), normalized)).not.toBe(
      placementSha(normalizedOrigin(), sendAs),
    );
    expectPlacementApproval(e.id, normalized);
    expect(wire).toEqual([]);
  }, 20_000);

  it.each([
    { label: 'Host header', proposal: { in: 'header', name: 'Host', template: '{secret}' } },
    { label: 'Cookie header', proposal: { in: 'header', name: 'Cookie', template: '{secret}' } },
    {
      label: 'CR/LF in the template',
      proposal: { in: 'header', name: 'X-Api-Key', template: '{secret}\r\nX-Injected: yes' },
    },
  ])('refuses $label before asking or sending', async ({ proposal }) => {
    const e = entry({ execAsk });
    entries.set(e.id, e);

    await refusal(e.id, '/invalid-placement', { send_as: proposal }, 'BAD_REQUEST');

    expect(wire).toEqual([]);
    expect(checks).toEqual([]);
    expect(approvalRequests).toEqual([]);
  });

  it('refuses a sealed placement whose recipe hash describes a different placement', async () => {
    const other: SendAs = { in: 'header', name: 'x-other', template: '{secret}' };
    const mismatched = {
      ...approvedPlacement(),
      recipe_sha256: placementSha(normalizedOrigin(), other),
    };
    // Seal authentic owner data with an internally inconsistent hash. Do not let
    // the fixture's normal policy validation reject it before the broker sees it.
    const e = entry({ execAsk, approved: [mismatched], uncheckedPolicy: true });
    entries.set(e.id, e);

    await refusal(e.id, '/bad-policy', {}, 'BAD_POLICY');

    expect(wire).toEqual([]);
    expect(checks).toEqual([]);
    expect(approvalRequests).toEqual([]);
  });
});

describe('BrokerOps.call with an ordinary null binding', () => {
  it('refuses agent-supplied send_as rather than overriding the ordinary binding', async () => {
    const e = entry({ ask: false });
    entries.set(e.id, e);

    await refusal(e.id, '/ordinary-override', { send_as: requestedSendAs }, 'BAD_REQUEST');

    expect(wire).toEqual([]);
    expect(checks).toEqual([]);
    expect(approvalRequests).toEqual([]);
  });

  it('preserves the implicit Authorization Bearer placement without send_as', async () => {
    const e = entry({ ask: false });
    entries.set(e.id, e);

    const result = await call(e.id, '/ordinary-bearer');

    success(result);
    expect(wire).toHaveLength(1);
    expect(wire[0]).toMatchObject({ method: 'GET', url: '/ordinary-bearer', body: '' });
    expect(wire[0].headers.authorization).toBe(`Bearer ${keyValue}`);
    expect(wire[0].headers['x-api-key']).toBeUndefined();
    expect(approvalRequests).toEqual([]);
  });
});
