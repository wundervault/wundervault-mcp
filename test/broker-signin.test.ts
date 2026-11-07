/**
 * Drive sign-ins through the real broker: a local vault serves encrypted entries
 * and sealed approvals, and an HTTPS router records what reached the wire.
 */
import { SetupPins, sealSetup } from '../src/setup-seal.js';
import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from 'vitest';
import crypto from 'node:crypto';
import dns from 'node:dns';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { canonicalJson } from '../src/opdef.js';
import { BrokerOps } from '../src/broker-ops.js';
import type { ActivityRecord } from '../src/activity-log.js';
import { signInRecipeSha, validateSignInRecipe, type SignInRecipe } from '../src/signin.js';
import { readPolicy } from '../src/wallet.js';

type CheckBody = Record<string, unknown>;
type Verdict = { allowed: boolean; tier?: string; request_id?: string };
type WireRequest = {
  headers: http.IncomingHttpHeaders;
  method: string;
  url: string;
  body: string;
};
type CallResult = Awaited<ReturnType<BrokerOps['call']>>;
type RequestExtra = Partial<NonNullable<Parameters<BrokerOps['call']>[0]['request']>>;
type TestEntry = Record<string, unknown> & { id: string };
type ApprovalRequest = { path: string; body: CheckBody };
type Certificate = { key: Buffer; cert: string; sha256: string };
type Approval = { recipe: SignInRecipe; origin: string; hashOrigin?: string };

const vaultKey = crypto.randomBytes(32);
const encKey = crypto.randomBytes(32);
const apiKey = `test-${crypto.randomBytes(16).toString('hex')}`;
const agentId = crypto.randomBytes(16).toString('hex');

const recipe: SignInRecipe = {
  login: {
    method: 'POST',
    path: '/login',
    body_format: 'json',
    body: {
      jsonrpc: '2.0',
      method: 'login',
      params: { user: '{{username}}', password: '{{password}}' },
    },
  },
  session_from: { cookie: 'sid' },
  send_session_as: { cookie: 'sid' },
  signed_out_when: [401, 403],
};

let dir = '';
let savedCAs: string[] | undefined;
let trustedCertificate: Certificate;
let pinnedCertificate: Certificate;
let replacementCertificate: Certificate;
let vaultServer: http.Server | undefined;
let routerServer: https.Server | undefined;
let vaultUrl = '';
let port = 0;
let broker: BrokerOps;
let entries = new Map<string, Record<string, unknown>>();
let wire: WireRequest[] = [];
let holdSignedOut = 0;
let echoHistory = false;
let heldSignedOut: http.ServerResponse[] = [];
let checks: CheckBody[] = [];
let approvalRequests: ApprovalRequest[] = [];
let denyRecipeApproval = false;
let unexpected: string[] = [];
let activities: ActivityRecord[] = [];
let password = '';
let passwords: string[] = [];
let currentSession: string | null = null;
let issuedSessions: string[] = [];
let logins = 0;
let redirectLogin = false;

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
  const ops = new BrokerOps('Test', apiKey, encKey.toString('base64url'), vaultUrl, null, undefined, {}, {
    pinsPath: path.join(dir, 'setup-pins.json'),
  });
  ops.activity = { record: (record) => activities.push(record) };
  return ops;
}

function sendJson(res: http.ServerResponse, body: unknown, status = 200): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function listen(server: http.Server | https.Server, requestedPort = 0): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(requestedPort, '127.0.0.1', () => {
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

function makeCertificate(name: string): Certificate {
  const keyPath = path.join(dir, `${name}-key.pem`);
  const certPath = path.join(dir, `${name}-cert.pem`);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', keyPath, '-out', certPath, '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  const cert = fs.readFileSync(certPath, 'utf8');
  return {
    key: fs.readFileSync(keyPath),
    cert,
    sha256: crypto.createHash('sha256').update(new crypto.X509Certificate(cert).raw).digest('hex'),
  };
}

function unicodeEscaped(value: string): string {
  return Array.from(value, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
}

// Construct actual JSON escape sequences on the wire, rather than JSON strings
// containing an extra layer of backslashes. The verifier below is independent of
// signin.ts's secretFormsFor.
function hostileBody(session: string, login: boolean): string {
  const body = JSON.stringify({
    ok: true,
    echo_session: session,
    echo_pw: password,
    url_session: encodeURIComponent(session),
    url_pw: encodeURIComponent(password),
    base64_session: Buffer.from(session, 'utf8').toString('base64'),
    base64_pw: Buffer.from(password, 'utf8').toString('base64'),
    base64url_session: Buffer.from(session, 'utf8').toString('base64url'),
    base64url_pw: Buffer.from(password, 'utf8').toString('base64url'),
    ...(login ? { login_response_only: 'must-not-reach-agent' } : {}),
  });
  return `${body.slice(0, -1)}`
    + `,"escaped":${JSON.stringify(session).replace(/\//g, '\\/')}`
    + `,"escaped_pw":${JSON.stringify(password).replace(/\//g, '\\/')}`
    + `,"unicode_session":"${unicodeEscaped(session)}"`
    + `,"unicode_pw":"${unicodeEscaped(password)}"}`;
}

async function startRouter(certificate: Certificate, requestedPort = 0): Promise<void> {
  routerServer = https.createServer({ key: certificate.key, cert: certificate.cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const received: WireRequest = {
        headers: { ...req.headers },
        method: req.method ?? '',
        url: req.url ?? '/',
        body: Buffer.concat(chunks).toString('utf8'),
      };
      wire.push(received);

      if (received.method === 'POST' && received.url === '/login') {
        logins++;
        if (redirectLogin) {
          res.setHeader('Location', 'https://evil.example/');
          sendJson(res, { error: 'This router has moved' }, 307);
          return;
        }

        let body: {
          jsonrpc?: unknown;
          method?: unknown;
          params?: { user?: unknown; password?: unknown };
        };
        try {
          body = JSON.parse(received.body) as typeof body;
        } catch {
          sendJson(res, { error: 'Invalid login JSON' }, 400);
          return;
        }
        if (body?.jsonrpc !== '2.0' || body.method !== 'login'
          || body.params?.user !== 'admin' || body.params.password !== password) {
          sendJson(res, { error: 'Invalid credentials' }, 401);
          return;
        }

        const session = `router/${crypto.randomBytes(16).toString('hex')}+${crypto.randomBytes(8).toString('hex')}=`;
        // Keep simultaneous first calls overlapping long enough to exercise the
        // broker's single-flight login, not just reuse of an already completed login.
        setTimeout(() => {
          currentSession = session;
          issuedSessions.push(session);
          res.writeHead(200, {
            'content-type': 'application/json',
            'set-cookie': `sid=${session}; Path=/`,
            'x-echo': session,
          });
          res.end(hostileBody(session, true));
        }, 20);
        return;
      }

      if (received.method === 'POST' && received.url === '/reboot') {
        if (!currentSession || received.headers.cookie !== `sid=${currentSession}`) {
          sendJson(res, { error: 'Signed out' }, 401);
          return;
        }
        sendJson(res, { ok: true });
        return;
      }

      if (received.method === 'GET' && received.url === '/status') {
        if (!currentSession || received.headers.cookie !== `sid=${currentSession}`) {
          if (holdSignedOut > 0) {
            // Release every "signed out" together, so the callers race to refresh.
            heldSignedOut.push(res);
            if (heldSignedOut.length >= holdSignedOut) {
              holdSignedOut = 0;
              for (const held of heldSignedOut.splice(0)) sendJson(held, { error: 'Signed out' }, 401);
            }
            return;
          }
          sendJson(res, { error: 'Signed out' }, 401);
          return;
        }
        res.writeHead(200, {
          'content-type': 'application/json',
          'set-cookie': `sid=${currentSession}; Path=/`,
          'x-echo': currentSession,
          'x-echo-password': password,
        });
        if (echoHistory) {
          // A diagnostics reply that lists every session ever issued, old ones included.
          res.end(JSON.stringify({ ok: true, history: issuedSessions }));
          return;
        }
        res.end(hostileBody(currentSession, false));
        return;
      }

      unexpected.push(`router: ${received.method} ${received.url}`);
      sendJson(res, { error: 'Not found' }, 404);
    });
  });
  port = await listen(routerServer, requestedPort);
}

function checkedRecipe(raw: SignInRecipe): SignInRecipe {
  const checked = validateSignInRecipe(raw);
  if (!checked.ok) throw new Error(`Invalid test recipe: ${checked.reason}`);
  return checked.recipe;
}

function sealedPolicy(id: string, approved: Approval[], version = 1): {
  policy_ciphertext: string;
  policy_nonce: string;
} {
  const list = approved.map((approval) => ({
    recipe_sha256: signInRecipeSha(checkedRecipe(approval.recipe), approval.hashOrigin ?? approval.origin),
    origin: approval.origin,
  }));
  const policy = encrypt(vaultKey, Buffer.from(JSON.stringify({
    v: 1,
    entry_id: id,
    version,
    kind: 'stamped',
    stamped: { approved: list },
  }), 'utf8'));
  const ciphertext = policy.ciphertext.toString('base64');
  const nonce = policy.nonce.toString('base64');
  const opened = readPolicy({
    ciphertext, nonce, vaultKey, entryId: id, kind: 'stamped',
  });
  if (!opened.ok) throw new Error(`Invalid test policy: ${opened.reason}`);
  expect(opened.policy?.stamped?.approved).toEqual(list);
  return { policy_ciphertext: ciphertext, policy_nonce: nonce };
}

function entry(options: {
  id?: string;
  rev?: number;
  shape?: 'password' | 'website_login' | 'api_key' | 'two_factor';
  parts?: Record<string, string>;
  approved?: Approval[];
} = {}): TestEntry {
  const id = options.id ?? crypto.randomBytes(16).toString('hex');
  const rev = options.rev ?? 1;
  const shape = options.shape ?? 'password';
  const binding = shape === 'api_key'
    ? { in: 'header', name: 'Authorization', template: 'Bearer {secret}' }
    : null;
  const value = encrypt(vaultKey, Buffer.from(JSON.stringify({
    parts: options.parts ?? { username: 'admin', password },
  }), 'utf8'));
  const setup = {
    v: 1,
    rev,
    value_sha256: crypto.createHash('sha256').update(value.ciphertext).digest('hex'),
    value_format: 'parts-1',
    name: 'Test router sign-in',
    shape,
    service: null,
    delivery: 'http',
    binding,
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
    entry_mode: 'BROKER_HTTP',
    delivery: 'http',
    allowed_private_origins: [origin()],
    encrypted_content: value.ciphertext.toString('base64'),
    content_nonce: value.nonce.toString('base64'),
    setup_ciphertext: sealed.ciphertext,
    setup_nonce: sealed.nonce,
    access_tier: '1',
    vault_locked: false,
    ...sealedPolicy(id, options.approved ?? [{ recipe, origin: origin() }]),
  };
}

function call(id: string, extra: RequestExtra = {}): Promise<CallResult> {
  return broker.call({
    entryId: id,
    purpose: 'Check the router status without receiving its password or session',
    request: {
      origin: { scheme: 'https', host: '127.0.0.1', port },
      method: 'GET',
      path: '/status',
      sign_in: recipe,
      ...extra,
    },
  });
}

function expectNoSecrets(value: unknown, secrets: string[]): void {
  const text = JSON.stringify(value);
  for (const secret of secrets) {
    const escaped = JSON.stringify(secret).slice(1, -1);
    const encoded = encodeURIComponent(secret);
    const forms = new Set([
      secret,
      escaped,
      escaped.replace(/\//g, '\\/'),
      unicodeEscaped(secret),
      encoded,
      encoded.replace(/%[0-9A-F]{2}/g, (match) => match.toLowerCase()),
      Buffer.from(secret, 'utf8').toString('base64'),
      Buffer.from(secret, 'utf8').toString('base64url'),
    ]);
    for (const form of forms) {
      expect(text).not.toContain(form);
      expect(text).not.toContain(JSON.stringify(form).slice(1, -1));
    }
  }
}

function success(result: CallResult): void {
  expect(result).toMatchObject({ status: 200 });
  if ('error' in result) throw new Error(result.error);
  const body: unknown = typeof result.body === 'string' ? JSON.parse(result.body) : result.body;
  expect(body).toMatchObject({ ok: true });
  expect(result).not.toHaveProperty('headers');
  expect(JSON.stringify(result)).not.toMatch(/set-cookie|x-echo|must-not-reach-agent/i);
  expectNoSecrets(result, [...passwords, ...issuedSessions]);
}

async function refusal(id: string, extra: RequestExtra = {}): Promise<string> {
  let result: CallResult;
  try {
    result = await call(id, extra);
  } catch (error) {
    expect(error).toBeInstanceOf(Error);
    const message = (error as Error).message;
    expectNoSecrets(message, [...passwords, ...issuedSessions]);
    return message;
  }
  expect(result).toHaveProperty('error');
  expect(result).not.toHaveProperty('status', 200);
  if (!('error' in result)) throw new Error('Expected the broker to refuse the request');
  expect(result.error).not.toBe('');
  expectNoSecrets(result, [...passwords, ...issuedSessions]);
  return result.error;
}

function expectApproval(id: string, proposed: SignInRecipe, hashOrigin = origin()): void {
  expect(approvalRequests).toHaveLength(1);
  const ask = JSON.stringify(approvalRequests[0].body);
  expect(ask).toContain(id);
  // A pinned certificate is folded into the hash; the approved address stays the plain origin.
  expect(ask).toContain(signInRecipeSha(checkedRecipe(proposed), hashOrigin));
  // The owner's page recomputes sha256(canonicalJson(detail.recipe)) itself (dashboard.js
  // _commitFields); it must land on the hash the broker checks, or no approval could match.
  const detail = (approvalRequests[0].body as { detail?: { recipe?: unknown } }).detail;
  expect(detail?.recipe).toBeDefined();
  expect(crypto.createHash('sha256').update(canonicalJson(detail!.recipe)).digest('hex'))
    .toBe(signInRecipeSha(checkedRecipe(proposed), hashOrigin));
  expect(ask).toContain(origin());
  expectNoSecrets(approvalRequests, [...passwords, ...issuedSessions]);
}

function expectAuthenticatedStatusRequests(count: number): void {
  const requests = wire.filter((received) => received.url === '/status');
  expect(requests).toHaveLength(count);
  for (const received of requests) {
    expect(received.method).toBe('GET');
    expect(issuedSessions.some((session) => received.headers.cookie === `sid=${session}`)).toBe(true);
    expect(received.body).toBe('');
    expect(received.headers.authorization).toBeUndefined();
  }
}

function expectNoSessionsOnDisk(root: string, secrets: string[]): void {
  for (const item of fs.readdirSync(root, { withFileTypes: true })) {
    const filename = path.join(root, item.name);
    if (item.isDirectory()) expectNoSessionsOnDisk(filename, secrets);
    else if (item.isFile()) expectNoSecrets(fs.readFileSync(filename, 'utf8'), secrets);
  }
}

// A broken redirect implementation must fail this test without ever resolving or
// connecting to an external host. Observe attempts as well as blocking them.
function forbidExternalNetwork(): { attempts: string[]; restore(): void } {
  const attempts: string[] = [];
  const guard = (host: unknown): void => {
    if (typeof host !== 'string' || host === '127.0.0.1') return;
    attempts.push(host);
    throw new Error('External network blocked by sign-in test');
  };
  const lookup = dns.lookup;
  const promiseLookup = dns.promises.lookup;
  const connect = net.Socket.prototype.connect;

  const lookupSpy = vi.spyOn(dns, 'lookup').mockImplementation(((...args: unknown[]) => {
    guard(args[0]);
    return Reflect.apply(lookup, dns, args);
  }) as typeof dns.lookup);
  const promiseLookupSpy = vi.spyOn(dns.promises, 'lookup').mockImplementation(((...args: unknown[]) => {
    guard(args[0]);
    return Reflect.apply(promiseLookup, dns.promises, args);
  }) as typeof dns.promises.lookup);
  const connectSpy = vi.spyOn(net.Socket.prototype, 'connect').mockImplementation((function (
    this: net.Socket, ...args: unknown[]
  ) {
    const normalized = Array.isArray(args[0]) ? args[0] as unknown[] : args;
    const first = normalized[0];
    if (first !== null && typeof first === 'object') {
      guard((first as { host?: unknown }).host);
    } else if (typeof first === 'number') {
      guard(normalized[1]);
    }
    return Reflect.apply(connect, this, args);
  }) as typeof net.Socket.prototype.connect);

  return {
    attempts,
    restore: () => {
      connectSpy.mockRestore();
      promiseLookupSpy.mockRestore();
      lookupSpy.mockRestore();
    },
  };
}

// Every machine path the broker writes goes to this test's temp dir; the real
// /var/lib/wundervault is never touched.
const redirected = ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR',
  'WUNDERVAULT_NETWORK_STORE'] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeAll(async () => {
  vi.useRealTimers();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-brokersignin-'));
  for (const name of redirected) savedEnv[name] = process.env[name];
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'system');
  process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'user');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  process.env.WUNDERVAULT_NETWORK_STORE = path.join(dir, 'system', 'network.json');
  for (const sub of ['system', 'user', 'run']) fs.mkdirSync(path.join(dir, sub), { recursive: true, mode: 0o700 });

  trustedCertificate = makeCertificate('trusted');
  pinnedCertificate = makeCertificate('pinned');
  replacementCertificate = makeCertificate('replacement');
  expect(pinnedCertificate.sha256).not.toBe(replacementCertificate.sha256);
  savedCAs = tls.getCACertificates('default');
  tls.setDefaultCACertificates([...savedCAs, trustedCertificate.cert]);

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
            approvalRequests.push({ path: pathname, body });
            sendJson(res, { allowed: false, tier: '1', message: 'Sign-in approval denied by test owner' });
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
    if (req.method === 'POST' && denyRecipeApproval) {
      // Observe approveStamp at its HTTP boundary without depending on a private
      // broker method or an approval endpoint name.
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as CheckBody;
          approvalRequests.push({ path: pathname, body });
          sendJson(res, { error: 'Sign-in approval denied by test owner' }, 403);
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

beforeEach(async () => {
  fs.rmSync(path.join(dir, 'setup-pins.json'), { force: true });
  SetupPins.resetSharedForTests();
  entries = new Map();
  wire = [];
  checks = [];
  approvalRequests = [];
  denyRecipeApproval = false;
  unexpected = [];
  activities = [];
  password = `router/pw+${crypto.randomBytes(16).toString('hex')}=&`;
  passwords = [password];
  currentSession = null;
  issuedSessions = [];
  logins = 0;
  redirectLogin = false;
  await startRouter(trustedCertificate);
  broker = newBroker();
});

afterEach(async () => {
  try {
    broker?.reset();
    expect(unexpected).toEqual([]);
    expectNoSecrets([activities, checks, approvalRequests], [...passwords, ...issuedSessions]);
    expectNoSessionsOnDisk(dir, [...passwords, ...issuedSessions]);
  } finally {
    await close(routerServer);
  }
});

afterAll(async () => {
  try {
    await Promise.all([close(vaultServer), close(routerServer)]);
  } finally {
    for (const name of redirected) {
      if (savedEnv[name] === undefined) delete process.env[name];
      else process.env[name] = savedEnv[name];
    }
    if (savedCAs !== undefined) tls.setDefaultCACertificates(savedCAs);
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
}, 20_000);

describe('BrokerOps.call with sign-in recipes', () => {
  it('asks the owner before an unapproved sign-in and sends nothing when approval is denied', async () => {
    const e = entry({ approved: [] });
    entries.set(e.id, e);
    denyRecipeApproval = true;

    const error = await refusal(e.id);

    expect(error).toMatch(/approv|denied/i);
    expectApproval(e.id, recipe);
    expect(logins).toBe(0);
    expect(wire).toEqual([]);
  }, 20_000);

  it('uses a sealed approval, sends the session cookie, and scrubs hostile response echoes', async () => {
    const e = entry();
    entries.set(e.id, e);

    const result = await call(e.id);

    success(result);
    expect(logins).toBe(1);
    expect(issuedSessions).toHaveLength(1);
    expect(wire).toHaveLength(2);
    expect(wire[0]).toMatchObject({ method: 'POST', url: '/login' });
    expect(JSON.parse(wire[0].body)).toEqual({
      jsonrpc: '2.0',
      method: 'login',
      params: { user: 'admin', password },
    });
    expect(wire[0].headers['content-type']).toMatch(/^application\/json\b/);
    expect(wire[0].headers.cookie).toBeUndefined();
    expect(wire[1].headers.cookie).toBe(`sid=${currentSession}`);
    expectAuthenticatedStatusRequests(1);
    expect(approvalRequests).toEqual([]);
    expect(activities).toEqual(expect.arrayContaining([
      expect.objectContaining({
        entry_id: e.id,
        agent: 'Test',
        reason: 'Check the router status without receiving its password or session',
        status: 200,
      }),
    ]));
  });

  it('reuses the session on a second call, including for a website_login entry', async () => {
    const e = entry({
      shape: 'website_login',
      parts: { username: 'admin', password, totp: '' },
    });
    entries.set(e.id, e);

    success(await call(e.id));
    const firstSession = currentSession;
    success(await call(e.id));

    expect(logins).toBe(1);
    expect(currentSession).toBe(firstSession);
    expectAuthenticatedStatusRequests(2);
    expect(approvalRequests).toEqual([]);
  });

  it('signs in exactly once more after the router expires the session', async () => {
    const e = entry();
    entries.set(e.id, e);
    success(await call(e.id));
    const oldSession = currentSession;
    currentSession = null;

    success(await call(e.id));

    expect(logins).toBe(2);
    expect(issuedSessions).toHaveLength(2);
    expect(currentSession).not.toBe(oldSession);
    const requests = wire.filter((received) => received.url === '/status');
    expect(requests).toHaveLength(3);
    expect(requests[1].headers.cookie).toBe(`sid=${oldSession}`);
    expect(requests[2].headers.cookie).toBe(`sid=${currentSession}`);
    expect(approvalRequests).toEqual([]);
  });

  it('three calls that all meet an ended session share ONE re-login (round 1, F2)', async () => {
    const e = entry();
    entries.set(e.id, e);
    success(await call(e.id));
    currentSession = null;
    holdSignedOut = 3;
    const results = await Promise.all([call(e.id), call(e.id), call(e.id)]);
    for (const r of results) success(r);
    expect(wire.filter((w) => w.url === '/status')).toHaveLength(1 + 3 + 3);
    expect(logins).toBe(2);
  });

  it('after a re-login, the OLD session is scrubbed too (round 2, F2)', async () => {
    const e = entry();
    entries.set(e.id, e);
    success(await call(e.id));
    currentSession = null;
    echoHistory = true;
    try {
      const r = await call(e.id);
      success(r);
      expect(issuedSessions).toHaveLength(2);
      expectNoSecrets(r, issuedSessions);
    } finally { echoHistory = false; }
  });

  it('a LATER call still scrubs a session retired by an earlier re-login (round 3, F1)', async () => {
    const e = entry();
    entries.set(e.id, e);
    success(await call(e.id));
    currentSession = null;
    success(await call(e.id)); // re-login: the first session is retired
    echoHistory = true;
    try {
      const r = await call(e.id); // uses the cached second session; reply lists both
      success(r);
      expect(issuedSessions).toHaveLength(2);
      expectNoSecrets(r, issuedSessions);
    } finally { echoHistory = false; }
  });

  it('a POST that meets an ended session is not sent again (round 1, B3)', async () => {
    const e = entry();
    entries.set(e.id, e);
    success(await call(e.id));
    currentSession = null;
    const r = await call(e.id, { method: 'POST', path: '/reboot', body: {} });
    expect(JSON.stringify(r)).toContain('not sent again');
    expect(wire.filter((x) => x.url === '/reboot')).toHaveLength(1);
    expect(logins).toBe(1);
    // The next call signs in first, then goes through.
    success(await call(e.id, { method: 'POST', path: '/reboot', body: {} }));
    expect(logins).toBe(2);
  });

  it('shares one login among five concurrent first calls', async () => {
    const e = entry();
    entries.set(e.id, e);

    const results = await Promise.all(Array.from({ length: 5 }, () => call(e.id)));

    for (const result of results) success(result);
    expect(logins).toBe(1);
    expect(issuedSessions).toHaveLength(1);
    expectAuthenticatedStatusRequests(5);
    expect(approvalRequests).toEqual([]);
  });

  it('signs in again immediately after the stored password changes without restarting', async () => {
    const e = entry();
    entries.set(e.id, e);
    success(await call(e.id));
    const oldSession = currentSession;
    password = `changed/pw+${crypto.randomBytes(16).toString('hex')}=&`;
    passwords.push(password);
    const updated = entry({ id: e.id, rev: 2 });
    entries.set(e.id, updated);
    expect(updated.encrypted_content).not.toBe(e.encrypted_content);

    success(await call(e.id));

    expect(logins).toBe(2);
    expect(currentSession).not.toBe(oldSession);
    const loginRequests = wire.filter((received) => received.url === '/login');
    expect(loginRequests).toHaveLength(2);
    expect(JSON.parse(loginRequests[1].body).params.password).toBe(password);
    expectAuthenticatedStatusRequests(2);
    expect(approvalRequests).toEqual([]);
  });

  it('asks again when one field of the recipe changes, even with a cached session', async () => {
    const e = entry();
    entries.set(e.id, e);
    success(await call(e.id));
    const previousWireCount = wire.length;
    const changed: SignInRecipe = { ...recipe, session_from: { cookie: 'another_sid' } };
    expect(signInRecipeSha(checkedRecipe(changed), origin()))
      .not.toBe(signInRecipeSha(checkedRecipe(recipe), origin()));
    denyRecipeApproval = true;

    const error = await refusal(e.id, { sign_in: changed });

    expect(error).toMatch(/approv|denied/i);
    expectApproval(e.id, changed);
    expect(logins).toBe(1);
    expect(wire).toHaveLength(previousWireCount);
  }, 20_000);

  it('checks a revoked approval on the very next call instead of using its cached session', async () => {
    const e = entry();
    entries.set(e.id, e);
    success(await call(e.id));
    const previousWireCount = wire.length;
    entries.set(e.id, { ...e, ...sealedPolicy(e.id, [], 2) });
    denyRecipeApproval = true;

    const error = await refusal(e.id);

    expect(error).toMatch(/approv|denied/i);
    expectApproval(e.id, recipe);
    expect(logins).toBe(1);
    expect(wire).toHaveLength(previousWireCount);
  }, 20_000);

  it('refuses a login redirect without resolving or connecting to the other origin', async () => {
    const e = entry();
    entries.set(e.id, e);
    redirectLogin = true;
    const network = forbidExternalNetwork();
    try {
      const error = await refusal(e.id);

      expect(error).toMatch(/sign.in/i);
      expect(error).toContain('307');
      expectNoSecrets(error, passwords);
      expect(network.attempts).toEqual([]);
      expect(logins).toBe(1);
      expect(issuedSessions).toEqual([]);
      expect(wire).toHaveLength(1);
      expect(wire[0].url).toBe('/login');
      expect(approvalRequests).toEqual([]);
    } finally {
      network.restore();
    }
  });

  it('requires approval of the exact self-signed certificate and refuses its replacement on the same port', async () => {
    const samePort = port;
    await close(routerServer);
    await startRouter(pinnedCertificate, samePort);
    expect(port).toBe(samePort);
    expect(tls.getCACertificates('default')).not.toContain(pinnedCertificate.cert);
    expect(tls.getCACertificates('default')).not.toContain(replacementCertificate.cert);
    const approvedOrigin = `${origin()}#cert-sha256=${pinnedCertificate.sha256}`;
    const e = entry({
      approved: [
        { recipe, origin: origin() },
        { recipe, origin: origin(), hashOrigin: approvedOrigin },
      ],
    });
    entries.set(e.id, e);

    const untrustedError = await refusal(e.id);
    expect(untrustedError).toMatch(/certificate|self.signed|verify|issuer/i);
    expect(logins).toBe(0);
    expect(wire).toEqual([]);

    success(await call(e.id, { trust_certificate: true }));
    expect(logins).toBe(1);
    expectAuthenticatedStatusRequests(1);
    expect(approvalRequests).toEqual([]);

    const previousWireCount = wire.length;
    await close(routerServer);
    await startRouter(replacementCertificate, samePort);
    expect(port).toBe(samePort);
    denyRecipeApproval = true;

    const changedError = await refusal(e.id, { trust_certificate: true });

    expect(changedError).toMatch(/approv|certificate|fingerprint|trust/i);
    expectApproval(e.id, recipe, `${origin()}#cert-sha256=${replacementCertificate.sha256}`);
    expect(logins).toBe(1);
    expect(wire).toHaveLength(previousWireCount);
  }, 20_000);

  it('refuses sign_in on an api_key entry with WRONG_KIND before contacting the router', async () => {
    const e = entry({ shape: 'api_key', parts: { key: 'not-a-login-api-key' } });
    entries.set(e.id, e);

    const result = await call(e.id);

    expect(result).toMatchObject({ code: 'WRONG_KIND', error: expect.any(String) });
    expectNoSecrets(result, passwords);
    expect(logins).toBe(0);
    expect(wire).toEqual([]);
    expect(approvalRequests).toEqual([]);
  });

  it('refuses trust_certificate without sign_in before contacting the router', async () => {
    const e = entry();
    entries.set(e.id, e);

    const result = await call(e.id, { sign_in: undefined, trust_certificate: true });

    expect(result).toMatchObject({ code: 'BAD_REQUEST', error: expect.stringMatching(/sign.in/i) });
    expectNoSecrets(result, passwords);
    expect(logins).toBe(0);
    expect(wire).toEqual([]);
    expect(approvalRequests).toEqual([]);
  });
});

// The real fetch path (resolveEntry + sealed setup), which the unit test's fake API skipped:
// a stored-only entry must reach vault_2fa_code, and plain vault_call must still refuse it.
describe('stored-only entries through the real entry view', () => {
  const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
  it('vault_2fa_code works for a website login and a 2FA secret', async () => {
    for (const [shape, parts] of [
      ['website_login', { username: 'admin', password: 'pw', totp: SEED }],
      ['two_factor', { seed: SEED }],
    ] as const) {
      const e = entry({ shape, parts: { ...parts } });
      entries.set(e.id, e);
      const r = await broker.twoFactorCode({ entryId: e.id, purpose: 'test' }) as Record<string, unknown>;
      expect(r.error).toBeUndefined();
      expect(String(r.code)).toMatch(/^\d{6}$/);
      expect(JSON.stringify(r)).not.toContain(SEED.slice(0, 10));
    }
  });
  it('plain vault_call refuses a stored login (no sign_in)', async () => {
    const e = entry({ shape: 'password' });
    entries.set(e.id, e);
    const r = await broker.call({ entryId: e.id, purpose: 'x', request: {
      origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'GET', path: '/status' } as never });
    expect(JSON.stringify(r)).toContain('stored only');
    expect(logins).toBe(0);
  });
});
