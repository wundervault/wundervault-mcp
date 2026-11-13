/**
 * vault_send_secret (SPEC-send-a-secret-to-a-service, revision 2), driven through the real
 * broker call path: a local vault serves sealed entries and plays the owner; a local HTTPS
 * stand-in plays api.cloudflare.com. Checks 1-6, 9, 10, 15-20 (helper half).
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
import { commitment } from '../src/wallet.js';
import { checkSendArgs, itemSha, listRecipe } from '../src/worker-secrets.js';

const vaultKey = crypto.randomBytes(32);
const encKey = crypto.randomBytes(32);
const apiKey = `test-${crypto.randomBytes(16).toString('hex')}`;
const agentId = crypto.randomBytes(16).toString('hex');
const TOKEN = 'cf-token-that-may-edit-workers-445566';
const STRIPE = 'sk_test_51StripeValue9f8e7d6c5b4a3928';
const DB = 'postgres://app:pa55-w0rd-x@db.example.com:5432/shop';
const ACCOUNT = '8e110ee7b68156bf105352884c339abe';

let dir = '';
let savedCAs: string[] | undefined;
let vaultServer: http.Server | undefined;
let service: https.Server | undefined;
let vaultUrl = '';
let port = 0;
let broker: BrokerOps;
let entries = new Map<string, Record<string, unknown>>();
let wire: { method: string; url: string; body: string; auth: string }[] = [];
let toVault: string[] = [];
let asks: { id: string; entry_id: string; kind: string; detail: Record<string, unknown>; bundle?: string[] }[] = [];
/** The fake server's open bundle reads (R11): `${parent}:${entry}`, removed when spent. */
let bundleReads = new Set<string>();
let ownerSays: 'approve' | 'deny' = 'approve';
let serviceAnswer: (body: string) => { status: number; body: unknown };
let tokenTier: '1' | '2' = '1';
let failFull = new Set<string>();

function gcm(key: Buffer, plaintext: string | Buffer) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  return { nonce, ciphertext: Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]) };
}
const origin = () => `https://127.0.0.1:${port}`;

function entry(name: string, value: string, o: { tier?: '1' | '2'; shape?: string; binding?: unknown; format?: string; mode?: string } = {}) {
  const id = crypto.randomBytes(16).toString('hex');
  const v = gcm(vaultKey, Buffer.from(value, 'utf8'));
  const setup = {
    v: 1, rev: 1, value_sha256: crypto.createHash('sha256').update(v.ciphertext).digest('hex'),
    value_format: o.format ?? 'raw', name, shape: o.shape ?? 'api_key', service: null, delivery: 'http',
    binding: o.binding === undefined ? { v: 1, in: 'header', name: 'authorization', template: 'Bearer {secret}' } : o.binding,
    ssh_hosts: [], private_origins: [origin()], known_addresses: [], approval: null, operations: {}, chain: null,
  };
  const sealed = sealSetup(vaultKey, agentId, id, 1, setup as unknown as Parameters<typeof sealSetup>[4]);
  if (!sealed.ok) throw new Error('seal');
  const e: Record<string, unknown> & { id: string } = {
    id, agent_id: agentId, rev: 1, encrypted_content: v.ciphertext.toString('base64'),
    content_nonce: v.nonce.toString('base64'), setup_ciphertext: sealed.ciphertext, setup_nonce: sealed.nonce,
    access_tier: o.tier ?? '1', vault_locked: false, ...(o.mode ? { entry_mode: o.mode } : {}),
  };
  entries.set(id, e);
  return e;
}

/** What the owner's page writes after approving a list: one record per item in the token's policy. */
function rememberApproved(tokenId: string, items: { secret: string; worker: string; name: string }[]) {
  const approved = items.map((it) => ({ recipe_sha256: itemSha(ACCOUNT, it, origin()), origin: origin(), label: `${it.name} in ${it.worker}` }));
  const p = gcm(vaultKey, JSON.stringify({ v: 1, entry_id: tokenId, version: 1, kind: 'stamped', stamped: { approved } }));
  const e = entries.get(tokenId)!;
  e.policy_ciphertext = p.ciphertext.toString('base64'); e.policy_nonce = p.nonce.toString('base64');
}

function send(using: string, items: unknown, account: unknown = ACCOUNT, purpose = 'deploying the checkout') {
  return broker.sendSecrets({ using, account, items, purpose });
}

function expectNowhere(result: unknown, ...secrets: string[]) {
  for (const secret of secrets) {
    const b = Buffer.from(secret, 'utf8');
    const forms = [secret, encodeURIComponent(secret), b.toString('base64'), b.toString('base64url'), b.toString('hex')];
    const files: string[] = [];
    const walk = (d: string) => { for (const n of fs.readdirSync(d)) { const f = path.join(d, n); if (fs.statSync(f).isDirectory()) walk(f); else if (!/\.pem$/.test(n)) files.push(fs.readFileSync(f, 'utf8')); } };
    walk(dir);
    for (const f of forms) for (const h of [JSON.stringify(result), ...toVault, ...files]) expect(h).not.toContain(f);
  }
}

const redirected = ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR', 'WUNDERVAULT_NETWORK_STORE'] as const;
const savedEnv: Record<string, string | undefined> = {};

async function listen(server: http.Server | https.Server): Promise<number> {
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve()); });
  return (server.address() as net.AddressInfo).port;
}
async function close(server: http.Server | https.Server | undefined) {
  if (!server?.listening) return;
  await new Promise<void>((resolve, reject) => { server.close((e) => e ? reject(e) : resolve()); server.closeAllConnections(); });
}
function sendJson(res: http.ServerResponse, body: unknown, status = 200) {
  res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body));
}

beforeAll(async () => {
  vi.useRealTimers();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-sendsecret-'));
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

  service = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      wire.push({ method: req.method ?? '', url: req.url ?? '/', body, auth: String(req.headers.authorization ?? '') });
      const a = serviceAnswer(body);
      sendJson(res, a.body, a.status);
    });
  });
  port = await listen(service);

  const wrapped = gcm(encKey, vaultKey);
  const vaultKeyForAgent = Buffer.concat([wrapped.nonce, wrapped.ciphertext]).toString('base64');
  vaultServer = http.createServer((req, res) => {
    const pathname = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      toVault.push(`${req.method} ${req.url} ${JSON.stringify(req.headers)} ${raw}`);
      if (req.method === 'GET' && pathname === '/agent/profile') return sendJson(res, { vault_key_for_agent: vaultKeyForAgent, agent_id: agentId });
      if (req.method === 'GET' && pathname.startsWith('/agent/vault/secrets/')) {
        const sid = pathname.slice('/agent/vault/secrets/'.length);
        if (failFull.has(sid) && !/meta=1/.test(req.url ?? '')) return sendJson(res, { detail: 'boom' }, 500);
        const found = entries.get(sid);
        return found ? sendJson(res, found) : sendJson(res, { detail: 'Not found' }, 404);
      }
      if (req.method === 'POST' && pathname === '/agent/vault/operation-check') {
        const b = JSON.parse(raw) as { entry_id: string; kind?: string; detail?: Record<string, unknown>; approval_id?: string; bundle?: string[]; bundle_id?: string };
        if (b.approval_id) {   // the burn of a used approval; it opens one read per bundled value, once
          const a = asks.find((x) => x.id === b.approval_id);
          if (a && !(a as { opened?: boolean }).opened) { for (const e of a.bundle ?? []) bundleReads.add(`${a.id}:${e}`); (a as { opened?: boolean }).opened = true; }
          return sendJson(res, { allowed: true, tier: '1' });
        }
        if (b.bundle_id !== undefined) {
          const k = `${b.bundle_id}:${b.entry_id}`;
          if (!bundleReads.delete(k)) return sendJson(res, { allowed: false, tier: '2', message: 'Not covered.' });
          return sendJson(res, { allowed: true, tier: '2' });
        }
        if (b.kind === 'recipe') {
          const id = `req-${crypto.randomBytes(6).toString("hex")}`;
          asks.push({ id, entry_id: b.entry_id, kind: b.kind, detail: b.detail!, bundle: b.bundle });
          return sendJson(res, { allowed: false, request_id: id });
        }
        // A tier-2 value is never read without its own approval.
        if (entries.get(b.entry_id)?.access_tier === '2') return sendJson(res, { allowed: false, tier: '2', message: 'Needs approval.' });
        return sendJson(res, { allowed: true, tier: String(entries.get(b.entry_id)?.access_tier ?? '1') });
      }
      if (req.method === 'GET' && pathname.startsWith('/agent/vault/tier2-requests/')) {
        const id = pathname.slice('/agent/vault/tier2-requests/'.length);
        const r = asks.find((x) => x.id === id);
        if (!r || ownerSays === 'deny') return sendJson(res, { status: 'denied' });
        // The owner's browser: commit to what the card SHOWS (the recipe it hashes itself).
        const fields = { entry_id: r.entry_id, origin: String(r.detail.origin), recipe_sha256: crypto.createHash('sha256').update(canonicalJson(r.detail.recipe)).digest('hex') };
        const t = gcm(vaultKey, JSON.stringify({ v: 1, request_id: id, entry_id: r.entry_id, kind: r.kind, commitment: commitment(fields), add_payee: false }));
        return sendJson(res, { status: 'approved', owner_token: { ciphertext: t.ciphertext.toString('base64'), nonce: t.nonce.toString('base64') } });
      }
      sendJson(res, { error: 'Not found' }, 404);
    });
  });
  vaultUrl = `http://127.0.0.1:${await listen(vaultServer)}`;
}, 20_000);

beforeEach(() => {
  fs.rmSync(path.join(dir, 'setup-pins.json'), { force: true });
  SetupPins.resetSharedForTests();
  entries = new Map(); wire = []; toVault = []; asks = []; bundleReads = new Set(); ownerSays = 'approve'; tokenTier = '1'; failFull = new Set();
  serviceAnswer = (body) => ({ status: 200, body: { success: true, errors: [], result: { name: JSON.parse(body).name, type: 'secret_text' } } });
  broker = new BrokerOps('Test', apiKey, encKey.toString('base64url'), vaultUrl, null, undefined, { approvalWaitMs: 3000 }, {
    pinsPath: path.join(dir, 'setup-pins.json'), outboxDir: path.join(dir, 'outbox'), cloudflareOrigin: origin(),
  });
});
afterEach(() => { broker?.reset(); });
afterAll(async () => {
  try { await Promise.all([close(vaultServer), close(service)]); } finally {
    for (const name of redirected) { if (savedEnv[name] === undefined) delete process.env[name]; else process.env[name] = savedEnv[name]; }
    if (savedCAs !== undefined) tls.setDefaultCACertificates(savedCAs);
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
}, 20_000);

describe('vault_send_secret', () => {
  it('checks 1, 2, 15: one approval for a 3-item list over 2 Workers; exact PUTs; the values only in "text"', async () => {
    const t = entry('Cloudflare workers', TOKEN), s = entry('Stripe test key', STRIPE), d = entry('Shop database', DB);
    const items = [{ secret: s.id, worker: 'shop-api', name: 'STRIPE_KEY' }, { secret: d.id, worker: 'shop-api', name: 'DATABASE_URL' },
      { secret: d.id, worker: 'shop-cron', name: 'DATABASE_URL' }];
    const r = await send(t.id, items);
    expect(r).toMatchObject({ sent: 3, asked: true });
    expect(asks).toHaveLength(1);
    expect(asks[0].entry_id).toBe(t.id);
    expect(asks[0].detail.recipe).toEqual(listRecipe(ACCOUNT, items, origin()));
    expect(String(asks[0].detail.summary)).toContain('Stripe test key -> STRIPE_KEY in Worker shop-api');
    expect(wire.map((w) => `${w.method} ${w.url}`)).toEqual([
      `PUT /client/v4/accounts/${ACCOUNT}/workers/scripts/shop-api/secrets`,
      `PUT /client/v4/accounts/${ACCOUNT}/workers/scripts/shop-api/secrets`,
      `PUT /client/v4/accounts/${ACCOUNT}/workers/scripts/shop-cron/secrets`]);
    expect(wire.map((w) => JSON.parse(w.body))).toEqual([
      { name: 'STRIPE_KEY', text: STRIPE, type: 'secret_text' }, { name: 'DATABASE_URL', text: DB, type: 'secret_text' },
      { name: 'DATABASE_URL', text: DB, type: 'secret_text' }]);
    for (const w of wire) expect(w.auth).toBe(`Bearer ${TOKEN}`);
    expectNowhere(r, STRIPE, DB, TOKEN);
    expect(toVault.join('\n')).not.toContain('wv-fill-'.repeat(2));
  });

  it('checks 6, 16, 17: an approved list asks nothing again; a new item asks only about itself', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE), d = entry('DB', DB);
    const a = { secret: s.id, worker: 'shop-api', name: 'STRIPE_KEY' }, b = { secret: d.id, worker: 'shop-api', name: 'DATABASE_URL' };
    rememberApproved(t.id, [a]);
    expect(await send(t.id, [a])).toMatchObject({ sent: 1, asked: false });
    expect(asks).toHaveLength(0);
    expect(await send(t.id, [a, b])).toMatchObject({ sent: 2, asked: true });
    expect(asks).toHaveLength(1);
    expect((asks[0].detail.recipe as { items: unknown[] }).items).toEqual([{ entry_id: d.id, worker: 'shop-api', name: 'DATABASE_URL' }]);
    // Change any of worker or name: asks again.
    asks = [];
    await send(t.id, [{ ...a, worker: 'other' }]);
    await send(t.id, [{ ...a, name: 'STRIPE_SECRET' }]);
    expect(asks).toHaveLength(2);
  });

  it('check 5: the owner says no -> nothing is sent', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE);
    ownerSays = 'deny';
    const r = await send(t.id, [{ secret: s.id, worker: 'w', name: 'K' }]);
    expect(r).toMatchObject({ code: 'NOT_APPROVED' });
    expect((r as { error: string }).error).toContain('Nothing was sent');
    expect(wire).toHaveLength(0);
  });

  it('check 3: Cloudflare echoing the value (plain, base64, url-encoded) never reaches the agent', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE);
    rememberApproved(t.id, [{ secret: s.id, worker: 'w', name: 'K' }]);
    serviceAnswer = () => ({ status: 400, body: { success: false, errors: [
      { code: 10021, message: `bad value ${STRIPE} / ${Buffer.from(STRIPE).toString('base64')} / ${encodeURIComponent(STRIPE)} / ${TOKEN}` }] } });
    const r = await send(t.id, [{ secret: s.id, worker: 'w', name: 'K' }]);
    expect(r).toMatchObject({ sent: 0, results: [{ sent: false, worker: 'w', name: 'K' }] });
    expect(JSON.stringify(r)).toContain('10021');
    expectNowhere(r, STRIPE, TOKEN);
  });

  it('checks 4, 20: bad arguments are refused before anything is fetched or sent', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE);
    const bad: unknown[][] = [
      [[{ secret: s.id, worker: 'a/b', name: 'K' }]], [[{ secret: s.id, worker: '..', name: 'K' }]],
      [[{ secret: s.id, worker: 'a%2Fb', name: 'K' }]], [[{ secret: s.id, worker: 'a?x', name: 'K' }]],
      [[{ secret: s.id, worker: 'shopа', name: 'K' }]], [[{ secret: s.id, worker: 'w', name: 'MY KEY' }]],
      [[{ secret: s.id, worker: 'w', name: 'K\n' }]], [[{ secret: s.id, worker: 'w', name: 'K', extra: 1 }]],
      [[{ secret: s.id, worker: 'w', name: 'K' }, { secret: s.id, worker: 'w', name: 'K' }]],
      [[{ secret: t.id, worker: 'w', name: 'K' }]], [[]], [[{ secret: s.id, worker: 'w', name: 'K' }], 'not-an-account'],
    ];
    for (const [items, account] of bad) {
      const r = await send(t.id, items, account ?? ACCOUNT);
      expect(r, JSON.stringify(items)).toMatchObject({ code: 'BAD_REQUEST' });
    }
    expect(wire).toHaveLength(0);
    expect(asks).toHaveLength(0);
  });

  it('check 9: a secret or signing key this agent does not have is refused, nothing sent', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE);
    expect(await send(t.id, [{ secret: 'nope0000', worker: 'w', name: 'K' }])).toMatchObject({ code: 'BAD_REQUEST' });
    expect(await send('nope0000', [{ secret: s.id, worker: 'w', name: 'K' }])).toMatchObject({ code: 'BAD_REQUEST' });
    expect(wire).toHaveLength(0);
  });

  it('check 10: a stored login and a stamped key are refused before any request', async () => {
    const t = entry('CF', TOKEN);
    const login = entry('Router', '{"username":"admin","password":"pw-123456"}', { shape: 'website_login', binding: null, format: 'parts-1' });
    const stamped = entry('X keys', '{"a":1}', { binding: { v: 1, in: 'stamp' } });
    expect(await send(t.id, [{ secret: login.id, worker: 'w', name: 'K' }])).toMatchObject({ code: 'WRONG_KIND' });
    expect(await send(t.id, [{ secret: stamped.id, worker: 'w', name: 'K' }])).toMatchObject({ code: 'WRONG_KIND' });
    expect(wire).toHaveLength(0);
    expect(asks).toHaveLength(0);
  });

  it('checks 21, 24: three "Ask me first" values on approved pairings: ONE card, one tap, all sent; again asks again', async () => {
    const t = entry('CF', TOKEN);
    const v = [entry('Live Stripe', STRIPE, { tier: '2' }), entry('Live DB', DB, { tier: '2' }), entry('Webhook', 'whsec_live_9f8e7d6c5b4a', { tier: '2' })];
    const items = v.map((e, i) => ({ secret: e.id, worker: 'shop-api', name: `K${i}` }));
    rememberApproved(t.id, items);
    expect(await send(t.id, items)).toMatchObject({ sent: 3, asked: true });
    expect(asks).toHaveLength(1);
    const rec = asks[0].detail.recipe as { ask_each_time: string[]; send: string; items: unknown[] };
    expect(rec.ask_each_time).toEqual(v.map((e) => e.id).sort());
    expect(rec.send).toMatch(/^[0-9a-f]{32}$/);
    expect(asks[0].bundle).toEqual(v.map((e) => e.id).sort());
    expect(String(asks[0].detail.summary)).toContain('(asks every time)');
    expect(wire.map((w) => JSON.parse(w.body).text)).toEqual([STRIPE, DB, 'whsec_live_9f8e7d6c5b4a']);
    expect(bundleReads.size).toBe(0);
    // The same list again: a new card (a new nonce), never "already approved".
    expect(await send(t.id, items)).toMatchObject({ sent: 3, asked: true });
    expect(asks).toHaveLength(2);
    expect((asks[1].detail.recipe as { send: string }).send).not.toBe(rec.send);
    expectNowhere({}, STRIPE, DB);
  });

  it('R11 r1 F1: one "Ask me first" value into two Workers: one card, read once, both set', async () => {
    const t = entry('CF', TOKEN), db2 = entry('Live DB', DB, { tier: '2' });
    const items = [{ secret: db2.id, worker: 'shop-api', name: 'DATABASE_URL' }, { secret: db2.id, worker: 'shop-cron', name: 'DATABASE_URL' }];
    const r = await send(t.id, items) as { sent: number; results: Array<{ sent: boolean }> };
    expect(r.sent).toBe(2);
    expect(asks).toHaveLength(1);
    expect(asks[0].bundle).toEqual([db2.id]);
    expect(wire.map((w) => `${w.url} ${JSON.parse(w.body).text}`)).toEqual([
      `/client/v4/accounts/${ACCOUNT}/workers/scripts/shop-api/secrets ${DB}`, `/client/v4/accounts/${ACCOUNT}/workers/scripts/shop-cron/secrets ${DB}`]);
  });

  it('R11 r1 F2: a retry while the card waits, after the owner remembered the new pairing, waits on the SAME card', async () => {
    const t = entry('CF', TOKEN), one = entry('Test Stripe', STRIPE), two = entry('Live DB', DB, { tier: '2' });
    const a = { secret: one.id, worker: 'w', name: 'A' }, b = { secret: two.id, worker: 'w', name: 'B' };
    let hold = true;
    const realWait = (broker as unknown as { api: { waitForOwnerApproval: (...x: unknown[]) => Promise<unknown> } }).api;
    const orig = realWait.waitForOwnerApproval.bind(realWait);
    realWait.waitForOwnerApproval = async (...x: unknown[]) => hold ? { status: 'pending' } : orig(...x);
    expect(await send(t.id, [a, b])).toMatchObject({ code: 'WAITING' });
    expect(asks).toHaveLength(1);
    rememberApproved(t.id, [a, b]);   // the owner's approval wrote both pairings
    hold = false;
    expect(await send(t.id, [a, b])).toMatchObject({ sent: 2 });
    expect(asks).toHaveLength(1);     // no second card
  });

  it('R11 r2 F1: a numeric error code equal to the value never reaches the agent', async () => {
    const t = entry('CF', TOKEN), n = entry('PIN', '8675309');
    rememberApproved(t.id, [{ secret: n.id, worker: 'w', name: 'PIN' }]);
    serviceAnswer = () => ({ status: 400, body: { success: false, errors: [{ code: 8675309, message: 'invalid secret 8675309' }] } });
    const r = await send(t.id, [{ secret: n.id, worker: 'w', name: 'PIN' }]);
    expect(JSON.stringify(r)).not.toContain('8675309');
  });

  it('check 22: approved tier-1 + tier-2 on approved pairings: the card lists only the tier-2 item', async () => {
    const t = entry('CF', TOKEN), one = entry('Test Stripe', STRIPE), two = entry('Live DB', DB, { tier: '2' });
    const a = { secret: one.id, worker: 'w', name: 'A' }, b = { secret: two.id, worker: 'w', name: 'B' };
    rememberApproved(t.id, [a, b]);
    expect(await send(t.id, [a, b])).toMatchObject({ sent: 2, asked: true });
    expect((asks[0].detail.recipe as { items: unknown[] }).items).toEqual([{ entry_id: two.id, worker: 'w', name: 'B' }]);
    expect(asks[0].bundle).toEqual([two.id]);
  });

  it('check 23: a declined "Ask me first" card sends nothing and opens no read', async () => {
    const t = entry('CF', TOKEN), two = entry('Live DB', DB, { tier: '2' });
    ownerSays = 'deny';
    expect(await send(t.id, [{ secret: two.id, worker: 'w', name: 'B' }])).toMatchObject({ code: 'NOT_APPROVED' });
    expect(wire).toHaveLength(0);
    expect(bundleReads.size).toBe(0);
  });

  it('R11: a tier-2 value whose read the server refuses is not sent; the rest still go', async () => {
    const t = entry('CF', TOKEN), one = entry('Test Stripe', STRIPE), two = entry('Live DB', DB, { tier: '2' });
    const a = { secret: one.id, worker: 'w', name: 'A' }, b = { secret: two.id, worker: 'w', name: 'B' };
    rememberApproved(t.id, [a, b]);
    const realAdd = bundleReads.add.bind(bundleReads);
    bundleReads.add = () => bundleReads;   // the server opens nothing
    try {
      const r = await send(t.id, [a, b]) as { results: Array<{ sent: boolean; code?: string }> };
      expect(r.results[0].sent).toBe(true);
      expect(r.results[1]).toMatchObject({ sent: false, code: 'NOT_ALLOWED' });
    } finally { bundleReads.add = realAdd; }
    expect(wire.map((w) => JSON.parse(w.body).name)).toEqual(['A']);
  });

  it('a private key as the value is refused at reading, nothing sent; the next item still goes', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE);
    const pk = entry('Oops', '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----');
    const items = [{ secret: pk.id, worker: 'w', name: 'A' }, { secret: s.id, worker: 'w', name: 'B' }];
    rememberApproved(t.id, items);
    const r = await send(t.id, items);
    expect(r).toMatchObject({ sent: 1, results: [{ name: 'A', sent: false, code: 'WRONG_KIND' }, { name: 'B', sent: true }] });
    expect(wire).toHaveLength(1);
  });

  it('check 19: the activity log never holds the value; the address and placeholder hash are what is logged', async () => {
    const lines: unknown[] = [];
    (broker as unknown as { activity: { record(r: unknown): void } }).activity = { record: (r) => lines.push(r) };
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE);
    rememberApproved(t.id, [{ secret: s.id, worker: 'w', name: 'K' }]);
    await send(t.id, [{ secret: s.id, worker: 'w', name: 'K' }]);
    expect(lines.length).toBeGreaterThan(0);
    expectNowhere(lines, STRIPE, TOKEN);
    expect(JSON.stringify(lines)).toContain('/workers/scripts/w/secrets');
  });

  it('r1 F1: a 2xx without Cloudflare\'s success envelope is not reported as set', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE);
    rememberApproved(t.id, [{ secret: s.id, worker: 'w', name: 'K' }]);
    serviceAnswer = () => ({ status: 200, body: {} });
    expect(await send(t.id, [{ secret: s.id, worker: 'w', name: 'K' }])).toMatchObject({ sent: 0, results: [{ sent: false, status: 200 }] });
  });

  it('r1 F4: the vault failing on item 2 keeps item 1\'s result and still tries item 3', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE), d = entry('DB', DB), e = entry('Other', 'whsec_abcdef0123456789');
    const items = [{ secret: s.id, worker: 'w', name: 'A' }, { secret: d.id, worker: 'w', name: 'B' }, { secret: e.id, worker: 'w', name: 'C' }];
    rememberApproved(t.id, items);
    failFull.add(d.id);
    const r = await send(t.id, items);
    expect(r).toMatchObject({ sent: 2, results: [{ name: 'A', sent: true }, { name: 'B', sent: false, code: 'VAULT_UNREACHABLE' }, { name: 'C', sent: true }] });
  });

  it('r1 F3: each send row names the vaulted secret; a refused list leaves one row', async () => {
    const lines: Array<{ extra?: Record<string, unknown>; outcome?: string }> = [];
    (broker as unknown as { activity: { record(r: unknown): void } }).activity = { record: (r) => lines.push(r as never) };
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE);
    rememberApproved(t.id, [{ secret: s.id, worker: 'w', name: 'K' }]);
    await send(t.id, [{ secret: s.id, worker: 'w', name: 'K' }]);
    expect(lines.some((l) => l.extra?.send_secret === s.id && l.extra?.worker === 'w' && l.extra?.as === 'K')).toBe(true);
    lines.length = 0; ownerSays = 'deny';
    await send(t.id, [{ secret: s.id, worker: 'other', name: 'K' }]);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatchObject({ outcome: 'refused' });
    expect(String(lines[0].extra?.send_secrets)).toContain(`${s.id}:other:K`);
  });

  it('r2 F2: a send that throws keeps the list going and says the outcome is unknown', async () => {
    const t = entry('CF', TOKEN), s = entry('Stripe', STRIPE), d = entry('DB', DB);
    const items = [{ secret: s.id, worker: 'w', name: 'A' }, { secret: d.id, worker: 'w', name: 'B' }];
    rememberApproved(t.id, items);
    const real = broker.call.bind(broker); let n = 0;
    (broker as unknown as { call: unknown }).call = async (a: never) => { if (n++ === 0) throw new Error(`socket hang up ${STRIPE}`); return real(a); };
    const r = await send(t.id, items);
    expect(r).toMatchObject({ sent: 1, results: [{ name: 'A', sent: false, code: 'UNKNOWN_OUTCOME' }, { name: 'B', sent: true }] });
    expectNowhere(r, STRIPE);
  });

  it('unit: the argument checker', () => {
    expect(checkSendArgs({ using: 'abc', account: ACCOUNT, items: [{ secret: 'x1', worker: 'my_worker-2', name: '_A1' }] }).ok).toBe(true);
    expect(checkSendArgs({ using: 'abc', account: ACCOUNT, items: [{ secret: 'x1', worker: '-w', name: 'A' }] }).ok).toBe(false);
    expect(checkSendArgs({ using: 'abc', account: ACCOUNT, items: [{ secret: 'x1', worker: 'w', name: '1A' }] }).ok).toBe(false);
    expect(checkSendArgs({ using: 'abc', account: ACCOUNT, items: Array.from({ length: 21 }, (_, i) => ({ secret: 'x', worker: 'w', name: `A${i}` })) }).ok).toBe(false);
  });
});
