import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  sealT2OpDetail, openT2OpDetail, type T2OpDetail,
} from '../src/setup-seal.js';
import { pay, sign, approveStamp, type Deps } from '../src/signing-ops.js';
import { SigningState, commitment } from '../src/wallet.js';
import { canonicalJson } from '../src/opdef.js';
import { evmAddressOf, parseEvmPrivateKey } from '../src/evm.js';

const VAULT_KEY = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const AGENT_ID = 'agent-t2op-1';
const REQUEST_ID = '00112233445566778899aabbccddeeff';
const NONCE = Buffer.from('000102030405060708090a0b', 'hex');
const MALFORMED = { ok: false, reason: 'malformed' };
const BAD_SEAL = { ok: false, reason: 'bad seal' };
const KINDS = ['payment', 'signature', 'recipe'] as const;

const vectorPlaintext = {
  v: 1 as const,
  name: 'Wallet',
  kind: 'payment' as const,
  detail: { payee: 'merchant', amount: '10000', purpose: 'buy data' },
};

function referenceSeal(json: string, paddedLength?: number) {
  const bytes = Buffer.from(json, 'utf8');
  const length = paddedLength ?? [256, 1024, 4096, 16384, 65536, 131072, 262144, 524288]
    .find(size => size >= bytes.length);
  if (length === undefined || length < bytes.length) throw new Error('bad test plaintext');
  const padded = Buffer.alloc(length, 0x20);
  bytes.copy(padded);
  const key = Buffer.from(crypto.hkdfSync(
    'sha256', VAULT_KEY, Buffer.alloc(32), Buffer.from('wv-t2op-1', 'utf8'), 32,
  ));
  const cipher = crypto.createCipheriv('aes-256-gcm', key, NONCE);
  cipher.setAAD(Buffer.from(`wv-t2op-1|${AGENT_ID}|${REQUEST_ID}`, 'utf8'));
  return {
    ciphertext: Buffer.concat([cipher.update(padded), cipher.final(), cipher.getAuthTag()]).toString('base64'),
    nonce: NONCE.toString('base64'),
  };
}

function openReference(value: unknown, paddedLength?: number) {
  const sealed = referenceSeal(JSON.stringify(value), paddedLength);
  return openT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, sealed.ciphertext, sealed.nonce);
}

describe('wv-t2op-1', () => {
  it.each(KINDS)('round trips %s with exactly the operation detail', (kind) => {
    const detail: T2OpDetail = {
      name: 'Owner key', kind,
      detail: { purpose: 'pay / sign / stamp', nested: { values: [1, true, null, 'é'] } },
    };
    const sealed = sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail);
    if (!sealed.ok) throw new Error(sealed.reason);
    expect(Buffer.from(sealed.nonce, 'base64')).toHaveLength(12);
    expect(openT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, sealed.ciphertext, sealed.nonce))
      .toEqual({ ok: true, detail: { v: 1, ...detail } });
  });

  it('matches an independent deterministic HKDF / AES-GCM calculation', () => {
    const { v, ...detail } = vectorPlaintext;
    expect(v).toBe(1);
    const expected = referenceSeal(JSON.stringify(vectorPlaintext));
    const sealed = sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail, NONCE);
    expect(sealed).toEqual({ ok: true, ...expected });
    expect(Buffer.from(expected.ciphertext, 'base64')).toHaveLength(256 + 16);
    expect(openT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, expected.ciphertext, expected.nonce))
      .toEqual({ ok: true, detail: vectorPlaintext });
    expect(sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail, NONCE)).toEqual(sealed);
  });

  it('binds both agent id and request id in the AAD', () => {
    const { v, ...detail } = vectorPlaintext;
    expect(v).toBe(1);
    const sealed = sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail, NONCE);
    if (!sealed.ok) throw new Error(sealed.reason);
    expect(openT2OpDetail(VAULT_KEY, 'another-agent', REQUEST_ID, sealed.ciphertext, sealed.nonce))
      .toEqual(BAD_SEAL);
    expect(openT2OpDetail(VAULT_KEY, AGENT_ID, 'f'.repeat(32), sealed.ciphertext, sealed.nonce))
      .toEqual(BAD_SEAL);
    expect(openT2OpDetail(Buffer.alloc(32, 99), AGENT_ID, REQUEST_ID, sealed.ciphertext, sealed.nonce))
      .toEqual(BAD_SEAL);
  });

  it.each([
    { ...vectorPlaintext, extra: true },
    { ...vectorPlaintext, v: 2 },
    { ...vectorPlaintext, kind: 'call' },
    { ...vectorPlaintext, kind: 'Payment' },
    { ...vectorPlaintext, name: 'x'.repeat(257) },
    { ...vectorPlaintext, name: 1 },
    { ...vectorPlaintext, detail: [] },
    { ...vectorPlaintext, detail: null },
    { v: 1, kind: 'payment', detail: {} },
    { v: 1, name: 'Wallet', kind: 'payment' },
  ])('rejects authenticated malformed JSON: %j', (value) => {
    expect(openReference(value)).toEqual(MALFORMED);
  });

  it('validates the seal input rather than silently dropping extra top-level keys', () => {
    const { v, ...detail } = vectorPlaintext;
    expect(v).toBe(1);
    for (const value of [
      { ...detail, extra: true },
      { ...detail, v: 1 },
      { ...detail, kind: 'call' },
      { ...detail, name: 'x'.repeat(257) },
      { ...detail, detail: [] },
      { name: 'Wallet', kind: 'payment' },
    ]) {
      expect(sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, value as T2OpDetail, NONCE))
        .toEqual(MALFORMED);
    }
  });

  it('accepts exactly 64 KiB before padding and rejects one more byte on seal and open', () => {
    const detail: T2OpDetail = { name: 'Wallet', kind: 'signature', detail: { text: '' } };
    const overhead = Buffer.byteLength(JSON.stringify({ v: 1, ...detail }), 'utf8');
    detail.detail.text = 'x'.repeat(64 * 1024 - overhead);
    const sealed = sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail, NONCE);
    if (!sealed.ok) throw new Error(sealed.reason);
    expect(Buffer.from(sealed.ciphertext, 'base64')).toHaveLength(65536 + 16);
    expect(openT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, sealed.ciphertext, sealed.nonce))
      .toEqual({ ok: true, detail: { v: 1, ...detail } });
    detail.detail.text += 'x';
    expect(sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail, NONCE)).toEqual(MALFORMED);
    expect(openReference({ v: 1, ...detail })).toEqual(MALFORMED);
  });

  it('measures the JSON size in UTF-8 bytes, including escaping and envelope overhead', () => {
    const detail: T2OpDetail = {
      name: 'Wallet', kind: 'signature', detail: { text: 'é'.repeat(32 * 1024) },
    };
    expect(sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail, NONCE)).toEqual(MALFORMED);
    expect(openReference({ v: 1, ...detail })).toEqual(MALFORMED);
    detail.detail.text = '"'.repeat(32 * 1024);
    expect(sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail, NONCE)).toEqual(MALFORMED);
  });

  it('rejects oversized authenticated JSON even when its parsed serialization would fit', () => {
    const json = JSON.stringify(vectorPlaintext).replace('"amount":', '"amount":' + ' '.repeat(65536));
    const sealed = referenceSeal(json);
    expect(openT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, sealed.ciphertext, sealed.nonce))
      .toEqual(MALFORMED);
  });

  it('rejects invalid ids, bad keys, bad nonces, invalid base64 and invalid padding lengths', () => {
    const { v, ...detail } = vectorPlaintext;
    expect(v).toBe(1);
    for (const [agentId, requestId] of [
      ['bad|agent', REQUEST_ID],
      [AGENT_ID, REQUEST_ID.toUpperCase()],
      [AGENT_ID, 'req-1'],
    ]) {
      expect(sealT2OpDetail(VAULT_KEY, agentId, requestId, detail, NONCE)).toEqual(MALFORMED);
      expect(openT2OpDetail(VAULT_KEY, agentId, requestId, '', '')).toEqual(MALFORMED);
    }
    expect(sealT2OpDetail(Buffer.alloc(31), AGENT_ID, REQUEST_ID, detail, NONCE)).toEqual(BAD_SEAL);
    expect(sealT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, detail, Buffer.alloc(11))).toEqual(BAD_SEAL);
    expect(openT2OpDetail(VAULT_KEY, AGENT_ID, REQUEST_ID, 'not base64', NONCE.toString('base64')))
      .toEqual(BAD_SEAL);
    expect(openReference(vectorPlaintext, 257)).toEqual(MALFORMED);
  });
});

const EVM_KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const MERCHANT = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const ASSET = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const RESOURCE = 'https://api.example.com/premium';
const PURPOSE = 'buy data';
const RECIPE = {
  mac: 'hmac-sha256', key: 'utf8', message: [{ var: 'body' }], encoding: 'hex',
  place: [{ in: 'header', name: 'x-sig', value: '{stamp}' }],
};
const RECIPE_SHA = crypto.createHash('sha256').update(canonicalJson(RECIPE)).digest('hex');
type Kind = typeof KINDS[number];

function gcm(plaintext: string) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, nonce);
  return {
    ciphertext: Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]).toString('base64'),
    nonce: nonce.toString('base64'),
  };
}

function expectedDetail(kind: Kind): Record<string, unknown> {
  if (kind === 'payment') {
    return {
      entry_id: 'key', network: 'base-sepolia', asset: ASSET, payee: MERCHANT, amount: '10000',
      reason: 'payee', spent_24h: '0', daily_cap: '0', payee_listed: false,
      resource_url: RESOURCE, purpose: PURPOSE,
    };
  }
  if (kind === 'signature') {
    return {
      entry_id: 'key', data_sha256: crypto.createHash('sha256').update('hello').digest('hex'),
      length: '5', text: 'hello', purpose: PURPOSE,
    };
  }
  return {
    entry_id: 'key', origin: 'https://api.example.com:443', recipe_sha256: RECIPE_SHA,
    recipe: RECIPE, summary: 'Sign the body', purpose: PURPOSE,
  };
}

interface Request {
  id: string;
  kind: Kind;
  detail: Record<string, unknown>;
  used: boolean;
}

class FakeServer {
  locked: unknown = true;
  agentId: string | undefined = AGENT_ID;
  name = 'Owner key';
  kind: Kind = 'signature';
  policy: { ciphertext: string; nonce: string } | null = null;
  decrypts = 0;
  request: Request | null = null;
  owner = 'approve';
  replyId: 'same' | 'different' | 'missing' = 'same';
  allowUnasked = false;
  tamperShown = false;

  getSecret = vi.fn(async (_id: string) => {
    const value = this.kind === 'payment' ? EVM_KEY
      : this.kind === 'signature' ? Buffer.alloc(32, 5).toString('base64') : 'stamp key';
    const enc = gcm(value);
    const out: Record<string, unknown> = {
      name: this.name, agent_id: this.agentId, vault_locked: this.locked, access_tier: '1',
      entry_mode: this.kind === 'payment' ? 'BROKER_WALLET'
        : this.kind === 'signature' ? 'BROKER_SIGN' : 'BROKER_HTTP',
      exec_config: this.kind === 'payment' ? { delivery: 'wallet', chain: 'evm' }
        : this.kind === 'signature' ? { delivery: 'sign' }
          : { delivery: 'http', credential_binding: { in: 'stamp' } },
      content_nonce: enc.nonce, policy_ciphertext: this.policy?.ciphertext ?? null,
      policy_nonce: this.policy?.nonce ?? null,
    };
    Object.defineProperty(out, 'encrypted_content', {
      enumerable: true,
      get: () => { this.decrypts++; return enc.ciphertext; },
    });
    return out;
  });

  ensureVaultKey = vi.fn(async () => new Uint8Array(VAULT_KEY));

  checkOperation = vi.fn(async (body: Record<string, unknown>) => {
    if (body.approval_id) {
      const allowed = !!this.request && this.request.id === body.approval_id && !this.request.used;
      if (allowed) this.request!.used = true;
      return { allowed, tier: '1' };
    }
    if (body.within_rules) return { allowed: true, tier: '1' };
    const id = typeof body.request_id === 'string' ? body.request_id : 'req-1';
    let detail: Record<string, unknown>;
    if (body.detail_ciphertext) {
      const opened = openT2OpDetail(
        VAULT_KEY, AGENT_ID, id, body.detail_ciphertext as string, body.detail_nonce as string,
      );
      if (!opened.ok) throw new Error(opened.reason);
      expect(opened.detail.name).toBe(this.name);
      expect(opened.detail.kind).toBe(body.kind);
      detail = opened.detail.detail;
    } else {
      detail = body.detail as Record<string, unknown>;
    }
    this.request = { id, kind: body.kind as Kind, detail, used: false };
    return {
      allowed: this.allowUnasked, tier: '1',
      request_id: this.replyId === 'same' ? id : this.replyId === 'different' ? 'f'.repeat(32) : undefined,
    };
  });

  waitForOwnerApproval = vi.fn(async (id: string, _ms: number) => {
    const r = this.request!;
    expect(id).toBe(r.id);
    expect(this.decrypts).toBe(0);
    if (this.owner !== 'approve') return { status: this.owner };
    const shown = { ...r.detail };
    if (this.tamperShown) {
      if (r.kind === 'payment') shown.amount = '1';
      else if (r.kind === 'signature') shown.data_sha256 = 'f'.repeat(64);
      else shown.recipe = { builtin: 'oauth1' };
    }
    const fields: Record<string, string> = r.kind === 'payment'
      ? {
        entry_id: 'key', network: shown.network as string, asset: shown.asset as string,
        payee: shown.payee as string, amount: shown.amount as string,
      }
      : r.kind === 'signature'
        ? { entry_id: 'key', data_sha256: shown.data_sha256 as string, length: shown.length as string }
        : {
          entry_id: 'key', origin: shown.origin as string,
          recipe_sha256: crypto.createHash('sha256').update(canonicalJson(shown.recipe)).digest('hex'),
        };
    return {
      status: 'approved',
      owner_token: gcm(JSON.stringify({
        v: 1, request_id: id, entry_id: 'key', kind: r.kind,
        commitment: commitment(fields), add_payee: false,
      })),
    };
  });

  api() {
    return {
      getSecret: this.getSecret, ensureVaultKey: this.ensureVaultKey,
      checkOperation: this.checkOperation, waitForOwnerApproval: this.waitForOwnerApproval,
    };
  }
}

let dir = '';
let server: FakeServer;
let deps: Deps;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-t2op-'));
  server = new FakeServer();
  deps = {
    api: server.api() as never,
    state: new SigningState(path.join(dir, 'wallet-ledger.json'), () => 1_800_000_000_000),
    approvalWaitMs: 0, now: () => 1_800_000_000_000,
  };
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

async function run(kind: Kind) {
  server.kind = kind;
  if (kind === 'payment') {
    return pay(deps, {
      entryId: 'key', purpose: PURPOSE,
      paymentRequired: {
        x402Version: 2,
        resource: { url: RESOURCE, description: 'premium', mimeType: 'application/json' },
        accepts: [{
          scheme: 'exact', network: 'eip155:84532', amount: '10000', asset: ASSET,
          payTo: MERCHANT, maxTimeoutSeconds: 60, extra: { name: 'USDC', version: '2' },
        }],
      },
    });
  }
  if (kind === 'signature') return sign(deps, { entryId: 'key', purpose: PURPOSE, data: 'hello' });
  return approveStamp(deps, {
    entryId: 'key', s: await server.getSecret('key') as never, vaultKey: new Uint8Array(VAULT_KEY),
    origin: 'https://api.example.com:443', recipe: RECIPE, recipeSha: RECIPE_SHA,
    summary: 'Sign the body', purpose: PURPOSE,
  });
}

function expectSuccess(result: Awaited<ReturnType<typeof run>>, kind: Kind) {
  if (kind === 'recipe') expect(result).toBeNull();
  else {
    expect(result).not.toBeNull();
    expect(result && 'error' in result).toBe(false);
  }
}

describe('locked operation approvals', () => {
  it.each(KINDS)('seals a new %s ask and leaves the owner-token burn unchanged', async (kind) => {
    expectSuccess(await run(kind), kind);
    expect(server.checkOperation).toHaveBeenCalledTimes(2);
    const ask = server.checkOperation.mock.calls[0][0];
    expect(Object.keys(ask).sort()).toEqual([
      'detail_ciphertext', 'detail_nonce', 'entry_id', 'kind', 'purpose', 'request_id',
    ]);
    expect(ask).toMatchObject({ entry_id: 'key', kind, purpose: '' });
    expect(ask.request_id).toMatch(/^[0-9a-f]{32}$/);
    expect(ask).not.toHaveProperty('detail');
    expect(ask).not.toHaveProperty('match_mac');
    const opened = openT2OpDetail(
      VAULT_KEY, AGENT_ID, ask.request_id as string,
      ask.detail_ciphertext as string, ask.detail_nonce as string,
    );
    expect(opened).toEqual({
      ok: true, detail: { v: 1, name: 'Owner key', kind, detail: expectedDetail(kind) },
    });
    expect(server.checkOperation.mock.calls[1][0]).toEqual({
      entry_id: 'key', kind, approval_id: ask.request_id, purpose: '',
    });
    expect(deps.state.isUsed(ask.request_id as string)).toBe(true);
    expect(server.request!.used).toBe(true);
    expect(server.decrypts).toBe(kind === 'recipe' ? 0 : 1);
  });

  it.each(KINDS)('keeps the unlocked %s ask exactly as before', async (kind) => {
    server.locked = false;
    expectSuccess(await run(kind), kind);
    expect(server.checkOperation.mock.calls[0][0]).toEqual({
      entry_id: 'key', kind, detail: expectedDetail(kind), purpose: '',
    });
    expect(server.checkOperation.mock.calls[1][0]).toEqual({
      entry_id: 'key', kind, approval_id: 'req-1', purpose: '',
    });
  });

  it.each([undefined, 'true', 1])('does not seal unless vault_locked is strictly true (%s)', async (locked) => {
    server.locked = locked;
    expectSuccess(await run('signature'), 'signature');
    expect(server.checkOperation.mock.calls[0][0]).toEqual({
      entry_id: 'key', kind: 'signature', detail: expectedDetail('signature'), purpose: '',
    });
  });

  it.each(KINDS)('refuses a %s seal failure without asking or decrypting', async (kind) => {
    server.name = 'x'.repeat(257);
    expect(await run(kind)).toEqual({
      error: 'Refused: this approval request could not be sealed. Nothing was signed.',
      code: 'BAD_REQUEST',
    });
    expect(server.checkOperation).not.toHaveBeenCalled();
    expect(server.waitForOwnerApproval).not.toHaveBeenCalled();
    expect(server.decrypts).toBe(0);
  });

  it('does not fall back to plaintext when a locked entry has no agent id', async () => {
    server.agentId = undefined;
    expect(await run('signature')).toMatchObject({ code: 'BAD_REQUEST' });
    expect(server.checkOperation).not.toHaveBeenCalled();
    expect(server.decrypts).toBe(0);
  });

  it('refuses an oversized locked signature envelope without asking', async () => {
    server.kind = 'signature';
    const result = await sign(deps, {
      entryId: 'key', purpose: PURPOSE, data: 'x'.repeat(65530),
    });
    expect(result).toMatchObject({ code: 'BAD_REQUEST' });
    expect(server.checkOperation).not.toHaveBeenCalled();
    expect(server.decrypts).toBe(0);
  });

  it.each(KINDS)('rejects a different server request id for %s before waiting or decrypting', async (kind) => {
    server.replyId = 'different';
    expect(await run(kind)).toMatchObject({ code: 'BAD_SERVER' });
    expect(server.checkOperation).toHaveBeenCalledTimes(1);
    expect(server.waitForOwnerApproval).not.toHaveBeenCalled();
    expect(server.decrypts).toBe(0);
    server.replyId = 'same';
    expectSuccess(await run(kind), kind);
    expect(server.checkOperation).toHaveBeenCalledTimes(3);
  });

  it('rejects a missing server request id', async () => {
    server.replyId = 'missing';
    expect(await run('signature')).toMatchObject({ code: 'BAD_SERVER' });
    expect(server.waitForOwnerApproval).not.toHaveBeenCalled();
    expect(server.decrypts).toBe(0);
  });

  it('still rejects a server that allows an ask without owner approval', async () => {
    server.allowUnasked = true;
    expect(await run('signature')).toMatchObject({ code: 'BAD_SERVER' });
    expect(server.waitForOwnerApproval).not.toHaveBeenCalled();
    expect(server.decrypts).toBe(0);
  });

  it.each(KINDS)('reuses a pending sealed %s request without another ask', async (kind) => {
    server.owner = 'pending';
    expect(await run(kind)).toMatchObject({ code: 'WAITING' });
    const id = server.request!.id;
    expect(await run(kind)).toMatchObject({ code: 'WAITING' });
    expect(server.checkOperation).toHaveBeenCalledTimes(1);
    server.owner = 'approve';
    expectSuccess(await run(kind), kind);
    expect(server.checkOperation).toHaveBeenCalledTimes(2);
    expect(server.checkOperation.mock.calls[1][0]).toEqual({
      entry_id: 'key', kind, approval_id: id, purpose: '',
    });
  });

  it.each(KINDS)('never decrypts or burns a declined %s request', async (kind) => {
    server.owner = 'denied';
    expect(await run(kind)).toMatchObject({ code: 'NOT_APPROVED' });
    expect(server.checkOperation).toHaveBeenCalledTimes(1);
    expect(server.decrypts).toBe(0);
    expect(deps.state.isUsed(server.request!.id)).toBe(false);
  });

  it.each(KINDS)('checks the owner commitment against the original %s fields', async (kind) => {
    server.tamperShown = true;
    expect(await run(kind)).toMatchObject({ code: 'BAD_APPROVAL' });
    expect(server.checkOperation).toHaveBeenCalledTimes(1);
    expect(server.decrypts).toBe(0);
    expect(deps.state.isUsed(server.request!.id)).toBe(false);
  });

  it('keeps a locked within-rules payment free of detail and approval asks', async () => {
    const address = evmAddressOf(parseEvmPrivateKey(EVM_KEY));
    server.policy = gcm(JSON.stringify({
      v: 1, entry_id: 'key', version: 1, kind: 'wallet',
      wallet: {
        address, networks: ['base-sepolia'], daily_cap: '1000000',
        payees: [{ address: MERCHANT }],
      },
    }));
    const result = await run('payment');
    expect(result).toMatchObject({ inside_rules: true });
    expect(server.checkOperation.mock.calls).toEqual([[
      { entry_id: 'key', kind: 'payment', within_rules: true, purpose: '' },
    ]]);
    expect(server.waitForOwnerApproval).not.toHaveBeenCalled();
  });
});

describe('shared browser interop vector (test/vectors/t2op-v1.json)', () => {
  it('re-seals to the same bytes and opens to its plaintext', async () => {
    const { readFileSync } = await import('node:fs');
    const v = JSON.parse(readFileSync(new URL('./vectors/t2op-v1.json', import.meta.url), 'utf8'));
    const key = Buffer.from(v.vault_key_hex, 'hex');
    const { v: _ver, ...plain } = v.plaintext;
    const sealed = sealT2OpDetail(key, v.agent_id, v.request_id, plain, Buffer.from(v.nonce_b64, 'base64'));
    expect(sealed).toEqual({ ok: true, ciphertext: v.ciphertext_b64, nonce: v.nonce_b64 });
    const opened = openT2OpDetail(key, v.agent_id, v.request_id, v.ciphertext_b64, v.nonce_b64);
    expect(opened).toEqual({ ok: true, detail: v.plaintext });
  });
});
