/**
 * SPEC-1.0-signing (burnbox): payments, signatures and stamp approvals, driven through the
 * broker-side functions against a fake server that behaves like the real one — including a
 * server that LIES about approvals, which is the case the owner seal exists for.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { pay, sign, approveStamp, type Deps } from '../src/signing-ops.js';
import { SigningState, commitment } from '../src/wallet.js';
import { canonicalJson } from '../src/opdef.js';
import { validateRecipe, recipeSha256, describeRecipe, type Recipe } from '../src/stamp.js';
import { recoverAddress, transferDigest, evmAddressOf, parseEvmPrivateKey } from '../src/evm.js';
import { base58Encode, parseSolanaSecretKey, associatedTokenAddress } from '../src/solana.js';
import { parsePaymentRequired, selectOffer } from '../src/x402.js';

const VAULT_KEY = Buffer.alloc(32, 9);
const OTHER_KEY = Buffer.alloc(32, 3);

function gcm(key: Buffer, plaintext: string | Buffer) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { ciphertext: body.toString('base64'), nonce: nonce.toString('base64') };
}

// ── keys and parties ─────────────────────────────────────────────────────────
const EVM_KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const EVM_ADDR = evmAddressOf(parseEvmPrivateKey(EVM_KEY)); // 0x2c7536E3605D9C16a7a3D7b1898e529396a65c23
const MERCHANT = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const STRANGER = '0x857b06519E91e3A54538791bDbb0E22373e36b66';
const SOL_SEED = new Uint8Array(32).fill(9);
const SOL_KEY = base58Encode(SOL_SEED);
const SOL_ADDR = parseSolanaSecretKey(SOL_KEY).address;
const SOL_MERCHANT = '2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4';
const FEE_PAYER = 'EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd';
const BLOCKHASH = '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi';
const INSTALLER_SEED_B64 = Buffer.alloc(32, 5).toString('base64');

function required402(o: Partial<{ network: string; amount: string; payTo: string; asset: string; extra: Record<string, unknown> }> = {}) {
  const network = o.network ?? 'eip155:84532';
  const evm = network.startsWith('eip155');
  return Buffer.from(JSON.stringify({
    x402Version: 2,
    resource: { url: 'https://api.example.com/premium', description: 'premium', mimeType: 'application/json' },
    accepts: [{
      scheme: 'exact', network, amount: o.amount ?? '10000',
      asset: o.asset ?? (evm ? '0x036CbD53842c5426634e7929541eC2318f3dCF7e' : '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'),
      payTo: o.payTo ?? (evm ? MERCHANT : SOL_MERCHANT), maxTimeoutSeconds: 60,
      extra: o.extra ?? (evm ? { name: 'USDC', version: '2' } : { feePayer: FEE_PAYER }),
    }],
  })).toString('base64');
}

// ── the fake server ──────────────────────────────────────────────────────────
interface Req { id: string; entry_id: string; kind: string; detail: Record<string, unknown> | null; status: string; owner_token?: unknown; used?: boolean }
interface Entry { mode: string; tier?: string; cfg: unknown; value: string; policy?: { ciphertext: string; nonce: string } | null }

class FakeServer {
  entries = new Map<string, Entry>();
  requests = new Map<string, Req>();
  checks: Array<Record<string, unknown>> = [];
  decrypts = 0;
  /** What the owner does when asked: 'approve' | 'deny' | 'wait' | a function. */
  owner: string | ((r: Req) => void) = 'approve';
  /** A compromised server: says approved without an owner token, or with a forged one. */
  lie: null | 'no-token' | 'other-request' | 'tamper-detail' | 'allow-unasked' = null;
  /** When set, the owner answers only once this resolves. */
  ownerGate: Promise<void> | null = null;

  api() {
    const self = this;
    return {
      async getSecret(id: string) {
        const e = self.entries.get(id);
        if (!e) throw new Error('404');
        const enc = gcm(VAULT_KEY, e.value);
        const out: Record<string, unknown> = {
          name: id, entry_mode: e.mode, access_tier: e.tier ?? '1', exec_config: e.cfg,
          content_nonce: enc.nonce, policy_ciphertext: e.policy?.ciphertext ?? null, policy_nonce: e.policy?.nonce ?? null,
        };
        Object.defineProperty(out, 'encrypted_content', { enumerable: true, get() { self.decrypts++; return enc.ciphertext; } });
        return out;
      },
      async ensureVaultKey() { return new Uint8Array(VAULT_KEY); },
      async checkOperation(body: Record<string, unknown>) {
        self.checks.push(body);
        const e = self.entries.get(body.entry_id as string)!;
        if (body.approval_id) {
          const r = self.requests.get(body.approval_id as string);
          if (!r || r.status !== 'approved' || r.used || r.kind !== body.kind || r.entry_id !== body.entry_id) {
            return { allowed: false, tier: e.tier ?? '1', message: 'no such approval' };
          }
          r.used = true;
          return { allowed: true, tier: e.tier ?? '1' };
        }
        if (body.kind === 'payment' && body.within_rules) {
          if ((e.tier ?? '1') === '2') throw new Error('HTTP 422');
          return { allowed: true, tier: '1' };
        }
        if (self.lie === 'allow-unasked') return { allowed: true, tier: '1' };
        const id = `req-${self.requests.size + 1}`;
        self.requests.set(id, { id, entry_id: body.entry_id as string, kind: body.kind as string, detail: body.detail as Record<string, unknown>, status: 'pending' });
        return { allowed: false, tier: e.tier ?? '1', request_id: id };
      },
      async waitForOwnerApproval(id: string) {
        if (self.ownerGate) await self.ownerGate;
        const r = self.requests.get(id)!;
        if (r.status === 'pending') {
          if (typeof self.owner === 'function') self.owner(r);
          else if (self.owner === 'approve') self.ownerApproves(r);
          else if (self.owner === 'deny') r.status = 'denied';
        }
        if (self.lie && r.status === 'pending') r.status = 'approved';
        if (self.lie === 'no-token') return { status: r.status };
        return { status: r.status, owner_token: r.owner_token };
      },
    };
  }

  /** What the owner's browser does: recompute the commitment from what it DISPLAYS, seal it. */
  ownerApproves(r: Req, addPayee = false) {
    const shown = { ...r.detail! };
    if (this.lie === 'tamper-detail') shown.amount = '1'; // the server showed the owner a smaller amount
    const fields: Record<string, string> = r.kind === 'payment'
      ? { entry_id: r.entry_id, network: shown.network as string, asset: shown.asset as string, payee: shown.payee as string, amount: shown.amount as string }
      : r.kind === 'signature'
        ? { entry_id: r.entry_id, data_sha256: shown.data_sha256 as string, length: shown.length as string }
        : { entry_id: r.entry_id, origin: shown.origin as string, recipe_sha256: crypto.createHash('sha256').update(canonicalJson(shown.recipe)).digest('hex') };
    const requestId = this.lie === 'other-request' ? 'req-999' : r.id;
    r.owner_token = gcm(VAULT_KEY, JSON.stringify({ v: 1, request_id: requestId, entry_id: r.entry_id, kind: r.kind, commitment: commitment(fields), add_payee: addPayee }));
    r.status = 'approved';
    r.detail = null; // erased on decision
  }
}

function walletPolicy(entryId: string, over: Partial<{ version: number; address: string; cap: string; payees: string[]; networks: string[]; extra: Record<string, unknown> }> = {}, key = VAULT_KEY) {
  return gcm(key, JSON.stringify({
    v: 1, entry_id: entryId, version: over.version ?? 1, kind: 'wallet',
    wallet: {
      address: over.address ?? EVM_ADDR, networks: over.networks ?? ['base', 'base-sepolia'],
      daily_cap: over.cap ?? '15000', payees: (over.payees ?? [MERCHANT]).map((address) => ({ address })),
    },
    ...(over.extra ?? {}),
  }));
}

let dir = '';
let server: FakeServer;
let deps: Deps;
let clock = 1_800_000_000_000;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-sign-'));
  server = new FakeServer();
  clock = 1_800_000_000_000;
  deps = {
    api: server.api() as never, state: new SigningState(path.join(dir, 'wallet-ledger.json'), () => clock),
    fetchBlockhash: async () => BLOCKHASH, approvalWaitMs: 0, now: () => clock,
  };
  server.entries.set('w', { mode: 'BROKER_WALLET', cfg: { delivery: 'wallet', chain: 'evm' }, value: EVM_KEY, policy: walletPolicy('w') });
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function decodeHeader(v: string) { return JSON.parse(Buffer.from(v, 'base64').toString('utf8')); }
const payW = (amount = '10000', extra: Partial<Parameters<typeof required402>[0]> = {}) =>
  pay(deps, { entryId: 'w', purpose: 'buy data', paymentRequired: required402({ amount, ...extra }) });

describe('vault_pay — EVM', () => {
  it('inside the rules: signs at once, and the payload is the complete x402 v2 payload', async () => {
    const r = await payW();
    if ('error' in r) throw new Error(r.error);
    expect(r.inside_rules).toBe(true);
    expect(r.header).toBe('PAYMENT-SIGNATURE');
    const p = decodeHeader(r.value);
    expect(p.x402Version).toBe(2);
    expect(p.resource.url).toBe('https://api.example.com/premium');
    expect(p.accepted.payTo).toBe(MERCHANT);
    expect(p.payload.authorization.from).toBe(EVM_ADDR);
    expect(p.payload.authorization.value).toBe('10000');
    const digest = transferDigest({ name: 'USDC', version: '2', chainId: 84532, verifyingContract: '0x036CbD53842c5426634e7929541eC2318f3dCF7e' }, p.payload.authorization);
    expect(recoverAddress(digest, p.payload.signature)).toBe(EVM_ADDR);
    // The server heard "a payment within the rules" and nothing else.
    expect(server.checks).toEqual([{ entry_id: 'w', kind: 'payment', within_rules: true, purpose: '' }]);
  });

  it('a merchant that names a different token domain does not change what is signed', async () => {
    const r = await payW('10000', { extra: { name: 'Totally USDC', version: '9' } });
    if ('error' in r) throw new Error(r.error);
    const p = decodeHeader(r.value);
    const pinned = transferDigest({ name: 'USDC', version: '2', chainId: 84532, verifyingContract: '0x036CbD53842c5426634e7929541eC2318f3dCF7e' }, p.payload.authorization);
    expect(recoverAddress(pinned, p.payload.signature)).toBe(EVM_ADDR);
  });

  it('no settings at all: every payment asks, and the ask carries the payment', async () => {
    server.entries.get('w')!.policy = null;
    const r = await payW();
    if ('error' in r) throw new Error(r.error);
    expect(r.inside_rules).toBe(false);
    const ask = server.checks[0];
    expect(ask.kind).toBe('payment');
    expect((ask.detail as Record<string, unknown>).payee).toBe(MERCHANT);
    expect((ask.detail as Record<string, unknown>).reason).toBe('payee');
    expect(server.checks[1]).toMatchObject({ kind: 'payment', approval_id: 'req-1' });
  });

  it('a $0 cap asks even for a listed payee', async () => {
    server.entries.get('w')!.policy = walletPolicy('w', { cap: '0' });
    const r = await payW('1');
    if ('error' in r) throw new Error(r.error);
    expect(r.inside_rules).toBe(false);
    expect((server.checks[0].detail as Record<string, unknown>).reason).toBe('cap');
  });

  it('the cap counts the last 24 hours on this machine, then rolls off', async () => {
    const a = await payW('10000');
    expect('error' in a ? a.error : a.inside_rules).toBe(true);
    server.owner = 'deny';
    const b = await payW('10000');
    expect('error' in b && b.code).toBe('NOT_APPROVED');
    clock += 24 * 60 * 60 * 1000 + 1;
    const c = await payW('10000');
    expect('error' in c ? c.error : c.inside_rules).toBe(true);
  });

  it('two payments at once that each fit but together do not: exactly one is inside the rules', async () => {
    server.owner = 'deny';
    const [a, b] = await Promise.all([payW('10000'), payW('10000')]);
    const inside = [a, b].filter((r) => !('error' in r) && r.inside_rules).length;
    expect(inside).toBe(1);
  });

  it('a second entry with the same wallet address counts toward the same total', async () => {
    server.entries.set('w2', { mode: 'BROKER_WALLET', cfg: { delivery: 'wallet', chain: 'evm' }, value: EVM_KEY, policy: walletPolicy('w2') });
    await payW('10000');
    server.owner = 'deny';
    const r = await pay(deps, { entryId: 'w2', purpose: 'x', paymentRequired: required402({ amount: '10000' }) });
    expect('error' in r && r.code).toBe('NOT_APPROVED');
  });

  it('a tier-2 wallet asks for every payment, inside the rules or not', async () => {
    server.entries.get('w')!.tier = '2';
    const r = await payW('1');
    if ('error' in r) throw new Error(r.error);
    expect(r.inside_rules).toBe(false);
    expect((server.checks[0].detail as Record<string, unknown>).reason).toBe('tier2');
  });

  it('an unlisted payee asks', async () => {
    const r = await payW('1', { payTo: STRANGER });
    if ('error' in r) throw new Error(r.error);
    expect((server.checks[0].detail as Record<string, unknown>).reason).toBe('payee');
  });

  it('the same payee and amount for a DIFFERENT resource is asked about on its own (round 1, F1)', async () => {
    server.owner = 'wait';
    server.entries.get('w')!.policy = null;
    await payW();
    const raw = JSON.parse(Buffer.from(required402(), 'base64').toString());
    raw.resource.url = 'https://api.example.com/other';
    await pay(deps, { entryId: 'w', purpose: 'x', paymentRequired: raw });
    expect(server.requests.size).toBe(2);
  });

  it('the agent\'s reason travels only inside the erasable detail (round 1, server F1)', async () => {
    server.entries.get('w')!.policy = null;
    await payW();
    expect(server.checks[0].purpose).toBe('');
    expect((server.checks[0].detail as Record<string, unknown>).purpose).toBe('buy data');
  });

  it('resources that differ only after 512 characters are two purchases (round 2, F3)', async () => {
    server.owner = 'wait';
    server.entries.get('w')!.policy = null;
    const base = 'https://api.example.com/' + 'x'.repeat(600);
    for (const tail of ['a', 'b']) {
      const raw = JSON.parse(Buffer.from(required402(), 'base64').toString());
      raw.resource.url = base + tail;
      await pay(deps, { entryId: 'w', purpose: 'x', paymentRequired: raw });
    }
    expect(server.requests.size).toBe(2);
  });

  it('text whose JSON escaping passes the limit is described, not shown (round 2, F2)', async () => {
    server.entries.set('k2', { mode: 'BROKER_SIGN', cfg: { delivery: 'sign' }, value: INSTALLER_SEED_B64 });
    await sign(deps, { entryId: 'k2', purpose: 'x', data: '"'.repeat(40 * 1024) });
    expect((server.checks[0].detail as Record<string, unknown>).text).toBeUndefined();
  });

  it('a v2 402 with no resource is refused (round 1, F4)', async () => {
    const raw = JSON.parse(Buffer.from(required402(), 'base64').toString());
    delete raw.resource;
    const r = await pay(deps, { entryId: 'w', purpose: 'x', paymentRequired: raw });
    expect('error' in r && r.error).toMatch(/no resource/);
  });

  it('a payment waiting on the owner does not hold up one inside the rules (round 1, B1)', async () => {
    let release!: () => void;
    server.ownerGate = new Promise<void>((r) => { release = r; });
    const waiting = payW('1', { payTo: STRANGER });          // outside: asks, and waits
    await new Promise((r) => setTimeout(r, 20));
    const inside = await Promise.race([payW('1'), new Promise((r) => setTimeout(() => r('blocked'), 2000))]);
    expect(inside !== 'blocked' && !('error' in (inside as object)) && (inside as { inside_rules: boolean }).inside_rules).toBe(true);
    release();
    const w = await waiting;
    expect('error' in w ? w.error : w.inside_rules).toBe(false);
  });

  it('a payment that waits on the owner, then is retried, does not ask twice', async () => {
    server.owner = 'wait';
    server.entries.get('w')!.policy = null;
    const a = await payW();
    expect('error' in a && a.code).toBe('WAITING');
    const b = await payW();
    expect('error' in b && b.code).toBe('WAITING');
    expect(server.requests.size).toBe(1);
    server.owner = 'approve';
    const c = await payW();
    expect('error' in c ? c.error : c.inside_rules).toBe(false);
    expect(server.requests.size).toBe(1);
  });
});

describe('vault_pay — a server that lies about approvals gets nothing', () => {
  beforeEach(() => { server.entries.get('w')!.policy = null; });
  it.each([
    ['approved with no owner seal', 'no-token'],
    ['a seal for a different request', 'other-request'],
    ['the owner was shown a different amount', 'tamper-detail'],
  ] as const)('%s', async (_name, lie) => {
    server.lie = lie;
    const before = server.decrypts;
    const r = await payW();
    expect('error' in r && r.code).toBe('BAD_APPROVAL');
    expect(server.decrypts).toBe(before); // the key was never decrypted
    expect(deps.state.spentLastDay('evm', EVM_ADDR)).toBe(0n);
  });
  it('a server that allows an ask outright', async () => {
    server.lie = 'allow-unasked';
    const r = await payW();
    expect('error' in r && r.code).toBe('BAD_SERVER');
  });
  it('an approval cannot be used twice', async () => {
    const r1 = await payW();
    expect('error' in r1).toBe(false);
    // Replay: the broker sees the same request id again.
    expect(deps.state.isUsed('req-1')).toBe(true);
  });
});

describe('vault_pay — settings', () => {
  const refused = async () => { const r = await payW(); return 'error' in r ? r.code : 'signed'; };
  it('settings for another entry are refused', async () => {
    server.entries.get('w')!.policy = walletPolicy('other');
    expect(await refused()).toBe('BAD_POLICY');
  });
  it('an unknown field is refused', async () => {
    server.entries.get('w')!.policy = walletPolicy('w', { extra: { surprise: 1 } });
    expect(await refused()).toBe('BAD_POLICY');
  });
  it('settings encrypted with another key are refused', async () => {
    server.entries.get('w')!.policy = walletPolicy('w', {}, OTHER_KEY);
    expect(await refused()).toBe('BAD_POLICY');
  });
  it('a lower version than one seen is refused; the same version with other content too', async () => {
    server.entries.get('w')!.policy = walletPolicy('w', { version: 5, cap: '1' });
    server.owner = 'deny';
    await payW();
    server.entries.get('w')!.policy = walletPolicy('w', { version: 4 });
    expect(await refused()).toBe('BAD_POLICY');
    server.entries.get('w')!.policy = walletPolicy('w', { version: 5, cap: '999999999' });
    expect(await refused()).toBe('BAD_POLICY');
  });
  it('a mistyped wallet address is refused before signing', async () => {
    server.entries.get('w')!.policy = walletPolicy('w', { address: STRANGER });
    expect(await refused()).toBe('ADDRESS_MISMATCH');
  });
});

describe('vault_pay — the record fails closed', () => {
  it('a corrupt ledger refuses', async () => {
    fs.writeFileSync(deps.state.file, '{not json');
    expect(await payW().then((r) => 'error' in r && r.code)).toBe('LEDGER');
  });
  it('a ledger that cannot be written returns no header', async () => {
    const blocker = path.join(dir, 'blocker');
    fs.writeFileSync(blocker, 'x');
    deps.state = new SigningState(path.join(blocker, 'wallet-ledger.json'), () => clock);
    await expect(payW()).rejects.toThrow();
  });
});

describe('vault_pay — wrong kinds and bad offers', () => {
  it('a signing key cannot pay, and a wallet cannot sign', async () => {
    server.entries.set('k', { mode: 'BROKER_SIGN', cfg: { delivery: 'sign' }, value: INSTALLER_SEED_B64 });
    const p = await pay(deps, { entryId: 'k', purpose: 'x', paymentRequired: required402() });
    expect('error' in p && p.code).toBe('WRONG_MODE');
    const s = await sign(deps, { entryId: 'w', purpose: 'x', data: 'hello' });
    expect('error' in s && s.code).toBe('WRONG_MODE');
  });
  it.each([
    ['negative', '-1'], ['fractional', '1.5'], ['exponent', '1e6'], ['leading zero', '010'],
    ['19 digits', '1000000000000000000'], ['zero', '0'],
  ])('amount %s is refused', async (_n, amount) => {
    expect(await payW(amount).then((r) => 'error' in r && r.code)).toBe('BAD_REQUEST');
  });
  it.each([0, -1, 1.5, 3601, undefined])('maxTimeoutSeconds %s is refused', (t) => {
    const raw = JSON.parse(Buffer.from(required402(), 'base64').toString());
    raw.accepts[0].maxTimeoutSeconds = t;
    expect(() => selectOffer(parsePaymentRequired(raw))).toThrow();
  });
  it('USDC at a different contract, an unknown network, and Permit2 are refused', async () => {
    expect(await payW('1', { asset: STRANGER }).then((r) => 'error' in r && r.code)).toBe('BAD_REQUEST');
    expect(await payW('1', { network: 'eip155:1' }).then((r) => 'error' in r && r.code)).toBe('BAD_REQUEST');
    expect(await payW('1', { extra: { assetTransferMethod: 'permit2' } }).then((r) => 'error' in r && r.code)).toBe('BAD_REQUEST');
  });
  it('two payable offers without accept_index are refused; with it, the chosen one is paid', async () => {
    const raw = JSON.parse(Buffer.from(required402(), 'base64').toString());
    raw.accepts.push({ ...raw.accepts[0], amount: '5000' });
    const a = await pay(deps, { entryId: 'w', purpose: 'x', paymentRequired: raw });
    expect('error' in a && a.error).toMatch(/accept_index/);
    const b = await pay(deps, { entryId: 'w', purpose: 'x', paymentRequired: raw, acceptIndex: 1 });
    if ('error' in b) throw new Error(b.error);
    expect(b.amount_usdc).toBe('0.005');
    const c = await pay(deps, { entryId: 'w', purpose: 'x', paymentRequired: raw, acceptIndex: 7 });
    expect('error' in c && c.error).toMatch(/out of range/);
  });
  it('a v1 402 gets a v1 X-PAYMENT payload', async () => {
    const v1 = { x402Version: 1, accepts: [{ scheme: 'exact', network: 'base-sepolia', maxAmountRequired: '10000',
      resource: 'https://api.example.com/x', payTo: MERCHANT, maxTimeoutSeconds: 60,
      asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', extra: { name: 'USDC', version: '2' } }] };
    const r = await pay(deps, { entryId: 'w', purpose: 'x', paymentRequired: v1 });
    if ('error' in r) throw new Error(r.error);
    expect(r.header).toBe('X-PAYMENT');
    const p = decodeHeader(r.value);
    expect(p).toMatchObject({ x402Version: 1, scheme: 'exact', network: 'base-sepolia' });
    expect(p.payload.authorization.to).toBe(MERCHANT);
  });
});

describe('vault_pay — Solana', () => {
  beforeEach(() => {
    server.entries.set('s', { mode: 'BROKER_WALLET', cfg: { delivery: 'wallet', chain: 'solana' }, value: SOL_KEY,
      policy: gcm(VAULT_KEY, JSON.stringify({ v: 1, entry_id: 's', version: 1, kind: 'wallet',
        wallet: { address: SOL_ADDR, networks: ['solana-devnet'], daily_cap: '1000000', payees: [{ address: SOL_MERCHANT }] } })) });
  });
  const payS = (extra?: Record<string, unknown>) => pay(deps, { entryId: 's', purpose: 'x',
    paymentRequired: required402({ network: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1', extra: extra ?? { feePayer: FEE_PAYER, memo: 'inv-42' } }) });

  it('builds the facilitator layout, with the merchant memo, the fee payer slot empty and the wallet signed', async () => {
    const r = await payS();
    if ('error' in r) throw new Error(r.error);
    const tx = Buffer.from(decodeHeader(r.value).payload.transaction, 'base64');
    expect(tx[0]).toBe(2);
    expect(tx.subarray(1, 65).every((b) => b === 0)).toBe(true);
    const message = tx.subarray(129);
    expect(ed25519.verify(tx.subarray(65, 129), message, parseSolanaSecretKey(SOL_KEY).publicKey)).toBe(true);
    expect(message.includes(Buffer.from('inv-42'))).toBe(true);
    // destination is ATA(payTo, mint) for devnet USDC
    const dest = associatedTokenAddress(SOL_MERCHANT, '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU');
    expect(message.toString('hex')).toContain(Buffer.from(require58(dest)).toString('hex'));
  });
  it('a merchant that names this wallet as the fee payer is refused', async () => {
    const r = await payS({ feePayer: SOL_ADDR });
    expect('error' in r && r.error).toMatch(/network fee/);
  });
  it('a memo over 256 bytes is refused', async () => {
    const r = await payS({ feePayer: FEE_PAYER, memo: 'x'.repeat(257) });
    expect('error' in r && r.code).toBe('BAD_REQUEST');
  });
});

function require58(s: string): Uint8Array {
  // tiny local decode, so this test does not lean on the module it checks
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n;
  for (const c of s) n = n * 58n + BigInt(A.indexOf(c));
  const out: number[] = [];
  while (n > 0n) { out.unshift(Number(n & 0xffn)); n >>= 8n; }
  return new Uint8Array(out);
}

describe('vault_sign', () => {
  beforeEach(() => {
    server.entries.set('k', { mode: 'BROKER_SIGN', cfg: { delivery: 'sign' }, value: INSTALLER_SEED_B64 });
  });
  it('signs the installer-key format after approval; the signature verifies', async () => {
    const r = await sign(deps, { entryId: 'k', purpose: 'sign onboard.py', data: 'print("hi")\n' });
    if ('error' in r) throw new Error(r.error);
    expect(r.algorithm).toBe('ed25519');
    const pub = ed25519.getPublicKey(new Uint8Array(Buffer.alloc(32, 5)));
    expect(r.public_key).toBe(Buffer.from(pub).toString('base64'));
    expect(ed25519.verify(Buffer.from(r.signature, 'base64'), Buffer.from('print("hi")\n'), pub)).toBe(true);
    const ask = server.checks[0];
    expect(ask.kind).toBe('signature');
    expect((ask.detail as Record<string, unknown>).text).toBe('print("hi")\n');
  });
  it('a denial never decrypts the key', async () => {
    server.owner = 'deny';
    const before = server.decrypts;
    const r = await sign(deps, { entryId: 'k', purpose: 'x', data: 'abc' });
    expect('error' in r && r.code).toBe('NOT_APPROVED');
    expect(server.decrypts).toBe(before);
  });
  it('binary data is described, not shown', async () => {
    await sign(deps, { entryId: 'k', purpose: 'x', data: '00ff10', encoding: 'hex' });
    expect((server.checks[0].detail as Record<string, unknown>).text).toBeUndefined();
  });
  it('PEM ed25519, P-256 and RSA verify', async () => {
    for (const type of ['ed25519', 'ec', 'rsa'] as const) {
      const { privateKey, publicKey } = type === 'ec'
        ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
        : type === 'rsa' ? crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }) : crypto.generateKeyPairSync('ed25519');
      server.entries.get('k')!.value = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
      const r = await sign(deps, { entryId: 'k', purpose: 'x', data: `data-${type}` });
      if ('error' in r) throw new Error(r.error);
      expect(crypto.verify(type === 'ed25519' ? null : 'sha256', Buffer.from(`data-${type}`), publicKey, Buffer.from(r.signature, 'base64'))).toBe(true);
    }
  });
  it('an OpenSSH key and a secp256k1 key are refused', async () => {
    server.entries.get('k')!.value = '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----';
    expect(await sign(deps, { entryId: 'k', purpose: 'x', data: 'a' }).then((r) => 'error' in r && r.code)).toBe('WRONG_KIND');
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    server.entries.get('k')!.value = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
    expect(await sign(deps, { entryId: 'k', purpose: 'x', data: 'b' }).then((r) => 'error' in r && r.error)).toMatch(/wallet/);
  });
  it('a seal for different bytes is refused (the agent swapped the data after approval)', async () => {
    server.owner = (r) => { r.detail = { ...r.detail!, data_sha256: 'f'.repeat(64) }; server.ownerApproves(r); };
    const r = await sign(deps, { entryId: 'k', purpose: 'x', data: 'abc' });
    expect('error' in r && r.code).toBe('BAD_APPROVAL');
  });
});

describe('stamp approval', () => {
  const recipe = { mac: 'hmac-sha256', key: 'utf8', message: [{ var: 'body' }], encoding: 'hex', place: [{ in: 'header', name: 'x-sig', value: '{stamp}' }] };
  const sha = crypto.createHash('sha256').update(canonicalJson(recipe)).digest('hex');
  const policy = (approved: Array<{ recipe_sha256: string; origin: string }>) =>
    gcm(VAULT_KEY, JSON.stringify({ v: 1, entry_id: 'st', version: 1, kind: 'stamped', stamped: { approved } }));
  const run = async (origin: string, recipeSha = sha) => approveStamp(deps, {
    entryId: 'st', s: await server.api().getSecret('st') as never, vaultKey: new Uint8Array(VAULT_KEY),
    origin, recipe, recipeSha, summary: 'x', purpose: 'p',
  });
  beforeEach(() => {
    server.entries.set('st', { mode: 'BROKER_HTTP', cfg: { delivery: 'http', credential_binding: { in: 'stamp' } }, value: 'k' });
  });
  it('first use asks; an approved (recipe, origin) does not; another origin or recipe asks', async () => {
    expect(await run('https://api.example.com:443')).toBeNull();
    expect(server.requests.size).toBe(1);
    server.entries.get('st')!.policy = policy([{ recipe_sha256: sha, origin: 'https://api.example.com:443' }]);
    expect(await run('https://api.example.com:443')).toBeNull();
    expect(server.requests.size).toBe(1);
    expect(await run('https://evil.example.com:443')).toBeNull();
    expect(server.requests.size).toBe(2);
  });
  it('a denial refuses the call', async () => {
    server.owner = 'deny';
    expect((await run('https://api.example.com:443'))?.code).toBe('NOT_APPROVED');
  });
  it('OAuth 1.0a: one approval covers the default and the explicit default (SPEC-oauth1, check 10)', async () => {
    const checked = (raw: unknown) => { const r = validateRecipe(raw); if (!r.ok) throw new Error(r.reason); return r.recipe; };
    const implicit = checked({ builtin: 'oauth1' });
    const explicit = checked({ builtin: 'oauth1', signature_method: 'HMAC-SHA1' });
    const ask = async (recipe: Recipe) => approveStamp(deps, {
      entryId: 'st', s: await server.api().getSecret('st') as never, vaultKey: new Uint8Array(VAULT_KEY),
      origin: 'https://api.x.com:443', recipe, recipeSha: recipeSha256(recipe), summary: describeRecipe(recipe), purpose: 'post',
    });
    expect(await ask(implicit)).toBeNull();
    expect(server.requests.size).toBe(1);
    server.entries.get('st')!.policy = policy([{ recipe_sha256: recipeSha256(implicit), origin: 'https://api.x.com:443' }]);
    expect(await ask(explicit)).toBeNull();
    expect(server.requests.size).toBe(1);
    expect(await ask(checked({ builtin: 'oauth1', signature_method: 'HMAC-SHA256' }))).toBeNull();
    expect(server.requests.size).toBe(2);
  });
});
