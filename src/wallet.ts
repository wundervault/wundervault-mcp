/**
 * The owner's rules for a key, the owner's approvals, and this machine's record of what was
 * signed — everything the broker consults before it signs a payment, a blob or a stamp.
 *
 * THREE THINGS THE SERVER IS NOT TRUSTED WITH
 *
 * 1. The rules (cap, payees, approved recipes). The owner's browser encrypts them with the
 *    agent's vault key, so the server stores bytes it can neither read nor rewrite. It can
 *    still serve an OLD copy — so the broker remembers the highest version it has seen,
 *    and the content it had, and refuses anything older or different at that version.
 * 2. "The owner approved". A server that only had to say `approved` could spend the
 *    wallet. The owner's browser seals each approval with the vault key and binds it to the
 *    exact operation it displayed (a commitment); the broker opens the seal and compares.
 * 3. The running total. It lives here, on this machine, in the broker's own account.
 *
 * See SPEC-1.0-signing.md §B, §C14–C17, §D18a.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalJson } from './opdef.js';
import { decryptSecretContent } from './crypto.js';
import { defaultStorePath } from './network-store.js';
import { NETWORKS, UINT_STRING, isAddressFor, sameAddress, type Chain, type NetworkName } from './x402.js';

// ── policy ─────────────────────────────────────────────────────────────────

export interface WalletRules {
  address: string;
  networks: NetworkName[];
  dailyCap: bigint;
  payees: Array<{ address: string; label?: string }>;
  solanaRpc?: string;
}

export interface StampRules {
  approved: Array<{ recipe_sha256: string; origin: string; label?: string }>;
}

export interface Policy {
  entryId: string;
  version: number;
  kind: 'wallet' | 'stamped';
  wallet?: WalletRules;
  stamped?: StampRules;
  /** sha256 of the decrypted plaintext — what "the same version" is compared by. */
  digest: string;
}

export type PolicyCheck = { ok: true; policy: Policy | null } | { ok: false; reason: string };

const MAX_LIST = 200;
const LABEL = (v: unknown) => v === undefined || (typeof v === 'string' && v.length <= 64);

function only(obj: Record<string, unknown>, allowed: string[]): string | null {
  const extra = Object.keys(obj).filter((k) => !allowed.includes(k));
  return extra.length ? `unknown field${extra.length > 1 ? 's' : ''} ${extra.sort().join(', ')}` : null;
}

/** https only, no credentials in it, a real host. */
function isRpcUrl(v: unknown): v is string {
  if (typeof v !== 'string' || v.length > 256) return false;
  try {
    const u = new URL(v);
    return u.protocol === 'https:' && !!u.hostname && !u.username && !u.password;
  } catch { return false; }
}

/**
 * Decrypt and check an entry's policy. ABSENT is a valid answer (`policy: null`) and means
 * "no rules": nothing is inside them. PRESENT BUT WRONG is a refusal — never the default,
 * because "the owner's rules could not be read" and "the owner set no rules" are different
 * facts, and the second is not always the stricter one for every reader of this code.
 */
export function readPolicy(args: {
  ciphertext?: string | null; nonce?: string | null; vaultKey: Uint8Array;
  entryId: string; kind: 'wallet' | 'stamped'; chain?: Chain;
}): PolicyCheck {
  const { ciphertext, nonce, vaultKey, entryId, kind, chain } = args;
  if (!ciphertext && !nonce) return { ok: true, policy: null };
  if (!ciphertext || !nonce) return { ok: false, reason: 'half of the settings is missing' };
  let plain: Uint8Array;
  try { plain = decryptSecretContent(vaultKey, ciphertext, nonce); } catch {
    return { ok: false, reason: 'the settings do not decrypt with this agent\'s vault key' };
  }
  let p: Record<string, unknown>;
  try { p = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain)); } catch {
    return { ok: false, reason: 'the settings are not readable' };
  }
  if (!p || typeof p !== 'object' || Array.isArray(p)) return { ok: false, reason: 'the settings are not an object' };
  const unknown = only(p, ['v', 'entry_id', 'version', 'kind', 'wallet', 'stamped']);
  if (unknown) return { ok: false, reason: `the settings have ${unknown}` };
  if (p.v !== 1) return { ok: false, reason: 'the settings are a version this broker does not know' };
  // Bound to the entry INSIDE the ciphertext: the server could otherwise serve one entry's
  // permissive settings as another's.
  if (p.entry_id !== entryId) return { ok: false, reason: 'the settings belong to a different entry' };
  if (typeof p.version !== 'number' || !Number.isInteger(p.version) || p.version < 1) {
    return { ok: false, reason: 'the settings have no valid version number' };
  }
  if (p.kind !== kind) return { ok: false, reason: `the settings are for a ${String(p.kind)} key, not a ${kind} key` };
  const policy: Policy = {
    entryId, version: p.version, kind,
    digest: createHash('sha256').update(plain).digest('hex'),
  };
  if (kind === 'wallet') {
    if (p.stamped !== undefined) return { ok: false, reason: 'wallet settings carry stamp approvals' };
    const w = p.wallet as Record<string, unknown> | undefined;
    if (!w || typeof w !== 'object' || Array.isArray(w)) return { ok: false, reason: 'the wallet settings are missing' };
    const unk = only(w, ['address', 'networks', 'daily_cap', 'payees', 'solana_rpc']);
    if (unk) return { ok: false, reason: `the wallet settings have ${unk}` };
    if (!chain || !isAddressFor(chain, w.address)) return { ok: false, reason: 'the wallet address is not an address on this chain' };
    if (!Array.isArray(w.networks) || w.networks.length > 4
        || !w.networks.every((n) => typeof n === 'string' && n in NETWORKS && NETWORKS[n as NetworkName].chain === chain)) {
      return { ok: false, reason: 'the wallet settings name a network this wallet cannot use' };
    }
    if (typeof w.daily_cap !== 'string' || !UINT_STRING.test(w.daily_cap)) {
      return { ok: false, reason: 'the daily limit is not a whole number of base units' };
    }
    if (!Array.isArray(w.payees) || w.payees.length > MAX_LIST) return { ok: false, reason: 'the payee list is not a list' };
    const payees: WalletRules['payees'] = [];
    for (const raw of w.payees) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, reason: 'a payee is not an object' };
      const r = raw as Record<string, unknown>;
      if (only(r, ['address', 'label']) || !isAddressFor(chain, r.address) || !LABEL(r.label)) {
        return { ok: false, reason: 'a payee is not a valid address on this chain' };
      }
      payees.push({ address: r.address as string, ...(r.label ? { label: r.label as string } : {}) });
    }
    if (w.solana_rpc !== undefined && (chain !== 'solana' || !isRpcUrl(w.solana_rpc))) {
      return { ok: false, reason: 'the Solana network service must be an https address' };
    }
    policy.wallet = {
      address: w.address as string, networks: [...new Set(w.networks as NetworkName[])],
      dailyCap: BigInt(w.daily_cap), payees,
      ...(w.solana_rpc ? { solanaRpc: w.solana_rpc as string } : {}),
    };
  } else {
    if (p.wallet !== undefined) return { ok: false, reason: 'stamp settings carry wallet rules' };
    const st = p.stamped as Record<string, unknown> | undefined;
    if (!st || typeof st !== 'object' || Array.isArray(st)) return { ok: false, reason: 'the stamp settings are missing' };
    const unk = only(st, ['approved']);
    if (unk) return { ok: false, reason: `the stamp settings have ${unk}` };
    if (!Array.isArray(st.approved) || st.approved.length > MAX_LIST) return { ok: false, reason: 'the approved list is not a list' };
    const approved: StampRules['approved'] = [];
    for (const raw of st.approved) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, reason: 'an approval is not an object' };
      const r = raw as Record<string, unknown>;
      if (only(r, ['recipe_sha256', 'origin', 'label']) || typeof r.recipe_sha256 !== 'string'
          || !/^[0-9a-f]{64}$/.test(r.recipe_sha256) || typeof r.origin !== 'string'
          || !/^https:\/\/[a-z0-9.-]{1,253}:[0-9]{1,5}$/.test(r.origin) || !LABEL(r.label)) {
        return { ok: false, reason: 'an approved recipe is malformed' };
      }
      approved.push({ recipe_sha256: r.recipe_sha256, origin: r.origin, ...(r.label ? { label: r.label as string } : {}) });
    }
    policy.stamped = { approved };
  }
  return { ok: true, policy };
}

// ── commitments and owner tokens ───────────────────────────────────────────

export type ApprovalKind = 'payment' | 'signature' | 'recipe';

/** sha256 of the canonical JSON of what the owner was shown. The dashboard computes the same. */
export function commitment(fields: Record<string, string | number>): string {
  return createHash('sha256').update(canonicalJson(fields)).digest('hex');
}

export interface OwnerToken { requestId: string; entryId: string; kind: ApprovalKind; commitment: string; addPayee: boolean }

/**
 * Open the owner's seal on an approval. Returns why not, or the token.
 *
 * Only something holding the agent's vault key can produce one: the owner's unlocked
 * browser, or this broker. The server holds neither, so a server that marks a request
 * approved without the owner produces a status with nothing here that opens.
 */
export function openOwnerToken(raw: unknown, vaultKey: Uint8Array, expect: {
  requestId: string; entryId: string; kind: ApprovalKind; commitment: string;
}): { ok: true; token: OwnerToken } | { ok: false; reason: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, reason: 'the approval carries no owner seal' };
  const t = raw as Record<string, unknown>;
  if (typeof t.ciphertext !== 'string' || typeof t.nonce !== 'string') return { ok: false, reason: 'the approval carries no owner seal' };
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(new TextDecoder().decode(decryptSecretContent(vaultKey, t.ciphertext, t.nonce)));
  } catch { return { ok: false, reason: 'the owner seal on the approval does not open' }; }
  if (!body || body.v !== 1) return { ok: false, reason: 'the owner seal is not a version this broker knows' };
  if (body.request_id !== expect.requestId) return { ok: false, reason: 'the owner seal is for a different request' };
  if (body.entry_id !== expect.entryId) return { ok: false, reason: 'the owner seal is for a different key' };
  if (body.kind !== expect.kind) return { ok: false, reason: 'the owner seal is for a different kind of approval' };
  if (body.commitment !== expect.commitment) {
    return { ok: false, reason: 'what the owner approved is not what is about to be signed' };
  }
  return { ok: true, token: {
    requestId: expect.requestId, entryId: expect.entryId, kind: expect.kind,
    commitment: expect.commitment, addPayee: body.add_payee === true,
  } };
}

// ── this machine's record ──────────────────────────────────────────────────

export interface Payment {
  at: number; entry_id: string; address: string; network: string; payee: string;
  amount: string; how: 'inside' | 'approved'; purpose: string;
}

interface StateFile {
  version: 1;
  payments: Payment[];
  /** Highest policy version seen per entry, and the content it had. */
  policies: Record<string, { version: number; digest: string }>;
  /** Approval request ids already used, and when. */
  used: Record<string, number>;
  /** Outside-rules requests still waiting on the owner, by commitment. */
  pending: Record<string, { request_id: string; at: number }>;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const KEEP_PAYMENTS_MS = 90 * DAY_MS;
const KEEP_USED_MS = 2 * DAY_MS;

export function defaultLedgerPath(): string {
  return process.env.WUNDERVAULT_WALLET_LEDGER || path.join(path.dirname(defaultStorePath()), 'wallet-ledger.json');
}

export class LedgerUnreadable extends Error {
  constructor(file: string) {
    super(`The broker's local payment record (${file}) cannot be read, so it will not sign `
      + 'anything inside the rules or accept an approval until it can. Removing the file '
      + 'resets this machine\'s daily total and approval history.');
  }
}

/**
 * The broker's local record. Reads fail CLOSED: a file that exists and does not parse is
 * not an empty history — treating it as one would hand back the whole daily allowance to
 * anybody who could corrupt one file.
 */
export class SigningState {
  private locks = new Map<string, Promise<unknown>>();

  constructor(
    public readonly file: string = defaultLedgerPath(),
    private readonly now: () => number = Date.now,
  ) {}

  private read(): StateFile {
    if (!fs.existsSync(this.file)) return { version: 1, payments: [], policies: {}, used: {}, pending: {} };
    let parsed: StateFile;
    try { parsed = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { throw new LedgerUnreadable(this.file); }
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.payments)
        || typeof parsed.policies !== 'object' || typeof parsed.used !== 'object' || typeof parsed.pending !== 'object'
        || !parsed.payments.every((p) => p && typeof p.amount === 'string' && UINT_STRING.test(p.amount)
          && typeof p.address === 'string' && typeof p.at === 'number')) {
      throw new LedgerUnreadable(this.file);
    }
    return parsed;
  }

  /** Write-then-rename. Throws if it cannot write — the caller must not hand out a signature then. */
  private write(s: StateFile): void {
    const t = this.now();
    s.payments = s.payments.filter((p) => t - p.at < KEEP_PAYMENTS_MS);
    for (const [k, at] of Object.entries(s.used)) if (t - at > KEEP_USED_MS) delete s.used[k];
    for (const [k, v] of Object.entries(s.pending)) if (t - v.at > DAY_MS) delete s.pending[k];
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const tmp = `${this.file}.tmp-${process.pid}`;
    // Synced before the rename and the directory after it: a header is handed out only once
    // its row would survive a power cut (round 2, B2).
    const fd = fs.openSync(tmp, 'w', 0o600);
    try { fs.writeSync(fd, JSON.stringify(s)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, this.file);
    try { const dfd = fs.openSync(path.dirname(this.file), 'r'); try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); } } catch { /* not every platform syncs a directory */ }
  }

  /** Run `fn` with nobody else checking or spending against `key` in this broker. */
  async exclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(key) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => { release = r; });
    const chained = prev.then(() => mine);
    this.locks.set(key, chained);
    await prev.catch(() => undefined);
    try { return await fn(); } finally {
      release();
      if (this.locks.get(key) === chained) this.locks.delete(key);
    }
  }

  /** Refuse a policy older than, or different from, the newest one this machine has seen. */
  acceptPolicy(p: Policy): string | null {
    const s = this.read();
    const seen = s.policies[p.entryId];
    if (seen) {
      if (p.version < seen.version) return `the settings went backwards (version ${p.version}, this machine has seen ${seen.version})`;
      if (p.version === seen.version && p.digest !== seen.digest) {
        return `two different settings both claim version ${p.version}`;
      }
      if (p.version === seen.version) return null;
    }
    s.policies[p.entryId] = { version: p.version, digest: p.digest };
    this.write(s);
    return null;
  }

  /** What this machine signed from `address` in the last 24 hours, on any network. */
  spentLastDay(chain: Chain, address: string): bigint {
    const s = this.read();
    const since = this.now() - DAY_MS;
    return s.payments
      .filter((p) => p.at > since && sameAddress(chain, p.address, address))
      .reduce((n, p) => n + BigInt(p.amount), 0n);
  }

  record(p: Omit<Payment, 'at'>): void {
    const s = this.read();
    s.payments.push({ ...p, at: this.now() });
    this.write(s);
  }

  isUsed(requestId: string): boolean {
    return Object.prototype.hasOwnProperty.call(this.read().used, requestId);
  }

  markUsed(requestId: string): void {
    const s = this.read();
    s.used[requestId] = this.now();
    this.write(s);
  }

  pendingFor(commit: string): string | null {
    const v = this.read().pending[commit];
    return v && this.now() - v.at < DAY_MS ? v.request_id : null;
  }

  setPending(commit: string, requestId: string | null): void {
    const s = this.read();
    if (requestId) s.pending[commit] = { request_id: requestId, at: this.now() };
    else delete s.pending[commit];
    this.write(s);
  }
}
