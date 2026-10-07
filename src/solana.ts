/**
 * Solana signing for x402 payments: one USDC TransferChecked, built and signed in the broker.
 *
 * The broker builds the whole transaction itself rather than signing one the agent hands
 * it. Signing a transaction somebody else assembled means parsing it well enough to be sure
 * it only moves the amount it claims to — and an x402 transaction is small enough that
 * building it is simpler than proving a stranger's is safe. The layout matches the x402
 * reference client and the facilitator rules in scheme_exact_svm.md:
 *
 *   SetComputeUnitLimit · SetComputeUnitPrice · TransferChecked · Memo
 *
 * with the facilitator as fee payer, whose signature slot is left empty for it to fill.
 *
 * See SPEC-1.0-signing.md §C12.
 */
import { createHash, randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';

export const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const ATA_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
export const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
export const COMPUTE_UNIT_LIMIT = 20_000;
export const COMPUTE_UNIT_PRICE_MICROLAMPORTS = 1n;
export const MAX_MEMO_BYTES = 256;

// ── base58 ──────────────────────────────────────────────────────────────────
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const INDEX = new Map([...ALPHABET].map((c, i) => [c, i]));

export function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = '1' + out; }
  return out;
}

export function base58Decode(s: string): Uint8Array {
  if (!s || s.length > 128) throw new Error('not base58');
  let n = 0n;
  for (const c of s) {
    const v = INDEX.get(c);
    if (v === undefined) throw new Error('not base58');
    n = n * 58n + BigInt(v);
  }
  const body: number[] = [];
  while (n > 0n) { body.unshift(Number(n & 0xffn)); n >>= 8n; }
  let zeros = 0;
  for (const c of s) { if (c !== '1') break; zeros++; }
  return new Uint8Array([...new Array(zeros).fill(0), ...body]);
}

/** A 32-byte public key in base58, or throws. */
export function decodeAddress(s: unknown): Uint8Array {
  if (typeof s !== 'string') throw new Error('not a Solana address');
  const b = base58Decode(s);
  if (b.length !== 32 || base58Encode(b) !== s) throw new Error(`not a Solana address: ${s.slice(0, 64)}`);
  return b;
}

export function isSolanaAddress(s: unknown): s is string {
  try { decodeAddress(s); return true; } catch { return false; }
}

// ── keys ────────────────────────────────────────────────────────────────────
export interface SolanaKey { seed: Uint8Array; publicKey: Uint8Array; address: string }

/**
 * A wallet secret, in the three spellings Solana tools export: base58 of the 64-byte
 * secret key (Phantom, Solflare), base58 of the 32-byte seed, or the JSON array of 64
 * numbers solana-keygen writes. A 64-byte key whose second half is not the seed's public
 * key is refused: it is either corrupt or not what it claims to be.
 */
export function parseSolanaSecretKey(raw: string): SolanaKey {
  const s = raw.trim();
  let bytes: Uint8Array;
  if (s.startsWith('[')) {
    let arr: unknown;
    try { arr = JSON.parse(s); } catch { throw new Error('this is not a Solana secret key'); }
    if (!Array.isArray(arr) || arr.length !== 64 || !arr.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
      throw new Error('a Solana keypair file is a JSON array of 64 numbers');
    }
    bytes = new Uint8Array(arr as number[]);
  } else {
    try { bytes = base58Decode(s); } catch { throw new Error('this is not a Solana secret key (expected base58 or a keypair file)'); }
  }
  if (bytes.length !== 64 && bytes.length !== 32) {
    throw new Error('a Solana secret key is 64 bytes (or a 32-byte seed)');
  }
  const seed = bytes.slice(0, 32);
  const publicKey = ed25519.getPublicKey(seed);
  if (bytes.length === 64 && Buffer.compare(Buffer.from(publicKey), Buffer.from(bytes.subarray(32))) !== 0) {
    throw new Error("this Solana secret key's two halves do not match");
  }
  return { seed, publicKey, address: base58Encode(publicKey) };
}

// ── program-derived addresses ───────────────────────────────────────────────
function onCurve(b: Uint8Array): boolean {
  try { ed25519.Point.fromBytes(b); return true; } catch { return false; }
}

/** findProgramAddress: the first bump, from 255 down, whose hash is not a curve point. */
export function findProgramAddress(seeds: Uint8Array[], programId: Uint8Array): Uint8Array {
  for (let bump = 255; bump >= 0; bump--) {
    const h = createHash('sha256');
    for (const s of seeds) h.update(s);
    h.update(Uint8Array.of(bump)).update(programId).update('ProgramDerivedAddress');
    const out = new Uint8Array(h.digest());
    if (!onCurve(out)) return out;
  }
  throw new Error('no program address found');
}

/** The associated token account that holds `mint` for `owner`. */
export function associatedTokenAddress(owner: string, mint: string, tokenProgram = TOKEN_PROGRAM): string {
  return base58Encode(findProgramAddress(
    [decodeAddress(owner), decodeAddress(tokenProgram), decodeAddress(mint)], decodeAddress(ATA_PROGRAM)));
}

// ── wire format ─────────────────────────────────────────────────────────────
function compactU16(n: number): number[] {
  if (n < 0 || n > 0xffff) throw new Error('compact-u16 out of range');
  const out: number[] = [];
  let v = n;
  for (;;) {
    let b = v & 0x7f;
    v >>= 7;
    if (v === 0) { out.push(b); return out; }
    b |= 0x80;
    out.push(b);
  }
}

function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

function u64le(n: bigint): number[] {
  if (n < 0n || n >= (1n << 64n)) throw new Error('u64 out of range');
  const out: number[] = [];
  let v = n;
  for (let i = 0; i < 8; i++) { out.push(Number(v & 0xffn)); v >>= 8n; }
  return out;
}

export interface TransferPlan {
  wallet: string;
  payTo: string;
  mint: string;
  amount: bigint;
  decimals: number;
  feePayer: string;
  recentBlockhash: string;
  memo: Uint8Array;
}

/**
 * The v0 message for one x402 payment. Accounts are ordered as the runtime requires —
 * fee payer, other signers, writable, read-only — and the header says so.
 */
export function buildTransferMessage(p: TransferPlan): Uint8Array {
  const source = associatedTokenAddress(p.wallet, p.mint);
  const destination = associatedTokenAddress(p.payTo, p.mint);
  const keys = [
    p.feePayer,            // 0  writable signer (the facilitator)
    p.wallet,              // 1  read-only signer (the authority)
    source,                // 2  writable
    destination,           // 3  writable
    p.mint,                // 4  read-only
    TOKEN_PROGRAM,         // 5  read-only
    COMPUTE_BUDGET_PROGRAM,// 6  read-only
    MEMO_PROGRAM,          // 7  read-only
  ];
  // Every account must be distinct, or the indices below point at the wrong thing — and a
  // fee payer that is also the wallet, a token account or a program is exactly the trick
  // the facilitator rules exist to stop.
  if (new Set(keys).size !== keys.length) throw new Error('the payment names the same account twice');
  if (p.memo.length > MAX_MEMO_BYTES) throw new Error(`the memo is longer than ${MAX_MEMO_BYTES} bytes`);
  if (p.amount <= 0n) throw new Error('the amount must be positive');

  const ix = (program: number, accounts: number[], data: number[]) =>
    [program, ...compactU16(accounts.length), ...accounts, ...compactU16(data.length), ...data];

  const instructions = [
    ix(6, [], [2, ...u32le(COMPUTE_UNIT_LIMIT)]),
    ix(6, [], [3, ...u64le(COMPUTE_UNIT_PRICE_MICROLAMPORTS)]),
    ix(5, [2, 4, 3, 1], [12, ...u64le(p.amount), p.decimals]),
    ix(7, [], [...p.memo]),
  ];

  const bytes: number[] = [
    0x80,          // version 0
    2, 1, 4,       // 2 signatures required; 1 of them read-only; 4 read-only unsigned
    ...compactU16(keys.length),
  ];
  for (const k of keys) bytes.push(...decodeAddress(k));
  bytes.push(...decodeAddress(p.recentBlockhash));
  bytes.push(...compactU16(instructions.length));
  for (const i of instructions) bytes.push(...i);
  bytes.push(...compactU16(0)); // no address lookup tables
  return new Uint8Array(bytes);
}

/** The wire transaction, base64: two signature slots (fee payer empty, wallet signed), then the message. */
export function signTransfer(message: Uint8Array, key: SolanaKey): string {
  const signature = ed25519.sign(message, key.seed);
  const out = new Uint8Array(1 + 64 * 2 + message.length);
  out[0] = 2;
  out.set(signature, 1 + 64);
  out.set(message, 1 + 128);
  return Buffer.from(out).toString('base64');
}

/** 16 random bytes, hex — the reference client's memo when the merchant gives none. */
export function randomMemo(): Uint8Array {
  return new TextEncoder().encode(randomBytes(16).toString('hex'));
}

export type BlockhashFetcher = (rpcUrl: string) => Promise<string>;

/** getLatestBlockhash over JSON-RPC. The RPC learns that a blockhash was wanted, nothing else. */
export const fetchLatestBlockhash: BlockhashFetcher = async (rpcUrl) => {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getLatestBlockhash', params: [{ commitment: 'confirmed' }] }),
    signal: AbortSignal.timeout(10_000),
    redirect: 'error',
  });
  if (!res.ok) throw new Error(`the Solana network service answered HTTP ${res.status}`);
  const j = await res.json() as { result?: { value?: { blockhash?: unknown } } };
  const h = j?.result?.value?.blockhash;
  if (typeof h !== 'string') throw new Error('the Solana network service did not return a blockhash');
  decodeAddress(h); // 32 bytes of base58, or throws
  return h;
};
