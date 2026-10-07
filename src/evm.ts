/**
 * Ethereum-family signing for x402 payments: EIP-3009 `TransferWithAuthorization`, signed as
 * EIP-712 typed data with secp256k1.
 *
 * This is the only thing a vaulted EVM wallet key does. There is no "sign this message" and
 * no "sign this transaction": an authorisation built here moves an exact amount of one
 * token to one address, for a few minutes, once — which is what makes a spending cap and a
 * payee list enforceable at all. A general signer would let an agent sign a transfer of the
 * whole balance and call it something else.
 *
 * See SPEC-1.0-signing.md §C11.
 */
import { randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

export interface Eip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

export interface TransferAuthorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export function isEvmAddress(s: unknown): s is string {
  return typeof s === 'string' && ADDRESS.test(s);
}

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('not hex');
  return new Uint8Array(Buffer.from(h, 'hex'));
}

function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

function keccak(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const all = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { all.set(p, off); off += p.length; }
  return keccak_256(all);
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** A uint256 as a 32-byte big-endian word. Refuses negatives and anything past 2^256-1. */
function uint256(v: bigint | number | string): Uint8Array {
  const n = BigInt(v);
  if (n < 0n || n >= (1n << 256n)) throw new Error('uint256 out of range');
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

function addressWord(addr: string): Uint8Array {
  if (!isEvmAddress(addr)) throw new Error(`not an address: ${addr}`);
  const out = new Uint8Array(32);
  out.set(hexToBytes(addr), 12);
  return out;
}

function bytes32(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== 32) throw new Error('nonce must be 32 bytes');
  return b;
}

/** EIP-55 mixed-case checksum spelling of an address. */
export function checksumAddress(addr: string): string {
  if (!isEvmAddress(addr)) throw new Error(`not an address: ${addr}`);
  const lower = addr.slice(2).toLowerCase();
  const hash = bytesToHex(keccak_256(utf8(lower)));
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

/**
 * A wallet private key, as people actually paste one: 64 hex characters, `0x` optional,
 * surrounding whitespace ignored. Anything else is refused rather than guessed at.
 */
export function parseEvmPrivateKey(raw: string): Uint8Array {
  const s = raw.trim();
  const h = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  if (!/^[0-9a-fA-F]{64}$/.test(h)) {
    throw new Error('this is not an Ethereum-style private key (expected 64 hex characters, 0x optional)');
  }
  const key = hexToBytes(h);
  if (!secp256k1.utils.isValidSecretKey(key)) throw new Error('this private key is out of range for secp256k1');
  return key;
}

/** The address a private key controls: the last 20 bytes of keccak(uncompressed public key). */
export function evmAddressOf(privateKey: Uint8Array): string {
  const pub = secp256k1.getPublicKey(privateKey, false); // 65 bytes, 0x04 prefix
  return checksumAddress(`0x${bytesToHex(keccak_256(pub.subarray(1)).subarray(12))}`);
}

const DOMAIN_TYPEHASH = keccak(utf8(
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));
const TRANSFER_TYPEHASH = keccak(utf8(
  'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)'));

export function domainSeparator(d: Eip712Domain): Uint8Array {
  return keccak(
    DOMAIN_TYPEHASH, keccak(utf8(d.name)), keccak(utf8(d.version)),
    uint256(d.chainId), addressWord(d.verifyingContract),
  );
}

/** The 32-byte digest EIP-712 says to sign: keccak(0x1901 ‖ domainSeparator ‖ structHash). */
export function transferDigest(domain: Eip712Domain, a: TransferAuthorization): Uint8Array {
  const structHash = keccak(
    TRANSFER_TYPEHASH, addressWord(a.from), addressWord(a.to), uint256(a.value),
    uint256(a.validAfter), uint256(a.validBefore), bytes32(a.nonce),
  );
  return keccak(new Uint8Array([0x19, 0x01]), domainSeparator(domain), structHash);
}

/** 0x ‖ r ‖ s ‖ v, v = 27 + recovery id — the 65-byte form USDC's ecrecover takes. */
export function signDigest(digest: Uint8Array, privateKey: Uint8Array): string {
  // noble's 'recovered' format puts the recovery byte FIRST; Ethereum puts v last.
  const sig = secp256k1.sign(digest, privateKey, { prehash: false, format: 'recovered', lowS: true });
  const rec = sig[0];
  if (rec > 1) throw new Error('unexpected recovery id');
  return `0x${bytesToHex(sig.subarray(1))}${(27 + rec).toString(16)}`;
}

/** Recover the signing address from a 65-byte r‖s‖v signature. Used by tests and self-checks. */
export function recoverAddress(digest: Uint8Array, signatureHex: string): string {
  const b = hexToBytes(signatureHex);
  if (b.length !== 65) throw new Error('signature must be 65 bytes');
  const v = b[64];
  const rec = v >= 27 ? v - 27 : v;
  const recovered = new Uint8Array(65);
  recovered[0] = rec;
  recovered.set(b.subarray(0, 64), 1);
  const pub = secp256k1.recoverPublicKey(recovered, digest, { prehash: false });
  const full = secp256k1.Point.fromBytes(pub).toBytes(false);
  return checksumAddress(`0x${bytesToHex(keccak_256(full.subarray(1)).subarray(12))}`);
}

export function randomNonce(): string {
  return `0x${randomBytes(32).toString('hex')}`;
}
