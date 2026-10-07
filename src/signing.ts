/**
 * Signing keys: the broker signs bytes the owner approved, and returns the signature.
 *
 * Every signature is approved by the owner, one at a time (§E23) — a signing key signs
 * whatever it is given, so there is no rule a broker could check on the owner's behalf.
 * What the broker CAN do is refuse keys whose signatures mean something else: an OpenSSH
 * key would sign SSH logins, and a secp256k1 key is a wallet that would sign transfers.
 *
 * See SPEC-1.0-signing.md §E.
 */
import { createPrivateKey, createPublicKey, sign as nodeSign, type KeyObject } from 'node:crypto';

export type SigningAlgorithm = 'ed25519' | 'ecdsa-p256-sha256' | 'rsa-pkcs1-sha256';

export interface SigningKey {
  algorithm: SigningAlgorithm;
  key: KeyObject;
  /** Raw 32 bytes for ed25519, SPKI DER otherwise — base64. */
  publicKey: string;
}

/** PKCS#8 prefix for a raw ed25519 seed (RFC 8410). */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function fromSeed(seed: Buffer): SigningKey {
  const key = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  return describe(key, 'ed25519');
}

function describe(key: KeyObject, algorithm: SigningAlgorithm): SigningKey {
  const pub = createPublicKey(key);
  const spki = pub.export({ format: 'der', type: 'spki' });
  // An ed25519 SPKI is a 12-byte header and the 32-byte key; people compare the raw key.
  const publicKey = algorithm === 'ed25519' ? spki.subarray(spki.length - 32).toString('base64') : spki.toString('base64');
  return { algorithm, key, publicKey };
}

export function parseSigningKey(raw: string): SigningKey {
  const s = raw.trim();
  if (/-----BEGIN OPENSSH PRIVATE KEY-----/.test(s)) {
    throw new Error('this is an SSH key; it would sign SSH logins. Store it as an SSH key and use vault_ssh_exec.');
  }
  if (/-----BEGIN ENCRYPTED PRIVATE KEY-----|Proc-Type: 4,ENCRYPTED/.test(s)) {
    throw new Error('this key is protected with a password; store it without one.');
  }
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)) {
    let key: KeyObject;
    try { key = createPrivateKey({ key: s, format: 'pem' }); } catch {
      throw new Error('this PEM key could not be read.');
    }
    const type = key.asymmetricKeyType;
    if (type === 'ed25519') return describe(key, 'ed25519');
    if (type === 'rsa') {
      if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error('RSA keys shorter than 2048 bits are refused.');
      return describe(key, 'rsa-pkcs1-sha256');
    }
    if (type === 'ec') {
      const curve = key.asymmetricKeyDetails?.namedCurve;
      if (curve === 'prime256v1' || curve === 'P-256') return describe(key, 'ecdsa-p256-sha256');
      if (curve === 'secp256k1') throw new Error('this is a secp256k1 key, which is what a crypto wallet uses; store it as a wallet.');
      throw new Error(`EC curve ${curve} is not supported (P-256 only).`);
    }
    throw new Error(`${type} keys are not supported (ed25519, ECDSA P-256 or RSA).`);
  }
  // A raw ed25519 seed: 32 bytes, base64 (the installer key's format) or hex.
  let seed: Buffer | null = null;
  if (/^[0-9a-fA-F]{64}$/.test(s)) seed = Buffer.from(s, 'hex');
  else if (/^[A-Za-z0-9+/_-]{43}=?$/.test(s)) seed = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (seed && seed.length === 32) return fromSeed(seed);
  throw new Error('this is not a signing key the broker knows: an ed25519 seed (32 bytes, base64 or hex), '
    + 'or a PEM ed25519, ECDSA P-256 or RSA private key.');
}

export function signBytes(k: SigningKey, data: Buffer): string {
  const alg = k.algorithm === 'ed25519' ? null : 'sha256';
  return nodeSign(alg, data, k.key).toString('base64');
}

export function decodeData(data: unknown, encoding: unknown): Buffer {
  if (typeof data !== 'string') throw new Error('data must be a string');
  const enc = encoding ?? 'utf8';
  if (enc === 'utf8') return Buffer.from(data, 'utf8');
  if (enc === 'hex') {
    if (!/^([0-9a-fA-F]{2})*$/.test(data)) throw new Error('data is not hex');
    return Buffer.from(data, 'hex');
  }
  if (enc === 'base64') {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(data)) throw new Error('data is not base64');
    return Buffer.from(data, 'base64');
  }
  throw new Error("encoding must be 'utf8', 'base64' or 'hex'");
}
