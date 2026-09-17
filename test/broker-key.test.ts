/**
 * The broker's identity, and the blob only it can open.
 *
 * The sealing side of this lives in the browser (`wundervault-crypto.js`), so the tests
 * here seal with WebCrypto — the same API the page uses, via Node's implementation of it
 * — rather than with node:crypto. Sealing with the same library that unseals would prove
 * the two halves of one implementation agree and say nothing about whether a browser can
 * talk to a broker.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import nodeCrypto from 'node:crypto';
import { loadOrCreateIdentity, openBrokerBlob, fingerprintOf, brokerKeyPath, hasIdentity } from '../src/broker-key.js';

const webcrypto = nodeCrypto.webcrypto as unknown as Crypto;

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-bkey-'));
  process.env.WUNDERVAULT_SYSTEM_ROOT = dir;
  delete process.env.WUNDERVAULT_BROKER_KEY;
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
  delete process.env.WUNDERVAULT_SYSTEM_ROOT;
});

/**
 * Seal exactly the way the browser does.
 *
 * Kept here in full rather than imported, because it IS the other implementation: if the
 * page's version drifts, this test must keep describing what a browser actually sends.
 */
async function sealLikeTheBrowser(brokerPubB64: string, payload: unknown): Promise<string> {
  const brokerPub = await webcrypto.subtle.importKey(
    'spki', Buffer.from(brokerPubB64, 'base64'),
    { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  const eph = await webcrypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
  ) as CryptoKeyPair;
  const shared = new Uint8Array(await webcrypto.subtle.deriveBits(
    { name: 'ECDH', public: brokerPub }, eph.privateKey, 256,
  ));
  const hkdfKey = await webcrypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const aesKey = await webcrypto.subtle.deriveKey(
    {
      name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0),
      info: new TextEncoder().encode('wundervault-broker-blob-v1'),
    },
    hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, aesKey,
    new TextEncoder().encode(JSON.stringify(payload)),
  ));
  const ephSpki = new Uint8Array(await webcrypto.subtle.exportKey('spki', eph.publicKey));
  const out = new Uint8Array(ephSpki.length + nonce.length + ct.length);
  out.set(ephSpki, 0);
  out.set(nonce, ephSpki.length);
  out.set(ct, ephSpki.length + nonce.length);
  return Buffer.from(out).toString('base64');
}

describe('the broker identity', () => {
  it('creates a private key only its own account can read', () => {
    expect(hasIdentity()).toBe(false);
    const id = loadOrCreateIdentity();
    expect(hasIdentity()).toBe(true);
    const mode = fs.statSync(brokerKeyPath()).mode & 0o777;
    expect(mode).toBe(0o600);
    expect(id.privateKeyPem).toContain('BEGIN PRIVATE KEY');
    expect(id.publicKeyB64.length).toBeGreaterThan(80);
  });

  it('is stable across reloads', () => {
    const a = loadOrCreateIdentity();
    const b = loadOrCreateIdentity();
    expect(b.publicKeyB64).toBe(a.publicKeyB64);
    expect(b.fingerprint).toBe(a.fingerprint);
  });

  it('derives the fingerprint from the key bytes, not from a stored field', () => {
    const id = loadOrCreateIdentity();
    // The browser computes this from the public key it fetched. If it were carried as a
    // field, whoever could change the field could make any key look like the right one —
    // and the fingerprint is the ONLY thing the owner checks.
    expect(fingerprintOf(id.publicKeyB64)).toBe(id.fingerprint);
    expect(id.fingerprint).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4})+$/);
  });

  it('agrees with the server and the page on the same key bytes', () => {
    // Vectors computed by the SERVER's Python implementation (app/routes/ui.py
    // broker_fingerprint) and asserted again by the page's JS (tests/js/broker-seal.test.js).
    // Three implementations of the one string the owner actually compares is three chances
    // to disagree — and a disagreement reads to the owner as "the fingerprint does not
    // match", which is the alarm, not a bug report.
    expect(fingerprintOf('AAAA')).toBe('E2F8-1J44-GYH4-27GY');
    expect(fingerprintOf('//8=')).toBe('S8QX-03X0-04CG-EH61');
  });

  it('gives different keys different fingerprints', () => {
    const a = loadOrCreateIdentity();
    fs.rmSync(brokerKeyPath());
    const b = loadOrCreateIdentity();
    expect(b.fingerprint).not.toBe(a.fingerprint);
  });
});

describe('the sealed blob', () => {
  const PAYLOAD = { api_key: 'wv_agent_A|k', api_key_hmac: 'h', encryption_key: 'e' };

  it('round-trips from a WebCrypto seal to the broker', async () => {
    const id = loadOrCreateIdentity();
    const blob = await sealLikeTheBrowser(id.publicKeyB64, PAYLOAD);
    const opened = JSON.parse(openBrokerBlob(id.privateKeyPem, blob).toString('utf8'));
    expect(opened).toEqual(PAYLOAD);
  });

  it('cannot be opened by a different broker', async () => {
    const mine = loadOrCreateIdentity();
    fs.rmSync(brokerKeyPath());
    const theirs = loadOrCreateIdentity();
    const blob = await sealLikeTheBrowser(mine.publicKeyB64, PAYLOAD);
    expect(() => openBrokerBlob(theirs.privateKeyPem, blob)).toThrow();
  });

  it('fails the tag rather than returning garbage when tampered', async () => {
    const id = loadOrCreateIdentity();
    const blob = await sealLikeTheBrowser(id.publicKeyB64, PAYLOAD);
    const raw = Buffer.from(blob, 'base64');
    // Flip a bit in the ciphertext, well past the ephemeral key and the nonce.
    raw[raw.length - 20] ^= 0x01;
    expect(() => openBrokerBlob(id.privateKeyPem, raw.toString('base64'))).toThrow();
  });

  it('refuses a truncated blob instead of reading past the end', async () => {
    const id = loadOrCreateIdentity();
    const blob = await sealLikeTheBrowser(id.publicKeyB64, PAYLOAD);
    const raw = Buffer.from(blob, 'base64');
    for (const cut of [1, 4, 40, raw.length - 10]) {
      expect(() => openBrokerBlob(id.privateKeyPem, raw.subarray(0, cut).toString('base64')))
        .toThrow();
    }
  });

  it('refuses a blob that does not begin with a public key', () => {
    const id = loadOrCreateIdentity();
    const junk = Buffer.alloc(200, 0x41);
    expect(() => openBrokerBlob(id.privateKeyPem, junk.toString('base64')))
      .toThrow(/does not start with a public key/);
  });

  it('reads the ephemeral key length from the DER header rather than assuming one', async () => {
    // The check that stops this breaking silently the day an encoder emits a
    // different-but-valid length form. A P-256 SPKI is 91 bytes and short-form, so the
    // assertion is that the parser AGREES with that rather than that it hardcodes it.
    const id = loadOrCreateIdentity();
    const blob = Buffer.from(await sealLikeTheBrowser(id.publicKeyB64, PAYLOAD), 'base64');
    expect(blob[0]).toBe(0x30);
    expect(2 + blob[1]).toBe(91);
    expect(() => openBrokerBlob(id.privateKeyPem, blob.toString('base64'))).not.toThrow();
  });
});
