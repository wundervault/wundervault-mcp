import crypto from 'node:crypto';
import { hasIdentity, loadOrCreateIdentity } from './broker-key.js';

/**
 * Phase 6 — signing a request so the server can tell the broker from a holder of its key.
 *
 * After key custody the broker is the only holder of an agent's credential. The server
 * did not know that: it authenticated the bearer credential and served whatever came
 * back, including the wrapped vault key and the ciphertext of entries a broker mode
 * exists to keep out of the agent's process.
 *
 * So every call the broker makes carries a detached ECDSA signature made with the same
 * P-256 key the owner confirmed by fingerprint when they paired this machine. A leaked
 * credential — a restored backup, a support copy — no longer opens anything on its own,
 * because the private key that signs is in a directory the agents cannot read.
 *
 * THE KEY NEVER LEAVES THIS PROCESS, and this process is the broker. Nothing on the agent
 * side imports this module; `test/key-custody.test.ts` pins that by grep.
 */

/** Domain separation. Every signed message begins with this and nothing else does. */
export const CANON_VERSION = 'wv-broker-req-v1';

export interface SignedHeaders {
  'X-Broker-Timestamp': string;
  'X-Broker-Nonce': string;
  'X-Broker-Signature': string;
}

/**
 * The bytes both sides sign.
 *
 * The query string goes in EXACTLY as sent — not re-ordered, not re-encoded. The server
 * compares bytes with what arrived rather than reconstructing what it believes the client
 * meant, which is the difference between a check and a guess.
 */
export function canonicalString(
  method: string,
  path: string,
  query: string,
  timestamp: string,
  nonce: string,
  bodySha256Hex: string,
): Buffer {
  return Buffer.from([
    CANON_VERSION,
    method.toUpperCase(),
    path,
    query,
    timestamp,
    nonce,
    bodySha256Hex,
  ].join('\n'), 'utf8');
}

export function sha256Hex(body: string | Buffer | undefined): string {
  return crypto.createHash('sha256').update(body ?? '').digest('hex');
}

export class BrokerSigner {
  private key: crypto.KeyObject;

  constructor(privateKeyPem: string) {
    this.key = crypto.createPrivateKey(privateKeyPem);
  }

  /**
   * Sign one request.
   *
   * A fresh nonce every time: the server records each one and refuses the second use, so
   * a captured request cannot be replayed inside its window. Sixteen random bytes,
   * because the value has to be unguessable by anything else running on this machine.
   */
  sign(method: string, path: string, query: string, body?: string | Buffer): SignedHeaders {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomBytes(16).toString('base64url');
    const message = canonicalString(method, path, query, timestamp, nonce, sha256Hex(body));
    // 'sha256' named explicitly rather than left to the key's default: the server
    // verifies with ECDSA-SHA256, and a digest chosen by whichever Node is installed is
    // a compatibility break waiting for a version bump.
    const signature = crypto.sign('sha256', message, this.key).toString('base64');
    return {
      'X-Broker-Timestamp': timestamp,
      'X-Broker-Nonce': nonce,
      'X-Broker-Signature': signature,
    };
  }
}

/**
 * A signer from this machine's broker identity, or null when there is no identity.
 *
 * Null is the honest answer on a machine that has never paired, and on macOS and Windows
 * until phases 7 and 8. The server accepts unsigned requests from an agent it has no
 * broker bond for, so returning null degrades to the pre-split shape rather than breaking
 * — and the server, not this, is what decides which agents may take that path.
 */
export function signerFromIdentity(): BrokerSigner | null {
  if (!hasIdentity()) return null;
  try {
    return new BrokerSigner(loadOrCreateIdentity().privateKeyPem);
  } catch {
    // loadOrCreateIdentity refuses a key that is a symlink or readable beyond its owner.
    // That refusal must not be swallowed into "unsigned is fine": a machine with a broken
    // key should fail its requests loudly, not quietly fall back to a weaker path.
    throw new Error(
      'This machine has a broker key that cannot be used. Run `sudo wundervault-agent '
      + '--pair` to inspect it, or fix its ownership and mode.');
  }
}
