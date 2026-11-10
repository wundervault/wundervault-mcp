/**
 * Short-lived OpenSSH user certificates for admin access (site SPEC-admin-access D13).
 *
 * A server set up for admin access trusts the admin key only as a certificate authority
 * ("cert-authority,principals=\"wv-admin\" <admin key>" in the admin account's
 * authorized_keys). For each admin session the helper app signs a certificate for that same
 * key, valid until the owner's admin access ends, whose force-command runs the server's
 * session check with the end time. sshd refuses the certificate after valid-before; the check
 * ends the session already open at that moment. The signature covers both, so the agent
 * cannot extend either.
 *
 * Format: PROTOCOL.certkeys in OpenSSH (ssh-ed25519-cert-v01@openssh.com).
 */
import { randomBytes, sign as cryptoSign } from 'node:crypto';
import type { LoadedIdentity } from './ssh-agent.js';

export const CERT_TYPE = 'ssh-ed25519-cert-v01@openssh.com';
export const ADMIN_PRINCIPAL = 'wv-admin';
export const ADMIN_SESSION_CHECK = '/usr/local/lib/wundervault/wv-admin-session';

function u32(n: number): Buffer { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0); return b; }
function u64(n: bigint): Buffer { const b = Buffer.alloc(8); b.writeBigUInt64BE(n, 0); return b; }
function str(v: Buffer | string): Buffer {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'utf8');
  return Buffer.concat([u32(b.length), b]);
}

/** The 32-byte public key inside `string "ssh-ed25519" || string pub32`. */
function rawPublic(keyBlob: Buffer): Buffer {
  const tlen = keyBlob.readUInt32BE(0);
  const off = 4 + tlen;
  const plen = keyBlob.readUInt32BE(off);
  if (keyBlob.subarray(4, 4 + tlen).toString() !== 'ssh-ed25519' || plen !== 32) throw new Error('not an ed25519 key');
  return keyBlob.subarray(off + 4, off + 4 + plen);
}

export interface AdminCertOptions {
  /** When admin access ends, Unix seconds. Becomes valid-before and the check's end time. */
  end: number;
  /** Not before, Unix seconds. Defaults to one minute ago (clock skew between computer and server). */
  start?: number;
  keyId?: string;
}

/**
 * A user certificate for `identity`'s own key, signed by the same key. Principal "wv-admin"
 * only; no forwarding of any kind; a pty is allowed (an interactive shell is still cut off).
 */
export function adminCertificate(identity: LoadedIdentity, o: AdminCertOptions): Buffer {
  if (!Number.isInteger(o.end) || o.end <= 0) throw new Error('admin certificate needs an end time');
  const start = o.start ?? Math.floor(Date.now() / 1000) - 60;
  if (start >= o.end) throw new Error('admin certificate would never be valid');
  const pub = rawPublic(identity.keyBlob);
  // Critical options and extensions are each sorted by name, values wrapped in a string.
  const critical = Buffer.concat([str('force-command'), str(str(`${ADMIN_SESSION_CHECK} ${o.end}`))]);
  const extensions = Buffer.concat([str('permit-pty'), str('')]);
  const body = Buffer.concat([
    str(CERT_TYPE),
    str(randomBytes(32)),
    str(pub),
    u64(BigInt('0x' + randomBytes(8).toString('hex'))),
    u32(1), // SSH2_CERT_TYPE_USER
    str(o.keyId ?? `wundervault admin access until ${new Date(o.end * 1000).toISOString()}`),
    str(str(ADMIN_PRINCIPAL)),
    u64(BigInt(start)),
    u64(BigInt(o.end)),
    str(critical),
    str(extensions),
    str(''), // reserved
    str(identity.keyBlob), // signature key
  ]);
  const sig = cryptoSign(null, body, identity.privateKey);
  return Buffer.concat([body, str(Buffer.concat([str('ssh-ed25519'), str(sig)]))]);
}

/** The `-cert.pub` file line ssh reads with CertificateFile=. */
export function certificateLine(certBlob: Buffer, comment = 'wundervault-admin-access'): string {
  return `${CERT_TYPE} ${certBlob.toString('base64')} ${comment}\n`;
}
