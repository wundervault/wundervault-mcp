/**
 * The broker's own identity, so a credential can travel through an agent safely.
 *
 * THE PROBLEM THIS SOLVES
 *
 * A setup link is a bearer credential: whoever reads it within fifteen minutes can redeem
 * it and obtain `encryption_key`, which unwraps `vault_key_for_agent`, which decrypts
 * every entry in that agent's vault. So the link has to travel from the owner's browser
 * to the broker without passing through anything an agent can read — and on a machine
 * where the agents run as the owner, "anything the owner can read" and "anything an agent
 * can read" are the same set. The owner driving the terminal themselves narrows it to one
 * process rather than closing it.
 *
 * `PLAN-local-shape-and-uid-split.md` named the fix in its sequencing — "re-wrap to a
 * device key" — and phase 5 built the other two thirds of that line (a fresh key
 * hierarchy, and rotating exposed upstream credentials) without it. This is that piece.
 *
 * THE SHAPE
 *
 * The broker generates a P-256 keypair at install. The public half is bound to the
 * account once, in a pairing step the owner performs. After that, a repair encrypts the
 * new credentials TO THAT PUBLIC KEY, and what the owner carries from the browser to the
 * terminal is a claim code — which names a blob and decrypts nothing. An agent reading
 * the whole screen and the whole command line learns a public key and a claim code.
 *
 * WHY P-256 AND NOT X25519
 *
 * WebCrypto implements P-256 ECDH everywhere; X25519 is newer and not universal in
 * browsers. The alternative was vendoring a curve into the page that also handles vault
 * passphrases, which is precisely what `app/static/js/vendor/PROVENANCE.md` exists to
 * make auditable — one vendored primitive there is a considered decision, a second one
 * added for convenience is how that becomes a habit.
 *
 * WHAT PAIRING TRUSTS, STATED PLAINLY
 *
 * The fingerprint is read off a terminal by a person and typed into a browser by that
 * same person. An agent driving that terminal could print a fingerprint for a key it
 * controls. Pairing is therefore the owner's job, in a session no agent is driving, once
 * per machine — the same trust the `sudo` install already assumes, and it replaces an
 * exposure on every repair with one on every machine.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { systemRoot, ensureSystemRoot } from './paths.js';

const CURVE = 'prime256v1';

export function brokerKeyPath(): string {
  return process.env.WUNDERVAULT_BROKER_KEY || path.join(systemRoot(), 'broker-key.pem');
}

export interface BrokerIdentity {
  /** PEM, private. Never leaves this process. */
  privateKeyPem: string;
  /** base64 SPKI, the half that is published. */
  publicKeyB64: string;
  /** What a human compares. */
  fingerprint: string;
}

/**
 * Crockford base32, five groups of four.
 *
 * Chosen over hex because a fingerprint is read aloud or copied by eye, and Crockford
 * drops the characters that are misread (I, L, O, U). Ten bytes is 80 bits, which is far
 * more than a person will compare carefully and still short enough that they will.
 */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function fingerprintOf(publicKeyB64: string): string {
  const digest = crypto.createHash('sha256').update(Buffer.from(publicKeyB64, 'base64')).digest();
  const bytes = digest.subarray(0, 10);
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(value << (5 - bits)) & 31];
  return (out.match(/.{1,4}/g) ?? []).join('-');
}

/** Read the identity, or make one. Called by the installer and by `--pair`. */
export function loadOrCreateIdentity(): BrokerIdentity {
  ensureSystemRoot();
  const p = brokerKeyPath();
  let privateKeyPem: string;
  if (fs.existsSync(p)) {
    // CHECK WHAT IS BEING READ BEFORE TRUSTING IT.
    //
    // A restore onto the wrong ownership, a packaging mistake, or an administrator
    // editing the file can leave this key world-readable or redirected through a symlink
    // to somewhere an agent can write. Reading it anyway would keep every claim in the
    // system working while the property the claims depend on had quietly gone.
    //
    // lstat, not stat: stat follows the symlink and reports the target's mode, which is
    // exactly the substitution being checked for.
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) {
      throw new Error(
        `${p} is a symlink. The broker's private key must be a real file in a directory `
        + `only the broker can open; a link can be repointed by whoever can write the link.`);
    }
    if (!st.isFile()) {
      throw new Error(`${p} is not a regular file.`);
    }
    if ((st.mode & 0o077) !== 0) {
      throw new Error(
        `${p} is mode ${(st.mode & 0o777).toString(8)}, which is readable beyond its owner. `
        + `That key is what every sealed credential on this machine depends on. `
        + `Fix it with: sudo chmod 600 ${p}`);
    }
    privateKeyPem = fs.readFileSync(p, 'utf8');
  } else {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: CURVE });
    privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    // Written with the mode in the call AND chmod'd after: writeFileSync's mode applies
    // only when it creates the file and is masked by umask either way, so a key written
    // under a permissive umask would land readable and nothing would say so.
    fs.writeFileSync(p, privateKeyPem, { mode: 0o600 });
    fs.chmodSync(p, 0o600);
  }
  const priv = crypto.createPrivateKey(privateKeyPem);
  const pub = crypto.createPublicKey(priv);
  const publicKeyB64 = pub.export({ type: 'spki', format: 'der' }).toString('base64');
  return { privateKeyPem, publicKeyB64, fingerprint: fingerprintOf(publicKeyB64) };
}

/** True when this machine has an identity. Does not create one. */
export function hasIdentity(): boolean {
  try { return fs.existsSync(brokerKeyPath()); } catch { return false; }
}

/**
 * Open a blob the browser sealed to this broker's public key.
 *
 * Layout, fixed and checked rather than inferred from lengths at use time:
 *
 *   ephemeral SPKI (91 bytes, DER) || nonce (12) || ciphertext || GCM tag (16)
 *
 * The SPKI length is not hardcoded — it is read from the DER header — because a
 * hardcoded 91 would break silently the day a browser emits a different-but-valid
 * encoding, and "silently" here means an enrolment that cannot complete with no useful
 * error.
 */
export function openBrokerBlob(privateKeyPem: string, blobB64: string): Buffer {
  const blob = Buffer.from(blobB64, 'base64');
  if (blob.length < 4) throw new Error('The broker blob is truncated.');
  // DER SEQUENCE: 0x30, then a length that is either short-form or 0x81/0x82 + N bytes.
  if (blob[0] !== 0x30) throw new Error('The broker blob does not start with a public key.');
  let spkiLen: number;
  if (blob[1] < 0x80) spkiLen = 2 + blob[1];
  else if (blob[1] === 0x81) spkiLen = 3 + blob[2];
  else if (blob[1] === 0x82) spkiLen = 4 + ((blob[2] << 8) | blob[3]);
  else throw new Error('The broker blob has an unsupported public key encoding.');

  if (blob.length < spkiLen + 12 + 16) throw new Error('The broker blob is truncated.');
  const ephemeralSpki = blob.subarray(0, spkiLen);
  const nonce = blob.subarray(spkiLen, spkiLen + 12);
  const body = blob.subarray(spkiLen + 12);
  const tag = body.subarray(body.length - 16);
  const ciphertext = body.subarray(0, body.length - 16);

  const ephemeral = crypto.createPublicKey({ key: ephemeralSpki, format: 'der', type: 'spki' });
  const shared = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(privateKeyPem),
    publicKey: ephemeral,
  });

  // HKDF with a fixed info string. The info is what stops a shared secret derived for one
  // purpose being usable for another if this ever grows a second kind of blob.
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0),
    Buffer.from('wundervault-broker-blob-v1'), 32));

  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ciphertext), d.final()]);
}
