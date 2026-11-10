/**
 * An ssh-agent that holds the key instead of handing it over.
 *
 * `vault_rsync` and remote `vault_exec` used to write the private key to a temp file for
 * the duration of the transfer, where anything running as the same user could read it.
 * Both are retired in 1.0. The ssh-agent protocol exists precisely so a private key never
 * has to leave the process that holds it: ssh asks for a signature over the session data,
 * the agent answers, and the key stays put.
 *
 * SCOPE, stated plainly — and this paragraph was out of date for three phases, which is
 * worth more than the correction itself.
 *
 * It used to read: "this daemon runs as the agent's own uid, so this is NOT yet a
 * confidentiality boundary… when the daemon moves to its own uid, the same interface
 * becomes a real boundary with no further API change." The daemon HAS moved. `startAgent`
 * is called from broker-ops.ts, which runs in the broker, under an account the agent
 * cannot read or attach to; the ssh CLIENT still runs in the agent's process and is
 * pointed at this socket, so it asks for signatures and never holds the key. That is the
 * boundary the old paragraph was waiting for, and it arrived without the API change it
 * predicted.
 *
 * The signing socket can be world-connectable. A pinned agent therefore requires a
 * verified OpenSSH session bind on each connection and signs only userauth requests for
 * that session and server. Legacy callers without a pin still allow any connected
 * process to ask for a signature while the session is open; capped, short-lived sessions
 * mitigate that legacy behaviour but do not make it a destination restriction.
 */
import { createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, createHash, KeyObject } from 'node:crypto';
import { createServer, Server, Socket } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, chmodSync, writeFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseGitSshUrl } from './git-op.js';
import { pinnedSshOptions } from './ssh-options.js';

// ── protocol constants (PROTOCOL.agent) ────────────────────────────────────────
const SSH_AGENT_FAILURE = 5;
const SSH_AGENT_SUCCESS = 6;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;
const SSH_AGENTC_EXTENSION = 27;

/** A framed agent message longer than this is refused rather than buffered. */
const MAX_MESSAGE_BYTES = 256 * 1024;

/**
 * A peer that declares a length and then stops sending would otherwise hold its
 * connection — and any message queued behind it — open for as long as the agent lives.
 * The declared length is authoritative, so this is not protocol leniency; it is just
 * refusing to wait forever for bytes that are not coming.
 */
const CONNECTION_IDLE_MS = 30_000;
const MAX_SESSION_BINDS = 8;

const ED25519_KEY_TYPE = 'ssh-ed25519';
const OPENSSH_MAGIC = Buffer.from('openssh-key-v1\0', 'binary');

/**
 * PKCS#8 prefix for a raw Ed25519 seed. Node can import a seed only via a structured
 * container, and OpenSSH stores it bare, so the 16-byte header is prepended here:
 *   SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }
 */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export interface LoadedIdentity {
  /** `string "ssh-ed25519" || string pub32` — the wire form ssh asks for by. */
  keyBlob: Buffer;
  publicKey: KeyObject;
  privateKey: KeyObject;
  comment: string;
  /** OpenSSH-style `SHA256:base64(sha256(keyBlob))`, unpadded. */
  fingerprint: string;
}

// ── SSH wire primitives ────────────────────────────────────────────────────────

/** Reads length-prefixed fields without ever running past the end of the buffer. */
class Reader {
  constructor(private buf: Buffer, private off = 0) {}

  byte(): number {
    if (this.off >= this.buf.length) throw new Error('truncated: expected a byte');
    return this.buf[this.off++];
  }

  u32(): number {
    if (this.off + 4 > this.buf.length) throw new Error('truncated: expected a 4-byte length');
    const v = this.buf.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }

  str(): Buffer {
    const n = this.u32();
    // A declared length beyond the buffer is the classic malformed-input crash; it is a
    // parse failure here, never an allocation.
    if (n > this.buf.length - this.off) throw new Error('truncated: string longer than remaining input');
    const v = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return v;
  }

  get remaining(): number { return this.buf.length - this.off; }
}

function u32(n: number): Buffer {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n, 0);
  return b;
}

/** Length-prefixed string, the only way anything goes onto the wire here. */
function sshString(v: Buffer | string): Buffer {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'utf8');
  return Buffer.concat([u32(b.length), b]);
}

// ── key loading ────────────────────────────────────────────────────────────────

/**
 * Parse an unencrypted OpenSSH ed25519 private key, in memory.
 *
 * Refusals are specific on purpose: "this is an encrypted key" and "this is RSA" are
 * things the owner can act on, whereas a parse error from deep inside a binary format
 * tells them nothing.
 */
export function loadOpenSshEd25519(pem: string): LoadedIdentity {
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(pem);
  if (!m) {
    throw new Error(
      'Not an OpenSSH private key. Expected a file beginning "-----BEGIN OPENSSH PRIVATE KEY-----". '
      + 'PEM/PKCS#8 and PuTTY formats are not supported; convert with `ssh-keygen -p -m RFC4716`.',
    );
  }

  const blob = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
  if (!blob.subarray(0, OPENSSH_MAGIC.length).equals(OPENSSH_MAGIC)) {
    throw new Error('Not an OpenSSH private key: missing the openssh-key-v1 magic.');
  }

  const r = new Reader(blob, OPENSSH_MAGIC.length);
  const cipherName = r.str().toString('utf8');
  r.str();                                  // kdfname — only meaningful when encrypted
  r.str();                                  // kdfoptions
  const nKeys = r.u32();

  if (cipherName !== 'none') {
    throw new Error(
      `This SSH key is passphrase-encrypted (cipher "${cipherName}"). The agent broker needs an `
      + 'unencrypted key. Either store the decrypted key, or use the ssh-passphrase recipe, which '
      + 'delivers the passphrase over an askpass helper instead.',
    );
  }
  if (nKeys !== 1) {
    throw new Error(`Expected exactly one key in the file, found ${nKeys}.`);
  }

  r.str();                                  // public section, re-read from the private half below
  const priv = new Reader(r.str());

  const check1 = priv.u32();
  const check2 = priv.u32();
  if (check1 !== check2) {
    // For an unencrypted key these must match; a mismatch means the file is damaged
    // rather than that a passphrase is needed.
    throw new Error('SSH key is corrupt: the private section checkints do not match.');
  }

  const keyType = priv.str().toString('utf8');
  if (keyType !== ED25519_KEY_TYPE) {
    throw new Error(
      `Unsupported SSH key type "${keyType}". The agent broker supports ${ED25519_KEY_TYPE} only. `
      + 'Generate one with `ssh-keygen -t ed25519`.',
    );
  }

  const pub = priv.str();
  const secret = priv.str();                // seed32 || pub32
  const comment = priv.str().toString('utf8');

  if (pub.length !== 32) throw new Error(`Malformed ed25519 public key: expected 32 bytes, got ${pub.length}.`);
  if (secret.length !== 64) throw new Error(`Malformed ed25519 private key: expected 64 bytes, got ${secret.length}.`);
  if (!secret.subarray(32).equals(pub)) {
    throw new Error('Malformed ed25519 key: the public half of the private key does not match the public key.');
  }

  const seed = secret.subarray(0, 32);
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);

  const keyBlob = Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(pub)]);
  const fingerprint = 'SHA256:' + createHash('sha256').update(keyBlob).digest('base64').replace(/=+$/, '');

  return { keyBlob, publicKey, privateKey, comment, fingerprint };
}

const HOST_CURVES: Record<string, { crv: string; bytes: number; hash: string }> = {
  nistp256: { crv: 'P-256', bytes: 32, hash: 'sha256' },
  nistp384: { crv: 'P-384', bytes: 48, hash: 'sha384' },
  nistp521: { crv: 'P-521', bytes: 66, hash: 'sha512' },
};

/** SSH mpints are signed; JWK and P1363 need the unsigned, positive magnitude. */
function positiveMpint(v: Buffer): Buffer {
  if (v.length === 0 || (v[0] & 0x80) !== 0) throw new Error('expected a positive mpint');
  if (v[0] === 0) {
    if (v.length < 2 || (v[1] & 0x80) === 0) throw new Error('non-canonical positive mpint');
    return v.subarray(1);
  }
  return v;
}

function hostPublicKey(blob: Buffer): {
  key: KeyObject; type: string; curve?: { crv: string; bytes: number; hash: string };
} {
  const r = new Reader(blob);
  const type = r.str().toString('utf8');
  let key: KeyObject;
  let curve: { crv: string; bytes: number; hash: string } | undefined;

  if (type === ED25519_KEY_TYPE) {
    const pub = r.str();
    if (pub.length !== 32) throw new Error('expected a 32-byte ed25519 host key');
    key = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: pub.toString('base64url') },
      format: 'jwk',
    });
  } else if (type.startsWith('ecdsa-sha2-')) {
    const name = r.str().toString('utf8');
    if (!Object.prototype.hasOwnProperty.call(HOST_CURVES, name) || type !== `ecdsa-sha2-${name}`) {
      throw new Error('unsupported ECDSA host curve');
    }
    curve = HOST_CURVES[name];
    const q = r.str();
    if (q.length !== 1 + 2 * curve.bytes || q[0] !== 4) {
      throw new Error('expected an uncompressed ECDSA host point');
    }
    key = createPublicKey({
      key: {
        kty: 'EC', crv: curve.crv,
        x: q.subarray(1, 1 + curve.bytes).toString('base64url'),
        y: q.subarray(1 + curve.bytes).toString('base64url'),
      },
      format: 'jwk',
    });
  } else if (type === 'ssh-rsa') {
    const e = positiveMpint(r.str());
    const n = positiveMpint(r.str());
    key = createPublicKey({
      key: { kty: 'RSA', e: e.toString('base64url'), n: n.toString('base64url') },
      format: 'jwk',
    });
  } else {
    throw new Error('unsupported SSH host key type');
  }

  if (r.remaining !== 0) throw new Error('trailing bytes in SSH host key');
  return { key, type, curve };
}

/** Accept a public key line (with an optional comment), or just its base64 wire blob. */
export function parseOpenSshPublicKey(line: string): Buffer {
  const fields = line.trim().split(/\s+/);
  const encoded = fields.length === 1 ? fields[0] : fields[1];
  if (!encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new Error('Expected an OpenSSH public key line or base64 public key blob.');
  }
  const blob = Buffer.from(encoded, 'base64');
  if (blob.toString('base64').replace(/=+$/, '') !== encoded.replace(/=+$/, '')) {
    throw new Error('Malformed base64 SSH public key.');
  }
  const parsed = hostPublicKey(blob);
  if (fields.length > 1 && fields[0] !== parsed.type) {
    throw new Error('SSH public key type does not match its blob.');
  }
  return blob;
}

/** Verify the server's proof of possession; malformed or unsupported inputs fail closed. */
export function verifySessionBind(hostKeyBlob: Buffer, sessionId: Buffer, signatureBlob: Buffer): boolean {
  try {
    if (sessionId.length === 0) return false;
    const host = hostPublicKey(hostKeyBlob);
    const r = new Reader(signatureBlob);
    const algo = r.str().toString('utf8');
    const signature = r.str();
    if (r.remaining !== 0) return false;

    if (host.type === ED25519_KEY_TYPE) {
      return algo === ED25519_KEY_TYPE && signature.length === 64
        && cryptoVerify(null, sessionId, host.key, signature);
    }
    if (host.type === 'ssh-rsa') {
      // An RSA public blob still says ssh-rsa, but SHA-1 signatures are not accepted.
      if (algo !== 'rsa-sha2-256' && algo !== 'rsa-sha2-512') return false;
      return cryptoVerify(algo === 'rsa-sha2-256' ? 'sha256' : 'sha512', sessionId, host.key, signature);
    }
    if (host.curve && algo === host.type) {
      const parts = new Reader(signature);
      const rPart = positiveMpint(parts.str());
      const sPart = positiveMpint(parts.str());
      const width = host.curve.bytes;
      if (parts.remaining !== 0 || rPart.length > width || sPart.length > width) return false;
      const p1363 = Buffer.alloc(2 * width);
      rPart.copy(p1363, width - rPart.length);
      sPart.copy(p1363, 2 * width - sPart.length);
      return cryptoVerify(
        host.curve.hash, sessionId, { key: host.key, dsaEncoding: 'ieee-p1363' }, p1363,
      );
    }
    return false;
  } catch {
    return false;
  }
}

// ── protocol handling ──────────────────────────────────────────────────────────

export interface AgentConnectionState {
  binds: Array<{ hostKeyBlob: Buffer; sessionId: Buffer; forwarding: boolean }>;
}

export interface SignEvent {
  fingerprint: string;
  host: string;
  at: string;
  /** "signed" or the reason it was refused. A refusal is the more interesting event. */
  outcome: 'signed' | 'refused_unknown_key' | 'refused_malformed' | 'refused_binding';
  refused?: boolean;
  reason?: string;
}

/**
 * Auditing is not caller-optional. Spec A5 says log EVERY signature, and an optional
 * callback means the one deployment that forgets to pass it silently keeps no record at
 * all. Callers may add their own sink; this one always runs.
 */
export function defaultSignAudit(e: SignEvent): void {
  process.stderr.write(
    `[wundervault-ssh-agent] ${e.at} ${e.outcome} key=${e.fingerprint} host=${e.host || '-'}`
    + (e.reason ? ` reason=${e.reason}` : '') + '\n',
  );
}

/** A pin authorises user authentication, not an arbitrary signing oracle. */
function isBoundUserauth(
  data: Buffer,
  identity: LoadedIdentity,
  bind: AgentConnectionState['binds'][number],
  user: string | undefined,
): boolean {
  try {
    const r = new Reader(data);
    if (!r.str().equals(bind.sessionId) || r.byte() !== 50) return false; // SSH_MSG_USERAUTH_REQUEST
    // The approved name, byte for byte: another account on the same server is a new approval.
    if (user === undefined || !r.str().equals(Buffer.from(user, 'utf8'))) return false;
    if (r.str().toString('utf8') !== 'ssh-connection') return false;
    const method = r.str().toString('utf8');
    if (method !== 'publickey' && method !== 'publickey-hostbound-v00@openssh.com') return false;
    if (r.byte() !== 1 || r.str().toString('utf8') !== ED25519_KEY_TYPE) return false;
    if (!r.str().equals(identity.keyBlob)) return false;
    if (method === 'publickey-hostbound-v00@openssh.com' && !r.str().equals(bind.hostKeyBlob)) return false;
    return r.remaining === 0;
  } catch {
    return false;
  }
}

/**
 * Answer one agent message. No I/O; only the supplied connection state is updated.
 * Returns the reply body; the caller frames it.
 */
export function handleAgentMessage(
  msg: Buffer,
  identity: LoadedIdentity,
  onOutcome?: (outcome: SignEvent['outcome'], reason?: string) => void,
  conn: AgentConnectionState = { binds: [] },
  opts: AgentSocketOptions = {},
): Buffer {
  if (msg.length === 0) return Buffer.from([SSH_AGENT_FAILURE]);
  const type = msg[0];

  if (type === SSH_AGENTC_REQUEST_IDENTITIES) {
    return Buffer.concat([
      Buffer.from([SSH_AGENT_IDENTITIES_ANSWER]),
      u32(1),
      sshString(identity.keyBlob),
      sshString(identity.comment),
    ]);
  }

  if (type === SSH_AGENTC_EXTENSION) {
    try {
      const r = new Reader(msg, 1);
      if (r.str().toString('utf8') !== 'session-bind@openssh.com') return Buffer.from([SSH_AGENT_FAILURE]);
      const hostKeyBlob = r.str();
      const sessionId = r.str();
      const signature = r.str();
      const forwarding = r.byte() !== 0;
      if (r.remaining !== 0 || conn.binds.length >= MAX_SESSION_BINDS
        || !verifySessionBind(hostKeyBlob, sessionId, signature)) {
        return Buffer.from([SSH_AGENT_FAILURE]);
      }
      conn.binds.push({
        hostKeyBlob: Buffer.from(hostKeyBlob), sessionId: Buffer.from(sessionId), forwarding,
      });
      return Buffer.from([SSH_AGENT_SUCCESS]);
    } catch {
      return Buffer.from([SSH_AGENT_FAILURE]);
    }
  }

  if (type === SSH_AGENTC_SIGN_REQUEST) {
    try {
      const r = new Reader(msg, 1);
      const wantBlob = r.str();
      const data = r.str();
      // flags are read but unused: ed25519 has no rsa-sha2 variants to select.
      if (r.remaining >= 4) r.u32();

      // A sign request naming a key this agent does not hold is refused rather than
      // signed with whatever it does hold.
      if (!wantBlob.equals(identity.keyBlob)) {
        // Someone asking this agent to sign with a key it does not hold is worth a
        // record, not just a silent refusal.
        onOutcome?.('refused_unknown_key');
        return Buffer.from([SSH_AGENT_FAILURE]);
      }

      if (opts.pinnedHostKey !== undefined) {
        const bind = conn.binds[conn.binds.length - 1];
        let reason: string | undefined;
        if (!bind) {
          reason = 'No verified server session bind on this connection.';
        } else if (bind.forwarding) {
          reason = 'The last server session bind is for forwarding, not authentication.';
        } else if (!bind.hostKeyBlob.equals(parseOpenSshPublicKey(opts.pinnedHostKey))) {
          reason = 'The bound server identity does not match the approved server.';
        } else if (!isBoundUserauth(data, identity, bind, opts.pinnedUser)) {
          reason = 'The signing data is not a userauth request for the bound session.';
        }
        if (reason) {
          onOutcome?.('refused_binding', reason);
          return Buffer.from([SSH_AGENT_FAILURE]);
        }
      }

      const sig = cryptoSign(null, data, identity.privateKey);
      onOutcome?.('signed');
      return Buffer.concat([
        Buffer.from([SSH_AGENT_SIGN_RESPONSE]),
        sshString(Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(sig)])),
      ]);
    } catch {
      // Malformed sign request: fail this message, keep the listener alive.
      onOutcome?.('refused_malformed');
      return Buffer.from([SSH_AGENT_FAILURE]);
    }
  }

  return Buffer.from([SSH_AGENT_FAILURE]);
}

// ── the socket ─────────────────────────────────────────────────────────────────

export interface AgentHandle {
  socketPath: string;
  /** Path to the PUBLIC key, written so ssh can be pinned to this identity. */
  publicKeyPath: string;
  signCount: () => number;
  close: () => void;
}

/**
 * Start a signing-only agent on a private socket.
 *
 * The directory is created with mode 0700 and removed on close, so the socket is not
 * merely deleted but its parent goes too — a stray socket outliving its command is the
 * thing that turns a bounded capability into an ambient one.
 */
/**
 * Where the socket goes, and who may reach it.
 *
 * The default — a 0700 directory under the process's own tmpdir — is right when the
 * agent protocol is served by the same process that will run `ssh`. It is WRONG when the
 * broker serves it for somebody else: the unit sets `PrivateTmp=yes`, so the broker's
 * /tmp exists only inside its own mount namespace and the agent would never find the
 * socket; and even if it could see the path, a 0700 directory owned by `wundervault`
 * excludes the very uid that has to connect.
 *
 * So the broker passes its own directory under /run and opens the modes. The path and
 * session lifetime limit exposure; pinned agents additionally enforce the server's
 * session bind before signing. Unpinned agents retain the legacy signing behaviour.
 */
export interface AgentSocketOptions {
  /** Pre-made directory to host the socket. Caller owns its mode and its removal. */
  dir?: string;
  socketMode?: number;
  publicKeyMode?: number;
  /** Approved server public key: an OpenSSH public key line or a base64 wire blob. */
  pinnedHostKey?: string;
  /** The approved sign-in name on that server. With a pin, a userauth for any other name is
   *  refused: the owner approved user@host, not the host (review 13 r1 F1). */
  pinnedUser?: string;
}

export function startAgent(
  identity: LoadedIdentity,
  onSign?: (e: SignEvent) => void,
  host = '',
  opts: AgentSocketOptions = {},
): AgentHandle {
  if (process.platform === 'win32') {
    throw new Error('The ssh-agent broker needs unix domain sockets and POSIX permissions; run on Linux or macOS.');
  }

  // Validate before creating files, and snapshot the pin so the caller cannot change
  // the signing policy by mutating its options while a session is open.
  if (opts.pinnedHostKey !== undefined &&
      (typeof opts.pinnedUser !== 'string' || opts.pinnedUser.length === 0)) {
    throw new Error('A pinned SSH agent needs the approved user name too.');
  }
  const agentOpts: AgentSocketOptions = opts.pinnedHostKey === undefined
    ? {}
    : { pinnedHostKey: parseOpenSshPublicKey(opts.pinnedHostKey).toString('base64'), pinnedUser: opts.pinnedUser };

  const providedDir = typeof opts.dir === 'string' && opts.dir.length > 0;
  const dir = providedDir ? opts.dir! : mkdtempSync(path.join(os.tmpdir(), 'wv-agent-'));
  // mkdtemp is already 0700, but state it rather than inherit it by luck — and a umask
  // cannot widen it back. A caller-supplied directory keeps the mode its caller chose.
  if (!providedDir) chmodSync(dir, 0o700);
  const socketMode = opts.socketMode ?? 0o600;
  const publicKeyMode = opts.publicKeyMode ?? 0o600;
  const socketPath = path.join(dir, 'agent.sock');

  // The PUBLIC half, written to the same 0700 directory. This is not a secret, and ssh
  // needs it: IdentitiesOnly alone does NOT stop ssh trying ~/.ssh/id_* — the man page
  // says "either the default files, or those explicitly configured". Naming the public
  // key as IdentityFile is the documented way to pin one agent identity, and without it
  // a host that accepts some other local key would authenticate with that instead and
  // the broker key would never be used.
  const publicKeyPath = path.join(dir, 'id.pub');
  writeFileSync(
    publicKeyPath,
    `ssh-ed25519 ${identity.keyBlob.toString('base64')} ${identity.comment || 'wundervault'}\n`,
    { mode: publicKeyMode },
  );
  // writeFileSync's mode applies only when it CREATES the file, and is masked by umask
  // either way. The public half is not a secret, but ssh must be able to read it, and a
  // 0644 asked for under umask 0077 arrives as 0600 — which fails silently as "ssh did
  // not offer the key" rather than as a permission error.
  try { chmodSync(publicKeyPath, publicKeyMode); } catch { /* best effort */ }

  let signs = 0;
  const sockets = new Set<Socket>();

  const server: Server = createServer((conn) => {
    const state: AgentConnectionState = { binds: [] };
    sockets.add(conn);
    conn.setTimeout(CONNECTION_IDLE_MS, () => { try { conn.destroy(); } catch { /* ignore */ } });
    conn.on('close', () => sockets.delete(conn));
    conn.on('error', () => { try { conn.destroy(); } catch { /* ignore */ } });

    let buf = Buffer.alloc(0);
    conn.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      // One chunk can carry several messages, or part of one. Drain whole frames only.
      for (;;) {
        if (buf.length < 4) return;
        const len = buf.readUInt32BE(0);
        if (len === 0 || len > MAX_MESSAGE_BYTES) {
          // A nonsense frame length would otherwise make us buffer forever waiting for
          // bytes that are never coming.
          try { conn.destroy(); } catch { /* ignore */ }
          return;
        }
        if (buf.length < 4 + len) return;
        const msg = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);

        const reply = handleAgentMessage(msg, identity, (outcome, reason) => {
          if (outcome === 'signed') signs += 1;
          const ev: SignEvent = {
            fingerprint: identity.fingerprint, host, at: new Date().toISOString(), outcome,
            ...(outcome === 'signed' ? {} : { refused: true, reason: reason || outcome }),
          };
          // Always audited; the caller's sink is additional, never a replacement.
          defaultSignAudit(ev);
          onSign?.(ev);
        }, state, agentOpts);
        try { conn.write(Buffer.concat([u32(reply.length), reply])); } catch { /* peer went away */ }
      }
    });
  });

  server.on('error', () => { /* a dead listener surfaces as a failed ssh, not a crash */ });
  server.listen(socketPath, () => {
    // Belt and braces. The 0700 directory is what actually stops another user reaching
    // this — connecting needs traverse on the dir AND write on the socket — but the
    // socket lands 0775 under a default umask, so a single wrong directory mode would
    // otherwise leave it open to everyone. Tighten the socket itself too.
    try { chmodSync(socketPath, socketMode); } catch { /* the directory is still the guard */ }
  });

  let closed = false;
  const handle = {
    socketPath,
    publicKeyPath,
    signCount: () => signs,
    close: () => {
      if (closed) return;
      closed = true;
      for (const s of sockets) { try { s.destroy(); } catch { /* ignore */ } }
      sockets.clear();
      try { server.close(); } catch { /* ignore */ }
      // rm -rf the directory: removing only the socket would leave the 0700 dir behind
      // every single run. A caller-supplied directory is removed too — the broker makes
      // one per session for exactly this reason, so leaving it would accumulate a
      // directory per ssh call under /run.
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
      process.removeListener('exit', onExit);
    },
  };

  // A crash or an unhandled signal would otherwise strand a live signing socket in
  // /tmp. `exit` fires for a normal end and for an uncaught throw; it cannot help
  // against SIGKILL, which nothing can.
  const onExit = () => { try { handle.close(); } catch { /* shutting down anyway */ } };
  process.once('exit', onExit);

  return handle;
}

// ── brokered execution ─────────────────────────────────────────────────────────

export interface SshBrokerResult { exitCode: number; stdout: string; stderr: string; signCount: number; }

/**
 * Run a command with the key available for signing but never present as a file.
 *
 * `argv` is an array and there is no shell: a command containing `;` or `|` is passed
 * as a literal argument. That is the point — the caller names a program and arguments,
 * not a string for /bin/sh to reinterpret.
 *
 * The host allowlist is enforced at invocation. Callers that also pass an approved
 * server pin to startAgent restrict signatures to that server's verified session.
 * The legacy single-process path below does not supply a pin.
 */
/** Everything after `ssh` that stops it choosing its own credentials or destination. */
export function hardenedSshOptions(socketPath: string, publicKeyPath: string): string[] {
  return [
    // -F /dev/null FIRST: ~/.ssh/config can set IdentityAgent, ProxyCommand or a
    // different Hostname for a given pattern, which would let user config redirect a
    // brokered connection. GIT_SSH_COMMAND does not help here — it is git-only, and a
    // direct ssh invocation ignores it entirely.
    '-F', '/dev/null',
    // IdentityFile + IdentitiesOnly together are what actually pin this connection to
    // the broker key. IdentitiesOnly by itself still permits the default identity files.
    '-o', `IdentityFile=${publicKeyPath}`,
    '-o', 'IdentitiesOnly=yes',
    '-o', `IdentityAgent=${socketPath}`,
    '-o', 'BatchMode=yes',              // never block on a passphrase or password prompt
    '-o', 'StrictHostKeyChecking=accept-new',
  ];
}

/** `user@host` → `host`. The allowlist is about the destination, not who you log in as. */
export function hostOf(destination: string): string {
  const at = destination.lastIndexOf('@');
  return at === -1 ? destination : destination.slice(at + 1);
}

/**
 * An rsync argument that names a remote side looks like `[user@]host:path`. Anything
 * with no colon before the first slash is a local path and needs no check.
 */
export function rsyncRemoteHost(arg: string): string | null {
  const colon = arg.indexOf(':');
  if (colon <= 0) return null;
  const slash = arg.indexOf('/');
  if (slash !== -1 && slash < colon) return null;   // e.g. ./weird:name
  return hostOf(arg.slice(0, colon));
}

/**
 * Quote one argument for the remote shell.
 *
 * `ssh host -- a b c` does NOT pass an argv: OpenSSH joins the arguments with spaces and
 * hands the result to the remote login shell. So an argument containing `;` executes on
 * the far side even though nothing was interpreted locally. Single-quoting, with the
 * usual '"'"' dance for embedded quotes, is what makes each element one literal word.
 */
export function quoteForRemoteShell(arg: string): string {
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

export type BrokeredOp =
  | { kind: 'ssh'; destination: string; remoteArgv: string[] }
  | { kind: 'rsync'; destination: string; rsyncArgs: string[] }
  // vault_git: every URL git will connect to for this subcommand, resolved by the caller
  // with git's own rules (pushurl, insteadOf). The broker checks EACH one.
  | { kind: 'git'; destination: string; urls: string[]; subcommand?: string };

/**
 * Is this destination one the entry authorises, and what host should the audit name?
 *
 * Split out of `runSshBrokered` so the BROKER can make this decision. It used to run in
 * the MCP server — the agent's own process — which meant the allowlist was advice the
 * caller gave itself. The broker now refuses to open a signing session for a host the
 * entry does not list, so the check happens where the key is.
 */
export function checkSshDestination(
  op: BrokeredOp,
  allowedHosts: string[],
): { ok: true; auditedHost: string } | { ok: false; error: string } {
  // Fail closed. An entry that names no hosts authorises nothing — treating "unset" as
  // "anywhere" is how an allowlist becomes decoration.
  if (!allowedHosts || allowedHosts.length === 0) {
    return { ok: false, error:
      'Refused: this entry lists no permitted SSH hosts, so it authorises nothing. '
      + "Add ssh_hosts to the entry's exec_config in the dashboard." };
  }

  if (op.kind === 'git') {
    if (!Array.isArray(op.urls) || op.urls.length === 0 || op.urls.length > 16) {
      return { ok: false, error: 'Refused: a git operation must name the addresses it connects to.' };
    }
    const hosts: string[] = [];
    for (const u of op.urls) {
      const parsed = typeof u === 'string' ? parseGitSshUrl(u) : { ok: false as const, reason: 'not text' };
      if (!parsed.ok) return { ok: false, error: 'Refused: git would connect to an address that is not SSH.' };
      if (!allowedHosts.includes(parsed.host)) {
        return { ok: false, error:
          `Refused: git would connect to "${parsed.host}", which is not in this entry's permitted hosts (${allowedHosts.join(', ')}).` };
      }
      if (!hosts.includes(parsed.host)) hosts.push(parsed.host);
    }
    return { ok: true, auditedHost: hosts.join(',') };
  }

  const host = hostOf(op.destination);
  if (!allowedHosts.includes(host)) {
    return { ok: false, error:
      `Refused: "${host}" is not in this entry's permitted hosts (${allowedHosts.join(', ')}).` };
  }

  if (op.kind === 'ssh') {
    if (!Array.isArray(op.remoteArgv) || op.remoteArgv.length === 0) {
      return { ok: false, error: 'Refused: remoteArgv must be a non-empty array.' };
    }
  } else {
    if (!Array.isArray(op.rsyncArgs) || op.rsyncArgs.length === 0) {
      return { ok: false, error: 'Refused: rsyncArgs must be a non-empty array.' };
    }
    // rsync carries its destination inside its path arguments, so every remote-looking
    // argument is checked against the same allowlist rather than trusting one field.
    for (const a of op.rsyncArgs) {
      const h = rsyncRemoteHost(a);
      if (h !== null && !allowedHosts.includes(h)) {
        return { ok: false, error:
          `Refused: rsync argument targets "${h}", which is not in this entry's permitted hosts (${allowedHosts.join(', ')}).` };
      }
    }
  }

  // rsync carries its destination in its path arguments, so with two allowlisted hosts
  // it can connect to the second while `destination` names the first — and every
  // signature line would then record a host the key was never used against. Audit what
  // the arguments actually target.
  let auditedHost = host;
  if (op.kind === 'rsync' && Array.isArray(op.rsyncArgs)) {
    const targets = [...new Set(op.rsyncArgs.map(rsyncRemoteHost).filter((h): h is string => h !== null))];
    if (targets.length > 0) auditedHost = targets.join(',');
  }
  return { ok: true, auditedHost };
}

/**
 * The argv for a brokered operation, given a signing socket somebody else is hosting.
 *
 * The destination is OURS, not the caller's. Previously the caller passed a whole argv
 * and the validated host was merely advisory: argv ["ssh","evil.example"] sailed through
 * a check for "good.example" and the key signed for evil.example. Building the command
 * here makes the check the thing that decides.
 */
export function buildSshArgv(op: BrokeredOp, socketPath: string, publicKeyPath: string, knownHostsPath?: string): string[] {
  if (op.kind === 'git') throw new Error('a git operation is run by vault_git, not as an ssh command');
  if (op.kind === 'ssh') {
    // A pinned server (spec 1.3): only the broker-written identity is trusted, and a
    // user@host:port destination becomes -p port + user@host.
    if (knownHostsPath) {
      const m = /^(.*):([0-9]{1,5})$/.exec(op.destination);
      return [
        'ssh', ...pinnedSshOptions(socketPath, publicKeyPath, knownHostsPath),
        ...(m ? ['-p', m[2]] : []), m ? m[1] : op.destination, '--',
        (op.remoteArgv as string[]).map(quoteForRemoteShell).join(' '),
      ];
    }
    // One quoted string, not N arguments: see quoteForRemoteShell.
    return [
      'ssh', ...hardenedSshOptions(socketPath, publicKeyPath), op.destination, '--',
      (op.remoteArgv as string[]).map(quoteForRemoteShell).join(' '),
    ];
  }
  const sshCmd = ['ssh', ...hardenedSshOptions(socketPath, publicKeyPath)]
    .map((t) => (/[\s"']/.test(t) ? JSON.stringify(t) : t)).join(' ');
  return ['rsync', '-e', sshCmd, ...(op.rsyncArgs as string[])];
}

/**
 * Run the command against a signing socket this process does NOT own.
 *
 * This is the half that stays in the agent's process after key custody moved. The broker
 * holds the private key and answers signatures; the command is the agent's own, run on
 * the agent's own machine, as the agent's own uid. The broker must never run it — a
 * broker that executes a caller-supplied command hands that caller code execution as the
 * uid that owns every credential on the box.
 */
export async function runSshWithAgent(opts: {
  op: BrokeredOp;
  socketPath: string;
  publicKeyPath: string;
  cwd?: string;
  timeoutMs?: number;
  /** Spec 1.3: the broker-written identity of a pinned server; strict checking against it. */
  knownHostsPath?: string;
  /** Admin access ended: kill the connection now (site SPEC-admin-access D7). */
  signal?: AbortSignal;
}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const { op, socketPath, publicKeyPath, cwd, timeoutMs = 120_000, knownHostsPath, signal } = opts;
  const argv = buildSshArgv(op, socketPath, publicKeyPath, knownHostsPath);

  // spawn, NOT spawnSync. When this process hosts the agent listener, a synchronous
  // spawn blocks the very loop that has to answer the child's signature request. It is
  // kept asynchronous now that the broker hosts it too, because the child still has to
  // be able to talk while we wait.
  return await new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), {
      shell: false,
      cwd,
      env: { ...process.env, SSH_AUTH_SOCK: socketPath },
    });

    // Bounded. A chatty or hostile remote could otherwise grow these strings for the
    // whole timeout window; truncation is visible rather than silent.
    const MAX_OUTPUT = 4 * 1024 * 1024;
    let stdout = '';
    let stderr = '';
    let truncated = false;
    const append = (cur: string, add: string): string => {
      if (cur.length >= MAX_OUTPUT) { truncated = true; return cur; }
      const room = MAX_OUTPUT - cur.length;
      if (add.length > room) { truncated = true; return cur + add.slice(0, room); }
      return cur + add;
    };
    let settled = false;
    const finish = (exitCode: number, extra = '') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const note = truncated ? `\n[output truncated at ${MAX_OUTPUT} bytes]` : '';
      resolve({ exitCode, stdout, stderr: stderr + extra + note });
    };

    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      finish(124, `\nCommand timed out after ${Math.round(timeoutMs / 1000)}s.`);
    }, timeoutMs);

    const onAbort = () => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      finish(125, `\n${String(signal?.reason ?? 'Stopped.')}`);
    };
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });

    child.stdout?.on('data', (d) => { stdout = append(stdout, d.toString()); });
    child.stderr?.on('data', (d) => { stderr = append(stderr, d.toString()); });
    child.on('error', (e) => finish(1, `\nFailed to run ${argv[0]}: ${e.message}`));
    child.on('close', (code) => finish(code ?? 1));
  });
}

/**
 * Check, start an agent, run, close — the single-process path.
 *
 * Kept because it is the whole operation in one call for the pre-split layout, for
 * macOS and Windows, and for the tests that exercise the allowlist and the argv
 * construction end to end. After key custody it is composed from the three pieces above
 * rather than duplicating them, so a change to the allowlist cannot apply to one path
 * and not the other.
 */
export async function runSshBrokered(opts: {
  identity: LoadedIdentity;
  op: BrokeredOp;
  allowedHosts: string[];
  cwd?: string;
  timeoutMs?: number;
  onSign?: (e: SignEvent) => void;
}): Promise<SshBrokerResult> {
  const { identity, op, allowedHosts, cwd, timeoutMs = 120_000, onSign } = opts;

  const check = checkSshDestination(op, allowedHosts);
  if (!check.ok) return { exitCode: 1, stdout: '', stderr: check.error, signCount: 0 };

  const agent = startAgent(identity, onSign, check.auditedHost);
  try {
    const r = await runSshWithAgent({
      op, socketPath: agent.socketPath, publicKeyPath: agent.publicKeyPath, cwd, timeoutMs,
    });
    return { ...r, signCount: agent.signCount() };
  } finally {
    // Always — including on throw and on timeout. A socket outliving its command is an
    // ambient signing capability.
    agent.close();
  }
}

// ── entry mode gating ──────────────────────────────────────────────────────────

export const BROKER_SSH_AGENT = 'BROKER_SSH_AGENT';
export const BROKER_HTTP = 'BROKER_HTTP';
export const BROKER_WALLET = 'BROKER_WALLET';
export const BROKER_SIGN = 'BROKER_SIGN';

/**
 * Which tool an entry may be used through — one tool per mode, and nothing else (spec §A1a):
 * a web-service key through vault_call, an SSH key through vault_ssh_exec, a wallet through
 * vault_pay, a signing key through vault_sign. Checked in the broker before the key is
 * decrypted.
 *
 * Anything else — an unknown mode, a missing one, or the retired LEGACY_EXEC (hand-over),
 * which the 1.0 server converts and refuses to serve — matches none, so it fails CLOSED.
 * There is no path left that a mode could fall back to.
 */
function modeIs(mode: string | undefined, want: string): boolean {
  return (mode || '').trim().toUpperCase() === want;
}
export function modeAllowsSshBroker(mode: string | undefined): boolean { return modeIs(mode, BROKER_SSH_AGENT); }
export function modeAllowsHttpBroker(mode: string | undefined): boolean { return modeIs(mode, BROKER_HTTP); }
export function modeAllowsWallet(mode: string | undefined): boolean { return modeIs(mode, BROKER_WALLET); }
export function modeAllowsSign(mode: string | undefined): boolean { return modeIs(mode, BROKER_SIGN); }

const MODES: Record<string, { kind: string; tool: string }> = {
  [BROKER_SSH_AGENT]: { kind: 'an SSH key', tool: 'vault_ssh_exec' },
  [BROKER_HTTP]: { kind: 'a web-service secret', tool: 'vault_call' },
  [BROKER_WALLET]: { kind: 'a wallet', tool: 'vault_pay' },
  [BROKER_SIGN]: { kind: 'a signing key', tool: 'vault_sign' },
};
const WANTED = { ssh: BROKER_SSH_AGENT, http: BROKER_HTTP, wallet: BROKER_WALLET, sign: BROKER_SIGN } as const;

export function wrongModeMessage(mode: string | undefined, wanted: keyof typeof WANTED): string {
  const m = (mode || '').trim().toUpperCase() || 'no';
  const have = MODES[m];
  if (!have) {
    return `Refused: this entry is in ${m} mode, which 1.0 does not use — secrets are no longer `
      + 'handed to agents. The owner needs to choose in the dashboard what kind of secret it is.';
  }
  return `Refused: this entry is ${have.kind}, not ${MODES[WANTED[wanted]].kind}. Use ${have.tool} with it, or the owner `
    + 'can change how it is used in the dashboard.';
}
