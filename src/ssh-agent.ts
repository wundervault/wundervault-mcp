/**
 * An ssh-agent that holds the key instead of handing it over.
 *
 * `vault_rsync` and remote `vault_exec` currently write the private key to a temp file
 * for the duration of the transfer. Anything running as the same user can read it while
 * it is there. The ssh-agent protocol exists precisely so a private key never has to
 * leave the process that holds it: ssh asks for a signature over the session data, the
 * agent answers, and the key stays put.
 *
 * SCOPE, stated plainly: this daemon runs as the agent's own uid, so this is NOT yet a
 * confidentiality boundary — a same-uid process can still reach the key in memory, and
 * while the socket is alive it could ask this agent to sign for a host the command was
 * never authorised for. What this buys today is that the key stops touching the disk,
 * every signature becomes an audit event, and the socket lives only as long as one
 * command. When the daemon moves to its own uid, the same interface becomes a real
 * boundary with no further API change.
 */
import { createPrivateKey, createPublicKey, sign as cryptoSign, createHash, KeyObject } from 'node:crypto';
import { createServer, Server, Socket } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, chmodSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// ── protocol constants (PROTOCOL.agent) ────────────────────────────────────────
const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;

/** A framed agent message longer than this is refused rather than buffered. */
const MAX_MESSAGE_BYTES = 256 * 1024;

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

// ── protocol handling ──────────────────────────────────────────────────────────

export interface SignEvent { fingerprint: string; host: string; at: string; }

/**
 * Answer one agent message. Pure — no I/O — so the protocol is testable without sockets.
 * Returns the reply body; the caller frames it.
 */
export function handleAgentMessage(
  msg: Buffer,
  identity: LoadedIdentity,
  onSign?: () => void,
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

  if (type === SSH_AGENTC_SIGN_REQUEST) {
    try {
      const r = new Reader(msg, 1);
      const wantBlob = r.str();
      const data = r.str();
      // flags are read but unused: ed25519 has no rsa-sha2 variants to select.
      if (r.remaining >= 4) r.u32();

      // A sign request naming a key this agent does not hold is refused rather than
      // signed with whatever it does hold.
      if (!wantBlob.equals(identity.keyBlob)) return Buffer.from([SSH_AGENT_FAILURE]);

      const sig = cryptoSign(null, data, identity.privateKey);
      onSign?.();
      return Buffer.concat([
        Buffer.from([SSH_AGENT_SIGN_RESPONSE]),
        sshString(Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(sig)])),
      ]);
    } catch {
      // Malformed sign request: fail this message, keep the listener alive.
      return Buffer.from([SSH_AGENT_FAILURE]);
    }
  }

  return Buffer.from([SSH_AGENT_FAILURE]);
}

// ── the socket ─────────────────────────────────────────────────────────────────

export interface AgentHandle {
  socketPath: string;
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
export function startAgent(identity: LoadedIdentity, onSign?: (e: SignEvent) => void, host = ''): AgentHandle {
  if (process.platform === 'win32') {
    throw new Error('The ssh-agent broker needs unix domain sockets and POSIX permissions; run on Linux or macOS.');
  }

  const dir = mkdtempSync(path.join(os.tmpdir(), 'wv-agent-'));
  // mkdtemp is already 0700, but state it rather than inherit it by luck — and a umask
  // cannot widen it back.
  chmodSync(dir, 0o700);
  const socketPath = path.join(dir, 'agent.sock');

  let signs = 0;
  const sockets = new Set<Socket>();

  const server: Server = createServer((conn) => {
    sockets.add(conn);
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

        const reply = handleAgentMessage(msg, identity, () => {
          signs += 1;
          onSign?.({ fingerprint: identity.fingerprint, host, at: new Date().toISOString() });
        });
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
    try { chmodSync(socketPath, 0o600); } catch { /* the directory is still the guard */ }
  });

  let closed = false;
  const handle = {
    socketPath,
    signCount: () => signs,
    close: () => {
      if (closed) return;
      closed = true;
      for (const s of sockets) { try { s.destroy(); } catch { /* ignore */ } }
      sockets.clear();
      try { server.close(); } catch { /* ignore */ }
      // rm -rf the directory: removing only the socket would leave the 0700 dir behind
      // every single run.
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
 * The host allowlist is enforced here, at invocation, rather than inside the agent
 * protocol. The honest limitation: while the socket is alive, a same-uid process could
 * ask this agent to sign for some other host. Closing that needs OpenSSH's
 * restrict-destination session-bind extension, and is out of scope for this build.
 */
export async function runSshBrokered(opts: {
  identity: LoadedIdentity;
  host: string;
  allowedHosts: string[];
  argv: string[];
  cwd?: string;
  timeoutMs?: number;
  onSign?: (e: SignEvent) => void;
}): Promise<SshBrokerResult> {
  const { identity, host, allowedHosts, argv, cwd, timeoutMs = 120_000, onSign } = opts;

  // Fail closed. An entry that names no hosts authorises nothing — the alternative,
  // treating "unset" as "anywhere", is how an allowlist becomes decoration.
  if (!allowedHosts || allowedHosts.length === 0) {
    return { exitCode: 1, stdout: '', stderr:
      'Refused: this entry lists no permitted SSH hosts, so it authorises nothing. '
      + "Add ssh_hosts to the entry's exec_config in the dashboard.", signCount: 0 };
  }
  if (!allowedHosts.includes(host)) {
    return { exitCode: 1, stdout: '', stderr:
      `Refused: "${host}" is not in this entry's permitted hosts (${allowedHosts.join(', ')}).`,
      signCount: 0 };
  }
  if (!Array.isArray(argv) || argv.length === 0) {
    return { exitCode: 1, stdout: '', stderr: 'Refused: argv must be a non-empty array.', signCount: 0 };
  }

  const agent = startAgent(identity, onSign, host);
  try {
    // spawn, NOT spawnSync. The agent's listener lives on this process's event loop, so
    // a synchronous spawn would block the very loop that has to answer the child's
    // signature request — the command would hang until its timeout, every time.
    return await new Promise<SshBrokerResult>((resolve) => {
      const child = spawn(argv[0], argv.slice(1), {
        shell: false,
        cwd,
        env: {
          ...process.env,
          SSH_AUTH_SOCK: agent.socketPath,
          // Stop ssh reaching for ~/.ssh/id_* or a previously-forwarded agent: this
          // command authenticates with THIS key or not at all.
          GIT_SSH_COMMAND: `ssh -o IdentitiesOnly=yes -o IdentityAgent=${agent.socketPath}`,
        },
      });

      let stdout = '';
      let stderr = '';
      let settled = false;
      const finish = (exitCode: number, extra = '') => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ exitCode, stdout, stderr: stderr + extra, signCount: agent.signCount() });
      };

      const timer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* already gone */ }
        finish(124, `\nCommand timed out after ${Math.round(timeoutMs / 1000)}s.`);
      }, timeoutMs);

      child.stdout?.on('data', (d) => { stdout += d.toString(); });
      child.stderr?.on('data', (d) => { stderr += d.toString(); });
      child.on('error', (e) => finish(1, `\nFailed to run ${argv[0]}: ${e.message}`));
      child.on('close', (code) => finish(code ?? 1));
    });
  } finally {
    // Always — including on throw and on timeout. A socket outliving its command is an
    // ambient signing capability.
    agent.close();
  }
}
