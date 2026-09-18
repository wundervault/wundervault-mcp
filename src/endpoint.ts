/**
 * WHERE THE BROKER LISTENS, AND HOW AN AGENT REACHES IT.
 *
 * On Linux and macOS this is a unix domain socket at a path, and nothing in this file
 * changes that — `endpointFor()` returns the same path the rest of the code always used
 * and `listenOn()` calls `server.listen(path)`. The Windows work below must not reach the
 * other two platforms, because a phase that was supposed to leave them alone has broken
 * them twice already.
 *
 * WHY WINDOWS CANNOT USE EITHER OF THE OBVIOUS ANSWERS
 *
 * A unix socket is not available: `listen()` on a filesystem path returns EACCES, measured
 * on Windows 10 22H2 with Node 22. libuv wants a named pipe.
 *
 * A NAMED PIPE IS WORSE, and the measurement that settled it is the one worth keeping.
 * libuv calls `CreateNamedPipeW` with a NULL security descriptor and Node exposes no way
 * to supply one, so the pipe gets the creating account's default DACL. With the server
 * running as a non-admin service account:
 *
 *   client as a local ADMINISTRATOR      connect OK, round trip OK
 *   client as a non-admin local account  EPERM: connect
 *
 * The first line is the trap. Every developer box runs its agents as an administrator, so
 * a pipe transport passes every test anyone would write and then fails for every customer
 * whose agents run unprivileged. "It works on my machine" would have been literally true.
 *
 * SO: LOOPBACK TCP, WITH A DAEMON-OWNED DISCOVERY FILE.
 *
 * The daemon binds 127.0.0.1:0 and writes the port it actually got into a file in the run
 * directory, which everyone can read and only the daemon can write. An OS-assigned port,
 * not a derived one — deriving the port is exactly how the single-instance lock shipped
 * broken on macOS (eight candidates inside the ephemeral range, two live holders of one
 * credential), and a derived port carries a birthday bound that an assigned one does not.
 *
 * This is the same exposure as the 0666 unix sockets: any local process can connect, and
 * the token decides what it gets. `paths.ts` argues that position at length and it is
 * unchanged here.
 *
 * THE ONE THING A PORT IS WEAKER AT, AND WHY IT IS CLOSED RATHER THAN DOCUMENTED
 *
 * A unix socket lives at a path inside a directory only the daemon can write, so nobody
 * else can put something there for an agent to find. A PORT is different: once the daemon
 * dies, its port is free, and any local process can bind it and answer as the broker while
 * the discovery file still points at it.
 *
 * So before an agent sends its token it sends a nonce, and the broker signs
 *
 *     wv-broker-hello-v1:<nonce>:<port>:<server_id>
 *
 * with the P-256 identity key phase 6 already gave it. The agent verifies against
 * `broker.pub`, published beside the discovery files. A squatter has no private key, so
 * the agent refuses and reports the broker as unavailable rather than handing a credential
 * to a stranger. The nonce is what stops a captured banner being replayed — `broker.pub`
 * and the port file are both world-readable, so a banner with nothing fresh in it would be
 * a replay waiting to happen.
 *
 * WHAT THE HANDSHAKE DOES NOT BUY. A rogue process running as the owner can already read
 * every agent's token out of `%USERPROFILE%\.wundervault\agents\*.token`, because all
 * agents run as the owner. This stops a stale port being answered by a stranger. It does
 * not make one agent safe from another — nothing local does, and phases 6 and 7 say so.
 */
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  platformShape, runtimeDir, mgmtSocketPath, agentSocketPath, mgmtDir, safeName,
} from './paths.js';

export const HELLO_VERSION = 'wv-broker-hello-v1';

/** How the broker is addressed on this platform. */
export type Endpoint =
  | { kind: 'path'; address: string }
  | { kind: 'port'; file: string };

/** True where the broker is reached by a port rather than a path. */
export function usesPortFiles(): boolean {
  return platformShape() === 'windows';
}

export function mgmtEndpoint(): Endpoint {
  return usesPortFiles()
    ? { kind: 'port', file: path.join(mgmtDir(), 'mgmt.port') }
    : { kind: 'path', address: mgmtSocketPath() };
}

export function agentEndpoint(name: string): Endpoint {
  return usesPortFiles()
    ? { kind: 'port', file: path.join(runtimeDir(), `${safeName(name)}.port`) }
    : { kind: 'path', address: agentSocketPath(name) };
}

/** Where the broker's public key is published for agents to verify against. */
export function brokerPubPath(): string {
  return path.join(runtimeDir(), 'broker.pub');
}

/** What a person should see in a message: a path, or an address they can check. */
export function endpointLabel(ep: Endpoint): string {
  if (ep.kind === 'path') return ep.address;
  const rec = readPortFile(ep.file);
  return rec ? `127.0.0.1:${rec.port} (${ep.file})` : ep.file;
}

export interface PortRecord {
  port: number;
  pid: number;
  server_id: string;
}

export function readPortFile(file: string): PortRecord | null {
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<PortRecord>;
    if (!Number.isInteger(raw.port) || raw.port! < 1 || raw.port! > 65535) return null;
    if (typeof raw.server_id !== 'string' || raw.server_id.length < 16) return null;
    return { port: raw.port!, pid: Number(raw.pid) || 0, server_id: raw.server_id };
  } catch { return null; }
}

// ── the daemon's side ─────────────────────────────────────────────────────────

/**
 * Everything the daemon needs to prove it is the daemon. Built once per process.
 *
 * `server_id` is fresh per start, so a discovery file left behind by a previous daemon
 * cannot be mistaken for this one's.
 */
export interface HelloSigner {
  serverId: string;
  sign(message: string): string;
}

export function helloSignerFrom(privateKeyPem: string): HelloSigner {
  const serverId = crypto.randomBytes(16).toString('hex');
  return {
    serverId,
    sign(message: string): string {
      return crypto.createSign('SHA256').update(message).sign(privateKeyPem).toString('base64');
    },
  };
}

/**
 * Bind, and record where we bound.
 *
 * REFUSES rather than retries. A daemon that cannot bind, or cannot write the file that
 * tells agents where it is, is a daemon nobody can reach — and the failure mode this
 * replaces (walk to another port, carry on) is the one that put two live holders on one
 * credential on macOS.
 */
export function listenOn(
  server: net.Server,
  ep: Endpoint,
  signer: HelloSigner | null,
  onReady: (label: string) => void,
  onError: (message: string) => void,
): void {
  if (ep.kind === 'path') {
    server.listen(ep.address, () => {
      // World-connectable BY DESIGN — see paths.ts. The daemon is a different uid from
      // every agent, so a mode that excluded others would exclude the agent too. The
      // token is the identity; this mode is not a control and must not be read as one.
      try { fs.chmodSync(ep.address, 0o666); } catch { /* best effort */ }
      onReady(ep.address);
    });
    return;
  }

  if (!signer) {
    onError(
      `Refusing to listen for ${path.basename(ep.file)}: the broker has no identity key, ` +
      `so it cannot prove to an agent that it is the broker. Run the installer.`,
    );
    return;
  }

  server.listen(0, '127.0.0.1', () => {
    const addr = server.address();
    if (!addr || typeof addr === 'string') {
      onError(`Bound ${ep.file} but the address is not a TCP address. Refusing to serve.`);
      try { server.close(); } catch { /* already gone */ }
      return;
    }
    const rec: PortRecord = { port: addr.port, pid: process.pid, server_id: signer.serverId };
    try {
      // Written whole and renamed into place. A half-written discovery file read by an
      // agent mid-write is a connection to a port that is not ours.
      const tmp = `${ep.file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(rec), { mode: 0o644 });
      fs.renameSync(tmp, ep.file);
    } catch (e) {
      onError(
        `Bound 127.0.0.1:${addr.port} but could not write ${ep.file}: ` +
        `${(e as Error).message}. No agent could find this broker, so it is not serving.`,
      );
      try { server.close(); } catch { /* already gone */ }
      return;
    }
    onReady(`127.0.0.1:${addr.port}`);
  });
}

/**
 * Is another broker already serving here?
 *
 * ON A UNIX SOCKET THIS QUESTION ANSWERS ITSELF: two daemons cannot bind one path, so the
 * second gets EADDRINUSE and stops. A PORT gives no such answer -- `listen(0)` always
 * succeeds -- so on Windows two brokers happily ran side by side, and the second
 * OVERWROTE the discovery files the first had published. Every agent on the machine was
 * then pointed at whichever daemon started last.
 *
 * That is not hypothetical. It happened during this phase's own testing: a mistyped flag
 * started a second broker as the wrong user, and the discovery files followed it.
 *
 * So the daemon asks before it publishes. A previous instance's file naming a port that
 * still accepts a connection means a live broker, and starting a second one would take its
 * agents away from it. A file naming a port nothing answers is a crash leftover and is
 * ignored -- which is the common case and must not be turned into a refusal.
 *
 * The check is a race in principle: two daemons starting in the same few milliseconds
 * could both find nothing. It closes the case that actually happens -- a second start
 * while the first is running -- and says so rather than claiming to be a lock.
 */
export async function anotherBrokerIsServing(ep: Endpoint, timeoutMs = 3000): Promise<boolean> {
  if (ep.kind !== 'port') return false;
  const rec = readPortFile(ep.file);
  if (!rec) return false;
  // NO pid GUARD. There was one -- "if the file names our own pid, it is us" -- and it
  // only ever produced false negatives: this runs BEFORE we publish anything, so a file
  // that is there belongs to another run, and a pid that matches by coincidence (reuse
  // after a crash) would wave a live sibling through. The signature below is the
  // discriminator; a pid is a hint, and a hint is not a check.

  // ASKS THE FAR END TO PROVE IT IS A BROKER, rather than merely noting that something
  // answers. The first version treated any open port as a live broker, and that is a trap
  // rather than a safeguard: after a crash the discovery file survives, its port goes back
  // to the ephemeral pool, an unrelated program takes it, and the daemon then refuses to
  // start FOR EVER over a file nobody will think to delete. Observed in testing, against a
  // leftover file from an earlier run.
  //
  // connectToEndpoint already asks exactly the right question -- it sends a nonce, checks
  // the signature against broker.pub, and checks the instance id against the file -- so a
  // stranger on a recycled port fails it and we carry on, while a live sibling passes it
  // and we stop. On a first start there is no broker.pub yet, which also fails, which is
  // also correct.
  try {
    const probe = await connectToEndpoint(ep, timeoutMs);
    try { probe.destroy(); } catch { /* already gone */ }
    return true;
  } catch {
    return false;
  }
}

/** Remove a discovery file on a clean stop, so a stale one never points at a free port. */
export function releaseEndpoint(ep: Endpoint): void {
  const target = ep.kind === 'path' ? ep.address : ep.file;
  try { fs.unlinkSync(target); } catch { /* never existed, or already gone */ }
}

/**
 * Wrap a connection handler so it answers the hello first, on Windows only.
 *
 * On every other platform this returns the handler UNCHANGED — not a wrapper that happens
 * to pass through, the same function object — so there is no new code between a Linux
 * agent and the daemon it has been talking to since phase 4.
 *
 * A client that does NOT send a hello is served exactly as before: the buffered bytes are
 * handed straight to the real handler. The handshake protects the CLIENT, so making it
 * mandatory would only break old agents without protecting anyone.
 */
export function withHello(
  onConnection: (socket: net.Socket) => void,
  signer: HelloSigner | null,
  port: () => number,
): (socket: net.Socket) => void {
  if (!usesPortFiles()) return onConnection;

  return (socket: net.Socket) => {
    // BUFFERS, NOT A STRING, and agent.ts already explains why at length: decoding each
    // TCP chunk independently turns a multi-byte character split across two reads into
    // replacement characters, silently, and only for non-ASCII payloads. This wrapper sits
    // in front of that handler and had reintroduced the exact bug it was written to fix --
    // twice over, since it also re-encoded the remainder with Buffer.from(rest, 'utf8')
    // before handing it on. Nothing is decoded here except one complete line.
    let buf: Buffer = Buffer.alloc(0);
    let settled = false;

    const handOff = (rest: Buffer) => {
      if (settled) return;
      settled = true;
      clearTimeout(helloDeadline);
      socket.removeListener('data', onData);
      onConnection(socket);
      if (rest.length > 0) socket.emit('data', rest);
    };

    // A DEADLINE BEFORE THE HANDOFF. Every timeout the real handler sets is armed inside
    // onConnection, so until this wrapper hands over there is nothing bounding the
    // connection: a client that opens a socket and never sends a newline holds a file
    // descriptor for ever. That is the resource-exhaustion shape agent.ts documents at
    // length, and this wrapper sat in front of all of it.
    const helloDeadline = setTimeout(() => {
      if (!settled) { try { socket.destroy(); } catch { /* already gone */ } }
    }, 10_000);
    (helloDeadline as unknown as { unref?: () => void }).unref?.();
    socket.on('close', () => clearTimeout(helloDeadline));

    const onData = (d: Buffer) => {
      buf = buf.length === 0 ? Buffer.from(d) : Buffer.concat([buf, d]);
      // A hello is tiny. Anything larger than this before a newline is not one, and is
      // the real handler's business — including its own size ceilings.
      if (buf.length > 4096) { handOff(buf); return; }
      const nl = buf.indexOf(0x0a);
      if (nl === -1) return;

      const line = buf.subarray(0, nl).toString('utf8');
      const rest = buf.subarray(nl + 1);
      let msg: { hello?: unknown; nonce?: unknown } | null = null;
      try {
        const parsed = JSON.parse(line) as unknown;
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          msg = parsed as { hello?: unknown; nonce?: unknown };
        }
      } catch { /* not JSON: the real handler says what it thinks of that */ }

      if (!msg || msg.hello !== HELLO_VERSION || typeof msg.nonce !== 'string') {
        handOff(buf);
        return;
      }

      // A nonce we are about to sign over. Bounded, because it is attacker-chosen and is
      // about to become part of a signed message.
      const nonce = msg.nonce.slice(0, 128);
      if (!signer) {
        try { socket.write(JSON.stringify({ error: 'no broker identity' }) + '\n'); } catch { /* gone */ }
        try { socket.end(); } catch { /* gone */ }
        return;
      }
      const p = port();
      const sig = signer.sign(`${HELLO_VERSION}:${nonce}:${p}:${signer.serverId}`);
      try {
        socket.write(JSON.stringify({
          hello: HELLO_VERSION, server_id: signer.serverId, port: p, sig,
        }) + '\n');
      } catch { /* the client hung up mid-handshake */ }

      // The connection continues. The agent sends its real request next, and the existing
      // handler owns the socket from here.
      settled = true;
      clearTimeout(helloDeadline);
      socket.removeListener('data', onData);
      onConnection(socket);
      if (rest.length > 0) socket.emit('data', rest);
    };

    socket.on('data', onData);
  };
}

// ── the agent's side ──────────────────────────────────────────────────────────

export class EndpointUnreachable extends Error {}
export class BrokerNotAuthentic extends Error {}

/**
 * Connect, and on Windows do not say a word until the far end has proved who it is.
 *
 * The order matters and is the whole point: nonce out, signature in, verify, and only then
 * does the caller get a socket it may write a token to.
 */
export function connectToEndpoint(ep: Endpoint, timeoutMs: number): Promise<net.Socket> {
  if (ep.kind === 'path') {
    return Promise.resolve(net.createConnection(ep.address));
  }

  return new Promise((resolve, reject) => {
    const rec = readPortFile(ep.file);
    if (!rec) {
      reject(new EndpointUnreachable(
        `No broker is listening: ${ep.file} is missing or unreadable.`));
      return;
    }
    const pub = loadBrokerPublicKey();
    if (!pub) {
      reject(new BrokerNotAuthentic(
        `Cannot verify the broker: ${brokerPubPath()} is missing or unreadable, and this ` +
        `platform reaches the broker by a port, which anything local can bind.`));
      return;
    }

    const nonce = crypto.randomBytes(16).toString('hex');
    const socket = net.createConnection({ host: '127.0.0.1', port: rec.port });
    // Buffers here too, for the same reason as withHello: the remainder is handed to the
    // caller's handler, and a string round trip corrupts anything non-ASCII that arrived
    // in the same TCP read as the banner.
    let buf: Buffer = Buffer.alloc(0);
    let done = false;
    const fail = (err: Error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* already gone */ }
      reject(err);
    };
    const timer = setTimeout(
      () => fail(new EndpointUnreachable(
        `The broker at 127.0.0.1:${rec.port} did not answer the handshake.`)),
      Math.min(timeoutMs, 15_000),
    );

    socket.on('error', (e) => fail(new EndpointUnreachable(
      `Could not reach the broker at 127.0.0.1:${rec.port}: ${e.message}`)));
    socket.on('connect', () => {
      socket.write(JSON.stringify({ hello: HELLO_VERSION, nonce }) + '\n');
    });
    socket.on('data', (d) => {
      if (done) return;
      buf = buf.length === 0 ? Buffer.from(d) : Buffer.concat([buf, d]);
      if (buf.length > 8192) { fail(new BrokerNotAuthentic('Handshake reply was too large.')); return; }
      const nl = buf.indexOf(0x0a);
      if (nl === -1) return;
      const line = buf.subarray(0, nl).toString('utf8');
      const rest = buf.subarray(nl + 1);

      let reply: { server_id?: unknown; port?: unknown; sig?: unknown } | null = null;
      try {
        const parsed = JSON.parse(line) as unknown;
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          reply = parsed as { server_id?: unknown; port?: unknown; sig?: unknown };
        }
      } catch { /* handled below */ }

      if (!reply || typeof reply.sig !== 'string' || typeof reply.server_id !== 'string') {
        fail(new BrokerNotAuthentic(
          `Whatever is listening on 127.0.0.1:${rec.port} did not answer as the broker. ` +
          `Refusing to send a credential to it.`));
        return;
      }
      // The port and server_id are checked against the DISCOVERY FILE, not taken from the
      // reply: a signature over values the far end chose proves only that it can sign.
      if (reply.server_id !== rec.server_id || Number(reply.port) !== rec.port) {
        fail(new BrokerNotAuthentic(
          `The broker on 127.0.0.1:${rec.port} identified itself as a different instance ` +
          `than ${path.basename(ep.file)} names. Refusing to send a credential to it.`));
        return;
      }
      const message = `${HELLO_VERSION}:${nonce}:${rec.port}:${rec.server_id}`;
      let ok = false;
      try {
        ok = crypto.createVerify('SHA256').update(message)
          .verify(pub, Buffer.from(reply.sig, 'base64'));
      } catch { ok = false; }
      if (!ok) {
        fail(new BrokerNotAuthentic(
          `The process on 127.0.0.1:${rec.port} could not prove it is the broker. ` +
          `Refusing to send a credential to it.`));
        return;
      }

      done = true;
      clearTimeout(timer);
      socket.removeAllListeners('data');
      resolve(socket);
      // Anything that arrived with the banner belongs to the caller's handler.
      if (rest.length > 0) socket.emit('data', rest);
    });
  });
}

function loadBrokerPublicKey(): crypto.KeyObject | null {
  try {
    const b64 = fs.readFileSync(brokerPubPath(), 'utf8').trim();
    return crypto.createPublicKey({
      key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki',
    });
  } catch { return null; }
}

/** Publish the half agents verify against. Written by the daemon, read by everyone. */
export function publishBrokerPublicKey(publicKeyB64: string): void {
  const p = brokerPubPath();
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, publicKeyB64 + '\n', { mode: 0o644 });
  fs.renameSync(tmp, p);
}
