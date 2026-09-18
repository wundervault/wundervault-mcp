/**
 * Single-instance lock for the MCP server.
 *
 * The vault's rule is ONE CONNECTED AGENT PER CREDENTIAL AT A TIME, so this is
 * a security control. Where the code cannot know the truth it refuses to serve.
 *
 * WHY NOT A PID FILE
 *
 * A pidfile cannot carry this: it can be deleted while the holder is still
 * connected, reading-then-writing it is a race, the PID it names can be
 * recycled, and deciding who a PID belongs to needs a readable /proc, which
 * does not exist under hidepid, in a sandbox, or off Linux.
 *
 * THE CLAIM IS A BOUND ADDRESS
 *
 * Binding is atomic — the kernel lets exactly one process hold an address, so
 * there is no window between checking and taking — and it is released on death
 * including SIGKILL, so a holder cannot leak the credential by dying badly.
 *
 *   Linux:  the ABSTRACT namespace (leading NUL). No filesystem entry exists,
 *           so there is nothing to delete and the delete-the-lock leak cannot
 *           happen rather than being defended against.
 *   Others: ONE loopback TCP port. A filesystem socket was tried and rejected —
 *           its pathname can be unlinked while it is still bound, after which a
 *           second process binds the same path and both serve, and recovering
 *           from a stale one means probe-then-unlink, which is itself a race.
 *           A port has the same properties as an abstract socket: no filesystem
 *           entry, kernel-released. It also avoids Windows, where a filesystem
 *           path is not a valid IPC address at all (\\.\pipe\... is) and the
 *           bind would simply fail, stranding a free credential.
 *
 * WHY ONE PORT AND NOT EIGHT — A REAL BUG, NOT A TIDY-UP
 *
 * This used to derive EIGHT candidate ports and walk them, on the reasoning
 * that a single derived port is a guess about a shared resource and an
 * unrelated occupant should not read as "held". The reasoning was right; the
 * range was not. The candidates landed in 49152-65535, which is exactly the
 * DEFAULT EPHEMERAL RANGE ON macOS (net.inet.ip.portrange.first = 49152), so
 * any outbound connection on the machine transiently owned one of them.
 *
 * The walk then did what it was told. Claim 1 finds candidate 0 momentarily
 * taken by somebody's outbound socket, gets no protocol answer, and binds
 * candidate 1. The ephemeral socket closes. Claim 2 starts at candidate 0,
 * finds it free, and binds it. TWO LIVE HOLDERS OF ONE CREDENTIAL — the exact
 * condition this module exists to prevent, arrived at by spreading the claim
 * across eight addresses instead of one. It showed up as two flaky macOS CI
 * assertions that were gated off as unexplained for a release.
 *
 * So: one port, derived into 20000-32767, which is below the ephemeral range on
 * macOS and Windows both. A stranger there is now a HARD ERROR naming the port
 * rather than a silent move to another address, because an operator can fix a
 * port conflict they are told about and cannot fix a second holder they are
 * not.
 *
 * THE HOLDER ANSWERS FOR ITSELF
 *
 * The bound address is also how a blocked instance learns WHO holds it: the
 * holder replies to any connection with a one-line identity banner. That does
 * not depend on a file anyone can remove, so the refusal stays actionable even
 * when the compatibility file is gone. The banner carries pid, connect time and
 * agent name — never a secret, and never the parent's argv.
 *
 * THE PID FILE IS KEPT, FOR COMPATIBILITY ONLY
 *
 * Older builds (<=1.7.0, including frozen copies in other agents' node_modules)
 * gate purely on `~/.wundervault/mcp-<Agent>.lock`, read with parseInt. If we
 * stopped writing it they would see no lock and start alongside a live holder,
 * so we still write it — and if we CANNOT write it we do not serve, because an
 * unwritten file is exactly the state in which an older copy joins us.
 */

import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';

export interface Holder {
  pid: number | null;
  since: string | null;
  agent: string | null;
  /** How we learned this: the holder itself, or the compatibility file. */
  source: 'holder' | 'lock-file' | 'unknown';
}

export interface Claim {
  ok: boolean;
  holder?: Holder;
  /** Set when we refused because we could not establish a claim safely. */
  reason?: string;
}

/**
 * Which primitive claims the credential.
 *
 * Overridable so the PORT path is reachable from Linux CI. It was not, which is why a
 * concurrency bug in it survived four rounds of review on the abstract-socket path and was
 * found only by a CI job on a platform nobody could reproduce on.
 */
export type LockStrategy = 'abstract' | 'port';

export function lockStrategy(): LockStrategy {
  const override = process.env.WUNDERVAULT_LOCK_STRATEGY;
  if (override === 'abstract' || override === 'port') return override;
  if (override) throw new Error(`WUNDERVAULT_LOCK_STRATEGY must be 'abstract' or 'port'.`);
  // The abstract namespace is a Linux feature. Everywhere else, the port.
  return process.platform === 'linux' ? 'abstract' : 'port';
}

export function agentName(): string {
  return process.env.WUNDERVAULT_AGENT_NAME || '';
}

function slug(): string {
  const agent = agentName();
  return agent ? agent.replace(/[^a-zA-Z0-9_-]/g, '_') : '_default';
}

export function lockFilePath(): string {
  const agent = agentName();
  // Filename shape is unchanged, because older copies look for exactly this.
  // The slug is capped only past the point where a filename stops being legal
  // at all (255 bytes on ext4): beyond that an older copy could not write this
  // file either, so there is no compatibility left to preserve — and an
  // unbounded name would make writeCompatFile() fail with ENAMETOOLONG, which
  // this design correctly but uselessly reports as "cannot claim".
  const name = agent ? `mcp-${slug().slice(0, 200)}.lock` : 'mcp.lock';
  return path.join(os.homedir(), '.wundervault', name);
}

/**
 * Address key. Slugging is lossy — "Team A" and "Team?A" both slug to Team_A —
 * and two DIFFERENT credentials must not exclude each other, so the key carries
 * a digest of the RAW name. Truncated because an address has a length limit
 * (108 bytes for a unix path) that a long agent name or home directory would
 * otherwise blow past.
 */
function addressKey(): string {
  // The abstract namespace and the loopback port range are MACHINE-global, not
  // per-user, so the uid belongs in the key: without it two OS accounts on one
  // box exclude each other over credentials they do not share.
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const digest = createHash('sha256').update(`${uid}:${agentName()}`).digest('hex').slice(0, 12);
  return `${slug().slice(0, 32)}-${digest}`;
}

/**
 * ONE deterministic loopback port, in 20000-32767.
 *
 * The range is the fix. 49152-65535 is the default ephemeral range on macOS and on
 * Windows, and Linux's is 32768-60999 — so a port derived below 32768 is not handed out to
 * unrelated outbound connections on any of the three. What remains is a collision with a
 * SERVICE that binds the same number, which is stable, diagnosable, and reported rather
 * than worked around.
 *
 * WUNDERVAULT_LOCK_PORT exists for that case, and for tests that need two claims on one
 * machine not to exclude each other.
 */
function addressPort(): number {
  const override = process.env.WUNDERVAULT_LOCK_PORT;
  if (override) {
    const n = Number(override);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      throw new Error(`WUNDERVAULT_LOCK_PORT=${JSON.stringify(override)} is not a port number.`);
    }
    return n;
  }
  // The port range is MACHINE-global, not per-user, so the uid belongs in the digest:
  // without it two OS accounts on one box exclude each other over credentials they do not
  // share.
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const digest = createHash('sha256').update(`wundervault-mcp:${uid}:${agentName()}`).digest();
  return 20000 + (digest.readUInt16BE(0) % 12768);
}

/** Exported for the test that asserts the range over a sample of names, not one name. */
export { addressPort as _addressPortForTests };

let held: net.Server | null = null;
let identityLine = '';

function listenOptions(): net.ListenOptions {
  return lockStrategy() === 'abstract'
    ? { path: `\0wundervault-mcp-${addressKey()}` }
    : { host: '127.0.0.1', port: addressPort() };
}

/** How to name the address in a message a person has to act on. */
function addressLabel(): string {
  return lockStrategy() === 'abstract'
    ? `the abstract socket wundervault-mcp-${addressKey()}`
    : `127.0.0.1:${addressPort()}`;
}

type BindResult =
  | { status: 'bound'; server: net.Server }
  | { status: 'in-use' }
  | { status: 'error'; message: string };

function tryBind(): Promise<BindResult> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', (err: NodeJS.ErrnoException) => {
      resolve(
        err.code === 'EADDRINUSE'
          ? { status: 'in-use' }
          : { status: 'error', message: err.code || err.message },
      );
    });
    server.listen(listenOptions(), () => {
      server.unref();
      resolve({ status: 'bound', server });
    });
  });
}

function closed(server: net.Server): Promise<void> {
  return new Promise((resolve) => {
    try { server.close(() => resolve()); } catch { resolve(); }
  });
}

/** Ask whoever holds the address who they are. */
function askHolder(): Promise<Holder | null> {
  return new Promise((resolve) => {
    let buf = '';
    let settled = false;
    const done = (h: Holder | null) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(h);
    };
    const sock = net.connect(listenOptions() as net.NetConnectOpts);
    sock.setEncoding('utf8');
    sock.on('data', (d: string) => {
      buf += d;
      // Whoever answers may not be us and may never send a newline.
      if (buf.length > 4096) { done(null); return; }
      if (buf.includes('\n')) {
        try {
          const o = JSON.parse(buf.slice(0, buf.indexOf('\n')));
          if (o && o.protocol === 'wundervault-mcp-holder') {
            done({ pid: o.pid ?? null, since: o.since ?? null, agent: o.agent ?? null, source: 'holder' });
            return;
          }
        } catch { /* not ours */ }
        done(null);
      }
    });
    sock.on('error', () => done(null));
    sock.on('close', () => done(null));
    setTimeout(() => done(null), 1000).unref();
  });
}

interface CompatFile {
  pid: number;
  since: string | null;
  token: string | null;
  /** Raw agent name. The FILENAME is slugged and lossy, so it cannot say this. */
  agent: string | null;
  /** Linux kernel start ticks, to tell this incarnation from a recycled PID. */
  start: string | null;
}

/**
 * An identifier for THIS INCARNATION of a pid, so a recycled pid is not mistaken for the
 * process that wrote the lock file.
 *
 * Linux: /proc/<pid>/stat field 22, start time in clock ticks since boot.
 * macOS: `ps -o lstart=`, the process's start time to the second. There is no /proc, and
 *        this returned null there — so on a Mac the recycling check was INERT and a
 *        recycled pid refused a free credential until someone deleted the file by hand.
 *        Second granularity is enough: a pid is not recycled and re-bound inside one
 *        second, and a false MATCH is the safe direction anyway (we stand down).
 *
 * Anything else returns null, which the caller treats as "cannot tell" and fails closed.
 */
function procStart(pid: number): string | null {
  if (process.platform === 'linux') {
    try {
      const stat = readFileSync(path.join('/proc', String(pid), 'stat'), 'utf8');
      return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19] ?? null;
    } catch {
      return null;
    }
  }

  if (process.platform === 'darwin') {
    try {
      const out = execFileSync('/bin/ps', ['-o', 'lstart=', '-p', String(pid)], {
        encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      return out || null;
    } catch {
      return null;
    }
  }

  return null;
}

function readCompatFile(): CompatFile | null {
  try {
    const raw = readFileSync(lockFilePath(), 'utf8');
    const pid = parseInt(raw.trim().split('\n')[0], 10);
    if (isNaN(pid)) return null;
    let since: string | null = null;
    let token: string | null = null;
    let agent: string | null = null;
    let start: string | null = null;
    const nl = raw.indexOf('\n');
    if (nl > 0) {
      try {
        const meta = JSON.parse(raw.slice(nl + 1)) as
          { since?: string; token?: string; agent?: string; start?: string };
        since = meta.since ?? null;
        token = meta.token ?? null;
        agent = meta.agent ?? null;
        start = meta.start ?? null;
      } catch { /* legacy plain-pid file */ }
    }
    return { pid, since, token, agent, start };
  } catch {
    return null;
  }
}

/** Our incarnation token, so only this exact run can release the lock file. */
let ourToken = '';

function writeCompatFile(version: string): boolean {
  try {
    ourToken = randomUUID();
    const meta = {
      pid: process.pid,
      agent: agentName(),
      since: new Date().toISOString(),
      version,
      token: ourToken,
      start: procStart(process.pid),
    };
    // Line 1 must stay a bare PID: older builds parseInt it, and a pure-JSON
    // file reads as NaN there, which makes them ignore the lock entirely.
    writeFileSync(lockFilePath(), `${process.pid}\n${JSON.stringify(meta)}\n`, 'utf8');
    return true;
  } catch {
    return false;
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function holderFromFile(): Holder {
  const compat = readCompatFile();
  if (!compat) return { pid: null, since: null, agent: null, source: 'unknown' };
  return { pid: compat.pid, since: compat.since, agent: agentName() || null, source: 'lock-file' };
}

/**
 * A holder that predates the socket: an older build binds no address at all and
 * leaves only the pid file, so during a mixed-version window that file is the
 * only trace of it. Honouring it is what keeps one-agent-per-credential across
 * versions — but three things must be true before a PID in that file counts.
 */
function legacyHolder(): Holder | null {
  const compat = readCompatFile();
  if (!compat || compat.pid === process.pid || !pidAlive(compat.pid)) return null;

  // The FILENAME is slugged and lossy — "Team A" and "Team?A" share it — so a
  // live PID in it does not imply a live holder of OUR credential. When the
  // file says whose it is, believe that over the filename.
  if (compat.agent !== null && compat.agent !== agentName()) return null;

  // A live PID is not the same process. When the file recorded an incarnation,
  // require it: otherwise a recycled PID refuses a free credential forever.
  if (compat.start !== null) {
    const actual = procStart(compat.pid);
    if (actual !== null && actual !== compat.start) return null;
  }

  // A legacy file says neither, and unknown fails closed.
  return holderFromFile();
}

/** Who holds the credential right now, asked of the holder first. */
export async function whoHolds(): Promise<Holder> {
  const h = await askHolder();
  // Same collision check as acquireCredential: an answer from a different agent is not an
  // answer about OUR credential, and reporting it as one would name the wrong process to
  // whoever is trying to work out what is holding theirs.
  if (h && (!h.agent || !agentName() || h.agent === agentName())) return h;
  return holderFromFile();
}

export async function acquireCredential(version: string): Promise<Claim> {
  const result = await tryBind();
  let bound: net.Server | null = null;

  if (result.status === 'bound') {
    bound = result.server;
  } else if (result.status === 'in-use') {
    // EADDRINUSE on OUR one address. Ask who is there.
    const who = await askHolder();

    // A wundervault holder for a DIFFERENT agent is a hash collision, not our holder.
    //
    // One derived port means 12,768 possible addresses, and the birthday bound bites long
    // before that: around a hundred distinct agent names on one machine already gives
    // roughly a one-in-three chance that two of them derive the same port. Reporting that
    // as "your credential is in use" would be a plain falsehood — a different credential
    // is in use — and the operator would go looking for a duplicate agent that does not
    // exist. Two unrelated agents must never be able to exclude each other silently.
    if (who && who.agent && agentName() && who.agent !== agentName()) {
      return {
        ok: false,
        holder: holderFromFile(),
        reason:
          `${addressLabel()} is already held by a different agent (${who.agent}). Two ` +
          `agent names can derive the same lock port; this is a collision, NOT your ` +
          `credential being in use. Set WUNDERVAULT_LOCK_PORT for one of them.`,
      };
    }

    if (who) return { ok: false, holder: who };

    // A stranger. This used to move to another candidate port, and moving is what
    // allowed two live holders — the second claim simply landed somewhere else and
    // reported success. Refusing is the only answer that keeps one-agent-per-credential,
    // and it is actionable in a way the silent move never was.
    return {
      ok: false,
      holder: holderFromFile(),
      reason:
        `${addressLabel()} is occupied by something that is not a wundervault holder, ` +
        `so the credential cannot be claimed safely. Free that address, or set ` +
        `WUNDERVAULT_LOCK_PORT to move this agent's lock.`,
    };
  }

  if (!bound) {
    return {
      ok: false,
      holder: await whoHolds(),
      reason: `could not claim ${addressLabel()}: ${
        result.status === 'error' ? result.message : 'unknown error'
      }`,
    };
  }

  // AWAITED, both of them. close() is asynchronous, and with eight candidate ports a
  // caller that retried after one of these refusals simply landed on a different address.
  // With one address it now meets our own half-closed socket, reads EADDRINUSE, gets no
  // protocol answer from a socket that is going away, and is told the address is occupied
  // by a stranger — a wrong and unactionable message for a machine where nothing is wrong.
  const legacy = legacyHolder();
  if (legacy) {
    await closed(bound);
    return { ok: false, holder: legacy };
  }

  if (!writeCompatFile(version)) {
    // An older copy gates on this file. Unwritten, it sees no lock and starts
    // alongside us — so failing to write it is failing to hold the credential.
    await closed(bound);
    return {
      ok: false,
      holder: { pid: null, since: null, agent: null, source: 'unknown' },
      reason: `could not write ${lockFilePath()}, which older copies rely on`,
    };
  }

  identityLine = JSON.stringify({
    protocol: 'wundervault-mcp-holder',
    pid: process.pid,
    agent: agentName(),
    since: new Date().toISOString(),
  }) + '\n';
  bound.on('connection', (sock) => {
    try { sock.end(identityLine); } catch { /* ignore */ }
  });

  held = bound;
  return { ok: true };
}

/** Release only a lock file this exact incarnation wrote. */
/**
 * Give up the credential.
 *
 * Returns a promise that settles once the bound address is actually gone.
 * net.Server.close() is asynchronous, so a caller that released and immediately
 * re-acquired in the same process could race its own teardown and get EADDRINUSE
 * from a socket it had just closed itself. Every production caller is a
 * process-exit path where the kernel reclaims the address anyway and the return
 * value is safely ignored; anything reconnecting in-process should await it.
 */
export function releaseCredential(): Promise<void> {
  try {
    const compat = readCompatFile();
    // A PID match alone is not proof — the file may have been replaced, or the
    // PID recycled. The token is generated once per run and never reused, so it
    // is the only thing that identifies THIS incarnation. A file with no token
    // was written by an older build, never by us, so it is never ours to remove.
    if (compat && ourToken !== '' && compat.token === ourToken) {
      unlinkSync(lockFilePath());
    }
  } catch { /* ignore */ }

  const server = held;
  held = null;
  if (!server) return Promise.resolve();

  return new Promise<void>((resolve) => {
    try {
      server.close(() => resolve());
    } catch {
      resolve();
    }
  });
}

/** Is the credential free right now? */
export async function credentialIsFree(): Promise<boolean> {
  if (held) return false;
  {
    const result = await tryBind();
    if (result.status === 'bound') {
      // Wait for the probe socket to actually be gone. close() is asynchronous,
      // and this function's whole job is to answer a question the caller acts on
      // immediately: an un-awaited teardown leaves our own closing socket on the
      // address, so the very next bind — another probe, or the acquire that
      // follows a "yes" — reads EADDRINUSE and reports a FREE credential as held.
      await closed(result.server);
      return legacyHolder() === null;
    }
    if (result.status === 'in-use' && (await askHolder())) return false;
  }
  return false;
}

export function describeHolder(h: Holder): string {
  const bits: string[] = [];
  if (h.pid !== null) bits.push(`PID ${h.pid}`);
  if (h.since) bits.push(`connected since ${h.since}`);
  if (!bits.length) return 'another process on this machine';
  if (h.source === 'lock-file') bits.push('reported by its lock file');
  return bits.join(', ');
}

export function addressDescription(): string {
  return addressLabel();
}

export function lockFileExists(): boolean {
  return existsSync(lockFilePath());
}
