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
 *   Others: a loopback TCP port. A filesystem socket was tried and rejected —
 *           its pathname can be unlinked while it is still bound, after which a
 *           second process binds the same path and both serve, and recovering
 *           from a stale one means probe-then-unlink, which is itself a race.
 *           A port has the same properties as an abstract socket: no filesystem
 *           entry, kernel-released. It also avoids Windows, where a filesystem
 *           path is not a valid IPC address at all (\\.\pipe\... is) and the
 *           bind would simply fail, stranding a free credential.
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

const IS_LINUX = process.platform === 'linux';

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
 * Deterministic loopback ports, as a CANDIDATE LIST rather than one number.
 *
 * A single derived port is a guess about a shared resource: the dynamic range
 * is 16,384 wide and anything on the machine may already own our number. Read
 * as "held", that turns an unrelated service into a permanent outage for a
 * credential nobody holds. So we try several, and EADDRINUSE alone never
 * settles it — the occupant is asked to identify itself, and only a real
 * holder stops the search.
 */
const PORT_CANDIDATES = 8;

function addressPorts(): number[] {
  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
  const digest = createHash('sha256').update(`wundervault-mcp:${uid}:${agentName()}`).digest();
  const ports: number[] = [];
  for (let i = 0; i < PORT_CANDIDATES; i++) {
    ports.push(49152 + (digest.readUInt16BE(i * 2) % 16384));
  }
  return ports;
}

let held: net.Server | null = null;
let identityLine = '';
let heldPort: number | undefined;

function listenOptions(port?: number): net.ListenOptions {
  return IS_LINUX
    ? { path: `\0wundervault-mcp-${addressKey()}` }
    : { host: '127.0.0.1', port: port ?? addressPorts()[0] };
}

type BindResult =
  | { status: 'bound'; server: net.Server }
  | { status: 'in-use' }
  | { status: 'error'; message: string };

function tryBind(port?: number): Promise<BindResult> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', (err: NodeJS.ErrnoException) => {
      resolve(
        err.code === 'EADDRINUSE'
          ? { status: 'in-use' }
          : { status: 'error', message: err.code || err.message },
      );
    });
    server.listen(listenOptions(port), () => {
      server.unref();
      resolve({ status: 'bound', server });
    });
  });
}

/** Ask whoever holds the address who they are. */
function askHolder(port?: number): Promise<Holder | null> {
  return new Promise((resolve) => {
    let buf = '';
    let settled = false;
    const done = (h: Holder | null) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(h);
    };
    const sock = net.connect(listenOptions(port) as net.NetConnectOpts);
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

/** /proc/<pid>/stat field 22: start time in clock ticks since boot. */
function procStart(pid: number): string | null {
  if (!IS_LINUX) return null;
  try {
    const stat = readFileSync(path.join('/proc', String(pid), 'stat'), 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19] ?? null;
  } catch {
    return null;
  }
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
  const ports = IS_LINUX ? [undefined] : addressPorts();
  for (const port of ports) {
    const h = await askHolder(port as number | undefined);
    if (h) return h;
  }
  return holderFromFile();
}

export async function acquireCredential(version: string): Promise<Claim> {
  const candidates: (number | undefined)[] = IS_LINUX ? [undefined] : addressPorts();
  let bound: net.Server | null = null;
  let boundPort: number | undefined;

  for (const port of candidates) {
    const result = await tryBind(port);

    if (result.status === 'bound') {
      bound = result.server;
      boundPort = port;
      break;
    }

    if (result.status === 'in-use') {
      // EADDRINUSE is not proof that OUR credential is taken — on a shared
      // loopback range the occupant is usually somebody else entirely. Ask.
      // Only a process that speaks our protocol is a holder; anything else is
      // just in the way, so we move to the next candidate rather than
      // reporting a free credential as held.
      const who = await askHolder(port);
      if (who) return { ok: false, holder: who };
      continue;
    }

    // Some other bind error on this candidate; try the next one.
  }

  if (!bound) {
    return {
      ok: false,
      holder: await whoHolds(),
      reason: IS_LINUX
        ? 'could not claim the credential address'
        : `every candidate port on 127.0.0.1 is occupied by something else (${addressPorts().join(', ')})`,
    };
  }

  const legacy = legacyHolder();
  if (legacy) {
    try { bound.close(); } catch { /* ignore */ }
    return { ok: false, holder: legacy };
  }

  if (!writeCompatFile(version)) {
    // An older copy gates on this file. Unwritten, it sees no lock and starts
    // alongside us — so failing to write it is failing to hold the credential.
    try { bound.close(); } catch { /* ignore */ }
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
  heldPort = boundPort;
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
  heldPort = undefined;
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
  const candidates: (number | undefined)[] = IS_LINUX ? [undefined] : addressPorts();
  for (const port of candidates) {
    const result = await tryBind(port);
    if (result.status === 'bound') {
      try { result.server.close(); } catch { /* ignore */ }
      return legacyHolder() === null;
    }
    if (result.status === 'in-use' && (await askHolder(port))) return false;
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
  if (IS_LINUX) return `abstract socket wundervault-mcp-${addressKey()}`;
  const ports = addressPorts();
  return heldPort !== undefined
    ? `127.0.0.1:${heldPort}`
    : `127.0.0.1:${ports[0]} (+${ports.length - 1} fallbacks)`;
}

export function lockFileExists(): boolean {
  return existsSync(lockFilePath());
}
