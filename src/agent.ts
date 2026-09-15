#!/usr/bin/env node
/**
 * The credential daemon, running as its own user.
 *
 * Before phase 4 this process shared a uid with the agents it served, so its key file, its
 * memory and its sockets were all readable by the party it was protecting them from.
 * Everything the vault claimed was true only against an agent that did not try.
 *
 * It now runs as the `wundervault` system account with its state in /var/lib/wundervault,
 * mode 0700. That directory mode is the boundary. The at-rest encryption is defence in
 * depth and is described as such — its key derives from the machine id, the uid and a salt
 * file kept beside the ciphertext, so anyone who can read the directory can recompute it.
 *
 * WHAT CHANGED IN THE THREAT MODEL, AND WHY THE SOCKETS LOOK WEAKER
 *
 * The per-agent sockets used to be 0600. They cannot be any more: the daemon is now a
 * different uid from every agent, and a 0600 socket it owns is one no agent could reach.
 * So the sockets are world-connectable and the TOKEN is the identity — a file in the
 * agent's own home at 0600, which only that uid can read.
 *
 * That makes the token check load-bearing in a way it never was. It used to be a second
 * lock behind a file mode; it is now the only lock. Two consequences the previous version
 * got wrong and this one must not:
 *
 *   1. A profile with no token used to be served to anyone who connected, because the
 *      check was inside `if (profile.socket_token)`. Behind a 0600 socket that was
 *      merely sloppy. In front of a world-connectable one it hands credentials to any
 *      local user. A profile without a token is now refused outright.
 *   2. Anyone may knock, so bad attempts are rate-limited per agent.
 */
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { VERSION } from './version.js';
import {
  systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
  runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
} from './paths.js';
import { load as loadNetworkShape } from './network-store.js';

interface AgentProfile {
  agent_name: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
  socket_token?: string;
}

interface ProfileStore {
  profiles: AgentProfile[];
}

/**
 * Refuse to be root.
 *
 * The unit says `User=wundervault`, but a unit is a file someone can edit, and a daemon
 * that silently keeps root because of a typo in /etc is worse than one that never had it:
 * every protection below would still appear to be working. Failing here makes the mistake
 * loud at the only moment anyone is watching.
 */
function refuseRoot(): void {
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  if (uid === 0) {
    console.error(
      `[wundervault-agent] Refusing to run as root.\n` +
      `  This daemon holds credentials and must run as its own unprivileged account.\n` +
      `  Expected User=${SYSTEM_ACCOUNT} in the unit file.\n` +
      `  If you installed by hand, re-run packaging/install-daemon.sh.`,
    );
    process.exit(1);
  }
}

function deriveMachineKey(): Buffer {
  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();

  let salt: Buffer;
  const sp = saltPath();
  if (fs.existsSync(sp)) {
    salt = fs.readFileSync(sp);
  } else {
    salt = crypto.randomBytes(32);
    ensureSystemRoot();
    fs.writeFileSync(sp, salt, { mode: 0o600 });
  }
  return crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
}

function encryptProfiles(store: ProfileStore, key: Buffer): Buffer {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(store), 'utf8'), cipher.final()]);
  return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
}

function decryptProfiles(buf: Buffer, key: Buffer): ProfileStore {
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}

/** Constant-time comparison of two hex tokens, safe against malformed input. */
export function tokenMatches(provided: string | undefined, expected: string | undefined): boolean {
  if (!expected) return false;          // no token configured: never a match
  if (!provided) return false;
  let a: Buffer, b: Buffer;
  try {
    a = Buffer.from(provided, 'hex');
    b = Buffer.from(expected, 'hex');
  } catch { return false; }
  // Length is compared first and separately on purpose: timingSafeEqual throws on a
  // length mismatch, and a thrown exception is a louder timing signal than the
  // comparison it was meant to protect.
  if (a.length === 0 || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Bad attempts, per agent name.
 *
 * The socket is world-connectable now, so any local process may knock. Guessing a 32-byte
 * token is not a real threat; an unbounded loop of connections is, and the log it would
 * produce is its own denial of service. A short lockout costs a legitimate agent one
 * retry after a genuine misconfiguration.
 */
class Knocks {
  private fails = new Map<string, { n: number; until: number }>();
  private readonly MAX = 10;
  private readonly WINDOW_MS = 60_000;

  lockedOut(name: string): boolean {
    const f = this.fails.get(name);
    return !!f && f.n >= this.MAX && Date.now() < f.until;
  }

  record(name: string): void {
    const now = Date.now();
    const f = this.fails.get(name);
    if (!f || now >= f.until) { this.fails.set(name, { n: 1, until: now + this.WINDOW_MS }); return; }
    f.n += 1;
  }

  clear(name: string): void { this.fails.delete(name); }
}

class AgentDaemon {
  private key: Buffer;
  private profiles: AgentProfile[] = [];
  private agentServers: Map<string, net.Server> = new Map();
  private mgmtServer: net.Server | null = null;
  private knocks = new Knocks();

  constructor() {
    ensureSystemRoot();
    this.key = deriveMachineKey();
    this.loadProfiles();
  }

  loadProfiles(): void {
    const pp = profilesPath();
    if (!fs.existsSync(pp)) return;
    try {
      this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
    } catch (err) {
      console.error('[wundervault-agent] Failed to decrypt profiles:', (err as Error).message);
    }
  }

  saveProfiles(): void {
    const pp = profilesPath();
    // Write-then-rename. A half-written store read after a crash decrypts to nothing and
    // every agent on the machine loses its credentials at once.
    const tmp = `${pp}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, encryptProfiles({ profiles: this.profiles }, this.key), { mode: 0o600 });
    fs.renameSync(tmp, pp);
    try { fs.chmodSync(pp, 0o600); } catch { /* best effort */ }
  }

  registerProfile(profile: AgentProfile): void {
    // The name becomes a path segment. It arrives over a socket any local process can
    // connect to, so "../../etc/cron.d/x" would otherwise have this daemon place a file
    // wherever it liked — which for the process holding the boundary is the whole game.
    profile.agent_name = safeName(profile.agent_name);

    if (!profile.socket_token) {
      throw new Error(
        'A profile must carry a socket_token. The per-agent socket is world-connectable ' +
        'now that the daemon runs as a different user, so the token is the only thing ' +
        'identifying the caller.',
      );
    }

    const idx = this.profiles.findIndex(p => p.agent_name === profile.agent_name);
    if (idx >= 0) {
      this.profiles[idx] = profile;
      const old = this.agentServers.get(profile.agent_name);
      if (old) {
        // Not unlinked in the close callback: startAgentSocket unlinks and rebinds
        // immediately, and the async callback would race it.
        old.close();
        this.agentServers.delete(profile.agent_name);
      }
    } else {
      this.profiles.push(profile);
    }
    this.knocks.clear(profile.agent_name);
    this.startAgentSocket(profile);
    this.saveProfiles();
  }

  removeProfile(name: string): boolean {
    const safe = safeName(name);
    const before = this.profiles.length;
    this.profiles = this.profiles.filter(p => p.agent_name !== safe);
    if (this.profiles.length === before) return false;
    const srv = this.agentServers.get(safe);
    if (srv) { try { srv.close(); } catch { /* already gone */ } }
    this.agentServers.delete(safe);
    try { fs.unlinkSync(agentSocketPath(safe)); } catch { /* already gone */ }
    this.saveProfiles();
    return true;
  }

  startAgentSocket(profile: AgentProfile): void {
    const sockPath = agentSocketPath(profile.agent_name);
    try { fs.unlinkSync(sockPath); } catch { /* nothing to clear */ }

    const srv = net.createServer((socket) => {
      let buf = '';
      // A caller that never sends a newline would otherwise hold a connection open for
      // ever, and a caller that streams without one would grow this buffer without bound.
      socket.setTimeout(5_000, () => socket.destroy());
      socket.on('data', (d) => {
        buf += d.toString();
        if (buf.length > 4096) { socket.destroy(); return; }
        if (!buf.includes('\n')) return;

        if (this.knocks.lockedOut(profile.agent_name)) {
          socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
          socket.end();
          return;
        }

        let msg: { token?: string } = {};
        try { msg = JSON.parse(buf.trim()); } catch { /* treated as no token */ }

        if (!tokenMatches(msg.token, profile.socket_token)) {
          this.knocks.record(profile.agent_name);
          // The same answer for a bad token, a missing token and a lockout. Anything more
          // specific tells a local prober which agent names exist on this machine.
          socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
          socket.end();
          console.error(`[wundervault-agent] Auth failure on ${profile.agent_name} socket`);
          return;
        }

        this.knocks.clear(profile.agent_name);
        socket.write(JSON.stringify({
          api_key: profile.api_key,
          enc_key: profile.enc_key,
          vault_url: profile.vault_url,
        }) + '\n');
        socket.end();
      });
      socket.on('error', () => { /* a client that hangs up is not an event */ });
    });

    srv.listen(sockPath, () => {
      // World-connectable BY DESIGN — see the header. The daemon is a different uid from
      // every agent, so a mode that excluded others would exclude the agent too. The
      // token is the identity; this mode is not a control and must not be read as one.
      try { fs.chmodSync(sockPath, 0o666); } catch { /* best effort */ }
    });
    srv.on('error', (err) => {
      console.error(`[wundervault-agent] Socket error for ${profile.agent_name}:`, err.message);
    });
    this.agentServers.set(profile.agent_name, srv);
  }

  startMgmtSocket(): void {
    const mp = mgmtSocketPath();
    // The directory is the control, and it exists before the socket does. chmod-after-
    // listen leaves a window in which the socket is bound at the default mode and a
    // process watching for it can connect; a 0770 directory has no such window.
    const md = mgmtDir();
    fs.mkdirSync(md, { recursive: true, mode: 0o770 });
    fs.chmodSync(md, 0o770);
    try { fs.unlinkSync(mp); } catch { /* nothing to clear */ }

    const mgmt = net.createServer((socket) => {
      let buf = '';
      socket.setTimeout(10_000, () => socket.destroy());
      socket.on('data', (d) => {
        buf += d.toString();
        // Enrolment carries a profile, so this ceiling is higher than the agent socket's —
        // but it is still a ceiling.
        if (buf.length > 64 * 1024) { socket.destroy(); return; }
        const nl = buf.indexOf('\n');
        if (nl < 0) return;

        try {
          const msg = JSON.parse(buf.slice(0, nl));
          if (msg.action === 'register_profile' && msg.profile) {
            this.registerProfile(msg.profile as AgentProfile);
            socket.write(JSON.stringify({ ok: true }) + '\n');
          } else if (msg.action === 'remove_profile' && msg.agent_name) {
            const gone = this.removeProfile(String(msg.agent_name));
            socket.write(JSON.stringify({ ok: true, removed: gone }) + '\n');
          } else if (msg.action === 'reload') {
            this.loadProfiles();
            socket.write(JSON.stringify({ ok: true, count: this.profiles.length }) + '\n');
          } else if (msg.action === 'destinations') {
            // The store is daemon-owned now, so the user who wants to READ it cannot.
            // Serving it here is what keeps `--destinations` working after the split —
            // and the alternative, letting the client read the file directly, is the
            // access this phase exists to remove.
            //
            // Not gated on a token: this is the owner's own record of their own agents,
            // reachable only through the 0770 management directory, and refusing to show
            // someone where their keys went would make the boundary a cage rather than a
            // wall.
            //
            // `load()` swallows a read error and returns an empty shape, which is right
            // for a vault call — one unreadable store must not break every request — and
            // wrong here. Someone asking where their keys went would be shown "nowhere".
            // The client was just fixed for exactly this; the same lie one level down is
            // no better, so the readability check happens before the load.
            const sp = networkStorePath();
            let readable = true;
            if (fs.existsSync(sp)) {
              try { fs.accessSync(sp, fs.constants.R_OK); } catch { readable = false; }
            }
            if (!readable) {
              socket.write(JSON.stringify({
                error: `the daemon cannot read its own store at ${sp}. Check its owner and mode.`,
              }) + '\n');
            } else {
              socket.write(JSON.stringify({
                ok: true, shape: loadNetworkShape(), store: sp,
              }) + '\n');
            }
          } else if (msg.action === 'ping') {
            socket.write(JSON.stringify({
              ok: true, version: VERSION, system_root: systemRoot(),
              agents: this.profiles.map(p => p.agent_name),
            }) + '\n');
          } else {
            socket.write(JSON.stringify({ error: 'unknown action' }) + '\n');
          }
        } catch (err) {
          // The message is reported because an agent-name rejection is actionable and
          // silence here reads as a hang.
          socket.write(JSON.stringify({ error: (err as Error).message || 'parse error' }) + '\n');
        }
        socket.end();
      });
      socket.on('error', () => { /* hang-ups are not events */ });
    });

    mgmt.listen(mp, () => {
      // Belt as well as braces. The 0770 directory above is what actually gates this; the
      // socket mode is set too so a misconfigured directory does not silently open it.
      //
      // The honest limit: group membership is coarse, and on Linux it is what 1Password
      // settles for too. A finer check needs SO_PEERCRED, which Node does not expose, and
      // a native addon would put a compiled binary inside a package whose selling point is
      // that you can read it.
      try { fs.chmodSync(mp, 0o660); } catch { /* best effort */ }
      console.log(`[wundervault-agent] Listening. Management: ${mp}`);
    });
    mgmt.on('error', (err) => {
      console.error('[wundervault-agent] Mgmt socket error:', err.message);
    });
    this.mgmtServer = mgmt;
  }

  start(): void {
    const rt = runtimeDir();
    fs.mkdirSync(rt, { recursive: true, mode: 0o755 });
    // Clear sockets left by a crash. A stale file makes listen() fail, and the daemon
    // would come up with no socket while reporting itself started.
    try {
      for (const f of fs.readdirSync(rt)) {
        if (f.endsWith('.sock')) { try { fs.unlinkSync(path.join(rt, f)); } catch { /* ignore */ } }
      }
    } catch { /* first run */ }

    for (const profile of this.profiles) {
      if (!profile.socket_token) {
        // Pre-split profiles may have none. Serving them now would hand credentials to
        // any local process, so they are skipped loudly rather than served quietly.
        console.error(
          `[wundervault-agent] Agent "${profile.agent_name}" has no socket token and will ` +
          `NOT be served. Re-run onboarding for it.`,
        );
        continue;
      }
      this.startAgentSocket(profile);
    }
    this.startMgmtSocket();
    console.log(
      `[wundervault-agent] Started with ${this.agentServers.size} agent(s). State: ${systemRoot()}`,
    );
  }

  shutdown(): void {
    for (const [name, srv] of this.agentServers) {
      try { srv.close(); } catch { /* already closing */ }
      try { fs.unlinkSync(agentSocketPath(name)); } catch { /* already gone */ }
    }
    if (this.mgmtServer) { try { this.mgmtServer.close(); } catch { /* already closing */ } }
    try { fs.unlinkSync(mgmtSocketPath()); } catch { /* already gone */ }
  }
}

export { AgentDaemon, deriveMachineKey, encryptProfiles, decryptProfiles, refuseRoot };
export type { AgentProfile, ProfileStore };

// Only run when invoked as the binary, so the class can be imported by tests and by the
// migration command without starting a daemon as a side effect.
const invokedDirectly = process.argv[1] && /wundervault-agent|agent\.(js|ts)$/.test(process.argv[1]);
if (invokedDirectly && !process.env.WUNDERVAULT_AGENT_NO_AUTOSTART) {
  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`
Wundervault agent daemon ${VERSION}

Usage: wundervault-agent [--migrate [--dry-run]]

With no arguments it runs as the daemon. It is normally started by systemd as the
'${SYSTEM_ACCOUNT}' account, not by hand.

  --migrate     Hand agents enrolled before the uid split over to the system daemon,
                then delete the copy in your home directory. Run as YOUR user, no sudo.
  --dry-run     With --migrate: say what would move, change nothing.

State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
`);
    process.exit(0);
  }

  if (argv.includes('--migrate')) {
    // Runs as the USER, not the daemon: it reads the old store from a home directory the
    // daemon deliberately cannot reach.
    const { migrate, describe } = await import('./migrate.js');
    const dryRun = argv.includes('--dry-run');
    migrate({ dryRun })
      .then((r) => { console.log(describe(r, dryRun)); process.exit(0); })
      .catch((e: Error) => { console.error(e.message); process.exit(1); });
  } else {
    refuseRoot();
    const daemon = new AgentDaemon();
    daemon.start();
    process.on('SIGTERM', () => { daemon.shutdown(); process.exit(0); });
    process.on('SIGINT', () => { daemon.shutdown(); process.exit(0); });
  }
}
