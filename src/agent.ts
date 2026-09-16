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
import { redeemSetupLink, peekAgentName } from './enrol.js';
import {
  systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
  runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
  splitAvailable, systemdCredential, sealedWithTpm,
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
/**
 * Say which world this daemon is actually running in.
 *
 * On Linux after the install it holds a real boundary: a different uid, a directory the
 * agent cannot open, memory the agent cannot read. Everywhere else it is the same uid as
 * the agents it serves, which is careful handling and nothing more. Printing that at
 * startup is the difference between a limitation and a false claim — the release notes say
 * "the key never reaches the agent", and on macOS today that is true only of an agent that
 * does not try.
 */
function announceBoundary(): void {
  if (splitAvailable()) return;
  console.error(
    `[wundervault-agent] Running on ${process.platform}, where the secret broker cannot yet\n` +
    `[wundervault-agent] have its own account. State is in your own directory and it runs as\n` +
    `[wundervault-agent] YOU — so its key material and memory are readable by anything you\n` +
    `[wundervault-agent] run, including your agents. That is the pre-split threat model.\n` +
    `[wundervault-agent] The boundary is Linux-only for now.`,
  );
}

function refuseRoot(): void {
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  if (uid === 0) {
    console.error(
      `[wundervault-agent] Refusing to run as root.\n` +
      `  The secret broker holds credentials and must run as its own unprivileged account.\n` +
      `  Expected User=${SYSTEM_ACCOUNT} in the unit file.\n` +
      `  If you installed by hand, re-run packaging/install-daemon.sh.`,
    );
    process.exit(1);
  }
}

/**
 * The key the profile store is encrypted with.
 *
 * TWO MODES, AND THE DIFFERENCE IS THE WHOLE POINT.
 *
 * SEALED (preferred). systemd unseals a random 32-byte key for us — sealed to this
 * machine's TPM where there is one, to the root-only host key otherwise — and drops it in a
 * private tmpfs only this service can read. The key is not derived from anything; it is a
 * secret. Copy the disk to another machine and the store does not open, because the TPM
 * that sealed it is not there.
 *
 * DERIVED (fallback, and what this used to be exclusively). HKDF over
 * sha256(machine-id : uid) with a salt stored beside the ciphertext. Every input to that is
 * readable by anyone who can read the directory, so the key is RECOMPUTABLE: it is not a
 * secret, it is an obfuscation, and the directory mode was doing all the real work. That is
 * fine as defence in depth and was always described as such — it is not fine as the only
 * thing standing between a stolen disk and every credential on it.
 *
 * Both are supported because the fallback has to exist: no TPM, an older systemd, a
 * container, a hand-started broker. What must not happen is a machine silently sitting in
 * the weaker mode while the release notes describe the stronger one, so the mode in force is
 * reported at startup and by `ping`.
 */
type KeyMode = 'sealed-tpm' | 'sealed-host' | 'derived';

function legacyDerivedKey(): Buffer {
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

function sealedKey(): Buffer | null {
  const raw = systemdCredential();
  if (!raw) return null;
  // Expanded rather than used raw, so the stored secret is never the working key and can be
  // re-purposed later (a second context string gives a second independent key).
  return crypto.hkdfSync(
    'sha256', raw, Buffer.alloc(0), Buffer.from('wundervault-store-v2'), 32,
  ) as unknown as Buffer;
}

function deriveMachineKey(): { key: Buffer; mode: KeyMode } {
  const sealed = sealedKey();
  if (sealed) return { key: sealed, mode: sealedWithTpm() ? 'sealed-tpm' : 'sealed-host' };
  return { key: legacyDerivedKey(), mode: 'derived' };
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
/**
 * Make guessing expensive without letting a guesser deny the real agent.
 *
 * The first shape of this was a lockout: ten bad tokens for an agent name and that name
 * was refused for sixty seconds. Behind a 0600 socket that was defensible. It is not
 * defensible now — this phase made the per-agent sockets world-connectable, because the
 * daemon is a different uid and a 0600 socket it owns is one no agent could reach. So any
 * local process could send ten wrong tokens and take the LEGITIMATE agent off the air,
 * repeatedly, for as long as it liked. The mechanism meant to slow an attacker down had
 * become the cheapest attack available, and this phase is what introduced it.
 *
 * The rule now: a correct token is ALWAYS served. Nothing an attacker sends can change
 * what the holder of the real token gets back. The cost falls on the failing caller
 * instead, as a delay that doubles per consecutive failure — which is what actually
 * throttles guessing, since it is the attacker's own connection that has to wait.
 *
 * The delay is per agent name, and that is a deliberate, stated limit: a unix socket
 * carries no address to attribute failures to, and Node exposes no SO_PEERCRED to
 * identify the caller. So a persistent guesser does slow down a legitimate client that
 * is ALSO failing — but a legitimate client that is failing has the wrong token, and
 * telling it so a second later costs nothing.
 */
class Knocks {
  private fails = new Map<string, { n: number; until: number }>();
  private readonly WINDOW_MS = 60_000;
  // Overridable so the tests can exercise the growth curve without sitting through it.
  // Production values are the defaults; nothing in the shipped path sets these.
  private readonly BASE_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_BASE_MS) || 50;
  private readonly MAX_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_MAX_MS) || 2_000;

  /**
   * How long to make a FAILING caller wait. Never consulted before a token is checked:
   * a valid token must not be delayed or refused because somebody else guessed wrong.
   */
  penaltyMs(name: string): number {
    const f = this.fails.get(name);
    if (!f || Date.now() >= f.until) return 0;
    return Math.min(this.BASE_DELAY_MS * 2 ** Math.min(f.n, 16), this.MAX_DELAY_MS);
  }

  record(name: string): void {
    const now = Date.now();
    const f = this.fails.get(name);
    if (!f || now >= f.until) { this.fails.set(name, { n: 1, until: now + this.WINDOW_MS }); return; }
    f.n += 1;
    // Sliding, not fixed: a guesser that keeps knocking keeps paying, rather than
    // getting a clean slate sixty seconds after its first attempt.
    f.until = now + this.WINDOW_MS;
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
    const { key, mode } = deriveMachineKey();
    this.key = key;
    this.keyMode = mode;
    this.loadProfiles();
  }

  /** 'sealed' when the key came from the TPM via systemd; 'derived' when it is recomputable. */
  keyMode: KeyMode = 'derived';

  /**
   * A store we could not read is NOT an empty store.
   *
   * This used to log the failure and carry on with `this.profiles` still `[]`. The daemon
   * would come up serving nobody, which looks like a bad day — and then the first
   * enrolment called saveProfiles(), which wrote a store containing ONLY that profile,
   * over the ciphertext holding every other agent's credentials. A recoverable problem
   * (a changed /etc/machine-id, a recreated wundervault account, a damaged file — all of
   * which leave the plaintext retrievable) became permanent loss, silently.
   *
   * So a decrypt failure is now a refusal: the daemon will not serve and will not save
   * until a person has looked at it. Refusing to start is a visible, reversible failure.
   * Overwriting is neither.
   */
  private unreadableStore: string | null = null;

  loadProfiles(): void {
    const pp = profilesPath();
    if (!fs.existsSync(pp)) { this.unreadableStore = null; return; }
    try {
      this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
      this.unreadableStore = null;
      return;
    } catch (err) {
      // Before giving up: a store written under the OLD derived key is not corrupt, it is
      // just addressed to a key we have stopped using. Try that key, and if it opens,
      // rewrite the store under the sealed one immediately. Migration has to be automatic —
      // an upgrade that leaves every existing install unable to start is not an upgrade, and
      // one that needs a manual step is one most people will not take.
      if (this.keyMode !== 'derived') {
        try {
          const viaLegacy = decryptProfiles(fs.readFileSync(pp), legacyDerivedKey()).profiles;
          this.profiles = viaLegacy;
          this.unreadableStore = null;
          this.saveProfiles();
          console.error(
            '[wundervault-agent] Re-sealed the profile store: it was encrypted with a key ' +
            'derived from public inputs, and is now sealed to this machine.',
          );
          // The old salt is no longer an input to anything. Leaving it implies otherwise.
          try { fs.unlinkSync(saltPath()); } catch { /* already gone */ }
          return;
        } catch { /* genuinely unreadable; fall through to the refusal below */ }
      }
      this.unreadableStore = (err as Error).message;
      this.profiles = [];
      console.error(
        `[wundervault-agent] Could not read the profile store at ${pp}: ${this.unreadableStore}\n` +
        `[wundervault-agent] It is encrypted against this machine's id and the daemon's uid.\n` +
        `[wundervault-agent] REFUSING to serve or to overwrite it. The credentials are still\n` +
        `[wundervault-agent] in that file; starting fresh would destroy them. Restore the file,\n` +
        `[wundervault-agent] or move it aside deliberately if you mean to start over.`,
      );
    }
  }

  /** True when the store exists but could not be read. Nothing may be written in this state. */
  get storeUnreadable(): boolean { return this.unreadableStore !== null; }

  saveProfiles(): void {
    if (this.unreadableStore) {
      throw new Error(
        `Refusing to write the profile store: it exists but could not be decrypted ` +
        `(${this.unreadableStore}). Writing now would replace every credential in it ` +
        `with only what is in memory.`,
      );
    }
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

    // Refuse before touching anything. Saving first was not enough on its own: by the time
    // saveProfiles() threw, the in-memory list had already been rewritten and the previous
    // agent's socket closed, so a rejected enrolment still took a working agent off the
    // air. The state a failure leaves behind has to be the state it started from.
    if (this.storeUnreadable) {
      throw new Error(
        `Refusing to enrol while the profile store cannot be read. Writing now would ` +
        `replace every credential in it with only what is in memory.`,
      );
    }

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
    // Saved BEFORE the socket is published. The other order started serving credentials
    // and then threw on save, so a daemon that had just declared it would not write to an
    // unreadable store was nonetheless handing out a profile it had not committed —
    // refusing the caller while serving the agent. Commit first; publish only if it stuck.
    this.saveProfiles();
    this.startAgentSocket(profile);
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
      // Inactivity timeout AND an absolute one. The inactivity timer alone is resettable
      // by any traffic, which is what let a connection be held open indefinitely.
      socket.setTimeout(5_000, () => socket.destroy());
      const deadline = setTimeout(() => socket.destroy(), 10_000);
      (deadline as unknown as { unref?: () => void }).unref?.();
      socket.on('close', () => clearTimeout(deadline));
      socket.on('data', (d) => {
        buf += d.toString();
        if (buf.length > 4096) { socket.destroy(); return; }
        if (!buf.includes('\n')) return;

        let msg: { token?: string } = {};
        try { msg = JSON.parse(buf.trim()); } catch { /* treated as no token */ }

        // The token is checked FIRST, before any penalty is consulted. The previous order
        // let a stranger's wrong guesses decide what the real agent got back.
        if (!tokenMatches(msg.token, profile.socket_token)) {
          const wait = this.knocks.penaltyMs(profile.agent_name);
          this.knocks.record(profile.agent_name);
          console.error(`[wundervault-agent] Auth failure on ${profile.agent_name} socket`);
          // The same answer for a bad token and a missing one. Anything more specific
          // tells a local prober which agent names exist on this machine.
          const refuse = () => {
            try {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
              socket.end();
            } catch { /* the prober hung up while waiting, which is fine */ }
          };
          if (wait > 0) {
            const t = setTimeout(refuse, wait);
            // Do not hold the event loop open on behalf of someone guessing tokens.
            (t as unknown as { unref?: () => void }).unref?.();
            socket.on('close', () => clearTimeout(t));
          } else {
            refuse();
          }
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

    // NO maxConnections here, deliberately — the second version of this code had one, and
    // it recreated the denial of service it was meant to prevent one layer down. A ceiling
    // of 64 means 64 held connections exclude everyone else, and the legitimate agent's
    // connection is dropped by the kernel BEFORE its token is ever read. Holding them was
    // easy: setTimeout() is an INACTIVITY timeout, so a byte every few seconds reset it
    // indefinitely, and the 4096-byte ceiling took hours to reach at that rate.
    //
    // What bounds the resource is the absolute deadline below instead: a connection dies a
    // fixed time after it was accepted, whatever it sends. Slots cannot be held, so they
    // do not need to be rationed, and nothing an attacker does can make the daemon refuse
    // a connection it has not yet authenticated.
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
    fs.mkdirSync(md, { recursive: true, mode: 0o755 });
    fs.chmodSync(md, 0o755);
    try { fs.unlinkSync(mp); } catch { /* nothing to clear */ }

    const mgmt = net.createServer((socket) => {
      let buf = '';
      // An ABSOLUTE deadline as well as the inactivity one. setTimeout() below is reset by
      // any traffic, so a byte every nine seconds held a management connection for days —
      // no newline, so never consumed, and the 64KiB ceiling never reached. Enough of
      // those and the daemon runs out of file descriptors and no agent can connect.
      //
      // It is generous because enrolment legitimately waits on two network round trips,
      // and the previous 10s inactivity timeout could destroy the socket mid-enrolment:
      // the profile still got registered and the link still got burned, but the caller
      // never learned the name, so it never wrote the token file. An agent existed that
      // nothing could authenticate as.
      const hardDeadline = setTimeout(() => socket.destroy(), 60_000);
      (hardDeadline as unknown as { unref?: () => void }).unref?.();
      socket.on('close', () => clearTimeout(hardDeadline));

      // Writing to a destroyed socket throws; every reply goes through here so a client
      // that hung up cannot turn into an unhandled error inside an async handler.
      const reply = (obj: unknown) => {
        try {
          if (socket.destroyed) return;
          socket.write(JSON.stringify(obj) + '\n');
          socket.end();
        } catch { /* the caller is gone */ }
      };
      // One request per connection. The handler fires on every 'data' event and reparses
      // whatever is in the buffer, so before this flag a caller could write one valid
      // enrol line and then dribble single bytes: each one re-ran the same request, and
      // each enrol is a 100,000-round PBKDF2 plus a network fetch. A thousand of those
      // stall the event loop that every agent's credential socket shares.
      let consumed = false;
      socket.setTimeout(10_000, () => socket.destroy());
      socket.on('data', (d) => {
        buf += d.toString();
        // Enrolment carries a profile, so this ceiling is higher than the agent socket's —
        // but it is still a ceiling.
        if (buf.length > 64 * 1024) { socket.destroy(); return; }
        const nl = buf.indexOf('\n');
        if (nl < 0) return;
        if (consumed) return;
        consumed = true;

        try {
          const msg = JSON.parse(buf.slice(0, nl));
          if (msg.action === 'enrol' && msg.setup_url) {
            // The ONLY way a profile gets in. `register_profile` used to live here and
            // took whatever it was handed: any local process — every agent on this
            // machine included, since they run as the owner — could register a name with
            // a token of its choosing and then read that agent's credentials off its own
            // socket. No local permission could fix that, because the kernel cannot tell
            // the owner's shell from an agent running as the owner.
            //
            // A setup link can. It is issued by the server to someone logged in to the
            // website, it is single-use, and it expires in fifteen minutes. An agent
            // cannot obtain one. So the daemon redeems it ITSELF: the caller hands over a
            // URL and learns a name, and the credentials never exist in the asking
            // process at all.
            void (async () => {
              try {
                // Checked BEFORE anything is redeemed. Redeeming first meant a missing
                // socket_token burned a single-use link and produced no usable agent —
                // the link spent, the agent absent, and another trip to the dashboard.
                if (!msg.socket_token || String(msg.socket_token).length < 32) {
                  throw new Error('An enrolment must carry a socket_token of at least 32 characters.');
                }
                // The burn is deferred: the link is marked used only once the profile is
                // actually stored, so a disk error cannot consume it either.
                const { creds, burn } = await redeemSetupLink(String(msg.setup_url));
                this.registerProfile({
                  agent_name: creds.agent_name,
                  api_key: creds.api_key,
                  enc_key: creds.enc_key,
                  vault_url: creds.vault_url,
                  socket_token: String(msg.socket_token),
                } as AgentProfile);
                const burned = await burn();
                // Reported, not swallowed. An unburned link stays usable for the rest of
                // its fifteen minutes and could be replayed to overwrite this profile with
                // a different token, so the caller is told rather than reassured.
                reply({
                  ok: true, agent_name: creds.agent_name, agent_id: creds.agent_id,
                  link_burned: burned,
                });
              } catch (e) {
                reply({ error: (e as Error).message });
              }
            })();
            return;   // the async path owns this socket from here
          } else if (msg.action === 'whose_link' && msg.setup_url) {
            // The agent's NAME, redeeming nothing — the GET endpoint does not burn. This
            // exists so enrolment can find out whether that agent already has a socket
            // token BEFORE committing, which replaced a two-step register-then-swap that
            // left an agent registered under a token the caller had not saved if the
            // connection dropped in between.
            void (async () => {
              try {
                const name = await peekAgentName(String(msg.setup_url));
                reply({ ok: true, agent_name: name });
              } catch (e) {
                reply({ error: (e as Error).message });
              }
            })();
            return;
          } else if (msg.action === 'remove_profile' && msg.agent_name) {
            // Gated on the agent's own token. The socket is world-connectable now, so
            // without this any local user could delete another user's agents. It does NOT
            // distinguish one agent from another under the same uid — nothing can, and
            // the spec says so in C5 — but it does stop everyone else.
            const name = String(msg.agent_name);
            const target = this.profiles.find(p => p.agent_name === name);
            if (!target || !tokenMatches(msg.token, target.socket_token)) {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
              socket.end();
              return;
            }
            const gone = this.removeProfile(name);
            socket.write(JSON.stringify({ ok: true, removed: gone }) + '\n');
          } else if (msg.action === 'reload') {
            this.loadProfiles();
            socket.write(JSON.stringify({ ok: true, count: this.profiles.length }) + '\n');
          } else if (msg.action === 'destinations') {
            // Deliberately gone. It was served here while the socket sat behind a locked
            // directory; that lock is off, because the owner and their agents are the same
            // uid and any door the owner can open an agent can open too. Serving this now
            // would hand every agent the record of where all the others sent secrets.
            socket.write(JSON.stringify({
              error: 'destinations are not served over this socket. Run: ' +
                     'sudo wundervault-agent --destinations',
            }) + '\n');
          } else if (msg.action === 'ping') {
            // Liveness only. This used to return every agent name on the machine, which
            // is a roster of what holds credentials here, handed to anyone who could
            // reach the socket. Migration is the only caller that needs the names, and it
            // asks for them explicitly below.
            socket.write(JSON.stringify({
              ok: true, version: VERSION, store_unreadable: this.storeUnreadable,
              key_mode: this.keyMode,
            }) + '\n');
          } else if (msg.action === 'known_agents') {
            // Names only, never credentials. This is what lets migration tell you which of
            // your agents still need a repair link, and it is the reason the destination
            // store is NOT served here any more: a roster of names is a much smaller thing
            // to give away than the record of where every agent sent its secrets.
            socket.write(JSON.stringify({
              ok: true, agents: this.profiles.map(p => p.agent_name),
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
      // Connectable by anyone, like the per-agent sockets, and for the same reason: the
      // daemon is a different uid, so a socket it owns at 0660 is one no agent could
      // reach. What guards the actions behind it is a server-issued setup link to enrol
      // and the agent's own token to remove — neither of which a file mode can supply.
      try { fs.chmodSync(mp, 0o666); } catch { /* best effort */ }
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
    // Said out loud, every start. A machine quietly running in the weaker mode while the
    // documentation describes the stronger one is the failure this line exists to prevent.
    if (this.keyMode === 'sealed-tpm') {
      console.log(
        '[wundervault-agent] Store key: SEALED TO THIS MACHINE\'S TPM. ' +
        'A copy of the disk does not open it.',
      );
    } else if (this.keyMode === 'sealed-host') {
      // Deliberately NOT the sentence above. systemd's host key lives at
      // /var/lib/systemd/credential.secret — on the same disk as the sealed store — so a copy
      // of that disk plus root does open this. Better than a key derived from public inputs,
      // and not the same claim.
      console.log(
        '[wundervault-agent] Store key: sealed to systemd\'s HOST KEY (no TPM found).\n' +
        '[wundervault-agent] That key is on this same disk, so an offline copy plus root\n' +
        '[wundervault-agent] WOULD open the store. It stops a casual file read, not a\n' +
        '[wundervault-agent] stolen disk. A TPM is what makes the disk copy useless.',
      );
    } else {
      console.error(
        '[wundervault-agent] Store key: DERIVED from machine-id and uid, which are not secret.\n' +
        '[wundervault-agent] Anyone who can read this directory can recompute it, so the\n' +
        '[wundervault-agent] directory mode is what protects the store — not the encryption.',
      );
    }
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

/**
 * Read the setup link from stdin.
 *
 * Deliberately not an argument. `/proc/<pid>/cmdline` is world-readable on Linux, so a
 * link passed on the command line is visible to every process running as the owner — which
 * is every agent — for as long as the command runs. That link is the one credential this
 * whole design assumes an agent cannot obtain, and fetching and burning are separate steps,
 * so an agent that copied it would have had time to redeem it first. Piping still works, so
 * this stays scriptable; nothing that reaches here lands in argv.
 */
function readLinkFromStdin(): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      process.stderr.write('Paste the setup link from the dashboard (it ends in #…): ');
    }
    let buf = '';
    process.stdin.setEncoding('utf8');
    const finish = (v: string) => { process.stdin.pause(); resolve(v.trim()); };
    process.stdin.on('data', (d) => {
      buf += d;
      // A terminal sends no EOF until ctrl-D, so the first newline ends the read.
      if (process.stdin.isTTY && buf.includes('\n')) finish(buf.split('\n')[0]);
    });
    process.stdin.on('end', () => finish(buf));
  });
}

// Only run when invoked as the binary, so the class can be imported by tests and by the
// migration command without starting a daemon as a side effect.
const invokedDirectly = process.argv[1] && /wundervault-agent|agent\.(js|ts)$/.test(process.argv[1]);
if (invokedDirectly && !process.env.WUNDERVAULT_AGENT_NO_AUTOSTART) {
  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`
Wundervault secret broker ${VERSION}

Usage: wundervault-agent [--enrol] [--migrate [--finish]] [--destinations]

With no arguments it runs as the secret broker: the process that holds your agents'
credentials so the agents cannot read them. It is normally started by systemd as the
'${SYSTEM_ACCOUNT}' account, not by hand.

  --enrol       Add an agent using a setup link from the dashboard. Prompts for the link
                rather than taking it as an argument: a command line is readable by every
                process on this machine. The broker redeems the link itself, so the
                credentials never pass through this process.
  --migrate     Show which agents still need moving to the broker, and how.
  --finish      With --migrate: delete the old store, once every agent is across.
  --destinations  Show where your agents have sent secrets. Needs sudo: the record
                belongs to the broker so your agents cannot read it. The page is opened
                and then DELETED, because it is a copy your agents could otherwise read.
  --keep        With --destinations: leave the page on disk instead.

State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
`);
    process.exit(0);
  }

  if (argv.includes('--destinations')) {
    // Dispatched here as well as in the MCP binary, because every message that mentions
    // this names THIS command — `sudo wundervault-agent --destinations`. It was only wired
    // into wundervault-mcp, so the advice printed by the daemon and the log viewer led
    // straight into refuseRoot and a message about not running as root.
    //
    // refuseRoot is deliberately NOT called on this path: reading the store is the one
    // thing that requires being root, because the file belongs to the daemon's account and
    // that is what stops the agents reading it.
    const { writeViewer, collectShape, resolveSudoUser, dropToSudoUser,
            shredViewer, openInBrowser } = await import('./log-viewer.js');
    const { defaultStorePath } = await import('./network-store.js');
    const pathMod = await import('node:path');
    const store = defaultStorePath();
    // Read as root — that is the only reason this needs privilege — then give it up before
    // writing anything into a home directory. Root must not follow paths an agent can
    // rearrange under it; doing so was a working escalation to a root cron job.
    // resolveSudoUser throws when SUDO_USER is set but cannot be resolved — refusing to
    // carry on as root is correct, but it has to read as a message rather than a stack
    // trace, and it happens before the promise chain that handles everything else.
    let sudoUser: { uid: number; gid: number; home: string } | null = null;
    try {
      sudoUser = resolveSudoUser();
    } catch (e) {
      console.error((e as Error).message);
      process.exit(1);
    }
    collectShape(store)
      .then(({ shape }) => {
        let target: string | undefined;
        if (sudoUser) {
          target = pathMod.join(sudoUser.home, '.wundervault', 'destinations.html');
          dropToSudoUser(sudoUser);
        }
        const out = writeViewer(store, target, shape);
        const calls = shape.seen.reduce((n: number, x: { count: number }) => n + x.count, 0);
        const keep = argv.includes('--keep');

        console.log(
          `\nDestination log — ${shape.seen.length} destination(s), ${calls} call(s)\n` +
          `  store:  ${store}\n  viewer: ${out}\n`);

        if (keep) {
          // Deliberate, and said plainly. Someone may want the page to keep or to send.
          console.log(
            `Kept on disk at your request. It is a full copy of the record above, and your\n` +
            `agents run as you — so anything you run can read it until you delete it.\n`);
          process.exit(0);
        }

        // Removed on the way out however we leave: a clean exit, a ctrl-C, or the timeout.
        // Leaving the copy behind is the thing being avoided, so it must not depend on the
        // user choosing the tidy path.
        // The inode, captured now, so cleanup can tell OUR page from one another
        // invocation wrote to the same path — including one deliberately kept with --keep.
        let stamp: { ino: number; mtimeMs: number } | undefined;
        try {
          const st = fs.statSync(out);
          stamp = { ino: st.ino, mtimeMs: st.mtimeMs };
        } catch { /* gone already; cleanup will no-op */ }

        let gone = false;
        const cleanup = () => { if (!gone) { gone = true; shredViewer(out, stamp); } };
        process.on('exit', cleanup);
        for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
          process.on(sig, () => { cleanup(); process.exit(0); });
        }

        const opened = openInBrowser(out);
        console.log(opened
          ? `Opened in your browser. The copy is removed when you close this command —\n` +
            `press ctrl-C when you are done, or it clears itself in 10 minutes.\n` +
            `(--keep leaves it on disk instead.)\n`
          : `Could not open a browser. Open the file above, then press ctrl-C here to\n` +
            `remove it. It clears itself in 10 minutes. (--keep leaves it on disk.)\n`);
        console.log(
          `It is deleted because it is a COPY of a record your agents cannot otherwise\n` +
          `read: they run as you, so a file in your home is a file they can open.\n`);

        setTimeout(() => { cleanup(); process.exit(0); }, 10 * 60 * 1000);
      })
      .catch((e: Error) => { console.error(e.message); process.exit(1); });
  } else if (argv.includes('--enrol')) {
    // Runs as the USER. It hands over a URL and gets back a name — the credentials are
    // fetched, decrypted and filed by the daemon, and never enter this process.
    //
    // The link is READ FROM STDIN, never taken from argv. A command line is world-readable
    // through /proc/<pid>/cmdline, so `--enrol "https://...#passphrase"` published the one
    // credential this design assumes an agent cannot get, to every agent on the machine,
    // for as long as the command ran. And because fetching and burning are separate steps,
    // an agent that copied it had time to redeem it first. Prompting costs one paste and
    // keeps the link out of argv and out of shell history.
    const url = await readLinkFromStdin();
    if (!url) {
      console.error('No setup link given.');
      process.exit(2);
    }
    const { enrol } = await import('./migrate.js');
    enrol(url)
      .then((r) => {
        console.log(`Enrolled ${r.agent_name}. Its credentials are held by the broker in ${systemRoot()}, ` +
                    `which your agents cannot read.`);
        if (!r.linkBurned) {
          console.log('');
          console.log('WARNING: the server did not confirm the setup link as used, so it stays');
          console.log('valid until it expires and could be replayed to re-point this agent.');
          console.log('Repair the agent again in the dashboard if that matters to you.');
        }
        process.exit(0);
      })
      .catch((e: Error) => { console.error(e.message); process.exit(1); });
  } else if (argv.includes('--migrate')) {
    // Runs as the USER, not the daemon: it reads the old store from a home directory the
    // daemon deliberately cannot reach.
    const { status, describeStatus, cleanup } = await import('./migrate.js');
    if (argv.includes('--finish')) {
      cleanup()
        .then((r) => {
          if (r.pending.length) {
            console.error(`Not yet — these are still on the old credentials: ${r.pending.join(', ')}`);
            console.error('Deleting the store now would take them off the air for good.');
            process.exit(1);
          }
          console.log(r.deleted
            ? 'Deleted the pre-split store. Credentials now live where your agents cannot read them.'
            : 'There was no pre-split store to delete.');
          if (!r.oldUnitStopped) {
            console.log('');
            console.log('The pre-split daemon may still be running. It is serving credentials the');
            console.log('server no longer accepts, but it should not be left behind:');
            console.log('  systemctl --user disable --now wundervault-agent.service');
          }
          process.exit(0);
        })
        .catch((e: Error) => { console.error(e.message); process.exit(1); });
    } else {
      status()
        .then((st) => { console.log(describeStatus(st)); process.exit(0); })
        .catch((e: Error) => { console.error(e.message); process.exit(1); });
    }
  } else {
    refuseRoot();
    announceBoundary();
    const daemon = new AgentDaemon();
    daemon.start();
    process.on('SIGTERM', () => { daemon.shutdown(); process.exit(0); });
    process.on('SIGINT', () => { daemon.shutdown(); process.exit(0); });
  }
}
