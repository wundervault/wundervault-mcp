/**
 * Where daemon state lives, and who is allowed to read it.
 *
 * Until phase 4 every path here was under `os.homedir()`, which meant the daemon and the
 * agent it serves were the same uid and shared a directory. Everything built in phases
 * 1–3.5 was true only against an agent that did not try: the key files were readable, the
 * daemon's memory was readable through /proc, and the record of where secrets went was
 * writable by the party it described.
 *
 * The split moves daemon state to `/var/lib/wundervault`, mode 0700, owned by a system
 * account — `wundervault` under a systemd unit on Linux, `_wundervault` under a
 * LaunchDaemon on macOS. The mode is the control. The at-rest encryption beside it is
 * defence in depth and nothing more; calling it "encrypted at rest" as though it were the
 * boundary would repeat exactly the mistake this phase exists to correct.
 *
 * ON macOS THE BOUNDARY IS THE SAME AND THE DEFENCE AROUND IT IS THINNER. The systemd unit
 * carries ProtectSystem=strict, ProtectHome, ProtectProc=invisible, a system-call filter
 * and an empty capability set. launchd has no equivalent for any of them, so the uid split
 * there is very nearly the whole of it. Written down here and in /limitations rather than
 * left for someone to infer parity that does not exist.
 *
 * TWO ROOTS, AND THEY ARE NOT THE SAME THING
 *
 *   systemRoot()  — the daemon's. Credentials, the destination store. The agent's uid
 *                   cannot read it. Only the daemon process writes here.
 *   userRoot()    — the agent's own. Its token, and nothing else that matters.
 *
 * The token stays in the user's home ON PURPOSE. It is the agent's identity now: a file
 * owned by the agent's uid at 0600, which the daemon checks. Moving it into the daemon's
 * directory would make it unreadable by the only party that needs it.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

/** The packaged default. Overridable for tests and for a non-standard install. */
export const DEFAULT_SYSTEM_ROOT = '/var/lib/wundervault';
export const SYSTEM_ACCOUNT = 'wundervault';

/**
 * macOS keeps its state one level down, and the reason is not tidiness.
 *
 * On Linux the sockets live in /run/wundervault, which systemd creates at 0755 OUTSIDE the
 * 0700 state directory. macOS has no /run and no RuntimeDirectory=, and the obvious answer
 * — put the sockets inside the state directory — is fatally wrong: 0700 means no search
 * permission for anyone but the daemon account, so an agent, which runs as the OWNER,
 * cannot traverse into it to reach its own socket. Every connection would fail with EACCES
 * on a machine where the install had gone perfectly.
 *
 * So the top directory is traversable and holds nothing readable, with the private state
 * one level down:
 *
 *   /var/lib/wundervault        0755  the account   — traversable, empty of secrets
 *   /var/lib/wundervault/state  0700  the account   — the boundary
 *   /var/lib/wundervault/run    0755  the account   — sockets, reachable by agents
 *
 * This is the same shape the module already argues for elsewhere: the sockets are
 * world-connectable and the TOKEN is the identity. Nothing is protected by being hard to
 * reach — so nothing legitimate may be made hard to reach either.
 */
export const DARWIN_BASE = '/var/lib/wundervault';
export const DARWIN_SYSTEM_ROOT = `${DARWIN_BASE}/state`;
export const DARWIN_ACCOUNT = '_wundervault';

/**
 * Windows, where the same shape is built out of a different mechanism.
 *
 *   %ProgramData%\wundervault        everyone may traverse; holds nothing readable
 *   %ProgramData%\wundervault\state  THE BOUNDARY — an ACL, not a mode
 *   %ProgramData%\wundervault\run    everyone reads; only the account writes
 *
 * Run is a SIBLING of state for the same reason as macOS and by a different route: on
 * macOS 0700 denies search permission to the agents, on Windows the state ACL simply does
 * not name them. Either way the agents must reach their endpoint, and the endpoint must
 * not live behind the boundary.
 *
 * `%ProgramData%` rather than `/var/lib`, which on Windows silently becomes `C:\var\lib`
 * — a directory the daemon would create successfully and then fail to use, which is the
 * quiet version of this bug that `platformShape()` already warns about below.
 */
export const WINDOWS_BASE = (): string =>
  path.join(process.env.ProgramData || 'C:\\ProgramData', 'wundervault');
export const WINDOWS_SYSTEM_ROOT = (): string => path.join(WINDOWS_BASE(), 'state');
export const WINDOWS_ACCOUNT = 'wundervault';

/**
 * Daemon-owned state.
 *
 * `WUNDERVAULT_SYSTEM_ROOT` exists so tests can point this somewhere writable, and so an
 * unusual install can relocate it. It is read from the DAEMON's environment, which after
 * the split is set by the unit file rather than by whoever started a shell — an agent
 * cannot move the daemon's state by exporting a variable, because it does not control the
 * daemon's environment.
 */
/**
 * Is the uid split actually available here, and which layout are we using?
 *
 * Phase 4 was Linux; phase 7 adds macOS; Windows (phase 8) is deliberately later. But OUT
 * OF SCOPE HAS TO MEAN UNCHANGED, not broken — and for two commits it meant broken. The
 * daemon's constructor calls ensureSystemRoot() unconditionally, so on macOS it tried to
 * mkdir /var/lib/wundervault as a normal user and died with EACCES where it had previously
 * used the home directory. On Windows it is quieter and worse: /var/lib/wundervault
 * resolves to C:\var\lib\wundervault, the mkdir SUCCEEDS, and the daemon then tries to
 * bind unix domain sockets there, which Windows does not have.
 *
 * Windows therefore keeps the pre-split layout exactly: state in the user's own directory,
 * daemon as the user. That is the old threat model, and the code says so out loud rather
 * than letting anyone infer a boundary that is not there.
 *
 * TWO QUESTIONS, NOT ONE — AND KEEPING THEM APART IS THE POINT
 *
 * `platformShape()` decides WHERE THINGS GO. It is overridable, because otherwise the
 * macOS layout is unreachable from CI on Linux and verifiable only by hand on one
 * machine — which is precisely how the port lock in lock.ts shipped broken and stayed
 * broken for a release.
 *
 * `splitAvailable()` decides WHETHER A BOUNDARY IS POSSIBLE. It consults the REAL
 * platform, so the override can make a Linux box exercise the darwin paths but can never
 * make a platform claim a separation it cannot perform.
 *
 * And neither of them is what we tell the user. That is `boundaryIsReal()`, below, which
 * looks at the directory rather than at the operating system.
 */
export type PlatformShape = 'linux' | 'darwin' | 'windows' | 'none';

/** Platforms on which a second uid is actually reachable. NOT overridable. */
const SPLIT_CAPABLE = new Set(['linux', 'darwin', 'win32']);

function shapeFor(platform: string): PlatformShape {
  if (platform === 'linux') return 'linux';
  if (platform === 'darwin') return 'darwin';
  if (platform === 'win32') return 'windows';
  return 'none';
}

/**
 * Which layout to use. `WUNDERVAULT_PLATFORM_SHAPE` exists so a test on one platform can
 * exercise another's paths. An unrecognised value is a typo, not a request for the
 * pre-split layout, so it throws rather than silently dropping the boundary.
 */
export function platformShape(): PlatformShape {
  const override = process.env.WUNDERVAULT_PLATFORM_SHAPE;
  if (override) {
    if (override !== 'linux' && override !== 'darwin' && override !== 'windows'
        && override !== 'none') {
      throw new Error(
        `WUNDERVAULT_PLATFORM_SHAPE=${JSON.stringify(override)} is not one of ` +
        `linux, darwin, windows, none.`,
      );
    }
    return override;
  }
  return shapeFor(process.platform);
}

/**
 * Pure, so the combination can be asserted directly rather than by stubbing a global.
 *
 * The real platform is the veto. A shape of 'linux' on Windows yields FALSE: the override
 * relocates state, it does not conjure an account the operating system cannot give us.
 */
export function splitAvailableFor(realPlatform: string, shape: PlatformShape): boolean {
  if (shape === 'none') return false;
  if (!SPLIT_CAPABLE.has(realPlatform)) return false;
  // WINDOWS CANNOT HOST A POSIX LAYOUT, and this is not pedantry about tidiness. The
  // linux and darwin shapes put unix domain sockets at filesystem paths, and `listen()`
  // on a filesystem path returns EACCES on Windows — measured, Node 22 on Windows 10.
  // Under either override a Windows daemon would bind nothing at all, so there is no
  // boundary to claim and the pre-split layout is the right answer.
  //
  // The reverse is deliberately permitted: a Linux box may be told to use the darwin or
  // windows layout, because exercising another platform's paths from CI is the only
  // defence against the failure mode that put this project here twice — code on a path
  // nobody can run until a customer runs it. What stops that becoming a false claim is
  // boundaryIsReal(), which looks at the directory: under the windows shape it wants
  // icacls, which a Linux box does not have, and answers false.
  if (realPlatform === 'win32') return shape === 'windows';
  return true;
}

/** True where the daemon CAN hold a real privilege boundary. Not that it does. */
export function splitAvailable(): boolean {
  return splitAvailableFor(process.platform, platformShape());
}

export function systemRoot(): string {
  if (process.env.WUNDERVAULT_SYSTEM_ROOT) return process.env.WUNDERVAULT_SYSTEM_ROOT;
  // Where there is no system account and no unit, the daemon is the user, as before.
  if (!splitAvailable()) return userRoot();
  if (platformShape() === 'darwin') return DARWIN_SYSTEM_ROOT;
  if (platformShape() === 'windows') return windowsStateRoot();
  return DEFAULT_SYSTEM_ROOT;
}

/**
 * The Windows state root, WHICH IS CONDITIONAL, and the condition is not fussiness.
 *
 * On Linux and macOS the system root is returned unconditionally and a daemon that has not
 * been installed gets EACCES creating it — a loud, correct "run the installer". That does
 * not work here, because `C:\ProgramData` grants Users the right to create subdirectories.
 * An uninstalled Windows daemon would therefore SUCCEED in creating
 * `%ProgramData%\wundervault\state`, inherit ProgramData's ACL, and store every
 * credential on the machine in a directory the other accounts on that machine can read.
 * Pre-split state in the owner's own profile is not a boundary either, but it is at least
 * private to the owner — so the uninstalled case would be a REGRESSION dressed as progress.
 *
 * The rule: use the installed location only when it exists AND its ACL is actually
 * private. A rogue process that pre-creates the directory to redirect the daemon gets
 * inherited ACEs, fails the check, and the daemon quietly stays in the owner's profile and
 * says it has no boundary — which is the truth in both cases.
 *
 * Cached, because it costs an `icacls` subprocess and the answer cannot change under a
 * running daemon without the install changing under it too.
 */
let cachedWindowsRoot: string | null = null;

function windowsStateRoot(): string {
  if (cachedWindowsRoot) return cachedWindowsRoot;
  const installed = WINDOWS_SYSTEM_ROOT();
  let use = userRoot();
  try {
    if (fs.statSync(installed).isDirectory()) {
      // WE ARE THE SERVICE ACCOUNT: this directory is ours, whatever its ACL says today.
      //
      // The first version fell back whenever the ACL was not private, and that is wrong
      // for an INSTALLED machine. Widening the state ACL -- a bad group policy, a careless
      // icacls, an attacker -- made the daemon quietly relocate to the service account's
      // own profile, leave a stale discovery file pointing at a port it no longer held,
      // and strand every credential in the store it had walked away from. Observed: after
      // granting Users:(RX), every agent got "connection refused" and the broker was
      // simply gone.
      //
      // Linux does not do that, and neither should this. A widened directory is a
      // boundary that is GONE, not a store that is someone else's: boundaryIsReal() says
      // so loudly, the startup warning prints, and the credentials keep working. Refusing
      // to serve protects nothing and strands everything -- the same argument
      // deriveMachineKey() makes about a store it cannot verify.
      //
      // The fallback still does its one job, which is the UNINSTALLED case: C:\ProgramData
      // lets any account create a subdirectory, so a rogue could pre-create this path to
      // capture credentials from a daemon that has never been installed. A rogue cannot be
      // the service account -- that account exists only because the installer made it.
      let ours = false;
      try { ours = os.userInfo().username.toLowerCase() === expectedAccount().toLowerCase(); }
      catch { ours = false; }

      if (ours) {
        use = installed;
      } else {
        const report = readAclReport(installed);
        if (report !== null && windowsAclIsRestricted(report, principalId())) use = installed;
      }
    }
  } catch { /* not installed, or unreadable: stay in the owner's profile */ }
  cachedWindowsRoot = use;
  return use;
}

/** Exported so a test can make the decision again after changing the world. */
export function _resetWindowsRootCacheForTests(): void { cachedWindowsRoot = null; }

/**
 * The agent's own directory: its token, and its view of things.
 *
 * Deliberately does NOT consult `SUDO_USER`. An earlier version did, so that
 * `sudo wundervault-agent --destinations` would write its page into the invoking user's
 * home rather than root's — and that turned a root process into one that resolves a path
 * through a directory the agent controls. The result was a working root escalation: an
 * agent replaced `~/.wundervault/destinations.html` with a symlink to `/etc/cron.d/x`, root
 * followed it, and the chown handed the agent a file it could fill with a root cron job.
 *
 * The sudo case is handled where it belongs — by dropping privileges before writing
 * anything into a user's home (see `dropToSudoUser` in log-viewer.ts). A root process must
 * not follow paths that an unprivileged account can rearrange under it.
 */
/**
 * WHO WE ARE, for the purposes of keying something that is machine-global.
 *
 * Every derivation in this codebase that needs "this account, not another one on the same
 * box" was written as `process.getuid?.() ?? 0`. On Windows `getuid` is undefined, so the
 * fallback fires and EVERY ACCOUNT ON THE MACHINE IS PRINCIPAL 0. `lock.ts` says in a
 * comment that the uid is in its port digest so that "two OS accounts on one box [do not]
 * exclude each other over credentials they do not share" — and on Windows that is precisely
 * what happened: two users, same agent name, same derived port, and one of them told its
 * credential was already in use.
 *
 * On POSIX this returns the uid as a string, so the derived values are bit-for-bit what
 * they were. On Windows it returns the account SID, which is the uid's actual counterpart:
 * unique per account, stable across renames, and machine-local.
 *
 * The SID costs a subprocess, so it is read once and cached. If it cannot be read we fall
 * back to the lowercased username — weaker (a renamed account changes principal) but still
 * per-account, which is the property that was missing.
 */
let cachedPrincipal: string | null = null;

export function principalId(): string {
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  if (uid !== undefined) return String(uid);
  if (cachedPrincipal) return cachedPrincipal;

  // NO ENVIRONMENT OVERRIDE. There was one, for tests that turned out not to need it, and
  // it was a hole: this value keys the lock port and the derived store key, so a variable
  // an agent can set is a variable an agent can use to answer as a different principal.
  // The other overrides in this file relocate state or choose a layout; none of them says
  // WHO WE ARE, and this one must not either.
  try {
    const out = execFileSync('whoami', ['/user', '/fo', 'csv', '/nh'], {
      encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'],
    });
    const m = out.match(/"(S-1-[0-9-]+)"/);
    if (m) { cachedPrincipal = m[1]; return cachedPrincipal; }
  } catch { /* fall through to the username */ }

  try { cachedPrincipal = os.userInfo().username.toLowerCase(); }
  catch { cachedPrincipal = 'unknown-principal'; }
  return cachedPrincipal;
}

/** Exported so a test can force the Windows path to be re-read. */
export function _resetPrincipalCacheForTests(): void { cachedPrincipal = null; }

export function userRoot(): string {
  return process.env.WUNDERVAULT_USER_ROOT || path.join(os.homedir(), '.wundervault');
}

/**
 * Where sockets live.
 *
 * `RuntimeDirectory=wundervault` in the unit makes systemd create and clean up
 * `/run/wundervault`, which is better than our code guessing: a stale socket in a
 * hand-made directory survives a crash and the next start binds somewhere else, leaving
 * agents talking to nothing.
 *
 * Falls back to the system root when there is no /run — a container, a test, a platform
 * that does not have one.
 */
export function runtimeDir(): string {
  if (process.env.RUNTIME_DIRECTORY) return process.env.RUNTIME_DIRECTORY.split(':')[0];
  if (process.env.WUNDERVAULT_RUNTIME_DIR) return process.env.WUNDERVAULT_RUNTIME_DIR;
  // /run is a Linux thing, and so is the systemd RuntimeDirectory that manages it.
  if (!splitAvailable()) return userRoot();
  const run = `/run/${SYSTEM_ACCOUNT}`;
  let linuxRunExists = false;
  try { linuxRunExists = fs.existsSync(run); } catch { /* treat as absent */ }
  const root = systemRoot();
  // Is the state root a directory belonging to somebody the agent is not? That is the
  // whole condition for putting the sockets beside it rather than inside it.
  let rootIsSeparate = true;
  try { rootIsSeparate = path.resolve(root) !== path.resolve(userRoot()); }
  catch { rootIsSeparate = true; }
  return runtimeDirFor(platformShape(), root, linuxRunExists, rootIsSeparate);
}

/**
 * Pure, and pure for a reason that cost a round to learn.
 *
 * The darwin branch and the Linux fallback return THE SAME STRING on a box that has no
 * /run/wundervault — which is every development box. So a test asserting the returned path
 * passed whether the darwin branch was there or not: deleting it entirely left the suite
 * green. What distinguishes the two is the DECISION, not the result, and a decision is only
 * observable if the inputs can be supplied.
 *
 * macOS has no /run, and /var/run is cleared at boot and unwritable by the service account,
 * so there is no analogue of systemd's RuntimeDirectory=. The runtime directory lives inside
 * the state directory, which the account already owns.
 */
export function runtimeDirFor(
  shape: PlatformShape,
  root: string,
  linuxRunExists: boolean,
  rootIsSeparate = true,
): string {
  // A SIBLING of the state directory, never a child. The state directory is 0700 on macOS
  // and ACL'd to the account on Windows; either way the agents that have to reach these
  // endpoints are shut out of it.
  //
  // ONLY WHEN THE STATE ROOT IS SOMEBODY ELSE'S, and that qualifier was missing for one
  // run on Windows. Pre-split, the state root IS the agent's own `~/.wundervault`, so the
  // sibling of it is `C:\Users\<you>\run` — a directory this daemon helpfully created in
  // the root of the user's home profile, next to Documents. Observed on Windows 10.
  //
  // There is nothing to be outside of when there is no boundary: pre-split the run
  // directory belongs INSIDE the root, exactly where the pre-split layout always put it.
  if ((shape === 'darwin' || shape === 'windows') && rootIsSeparate) {
    return path.join(path.dirname(root), 'run');
  }
  if (linuxRunExists) return `/run/${SYSTEM_ACCOUNT}`;
  return path.join(root, 'run');
}

/**
 * Where systemd drops credentials it has unsealed for us.
 *
 * `LoadCredentialEncrypted=` in the unit has systemd decrypt a sealed blob AS ROOT and place
 * the plaintext in a private tmpfs readable only by this service. That is the whole trick:
 * the broker never needs access to /dev/tpmrm0 or to the host key, and the sealed file on
 * disk is useless to anyone who copies it — on another machine the TPM will not unseal it,
 * and on this one it takes root.
 */
export const CREDENTIAL_NAME = 'wv-store-key';

export function systemdCredential(name = CREDENTIAL_NAME): Buffer | null {
  // Two places, because the unit unseals with ExecStartPre rather than
  // LoadCredentialEncrypted — that mechanism is fatal when the source cannot be decrypted,
  // which turns a cleared TPM into a broker that will not start. $CREDENTIALS_DIRECTORY is
  // still checked first so the unit can be switched back without touching this code.
  const candidates: string[] = [];
  const dir = process.env.CREDENTIALS_DIRECTORY;
  if (dir) candidates.push(path.join(dir, name));
  candidates.push(path.join(runtimeDir(), 'store.key'));
  // macOS and Windows have no systemd and nothing that unseals on our behalf, so the
  // installer writes a RANDOM key into the state directory -- 0600 on macOS, and on Windows
  // an ACL naming only the account, SYSTEM and Administrators. It is not sealed and the
  // startup report must not say it is — but it is not DERIVED either, which is the
  // difference that matters: nobody can recompute it from public inputs.
  //
  // WINDOWS WAS MISSING FROM THIS LIST for one run, and the symptom was quiet: the
  // installer wrote a perfectly good random key, the daemon never looked at it, and
  // reported key_mode=derived — a key recomputable by anyone who can read the directory —
  // while a 32-byte secret sat unread beside the store. Caught by the verifier asking the
  // daemon what key it was actually using, rather than by anyone reading this line.
  if (platformShape() === 'darwin' || platformShape() === 'windows') {
    candidates.push(storeKeyPath());
  }

  for (const p of candidates) {
    try {
      const buf = fs.readFileSync(p);
      if (buf.length >= 32) return buf;
    } catch { /* try the next */ }
  }
  return null;
}

/**
 * Was the key sealed to the TPM, or only to systemd's host key?
 *
 * The difference is the entire claim. A TPM-sealed key does not leave the machine: copy the
 * disk and it does not open. A HOST-KEY-sealed one is protected by a file at
 * /var/lib/systemd/credential.secret which lives ON THE SAME DISK, so a copy of that disk
 * plus root access opens it — verified by decrypting a sealed blob using nothing but files
 * from the same filesystem. It is still far better than a key derived from public inputs, but
 * saying "a copy of the disk does not open it" about it is simply false, and that sentence
 * was being printed.
 */
export function sealedWithTpm(): boolean {
  return sealKind() === 'tpm';
}

/**
 * Which mechanism produced the store key, so the startup report can make the RIGHT promise.
 *
 *   'tpm'        — sealed to this machine's TPM. A copy of the disk does not open it.
 *   'host'       — sealed to systemd's host key, which is on the same disk. Root plus a
 *                  disk copy does open it.
 *   'local-file' — macOS. A random key in a 0600 file owned by the daemon account. Same
 *                  promise as 'host': not recomputable, not sealed to hardware. FileVault
 *                  is what covers the stolen-disk case, and FileVault is not ours to claim.
 *
 * Three names because three different sentences are true, and the failure this codebase
 * keeps having is one sentence being reused for a weaker mechanism.
 */
export type SealKind = 'tpm' | 'host' | 'local-file' | null;

export function sealKind(): SealKind {
  const declared = process.env.WUNDERVAULT_SEAL_KIND;
  if (declared === 'tpm' || declared === 'host' || declared === 'local-file') return declared;
  // Undeclared but the file is there: the installer wrote it and did not get to set the
  // variable, or the daemon was started by hand. Report what is actually in use.
  //
  // This is the ONLY route on Windows, where a scheduled task carries no environment of
  // its own the way a systemd unit or a launchd plist does -- so the file on disk is the
  // whole of the evidence and there is nothing to declare it.
  const shape = platformShape();
  if (shape === 'darwin' || shape === 'windows') {
    try { if (fs.statSync(storeKeyPath()).size >= 32) return 'local-file'; } catch { /* none */ }
  }
  return null;
}

/** The macOS store key: written by the installer, read by us, 0600 and never shared. */
export const storeKeyPath = () => path.join(systemRoot(), 'store.key');

/** The sealed blob on disk. Written by the installer, read by systemd, never by us. */
export const sealedKeyPath = () => path.join(systemRoot(), 'store.key.cred');

// ── daemon-side paths ─────────────────────────────────────────────────────────

export const profilesPath = () => path.join(systemRoot(), 'agent-profiles.enc');
export const saltPath = () => path.join(systemRoot(), 'agent-salt.bin');

/**
 * The destination store — daemon-owned, which is what turns it from an observation into
 * an integrity control. Before the split, the party being audited could edit the evidence.
 */
export const networkStorePath = () => path.join(systemRoot(), 'network.json');

/**
 * The management socket, inside its own directory.
 *
 * This directory was 0770, on the reasoning that enrolment writes credentials INTO the
 * daemon and so must not be reachable by every local process. The reasoning was right and
 * the mechanism could not deliver it. Agents run as the machine's owner, so a mode that
 * excludes agents excludes the owner, and the installer's own closing instruction —
 * `wundervault-agent --migrate`, no sudo — could not open the door it had just locked.
 * Adding the owner to the group would have added all seven of their agents with them.
 *
 * There is no local permission that separates the owner from a process running as the
 * owner. So the lock moved off the directory entirely and onto the thing an agent cannot
 * obtain: a setup link, issued by the server to someone logged in to the website,
 * single-use and valid for fifteen minutes. The daemon redeems it itself.
 *
 * The directory is therefore traversable and the socket connectable, exactly like the
 * per-agent ones, and every action behind it carries its own proof — a setup link to
 * enrol, the agent's own token to remove. Nothing is protected by being hard to reach.
 */
export const mgmtDir = () =>
  splitAvailable() ? path.join(runtimeDir(), 'mgmt') : runtimeDir();
export const mgmtSocketPath = () => path.join(mgmtDir(), 'agent.sock');
export const agentSocketPath = (name: string) =>
  splitAvailable()
    ? path.join(runtimeDir(), `${safeName(name)}.sock`)
    : path.join(runtimeDir(), 'agents', `${safeName(name)}.sock`);

// ── agent-side paths ──────────────────────────────────────────────────────────

/** The agent's identity. 0600, owned by the agent's uid, checked by the daemon. */
export const agentTokenPath = (name: string) =>
  path.join(userRoot(), 'agents', `${safeName(name)}.token`);

/** Where `--destinations` writes its page: the user's own directory, not the daemon's. */
export const viewerPath = () => path.join(userRoot(), 'destinations.html');

// ── pre-split locations, for migration only ───────────────────────────────────

/**
 * Pre-split locations, for migration only.
 *
 * These resolve through `userRoot()`, NOT through `os.homedir()` directly, and that is not
 * a stylistic preference — it is a safety property, learned the hard way.
 *
 * `os.homedir()` on Linux reads the passwd entry rather than honouring a `$HOME` set at
 * runtime. A test that set `process.env.HOME` to a scratch directory and expected these
 * paths to follow got the REAL home instead, and since migration deletes the old store
 * after moving it, the test destroyed a live credential file. It was recoverable only
 * because a long-running daemon still held the profiles in memory.
 *
 * Routing through `userRoot()` means `WUNDERVAULT_USER_ROOT` redirects every one of these,
 * so a test can point the destructive path somewhere harmless and have that actually
 * work. Anything that deletes should be reachable by an override that a test can prove it
 * has set.
 */
const legacyRoot = () => userRoot();

export const legacy = {
  root: legacyRoot,
  profiles: () => path.join(legacyRoot(), 'agent-profiles.enc'),
  salt: () => path.join(legacyRoot(), 'agent-salt.bin'),
  networkStore: () => path.join(legacyRoot(), 'network.json'),
  mgmtSocket: () => path.join(legacyRoot(), 'agent.sock'),
  agentSocket: (name: string) =>
    path.join(legacyRoot(), 'agents', `${safeName(name)}.sock`),
};

/**
 * An agent name reaches this from configuration and from the network, and it is about to
 * become a path segment.
 *
 * `../../etc/cron.d/x` as an agent name would otherwise place a daemon-written file
 * wherever it liked, which for a process that exists to hold a privilege boundary is the
 * whole game. Restricting to a known-safe alphabet is the check; rejecting rather than
 * sanitising means a name that would have been mangled fails visibly instead of quietly
 * pointing at the wrong file.
 */
export function safeName(name: string): string {
  const n = String(name ?? '').trim();
  if (!n || n.length > 64 || !/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(n) || n.includes('..')) {
    throw new Error(
      `Invalid agent name ${JSON.stringify(name)}. Use letters, digits, spaces, dot, ` +
      `underscore or hyphen, up to 64 characters.`,
    );
  }
  return n;
}

/**
 * Create the daemon's directory, refusing to widen one that already exists.
 *
 * mkdir's mode argument is masked by umask and is ignored entirely when the directory is
 * already there — so a directory created 0755 by an earlier version, or by a careless
 * hand, would stay 0755 and the boundary would be open while every other check passed.
 * chmod unconditionally, then verify.
 */
export function ensureSystemRoot(root = systemRoot()): void {
  try {
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    fs.chmodSync(root, 0o700);
  } catch (err) {
    // The commonest first-run failure on a machine where the privileged step has not been
    // taken: the daemon is not the account that owns this directory, and cannot create it.
    // Raw EACCES on /var/lib/wundervault sends a person looking for a bug in the daemon
    // rather than telling them the one command that fixes it — and on macOS, where this
    // path is new in phase 7, an upgrade lands exactly here.
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EACCES' || code === 'EPERM') {
      const installer = process.platform === 'darwin'
        ? 'sudo sh packaging/install-daemon-macos.sh'
        : process.platform === 'win32'
          ? 'powershell -ExecutionPolicy Bypass -File packaging\\install-daemon-windows.ps1  (as Administrator)'
          : 'sudo sh packaging/install-daemon.sh';
      throw new Error(
        `Cannot use ${root}: permission denied.\n` +
        `  The secret broker needs its own account, and the privileged install step has\n` +
        `  not been run on this machine:\n` +
        `    ${installer}\n` +
        `  Then hand your existing agents over:  wundervault-agent --migrate`,
      );
    }
    throw err;
  }
  // The mode check is the BOUNDARY on Linux and macOS. It is NOT one on Windows, and this
  // guard is now load-bearing rather than cautious: measured on Windows 10, chmod(0o700)
  // followed by stat() returns 666, every time, for every directory. Leaving the check in
  // would refuse to start on a correctly installed Windows box. The Windows boundary is an
  // ACL and is checked in boundaryIsReal(), against icacls, which reports what is real.
  if (!splitAvailable() || platformShape() === 'windows') return;
  const mode = fs.statSync(root).mode & 0o777;
  if (mode !== 0o700) {
    throw new Error(
      `${root} is mode ${mode.toString(8)}, expected 700. The directory mode IS the ` +
      `boundary here — refusing to run with it open.`,
    );
  }
}

/**
 * Is daemon state reachable by whoever is asking?
 *
 * Used to give a person a straight answer instead of ENOENT. After the split a user
 * running `--destinations` genuinely cannot read the store, and "no such file" would send
 * them looking for a bug rather than telling them the boundary is working.
 */
export function canReadSystemRoot(root = systemRoot()): boolean {
  try { fs.accessSync(root, fs.constants.R_OK | fs.constants.X_OK); return true; }
  catch { return false; }
}

/** True when this process is the daemon owning the state, rather than a client of it. */
export function runningAsDaemonAccount(root = systemRoot()): boolean {
  try {
    const uid = (process as unknown as { getuid?: () => number }).getuid?.();
    return uid !== undefined && fs.statSync(root).uid === uid;
  } catch { return false; }
}

/**
 * Is there ACTUALLY a boundary here, right now?
 *
 * Every other function in this file answers a question about the operating system. This
 * one answers the question the user is actually asking, and it answers it by looking at
 * the directory rather than at `process.platform`.
 *
 * The distinction is not academic. Before this existed, the startup warning keyed off the
 * platform alone — so a daemon started by hand on Linux with WUNDERVAULT_SYSTEM_ROOT
 * pointed into the owner's home printed NOTHING, while running as the same uid as the
 * agents it served. The platform was Linux, and the platform was all the check consulted.
 * The same shape of mistake on macOS would be a broker that had never been installed
 * reporting a separation it did not have.
 *
 * Five things, all observed:
 *   - the state root exists and is a directory;
 *   - its mode is exactly 0700 — anything wider is not a boundary whatever owns it;
 *   - it is owned by OUR euid, so we are the daemon account rather than a visitor;
 *   - our euid is not 0, because root is not a boundary against anything, and is not the
 *     uid that invoked us under sudo, because that is the owner's own account;
 *   - the state root is NOT the pre-split location.
 *
 * That last one is not belt-and-braces, it is the check that makes the rest mean anything.
 * Pre-split, state lives in the owner's own `~/.wundervault`, which ensureSystemRoot()
 * chmods to 0700 — so it is a 0700 directory owned by the euid running the daemon, and the
 * first four tests all pass while the agent and the daemon are the same account. The
 * boundary is not "a private directory"; it is "a directory belonging to somebody the
 * agent is not". When the state root IS the agent's own directory, there is nobody else.
 */
export function expectedAccount(): string {
  const shape = platformShape();
  return process.env.WUNDERVAULT_SYSTEM_ACCOUNT
    || (shape === 'darwin' ? DARWIN_ACCOUNT : shape === 'windows' ? WINDOWS_ACCOUNT : SYSTEM_ACCOUNT);
}

/**
 * The allowed holders of the Windows state directory.
 *
 * The service account, because it is the daemon. SYSTEM and Administrators, because they
 * are outside every boundary on this operating system exactly as root is on Linux, and
 * pretending otherwise would be the false claim this file exists to prevent.
 * TrustedInstaller because Windows puts it on things and removing it fights the OS.
 *
 * `Users`, `Authenticated Users` and `Everyone` are the ones this is looking for. Any of
 * them means the agents can read the store, which is the whole boundary gone.
 */
/**
 * Well-known SIDs, because NAMES ARE LOCALISED AND SIDS ARE NOT.
 *
 * The first version of this read `icacls` output and compared the text against
 * "administrators" and "system". On a German or Japanese Windows those strings are
 * `Administratoren` and `SYSTEM`/`システム`, so the check would have failed closed on a
 * perfectly installed machine and reported no boundary — or, with a looser comparison,
 * failed OPEN. A security check that depends on the display language is not a check.
 */
const SID_SYSTEM = 'S-1-5-18';
const SID_ADMINISTRATORS = 'S-1-5-32-544';
const SID_TRUSTED_INSTALLER =
  'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
/** The ones this is actually looking for: anything that means "other people". */
const SID_USERS = 'S-1-5-32-545';
const SID_EVERYONE = 'S-1-1-0';
const SID_AUTHENTICATED_USERS = 'S-1-5-11';
const SID_INTERACTIVE = 'S-1-5-4';
const BROAD_SIDS = new Set([
  SID_USERS, SID_EVERYONE, SID_AUTHENTICATED_USERS, SID_INTERACTIVE,
]);

export interface AclEntry {
  allow: boolean;
  inherited: boolean;
  sid: string;
}

/**
 * Parse the ACL report the daemon asks PowerShell for.
 *
 * One entry per line, `Allow;False;S-1-5-32-544`. Generated rather than scraped: the
 * report is produced by translating each IdentityReference to a SecurityIdentifier, so
 * what arrives here is already language-independent.
 *
 * PURE. The thing that can silently return the wrong answer is the parsing, and the
 * parsing has to be testable on a machine that is not Windows — phase 7 learned that twice
 * and this file is where both lessons live.
 */
export interface AclReport {
  /** Is inheritance switched OFF on this directory? */
  protected: boolean;
  /** Who owns it, which is a party the DACL need not mention. */
  owner: string | null;
  entries: AclEntry[];
}

export function parseAclReport(report: string): AclReport {
  const out: AclEntry[] = [];
  let isProtected = false;
  let owner: string | null = null;

  for (const raw of report.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const parts = line.split(';');

    if (parts.length === 2 && /^PROTECTED$/i.test(parts[0].trim())) {
      isProtected = /^true$/i.test(parts[1].trim());
      continue;
    }
    if (parts.length === 2 && /^OWNER$/i.test(parts[0].trim())) {
      const v = parts[1].trim().toUpperCase();
      owner = /^S-1-[0-9-]+$/.test(v) ? v : null;
      continue;
    }

    if (parts.length < 3) continue;
    const sid = parts[2].trim().toUpperCase();
    if (!/^S-1-[0-9-]+$/.test(sid)) continue;
    out.push({
      allow: /^allow$/i.test(parts[0].trim()),
      inherited: /^true$/i.test(parts[1].trim()),
      sid,
    });
  }
  return { protected: isProtected, owner, entries: out };
}

/**
 * Is this directory closed to the other accounts on the machine?
 *
 * The weaker of the two questions, and the one `windowsStateRoot()` asks before it agrees
 * to store credentials somewhere. It does not care WHO owns the directory — only that
 * `Users`, `Everyone` and friends are not on it, and that nothing is inherited.
 *
 * Inheritance is fatal on its own: an inherited ACE means access is whatever the parent
 * says today and whatever it says tomorrow. `C:\ProgramData` grants Users the right to
 * create subdirectories, so a directory created there and left with inherited permissions
 * is readable by every account on the box.
 */
export function windowsAclIsRestricted(report: string, ourSid: string): boolean {
  // PRIVATE TO US, not merely "no broad groups on it", and the difference is an attack.
  //
  // The weaker rule accepted any inheritance-free directory with no Users/Everyone grant.
  // So a second local account could pre-create %ProgramData%\wundervault\state, remove
  // inheritance, and grant exactly two principals -- itself and you. Nothing broad is on
  // it, so the check passed, your daemon adopted the directory, and every credential it
  // stored was readable by the account that laid the trap.
  //
  // The uninstalled case is the only one this governs, so "us" is whoever is running.
  return windowsAclIsPrivate(report, ourSid);
}

/**
 * Is this directory private to the broker's own account?
 *
 * The strong question, and the one the startup report is allowed to answer `true` to.
 * Every ALLOW entry must name the service account, SYSTEM, Administrators or
 * TrustedInstaller. Deny entries are ignored: a deny only ever narrows.
 *
 * SYSTEM and Administrators are inside the wall, and saying so is the point rather than an
 * embarrassment — they are outside every boundary on this operating system exactly as root
 * is on Linux, and `/limitations` says the same thing about both.
 */
export function windowsAclIsPrivate(report: string, accountSid: string): boolean {
  const allowed = new Set([
    SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER, accountSid.toUpperCase(),
  ]);
  const parsed = parseAclReport(report);
  if (parsed.entries.length === 0) return false;

  // Inheritance must be switched OFF, not merely unused. See readAclReport.
  if (!parsed.protected) return false;

  // The owner is inside the wall whether the DACL says so or not.
  if (!parsed.owner || !allowed.has(parsed.owner)) return false;

  let sawAllow = false;
  for (const e of parsed.entries) {
    if (e.inherited) return false;
    if (!e.allow) continue;
    sawAllow = true;
    if (!allowed.has(e.sid)) return false;
  }
  return sawAllow;
}

/**
 * Ask Windows for the ACL, in SIDs.
 *
 * A PowerShell subprocess, once, at startup — and `-NonInteractive` and a timeout because
 * a daemon must not be able to hang on a shell.
 */
export function readAclReport(target: string): string | null {
  try {
    // THE PATH TRAVELS IN THE ENVIRONMENT, and that is not a style choice.
    //
    // The first version passed it as a trailing argv element and read it as `$args[0]`.
    // `powershell -Command` takes the REST OF THE LINE as the command, so the extra
    // argument was never bound: `$args[0]` was empty, Get-Acl threw, the catch returned
    // null, and every Windows daemon silently concluded it had no boundary and fell back
    // to the pre-split layout. It failed identically on a perfectly installed machine and
    // on one that had never run the installer, which is why it took running it to find.
    //
    // An environment variable also removes the quoting question entirely: nothing about
    // the path is parsed by PowerShell, so a directory name containing a quote or a
    // backtick is data rather than an injection site.
    return execFileSync('powershell', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
      "$ErrorActionPreference='Stop';$a = Get-Acl -LiteralPath $env:WV_ACL_TARGET;" +
      // WHETHER INHERITANCE IS SWITCHED OFF, which is NOT the same question as whether any
      // entry happens to be inherited today. A directory can have inheritance enabled and
      // show no inherited entries, simply because its parent has no inheritable ones yet --
      // and the day the parent gains one, it flows straight in. AreAccessRulesProtected is
      // the flag; the per-entry IsInherited is only its visible consequence.
      '"PROTECTED;$($a.AreAccessRulesProtected)";' +
      // AND THE OWNER, which on Windows is a party the DACL does not have to mention. An
      // owner always holds READ_CONTROL and WRITE_DAC implicitly, so an account that owns
      // this directory can grant itself access whenever it likes, and a DACL that excludes
      // it excludes it only until it decides otherwise. A boundary whose owner is the
      // agent's own account is not a boundary; it is a locked door with the key taped to it.
      "$o = try { $a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } " +
      "catch { 'UNKNOWN' }; " +
      '"OWNER;$o";' +
      "$a.Access | ForEach-Object { " +
      "$s = try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } " +
      "catch { $_.IdentityReference.Value }; " +
      '"$($_.AccessControlType);$($_.IsInherited);$s" }',
    ], {
      encoding: 'utf8', timeout: 20000, stdio: ['ignore', 'pipe', 'ignore'],
      env: { ...process.env, WV_ACL_TARGET: target },
    });
  } catch { return null; }
}

/**
 * The Windows half of boundaryIsReal(), separated because nothing it checks is a uid.
 *
 * There is no euid and no mode here — measured: chmod is a no-op and stat().uid is 0 for
 * every file on the volume. What IS real is the ACL (a non-administrator was denied read
 * and list on an ACL'd directory, observed on Windows 10 with two accounts), so the ACL is
 * what gets checked.
 */
function windowsBoundaryIsReal(root: string): boolean {
  // Same check as everywhere else, and the same reason: an owner who starts the daemon by
  // hand gets a directory they own, and it is not a boundary against the agents they also
  // run.
  try {
    if (os.userInfo().username.toLowerCase() !== expectedAccount().toLowerCase()) return false;
  } catch { return false; }

  // The pre-split location passes an ACL test trivially — it is the owner's own directory.
  try {
    if (fs.realpathSync(root) === fs.realpathSync(userRoot())) return false;
  } catch {
    if (path.resolve(root) === path.resolve(userRoot())) return false;
  }

  try { if (!fs.statSync(root).isDirectory()) return false; } catch { return false; }

  // Our own SID. principalId() returns it on Windows; if it fell back to a username there
  // is no SID to compare and we cannot vouch for the ACL.
  const sid = principalId();
  if (!/^S-1-[0-9-]+$/i.test(sid)) return false;

  const report = readAclReport(root);
  if (report === null) return false;   // cannot see the ACL, cannot promise it
  return windowsAclIsPrivate(report, sid);
}

export function boundaryIsReal(root = systemRoot()): boolean {
  if (platformShape() === 'windows') return windowsBoundaryIsReal(root);

  const geteuid = (process as unknown as { geteuid?: () => number }).geteuid;
  if (typeof geteuid !== 'function') return false; // no uids, no boundary.
  const euid = geteuid.call(process);
  if (euid === 0) return false;

  // WE MUST BE THE SERVICE ACCOUNT, BY NAME. This is the check that does the work, and
  // leaving it out was a hole big enough to drive the whole phase through: an owner who
  // starts the daemon by hand with WUNDERVAULT_SYSTEM_ROOT pointed at a scratch directory
  // gets a 0700 directory owned by their own uid, outside their ~/.wundervault — which
  // passes every test below it. The daemon would then report a boundary while running as
  // precisely the account its agents run as.
  //
  // SUDO_UID does not cover this; it is only set when someone used sudo. The account name
  // is the one signal that is present however the process was started.
  try {
    if (os.userInfo().username !== expectedAccount()) return false;
  } catch {
    return false; // Cannot identify ourselves: not a boundary we can vouch for.
  }

  // Running under `sudo` as the invoking user's own account is the one case that looks
  // right from the inside and is not: the agent runs as that uid too.
  const sudoUid = process.env.SUDO_UID ? Number(process.env.SUDO_UID) : NaN;
  if (Number.isInteger(sudoUid) && sudoUid === euid) return false;

  // The pre-split layout, which passes every other test here while being the exact thing
  // this function exists to deny. EQUALITY, not containment: pre-split, systemRoot()
  // literally returns userRoot(), so they are the same path and nothing weaker is needed.
  //
  // Containment was tried and is WRONG. The installer runs
  // `useradd --home-dir /var/lib/wundervault`, so inside the daemon os.homedir() is the
  // state directory and userRoot() is `<state dir>/.wundervault` — contained by the state
  // root on every correct install. A containment test therefore reports "no privilege
  // boundary" on precisely the configuration that has one.
  try {
    if (fs.realpathSync(root) === fs.realpathSync(userRoot())) return false;
  } catch {
    if (path.resolve(root) === path.resolve(userRoot())) return false;
  }

  try {
    const st = fs.statSync(root);
    if (!st.isDirectory()) return false;
    if ((st.mode & 0o777) !== 0o700) return false;
    return st.uid === euid;
  } catch {
    return false;
  }
}

/**
 * Does `child` live inside `parent`?
 *
 * Both sides are resolved before they are compared, because on macOS `/var` is a symlink
 * to `/private/var`. `/var/lib/wundervault` and `/private/var/lib/wundervault` are the
 * same directory, and a string prefix test says they are not — so a containment check
 * written the obvious way passes on Linux, fails on a Mac, and fails in the direction that
 * refuses legitimate paths rather than admitting illegitimate ones.
 *
 * Falls back to the unresolved path when a component does not exist yet: realpath throws
 * on a path that is about to be created, and refusing to answer would be worse than
 * answering about the lexical path.
 */
export function isInside(parent: string, child: string): boolean {
  // Resolving each side independently is NOT enough, and the asymmetry is the bug: on a
  // Mac an existing parent resolves to /private/var/... while a child that does not exist
  // yet falls back to its literal /var/... form, so a path genuinely inside the parent
  // reports false. Anything about to be created — every socket path — takes that branch.
  //
  // So: resolve the deepest ancestor that DOES exist, then re-append the rest.
  const resolve = (p: string): string => {
    const abs = path.resolve(p);
    let head = abs;
    const tail: string[] = [];
    for (;;) {
      try { return path.join(fs.realpathSync(head), ...tail); } catch { /* go up */ }
      const parentOfHead = path.dirname(head);
      if (parentOfHead === head) return abs;   // reached the root, nothing resolvable
      tail.unshift(path.basename(head));
      head = parentOfHead;
    }
  };
  const p = resolve(parent);
  const c = resolve(child);
  return c === p || c.startsWith(p.endsWith(path.sep) ? p : p + path.sep);
}
