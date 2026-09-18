import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, chmodSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Phase 7: the macOS layout, exercised from Linux.
 *
 * The point of WUNDERVAULT_PLATFORM_SHAPE is that these paths are reachable in CI. Before
 * it existed, everything macOS-specific in this codebase was verifiable only by hand on
 * one machine, and the two things that were in that position — the port lock and the
 * derived store key — were both broken, one of them for every Mac in the world.
 */

let paths: typeof import('../src/paths.js');
const saved: Record<string, string | undefined> = {};

function setEnv(k: string, v: string | undefined) {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
}

beforeEach(async () => {
  paths = await import('../src/paths.js');
  setEnv('WUNDERVAULT_SYSTEM_ROOT', undefined);
  setEnv('WUNDERVAULT_RUNTIME_DIR', undefined);
  setEnv('RUNTIME_DIRECTORY', undefined);
  setEnv('WUNDERVAULT_PLATFORM_SHAPE', undefined);
});

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
});

describe('the shape override reaches the macOS layout', () => {
  it('puts daemon state and the runtime directory where macOS can have them', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'darwin');
    expect(paths.platformShape()).toBe('darwin');
    // One level down, so the directory ABOVE it can be traversable.
    expect(paths.systemRoot()).toBe('/var/lib/wundervault/state');
    // macOS has no /run and no RuntimeDirectory=. The sockets go in a SIBLING of the
    // state directory, never a child of it.
    expect(paths.runtimeDir()).toBe('/var/lib/wundervault/run');
    expect(paths.mgmtSocketPath()).toBe('/var/lib/wundervault/run/mgmt/agent.sock');
    expect(paths.agentSocketPath('Claude 0512')).toBe('/var/lib/wundervault/run/Claude 0512.sock');
  });

  it('never puts the sockets inside the 0700 state directory', () => {
    // THE bug this layout exists to avoid, and one that only a Mac would have shown.
    // 0700 denies search permission to everyone but the daemon account — so an agent,
    // which runs as the OWNER, cannot traverse into it to reach its own socket. Every
    // connection fails with EACCES on a machine where the install went perfectly.
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'darwin');
    const state = paths.systemRoot();
    for (const sock of [paths.mgmtSocketPath(), paths.agentSocketPath('Any Agent')]) {
      expect(paths.isInside(state, sock)).toBe(false);
    }
    // And the same property stated as the rule, not as three examples.
    expect(paths.isInside(state, paths.runtimeDir())).toBe(false);
  });

  it('does not consult /run on the darwin shape even when one exists', () => {
    // Asserted on the DECISION, not the result. On a box with no /run/wundervault the
    // darwin branch and the Linux fallback return the same string, so deleting the darwin
    // branch left an earlier version of this test green. Supplying linuxRunExists=true is
    // what separates them.
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'darwin');
    expect(paths.platformShape()).toBe('darwin');
    expect(paths.runtimeDirFor('darwin', '/var/lib/wundervault/state', true))
      .toBe('/var/lib/wundervault/run');
    // …and the Linux shape, given the same inputs, does the opposite.
    expect(paths.runtimeDirFor('linux', '/var/lib/wundervault', true))
      .toBe('/run/wundervault');
    expect(paths.runtimeDirFor('linux', '/var/lib/wundervault', false))
      .toBe('/var/lib/wundervault/run');
  });

  it('keeps the Linux layout under the linux shape', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'linux');
    expect(paths.platformShape()).toBe('linux');
    // Unchanged by phase 7: Linux keeps /var/lib/wundervault as the state root itself,
    // because systemd gives it /run/wundervault for the sockets.
    expect(paths.systemRoot()).toBe('/var/lib/wundervault');
    expect(paths.mgmtSocketPath()).toMatch(/\/mgmt\/agent\.sock$/);
  });

  it('rejects an unrecognised shape rather than quietly dropping the boundary', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'macos');
    expect(() => paths.platformShape()).toThrow(/not one of/);
  });

  it('keeps every macOS socket path inside the 104-byte sun_path limit', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'darwin');
    // safeName permits 64 characters, so that is the longest an agent socket can get.
    const longest = 'a'.repeat(64);
    expect(paths.agentSocketPath(longest).length).toBeLessThanOrEqual(103);
    expect(paths.mgmtSocketPath().length).toBeLessThanOrEqual(103);
  });
});

describe('the override cannot manufacture a boundary', () => {
  it('is false on a platform that cannot host the layout it was told to use', () => {
    // The shape relocates state. It does not conjure a layout the OS cannot host.
    //
    // These three read `win32` because that is what phase 8 changed and why. Windows CAN
    // now hold a boundary — its own, an ACL — so the blanket "win32 is never capable"
    // this replaced is no longer true. What is still true, and is what these assert, is
    // that the POSIX layouts put sockets at filesystem paths and `listen()` on a
    // filesystem path is EACCES on Windows. Told to use them, a Windows daemon binds
    // nothing, so there is nothing to claim.
    expect(paths.splitAvailableFor('win32', 'linux')).toBe(false);
    expect(paths.splitAvailableFor('win32', 'darwin')).toBe(false);
    expect(paths.splitAvailableFor('win32', 'none')).toBe(false);
  });

  it('is true only where the real platform can actually do it', () => {
    expect(paths.splitAvailableFor('linux', 'linux')).toBe(true);
    expect(paths.splitAvailableFor('darwin', 'darwin')).toBe(true);
    expect(paths.splitAvailableFor('win32', 'windows')).toBe(true);
    // A capable platform told to use the pre-split layout still has no boundary.
    expect(paths.splitAvailableFor('linux', 'none')).toBe(false);
    expect(paths.splitAvailableFor('darwin', 'none')).toBe(false);
    expect(paths.splitAvailableFor('win32', 'none')).toBe(false);
    // And a platform that has neither mechanism is false under every shape.
    expect(paths.splitAvailableFor('freebsd', 'linux')).toBe(false);
    expect(paths.splitAvailableFor('freebsd', 'windows')).toBe(false);
  });
});

describe('boundaryIsReal looks at the directory, not the operating system', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'wv-boundary-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('is true for a 0700 directory owned by the service account', () => {
    const root = path.join(dir, 'state');
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', os.userInfo().username);
    expect(paths.boundaryIsReal(root)).toBe(true);
  });

  it('is FALSE when we are not the service account, however right the directory looks', () => {
    // The hole this closes. An owner who starts the daemon by hand with
    // WUNDERVAULT_SYSTEM_ROOT pointed at a scratch directory gets a 0700 directory owned
    // by their own uid, outside their ~/.wundervault — which passes every other check
    // here. The daemon would report a boundary while running as exactly the account its
    // agents run as. SUDO_UID does not catch it: nobody used sudo.
    const root = path.join(dir, 'looks-right');
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', 'wundervault');   // and we are not that
    expect(os.userInfo().username).not.toBe('wundervault');
    expect(paths.boundaryIsReal(root)).toBe(false);
  });

  it('is false when the directory is wider than 0700', () => {
    const root = path.join(dir, 'open');
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', os.userInfo().username);
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o755);
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    expect(statSync(root).mode & 0o777).toBe(0o755);
    expect(paths.boundaryIsReal(root)).toBe(false);
  });

  it('is TRUE on a correctly installed Linux box, where the account home IS the state dir', () => {
    // The installer runs `useradd --home-dir /var/lib/wundervault`, so inside the daemon
    // os.homedir() IS the state directory and userRoot() resolves to a path UNDER it.
    // A containment test between the two therefore fires on every correct install and
    // reports "no privilege boundary" on the one configuration that has one. Caught by
    // working the real install through by hand, not by the suite — which is why it is
    // pinned here now.
    const root = path.join(dir, 'state');
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
    setEnv('WUNDERVAULT_USER_ROOT', path.join(root, '.wundervault'));
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', os.userInfo().username);
    expect(paths.boundaryIsReal(root)).toBe(true);
  });

  it('is false when the state root IS the pre-split location', () => {
    // The case that passes every other check while there is no boundary at all: the
    // daemon running as the owner, with its state in the owner's own directory at 0700.
    const root = path.join(dir, 'home');
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
    setEnv('WUNDERVAULT_USER_ROOT', root);
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', os.userInfo().username);
    expect(paths.boundaryIsReal(root)).toBe(false);
  });

  it('is false for a directory owned by somebody else', () => {
    // We are not that uid, so we are a visitor, not the daemon account.
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', os.userInfo().username);
    // Asserted unconditionally. The earlier version wrapped this in `if (notOurs)`, so on
    // a machine where the test ran as root it silently made no assertion at all — a test
    // that reports success for having checked nothing.
    expect(statSync('/').uid).not.toBe(process.geteuid!());
    expect(paths.boundaryIsReal('/')).toBe(false);
  });

  it('is false when the directory does not exist', () => {
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', os.userInfo().username);
    expect(paths.boundaryIsReal(path.join(dir, 'nope'))).toBe(false);
  });

  it('is false when running as the account that invoked sudo', () => {
    const root = path.join(dir, 'state2');
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', os.userInfo().username);
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    setEnv('SUDO_UID', String(process.geteuid!()));
    expect(paths.boundaryIsReal(root)).toBe(false);
  });
});

describe('/var and /private/var are the same directory on macOS', () => {
  it('compares resolved paths, not string prefixes', () => {
    // A lexical prefix test says /private/var/lib/wundervault is not inside
    // /var/lib/wundervault. On a Mac they are the same directory, and the check would
    // refuse the daemon's own state root.
    const real = mkdtempSync(path.join(os.tmpdir(), 'wv-real-'));
    const sub = path.join(real, 'inner');
    mkdirSync(sub);
    try {
      expect(paths.isInside(real, sub)).toBe(true);
      expect(paths.isInside(real, real)).toBe(true);
      expect(paths.isInside(sub, real)).toBe(false);
      // The trap a prefix test falls into: a sibling whose name starts with the parent's.
      const sibling = `${real}-elsewhere`;
      mkdirSync(sibling);
      try {
        expect(paths.isInside(real, sibling)).toBe(false);
      } finally {
        rmSync(sibling, { recursive: true, force: true });
      }
    } finally {
      rmSync(real, { recursive: true, force: true });
    }
  });
});

describe('a machine where the privileged step has not been run', () => {
  it('says which command fixes it instead of reporting a raw EACCES', () => {
    // The commonest first run on a Mac after this phase: /var/lib/wundervault belongs to
    // root, the daemon is not root, and mkdir fails. A stack trace sends a person looking
    // for a bug in the daemon rather than at the one command that fixes it.
    let msg = '';
    try {
      paths.ensureSystemRoot('/var/lib/wundervault-definitely-not-permitted');
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/permission denied/i);
    expect(msg).toMatch(/install-daemon/);
    expect(msg).toMatch(/--migrate/);
  });
});

describe('the socket directory stays reachable by the agents', () => {
  it('widens a 0700 runtime directory on start, and refuses one it cannot', async () => {
    // The LaunchDaemon sets Umask 0077 so the files this process writes are private. That
    // masks mkdir's 0755 straight down to 0700 — and the agents run as the OWNER, so a
    // 0700 socket directory means every agent gets EACCES connecting to its own socket on
    // a machine where nothing else is wrong. mkdir's mode is a request; chmod is the
    // instruction, and the daemon verifies the result rather than assuming it.
    const { mkdtempSync: mk, statSync: st, rmSync: rm, mkdirSync: md, chmodSync: cm } =
      await import('node:fs');
    const base = mk(path.join(os.tmpdir(), 'wv-rtmode-'));
    const saveEnv = { ...process.env };
    try {
      const run = path.join(base, 'run');
      md(run, { recursive: true });
      cm(run, 0o700);                       // exactly what umask 0077 leaves behind
      expect(st(run).mode & 0o777).toBe(0o700);

      setEnv('WUNDERVAULT_SYSTEM_ROOT', path.join(base, 'state'));
      setEnv('WUNDERVAULT_USER_ROOT', path.join(base, 'home', '.wundervault'));
      setEnv('WUNDERVAULT_RUNTIME_DIR', run);
      setEnv('WUNDERVAULT_AGENT_NO_AUTOSTART', '1');
      setEnv('WUNDERVAULT_OLD_UNIT', 'wundervault-test-not-a-real-unit.service');

      const { AgentDaemon } = await import('../src/agent.js');
      const d = new AgentDaemon();
      try {
        d.start();
        // The property that matters: the owner can traverse it.
        expect(st(run).mode & 0o011).toBe(0o011);
      } finally {
        d.shutdown();
      }
    } finally {
      for (const k of Object.keys(process.env)) {
        if (!(k in saveEnv)) delete process.env[k];
      }
      rm(base, { recursive: true, force: true });
    }
  });
});

describe('isInside resolves a child that does not exist yet', () => {
  it('handles the /var -> /private/var case for a path about to be created', async () => {
    // Every socket path takes this branch: the file is not there when we ask. Resolving
    // each side independently made the parent resolve through the symlink while the child
    // fell back to its literal form, so a path genuinely inside reported false — on macOS
    // only, where /var is a symlink to /private/var.
    //
    // Reproduced here with a symlink of our own, which is the same shape on any platform.
    const { mkdtempSync: mk, mkdirSync: md, symlinkSync: ln, rmSync: rm } =
      await import('node:fs');
    const base = mk(path.join(os.tmpdir(), 'wv-alias-'));
    try {
      const real = path.join(base, 'private', 'store');
      md(real, { recursive: true });
      const alias = path.join(base, 'store');
      ln(path.join(base, 'private', 'store'), alias);

      // The child does NOT exist — exactly the socket case.
      const unborn = path.join(alias, 'run', 'agent.sock');
      expect(paths.isInside(real, unborn)).toBe(true);
      expect(paths.isInside(alias, unborn)).toBe(true);

      // And it still says no to something genuinely outside.
      expect(paths.isInside(real, path.join(base, 'elsewhere', 'agent.sock'))).toBe(false);
    } finally {
      rm(base, { recursive: true, force: true });
    }
  });
});

describe('a refusal launchd cannot fix by restarting', () => {
  it('is marked so the daemon can exit cleanly and stay down', async () => {
    // launchd has no Restart=on-failure with a give-up count. A KeepAlive job that exits
    // non-zero comes back every ThrottleInterval for ever — so a daemon correctly
    // refusing to start would respawn every two seconds and append its reason to a log
    // inside a 0700 directory nobody is watching, until the disk filled.
    //
    // The plist says KeepAlive/SuccessfulExit=false; the daemon exits 0 for exactly these.
    // Both halves have to stay in step, so both are pinned.
    const { ConfigurationRefusal } = await import('../src/agent.js');
    const e = new ConfigurationRefusal('nope');
    expect((e as unknown as { configurationRefusal: boolean }).configurationRefusal).toBe(true);
    expect(e).toBeInstanceOf(Error);

    const { readFileSync: rf } = await import('node:fs');
    const plist = rf(path.join(__dirname, '..', 'packaging', 'com.wundervault.agent.plist'), 'utf8');
    // A bare <true/> KeepAlive would restart a clean exit too, which is the bug.
    expect(plist).toMatch(/<key>KeepAlive<\/key>\s*<dict>\s*<key>SuccessfulExit<\/key>\s*<false\/>/);
  });
});
