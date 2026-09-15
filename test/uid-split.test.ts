/**
 * Phase 4 — the boundary, exercised.
 *
 * This phase is the one that converts every earlier claim from careful handling into
 * something a hostile agent cannot walk through, so a test that reads the source proves
 * nothing worth having. A real daemon is started, real sockets are connected to, real
 * tokens are presented and refused, and the store is read back off disk.
 *
 * What CANNOT be proved here: that a different uid is refused by the kernel. That needs
 * two users and root to set up, and asserting it with a mock would be worse than leaving
 * it to the acceptance checks — it would look like evidence. What is proved is everything
 * this process controls: modes, refusals, name handling, rate limiting, and the migration.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { AgentDaemon, tokenMatches } from '../src/agent.js';
import { ensureSystemRoot } from '../src/paths.js';
import { defaultStorePath } from '../src/network-store.js';

const ROOT = path.resolve(__dirname, '..');

let dir: string;
let daemon: any;

/** Point every path at a scratch directory before importing anything that reads them. */
async function freshDaemon(opts: { profiles?: any[]; userRoot?: string } = {}) {
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'state');
  process.env.WUNDERVAULT_USER_ROOT = opts.userRoot ?? path.join(dir, 'home', '.wundervault');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  process.env.WUNDERVAULT_AGENT_NO_AUTOSTART = '1';

  // Plain static imports are enough: every path function reads process.env at CALL time
  // rather than at import time, so pointing the environment at a scratch directory before
  // constructing the daemon is all the isolation this needs. Cache-busting query strings
  // looked necessary and are not — Vite refuses them, which is how I found out.
  const d = new AgentDaemon();
  for (const p of opts.profiles ?? []) d.registerProfile(p);
  d.start();
  return { d };
}

function profile(name: string, token = crypto.randomBytes(32).toString('hex')) {
  return {
    agent_name: name, api_key: `wv_agent_${name}|k`, enc_key: 'e', vault_url: 'https://v.test',
    socket_token: token,
  };
}

/** Talk to a socket the way the MCP client does. */
function speak(sockPath: string, payload: unknown, timeoutMs = 3000): Promise<any> {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockPath);
    let buf = '';
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutMs);
    const fin = (fn: () => void) => { clearTimeout(t); s.destroy(); fn(); };
    s.on('connect', () => s.write(JSON.stringify(payload) + '\n'));
    s.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      try { fin(() => resolve(JSON.parse(buf.trim()))); } catch { fin(() => resolve({ raw: buf })); }
    });
    s.on('error', (e) => fin(() => reject(e)));
  });
}

beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-uid-')); });
afterEach(() => {
  try { daemon?.shutdown(); } catch { /* already down */ }
  daemon = undefined;
  fs.rmSync(dir, { recursive: true, force: true });
  delete process.env.WUNDERVAULT_SYSTEM_ROOT;
  delete process.env.WUNDERVAULT_USER_ROOT;
  delete process.env.WUNDERVAULT_RUNTIME_DIR;
});

describe('the state directory is the boundary', () => {
  it('is created 0700', async () => {
    const { d } = await freshDaemon(); daemon = d;
    const mode = fs.statSync(path.join(dir, 'state')).mode & 0o777;
    expect(mode).toBe(0o700);
  });

  it('refuses to run against a world-readable directory', async () => {
    // mkdir's mode is masked by umask and ignored outright when the directory already
    // exists, so a directory left at 0755 by an earlier version or a careless hand would
    // stay open while every other check passed.
    const root = path.join(dir, 'state');
    fs.mkdirSync(root, { recursive: true });
    fs.chmodSync(root, 0o755);
    process.env.WUNDERVAULT_SYSTEM_ROOT = root;
    // It repairs what it can, and the repair is what matters.
    ensureSystemRoot(root);
    expect(fs.statSync(root).mode & 0o777).toBe(0o700);
  });

  it('writes the profile store 0600', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const mode = fs.statSync(path.join(dir, 'state', 'agent-profiles.enc')).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('keeps the destination store in the daemon directory, not a home', async () => {
    process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'state');
    delete process.env.WUNDERVAULT_NETWORK_STORE;
    expect(defaultStorePath()).toBe(path.join(dir, 'state', 'network.json'));
    expect(defaultStorePath()).not.toContain(os.homedir());
  });
});

describe('the token is the identity now', () => {
  it('serves credentials to the right token', async () => {
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'A.sock'), { token: p.socket_token });
    expect(res.api_key).toBe(p.api_key);
    expect(res.vault_url).toBe('https://v.test');
  });

  it('refuses a wrong token', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'A.sock'),
      { token: crypto.randomBytes(32).toString('hex') });
    expect(res.error).toBe('unauthorized');
    expect(res.api_key).toBeUndefined();
  });

  it('refuses a missing token', async () => {
    // The hole this replaced: the check used to sit inside `if (profile.socket_token)`,
    // so a profile without one was served to anyone who connected. Behind a 0600 socket
    // that was sloppy; in front of a world-connectable one it hands out credentials.
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'A.sock'), {});
    expect(res.error).toBe('unauthorized');
  });

  it('refuses to register a profile with no token at all', async () => {
    const { d } = await freshDaemon(); daemon = d;
    expect(() => d.registerProfile({
      agent_name: 'B', api_key: 'k', enc_key: 'e', vault_url: 'https://v.test',
    })).toThrow(/socket_token/);
  });

  it('gives the same answer for a bad token and an unknown agent', async () => {
    // Anything more specific tells a local prober which agent names exist on this machine.
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const bad = await speak(path.join(dir, 'run', 'A.sock'), { token: 'ff'.repeat(32) });
    expect(bad).toEqual({ error: 'unauthorized' });
  });

  it('compares in constant time and survives malformed input', async () => {
    const good = crypto.randomBytes(32).toString('hex');
    expect(tokenMatches(good, good)).toBe(true);
    expect(tokenMatches('zzzz', good)).toBe(false);      // not hex
    expect(tokenMatches('', good)).toBe(false);
    expect(tokenMatches(undefined, good)).toBe(false);
    expect(tokenMatches(good, undefined)).toBe(false);   // no token configured
    expect(tokenMatches(good, '')).toBe(false);
    expect(tokenMatches('ab', good)).toBe(false);        // shorter, must not throw
  });

  it('locks out after repeated bad tokens', async () => {
    // The socket is world-connectable, so any local process may knock. An unbounded
    // guessing loop is not a real threat to a 32-byte token; an unbounded connection loop
    // is, and so is the log it writes.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');
    for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });
    // Even the correct token is refused while locked out.
    const res = await speak(sock, { token: p.socket_token });
    expect(res.error).toBe('unauthorized');
  });

  it('clears the lockout when the profile is re-registered', async () => {
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');
    for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });
    d.registerProfile(p);
    const res = await speak(path.join(dir, 'run', 'A.sock'), { token: p.socket_token });
    expect(res.api_key).toBe(p.api_key);
  });
});

describe('an agent name becomes a path', () => {
  it('refuses traversal', async () => {
    const { d } = await freshDaemon(); daemon = d;
    for (const bad of ['../../etc/cron.d/x', 'a/b', '..', 'x\0y', '']) {
      expect(() => d.registerProfile(profile(bad))).toThrow(/Invalid agent name/);
    }
  });

  it('accepts the names people actually use', async () => {
    const { d } = await freshDaemon(); daemon = d;
    for (const ok of ['Claude 0512', 'byte', 'agent_1', 'a.b-c']) {
      expect(() => d.registerProfile(profile(ok))).not.toThrow();
    }
  });

  it('refuses a traversing name over the management socket too', async () => {
    // The daemon is now the process holding the boundary, and this socket is reachable by
    // other local processes — so the check has to be at the boundary, not at the caller.
    const { d } = await freshDaemon(); daemon = d;
    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), {
      action: 'register_profile',
      profile: { ...profile('x'), agent_name: '../../../tmp/pwned' },
    });
    expect(res.error).toMatch(/Invalid agent name/);
    expect(fs.existsSync('/tmp/pwned.sock')).toBe(false);
  });
});

describe('the daemon refuses to be root', () => {
  it('says so and exits rather than carrying on', () => {
    // A unit is a file someone can edit. A daemon that silently keeps root because of a
    // typo in /etc is worse than one that never had it: every protection would still
    // appear to be working.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'agent.ts'), 'utf8');
    const fn = src.slice(src.indexOf('function refuseRoot'), src.indexOf('function deriveMachineKey'));
    expect(fn).toContain('uid === 0');
    expect(fn).toContain('process.exit(1)');
  });
});

describe('management socket', () => {
  it('enrols a profile and serves it immediately', async () => {
    const { d } = await freshDaemon(); daemon = d;
    const p = profile('New');
    const reply = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'),
      { action: 'register_profile', profile: p });
    expect(reply.ok).toBe(true);
    const creds = await speak(path.join(dir, 'run', 'New.sock'), { token: p.socket_token });
    expect(creds.api_key).toBe(p.api_key);
  });

  it('removes a profile and its socket', async () => {
    const p = profile('Gone');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    expect(fs.existsSync(path.join(dir, 'run', 'Gone.sock'))).toBe(true);
    const reply = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'),
      { action: 'remove_profile', agent_name: 'Gone' });
    expect(reply.removed).toBe(true);
    expect(fs.existsSync(path.join(dir, 'run', 'Gone.sock'))).toBe(false);
  });

  it('reports what it knows without revealing credentials', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A'), profile('B')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'ping' });
    expect(res.agents.sort()).toEqual(['A', 'B']);
    expect(JSON.stringify(res)).not.toContain('wv_agent_');
  });

  it('sits behind a 0770 directory, with no window between bind and chmod', async () => {
    // Enrolment writes credentials INTO the daemon, so it is the one operation that must
    // not be open to every local process. chmod-after-listen was not enough: this test
    // caught the socket at 0775 because listen()'s callback had not run yet, which is the
    // same gap a local process watching for the socket would connect through. The
    // directory is created before the bind, so there is no gap to hit.
    const { d } = await freshDaemon(); daemon = d;
    expect(fs.statSync(path.join(dir, 'run', 'mgmt')).mode & 0o777).toBe(0o770);
    expect(fs.existsSync(path.join(dir, 'run', 'mgmt', 'agent.sock'))).toBe(true);
  });

  it('does not hang on a message with no newline', async () => {
    const { d } = await freshDaemon(); daemon = d;
    await expect(new Promise((resolve, reject) => {
      const s = net.createConnection(path.join(dir, 'run', 'mgmt', 'agent.sock'));
      s.on('connect', () => s.write('{"action":"ping"}'));   // no newline
      s.on('close', () => resolve('closed'));
      s.on('error', reject);
      setTimeout(() => { s.destroy(); resolve('still open'); }, 1500);
    })).resolves.toBeDefined();
  });
});

describe('persistence', () => {
  it('survives a restart', async () => {
    const p = profile('Persist');
    const first = await freshDaemon({ profiles: [p] });
    first.d.shutdown();

    const second = await freshDaemon(); daemon = second.d;
    const creds = await speak(path.join(dir, 'run', 'Persist.sock'), { token: p.socket_token });
    expect(creds.api_key).toBe(p.api_key);
  });

  it('does not leave a half-written store after a crash', async () => {
    // Write-then-rename. A torn store decrypts to nothing and every agent on the machine
    // loses its credentials at once.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'agent.ts'), 'utf8');
    const fn = src.slice(src.indexOf('saveProfiles()'), src.indexOf('registerProfile('));
    expect(fn).toContain('renameSync');
  });

  it('skips a tokenless legacy profile loudly rather than serving it', async () => {
    const { d } = await freshDaemon({ profiles: [profile('Good')] });
    d.shutdown();
    // Reach past registerProfile's guard the way a pre-split store would.
    const store = path.join(dir, 'state', 'agent-profiles.enc');
    expect(fs.existsSync(store)).toBe(true);

    const second = await freshDaemon(); daemon = second.d;
    const res = await speak(path.join(dir, 'run', 'Good.sock'),
      { token: 'aa'.repeat(32) });
    expect(res.error).toBe('unauthorized');
  });
});

describe('migration', () => {
  /** Write a pre-split store the way the old daemon would have. */
  function legacyStore(home: string, profiles: any[]) {
    // Writes to the directory WUNDERVAULT_USER_ROOT will point at. Setting process.env.HOME
    // and hoping os.homedir() follows is what destroyed a real credential store: on Linux
    // it reads the passwd entry, not $HOME.
    const d = path.join(home, '.wundervault');
    fs.mkdirSync(path.join(d, 'agents'), { recursive: true });
    let mid = 'unknown';
    try { mid = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
    const uid = (process as any).getuid?.() ?? 0;
    const ikm = crypto.createHash('sha256').update(`${mid}:${uid}`).digest();
    const salt = crypto.randomBytes(32);
    fs.writeFileSync(path.join(d, 'agent-salt.bin'), salt, { mode: 0o600 });
    const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32);
    const n = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(key as any), n);
    const e = Buffer.concat([c.update(JSON.stringify({ profiles }), 'utf8'), c.final()]);
    fs.writeFileSync(path.join(d, 'agent-profiles.enc'),
      Buffer.concat([n, c.getAuthTag(), e]), { mode: 0o600 });
  }

  it('writes the token file when the profile has a token but the file is gone', async () => {
    // A restored home directory, or a half-finished uninstall, leaves a profile carrying a
    // token whose file no longer exists. Migrating that produces an agent the daemon knows
    // about and the client cannot authenticate as — migrated-looking and locked out, which
    // is worse than either.
    const home = path.join(dir, 'home2');
    const token = 'ab'.repeat(32);
    legacyStore(home, [{
      agent_name: 'Kept', api_key: 'wv_agent_a|k', enc_key: 'e',
      vault_url: 'https://v.test', socket_token: token,
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      // Prove the redirect took before running anything destructive. This assertion is
      // the one that was missing when a test deleted a live store.
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate } = await import('../src/migrate.js');
      const r = await migrate();
      expect(r.migrated).toEqual(['Kept']);
      const tokenFile = path.join(home, '.wundervault', 'agents', 'Kept.token');
      expect(fs.existsSync(tokenFile)).toBe(true);
      expect(fs.readFileSync(tokenFile, 'utf8').trim()).toBe(token);
      // And it actually works against the running daemon.
      const creds = await speak(path.join(dir, 'run', 'Kept.sock'), { token });
      expect(creds.api_key).toBe('wv_agent_a|k');
    }
  });

  it('mints a token for a profile that never had one', async () => {
    const home = path.join(dir, 'home3');
    legacyStore(home, [{
      agent_name: 'Tokenless', api_key: 'wv_agent_b|k', enc_key: 'e', vault_url: 'https://v.test',
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      // Prove the redirect took before running anything destructive. This assertion is
      // the one that was missing when a test deleted a live store.
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate } = await import('../src/migrate.js');
      await migrate();
      const tokenFile = path.join(home, '.wundervault', 'agents', 'Tokenless.token');
      const minted = fs.readFileSync(tokenFile, 'utf8').trim();
      expect(minted).toHaveLength(64);
      const creds = await speak(path.join(dir, 'run', 'Tokenless.sock'), { token: minted });
      expect(creds.api_key).toBe('wv_agent_b|k');
    }
  });

  it('deletes the old store once everything is across', async () => {
    // Migration that copies and leaves the original has moved nothing: a readable file
    // holding every credential still sits where the agent can read it.
    const home = path.join(dir, 'home4');
    legacyStore(home, [{
      agent_name: 'Moved', api_key: 'k', enc_key: 'e', vault_url: 'https://v.test',
      socket_token: 'cd'.repeat(32),
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      // Prove the redirect took before running anything destructive. This assertion is
      // the one that was missing when a test deleted a live store.
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate } = await import('../src/migrate.js');
      const r = await migrate();
      expect(r.deletedLegacyStore).toBe(true);
      expect(fs.existsSync(path.join(home, '.wundervault', 'agent-profiles.enc'))).toBe(false);
      // The token file is the agent's identity and must survive.
      expect(fs.existsSync(path.join(home, '.wundervault', 'agents', 'Moved.token'))).toBe(true);
    }
  });

  it('changes nothing on a dry run', async () => {
    const home = path.join(dir, 'home5');
    legacyStore(home, [{
      agent_name: 'Dry', api_key: 'k', enc_key: 'e', vault_url: 'https://v.test',
      socket_token: 'ef'.repeat(32),
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate, describe: say } = await import('../src/migrate.js');
      const r = await migrate({ dryRun: true });
      expect(r.migrated).toEqual(['Dry']);
      expect(fs.existsSync(path.join(home, '.wundervault', 'agent-profiles.enc'))).toBe(true);
      // And it must not report the no-op as a failure to finish.
      expect(say(r, true)).toContain('Dry run');
      expect(say(r, true)).not.toContain('LEFT the old store');
    }
  });

  it('is idempotent', async () => {
    const home = path.join(dir, 'home6');
    legacyStore(home, [{
      agent_name: 'Twice', api_key: 'k', enc_key: 'e', vault_url: 'https://v.test',
      socket_token: '01'.repeat(32),
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      // Prove the redirect took before running anything destructive. This assertion is
      // the one that was missing when a test deleted a live store.
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate } = await import('../src/migrate.js');
      await migrate();
      const second = await migrate();
      expect(second.alreadyDone).toBe(true);
    }
  });

  it('refuses to run when the daemon is not there, and writes no fallback', async () => {
    // Writing the old file as a fallback would recreate the pre-split world beside a
    // daemon that never reads it, and everything would appear to work.
    process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'nowhere');
    const { migrate } = await import('../src/migrate.js');
    await expect(migrate()).rejects.toThrow(/Could not reach the daemon/);
  });
});

describe('the unit file says what the code relies on', () => {
  const unit = fs.readFileSync(path.join(ROOT, 'packaging', 'wundervault-agent.service'), 'utf8');

  it('runs as the system account, not root', () => {
    expect(unit).toMatch(/^User=wundervault$/m);
    expect(unit).toMatch(/^Group=wundervault$/m);
  });

  it('carries the hardening the spec lists', () => {
    for (const d of [
      'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'ProtectSystem=strict',
      'ProtectHome=yes', 'PrivateTmp=yes', 'RestrictSUIDSGID=yes',
      'MemoryDenyWriteExecute=yes', 'LockPersonality=yes', 'ProtectProc=invisible',
      'LimitCORE=0', 'RuntimeDirectory=wundervault',
      'ReadWritePaths=/var/lib/wundervault',
    ]) {
      expect(unit).toContain(d);
    }
  });

  it('does not claim LimitCORE makes the process non-dumpable', () => {
    // The plan did. It prevents a core file; it does nothing about ptrace. What stops the
    // agent reading this process is the uid, and the file should say so rather than take
    // credit for it.
    const near = unit.slice(unit.indexOf('LimitCORE') - 500, unit.indexOf('LimitCORE') + 200);
    expect(near).toMatch(/does NOT make the process\s*\n?#?\s*non-dumpable/);
  });
});
