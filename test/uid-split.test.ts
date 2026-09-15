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
  // Small penalties: the growth curve is what is under test, not the wall-clock wait.
  process.env.WUNDERVAULT_KNOCK_BASE_MS = '5';
  process.env.WUNDERVAULT_KNOCK_MAX_MS = '80';
  // NEVER the real unit. Without this, migration's stop step reached the developer's own
  // running daemon and disabled it — systemctl did precisely what it was told.
  process.env.WUNDERVAULT_OLD_UNIT = 'wundervault-test-not-a-real-unit.service';

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

/** Build a pre-split store on disk, encrypted the way the old daemon wrote it. */
function writeLegacyStore(home: string, profiles: any[]) {
  const root = path.join(home, '.wundervault');
  fs.mkdirSync(root, { recursive: true });
  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();
  const salt = crypto.randomBytes(32);
  fs.writeFileSync(path.join(root, 'agent-salt.bin'), salt);
  const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([c.update(JSON.stringify({ profiles }), 'utf8'), c.final()]);
  fs.writeFileSync(path.join(root, 'agent-profiles.enc'),
    Buffer.concat([iv, c.getAuthTag(), body]), { mode: 0o600 });
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
  delete process.env.WUNDERVAULT_KNOCK_BASE_MS;
  delete process.env.WUNDERVAULT_KNOCK_MAX_MS;
  delete process.env.WUNDERVAULT_OLD_UNIT;
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

  it('still serves the real agent while somebody else is guessing', async () => {
    // THE regression test for this phase. The first version of this code locked out the
    // agent NAME after ten bad tokens and checked that lockout before comparing the
    // token — so any local process could send ten wrong guesses and take the legitimate
    // agent off the air for a minute, over and over. Making the socket world-connectable
    // is what created that, and this phase is what made the socket world-connectable.
    //
    // The old test asserted the bug: it sent twelve bad tokens, then presented the CORRECT
    // one, and expected 'unauthorized'. It passed, and the denial-of-service passed with it.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');
    for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });

    const res = await speak(sock, { token: p.socket_token });
    expect(res.api_key).toBe(p.api_key);
  });

  it('makes the guesser wait, and the delay grows', async () => {
    // The cost has to land on the failing caller — that is the only party a unix socket
    // lets us charge, since it carries no address and Node exposes no SO_PEERCRED.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');

    const first = Date.now();
    await speak(sock, { token: 'aa'.repeat(32) });
    const firstMs = Date.now() - first;

    for (let i = 0; i < 8; i++) await speak(sock, { token: 'aa'.repeat(32) });

    const later = Date.now();
    await speak(sock, { token: 'aa'.repeat(32) });
    const laterMs = Date.now() - later;

    expect(laterMs).toBeGreaterThan(firstMs);
    expect(laterMs).toBeGreaterThanOrEqual(20);
  });

  it("does not make the real agent pay the guesser's penalty", async () => {
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');
    for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });

    const t = Date.now();
    const res = await speak(sock, { token: p.socket_token });
    expect(res.api_key).toBe(p.api_key);
    // Served promptly, not after the penalty the guesser earned.
    expect(Date.now() - t).toBeLessThan(200);
  });

  it('clears the penalty when the profile is re-registered', async () => {
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
  it('answers ping with liveness only, not a roster of what holds credentials', async () => {
    // ping used to return every agent name on the machine — a list of what is worth
    // attacking here, handed to anything that can reach the socket.
    const { d } = await freshDaemon({ profiles: [profile('A'), profile('B')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'ping' });
    expect(res.ok).toBe(true);
    expect(res.agents).toBeUndefined();
    expect(JSON.stringify(res)).not.toContain('wv_agent_');
  });

  it('gives the names only when they are asked for, and still no credentials', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A'), profile('B')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'known_agents' });
    expect(res.agents.sort()).toEqual(['A', 'B']);
    expect(JSON.stringify(res)).not.toContain('wv_agent_');
  });

  it('removes a profile only for a caller holding that agent\'s token', async () => {
    // The socket is connectable by anyone now, so an unauthenticated remove would let any
    // local user delete someone else's agents. This does NOT separate one agent from
    // another under the same uid — nothing can, and the spec says so — but it stops
    // everybody else.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'mgmt', 'agent.sock');

    const refused = await speak(sock, { action: 'remove_profile', agent_name: 'A' });
    expect(refused.error).toBe('unauthorized');
    expect(fs.existsSync(path.join(dir, 'run', 'A.sock'))).toBe(true);

    const ok = await speak(sock, { action: 'remove_profile', agent_name: 'A', token: p.socket_token });
    expect(ok.removed).toBe(true);
    expect(fs.existsSync(path.join(dir, 'run', 'A.sock'))).toBe(false);
  });

  it('does not serve the destination store, and says where to get it', async () => {
    // It was served here while the socket sat behind a locked directory. That lock is off,
    // because a mode that keeps agents out keeps the owner out too — same uid. Serving it
    // now would hand every agent the record of where all the others sent secrets.
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'destinations' });
    expect(res.shape).toBeUndefined();
    expect(res.error).toMatch(/sudo wundervault-agent --destinations/);
  });

  it('is reachable without group membership, because the link is the lock', async () => {
    // The 0770 directory this replaced could not be opened by the owner either, so the
    // installer's own closing instruction failed on a real install.
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const md = path.join(dir, 'run', 'mgmt');
    expect(fs.statSync(md).mode & 0o777).toBe(0o755);
    const res = await speak(path.join(md, 'agent.sock'), { action: 'ping' });
    expect(res.ok).toBe(true);
  });

  it('does not hang on a message with no newline', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const s = net.createConnection(path.join(dir, 'run', 'mgmt', 'agent.sock'));
    await new Promise((r) => s.on('connect', r));
    s.write('{"action":"ping"}');
    const closed = await new Promise<boolean>((resolve) => {
      const t = setTimeout(() => resolve(false), 15_000);
      s.on('close', () => { clearTimeout(t); resolve(true); });
    });
    s.destroy();
    expect(closed).toBe(true);
    // 20s ceiling: the daemon's own inactivity timeout on this socket is 10s, so the test
    // has to outlast it to observe the close rather than its own impatience.
  }, 20_000);
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


describe('a store it could not read is not an empty store', () => {
  it('refuses to save over ciphertext it failed to decrypt', async () => {
    // The failure that motivates this: decrypt throws, the daemon carries on with an
    // empty in-memory list, and the next enrolment writes a store containing only that
    // one profile — over the credentials of every other agent on the machine. A changed
    // /etc/machine-id or a recreated system account is enough to trigger it, and both are
    // recoverable until the moment the file is overwritten.
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const storePath = path.join(dir, 'state', 'agent-profiles.enc');
    const before = fs.readFileSync(storePath);

    fs.writeFileSync(storePath, Buffer.concat([before.subarray(0, 28), crypto.randomBytes(64)]));
    d.loadProfiles();
    expect(d.storeUnreadable).toBe(true);

    // Refused before anything is mutated, not merely before the write lands.
    expect(() => d.registerProfile(profile('B'))).toThrow(/Refusing to enrol/);
    expect(() => d.saveProfiles()).toThrow(/Refusing to write/);
    // The ciphertext is untouched, so the credentials are still recoverable.
    expect(fs.readFileSync(storePath).length).toBeGreaterThan(28);
    expect(fs.readFileSync(storePath).subarray(0, 28)).toEqual(before.subarray(0, 28));
  });

  it('says so on ping rather than looking healthy and empty', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const storePath = path.join(dir, 'state', 'agent-profiles.enc');
    fs.writeFileSync(storePath, crypto.randomBytes(120));
    d.loadProfiles();
    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'ping' });
    expect(res.store_unreadable).toBe(true);
  });
});



describe('a held connection must not exclude the real agent', () => {
  it('serves the valid token while many connections sit open', async () => {
    // The regression this exists for is mine: the first fix for the token-level lockout
    // added srv.maxConnections = 64, which moved the same denial of service down a layer.
    // Sixty-four connections held open — trivial, since the timeout was an INACTIVITY one
    // a single byte could reset — and the legitimate agent's connection was dropped by the
    // kernel before its token was read.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');

    const held: net.Socket[] = [];
    for (let i = 0; i < 80; i++) {
      const c = net.createConnection(sock);
      c.on('error', () => { /* the daemon may close it; that is fine */ });
      c.write('x');                    // no newline: never a complete message
      held.push(c);
    }
    await new Promise((r) => setTimeout(r, 150));

    const res = await speak(sock, { token: p.socket_token });
    for (const c of held) c.destroy();
    expect(res.api_key).toBe(p.api_key);
  });
});


describe('the installer refuses what the sandbox would hide', () => {
  const script = fs.readFileSync(path.join(ROOT, 'packaging', 'install-daemon.sh'), 'utf8');

  it('rejects an ExecStart under a home directory', () => {
    // ProtectHome=yes makes /home empty for the service, so a home-based ExecStart installs
    // cleanly and then fails at start with 203/EXEC. On the owner's own machine
    // `wundervault-agent` resolves to ~/.local/bin, so this is the default path, not an
    // edge case.
    expect(script).toMatch(/\/home\/\*\|\/root\/\*\|\/run\/user\/\*/);
    expect(script).toContain('readlink -f');
  });

  it('does not let set -e swallow the explanation', () => {
    // A bare `a && b && echo` list returns non-zero when the note does not apply, and
    // `set -e` would exit on it — printing "ERROR:" and nothing that says what to do.
    // The guard must be an `if ...; then` — a bare list is the bug. Matching on "not a
    // bare list" is what the first version of this test got wrong: the corrected `if` form
    // contains the same bracket text, so the negative regex matched it too and failed.
    expect(script).toMatch(/if \[ "\$CANDIDATE" = "\$REAL_EXEC" \] && \[ "\$EXEC" != "\$REAL_EXEC" \]; then/);
    expect(script).not.toMatch(/^\s*\[ "\$CANDIDATE" = "\$REAL_EXEC" \] && \[ [^\n]*\] && \\$/m);
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
      'LockPersonality=yes', 'ProtectProc=invisible',
      'LimitCORE=0', 'RuntimeDirectory=wundervault',
      'ReadWritePaths=/var/lib/wundervault',
    ]) {
      expect(unit).toContain(d);
    }
  });

  it('does NOT set MemoryDenyWriteExecute, which would stop the daemon booting', () => {
    // This was in the hardening list, so this very test file was asserting a directive that
    // made the service die at startup with SIGTRAP — V8 compiles at runtime and cannot run
    // without writable-executable memory. Nothing caught it because no test had ever
    // launched the unit. Asserting its ABSENCE is what stops it coming back.
    expect(unit).not.toMatch(/^MemoryDenyWriteExecute=yes$/m);
    expect(unit).toMatch(/MemoryDenyWriteExecute is NOT set/);
  });

  it('does not claim LimitCORE makes the process non-dumpable', () => {
    // The plan did. It prevents a core file; it does nothing about ptrace. What stops the
    // agent reading this process is the uid, and the file should say so rather than take
    // credit for it.
    const near = unit.slice(unit.indexOf('LimitCORE') - 500, unit.indexOf('LimitCORE') + 200);
    expect(near).toMatch(/does NOT make the process\s*\n?#?\s*non-dumpable/);
  });
});
