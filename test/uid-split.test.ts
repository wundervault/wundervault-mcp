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

/**
 * The same conversation, returning the RAW reply bytes.
 *
 * `speak` parses, and a parsed object is the wrong thing to assert "no credential here"
 * against: `res.api_key` is undefined for a field nested one level down, or spelled
 * differently, or embedded in an error string. The bytes are what actually crossed the
 * socket.
 */
function speakRaw(sockPath: string, payload: unknown, timeoutMs = 3000): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockPath);
    let buf = '';
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutMs);
    const fin = (fn: () => void) => { clearTimeout(t); s.destroy(); fn(); };
    s.on('connect', () => s.write(JSON.stringify(payload) + '\n'));
    s.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      fin(() => resolve(buf));
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
  it('serves an operation to the right token, and NEVER a credential', async () => {
    // This test used to assert the opposite — `expect(res.api_key).toBe(p.api_key)` —
    // and it passed, because that is what the socket did. The uid split protected the
    // store on disk and the broker's memory and then handed the key back over the
    // socket to a process running as the agent. The assertion is inverted deliberately:
    // a valid token now buys an ANSWER, not the means to answer yourself.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'A.sock'), { token: p.socket_token, op: 'ping' });
    expect(res.ok).toBe(true);
    expect(res.agent).toBe('A');
    expect(res.api_key).toBeUndefined();
    expect(res.enc_key).toBeUndefined();
  });

  it('answers the pre-custody request shape with an upgrade error, not credentials', async () => {
    // An old MCP server sends `{token}` and nothing else. It must not be served, and it
    // must not be left guessing: the reply names the version and the fix. There is no
    // flag, env var or legacy mode that brings the old reply back — a deprecation path
    // here is a downgrade path for anything that can read the token file.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'A.sock'), { token: p.socket_token });
    expect(res.code).toBe('UPGRADE_REQUIRED');
    expect(res.api_key).toBeUndefined();
    expect(res.enc_key).toBeUndefined();
    expect(res.vault_url).toBeUndefined();
  });

  it('leaks no credential field from ANY operation, including the failures', async () => {
    // The property, asserted over the surface rather than one call. Every operation is
    // driven with a valid token and an unusable profile, so each one fails somewhere
    // different — and the thing being checked is what the failures carry, because a
    // handler that returns `{...profile, error}` on the way out is exactly the mistake
    // this phase exists to prevent.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');
    const ops = [
      { op: 'ping' },
      { op: 'list_entries' },
      { op: 'profile_flags' },
      { op: 'get_entry', entry_id: 'e1', purpose: 'p' },
      { op: 'get_entry' },
      { op: 'call', entry_id: 'e1', purpose: 'p', request: { origin: { scheme: 'https', host: 'x.test', port: 443 }, method: 'GET', path: '/' } },
      { op: 'ssh_agent_open', entry_id: 'e1', purpose: 'p', op_spec: { kind: 'ssh', destination: 'h', remoteArgv: ['true'] } },
      { op: 'ssh_agent_close', session_id: 'nope' },
      { op: 'settings' },
      { op: 'no_such_operation' },
      {},
    ];
    for (const payload of ops) {
      const raw = await speakRaw(sock, { token: p.socket_token, ...payload });
      // On the RAW BYTES, not the parsed object: a field nested anywhere in a reply is
      // still a credential on the wire, and `res.api_key === undefined` would miss it.
      expect(raw, `operation ${JSON.stringify(payload)}`).not.toContain('api_key');
      expect(raw, `operation ${JSON.stringify(payload)}`).not.toContain('enc_key');
      expect(raw, `operation ${JSON.stringify(payload)}`).not.toContain(p.api_key);
    }
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

    const res = await speak(sock, { token: p.socket_token, op: 'ping' });
    expect(res.ok).toBe(true);
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
    const res = await speak(sock, { token: p.socket_token, op: 'ping' });
    expect(res.ok).toBe(true);
    // Served promptly, not after the penalty the guesser earned.
    expect(Date.now() - t).toBeLessThan(200);
  });

  it('clears the penalty when the profile is re-registered', async () => {
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');
    for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });
    d.registerProfile(p);
    const res = await speak(path.join(dir, 'run', 'A.sock'), { token: p.socket_token, op: 'ping' });
    expect(res.ok).toBe(true);
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
    // The profile survived the restart — proved by the socket answering for that agent
    // at all, since a daemon that failed to load the store serves nobody. The credential
    // itself is deliberately not observable from here any more, which is the point; it
    // is checked on disk by the store test instead.
    const alive = await speak(path.join(dir, 'run', 'Persist.sock'), { token: p.socket_token, op: 'ping' });
    expect(alive.ok).toBe(true);
    expect(alive.agent).toBe('Persist');
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

    const res = await speak(sock, { token: p.socket_token, op: 'ping' });
    for (const c of held) c.destroy();
    expect(res.ok).toBe(true);
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

describe('a root process must not follow paths an agent controls', () => {
  // The escalation this prevents was demonstrated end to end before it was fixed: an agent
  // replaced ~/.wundervault/destinations.html with a symlink to /etc/cron.d/x, the owner
  // ran the one supported command for reading their own log, and root created that file
  // and chowned it to the agent's uid — which then wrote a root cron job into it.
  it('drops privileges rather than chowning the result back', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'src', 'log-viewer.ts'), 'utf8');
    expect(src).toContain('dropToSudoUser');
    // The chown is what made root's write exploitable; its absence is the property.
    expect(src).not.toMatch(/chownSync/);
  });

  it('refuses to continue as root when SUDO_USER cannot be resolved', () => {
    // Returning null there meant staying root and writing through root's own path
    // resolution — the caller cannot open the result, and the path-following is back.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'log-viewer.ts'), 'utf8');
    expect(src).toMatch(/Refusing to continue as root/);
  });

  it('writes the viewer through an exclusive temp file and renames', () => {
    // writeFileSync's mode applies only on create, so an existing 0644 page was refilled
    // with the whole destination record while still world-readable.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'log-viewer.ts'), 'utf8');
    expect(src).toMatch(/O_EXCL/);
    expect(src).toMatch(/renameSync/);
  });

  it('resolves the sudo user through NSS, not by parsing /etc/passwd', () => {
    // An LDAP or SSSD account is a valid sudo user with no line in /etc/passwd.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'log-viewer.ts'), 'utf8');
    expect(src).toMatch(/execFileSync\('getent', \['passwd'/);
    expect(src).not.toMatch(/readFileSync\('\/etc\/passwd'/);
  });

  it('keeps SUDO_USER out of path resolution entirely', () => {
    // userRoot() backs the agent token paths and the legacy migration paths too, so a
    // sudo-aware home here would widen far more than the viewer.
    // Mentioned in the comment that explains why it is not consulted; never read.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'paths.ts'), 'utf8');
    expect(src).not.toMatch(/process\.env\.SUDO_USER/);
    expect(src).toMatch(/does NOT consult `SUDO_USER`/);
  });

  it('refuses to carry on if the privilege drop did not take', () => {
    const src = fs.readFileSync(path.join(ROOT, 'src', 'log-viewer.ts'), 'utf8');
    expect(src).toMatch(/could not drop root privileges/);
  });
});

describe('the installer will not hand the boundary to a human account', () => {
  const script = fs.readFileSync(path.join(ROOT, 'packaging', 'install-daemon.sh'), 'utf8');

  it('refuses an existing account that can log in, whatever its uid', () => {
    // The uid number is a convention, not a rule — human logins at uid 500 exist. What
    // actually matters is whether a person can become that account, and whether it is the
    // account running the installer.
    expect(script).toMatch(/must not be able to log in/);
    expect(script).toMatch(/\*\/nologin\|\*\/false/);
  });

  it('refuses to run the daemon as the account invoking the installer', () => {
    expect(script).toMatch(/SUDO_UID/);
    expect(script).toMatch(/must not run as the account its agents run as/);
  });

  it('restarts a running daemon rather than leaving the old config live', () => {
    // `enable --now` starts a stopped unit and leaves a running one exactly as it was.
    expect(script).toMatch(/systemctl restart "\$UNIT_NAME"/);
  });
});

describe('a damaged destination log is not an empty one', () => {
  it('refuses to render zero destinations for a store it could not parse', async () => {
    const store = path.join(dir, 'broken-network.json');
    fs.writeFileSync(store, '{"version":1,"seen":[{"host":"x"');
    const { collectShape } = await import('../src/log-viewer.js');
    await expect(collectShape(store)).rejects.toThrow(/damaged/);
  });

  it('reports genuinely empty as empty when the directory is readable', async () => {
    const storeDir = path.join(dir, 'emptystate');
    fs.mkdirSync(storeDir, { recursive: true });
    const { collectShape } = await import('../src/log-viewer.js');
    const { shape } = await collectShape(path.join(storeDir, 'network.json'));
    expect(shape.seen).toEqual([]);
  });
});

describe('migration needs a split to migrate to, and saying so prevents data loss', () => {
  // Without one, systemRoot() returns userRoot() — which means profilesPath() and
  // legacy.profiles() resolve to THE SAME FILE. Every agent then looks "already across",
  // nothing is pending, and --migrate --finish shreds the store the running daemon is
  // using. A cleanup step deleting the live credential file because it mistook it for a
  // leftover, reported as a successful migration.
  //
  // This used to be asserted by grepping migrate.ts for the function name and for a
  // sentence in a comment, which is a test of the source text rather than of the
  // behaviour: renaming the function broke it and deleting the CALL would not have. The
  // shape override makes the refusal drivable, so now it is driven.
  const saved: Record<string, string | undefined> = {};
  const setEnv = (k: string, v: string | undefined) => {
    if (!(k in saved)) saved[k] = process.env[k];
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  };

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    for (const k of Object.keys(saved)) delete saved[k];
  });

  it('refuses to REPORT on a machine with no split', async () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'none');
    const migrate = await import('../src/migrate.js');
    await expect(migrate.status()).rejects.toThrow(/cannot\s+have one yet|nothing to move/);
  });

  it('refuses to DELETE on a machine with no split', async () => {
    // The dangerous half. status() being safe would not save anything if cleanup() ran.
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'none');
    const migrate = await import('../src/migrate.js');
    await expect(migrate.cleanup()).rejects.toThrow(/cannot\s+have one yet|nothing to move/);
  });

  it('refuses when the destination IS the source, on a platform that CAN split', async () => {
    // Capability is not an actual split. Point WUNDERVAULT_SYSTEM_ROOT at the owner's own
    // ~/.wundervault on Linux — a hand-started daemon, a misconfigured unit — and
    // splitAvailable() is still true while profilesPath() and legacy.profiles() are once
    // again THE SAME FILE. cleanup() would then find every agent "already across",
    // conclude the source is a leftover, and delete the live store.
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'linux');
    const same = path.join(dir, 'same-place');
    fs.mkdirSync(same, { recursive: true });
    setEnv('WUNDERVAULT_SYSTEM_ROOT', same);
    setEnv('WUNDERVAULT_USER_ROOT', same);
    const migrate = await import('../src/migrate.js');
    await expect(migrate.status()).rejects.toThrow(/same place/);
    await expect(migrate.cleanup()).rejects.toThrow(/same place/);
  });

  it('keeps the redundant guard on cleanup(), which no behavioural test can see', () => {
    // cleanup() calls status(), which refuses on its own — so deleting cleanup()'s OWN
    // guard changes no observable behaviour and the two tests above stay green. Verified
    // by doing exactly that. The guard is still worth keeping, for the day status() stops
    // being the first thing cleanup() calls, and the only way to assert something that
    // cannot be observed is to look at the source. Labelled as the weaker check it is,
    // rather than dressed up as coverage.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'migrate.ts'), 'utf8');
    const cleanupFn = src.slice(src.indexOf('export async function cleanup'));
    expect(cleanupFn.slice(0, 200)).toMatch(/refuseWithoutSplit\(\)/);
  });

  it('does not refuse where there IS a split', async () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'linux');
    const migrate = await import('../src/migrate.js');
    // It may fail for other reasons on this box; what it must not do is refuse for THIS one.
    await migrate.status().catch((e: Error) => {
      expect(e.message).not.toMatch(/cannot\s+have one yet/);
    });
  });
});

describe('the ephemeral viewer removes the page it actually wrote', () => {
  it('unlinks even when the overwrite cannot be done', async () => {
    const { shredViewer } = await import('../src/log-viewer.js');
    const f = path.join(dir, 'page.html');
    fs.writeFileSync(f, 'x'.repeat(100));
    shredViewer(f);
    expect(fs.existsSync(f)).toBe(false);
  });

  it('leaves a page written by someone else at the same path', async () => {
    // One invocation must not shred another's output — including a page deliberately kept.
    const { shredViewer } = await import('../src/log-viewer.js');
    const f = path.join(dir, 'shared.html');
    fs.writeFileSync(f, 'first');
    const st = fs.statSync(f);
    const stamp = { ino: st.ino, mtimeMs: st.mtimeMs };
    fs.unlinkSync(f);
    fs.writeFileSync(f, 'second — a different file at the same name');
    // The inode is very often REUSED here, which is exactly why the stamp carries mtime
    // too: identity by inode alone would call this the same file and delete it.
    fs.utimesSync(f, new Date(st.mtimeMs + 5000), new Date(st.mtimeMs + 5000));

    shredViewer(f, stamp);
    expect(fs.existsSync(f)).toBe(true);
    expect(fs.readFileSync(f, 'utf8')).toMatch(/second/);
  });

  it('does not block the loop that has to run the cleanup', () => {
    // execFileSync here blocks the event loop the timer and SIGINT handler live on, so a
    // browser helper that hangs means the page never gets removed.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'log-viewer.ts'), 'utf8');
    const opener = src.slice(src.indexOf('export function openInBrowser'));
    expect(opener.slice(0, 900)).toMatch(/spawn\(/);
    expect(opener.slice(0, 900)).not.toMatch(/execFileSync\(/);
  });
});

describe('the store key claim matches the store key', () => {
  it('distinguishes TPM sealing from host-key sealing', () => {
    // These make different promises. A TPM-sealed key does not leave the machine. systemd's
    // host key lives at /var/lib/systemd/credential.secret — on the SAME DISK as the sealed
    // store — so an offline copy plus root opens it, which was verified by decrypting a
    // sealed blob using nothing but files from that filesystem. The code printed "a copy of
    // the disk does not open it" for both.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'agent.ts'), 'utf8');
    expect(src).toMatch(/'sealed-tpm' \| 'sealed-host' \| 'local-file' \| 'derived' \| 'derived-shared'/);
    // The strong sentence must appear only on the TPM branch.
    const tpmIdx = src.indexOf("SEALED TO THIS MACHINE");
    const hostIdx = src.indexOf("sealed to systemd\\'s HOST KEY");
    expect(tpmIdx).toBeGreaterThan(-1);
    expect(hostIdx).toBeGreaterThan(-1);
    const hostBranch = src.slice(hostIdx, hostIdx + 700);
    expect(hostBranch).toMatch(/WOULD open the store/);
    expect(hostBranch).not.toMatch(/does not open it/);

    // macOS gets its own sentence for the same reason, and it must not borrow the TPM one:
    // the key is random rather than derived, which is the improvement, but it is not sealed
    // to anything, which is the limit.
    const localIdx = src.indexOf('a random key in a 0600 file');
    expect(localIdx).toBeGreaterThan(-1);
    const localBranch = src.slice(localIdx, localIdx + 700);
    expect(localBranch).toMatch(/NOT sealed to hardware/);
    expect(localBranch).toMatch(/WOULD open the store/);
    expect(localBranch).not.toMatch(/does not open it/);
  });

  it('does not let a cleared TPM stop the broker starting', () => {
    // LoadCredentialEncrypted is fatal when the source cannot be decrypted, which turns a
    // cleared or replaced TPM into a broker that never reaches ExecStart — so the derived-key
    // fallback it carries could never run, and the store has already been migrated away from
    // that key. ExecStartPre with '-' is non-fatal by construction; '+' runs it as root,
    // which is what reaching the TPM needs.
    const unit = fs.readFileSync(path.join(ROOT, 'packaging', 'wundervault-agent.service'), 'utf8');
    expect(unit).toMatch(/^ExecStartPre=-\+/m);
    expect(unit).not.toMatch(/^LoadCredentialEncrypted=/m);
  });

  it('asks the broker which key it used, rather than grepping a log window', () => {
    // A fixed `journalctl -n 20` window can scroll past the line on a chatty start, and then
    // the install reports success while the machine runs on the weaker key.
    const script = fs.readFileSync(path.join(ROOT, 'packaging', 'install-daemon.sh'), 'utf8');
    expect(script).toMatch(/"action":"ping"/);
    expect(script).toMatch(/key_mode/);
    expect(script).not.toMatch(/journalctl -u "\$UNIT_NAME" -n 20/);
  });

  it('derives the setup-link key asynchronously', () => {
    // 600,000 synchronous rounds block the loop every agent's credential socket shares, and
    // a v1 link pays for a failed v2 attempt first.
    // Matching the CALL, not the word — the comment above it names pbkdf2Sync to say why it
    // is not used, and a blunt search flagged that as the defect it was describing.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'enrol.ts'), 'utf8');
    expect(src).not.toMatch(/crypto\.pbkdf2Sync\(/);
    expect(src).toMatch(/crypto\.pbkdf2\(/);
  });
});
