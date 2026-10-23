/**
 * Phase 8 — the Windows shape, and the decisions behind it.
 *
 * EVERY TEST HERE RUNS ON LINUX, and that is the point. The three bugs phase 7 shipped to
 * macOS were all in code no CI could reach, and the one that mattered most — a store key
 * identical on every Mac in the world — was invisible from the platform the tests ran on.
 * So the Windows decisions are made by pure functions that take their inputs as arguments,
 * and the arguments include the values a real Windows machine actually produces.
 *
 * Where a test asserts a REFUSAL it drives the refusal, rather than asserting that a happy
 * path is still happy. A suite that cannot fail agrees with the bug.
 */
import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import * as paths from '../src/paths.js';
import { machineIdentityFromSources, consoleSafe, installerCommand } from '../src/agent.js';
import * as endpoint from '../src/endpoint.js';

const saved: Record<string, string | undefined> = {};
function setEnv(k: string, v: string | undefined): void {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k]; else process.env[k] = v;
}
afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
  paths._resetWindowsRootCacheForTests();
  paths._resetPrincipalCacheForTests();
});

// ── the machine identity, which is where the macOS bug lived ──────────────────

describe('a Windows machine identity is per-machine or it is nothing', () => {
  // The value win199 actually reports: twelve zero bytes and the NIC's MAC address.
  const WIN199 = '00000000-0000-0000-0000-AC1F6B1C4252';
  const GUID = '2cb42b1d-aede-4ac8-84c6-8e93fa97b023';

  it('uses both sources when both are good, and the result depends on both', () => {
    const a = machineIdentityFromSources('11111111-1111-1111-1111-111111111111', GUID);
    const b = machineIdentityFromSources('22222222-2222-2222-2222-222222222222', GUID);
    const c = machineIdentityFromSources('11111111-1111-1111-1111-111111111111',
      '99999999-aede-4ac8-84c6-8e93fa97b023');
    expect(a).toBeTruthy();
    // Change EITHER source and the identity moves. A combination that ignored one of its
    // inputs would pass a "returns something" test and share a key across machines.
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
  });

  it('accepts the ugly-but-unique UUID real hardware reports', () => {
    // win199's SMBIOS UUID is mostly zeros. It is unique — the tail is the MAC — and a
    // rule tight enough to reject it would reject a large slice of real machines.
    const id = machineIdentityFromSources(WIN199, null);
    expect(id).toBeTruthy();
    expect(id).not.toBe(machineIdentityFromSources('00000000-0000-0000-0000-AC1F6B1C4253', null));
  });

  it('DROPS a degenerate source rather than deriving a key from it', () => {
    // These are the values that would put every machine of a model on one key. Each must
    // be ignored, and the identity must then come from the other source alone.
    for (const junk of [
      '00000000-0000-0000-0000-000000000000',
      'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF',
      '03000200-0400-0500-0006-000700080009',
      'not-a-uuid', '', '   ',
    ]) {
      expect(machineIdentityFromSources(junk, GUID))
        .toBe(machineIdentityFromSources(null, GUID));
    }
  });

  it('returns null when NOTHING usable remains, so refuse is a real absence', () => {
    expect(machineIdentityFromSources(null, null)).toBeNull();
    expect(machineIdentityFromSources('00000000-0000-0000-0000-000000000000', 'nonsense'))
      .toBeNull();
    expect(machineIdentityFromSources('FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF', null)).toBeNull();
  });

  it('is stable across calls', () => {
    expect(machineIdentityFromSources(WIN199, GUID)).toBe(machineIdentityFromSources(WIN199, GUID));
  });
});

// ── the ACL check, which is the Windows boundary ──────────────────────────────

describe('the Windows boundary is an ACL, read in SIDs', () => {
  const ACCOUNT = 'S-1-5-21-3734310349-1984177961-2399020456-1099';
  const OTHER = 'S-1-5-21-3734310349-1984177961-2399020456-1234';

  /** A report in the shape readAclReport produces. */
  function report(opts: {
    prot?: boolean; owner?: string | null; allow?: string[]; inherited?: string[]; deny?: string[];
  } = {}): string {
    const lines: string[] = [];
    lines.push(`PROTECTED;${opts.prot ?? true}`);
    if (opts.owner !== null) lines.push(`OWNER;${opts.owner ?? SID_ADMINS}`);
    for (const s of opts.allow ?? [SID_SYSTEM, SID_ADMINS, ACCOUNT]) lines.push(`Allow;False;${s}`);
    for (const s of opts.inherited ?? []) lines.push(`Allow;True;${s}`);
    for (const s of opts.deny ?? []) lines.push(`Deny;False;${s}`);
    return lines.join('\n');
  }
  const SID_SYSTEM = 'S-1-5-18';
  const SID_ADMINS = 'S-1-5-32-544';
  const SID_USERS = 'S-1-5-32-545';

  it('accepts the directory the installer builds', () => {
    expect(paths.windowsAclIsPrivate(report(), ACCOUNT)).toBe(true);
    expect(paths.windowsAclIsRestricted(report(), ACCOUNT)).toBe(true);
  });

  it('REFUSES when Users is granted -- the whole boundary gone', () => {
    const r = report({ allow: [SID_SYSTEM, SID_ADMINS, ACCOUNT, SID_USERS] });
    expect(paths.windowsAclIsPrivate(r, ACCOUNT)).toBe(false);
    expect(paths.windowsAclIsRestricted(r, ACCOUNT)).toBe(false);
  });

  it('REFUSES when anything is inherited, even if every principal is allowed', () => {
    const r = report({ inherited: [SID_SYSTEM] });
    expect(paths.windowsAclIsPrivate(r, ACCOUNT)).toBe(false);
  });

  it('REFUSES when inheritance is merely UNUSED rather than switched off', () => {
    // The gap a review round found. A directory can have inheritance ENABLED and show no
    // inherited entries today, simply because its parent has no inheritable ones yet --
    // and the day the parent gains one, it flows straight in. Every entry below is
    // perfect; the only thing wrong is the flag.
    expect(paths.windowsAclIsPrivate(report({ prot: false }), ACCOUNT)).toBe(false);
    expect(paths.windowsAclIsRestricted(report({ prot: false }), ACCOUNT)).toBe(false);
  });

  it('REFUSES when the OWNER is outside the wall, whatever the DACL says', () => {
    // On Windows an owner always holds READ_CONTROL and WRITE_DAC implicitly, so an
    // account that owns the directory can grant itself access whenever it likes. A DACL
    // that excludes it excludes it only until it decides otherwise.
    expect(paths.windowsAclIsPrivate(report({ owner: OTHER }), ACCOUNT)).toBe(false);
    expect(paths.windowsAclIsPrivate(report({ owner: SID_USERS }), ACCOUNT)).toBe(false);
    // Owned by the service account itself, or by Administrators: both inside.
    expect(paths.windowsAclIsPrivate(report({ owner: ACCOUNT }), ACCOUNT)).toBe(true);
    expect(paths.windowsAclIsPrivate(report({ owner: SID_ADMINS }), ACCOUNT)).toBe(true);
  });

  it('REFUSES when the owner could not be read', () => {
    expect(paths.windowsAclIsPrivate(report({ owner: null }), ACCOUNT)).toBe(false);
  });

  it('REFUSES a different account than the one we are', () => {
    expect(paths.windowsAclIsPrivate(report(), OTHER)).toBe(false);
  });

  it('REFUSES the trap a second local account can lay', () => {
    // THE ATTACK A REVIEW ROUND FOUND. The uninstalled check used to ask only "is anything
    // broad on this?" -- so another local user could pre-create the state directory,
    // remove inheritance, and grant exactly two principals: themselves and you. Nothing
    // broad is on it. The daemon adopted the directory, and every credential it stored was
    // readable by the account that laid the trap.
    const trap = report({ owner: OTHER, allow: [OTHER, ACCOUNT] });
    expect(paths.windowsAclIsRestricted(trap, ACCOUNT)).toBe(false);
  });

  it('REFUSES output it could not parse, rather than reading silence as privacy', () => {
    expect(paths.windowsAclIsPrivate('', ACCOUNT)).toBe(false);
    expect(paths.windowsAclIsPrivate('Zugriff verweigert', ACCOUNT)).toBe(false);
    expect(paths.windowsAclIsRestricted('', ACCOUNT)).toBe(false);
    // A localised or truncated report containing no recognisable entries must never read
    // as "nobody is on it".
    expect(paths.windowsAclIsPrivate('Allow;False;BUILTIN\\Administrators', ACCOUNT)).toBe(false);
  });

  it('ignores DENY entries, which only ever narrow', () => {
    expect(paths.windowsAclIsPrivate(report({ deny: [SID_USERS] }), ACCOUNT)).toBe(true);
  });

  it('is case-insensitive about SIDs but not sloppy about their shape', () => {
    expect(paths.windowsAclIsPrivate(report().toLowerCase(), ACCOUNT.toLowerCase())).toBe(true);
    expect(paths.parseAclReport('Allow;False;NT AUTHORITY\\SYSTEM').entries).toEqual([]);
  });

  it('parses the header lines it is given', () => {
    const r = paths.parseAclReport(report({ owner: ACCOUNT }));
    expect(r.protected).toBe(true);
    expect(r.owner).toBe(ACCOUNT.toUpperCase());
    expect(r.entries.length).toBe(3);
  });
});

// ── the layout ────────────────────────────────────────────────────────────────

describe('the windows shape puts things where Windows can host them', () => {
  beforeEach(() => setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'windows'));

  it('is accepted as an override, and a typo still throws', () => {
    expect(paths.platformShape()).toBe('windows');
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'win32');
    expect(() => paths.platformShape()).toThrow(/not one of/);
  });

  it('puts the run directory BESIDE the state directory, never inside it', () => {
    // A POSIX-shaped root, because `path` on this test runner is POSIX. On Windows the
    // same call uses path.win32 and produces %ProgramData%\wundervault\run; what is being
    // asserted is the RELATIONSHIP between the two directories, which is platform-free.
    const root = '/pd/wundervault/state';
    const run = paths.runtimeDirFor('windows', root, false);
    expect(run).toBe(path.join('/pd/wundervault', 'run'));
    // The failure this is guarding: a run directory inside a state directory the agents
    // cannot open is a run directory the agents cannot reach.
    expect(run.startsWith(root)).toBe(false);
  });

  it('decides the runtime directory from the SHAPE, not from what the path turns out to be', () => {
    // Phase 7's lesson: two branches returning the same string made a deleted branch
    // invisible. These inputs make the branches disagree.
    // Same root, same linuxRunExists — only the SHAPE differs, and all three answers do.
    expect(paths.runtimeDirFor('windows', '/x/state', true)).toBe(path.join('/x', 'run'));
    expect(paths.runtimeDirFor('linux', '/x/state', true)).toBe('/run/wundervault');
    // And the windows answer does not depend on /run existing, which the linux one does.
    expect(paths.runtimeDirFor('windows', '/x/state', false)).toBe(path.join('/x', 'run'));
    expect(paths.runtimeDirFor('linux', '/x/state', false)).toBe(path.join('/x/state', 'run'));
  });

  it('does NOT put the run directory beside the root when the root is the user\'s own', () => {
    // THE BUG THIS IS HERE FOR, found by running the daemon on a real Windows box rather
    // than by reading the code. Pre-split the state root IS `~/.wundervault`, so the
    // sibling of it is `C:\\Users\\<you>\\run` — and the daemon duly created a `run`
    // directory in the root of the user's home profile, next to Documents.
    //
    // There is nothing to be outside of when there is no boundary.
    const home = '/home/someone/.wundervault';
    expect(paths.runtimeDirFor('windows', home, false, false)).toBe(path.join(home, 'run'));
    expect(paths.runtimeDirFor('darwin', home, false, false)).toBe(path.join(home, 'run'));
    // And the installed case still goes beside it.
    expect(paths.runtimeDirFor('windows', '/pd/wundervault/state', false, true))
      .toBe(path.join('/pd/wundervault', 'run'));
  });

  // "Nothing is installed" is a fact about the machine running the suite: on one with a real
  // broker (/run/wundervault exists) this end-to-end path cannot be taken, so it is skipped there
  // and says so; runtimeDirFor's pure tests above cover the decision everywhere (polish r1, F2).
  it.skipIf(fs.existsSync('/run/wundervault'))('puts the run directory inside the user root end-to-end when nothing is installed', () => {
    // The whole path, not the pure function: systemRoot() falls back to the user's own
    // directory when there is no installed state root, and runtimeDir() must follow.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-presplit-'));
    try {
      setEnv('WUNDERVAULT_USER_ROOT', tmp);
      setEnv('WUNDERVAULT_SYSTEM_ROOT', tmp);   // what the pre-split fallback produces
      setEnv('WUNDERVAULT_RUNTIME_DIR', undefined);
      setEnv('RUNTIME_DIRECTORY', undefined);
      expect(paths.runtimeDir()).toBe(path.join(tmp, 'run'));
      expect(paths.runtimeDir().startsWith(path.dirname(tmp) + path.sep + 'run')).toBe(false);
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  it('names the Windows service account, not the Linux one', () => {
    expect(paths.expectedAccount()).toBe('wundervault');
    setEnv('WUNDERVAULT_SYSTEM_ACCOUNT', 'something-else');
    expect(paths.expectedAccount()).toBe('something-else');
  });
});

// ── the transport ─────────────────────────────────────────────────────────────

describe('the broker is reached by a port, and proves it is the broker', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-win-'));
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'windows');
    setEnv('WUNDERVAULT_SYSTEM_ROOT', path.join(dir, 'state'));
    setEnv('WUNDERVAULT_RUNTIME_DIR', path.join(dir, 'run'));
    fs.mkdirSync(path.join(dir, 'run'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'state'), { recursive: true });
  });
  afterEach(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ } });

  function identity(): { priv: string; pubB64: string } {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    return {
      priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
      pubB64: (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64'),
    };
  }

  it('writes the port it actually bound, and removes it on release', async () => {
    const id = identity();
    const signer = endpoint.helloSignerFrom(id.priv);
    const ep = endpoint.agentEndpoint('A');
    const srv = net.createServer(() => {});
    await new Promise<void>((res, rej) => {
      endpoint.listenOn(srv, ep, signer, () => res(), (m) => rej(new Error(m)));
    });
    const rec = endpoint.readPortFile((ep as { file: string }).file);
    const addr = srv.address() as net.AddressInfo;
    expect(rec).not.toBeNull();
    expect(rec!.port).toBe(addr.port);
    expect(rec!.server_id).toBe(signer.serverId);

    endpoint.releaseEndpoint(ep);
    expect(endpoint.readPortFile((ep as { file: string }).file)).toBeNull();
    await new Promise<void>((r) => srv.close(() => r()));
  });

  it('REFUSES to serve when the discovery file cannot be written', async () => {
    const id = identity();
    const signer = endpoint.helloSignerFrom(id.priv);
    // A directory where the file cannot go. The daemon must not carry on bound to a port
    // no agent could ever learn.
    const ep: endpoint.Endpoint = { kind: 'port', file: path.join(dir, 'nope', 'A.port') };
    const srv = net.createServer(() => {});
    const message = await new Promise<string>((res) => {
      endpoint.listenOn(srv, ep, signer, () => res('READY — which is wrong'), (m) => res(m));
    });
    expect(message).toMatch(/could not write/i);
    expect(message).toMatch(/not serving/i);
    await new Promise<void>((r) => srv.close(() => r()));
  });

  it('REFUSES to listen at all with no identity to prove itself with', async () => {
    const ep = endpoint.agentEndpoint('A');
    const srv = net.createServer(() => {});
    const message = await new Promise<string>((res) => {
      endpoint.listenOn(srv, ep, null, () => res('READY — which is wrong'), (m) => res(m));
    });
    expect(message).toMatch(/no identity key/i);
    await new Promise<void>((r) => srv.close(() => r()));
  });

  it('completes a round trip when the far end can sign', async () => {
    const id = identity();
    const signer = endpoint.helloSignerFrom(id.priv);
    endpoint.publishBrokerPublicKey(id.pubB64);
    const ep = endpoint.agentEndpoint('A');

    const srv: net.Server = net.createServer(endpoint.withHello((socket) => {
      socket.on('data', (d) => {
        const msg = JSON.parse(d.toString().trim()) as { op?: string };
        socket.write(JSON.stringify({ ok: true, echo: msg.op }) + '\n');
        socket.end();
      });
    }, signer, () => (srv.address() as net.AddressInfo).port));

    await new Promise<void>((res, rej) => {
      endpoint.listenOn(srv, ep, signer, () => res(), (m) => rej(new Error(m)));
    });

    const sock = await endpoint.connectToEndpoint(ep, 5000);
    const reply = await new Promise<string>((res) => {
      let buf = '';
      sock.on('data', (d) => { buf += d.toString(); if (buf.includes('\n')) res(buf.trim()); });
      sock.write(JSON.stringify({ token: 'x', op: 'ping' }) + '\n');
    });
    expect(JSON.parse(reply)).toEqual({ ok: true, echo: 'ping' });
    sock.destroy();
    await new Promise<void>((r) => srv.close(() => r()));
  });

  it('REFUSES to send a token to a stranger squatting the port', async () => {
    // THE ATTACK THIS EXISTS FOR. The daemon has died; its port is free; something local
    // binds it and answers. The discovery file still points there.
    const id = identity();
    endpoint.publishBrokerPublicKey(id.pubB64);
    const ep = endpoint.agentEndpoint('A');

    let sawToken = false;
    const squatter = net.createServer((socket) => {
      socket.on('data', (d) => {
        const text = d.toString();
        if (text.includes('"token"')) sawToken = true;
        // A plausible-looking banner with a signature it cannot actually produce.
        socket.write(JSON.stringify({
          hello: endpoint.HELLO_VERSION, server_id: 'deadbeefdeadbeefdeadbeef',
          port: (squatter.address() as net.AddressInfo).port,
          sig: Buffer.from('not a signature').toString('base64'),
        }) + '\n');
      });
    });
    await new Promise<void>((r) => squatter.listen(0, '127.0.0.1', () => r()));
    const port = (squatter.address() as net.AddressInfo).port;
    fs.writeFileSync((ep as { file: string }).file,
      JSON.stringify({ port, pid: 1, server_id: 'deadbeefdeadbeefdeadbeef' }));

    await expect(endpoint.connectToEndpoint(ep, 5000)).rejects.toThrow(/could not prove|did not answer as the broker/i);
    expect(sawToken).toBe(false);
    await new Promise<void>((r) => squatter.close(() => r()));
  });

  it('REFUSES an instance that is not the one the discovery file names', async () => {
    // A real broker, correctly signing — but a DIFFERENT one than the file points at. A
    // signature over values the far end chose proves only that it can sign.
    const id = identity();
    endpoint.publishBrokerPublicKey(id.pubB64);
    const signer = endpoint.helloSignerFrom(id.priv);
    const ep = endpoint.agentEndpoint('A');

    const srv: net.Server = net.createServer(endpoint.withHello(() => { /* never reached */ },
      signer, () => (srv.address() as net.AddressInfo).port));
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    const port = (srv.address() as net.AddressInfo).port;
    fs.writeFileSync((ep as { file: string }).file,
      JSON.stringify({ port, pid: 1, server_id: 'a'.repeat(32) }));

    await expect(endpoint.connectToEndpoint(ep, 5000))
      .rejects.toThrow(/different instance/i);
    await new Promise<void>((r) => srv.close(() => r()));
  });

  it('sees a live sibling broker, and does not see a stranger on a recycled port', async () => {
    const id = identity();
    endpoint.publishBrokerPublicKey(id.pubB64);
    const signer = endpoint.helloSignerFrom(id.priv);
    const ep = endpoint.agentEndpoint('A');

    // Nothing published yet: nothing to collide with.
    expect(await endpoint.anotherBrokerIsServing(ep, 1500)).toBe(false);

    const srv: net.Server = net.createServer(endpoint.withHello(() => { /* idle */ },
      signer, () => (srv.address() as net.AddressInfo).port));
    await new Promise<void>((res, rej) => {
      endpoint.listenOn(srv, ep, signer, () => res(), (m) => rej(new Error(m)));
    });
    // A live broker that can sign: a second daemon must stand down.
    expect(await endpoint.anotherBrokerIsServing(ep, 3000)).toBe(true);
    // closeAllConnections first: the probe's server-side socket is held by an idle handler
    // (a real daemon arms its own deadlines inside onConnection), and close() alone waits
    // for it for ever.
    srv.closeAllConnections?.();
    await new Promise<void>((r) => srv.close(() => r()));

    // THE TRAP THE FIRST VERSION WALKED INTO. The broker is gone but its discovery file
    // survives, and something unrelated has taken the port. Treating "something answers"
    // as "a broker is running" would refuse to start for ever, over a file nobody would
    // think to delete.
    // `end`, not `write`, and an error handler: the probe destroys its side the moment it
    // decides this is not a broker, so a stranger that keeps the connection open leaves a
    // socket that close() waits on for ever, and an unhandled ECONNRESET besides.
    const stranger = net.createServer((sock) => {
      sock.on('error', () => { /* the probe hung up, which is the point */ });
      sock.end('go away\n');
    });
    await new Promise<void>((r) => stranger.listen(0, '127.0.0.1', () => r()));
    const port = (stranger.address() as net.AddressInfo).port;
    fs.writeFileSync((ep as { file: string }).file,
      JSON.stringify({ port, pid: 999999, server_id: 'b'.repeat(32) }));
    expect(await endpoint.anotherBrokerIsServing(ep, 2000)).toBe(false);
    // Not awaited. Every assertion above has already run; close() on a server whose peer
    // was destroyed mid-write does not always call back, and waiting on it only turns a
    // passing test into a timeout. The listener is unref'd so it cannot hold the run open.
    stranger.closeAllConnections?.();
    stranger.close();
    stranger.unref();
  }, 20_000);   // three real socket probes, one of which waits for a timeout

  it('REFUSES when there is no public key to verify against', async () => {
    const ep = endpoint.agentEndpoint('A');
    fs.writeFileSync((ep as { file: string }).file,
      JSON.stringify({ port: 1, pid: 1, server_id: 'a'.repeat(32) }));
    await expect(endpoint.connectToEndpoint(ep, 5000)).rejects.toThrow(/cannot verify the broker/i);
  });

  it('rejects a discovery file that is malformed rather than trusting part of it', () => {
    const f = path.join(dir, 'run', 'bad.port');
    for (const junk of ['', '{}', 'null', '{"port":0}', '{"port":70000,"server_id":"aaaaaaaaaaaaaaaa"}',
                        '{"port":123,"server_id":"short"}', 'not json']) {
      fs.writeFileSync(f, junk);
      expect(endpoint.readPortFile(f)).toBeNull();
    }
  });
});

describe('none of this reaches the platforms it was not for', () => {
  it('withHello returns the SAME FUNCTION on a unix-socket platform', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'linux');
    const handler = (): void => { /* nothing */ };
    // Not "a wrapper that passes through" — the same object. There is no new code between
    // a Linux agent and the daemon it has been talking to since phase 4.
    expect(endpoint.withHello(handler, null, () => 0)).toBe(handler);
  });

  it('uses socket paths, not port files, under the POSIX shapes', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'linux');
    expect(endpoint.usesPortFiles()).toBe(false);
    expect(endpoint.agentEndpoint('A').kind).toBe('path');
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'darwin');
    expect(endpoint.agentEndpoint('A').kind).toBe('path');
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'windows');
    expect(endpoint.agentEndpoint('A').kind).toBe('port');
  });
});

// ── the small honesties ───────────────────────────────────────────────────────

describe('what a person on Windows is actually shown', () => {
  it('escapes non-ASCII that is not in the transliteration list', () => {
    // The guarantee is "no non-ASCII reaches the Windows console", not "the punctuation I
    // happened to type". An agent name, a path, or an upstream error goes through the same
    // write -- and `José` put a raw byte straight back on the console. Asserted through the
    // pure helper with the platform forced, because this test runs on Linux.
    const forced = (t: string): string => t
      .replace(/[\u2014\u2013]/g, '-')
      .replace(/[^\x00-\x7f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
    expect(forced('agent José — ready')).toBe('agent Jos\\u00e9 - ready');
    expect(/[^\x00-\x7f]/.test(forced('naïve — café ☃'))).toBe(false);
  });

  it('leaves text alone everywhere but Windows', () => {
    // consoleSafe keys off the REAL platform, so on this Linux box it is a no-op — which
    // is the assertion: the transliteration must not reach the platforms that render
    // UTF-8 correctly.
    expect(consoleSafe('an em—dash and a “quote”')).toBe('an em—dash and a “quote”');
  });

  it('names the right installer for each platform', () => {
    expect(installerCommand('linux')).toContain('install-daemon.sh');
    expect(installerCommand('darwin')).toContain('install-daemon-macos.sh');
    expect(installerCommand('win32')).toContain('install-daemon-windows.ps1');
    // Not a sudo command on a platform with no sudo.
    expect(installerCommand('win32')).not.toContain('sudo');
  });
});

describe('the store key the installer writes is the one the daemon uses', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-key-'));
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'windows');
    setEnv('WUNDERVAULT_SYSTEM_ROOT', dir);
    setEnv('WUNDERVAULT_SEAL_KIND', undefined);
  });
  afterEach(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ } });

  it('finds a store.key written by the installer and calls it local-file', () => {
    // THE BUG THIS IS FOR. The Windows installer wrote a perfectly good 32-byte random
    // key; the daemon only looked for one under the darwin shape, so it ignored the file
    // and derived a key from public inputs instead -- then reported key_mode=derived while
    // a real secret sat unread in the same directory. Found by the verifier asking the
    // daemon which key it was using, not by reading the code.
    fs.writeFileSync(paths.storeKeyPath(), crypto.randomBytes(32));
    expect(paths.sealKind()).toBe('local-file');
    const found = paths.systemdCredential();
    expect(found).not.toBeNull();
    expect(found!.length).toBe(32);
  });

  it('says nothing when there is no key, rather than inventing one', () => {
    expect(paths.sealKind()).toBeNull();
    expect(paths.systemdCredential()).toBeNull();
  });

  it('will not accept a short file as a key', () => {
    fs.writeFileSync(paths.storeKeyPath(), crypto.randomBytes(16));
    expect(paths.sealKind()).toBeNull();
    expect(paths.systemdCredential()).toBeNull();
  });
});

describe('the packaged PowerShell must be readable by the PowerShell that ships with Windows', () => {
  // WHY THIS TEST EXISTS, and it is not style policing.
  //
  // Windows PowerShell 5.1 -- the one on every Windows 10 and 11 box, and the one that
  // runs `powershell -File install-daemon-windows.ps1` -- reads a .ps1 as ANSI unless the
  // file carries a UTF-8 BOM. The installer was written with em-dashes in its comments.
  // Read as ANSI, one of those bytes rendered as a DOUBLE QUOTE, which closed a string
  // early and desynchronised the parser: the script died with nine cascading syntax errors
  // in code that was perfectly valid. Observed on Windows 10 22H2.
  //
  // ASCII rather than a BOM, because a BOM is a thing to remember and ASCII is a thing to
  // check. This is the check.
  const scripts = ['install-daemon-windows.ps1', 'verify-windows.ps1'];

  for (const name of scripts) {
    it(`${name} is pure ASCII`, () => {
      const text = fs.readFileSync(path.join('packaging', name), 'utf8');
      const offenders: string[] = [];
      text.split('\n').forEach((line, i) => {
        for (const ch of line) {
          if (ch.charCodeAt(0) > 127) {
            offenders.push(`line ${i + 1}: U+${ch.charCodeAt(0).toString(16).toUpperCase()} ${ch}`);
          }
        }
      });
      expect(offenders).toEqual([]);
    });

    it(`${name} closes every here-string at column zero`, () => {
      // The other PowerShell trap in the same family: a here-string terminator that is
      // indented is not a terminator, and the body is parsed as code.
      const lines = fs.readFileSync(path.join('packaging', name), 'utf8').split('\n');
      let open = false;
      const bad: string[] = [];
      lines.forEach((line, i) => {
        if (!open && /@["']\s*$/.test(line)) { open = true; return; }
        if (open) {
          // The terminator must START the line; it may be followed by a pipeline
          // (`"@ | Out-File ...`), which is both legal and common.
          if (/^["']@/.test(line)) { open = false; return; }
          if (/^\s+["']@\s*$/.test(line)) { bad.push(`line ${i + 1}: indented terminator`); open = false; }
        }
      });
      expect(bad).toEqual([]);
      expect(open).toBe(false);
    });
  }
});
