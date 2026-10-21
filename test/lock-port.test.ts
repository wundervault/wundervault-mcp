import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

/**
 * The PORT path of the single-instance lock, driven from Linux.
 *
 * This file exists because the port path was unreachable from CI on the only platform
 * anyone ran CI on. It shipped with a concurrency bug that four rounds of review on the
 * abstract-socket path could not have found, and the two macOS assertions that did catch
 * it were gated off as unexplained — see the deleted HANDOFF-lock-on-non-linux.md.
 *
 * The bug: eight candidate ports derived into 49152-65535, which is macOS's default
 * ephemeral range, walked until one bound. An unrelated outbound socket transiently owning
 * a candidate made the first claim land on candidate 1 and the second claim — finding
 * candidate 0 free again — land on candidate 0 and report SUCCESS. Two holders.
 *
 * Every test here fails against that implementation.
 */

const AGENT = `PortLockTest_${process.pid}_${Date.now()}`;

let home: string;
let lock: typeof import('../src/lock.js');
const realHomedir = os.homedir;
const saved: Record<string, string | undefined> = {};

function setEnv(k: string, v: string | undefined) {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
}

/** A port nothing is listening on, taken and released so the number is known-free. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen({ host: '127.0.0.1', port: 0 }, () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });
}

/** Something on the address that is NOT us: accepts, says nothing, never answers. */
function stranger(port: number): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const s = net.createServer(() => { /* accept and stay silent */ });
    s.once('error', reject);
    s.listen({ host: '127.0.0.1', port }, () => resolve(s));
  });
}

function closeServer(s: net.Server): Promise<void> {
  return new Promise((r) => { try { s.close(() => r()); } catch { r(); } });
}

beforeEach(async () => {
  home = mkdtempSync(path.join(os.tmpdir(), 'wv-portlock-'));
  (os as any).homedir = () => home;
  mkdirSync(path.join(home, '.wundervault'), { recursive: true });
  setEnv('WUNDERVAULT_AGENT_NAME', AGENT);
  setEnv('WUNDERVAULT_LOCK_STRATEGY', 'port');
  setEnv('WUNDERVAULT_LOCK_PORT', undefined);
  lock = await import('../src/lock.js');
});

afterEach(async () => {
  await lock.releaseCredential();
  (os as any).homedir = realHomedir;
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
  rmSync(home, { recursive: true, force: true });
});

describe('the port lock claims ONE address', () => {
  it('derives a port below the ephemeral range, for any agent name', () => {
    // 49152-65535 is ephemeral on macOS and Windows; 32768-60999 on Linux. A port derived
    // below 32768 is handed out by none of them. Asserted over a sample rather than on one
    // name, because the old range failed for every name and a single-name test would have
    // passed just as happily on a range that was wrong for most of them.
    setEnv('WUNDERVAULT_LOCK_PORT', undefined);
    for (let i = 0; i < 1000; i++) {
      setEnv('WUNDERVAULT_AGENT_NAME', `sample-${i}-${Math.random()}`);
      const port = lock._addressPortForTests();
      expect(port).toBeGreaterThanOrEqual(20000);
      expect(port).toBeLessThanOrEqual(32767);
    }
    setEnv('WUNDERVAULT_AGENT_NAME', AGENT);
  });

  it('gives the same agent the same port and different agents different ports', () => {
    setEnv('WUNDERVAULT_AGENT_NAME', 'alpha');
    const a1 = lock._addressPortForTests();
    setEnv('WUNDERVAULT_AGENT_NAME', 'beta');
    const b = lock._addressPortForTests();
    setEnv('WUNDERVAULT_AGENT_NAME', 'alpha');
    const a2 = lock._addressPortForTests();
    expect(a1).toBe(a2);
    expect(a1).not.toBe(b);
    setEnv('WUNDERVAULT_AGENT_NAME', AGENT);
  });

  it('refuses a second claim while the first is held, and names the holder', async () => {
    // THE regression. Against the candidate walk this returned ok: true whenever the first
    // claim had been pushed off candidate 0.
    const first = await lock.acquireCredential('test');
    expect(first.ok).toBe(true);

    const second = await lock.acquireCredential('test');
    expect(second.ok).toBe(false);
    expect(second.holder?.source).toBe('holder');
    expect(second.holder?.pid).toBe(process.pid);
  });

  it('reports the lock file when nobody answers the address', async () => {
    // The second assertion macOS CI failed. With no holder listening, whoHolds() must fall
    // back to the compatibility file rather than finding some other candidate's occupant.
    writeFileSync(
      path.join(home, '.wundervault', `mcp-${AGENT}.lock`),
      `4242\n${JSON.stringify({ pid: 4242, since: '2026-01-01T00:00:00.000Z', agent: AGENT })}\n`,
      'utf8',
    );
    const who = await lock.whoHolds();
    expect(who.source).toBe('lock-file');
    expect(who.pid).toBe(4242);
  });
});

describe('a stranger on the address is an error, not a detour', () => {
  it('refuses rather than binding somewhere else', async () => {
    // The old behaviour was to walk on. Walking on is what produced two holders: the
    // claim succeeded at a different address and the caller was told it held the
    // credential. Refusing is the only answer that preserves one-agent-per-credential.
    const port = lock._addressPortForTests();
    const squatter = await stranger(port);
    try {
      const claim = await lock.acquireCredential('test');
      expect(claim.ok).toBe(false);
      expect(claim.reason).toContain(String(port));
      expect(claim.reason).toMatch(/not a wundervault holder/);
    } finally {
      await closeServer(squatter);
    }
  }, 10_000);

  it('does not leave a claim behind after refusing', async () => {
    const port = lock._addressPortForTests();
    const squatter = await stranger(port);
    try {
      await lock.acquireCredential('test');
    } finally {
      await closeServer(squatter);
    }
    // The refusal must not have half-claimed: once the squatter is gone the address is
    // free and a real claim succeeds.
    const claim = await lock.acquireCredential('test');
    expect(claim.ok).toBe(true);
  }, 10_000);
});

describe('WUNDERVAULT_LOCK_PORT', () => {
  it('moves the address', async () => {
    const moved = await freePort();
    setEnv('WUNDERVAULT_LOCK_PORT', String(moved));
    const claim = await lock.acquireCredential('test');
    expect(claim.ok).toBe(true);
    expect(lock.addressDescription()).toBe(`127.0.0.1:${moved}`);
  });

  it('rejects a value that is not a port', () => {
    setEnv('WUNDERVAULT_LOCK_PORT', 'not-a-port');
    expect(() => lock._addressPortForTests()).toThrow(/not a port number/);
    setEnv('WUNDERVAULT_LOCK_PORT', '70000');
    expect(() => lock._addressPortForTests()).toThrow(/not a port number/);
  });
});

describe('the strategy is chosen, not assumed', () => {
  it('rejects an unrecognised strategy instead of silently picking one', () => {
    setEnv('WUNDERVAULT_LOCK_STRATEGY', 'sockets-maybe');
    expect(() => lock.lockStrategy()).toThrow(/must be/);
  });

  it('defaults to the abstract socket only on Linux', () => {
    setEnv('WUNDERVAULT_LOCK_STRATEGY', undefined);
    expect(lock.lockStrategy()).toBe(process.platform === 'linux' ? 'abstract' : 'port');
  });
});

describe('a refusal after binding does not poison the next attempt', () => {
  it('leaves the address actually free, not half-closed', async () => {
    // acquireCredential binds FIRST and can still refuse afterwards — here because the
    // compatibility file cannot be written, which older copies gate on. The address must
    // be genuinely free afterwards, not left half-closed.
    //
    // WHAT THIS TEST DOES NOT PROVE, stated because the alternative is letting it look
    // like it does: it does not prove the close is AWAITED. Reverting `await closed(bound)`
    // to a bare `bound.close()` leaves this green, because with no active connections the
    // close callback wins the race against the next call on this machine every time. The
    // await is reasoned, not demonstrated — with one address rather than eight a retry now
    // meets its own closing socket instead of moving to a free candidate, and is told a
    // stranger holds the address. If someone can make that timing deterministic, this is
    // the test to strengthen.
    // A directory nobody may write to. (A MISSING one is a fresh machine, which now claims:
    // the lock creates ~/.wundervault itself.)
    const { chmodSync } = await import('node:fs');
    chmodSync(path.join(home, '.wundervault'), 0o500);

    const refused = await lock.acquireCredential('test');
    expect(refused.ok).toBe(false);
    expect(refused.reason).toMatch(/could not write/);

    // Make it writable again and try again. This must succeed, and must NOT report the
    // address as occupied by a stranger.
    chmodSync(path.join(home, '.wundervault'), 0o700);

    const second = await lock.acquireCredential('test');
    expect(second.reason ?? '').not.toMatch(/not a wundervault holder/);
    expect(second.ok).toBe(true);
  }, 10_000);
});

describe('two different agents that derive the same port', () => {
  /** A real wundervault holder banner, for some OTHER agent. */
  function otherAgentHolder(port: number, agent: string): Promise<net.Server> {
    return new Promise((resolve, reject) => {
      const line = JSON.stringify({
        protocol: 'wundervault-mcp-holder', pid: 4242, agent,
        since: '2026-01-01T00:00:00.000Z',
      }) + '\n';
      const s = net.createServer((sock) => { try { sock.end(line); } catch { /* ignore */ } });
      s.once('error', reject);
      s.listen({ host: '127.0.0.1', port }, () => resolve(s));
    });
  }

  it('is reported as a COLLISION, not as our credential being in use', async () => {
    // 12,768 possible ports, so the birthday bound bites early: about a hundred agent
    // names on one machine already gives roughly a one-in-three chance that two of them
    // derive the same port. Telling the second one "your credential is held" would be a
    // plain falsehood — a DIFFERENT credential is held — and sends the operator looking
    // for a duplicate agent that does not exist.
    const port = lock._addressPortForTests();
    const squatter = await otherAgentHolder(port, 'A Completely Different Agent');
    try {
      const claim = await lock.acquireCredential('test');
      expect(claim.ok).toBe(false);
      expect(claim.reason).toMatch(/collision/i);
      expect(claim.reason).toContain('A Completely Different Agent');
      expect(claim.reason).toMatch(/WUNDERVAULT_LOCK_PORT/);
      // And emphatically NOT presented as our own holder.
      expect(claim.holder?.source).not.toBe('holder');
    } finally {
      await closeServer(squatter);
    }
  }, 10_000);

  it('whoHolds() does not name another agent as the holder of our credential', async () => {
    const port = lock._addressPortForTests();
    const squatter = await otherAgentHolder(port, 'Somebody Else');
    try {
      const who = await lock.whoHolds();
      expect(who.source).not.toBe('holder');
    } finally {
      await closeServer(squatter);
    }
  }, 10_000);

  it('still refuses normally when the holder IS our agent', async () => {
    // The collision check must not become a way to steal a credential by lying about a
    // name: an answer that matches our agent is still a refusal.
    const first = await lock.acquireCredential('test');
    expect(first.ok).toBe(true);
    const second = await lock.acquireCredential('test');
    expect(second.ok).toBe(false);
    expect(second.holder?.source).toBe('holder');
    expect(second.reason ?? '').not.toMatch(/collision/i);
  });
});
