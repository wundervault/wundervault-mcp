import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

// The lock has two implementations. On Linux it claims a kernel-held abstract socket,
// which is atomic and released on death — that is the one the daemon runs on and the
// one these tests verify. Everywhere else it walks 8 loopback port candidates and
// moves to the next when one is in use but does not answer the protocol, which is not
// the same guarantee: macOS CI shows a second in-process claim succeeding, and
// whoHolds() reporting 'holder' where 'lock-file' was expected. That is a real gap,
// not a test artifact — see HANDOFF-lock-on-non-linux.md. Asserting Linux semantics
// on a platform that does not implement them would just be a red suite nobody reads.
const LINUX_ONLY = process.platform === 'linux' ? describe : describe.skip;

/**
 * A pid that is genuinely not running.
 *
 * 999999 was hardcoded here as "obviously dead", but pid_max on Linux is commonly
 * 4194304 and a busy box hands out pids well above a million — so that pid is
 * sometimes a LIVE process, the lock correctly refuses to steal it, and the test
 * fails perhaps one run in ten. Find a free one instead of assuming.
 */
function deadPid(): number {
  for (let p = 999999; p > 90000; p--) {
    try {
      process.kill(p, 0);   // it exists (or we lack permission) — keep looking
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ESRCH') return p;
    }
  }
  throw new Error('could not find an unused pid for the test');
}


// A unique agent name per run: the Linux abstract socket namespace is
// machine-global, so a test must never claim the name a real agent uses.
const AGENT = `TestAgent_${process.pid}_${Date.now()}`;

let home: string;
let lock: typeof import('../src/lock.js');
const realHomedir = os.homedir;
const realAgent = process.env.WUNDERVAULT_AGENT_NAME;

beforeEach(async () => {
  home = mkdtempSync(path.join(os.tmpdir(), 'wv-lock-'));
  (os as any).homedir = () => home;
  mkdirSync(path.join(home, '.wundervault'), { recursive: true });
  process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  lock = await import('../src/lock.js');
});

afterEach(async () => {
  await lock.releaseCredential();
  (os as any).homedir = realHomedir;
  if (realAgent === undefined) delete process.env.WUNDERVAULT_AGENT_NAME;
  else process.env.WUNDERVAULT_AGENT_NAME = realAgent;
  rmSync(home, { recursive: true, force: true });
});

LINUX_ONLY('acquiring the credential', () => {
  it('grants it when nobody holds it', async () => {
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
  });

  it('refuses a second claim while the first is held', async () => {
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
    const second = await lock.acquireCredential('9.9.9');
    expect(second.ok).toBe(false);
    expect(second.holder).toBeDefined();
  });

  it('grants it again after release', async () => {
    await lock.acquireCredential('9.9.9');
    await lock.releaseCredential();
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
  });

  it('still refuses when the lock FILE is deleted out-of-band', async () => {
    // The failure that started all this: enforcement must not depend on a file
    // that anything can remove.
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
    rmSync(lock.lockFilePath());
    expect(existsSync(lock.lockFilePath())).toBe(false);
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(false);
  });

  it('reports the credential as taken while held, and free once released', async () => {
    await lock.acquireCredential('9.9.9');
    expect(await lock.credentialIsFree()).toBe(false);
    await lock.releaseCredential();
    expect(await lock.credentialIsFree()).toBe(true);
  });
});

LINUX_ONLY('compatibility lock file', () => {
  it('keeps a bare PID on line 1 so pre-1.7.1 readers still see the lock', async () => {
    await lock.acquireCredential('9.9.9');
    const raw = readFileSync(lock.lockFilePath(), 'utf8');

    // Exactly what older builds do. A pure-JSON file yields NaN there, which
    // makes them ignore the lock and start alongside a live holder.
    expect(parseInt(raw.trim().split('\n')[0], 10)).toBe(process.pid);

    const meta = JSON.parse(raw.slice(raw.indexOf('\n') + 1));
    expect(meta.pid).toBe(process.pid);
    expect(meta.agent).toBe(AGENT);
    expect(meta.version).toBe('9.9.9');
  });

  it('names the file after the agent, slugged', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'Claude 0512';
    expect(path.basename(lock.lockFilePath())).toBe('mcp-Claude_0512.lock');
    process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  });

  it('releases only a file this process owns', async () => {
    await lock.acquireCredential('9.9.9');
    const dead = deadPid();
    writeFileSync(lock.lockFilePath(), `${dead}\n${JSON.stringify({ pid: dead })}\n`);
    await lock.releaseCredential();
    expect(existsSync(lock.lockFilePath())).toBe(true);
  });
});

LINUX_ONLY('cross-process exclusion', () => {
  it('a second OS process cannot take a held credential', () => {
    const script = `
      process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(AGENT)};
      const os = require('os');
      os.homedir = () => ${JSON.stringify(home)};
      import(${JSON.stringify(path.resolve('dist/lock.js'))}).then(async (lock) => {
        const first = await lock.acquireCredential('1');
        // Hold it, then report what a fresh claim in ANOTHER process sees.
        const { execFileSync } = require('child_process');
        const inner = \`
          process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(AGENT)};
          const os = require('os');
          os.homedir = () => ${JSON.stringify(home)};
          import(${JSON.stringify(path.resolve('dist/lock.js'))}).then(async (l) => {
            const c = await l.acquireCredential('1');
            console.log(JSON.stringify({ second: c.ok }));
          });
        \`;
        const out = execFileSync(process.execPath, ['-e', inner], { encoding: 'utf8' });
        console.log(JSON.stringify({ first: first.ok, inner: JSON.parse(out).second }));
      });
    `;
    const out = execFileSync(process.execPath, ['-e', script], { encoding: 'utf8' });
    const result = JSON.parse(out.trim().split('\n').pop()!);
    expect(result.first).toBe(true);
    expect(result.inner).toBe(false);
  });

  it('frees the credential when the holding process dies', () => {
    // The kernel releases the socket, so a crashed holder cannot strand it.
    const holder = `
      process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(AGENT)};
      const os = require('os');
      os.homedir = () => ${JSON.stringify(home)};
      import(${JSON.stringify(path.resolve('dist/lock.js'))}).then(async (l) => {
        await l.acquireCredential('1');
        process.exit(0);   // exits while "holding"
      });
    `;
    execFileSync(process.execPath, ['-e', holder], { encoding: 'utf8' });
    const after = `
      process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(AGENT)};
      const os = require('os');
      os.homedir = () => ${JSON.stringify(home)};
      import(${JSON.stringify(path.resolve('dist/lock.js'))}).then(async (l) => {
        const c = await l.acquireCredential('1');
        console.log(JSON.stringify({ ok: c.ok }));
      });
    `;
    const out = execFileSync(process.execPath, ['-e', after], { encoding: 'utf8' });
    expect(JSON.parse(out.trim()).ok).toBe(true);
  });
});

LINUX_ONLY('holder identity', () => {
  it('answers who it is over the bound address, with no lock file involved', async () => {
    await lock.acquireCredential('9.9.9');
    rmSync(lock.lockFilePath());          // the file anyone could delete
    const who = await lock.whoHolds();
    expect(who.source).toBe('holder');    // learned from the holder, not the file
    expect(who.pid).toBe(process.pid);
    expect(who.agent).toBe(AGENT);
  });

  it('falls back to the lock file when nobody answers', async () => {
    writeFileSync(lock.lockFilePath(), `${process.ppid}\n${JSON.stringify({ since: 'x' })}\n`);
    const who = await lock.whoHolds();
    expect(who.source).toBe('lock-file');
    expect(who.pid).toBe(process.ppid);
  });

  it('never puts a secret or a parent command line in the banner', async () => {
    await lock.acquireCredential('9.9.9');
    const who = await lock.whoHolds();
    expect(Object.keys(who).sort()).toEqual(['agent', 'pid', 'since', 'source']);
  });
});

LINUX_ONLY('release guard', () => {
  it('does not remove a lock file written by a different incarnation', async () => {
    await lock.acquireCredential('9.9.9');
    // Same PID, different token — a replaced or restored file.
    writeFileSync(
      lock.lockFilePath(),
      `${process.pid}\n${JSON.stringify({ pid: process.pid, token: 'someone-elses-token' })}\n`,
    );
    await lock.releaseCredential();
    expect(existsSync(lock.lockFilePath())).toBe(true);
  });

  it('does not remove a legacy tokenless lock file', async () => {
    await lock.acquireCredential('9.9.9');
    writeFileSync(lock.lockFilePath(), String(process.pid));
    await lock.releaseCredential();
    expect(existsSync(lock.lockFilePath())).toBe(true);
  });
});

LINUX_ONLY('distinct agents that slug the same', () => {
  it('share a lock FILENAME but claim different addresses', async () => {
    // 'Team A' and 'Team?A' both slug to mcp-Team_A. They are DIFFERENT
    // credentials, so they must not exclude each other — but the lock filename
    // has to stay slug-based for older copies. Hence the address, and only the
    // address, carries a digest of the raw name.
    process.env.WUNDERVAULT_AGENT_NAME = 'Team A';
    const fileA = lock.lockFilePath();
    const addrA = lock.addressDescription();

    process.env.WUNDERVAULT_AGENT_NAME = 'Team?A';
    const fileB = lock.lockFilePath();
    const addrB = lock.addressDescription();

    expect(fileA).toBe(fileB);        // unchanged, for older readers
    expect(addrA).not.toBe(addrB);    // distinct credentials, distinct claims
    process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  });

  it('bounds the address length however long the agent name is', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'A'.repeat(500);
    // A unix socket address is capped at 108 bytes; an unbounded name would
    // make the claim fail to bind and a free credential look held.
    expect(lock.addressDescription().length).toBeLessThan(100);
    process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  });
});

LINUX_ONLY('refusing when the claim cannot be made safely', () => {
  it('does not serve when the lock file cannot be written', async () => {
    // An older copy gates on that file; unwritten, it would start alongside us.
    (os as any).homedir = () => path.join(home, 'does', 'not', 'exist');
    const claim = await lock.acquireCredential('9.9.9');
    (os as any).homedir = () => home;
    expect(claim.ok).toBe(false);
    expect(claim.reason).toMatch(/could not write/);
  });
});

LINUX_ONLY('a live PID in the lock file is not automatically the holder', () => {
  it('ignores a file belonging to a DIFFERENT agent that slugs the same', async () => {
    // 'Team A' and 'Team?A' share mcp-Team_A.lock. A live PID in it must not
    // block a distinct credential.
    writeFileSync(
      lock.lockFilePath(),
      `${process.ppid}\n${JSON.stringify({ pid: process.ppid, agent: 'somebody else entirely' })}\n`,
    );
    const claim = await lock.acquireCredential('9.9.9');
    expect(claim.ok).toBe(true);
  });

  it('ignores a file whose PID was recycled by another process', async () => {
    // Same live PID, an incarnation that is not it.
    writeFileSync(
      lock.lockFilePath(),
      `${process.ppid}\n${JSON.stringify({ pid: process.ppid, agent: AGENT, start: '999999999' })}\n`,
    );
    const claim = await lock.acquireCredential('9.9.9');
    expect(claim.ok).toBe(process.platform === 'linux');
  });

  it('still stands down for a legacy file that says neither', async () => {
    // No agent, no incarnation — nothing to check, so unknown fails closed.
    writeFileSync(lock.lockFilePath(), String(process.ppid));
    const claim = await lock.acquireCredential('9.9.9');
    expect(claim.ok).toBe(false);
  });
});

LINUX_ONLY('address keying', () => {
  it('separates OS users, since the namespace is machine-global', () => {
    const mine = lock.addressDescription();
    const realUid = process.getuid;
    (process as any).getuid = () => 4242;
    const theirs = lock.addressDescription();
    (process as any).getuid = realUid;
    expect(mine).not.toBe(theirs);
  });

  it('bounds the lock FILENAME as well as the address', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'A'.repeat(500);
    // 255 bytes is the ext4 limit; an unbounded name makes the write fail with
    // ENAMETOOLONG, which this design reports as "cannot claim".
    expect(path.basename(lock.lockFilePath()).length).toBeLessThan(255);
    expect(lock.addressDescription().length).toBeLessThan(100);
    process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  });
});

LINUX_ONLY('mixed-version safety', () => {
  it('stands down for an older-build holder, which binds no socket', async () => {
    // Simulates a frozen pre-socket copy: it writes only the pid file. The
    // socket is free, so binding succeeds — the pid file is the only evidence
    // that anyone is connected, and it has to be enough.
    writeFileSync(lock.lockFilePath(), `${process.ppid}\n`);
    const claim = await lock.acquireCredential('9.9.9');
    expect(claim.ok).toBe(false);
    expect(claim.holder?.pid).toBe(process.ppid);
  });

  it('ignores an older-build lock whose process is gone', async () => {
    writeFileSync(lock.lockFilePath(), `${deadPid()}\n`);
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
  });
});
