import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

/**
 * Copies of one agent share its connection (SPEC-2.0-shared-agent).
 *
 * The owner's Mac, 2026-10-21: OpenClaw's gateway and its Codex runtime each started a
 * wundervault-mcp for "Bearclaw" in the same second; the second was refused and the chat had no
 * vault tools. In 2.0 the MCP process holds nothing, so same-agent copies share. A holder of
 * another build, or of another agent, is still refused. Run on both lock strategies.
 */

const AGENT = `ShareTest_${process.pid}_${Date.now()}`;
const realHomedir = os.homedir;
const saved: Record<string, string | undefined> = {};
let home: string;
let lock: typeof import('../src/lock.js');
const servers: net.Server[] = [];

function setEnv(k: string, v: string | undefined) {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
}

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

/** A holder of some build on this agent's address. `readyAfterMs`: silent until then, as a
 *  real holder is between binding and writing its banner. */
function fakeHolder(banner: Record<string, unknown>, readyAfterMs = 0): Promise<net.Server> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const s = net.createServer((sock) => {
      if (Date.now() - start < readyAfterMs) return;   // accepted, never answered
      sock.end(JSON.stringify({ protocol: 'wundervault-mcp-holder', since: 'x', account: lock._accountTagForTests(), ...banner }) + '\n');
    });
    s.once('error', reject);
    s.listen(lock._listenOptionsForTests(), () => { servers.push(s); resolve(s); });
  });
}

function closeServer(s: net.Server): Promise<void> {
  return new Promise((r) => { try { s.close(() => r()); } catch { r(); } });
}

const STRATEGIES = process.platform === 'linux' ? ['abstract', 'port'] : ['port'];

for (const strategy of STRATEGIES) {
  describe(`sharing one agent's claim (${strategy})`, () => {
    beforeEach(async () => {
      home = mkdtempSync(path.join(os.tmpdir(), 'wv-share-'));
      (os as any).homedir = () => home;
      mkdirSync(path.join(home, '.wundervault'), { recursive: true });
      setEnv('WUNDERVAULT_AGENT_NAME', AGENT);
      setEnv('WUNDERVAULT_LOCK_STRATEGY', strategy);
      setEnv('WUNDERVAULT_LOCK_PORT', strategy === 'port' ? String(await freePort()) : undefined);
      lock = await import('../src/lock.js');
    });

    afterEach(async () => {
      await lock.releaseCredential();
      for (const s of servers.splice(0)) await closeServer(s);
      (os as any).homedir = realHomedir;
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      for (const k of Object.keys(saved)) delete saved[k];
      rmSync(home, { recursive: true, force: true });
    });

    it('lets a second copy of the same agent share, and the first keeps holding', async () => {
      const first = await lock.acquireCredential('2.0.0');
      expect(first).toMatchObject({ ok: true, role: 'holder' });
      const second = await lock.acquireCredential('2.0.0', { share: true });
      expect(second.ok).toBe(true);
      expect(second.role).toBe('shared');
      expect(second.holder?.pid).toBe(process.pid);
      expect(second.holder?.shares).toBe(true);
      expect(lock.isHolding()).toBe(true);
      expect(existsSync(lock.lockFilePath())).toBe(true);
    });

    it('still refuses a claim that does not ask to share', async () => {
      await lock.acquireCredential('2.0.0');
      expect((await lock.acquireCredential('2.0.0')).ok).toBe(false);
    });

    it('refuses to share with a holder that does not say it can (an older build)', async () => {
      await fakeHolder({ pid: 4242, agent: AGENT });
      const c = await lock.acquireCredential('2.0.0', { share: true });
      expect(c.ok).toBe(false);
      expect(c.holder?.pid).toBe(4242);
    });

    it('refuses to share with a holder of a different agent, as a collision', async () => {
      await fakeHolder({ pid: 4343, agent: AGENT + '_other', shares: 1 });
      const c = await lock.acquireCredential('2.0.0', { share: true });
      expect(c.ok).toBe(false);
      expect(c.reason).toMatch(/different agent/);
    });

    it('refuses to share while a live 1.x copy holds the compatibility file, even if a holder answers (polish r1 F1)', async () => {
      // A holder answers "shares" before it checks for a 1.x copy; a copy joining then must check too.
      // Node itself, not `sleep`: Windows has none (round 2, F1).
      const old = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30000)'], { stdio: 'ignore' });
      try {
        await new Promise((r) => setTimeout(r, 100));
        mkdirSync(path.dirname(lock.lockFilePath()), { recursive: true });
        writeFileSync(lock.lockFilePath(), `${old.pid}\n${JSON.stringify({ agent: AGENT })}\n`, 'utf8');
        await fakeHolder({ pid: 4545, agent: AGENT, shares: 1 });
        const c = await lock.acquireCredential('2.0.0', { share: true });
        expect(c.ok).toBe(false);
        expect(c.holder?.pid).toBe(old.pid);
      } finally { old.kill(); }
    });

    it('waits for a holder that has bound but not started answering, then shares', async () => {
      await fakeHolder({ pid: 4444, agent: AGENT, shares: 1 }, 400);
      const c = await lock.acquireCredential('2.0.0', { share: true });
      expect(c).toMatchObject({ ok: true, role: 'shared' });
      expect(c.holder?.pid).toBe(4444);
    });

    it('takes the claim over once the holder exits, and the compatibility file names it', async () => {
      const holder = await fakeHolder({ pid: 4545, agent: AGENT, shares: 1 });
      const c = await lock.acquireCredential('2.0.0', { share: true });
      expect(c.role).toBe('shared');
      let taken = false;
      const t = lock.startReclaim('2.0.0', () => { taken = true; }, 100);
      try {
        await new Promise((r) => setTimeout(r, 300));
        expect(lock.isHolding()).toBe(false);          // the holder is still there
        servers.splice(servers.indexOf(holder), 1);
        await closeServer(holder);
        for (let i = 0; i < 30 && !taken; i++) await new Promise((r) => setTimeout(r, 100));
        expect(taken).toBe(true);
        expect(lock.isHolding()).toBe(true);
        expect(parseInt(readFileSync(lock.lockFilePath(), 'utf8').split('\n')[0], 10)).toBe(process.pid);
      } finally {
        clearInterval(t);
      }
    });

    it('refuses a silent occupant within about 1.5 s, not several timeouts (round 1, F2)', async () => {
      await fakeHolder({ pid: 4646, agent: AGENT, shares: 1 }, 1e9);   // accepts, never answers
      const t0 = Date.now();
      const c = await lock.acquireCredential('2.0.0', { share: true });
      const took = Date.now() - t0;
      expect(c.ok).toBe(false);
      expect(took).toBeLessThan(2500);
    });

    it('takes the claim when the occupant leaves while being asked (round 1, F1)', async () => {
      const s = await fakeHolder({ pid: 4747, agent: AGENT, shares: 1 }, 1e9);
      setTimeout(() => { servers.splice(servers.indexOf(s), 1); void closeServer(s); }, 300);
      const c = await lock.acquireCredential('2.0.0', { share: true });
      expect(c).toMatchObject({ ok: true, role: 'holder' });
      expect(lock.isHolding()).toBe(true);
    });

    it('takes the claim when the occupant leaves during the LAST attempt (round 2, F1)', async () => {
      // Attempts run at ~0, ~650 and ~1300 ms of the 1.5 s deadline; leaving at ~1400 ms lands
      // inside the final one, which used to return "stranger" without looking again.
      const s = await fakeHolder({ pid: 4949, agent: AGENT, shares: 1 }, 1e9);
      const t0 = Date.now();
      setTimeout(() => { servers.splice(servers.indexOf(s), 1); void closeServer(s); }, 1400);
      const c = await lock.acquireCredential('2.0.0', { share: true });
      expect(Date.now() - t0).toBeGreaterThan(1300);
      expect(c).toMatchObject({ ok: true, role: 'holder' });
    });

    it('refuses to share with a same-name holder under another account (round 1, B2)', async () => {
      await fakeHolder({ pid: 4848, agent: AGENT, shares: 1, account: 'ffffffffffff' });
      const c = await lock.acquireCredential('2.0.0', { share: true });
      expect(c.ok).toBe(false);
      expect(c.holder?.shares).toBe(false);
    });

    it('says it can share in its banner, and nothing more than before', async () => {
      await lock.acquireCredential('2.0.0');
      const who = await lock.whoHolds();
      expect(Object.keys(who).sort()).toEqual(['agent', 'pid', 'shares', 'since', 'source']);
      expect(who.shares).toBe(true);
    });
  });
}


/**
 * Two real processes (round 1, B3): each has its own `held` and incarnation token, so this is
 * where a sharing copy rewriting or removing the holder's compatibility file would show.
 */
describe('sharing across real processes', () => {
  const DIST = path.resolve('dist/lock.js');
  // These processes run the BUILT lock; a dist older than src would test yesterday's code and pass
  // (polish review round 1, broker blind spot B3). Say so instead.
  beforeAll(() => {
    const built = statSync(DIST).mtimeMs, source = statSync(path.resolve('src/lock.ts')).mtimeMs;
    if (built < source) throw new Error('dist/lock.js is older than src/lock.ts: run `npm run build` first');
  });
  const NAME = `ShareProc_${process.pid}_${Date.now()}`;
  let procHome: string;
  let kids: ChildProcess[] = [];

  function holderProcess(): Promise<{ kid: ChildProcess; pid: number }> {
    const code = `
      process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(NAME)};
      const os = require('os'); os.homedir = () => ${JSON.stringify('HOME')};
      import(${JSON.stringify(DIST)}).then(async (l) => {
        const c = await l.acquireCredential('2.0.0');
        console.log(JSON.stringify({ ok: c.ok, role: c.role, pid: process.pid }));
        setInterval(() => {}, 1000);
      });`;
    return new Promise((resolve, reject) => {
      const kid = spawn(process.execPath, ['-e', code.replace('"HOME"', JSON.stringify(procHome))], { stdio: ['ignore', 'pipe', 'inherit'] });
      kids.push(kid);
      kid.stdout!.once('data', (d) => {
        const o = JSON.parse(String(d).trim().split('\n')[0]);
        if (!o.ok) reject(new Error('holder process could not claim')); else resolve({ kid, pid: o.pid });
      });
    });
  }

  function sharerRunsAndExits(): { ok: boolean; role: string } {
    const code = `
      process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(NAME)};
      const os = require('os'); os.homedir = () => ${JSON.stringify('HOME')};
      import(${JSON.stringify(DIST)}).then(async (l) => {
        const c = await l.acquireCredential('2.0.0', { share: true });
        await l.releaseCredential();
        console.log(JSON.stringify({ ok: c.ok, role: c.role }));
        process.exit(0);
      });`;
    const out = execFileSync(process.execPath, ['-e', code.replace('"HOME"', JSON.stringify(procHome))], { encoding: 'utf8' });
    return JSON.parse(out.trim().split('\n').pop()!);
  }

  beforeEach(async () => {
    procHome = mkdtempSync(path.join(os.tmpdir(), 'wv-shareproc-'));
    (os as any).homedir = () => procHome;
    mkdirSync(path.join(procHome, '.wundervault'), { recursive: true });
    setEnv('WUNDERVAULT_AGENT_NAME', NAME);
    setEnv('WUNDERVAULT_LOCK_STRATEGY', undefined);
    setEnv('WUNDERVAULT_LOCK_PORT', undefined);
    lock = await import('../src/lock.js');
  });

  afterEach(async () => {
    await lock.releaseCredential();
    for (const k of kids) { try { k.kill('SIGKILL'); } catch { /* gone */ } }
    kids = [];
    (os as any).homedir = realHomedir;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    for (const k of Object.keys(saved)) delete saved[k];
    rmSync(procHome, { recursive: true, force: true });
  });

  it('a sharing process leaves the holder its address and file, and takes over when it dies', async () => {
    const { kid, pid } = await holderProcess();
    const fileBefore = readFileSync(lock.lockFilePath(), 'utf8');
    expect(parseInt(fileBefore.split('\n')[0], 10)).toBe(pid);

    // Another process shares, then exits: the holder's file is untouched.
    expect(sharerRunsAndExits()).toEqual({ ok: true, role: 'shared' });
    expect(readFileSync(lock.lockFilePath(), 'utf8')).toBe(fileBefore);

    // This process shares too, and takes over once the holder is killed.
    const c = await lock.acquireCredential('2.0.0', { share: true });
    expect(c).toMatchObject({ ok: true, role: 'shared' });
    expect(c.holder?.pid).toBe(pid);
    expect(readFileSync(lock.lockFilePath(), 'utf8')).toBe(fileBefore);
    let taken = false;
    const t = lock.startReclaim('2.0.0', () => { taken = true; }, 100);
    try {
      kid.kill('SIGKILL');
      for (let i = 0; i < 50 && !taken; i++) await new Promise((r) => setTimeout(r, 100));
      expect(taken).toBe(true);
      expect(parseInt(readFileSync(lock.lockFilePath(), 'utf8').split('\n')[0], 10)).toBe(process.pid);
    } finally {
      clearInterval(t);
    }
  }, 20_000);
});
