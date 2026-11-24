/**
 * Jobs that bring a file back (site SPEC-job-file-pull-2026-11-24). Stdout streams into one
 * private file the helper names; size and disk-space stops; nothing partial is ever kept.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import {
  diskReserve, runJob, validateJobOrder, validJobFile, FILE_MAX_BYTES,
  type JobDefinition, type StoredJob,
} from '../src/jobs.js';
import { validateJobProposal } from '../src/job-request.js';
import type { ServerRunner } from '../src/server-setup.js';
import { runSshWithAgent } from '../src/ssh-agent.js';

const fingerprint = 'test-broker-fingerprint';
const now = new Date('2026-03-07T00:00:00.000Z');
const temporary: string[] = [];
const GB = 1024 ** 3;
const plenty = () => ({ free: 500 * GB, total: 1000 * GB });

function directory(): string {
  const dir = fs.mkdtempSync(path.join(process.platform === 'darwin' ? '/tmp' : os.tmpdir(), 'wv-jobf-'));
  temporary.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of temporary.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function definition(patch: Partial<JobDefinition> = {}): JobDefinition {
  return {
    v: 1, type: 'job-set', broker: fingerprint, order_id: 'order_123',
    issued_at: now.toISOString(), expires_at: '2026-03-07T00:10:00.000Z',
    job_id: 'job_12345', version: 1, name: 'Nightly backup', entry_id: 'entry_123',
    destination: 'backup@example.com', argv: ['wv-backup'],
    schedule: { kind: 'daily', time: '03:00', tz: 'UTC' }, timeout_s: 300,
    file: { max_bytes: 64 * 1024 * 1024, keep: 3 },
    ...patch,
  };
}

const stored = (def = definition()): StoredJob => ({ def, agent_id: 'agent_1', state: 'active', applied_at: now.toISOString() });

/** A server that sends `chunks` as its output, then exits with `exitCode`. */
function sends(chunks: Buffer[], exitCode = 0, stderr = ''): ServerRunner {
  return {
    serverRun: vi.fn(async (args) => {
      for (const c of chunks) {
        const stop = args.onStdout?.(c);
        if (stop !== undefined) return { exitCode: 125, stdout: '', stderr: `${stderr}\n${stop}` };
      }
      return { exitCode, stdout: args.onStdout ? '' : Buffer.concat(chunks).toString(), stderr };
    }),
  };
}

const files = (dir: string, ext: string) => fs.existsSync(path.join(dir, 'job_12345'))
  ? fs.readdirSync(path.join(dir, 'job_12345')).filter(n => n.endsWith(`.${ext}`)) : [];

describe('file job definitions', () => {
  it('accepts a file block and keeps it; a text job is unchanged', () => {
    const r = validateJobOrder(definition(), fingerprint, now.getTime());
    expect(r.ok && r.job.file).toEqual({ max_bytes: 64 * 1024 * 1024, keep: 3 });
    const { file: _f, ...text } = definition();
    const t = validateJobOrder(text, fingerprint, now.getTime());
    expect(t.ok && Object.hasOwn(t.job, 'file')).toBe(false);
  });

  it.each([
    [{ max_bytes: 0, keep: 1 }], [{ max_bytes: FILE_MAX_BYTES + 1, keep: 1 }], [{ max_bytes: 1.5, keep: 1 }],
    [{ max_bytes: 10, keep: 0 }], [{ max_bytes: 10, keep: 15 }], [{ max_bytes: 10 }],
    [{ max_bytes: 10, keep: 1, path: '/etc' }], [null], ['big'],
  ])('refuses a bad file block %j', (file) => {
    expect(validJobFile(file)).toBeNull();
    expect(validateJobOrder(definition({ file: file as never }), fingerprint, now.getTime()))
      .toEqual({ ok: false, reason: 'bad file' });
  });

  it('an agent proposal carries the file block, or is refused with the limits', () => {
    const base = { name: 'Backup', entry_id: 'entry_123', destination: 'a@b.example', argv: ['x'],
      schedule: { kind: 'daily', time: '03:00', tz: 'UTC' }, why: 'nightly backup' };
    const ok = validateJobProposal({ ...base, file: { max_bytes: 1000, keep: 7 } });
    expect(ok.ok && ok.proposal.file).toEqual({ max_bytes: 1000, keep: 7 });
    const dflt = validateJobProposal({ ...base, file: { max_bytes: 1000 } });
    expect(dflt.ok && dflt.proposal.file).toEqual({ max_bytes: 1000, keep: 7 });   // review r1 F2
    const bad = validateJobProposal({ ...base, file: { max_bytes: 1000, keep: 99 } });
    expect(bad).toEqual({ ok: false, reason: expect.stringContaining('keep: 1 to 14') });
  });

  it('the reserve is 1 GB or 5% of the drive, whichever is more', () => {
    expect(diskReserve(10 * GB)).toBe(GB);
    expect(diskReserve(1000 * GB)).toBe(50 * GB);
  });
});

describe('a file job run', () => {
  it('keeps binary output byte-identical, private, under a name the helper chose (check 1, 6)', async () => {
    const dir = directory();
    const data = randomBytes(3 * 1024 * 1024 + 17);
    const chunks = [data.subarray(0, 65536), data.subarray(65536, 2_000_000), data.subarray(2_000_000)];
    const run = await runJob(sends(chunks), stored(), 'schedule', dir, () => now, plenty);
    expect(run).toMatchObject({ ok: true, exit_code: 0, bytes: data.length });
    expect(run.sha256).toBe(createHash('sha256').update(data).digest('hex'));
    const kept = path.join(dir, 'job_12345', `${run.run_id}.file`);
    expect(fs.readFileSync(kept).equals(data)).toBe(true);
    expect(fs.statSync(kept).mode & 0o777).toBe(0o600);
    expect(fs.statSync(path.join(dir, 'job_12345')).mode & 0o777).toBe(0o700);
    const record = JSON.parse(fs.readFileSync(path.join(dir, 'job_12345', `${run.run_id}.json`), 'utf8'));
    expect(record).toMatchObject({ bytes: data.length, sha256: run.sha256 });
    expect(files(dir, 'part')).toEqual([]);
    expect(files(dir, 'out')).toEqual([]);
  });

  it('stops past max_bytes, keeps nothing new and leaves earlier copies (check 3, 12)', async () => {
    const dir = directory();
    const first = await runJob(sends([Buffer.from('good copy')]), stored(), 'schedule', dir, () => now, plenty);
    expect(first.ok).toBe(true);
    const def = definition({ file: { max_bytes: 100_000, keep: 3 } });
    const ops = sends(Array.from({ length: 50 }, () => randomBytes(65536)));
    const run = await runJob(ops, stored(def), 'schedule', dir, () => now, plenty);
    expect(run).toMatchObject({ ok: false, exit_code: -1, error: expect.stringContaining('bigger than its limit') });
    expect(run.bytes).toBeLessThanOrEqual(100_000);
    expect(files(dir, 'file')).toEqual([`${first.run_id}.file`]);
    expect(files(dir, 'part')).toEqual([]);
    expect(run.tail).toContain('bigger than its limit');
  });

  it('stops before the drive falls below the reserve, and still returns the run (check 4)', async () => {
    const dir = directory();
    let free = GB + 20 * 1024 * 1024;           // 20 MB above the reserve of a 10 GB drive
    const space = () => ({ free, total: 10 * GB });
    const chunk = randomBytes(1024 * 1024);
    const ops: ServerRunner = {
      serverRun: vi.fn(async (args) => {
        for (let i = 0; i < 40; i++) {
          const stop = args.onStdout!(chunk);
          free -= chunk.length;
          if (stop !== undefined) return { exitCode: 125, stdout: '', stderr: stop };
        }
        return { exitCode: 0, stdout: '', stderr: '' };
      }),
    };
    const run = await runJob(ops, stored(), 'schedule', dir, () => now, space);
    expect(run).toMatchObject({ ok: false, error: expect.stringContaining('not enough disk space') });
    expect(files(dir, 'file')).toEqual([]);
    expect(files(dir, 'part')).toEqual([]);
  });

  it('checks the space before every write, not every few MB (review r1 F3)', async () => {
    const dir = directory();
    let free = GB + 9 * 1024 * 1024;
    const ops: ServerRunner = {
      serverRun: vi.fn(async (args) => {
        expect(args.onStdout!(Buffer.alloc(65536))).toBeUndefined();
        free = GB + 32 * 1024;                   // another program filled the drive meanwhile
        const stop = args.onStdout!(Buffer.alloc(65536));
        return stop === undefined ? { exitCode: 0, stdout: '', stderr: '' } : { exitCode: 125, stdout: '', stderr: stop };
      }),
    };
    const run = await runJob(ops, stored(), 'schedule', dir, () => now, () => ({ free, total: 10 * GB }));
    expect(run).toMatchObject({ ok: false, error: expect.stringContaining('not enough disk space') });
    expect(files(dir, 'file')).toEqual([]);
  });

  it('a failure removing OLD copies never undoes the new one (review r1 F4)', async () => {
    const dir = directory();
    const def = definition({ file: { max_bytes: 1024, keep: 1 } });
    const first = await runJob(sends([Buffer.from('old')]), stored(def), 'schedule', dir, () => now, plenty);
    fs.utimesSync(path.join(dir, 'job_12345', `${first.run_id}.file`), 1, 1);
    const real = fs.unlinkSync;
    vi.spyOn(fs, 'unlinkSync').mockImplementation(((p: fs.PathLike) => {
      if (String(p).endsWith(`${first.run_id}.json`)) throw Object.assign(new Error('immutable'), { code: 'EPERM' });
      return real(p);
    }) as typeof fs.unlinkSync);
    const run = await runJob(sends([Buffer.from('new')]), stored(def), 'schedule', dir, () => now, plenty);
    expect(run.ok).toBe(true);
    expect(fs.readFileSync(path.join(dir, 'job_12345', `${run.run_id}.file`), 'utf8')).toBe('new');
  });

  it('refuses to start when the drive is already at the reserve', async () => {
    const dir = directory();
    const ops = sends([Buffer.from('x')]);
    const run = await runJob(ops, stored(), 'schedule', dir, () => now, () => ({ free: GB - 1, total: 10 * GB }));
    expect(run).toMatchObject({ ok: false, error: expect.stringContaining('not enough disk space') });
    expect(ops.serverRun).not.toHaveBeenCalled();
  });

  it('a write that hits a full disk (ENOSPC) is reported as disk space, not a crash', async () => {
    const dir = directory();
    const real = fs.writeSync;
    vi.spyOn(fs, 'writeSync').mockImplementation(((fd: number, ...rest: unknown[]) => {
      if (typeof rest[0] === 'object' && Buffer.isBuffer(rest[0])) throw Object.assign(new Error('no space'), { code: 'ENOSPC' });
      return (real as (...a: unknown[]) => number)(fd, ...rest);
    }) as typeof fs.writeSync);
    const run = await runJob(sends([Buffer.from('data')]), stored(), 'schedule', dir, () => now, plenty);
    expect(run).toMatchObject({ ok: false, error: expect.stringContaining('not enough disk space') });
    expect(files(dir, 'part')).toEqual([]);
  });

  it('a non-zero exit keeps nothing and leaves earlier copies (check 5)', async () => {
    const dir = directory();
    const first = await runJob(sends([Buffer.from('good')]), stored(), 'schedule', dir, () => now, plenty);
    const run = await runJob(sends([Buffer.from('half a backu')], 3, 'sqlite3: disk I/O error'), stored(), 'schedule', dir, () => now, plenty);
    expect(run).toMatchObject({ ok: false, exit_code: 3 });
    expect(run.tail).toContain('disk I/O error');
    expect(run.tail).not.toContain('half a backu');
    expect(files(dir, 'file')).toEqual([`${first.run_id}.file`]);
    expect(files(dir, 'part')).toEqual([]);
  });

  it('keeps only the last `keep` copies (check 7)', async () => {
    const dir = directory();
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const run = await runJob(sends([Buffer.from(`copy ${i}`)]), stored(), 'schedule', dir, () => now, plenty);
      ids.push(run.run_id);
      const f = path.join(dir, 'job_12345', `${run.run_id}.file`);
      fs.utimesSync(f, i + 1, i + 1);
    }
    expect(files(dir, 'file').sort()).toEqual(ids.slice(2).map(id => `${id}.file`).sort());
    expect(files(dir, 'json')).toHaveLength(3);
  });

  it('removes a partial copy a crash left behind', async () => {
    const dir = directory();
    fs.mkdirSync(path.join(dir, 'job_12345'), { recursive: true, mode: 0o700 });
    const stale = path.join(dir, 'job_12345', `${'A'.repeat(22)}.part`);
    fs.writeFileSync(stale, 'partial');
    await runJob(sends([Buffer.from('x')]), stored(), 'schedule', dir, () => now, plenty);
    expect(fs.existsSync(stale)).toBe(false);
  });

  it('refuses a job folder that is a symlink (check 6)', async () => {
    const dir = directory();
    const elsewhere = directory();
    fs.symlinkSync(elsewhere, path.join(dir, 'job_12345'));
    const ops = sends([Buffer.from('x')]);
    const run = await runJob(ops, stored(), 'schedule', dir, () => now, plenty);
    expect(run.ok).toBe(false);
    expect(ops.serverRun).not.toHaveBeenCalled();
    expect(fs.readdirSync(elsewhere)).toEqual([]);
  });

  it('refuses a job folder owned by another account (review r2 F1)', async () => {
    const dir = directory();
    fs.mkdirSync(path.join(dir, 'job_12345'), { mode: 0o700 });
    const real = fs.lstatSync;
    vi.spyOn(fs, 'lstatSync').mockImplementation(((p: fs.PathLike, o?: unknown) => {
      const st = (real as (p: fs.PathLike, o?: unknown) => fs.Stats)(p, o);
      return String(p).endsWith('job_12345') ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: st.uid + 1 }) : st;
    }) as typeof fs.lstatSync);
    const ops = sends([Buffer.from('x')]);
    const run = await runJob(ops, stored(), 'schedule', dir, () => now, plenty);
    expect(run).toMatchObject({ ok: false, error: expect.stringContaining('wrong owner') });
    expect(ops.serverRun).not.toHaveBeenCalled();
  });

  it('text jobs still keep text output as before (check 13)', async () => {
    const dir = directory();
    const { file: _f, ...text } = definition();
    const run = await runJob(sends([Buffer.from('report\n')]), stored(text as JobDefinition), 'schedule', dir, () => now, plenty);
    expect(run.ok).toBe(true);
    expect(fs.readFileSync(path.join(dir, 'job_12345', `${run.run_id}.out`), 'utf8')).toBe('report\n');
  });
});

describe('streaming through the real ssh runner', () => {
  const withFakeSsh = async <T>(script: string, fn: () => Promise<T>): Promise<T> => {
    const bin = directory();
    fs.writeFileSync(path.join(bin, 'ssh'), `#!/bin/sh\n${script}\n`, { mode: 0o755 });
    const saved = process.env.PATH;
    process.env.PATH = `${bin}:${saved}`;
    try { return await fn(); } finally { process.env.PATH = saved; }
  };
  const viaSsh: ServerRunner = {
    serverRun: async (args) => runSshWithAgent({
      op: { kind: 'ssh', destination: 'u@h', remoteArgv: args.argv('') }, socketPath: '/nonexistent',
      publicKeyPath: '/nonexistent', timeoutMs: args.timeoutMs ?? 20_000,
      ...(args.onStdout ? { onStdout: args.onStdout } : {}),
    }),
  };

  it('50 MB of binary arrives identical with bounded memory (checks 1, 2)', async () => {
    const dir = directory();
    const src = path.join(directory(), 'src.bin');
    fs.writeFileSync(src, randomBytes(50 * 1024 * 1024));
    const want = createHash('sha256').update(fs.readFileSync(src)).digest('hex');
    if (global.gc) global.gc();
    const before = process.memoryUsage().rss;
    let peak = before;
    const t = setInterval(() => { peak = Math.max(peak, process.memoryUsage().rss); }, 5);
    const run = await withFakeSsh(`cat '${src}'`, () => runJob(viaSsh, stored(), 'schedule', dir, () => now, plenty));
    clearInterval(t);
    expect(run).toMatchObject({ ok: true, bytes: 50 * 1024 * 1024, sha256: want });
    expect(peak - before).toBeLessThan(64 * 1024 * 1024);
  });

  it('a server that never stops is cut at max_bytes and the command is killed (check 12)', async () => {
    const dir = directory();
    const def = definition({ file: { max_bytes: 5 * 1024 * 1024, keep: 1 } });
    const t0 = Date.now();
    const run = await withFakeSsh('exec cat /dev/zero', () => runJob(viaSsh, stored(def), 'schedule', dir, () => now, plenty));
    expect(run).toMatchObject({ ok: false, error: expect.stringContaining('bigger than its limit') });
    expect(run.bytes).toBeLessThanOrEqual(5 * 1024 * 1024);
    expect(Date.now() - t0).toBeLessThan(10_000);
    expect(files(dir, 'file')).toEqual([]);
    expect(files(dir, 'part')).toEqual([]);
  });

  it('the timeout still ends a file run', async () => {
    const dir = directory();
    const def = definition({ timeout_s: 10 });
    const ops: ServerRunner = { serverRun: (args) => viaSsh.serverRun({ ...args, timeoutMs: 300 }) };
    const run = await withFakeSsh('printf start; sleep 30', () => runJob(ops, stored(def), 'schedule', dir, () => now, plenty));
    expect(run).toMatchObject({ ok: false, exit_code: 124 });
    expect(files(dir, 'part')).toEqual([]);
  });
});

describe('vault_job_request checks the helper has room (check 10)', () => {
  it('refuses when max_bytes × keep does not fit above the reserve, and says how much is free', async () => {
    const { BrokerOps } = await import('../src/broker-ops.js');
    const ops = new BrokerOps('Tester', 'k', Buffer.alloc(32).toString('base64'), 'http://127.0.0.1:1', null);
    const posted: unknown[] = [];
    (ops as unknown as { api: unknown }).api = {
      ensureVaultKey: async () => new Uint8Array(32),
      postJobRequest: async (b: unknown) => { posted.push(b); return { id: 'r1', state: 'pending', expires_at: 'x' }; },
    };
    (ops as unknown as { jobKeyCheck: unknown }).jobKeyCheck = async () => ({ ok: true });
    (ops as unknown as { record: unknown }).record = () => {};
    const base = { name: 'Backup', entry_id: 'entry_123', destination: 'a@b.example', argv: ['x'],
      schedule: { kind: 'daily', time: '03:00', tz: 'UTC' }, why: 'nightly backup' };
    try {
      BrokerOps.jobDiskSpace = () => ({ free: 5 * GB, total: 10 * GB });   // 4 GB above the reserve
      const no = await ops.jobRequest({ ...base, file: { max_bytes: GB, keep: 5 } });
      expect(no.error).toMatch(/Not enough disk space.*5\.0 GB free.*1\.0 GB must stay free.*6\.0 GB/);
      expect(posted).toEqual([]);
      // keep 4 needs 5 GB (one more copy while the oldest is still kept, review r1 B1): refused.
      expect((await ops.jobRequest({ ...base, file: { max_bytes: GB, keep: 4 } })).error).toMatch(/Not enough/);
      const yes = await ops.jobRequest({ ...base, file: { max_bytes: GB, keep: 3 } });
      expect(yes).toMatchObject({ request_id: 'r1' });
      expect(await ops.jobRequest(base)).toMatchObject({ request_id: 'r1' });   // text jobs: no check
      expect(posted).toHaveLength(2);
    } finally {
      BrokerOps.jobDiskSpace = null;
    }
  });
});

describe('limits the agent can ask for (owner 11-24: higher limits need only approval)', () => {
  it('a 6-hour, 1 TB file job is a valid order; beyond that is refused', () => {
    const big = validateJobOrder(definition({ timeout_s: 6 * 3600, file: { max_bytes: 1024 ** 4, keep: 1 } }), fingerprint, now.getTime());
    expect(big.ok).toBe(true);
    expect(validateJobOrder(definition({ timeout_s: 6 * 3600 + 1 }), fingerprint, now.getTime()))
      .toEqual({ ok: false, reason: 'bad timeout' });
  });

  it('the signing session outlives a long job, so it is not cut at 10 minutes', async () => {
    const { BrokerOps } = await import('../src/broker-ops.js');
    const ops = new BrokerOps('Tester', 'k', Buffer.alloc(32).toString('base64'), 'http://127.0.0.1:1', null);
    let ttl = 0;
    (ops as unknown as { sshAgentOpen: unknown }).sshAgentOpen = async (a: { ttlSeconds: number }) => {
      ttl = a.ttlSeconds; return { error: 'stop here' };
    };
    await ops.serverRun({ entryId: 'e', destination: 'a@b', purpose: 'p', argv: () => ['x'], timeoutMs: 3 * 3600_000 });
    expect(ttl).toBeGreaterThanOrEqual(3 * 3600);
    await ops.serverRun({ entryId: 'e', destination: 'a@b', purpose: 'p', argv: () => ['x'], timeoutMs: 60_000 });
    expect(ttl).toBe(600);
  });
});
