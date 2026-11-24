import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  JobStore, dueKind, lastSlot, openJobOrder, runDue, runJob, validateJobOrder,
  type JobDefinition, type JobRoute, type JobRun, type JobStatus, type StoredJob,
} from '../src/jobs.js';
import { pollOnce, type BrokerUpdateDeps } from '../src/broker-update.js';
import { sealForOwner, type ServerRunner } from '../src/server-setup.js';

const fingerprint = 'test-broker-fingerprint';
const agentId = 'agent_123';
const now = new Date('2026-03-07T00:00:00.000Z');
const temporary: string[] = [];

function directory(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-jobs-'));
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
    job_id: 'job_12345', version: 1, name: 'Nightly report', entry_id: 'entry_123',
    destination: 'backup@example.com', argv: ['printf', '%s', 'a b;$HOME'],
    schedule: { kind: 'daily', time: '03:00', tz: 'UTC' }, timeout_s: 300,
    ...patch,
  };
}

function stored(def = definition()): StoredJob {
  return { def, agent_id: agentId, state: 'active', applied_at: now.toISOString() };
}

function storeIn(dir: string, def = definition()): JobStore {
  const store = new JobStore(path.join(dir, 'jobs.json'));
  expect(store.apply(def, agentId, now)).toEqual({ ok: true });
  return store;
}

function success(stdout = 'report\n'): ServerRunner {
  return { serverRun: vi.fn(async () => ({ exitCode: 0, stdout, stderr: '' })) };
}

describe('job orders', () => {
  it('accepts the exact definition and canonicalizes an explicit default port', () => {
    const result = validateJobOrder(definition({ destination: 'backup@example.com:22' }), fingerprint, now.getTime());
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.job.destination).toBe('backup@example.com');
  });

  it.each([
    ['extra key', { ...definition(), extra: true }, 'malformed'],
    ['missing timeout', Object.fromEntries(Object.entries(definition()).filter(([key]) => key !== 'timeout_s')), 'malformed'],
    ['wrong broker', definition({ broker: 'another' }), 'wrong broker'],
    ['bad id', definition({ job_id: '../output' }), 'malformed'],
    ['bad version', definition({ version: 0 }), 'malformed'],
    ['huge version', definition({ version: 1e9 + 1 }), 'malformed'],
    ['bad name', definition({ name: 'two\nlines' }), 'malformed'],
    ['bad destination', definition({ destination: 'root@host;true' }), 'bad destination'],
    ['empty argv', definition({ argv: [] }), 'bad argv'],
    ['NUL', definition({ argv: ['a\0b'] }), 'bad argv'],
    ['long argument', definition({ argv: ['x'.repeat(4097)] }), 'bad argv'],
    ['many arguments', definition({ argv: Array(65).fill('x') }), 'bad argv'],
    ['large total', definition({ argv: Array(5).fill('x'.repeat(4096)) }), 'bad argv'],
    ['UTF-8 byte total', definition({ argv: Array(3).fill('é'.repeat(4096)) }), 'bad argv'],
    ['bad timezone', definition({ schedule: { kind: 'daily', time: '03:00', tz: 'Not/A_Zone' } }), 'bad timezone'],
    ['bad time', definition({ schedule: { kind: 'daily', time: '24:00', tz: 'UTC' } }), 'bad schedule'],
    ['bad hours', definition({ schedule: { kind: 'every', hours: 25, tz: 'UTC' } }), 'bad schedule'],
    ['fractional hours', definition({ schedule: { kind: 'every', hours: 1.5, tz: 'UTC' } }), 'bad schedule'],
    ['timeout', definition({ timeout_s: 601 }), 'bad timeout'],
    ['short timeout', definition({ timeout_s: 9 }), 'bad timeout'],
    ['expired', definition({ expires_at: now.toISOString() }), 'malformed'],
    ['long expiry', definition({ expires_at: '2026-03-07T00:17:00.000Z' }), 'malformed'],
    ['future issue', definition({ issued_at: '2026-03-07T00:03:00.000Z' }), 'expired'],
  ])('refuses %s', (_name, value, reason) => {
    expect(validateJobOrder(value, fingerprint, now.getTime())).toEqual({ ok: false, reason });
  });

  it('checks schedule keys, finite clocks and expiry at the current instant', () => {
    const extra = { ...definition(), schedule: { kind: 'every', hours: 2, tz: 'UTC', extra: 1 } };
    expect(validateJobOrder(extra, fingerprint, now.getTime())).toEqual({ ok: false, reason: 'bad schedule' });
    expect(validateJobOrder(definition(), fingerprint, NaN)).toEqual({ ok: false, reason: 'malformed' });
    expect(validateJobOrder(definition(), fingerprint, Date.parse('2026-03-07T00:10:00Z')))
      .toEqual({ ok: false, reason: 'expired' });
  });

  it('opens large valid job envelopes with the existing AAD, but rejects another key or type', () => {
    const key = randomBytes(32);
    const def = definition({ argv: Array(4).fill('\x01'.repeat(4096)) });
    const sealed = sealForOwner(key, `wv-broker-order-v1|${fingerprint}`, def);
    expect(sealed.ciphertext.length).toBeGreaterThan(16_384);
    expect(openJobOrder(sealed.ciphertext, sealed.nonce, key, fingerprint, now.getTime())).toEqual({ ok: true, job: def });
    expect(openJobOrder(sealed.ciphertext, sealed.nonce, randomBytes(32), fingerprint, now.getTime()))
      .toEqual({ ok: false, reason: 'bad seal' });
    const wrong = sealForOwner(key, `wv-broker-order-v1|${fingerprint}`, { ...def, type: 'setup' });
    expect(openJobOrder(wrong.ciphertext, wrong.nonce, key, fingerprint, now.getTime()))
      .toEqual({ ok: false, reason: 'kind mismatch' });
  });
});

describe('JobStore', () => {
  it('persists privately, replaces atomically, keeps state and refuses old versions', () => {
    const dir = directory();
    const file = path.join(dir, 'jobs.json');
    const store = storeIn(dir);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    store.setState('job_12345', 'paused');
    const fd = fs.openSync(file, 'r');
    const before = fs.readFileSync(fd, 'utf8');
    try {
      expect(store.apply(definition({ version: 2 }), agentId, now)).toEqual({ ok: true });
      // The old file, read from its start through the handle opened before the rewrite.
      const buf = Buffer.alloc(before.length + 64);
      expect(buf.subarray(0, fs.readSync(fd, buf, 0, buf.length, 0)).toString('utf8')).toBe(before);
    } finally {
      fs.closeSync(fd);
    }
    expect(new JobStore(file).get('job_12345')?.state).toBe('paused');
    expect(store.apply(definition({ version: 2 }), agentId, now)).toEqual({ ok: false, reason: 'older version' });
    expect(store.apply(definition(), agentId, now)).toEqual({ ok: false, reason: 'older version' });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    expect(fs.readdirSync(dir)).toEqual(['jobs.json']);
    store.remove('job_12345');
    expect(store.entries()).toEqual([]);
  });

  it('does not replace an unreadable or corrupt store with an empty one', () => {
    const file = path.join(directory(), 'jobs.json');
    fs.writeFileSync(file, '{broken');
    const store = new JobStore(file);
    expect(() => store.entries()).toThrow();
    expect(() => store.apply(definition(), agentId, now)).toThrow();
    expect(fs.readFileSync(file, 'utf8')).toBe('{broken');
  });

  it('does not let a different agent take over an existing job', () => {
    const store = storeIn(directory());
    expect(store.apply(definition({ version: 2 }), 'agent_456', now))
      .toEqual({ ok: false, reason: 'wrong agent' });
  });
});

describe('scheduled slots', () => {
  it('finds UTC daily slots and runs only once at the scheduled time', () => {
    const job = stored();
    expect(lastSlot(new Date('2026-03-07T02:59:59Z'), job.def.schedule)?.toISOString())
      .toBe('2026-03-06T03:00:00.000Z');
    expect(dueKind(job, new Date('2026-03-07T02:59:59Z'))).toBeNull();
    const at = new Date('2026-03-07T03:00:00Z');
    expect(dueKind(job, at)).toBe('schedule');
    job.last_scheduled = at.toISOString();
    expect(dueKind(job, new Date('2026-03-07T23:00:00Z'))).toBeNull();
    expect(dueKind(job, new Date('2026-03-08T03:00:00Z'))).toBe('schedule');
  });

  it('advances a spring gap to the next valid minute', () => {
    const schedule = { kind: 'daily' as const, time: '02:30', tz: 'America/Los_Angeles' };
    expect(lastSlot(new Date('2026-03-08T09:59:00Z'), schedule)?.toISOString())
      .toBe('2026-03-07T10:30:00.000Z');
    expect(lastSlot(new Date('2026-03-08T10:00:00Z'), schedule)?.toISOString())
      .toBe('2026-03-08T10:00:00.000Z');
    expect(lastSlot(new Date('2026-03-09T10:00:00Z'), schedule)?.toISOString())
      .toBe('2026-03-09T09:30:00.000Z');
  });

  it('uses the first occurrence during a fall overlap, not the second', () => {
    const schedule = { kind: 'daily' as const, time: '01:30', tz: 'America/Los_Angeles' };
    expect(lastSlot(new Date('2026-11-01T08:29:00Z'), schedule)?.toISOString())
      .toBe('2026-10-31T08:30:00.000Z');
    expect(lastSlot(new Date('2026-11-01T08:30:00Z'), schedule)?.toISOString())
      .toBe('2026-11-01T08:30:00.000Z');
    expect(lastSlot(new Date('2026-11-01T09:45:00Z'), schedule)?.toISOString())
      .toBe('2026-11-01T08:30:00.000Z');
  });

  it('anchors every-N-hours to application time', () => {
    const schedule = { kind: 'every' as const, hours: 3, tz: 'America/Los_Angeles' };
    const anchor = '2026-03-07T00:15:00.000Z';
    expect(lastSlot(new Date('2026-03-07T00:14:00Z'), schedule, anchor)).toBeNull();
    expect(lastSlot(new Date('2026-03-07T03:14:00Z'), schedule, anchor)?.toISOString()).toBe(anchor);
    expect(lastSlot(new Date('2026-03-07T06:20:00Z'), schedule, anchor)?.toISOString())
      .toBe('2026-03-07T06:15:00.000Z');
    const job = { ...stored(definition({ schedule })), applied_at: anchor };
    expect(dueKind(job, new Date(anchor))).toBeNull();
    expect(dueKind(job, new Date('2026-03-07T03:15:00Z'))).toBe('schedule');
  });

  it('coalesces three missed days into one catch-up and never runs a paused job', () => {
    const job = stored();
    const later = new Date('2026-03-10T05:00:00Z');
    expect(dueKind(job, later)).toBe('catch-up');
    job.last_scheduled = lastSlot(later, job.def.schedule)!.toISOString();
    expect(dueKind(job, later)).toBeNull();
    job.state = 'paused';
    expect(dueKind(job, new Date('2026-03-11T03:00:00Z'))).toBeNull();
    job.state = 'deleted';
    expect(dueKind(job, new Date('2026-03-11T03:00:00Z'))).toBeNull();
  });
});

describe('runJob', () => {
  it('uses the fixed argv, purpose and timeout without an offer, and keeps five private outputs', async () => {
    const dir = directory();
    const ops = success();
    let clock = now.getTime();
    const ids: string[] = [];
    for (let i = 0; i < 6; i++) {
      const run = await runJob(ops, stored(), 'schedule', dir, () => new Date(clock += 1000));
      ids.push(run.run_id);
      expect(run.ok).toBe(true);
      const file = path.join(dir, 'job_12345', `${run.run_id}.out`);
      expect(fs.readFileSync(file, 'utf8')).toBe('report\n');
      expect(fs.statSync(file).mode & 0o777).toBe(0o600);
      // Give retention a deterministic age order, independent of filesystem timestamp precision.
      fs.utimesSync(file, i + 1, i + 1);
    }
    const args = vi.mocked(ops.serverRun).mock.calls[0]![0];
    expect(args.entryId).toBe('entry_123');
    expect(args.destination).toBe('backup@example.com');
    expect(args.purpose).toBe('job: Nightly report');
    expect(args.argv('unused')).toEqual(definition().argv);
    expect(args.timeoutMs).toBe(300_000);
    // Never waits for an owner's approval (review r1 B4).
    expect((args as { noAsk?: boolean }).noAsk).toBe(true);
    expect(Object.hasOwn(args, 'offer')).toBe(false);
    const jobDir = path.join(dir, 'job_12345');
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    expect(fs.statSync(jobDir).mode & 0o777).toBe(0o700);
    expect(fs.readdirSync(jobDir).filter(name => name.endsWith('.out'))).toHaveLength(5);
    expect(fs.readdirSync(jobDir).filter(name => name.endsWith('.json'))).toHaveLength(5);
    expect(fs.existsSync(path.join(jobDir, `${ids[0]}.out`))).toBe(false);
  });

  it('caps output by bytes, while counting the full UTF-8 output', async () => {
    const dir = directory();
    const stdout = 'é'.repeat(600_000);
    const run = await runJob(success(stdout), stored(), 'catch-up', dir);
    expect(run.bytes).toBe(Buffer.byteLength(stdout));
    expect(fs.statSync(path.join(dir, 'job_12345', `${run.run_id}.out`)).size).toBe(1024 * 1024);
  });

  it.each(['admin access required', 'tier-2 approval required', 'host not approved'])(
    'records an operation refusal locally: %s', async reason => {
      const dir = directory();
      const ops: ServerRunner = { serverRun: async () => ({ error: `${reason}\nprivate detail` }) };
      const run = await runJob(ops, stored(), 'run-now', dir);
      expect(run).toMatchObject({ ok: false, exit_code: -1, error: reason, bytes: 0 });
      const saved = JSON.parse(fs.readFileSync(path.join(dir, 'job_12345', `${run.run_id}.json`), 'utf8'));
      expect(saved.error).toBe(reason);
      expect(fs.statSync(path.join(dir, 'job_12345', `${run.run_id}.json`)).mode & 0o777).toBe(0o600);
    },
  );

  it('also handles thrown operation errors and nonzero SSH exits', async () => {
    const ops: ServerRunner = { serverRun: async () => { throw new Error('approval required\nsecond line'); } };
    expect(await runJob(ops, stored(), 'schedule', directory()))
      .toMatchObject({ ok: false, exit_code: -1, error: 'approval required' });
    const failed: ServerRunner = { serverRun: async () => ({ exitCode: 23, stdout: 'partial', stderr: 'failure' }) };
    expect(await runJob(failed, stored(), 'schedule', directory()))
      .toMatchObject({ ok: false, exit_code: 23, bytes: 7 });
  });
});

function routeFor(dir: string, statuses: JobStatus[], ops = success()): JobRoute {
  return {
    agent_id: agentId, outputDir: path.join(dir, 'output'), ops,
    getJobs: vi.fn(async () => ({ jobs: statuses })),
    postJobRun: vi.fn(async (_id: string, _body: JobRun) => {}),
    authorize: vi.fn(async () => ({ ok: true as const })),
    recordRun: vi.fn(async () => {}),
  };
}

describe('runJob output storage (review r1 F4)', () => {
  it('still returns the run when its output cannot be kept', async () => {
    const dir = directory();
    fs.writeFileSync(path.join(dir, 'blocked'), 'a file where the output folder should be');
    const run = await runJob(success(), stored(), 'schedule', path.join(dir, 'blocked'));
    expect(run.ok).toBe(true);
    expect(run.error).toMatch(/^output not kept: /);
  });
});

describe('runDue', () => {
  it('runs jobs as last known when the site cannot be reached (review r1 B1)', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const route = routeFor(dir, []);
    route.getJobs = vi.fn(async () => { throw new Error('site down'); });
    await runDue({ store, routes: [route], now: new Date('2026-03-07T03:00:00Z'), running: new Set() });
    expect(route.ops.serverRun).toHaveBeenCalledTimes(1);
    expect(store.get('job_12345')).toBeDefined();
  });

  it('drops a job the site no longer lists, without running it (review r1 F2)', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const route = routeFor(dir, []);
    await runDue({ store, routes: [route], now: new Date('2026-03-07T03:00:00Z'), running: new Set() });
    expect(route.ops.serverRun).not.toHaveBeenCalled();
    expect(store.get('job_12345')).toBeUndefined();
  });


  it('persists a slot before SSH starts and does not repeat it after restart', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const at = new Date('2026-03-07T03:00:00Z');
    const ops: ServerRunner = {
      serverRun: vi.fn(async () => {
        expect(new JobStore(path.join(dir, 'jobs.json')).get('job_12345')?.last_scheduled).toBe(at.toISOString());
        return { exitCode: 0, stdout: 'secret report', stderr: '' };
      }),
    };
    const route = routeFor(dir, [{ id: 'job_12345', version: 1, state: 'active', run_now: false }], ops);
    await runDue({ store, routes: [route], now: at, running: new Set() });
    await runDue({ store: new JobStore(path.join(dir, 'jobs.json')), routes: [route], now: at, running: new Set() });
    expect(ops.serverRun).toHaveBeenCalledTimes(1);
    expect(route.recordRun).toHaveBeenCalledTimes(1);
    expect(route.postJobRun).toHaveBeenCalledTimes(1);
    const body = vi.mocked(route.postJobRun).mock.calls[0]![1];
    expect(Object.keys(body).sort()).toEqual([
      'bytes', 'exit_code', 'finished_at', 'ok', 'run_id', 'started_at', 'trigger',
    ]);
    expect(JSON.stringify(body)).not.toContain('secret report');
  });

  it('rechecks authorization and sends no local error to the site', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const route = routeFor(dir, [{ id: 'job_12345', version: 1, state: 'active', run_now: true }]);
    route.authorize = async () => ({ ok: false, reason: 'admin key refused' });
    await runDue({ store, routes: [route], now, running: new Set() });
    expect(route.ops.serverRun).not.toHaveBeenCalled();
    expect(vi.mocked(route.recordRun).mock.calls[0]![1]).toMatchObject({ error: 'admin key refused' });
    expect(vi.mocked(route.postJobRun).mock.calls[0]![1]).toMatchObject({ ok: false, exit_code: -1 });
    expect(Object.hasOwn(vi.mocked(route.postJobRun).mock.calls[0]![1], 'error')).toBe(false);
  });

  it('rate limits run-now, refreshes pause/delete, and retries a post without rerunning', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const statuses: JobStatus[] = [{ id: 'job_12345', version: 1, state: 'active', run_now: true }];
    const route = routeFor(dir, statuses);
    vi.mocked(route.postJobRun).mockRejectedValueOnce(new Error('offline'));
    const running = new Set<string>();
    await runDue({ store, routes: [route], now, running });
    expect(store.get('job_12345')?.pending_runs).toHaveLength(1);
    await runDue({ store, routes: [route], now: new Date(now.getTime() + 60_000), running });
    expect(route.ops.serverRun).toHaveBeenCalledTimes(1);
    expect(route.postJobRun).toHaveBeenCalledTimes(2);
    expect(store.get('job_12345')?.pending_runs).toBeUndefined();
    await runDue({ store, routes: [route], now: new Date(now.getTime() + 600_000), running });
    expect(route.ops.serverRun).toHaveBeenCalledTimes(2);
    statuses[0]!.state = 'paused';
    await runDue({ store, routes: [route], now: new Date('2026-03-08T03:00:00Z'), running });
    expect(route.ops.serverRun).toHaveBeenCalledTimes(2);
    statuses[0]!.state = 'deleted';
    await runDue({ store, routes: [route], now: new Date('2026-03-08T03:01:00Z'), running });
    expect(store.get('job_12345')).toBeUndefined();
  });

  it('keeps running while the site is down, queuing every summary (review r2 F1)', async () => {
    const dir = directory();
    const store = storeIn(dir);
    expect(store.apply(definition({ schedule: { kind: 'every', hours: 1, tz: 'UTC' } as never, version: 2, order_id: 'order_789' }), agentId, now)).toEqual({ ok: true });
    const route = routeFor(dir, []);
    route.getJobs = vi.fn(async () => { throw new Error('site down'); });
    route.postJobRun = vi.fn(async () => { throw new Error('site down'); });
    for (let h = 1; h <= 3; h++) {
      await runDue({ store, routes: [route], now: new Date(now.getTime() + h * 3_600_000 + 1000), running: new Set() });
    }
    expect(route.ops.serverRun).toHaveBeenCalledTimes(3);
    expect(store.get('job_12345')?.pending_runs).toHaveLength(3);
    route.postJobRun = vi.fn(async () => {});
    route.getJobs = vi.fn(async () => ({ jobs: [{ id: 'job_12345', version: 2, state: 'active' as const, run_now: false }] }));
    await runDue({ store, routes: [route], now: new Date(now.getTime() + 3 * 3_600_000 + 2000), running: new Set() });
    expect(route.postJobRun).toHaveBeenCalledTimes(3);
    expect(store.get('job_12345')?.pending_runs).toBeUndefined();
  });

  it('drops a summary the site refuses instead of retrying it forever (review r2 B2)', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const route = routeFor(dir, [{ id: 'job_12345', version: 1, state: 'active', run_now: false }]);
    route.postJobRun = vi.fn(async () => { throw Object.assign(new Error('bad time'), { status: 422 }); });
    await runDue({ store, routes: [route], now: new Date('2026-03-07T03:00:00Z'), running: new Set() });
    expect(route.ops.serverRun).toHaveBeenCalledTimes(1);
    expect(store.get('job_12345')?.pending_runs).toBeUndefined();
  });

  it('a failing log append does not stop the summary going out (review r2 F2)', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const route = routeFor(dir, [{ id: 'job_12345', version: 1, state: 'active', run_now: false }]);
    route.recordRun = vi.fn(async () => { throw new Error('ENOSPC'); });
    await runDue({ store, routes: [route], now: new Date('2026-03-07T03:00:00Z'), running: new Set() });
    expect(route.postJobRun).toHaveBeenCalledTimes(1);
  });

  it('one run per SERVER even when jobs sign in as different accounts (review r2 F4)', async () => {
    const dir = directory();
    const store = storeIn(dir);
    expect(store.apply(definition({ job_id: 'job_67890', order_id: 'order_456', destination: 'reports@example.com' }), agentId, now)).toEqual({ ok: true });
    const route = routeFor(dir, ['job_12345', 'job_67890'].map(id => ({ id, version: 1, state: 'active' as const, run_now: false })));
    await runDue({ store, routes: [route], now: new Date('2026-03-07T03:00:00Z'), running: new Set() });
    expect(route.ops.serverRun).toHaveBeenCalledTimes(1);
  });

  it('accepts a name with accents, refuses control characters (review r2 F3)', () => {
    expect(validateJobOrder(definition({ name: 'Sauvegarde été' }), fingerprint, now.getTime()).ok).toBe(true);
    expect(validateJobOrder(definition({ name: 'bad\u0007bell' }), fingerprint, now.getTime()).ok).toBe(false);
  });

  it('starts at most one job per destination in a tick', async () => {
    const dir = directory();
    const store = storeIn(dir);
    expect(store.apply(definition({ job_id: 'job_67890', order_id: 'order_456' }), agentId, now)).toEqual({ ok: true });
    const statuses: JobStatus[] = ['job_12345', 'job_67890'].map(id => ({
      id, version: 1, state: 'active', run_now: false,
    }));
    const route = routeFor(dir, statuses);
    await runDue({ store, routes: [route], now: new Date('2026-03-07T03:00:00Z'), running: new Set() });
    expect(route.ops.serverRun).toHaveBeenCalledTimes(1);
  });
});

describe('job broker envelopes', () => {
  it('hands an opened job to jobOrder once, refuses a replay and reports validation reasons', async () => {
    const dir = directory();
    const key = randomBytes(32);
    const seal = (value: unknown) => sealForOwner(key, `wv-broker-order-v1|${fingerprint}`, value);
    const good = seal(definition());
    let envelopes = [{ id: 'order_123', agent_id: agentId, kind: 'job-set', ...good }];
    const postState = vi.fn(async () => {});
    const jobOrder = vi.fn();
    const deps: BrokerUpdateDeps = {
      fingerprint, version: '2.5.1',
      client: { getOrders: async () => ({ orders: envelopes }), postState },
      vaultKeyFor: async () => key,
      seenPath: path.join(dir, 'seen.json'), requestPath: path.join(dir, 'request.json'),
      statusPath: path.join(dir, 'status.json'), now: () => now.getTime(), log: () => {},
      jobOrder,
    };
    await pollOnce(deps);
    expect(jobOrder).toHaveBeenCalledTimes(1);
    expect(jobOrder).toHaveBeenCalledWith(agentId, definition());
    expect(postState).toHaveBeenCalledWith('order_123', 'received', '');
    await pollOnce(deps);
    expect(jobOrder).toHaveBeenCalledTimes(1);
    envelopes = [{ id: 'replay_123', agent_id: agentId, kind: 'job-set', ...good }];
    await pollOnce(deps);
    expect(postState).toHaveBeenCalledWith('replay_123', 'refused', 'replay');
    const bad = seal(definition({ order_id: 'order_bad', timeout_s: 601 }));
    envelopes = [{ id: 'order_bad', agent_id: agentId, kind: 'job-set', ...bad }];
    await pollOnce(deps);
    expect(postState).toHaveBeenCalledWith('order_bad', 'refused', 'bad timeout');
    envelopes = [{ id: 'unknown_1', agent_id: agentId, kind: 'job-delete', ...good }];
    await pollOnce(deps);
    expect(postState).toHaveBeenCalledWith('unknown_1', 'refused', 'not supported');
    expect(jobOrder).toHaveBeenCalledTimes(1);
  });
});

describe('failed-run details for the owner', () => {
  it('keeps the last 20 lines, at most 4 KB, and seals them; a good run carries none', async () => {
    const { failureTail } = await import('../src/jobs.js');
    const many = Array.from({ length: 50 }, (_, i) => `line ${i}`).join('\n');
    const tail = failureTail(many, 'oops\u0007', 'exit 3');
    expect(tail.split('\n')).toHaveLength(20);
    expect(tail.endsWith('helper: exit 3')).toBe(true);
    expect(tail).not.toContain('\u0007');
    expect(Buffer.byteLength(failureTail('x'.repeat(10_000), '', undefined))).toBeLessThanOrEqual(4096);
    const dir = directory();
    const store = storeIn(dir);
    const route = routeFor(dir, [{ id: 'job_12345', version: 1, state: 'active', run_now: false }],
      { serverRun: vi.fn(async () => ({ exitCode: 2, stdout: 'starting\n', stderr: 'disk full\n' })) });
    route.sealForOwner = vi.fn(async (_aad: string, _v: unknown) => ({ ciphertext: 'c2VhbGVk', nonce: 'bm9uY2U=' }));
    await runDue({ store, routes: [route], now: new Date('2026-03-07T03:00:00Z'), running: new Set() });
    const [aad, value] = vi.mocked(route.sealForOwner!).mock.calls[0]!;
    expect(aad).toMatch(/^wv-job-error-v1\|job_12345\|/);
    expect((value as { tail: string }).tail).toBe('starting\ndisk full');
    const body = vi.mocked(route.postJobRun).mock.calls[0]![1];
    expect(body).toMatchObject({ ok: false, exit_code: 2, error_ciphertext: 'c2VhbGVk', error_nonce: 'bm9uY2U=' });
    expect(JSON.stringify(body)).not.toContain('disk full');
  });
});

describe('local log of job changes (owner 11-23)', () => {
  it('records pause, resume and delete once each, and nothing when the state is unchanged', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const changes: string[] = [];
    const statuses: JobStatus[] = [{ id: 'job_12345', version: 1, state: 'active', run_now: false }];
    const route = routeFor(dir, statuses);
    route.getJobs = vi.fn(async () => ({ jobs: statuses.map((s) => ({ ...s })) }));
    route.recordChange = vi.fn(async (_job, change) => { changes.push(change); });
    const at = new Date('2026-03-07T01:00:00Z');   // not due: only state changes happen
    await runDue({ store, routes: [route], now: at, running: new Set() });
    expect(changes).toEqual([]);
    statuses[0]!.state = 'paused';
    await runDue({ store, routes: [route], now: at, running: new Set() });
    await runDue({ store, routes: [route], now: at, running: new Set() });
    statuses[0]!.state = 'active';
    await runDue({ store, routes: [route], now: at, running: new Set() });
    statuses[0]!.state = 'deleted';
    await runDue({ store, routes: [route], now: at, running: new Set() });
    expect(changes).toEqual(['paused', 'resumed', 'deleted']);
    expect(store.get('job_12345')).toBeUndefined();
  });

  it('a failing log write does not stop the job loop', async () => {
    const dir = directory();
    const store = storeIn(dir);
    const route = routeFor(dir, [{ id: 'job_12345', version: 1, state: 'paused', run_now: false }]);
    route.recordChange = vi.fn(async () => { throw new Error('disk full'); });
    await runDue({ store, routes: [route], now: new Date('2026-03-07T01:00:00Z'), running: new Set() });
    expect(route.recordChange).toHaveBeenCalledTimes(1);
    expect(store.get('job_12345')?.state).toBe('paused');
  });
});
