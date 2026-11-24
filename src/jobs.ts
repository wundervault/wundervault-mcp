/**
 * Owner-approved unattended jobs. Definitions and output belong in the helper's own storage,
 * never in an agent's home. Only sealed owner orders may call JobStore.apply.
 */
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { openSealed } from './broker-update.js';
import { canonicalDestination, type ServerRunner } from './server-setup.js';

export type JobState = 'active' | 'paused' | 'deleted';
export type JobTrigger = 'schedule' | 'run-now' | 'catch-up';
export type JobSchedule =
  | { kind: 'daily'; time: string; tz: string }
  | { kind: 'every'; hours: number; tz: string };

export interface JobDefinition {
  v: 1;
  type: 'job-set';
  broker: string;
  order_id: string;
  issued_at: string;
  expires_at: string;
  job_id: string;
  version: number;
  name: string;
  entry_id: string;
  destination: string;
  argv: string[];
  schedule: JobSchedule;
  timeout_s: number;
}

export interface JobRun {
  /** A failed run's last lines, sealed for the owner (only the vault page opens them). */
  error_ciphertext?: string;
  error_nonce?: string;
  run_id: string;
  started_at: string;
  finished_at: string;
  ok: boolean;
  exit_code: number;
  bytes: number;
  trigger: JobTrigger;
}

export interface LocalJobRun extends JobRun {
  error?: string;
  /** Only the first 1 MiB of the output was kept (review r2 B3): never read it as complete. */
  output_truncated?: boolean;
  /** A failed run's last 20 lines (stdout + stderr, at most 4 KB): sealed before it leaves. */
  tail?: string;
}

export interface StoredJob {
  def: JobDefinition;
  agent_id: string;
  state: JobState;
  applied_at: string;
  last_run_at?: string;
  last_scheduled?: string;
  last_run_now_at?: string;
  /** Summaries not yet delivered to the site, oldest first (at most 50). */
  pending_runs?: JobRun[];
}

export interface JobStatus {
  id: string;
  version: number;
  state: JobState;
  run_now: boolean;
}

export interface JobClient {
  getJobs(): Promise<{ jobs: JobStatus[] }>;
  postJobRun(id: string, body: JobRun): Promise<void>;
}

/**
 * The agent supplies its account-specific route, including an everyday/tier-1 preflight.
 * authorize must re-read the entry and approved destinations, not trust the saved definition.
 */
export interface JobRoute extends JobClient {
  agent_id: string;
  ops: ServerRunner;
  outputDir: string;
  authorize(job: JobDefinition): Promise<{ ok: true } | { ok: false; reason: string }>;
  /** Seal a failed run's last lines for the owner (the account's vault key). Optional. */
  sealForOwner?(aad: string, value: unknown): Promise<{ ciphertext: string; nonce: string }>;
  recordRun(job: StoredJob, run: LocalJobRun): Promise<void>;
  /** A signed local line when the owner pauses, resumes or deletes a job (optional). */
  recordChange?(job: StoredJob, change: 'paused' | 'resumed' | 'deleted'): Promise<void>;
}

const ID = /^[A-Za-z0-9_-]{8,64}$/;
const STATES: readonly JobState[] = ['active', 'paused', 'deleted'];
const KEYS = [
  'v', 'type', 'broker', 'order_id', 'issued_at', 'expires_at', 'job_id', 'version',
  'name', 'entry_id', 'destination', 'argv', 'schedule', 'timeout_s',
];

function record(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function exact(o: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(o).length === keys.length && keys.every(k => Object.hasOwn(o, k));
}

function isoMs(v: unknown): number {
  return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/.test(v)
    ? Date.parse(v) : NaN;
}

export function validateJobOrder(
  o: unknown, fingerprint: string, nowMs: number,
): { ok: true; job: JobDefinition } | { ok: false; reason: string } {
  if (!record(o) || !exact(o, KEYS) || o.v !== 1 || o.type !== 'job-set') {
    return { ok: false, reason: 'malformed' };
  }
  if (o.broker !== fingerprint) return { ok: false, reason: 'wrong broker' };
  const issued = isoMs(o.issued_at);
  const expires = isoMs(o.expires_at);
  if (!Number.isFinite(nowMs) || !Number.isFinite(issued) || !Number.isFinite(expires) ||
      expires <= issued || expires - issued > 16 * 60_000) {
    return { ok: false, reason: 'malformed' };
  }
  if (issued > nowMs + 2 * 60_000 || expires <= nowMs) return { ok: false, reason: 'expired' };
  if (![o.order_id, o.job_id, o.entry_id].every(v => typeof v === 'string' && ID.test(v)) ||
      !Number.isInteger(o.version) || (o.version as number) < 1 || (o.version as number) > 1e9 ||
      typeof o.name !== 'string' || !/^[^\p{C}]{1,80}$/u.test(o.name) || o.name.trim() !== o.name) {
    return { ok: false, reason: 'malformed' };
  }
  const destination = canonicalDestination(o.destination);
  if (!destination) return { ok: false, reason: 'bad destination' };
  if (!Array.isArray(o.argv) || o.argv.length < 1 || o.argv.length > 64 ||
      !o.argv.every(v => typeof v === 'string' && v.length >= 1 && v.length <= 4096 && !v.includes('\0')) ||
      o.argv.reduce((n: number, v: string) => n + Buffer.byteLength(v, 'utf8'), 0) > 16 * 1024) {
    return { ok: false, reason: 'bad argv' };
  }
  const schedule = o.schedule;
  if (!record(schedule) ||
      !(schedule.kind === 'daily' && exact(schedule, ['kind', 'time', 'tz']) &&
        typeof schedule.time === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(schedule.time) ||
        schedule.kind === 'every' && exact(schedule, ['kind', 'hours', 'tz']) &&
        Number.isInteger(schedule.hours) && (schedule.hours as number) >= 1 && (schedule.hours as number) <= 24)) {
    return { ok: false, reason: 'bad schedule' };
  }
  if (typeof schedule.tz !== 'string' || schedule.tz.length < 1 || schedule.tz.length > 64) {
    return { ok: false, reason: 'bad timezone' };
  }
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: schedule.tz }).format(new Date(nowMs));
  } catch {
    return { ok: false, reason: 'bad timezone' };
  }
  if (!Number.isInteger(o.timeout_s) || (o.timeout_s as number) < 10 || (o.timeout_s as number) > 600) {
    return { ok: false, reason: 'bad timeout' };
  }
  return {
    ok: true,
    job: {
      v: 1, type: 'job-set', broker: fingerprint,
      order_id: o.order_id as string, issued_at: o.issued_at as string, expires_at: o.expires_at as string,
      job_id: o.job_id as string, version: o.version as number, name: o.name,
      entry_id: o.entry_id as string, destination: destination.text, argv: [...o.argv] as string[],
      schedule: { ...schedule } as JobSchedule, timeout_s: o.timeout_s as number,
    },
  };
}

export function openJobOrder(
  ciphertext: string, nonce: string, key: Uint8Array, fingerprint: string, nowMs: number,
): { ok: true; job: JobDefinition } | { ok: false; reason: string } {
  // JSON can expand a 16 KiB argv to six times its size before base64 encoding.
  const opened = openSealed(ciphertext, nonce, key, fingerprint, 160_000);
  if (!opened.ok) return opened;
  if (opened.value.type !== 'job-set') return { ok: false, reason: 'kind mismatch' };
  return validateJobOrder(opened.value, fingerprint, nowMs);
}

function atomicJson(file: string, value: unknown): void {
  const temporary = `${file}.${randomBytes(12).toString('hex')}.tmp`;
  let fd: number | undefined;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(value));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporary, file);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
  }
}

export class JobStore {
  constructor(private file: string) {}

  private read(): { jobs: Record<string, StoredJob> } {
    let value: unknown;
    try {
      value = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { jobs: Object.create(null) };
      throw e;
    }
    if (!record(value) || !exact(value, ['jobs']) || !record(value.jobs)) throw new Error('invalid job store');
    const jobs: Record<string, StoredJob> = Object.create(null);
    for (const [id, raw] of Object.entries(value.jobs)) {
      if (!ID.test(id) || !record(raw) || !record(raw.def) ||
          typeof raw.agent_id !== 'string' || !ID.test(raw.agent_id) ||
          !STATES.includes(raw.state as JobState) || !Number.isFinite(isoMs(raw.applied_at))) {
        throw new Error('invalid job store');
      }
      const checked = validateJobOrder(raw.def, String(raw.def.broker), isoMs(raw.def.issued_at));
      if (!checked.ok || checked.job.job_id !== id) throw new Error('invalid job store');
      for (const key of ['last_run_at', 'last_scheduled', 'last_run_now_at']) {
        if (raw[key] !== undefined && !Number.isFinite(isoMs(raw[key]))) throw new Error('invalid job store');
      }
      if (raw.pending_runs !== undefined && (!Array.isArray(raw.pending_runs) || raw.pending_runs.length > 50 ||
          !raw.pending_runs.every(validRun))) throw new Error('invalid job store');
      jobs[id] = { ...raw, def: checked.job } as unknown as StoredJob;
    }
    return { jobs };
  }

  entries(): [string, StoredJob][] { return Object.entries(this.read().jobs); }
  get(id: string): StoredJob | undefined { return this.read().jobs[id]; }

  apply(def: JobDefinition, agentId: string, now: Date): { ok: true } | { ok: false; reason: string } {
    if (!ID.test(agentId) || !Number.isFinite(now.getTime())) return { ok: false, reason: 'malformed' };
    const checked = validateJobOrder(def, def.broker, now.getTime());
    if (!checked.ok) return checked;
    const all = this.read();
    const old = all.jobs[def.job_id];
    if (old && old.agent_id !== agentId) return { ok: false, reason: 'wrong agent' };
    if (old && old.def.version >= def.version) return { ok: false, reason: 'older version' };
    all.jobs[def.job_id] = {
      def: checked.job, agent_id: agentId, state: old?.state ?? 'active', applied_at: now.toISOString(),
      ...(old?.last_run_at ? { last_run_at: old.last_run_at } : {}),
      ...(old?.last_run_now_at ? { last_run_now_at: old.last_run_now_at } : {}),
      ...(old?.pending_runs?.length ? { pending_runs: old.pending_runs } : {}),
    };
    atomicJson(this.file, all);
    return { ok: true };
  }

  setState(id: string, state: JobState): void {
    if (!STATES.includes(state)) throw new Error('invalid job state');
    const all = this.read();
    if (!all.jobs[id]) return;
    all.jobs[id]!.state = state;
    atomicJson(this.file, all);
  }

  remove(id: string): void {
    const all = this.read();
    if (!all.jobs[id]) return;
    delete all.jobs[id];
    atomicJson(this.file, all);
  }

  recordStart(id: string, at: string, slot?: string, runNow = false): void {
    const all = this.read();
    const job = all.jobs[id];
    if (!job) throw new Error('unknown job');
    job.last_run_at = at;
    if (slot) job.last_scheduled = slot;
    if (runNow) job.last_run_now_at = at;
    atomicJson(this.file, all);
  }

  pending(id: string, run: JobRun): void {
    const all = this.read();
    const job = all.jobs[id];
    if (!job) throw new Error('unknown job');
    // A queue, not one slot: an undelivered summary must never stop the next run (review r2 F1).
    job.pending_runs = [...(job.pending_runs ?? []), publicRun(run)].slice(-50);
    atomicJson(this.file, all);
  }

  delivered(id: string, runId: string): void {
    const all = this.read();
    const job = all.jobs[id];
    if (!job || !job.pending_runs?.some((r) => r.run_id === runId)) return;
    job.pending_runs = job.pending_runs.filter((r) => r.run_id !== runId);
    if (!job.pending_runs.length) delete job.pending_runs;
    atomicJson(this.file, all);
  }
}

function validRun(v: unknown): v is JobRun {
  return record(v) && typeof v.run_id === 'string' && /^[A-Za-z0-9_-]{22}$/.test(v.run_id) &&
    Number.isFinite(isoMs(v.started_at)) && Number.isFinite(isoMs(v.finished_at)) &&
    typeof v.ok === 'boolean' && Number.isInteger(v.exit_code) &&
    (v.exit_code as number) >= -1 && (v.exit_code as number) <= 255 &&
    Number.isSafeInteger(v.bytes) && (v.bytes as number) >= 0 &&
    ['schedule', 'run-now', 'catch-up'].includes(v.trigger as string) &&
    ((v.error_ciphertext === undefined && v.error_nonce === undefined) ||
      (typeof v.error_ciphertext === 'string' && v.error_ciphertext.length <= 8192 && typeof v.error_nonce === 'string'));
}

/** Do not accidentally send the local error (or future local-only fields) to the site. */
function publicRun(run: JobRun): JobRun {
  return {
    run_id: run.run_id, started_at: run.started_at, finished_at: run.finished_at,
    ok: run.ok, exit_code: run.exit_code, bytes: run.bytes, trigger: run.trigger,
    ...(run.error_ciphertext && run.error_nonce ? { error_ciphertext: run.error_ciphertext, error_nonce: run.error_nonce } : {}),
  };
}

/** The last lines of a failed run for its owner: 20 lines, at most 4 KB, printable text only. */
export function failureTail(stdout: string, stderr: string, error?: string): string {
  const text = [stdout, stderr, error ? `helper: ${error}` : ''].filter(Boolean).join('\n')
    .replace(/[^\x09\x0a\x20-\x7e\u00a0-\uffff]/g, '');
  const lines = text.split('\n').filter((l) => l.trim() !== '').slice(-20).join('\n');
  return Buffer.from(lines, 'utf8').subarray(-4096).toString('utf8');
}

const formatters = new Map<string, Intl.DateTimeFormat>();

function wallMs(ms: number, tz: string): number {
  let formatter = formatters.get(tz);
  if (!formatter) {
    formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
    });
    formatters.set(tz, formatter);
  }
  const parts: Record<string, number> = {};
  for (const part of formatter.formatToParts(new Date(ms))) {
    if (part.type !== 'literal') parts[part.type] = Number(part.value);
  }
  return Date.UTC(parts.year!, parts.month! - 1, parts.day!, parts.hour!, parts.minute!, parts.second!);
}

/** First occurrence of a wall minute, advancing through a DST gap to the next valid minute. */
function wallSlot(target: number, tz: string): number | null {
  const offsets = new Set<number>();
  for (let hours = -48; hours <= 48; hours += 6) {
    const sample = target + hours * 3_600_000;
    offsets.add(wallMs(sample, tz) - sample);
  }
  for (let minutes = 0; minutes <= 24 * 60; minutes++) {
    const wall = target + minutes * 60_000;
    const matches: number[] = [];
    for (const offset of offsets) {
      const instant = wall - offset;
      if (wallMs(instant, tz) === wall) matches.push(instant);
    }
    if (matches.length) return Math.min(...matches);
  }
  return null;
}

/**
 * Every-N-hours schedules need their persisted anchor, supplied as the third argument.
 * Slot zero is applied_at; dueKind deliberately excludes that initial slot.
 */
export function lastSlot(now: Date, schedule: JobSchedule, appliedAt?: string | Date): Date | null {
  const ms = now.getTime();
  if (!Number.isFinite(ms)) return null;
  if (schedule.kind === 'every') {
    const anchor = appliedAt instanceof Date ? appliedAt.getTime() : isoMs(appliedAt);
    if (!Number.isFinite(anchor) || ms < anchor) return null;
    const period = schedule.hours * 3_600_000;
    return new Date(anchor + Math.floor((ms - anchor) / period) * period);
  }
  const local = new Date(wallMs(ms, schedule.tz));
  const [hours, minutes] = schedule.time.split(':').map(Number);
  const target = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate(), hours, minutes);
  // Three preceding local dates also cover an entirely skipped calendar date.
  for (let days = 0; days <= 3; days++) {
    const slot = wallSlot(target - days * 86_400_000, schedule.tz);
    if (slot !== null && slot <= ms) return new Date(slot);
  }
  return null;
}

export function dueKind(job: StoredJob, now: Date): 'schedule' | 'catch-up' | null {
  if (job.state !== 'active') return null;
  const slot = lastSlot(now, job.def.schedule, job.applied_at);
  if (!slot || slot.getTime() <= Date.parse(job.applied_at) || job.last_scheduled === slot.toISOString()) return null;
  return now.getTime() - slot.getTime() > 3_600_000 ? 'catch-up' : 'schedule';
}

function privateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('invalid job output directory');
  fs.chmodSync(dir, 0o700);
}

function pruneOutput(dir: string, current: string): void {
  const files = fs.readdirSync(dir).filter(name => /^[A-Za-z0-9_-]{22}\.out$/.test(name));
  files.sort((a, b) => {
    if (a === `${current}.out`) return -1;
    if (b === `${current}.out`) return 1;
    return fs.statSync(path.join(dir, b)).mtimeMs - fs.statSync(path.join(dir, a)).mtimeMs ||
      b.localeCompare(a);
  });
  for (const name of files.slice(5)) {
    fs.unlinkSync(path.join(dir, name));
    const metadata = path.join(dir, name.replace(/\.out$/, '.json'));
    try { fs.unlinkSync(metadata); } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
  }
}

/**
 * serverRun remains the signing/host-approval gate. The route must additionally refuse admin
 * and tier-2 entries even if an unrelated interactive approval is currently open.
 */
export async function runJob(
  ops: ServerRunner, job: StoredJob, trigger: JobTrigger, outputDir: string,
  nowFn: () => Date = () => new Date(),
): Promise<LocalJobRun> {
  const def = job.def;
  if (!ID.test(def.job_id)) throw new Error('invalid job id');
  const runId = randomBytes(16).toString('base64url');
  const started = nowFn().toISOString();
  let stdout = '';
  let stderr = '';
  let exitCode = -1;
  let error: string | undefined;
  try {
    const result = await ops.serverRun({
      entryId: def.entry_id, destination: def.destination, purpose: `job: ${def.name}`,
      argv: () => [...def.argv], timeoutMs: def.timeout_s * 1000,
      // Nobody is there to answer: a server not yet approved for this key refuses at once (r1 B4).
      noAsk: true,
    });
    if ('error' in result) error = result.error;
    else {
      stdout = result.stdout;
      stderr = result.stderr ?? '';
      if (Number.isInteger(result.exitCode) && result.exitCode >= 0 && result.exitCode <= 255) {
        exitCode = result.exitCode;
      } else error = 'invalid exit code';
    }
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }
  const output = Buffer.from(stdout, 'utf8');
  const run: LocalJobRun = {
    run_id: runId, started_at: started, finished_at: nowFn().toISOString(),
    ok: error === undefined && exitCode === 0, exit_code: error === undefined ? exitCode : -1,
    bytes: output.length, trigger,
    ...(error !== undefined ? { error: error.split(/\r?\n/)[0]!.slice(0, 500) } : {}),
    ...(output.length > 1024 * 1024 ? { output_truncated: true } : {}),
  };
  if (!run.ok) run.tail = failureTail(stdout, stderr, run.error);
  // The command HAS run: a full disk while keeping its output must not lose the run from the
  // log and the site (review r1 F4). The run is still returned, saying the output was not kept.
  try {
    privateDir(outputDir);
    const dir = path.join(outputDir, def.job_id);
    privateDir(dir);
    fs.writeFileSync(path.join(dir, `${runId}.out`), output.subarray(0, 1024 * 1024), { mode: 0o600, flag: 'wx' });
    atomicJson(path.join(dir, `${runId}.json`), run);
    pruneOutput(dir, runId);
  } catch (e) {
    run.error = `${run.error ? run.error + '; ' : ''}output not kept: ${(e instanceof Error ? e.message : String(e)).split(/\r?\n/)[0]!.slice(0, 200)}`;
  }
  return run;
}

const jobLock = (id: string) => `job:${id}`;
// One run at a time per SERVER, whichever account a job signs in as (review r2 F4).
const destinationLock = (destination: string) => `job-destination:${destination.slice(destination.indexOf('@') + 1)}`;

/**
 * Call once per scheduler tick with a shared running set. A failed state refresh runs jobs as
 * last known (a site outage must not stop backups).
 * Pending summaries are retried before another run; a run is never repeated to retry its post.
 */
export async function runDue(args: {
  store: JobStore; routes: JobRoute[]; now: Date; running: Set<string>;
  nowFn?: () => Date;
}): Promise<void> {
  const { store, routes, now, running } = args;
  const tasks: Promise<void>[] = [];
  for (const route of routes) {
    for (const [id, job] of store.entries()) {
      if (job.agent_id !== route.agent_id || !job.pending_runs?.length || running.has(jobLock(id))) continue;
      for (const pendingRun of job.pending_runs) {
        try {
          await route.postJobRun(id, publicRun(pendingRun));
          store.delivered(id, pendingRun.run_id);
        } catch (e) {
          // The site said no (e.g. a helper clock far off): drop it rather than retry forever
          // (review r2 B2). Anything else (site down): keep it and try again next tick.
          const status = (e as { status?: number }).status;
          if (typeof status === 'number' && status >= 400 && status < 500 && status !== 408 && status !== 429) {
            store.delivered(id, pendingRun.run_id);
          } else break;
        }
      }
    }
    // The site down must not stop a backup (review r1 B1): with no answer, jobs run as last
    // known. A pause or delete made meanwhile applies on the first answer after.
    let statuses: JobStatus[] | null;
    try { statuses = (await route.getJobs()).jobs; } catch { statuses = null; }
    const remote = new Map((statuses ?? []).map(status => [status.id, status]));
    for (const [id, saved] of store.entries()) {
      if (saved.agent_id !== route.agent_id) continue;
      let status = remote.get(id);
      if (statuses === null) {
        status = { id, version: saved.def.version, state: saved.state, run_now: false };
      } else if (!status) {
        // Missing from a list the site DID send: deleted (its record may be past the site's
        // seven days), so it is dropped here too (review r1 F2). Only ever stops a job.
        status = { id, version: saved.def.version, state: 'deleted', run_now: false };
      }
      const before = saved.state;
      if (status.state === 'deleted' && status.version >= saved.def.version) {
        store.setState(id, 'deleted');
      } else if (status.version === saved.def.version && STATES.includes(status.state)) {
        store.setState(id, status.state);
      } else continue;
      const job = store.get(id)!;
      if (job.state !== before && route.recordChange) {
        const change = job.state === 'deleted' ? 'deleted' : job.state === 'paused' ? 'paused' : 'resumed';
        try { await route.recordChange(job, change); } catch { /* the log write must not stop jobs */ }
      }
      if (job.state === 'deleted') {
        if (!running.has(jobLock(id)) && !job.pending_runs?.length) store.remove(id);
        continue;
      }
      if (job.state !== 'active' ||
          running.has(jobLock(id)) || running.has(destinationLock(job.def.destination))) continue;
      const slot = lastSlot(now, job.def.schedule, job.applied_at);
      const scheduled = dueKind(job, now);
      const lastNow = job.last_run_now_at ? Date.parse(job.last_run_now_at) : -Infinity;
      const runNow = status.run_now === true && now.getTime() - lastNow >= 10 * 60_000;
      const trigger: JobTrigger | null = runNow ? 'run-now' : scheduled;
      if (!trigger) continue;
      // Reserve both locks and persist the slot BEFORE yielding or starting SSH.
      running.add(jobLock(id));
      running.add(destinationLock(job.def.destination));
      try {
        store.recordStart(id, now.toISOString(), slot?.toISOString(), runNow);
      } catch (e) {
        running.delete(jobLock(id));
        running.delete(destinationLock(job.def.destination));
        throw e;
      }
      tasks.push((async () => {
        try {
          const allowed = await route.authorize(job.def);
          const ops: ServerRunner = allowed.ok ? route.ops : {
            serverRun: async () => ({ error: allowed.reason }),
          };
          const run = await runJob(ops, job, trigger, route.outputDir, args.nowFn);
          // This is the account's signed activity-log append, including the outcome.
          // The command HAS run. Neither a log append nor a local write that fails (a full disk)
          // may stop the site hearing of it, so the summary goes out FIRST and is kept locally
          // only if it could not be sent (review r2 F2).
          try { await route.recordRun(job, run); } catch { /* the site summary still goes */ }
          // The owner sees why it failed, in the vault only: the site carries bytes it can't read.
          if (!run.ok && run.tail && route.sealForOwner) {
            try {
              const sealed = await route.sealForOwner(`wv-job-error-v1|${id}|${run.run_id}`, { v: 1, job_id: id, run_id: run.run_id, tail: run.tail });
              run.error_ciphertext = sealed.ciphertext; run.error_nonce = sealed.nonce;
            } catch { /* the summary still goes, without details */ }
          }
          try {
            await route.postJobRun(id, publicRun(run));
          } catch (e) {
            const status = (e as { status?: number }).status;
            const refused = typeof status === 'number' && status >= 400 && status < 500 && status !== 408 && status !== 429;
            if (!refused) { try { store.pending(id, run); } catch { /* nowhere left to keep it */ } }
          }
          const current = store.get(id);
          if (current?.state === 'deleted' && !current.pending_runs?.length) store.remove(id);
        } finally {
          running.delete(jobLock(id));
          running.delete(destinationLock(job.def.destination));
        }
      })());
    }
  }
  // Observe every task even if one fails; none may outlive the scheduler's error handling.
  const results = await Promise.allSettled(tasks);
  const failed = results.find((result): result is PromiseRejectedResult => result.status === 'rejected');
  if (failed) throw failed.reason;
}
