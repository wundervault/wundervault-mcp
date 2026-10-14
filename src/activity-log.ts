/**
 * The broker's full activity log: one signed line for every thing it does with a key.
 *
 * WHY THIS EXISTS (owner, 2026-10-13)
 *
 * The hosted audit log records that a key was used, by which agent, when and with what
 * outcome — and deliberately not where it went or why (the network-shape decision). The
 * local destination store (network-store.ts) kept the other half, but only as a summary:
 * one row per key and website, a count, the last twenty reasons. Neither log told the
 * whole story of one call, and matching them meant lining up timestamps by hand. This is
 * the whole story, one line per use, on the owner's machine, and kept for a year.
 *
 * WHAT A LINE PROVES, AND WHAT IT DOES NOT
 *
 * Every line carries `prev` (the previous line's hash), its own `hash`, and `sig`, an
 * ECDSA P-256 signature by this machine's broker key over that hash. So:
 *
 *   - editing, removing or reordering a line breaks the chain, and the viewer says where;
 *   - a line nobody with the broker key wrote fails its signature;
 *   - cutting lines off the END is not visible from the file alone. That is what the
 *     server-side anchor is for (activity-anchor.ts): the server folds each line's digest
 *     into its own copy of the chain, so a rewrite or a truncation stops matching it.
 *
 * Someone with administrator rights can read the broker key and re-sign a rewritten file.
 * They cannot make the server's copy of the chain agree with it, which is why the owner
 * chose the anchored version ("Signed + checked by us").
 *
 * WHAT IS NEVER WRITTEN HERE: a key's value, a request or response body (only a body's
 * sha256), or anything the service said beyond a status code. The address is the one the
 * agent asked for, before the broker adds the key, and is scrubbed of the key regardless.
 *
 * THE SIGNED MESSAGE IS DOMAIN-SEPARATED from the broker's request signatures:
 * those begin "wv-broker-req-v1", these begin "wv-activity-log-v1", and the signed bytes
 * are that line plus a hex hash, never text an agent chose.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { systemRoot } from './paths.js';

export const CHAIN_DOMAIN = 'wv-activity-chain-v1';
export const SIGN_DOMAIN = 'wv-activity-log-v1';
/** The `prev` of the first line ever written on a machine. */
export const GENESIS_PREV = '0'.repeat(64);
/** One year, the owner's choice (2026-10-13). */
export const RETENTION_MS = 365 * 24 * 60 * 60 * 1000;

const MAX_REASON = 500;
const MAX_ADDRESS = 2048;
const MAX_DETAIL = 300;
const MAX_SHORT = 200;

export function activityLogPath(): string {
  return process.env.WUNDERVAULT_ACTIVITY_LOG || path.join(systemRoot(), 'activity.log');
}

/** The result of the last check against the server, for the viewer to show. */
export function activityCheckPath(): string {
  return path.join(path.dirname(activityLogPath()), 'activity-check.json');
}

export type ActivityKind = 'call' | 'ssh' | 'ssh_closed' | 'pay' | 'sign' | 'pruned' | 'gap';
export type Approval = 'none' | 'asked' | 'approved' | 'not_approved';

/** What the broker reports about one use. */
export interface ActivityRecord {
  kind: ActivityKind;
  /** sent | failed | refused | error | opened | closed | signed | removed */
  outcome: string;
  agent?: string;
  entry_id?: string;
  /** The key's name at the time, so a later rename or delete does not orphan the line. */
  key?: string;
  method?: string;
  /** Where the agent asked to go, before the key was added. */
  address?: string;
  body_sha256?: string;
  reason?: string;
  tier?: string;
  approval?: Approval;
  status?: number;
  /** Our own words about a refusal or failure: never the service's response. */
  detail?: string;
  extra?: Record<string, string | number | boolean>;
}

export interface ActivityLine extends ActivityRecord {
  v: 1;
  seq: number;
  ts: string;
  /** Random per line, so a digest sent to the server cannot be confirmed by guessing. */
  salt: string;
  /** The fingerprint of the key that signed this line, or absent when unsigned. In the hash. */
  key_fp?: string;
  prev: string;
  hash: string;
  /** base64 DER ECDSA-SHA256, or '' on a machine with no broker key yet. */
  sig: string;
}

// ── canonical form and hashes ─────────────────────────────────────────────────

/** JSON with keys sorted at every level and undefined dropped: one byte string per value. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(',')}}`;
}

function sha256hex(s: string): string {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/** Everything in a line except the chain and signature fields. */
export function contentOf(line: ActivityLine): Record<string, unknown> {
  const { prev: _p, hash: _h, sig: _s, ...rest } = line;
  return rest;
}

/** What the server is sent for each line. Reveals nothing: the content includes a random salt. */
export function digestOf(line: ActivityLine): string {
  return sha256hex(canonical(contentOf(line)));
}

/** The chain step. The server computes exactly this (app/activity_anchor.py). */
export function chainHash(prev: string, digest: string): string {
  return sha256hex(`${CHAIN_DOMAIN}\n${prev}\n${digest}`);
}

export function signedMessage(hash: string): Buffer {
  return Buffer.from(`${SIGN_DOMAIN}\n${hash}`, 'utf8');
}

/** Short, human-comparable form of a line's hash: Crockford base32, two groups of four. */
export function shortFingerprint(hash: string): string {
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const bytes = Buffer.from(hash.slice(0, 10), 'hex');
  let bits = 0; let value = 0; let out = '';
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += A[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return `${out.slice(0, 4)}-${out.slice(4, 8)}`;
}

// ── signing ───────────────────────────────────────────────────────────────────

export interface LogSigner {
  sign(message: Buffer): string;
  /**
   * The signing key's fingerprint. Written into the line's CONTENT, so it is inside the hash
   * and the server's copy: a signature stripped later leaves a line that says it was signed
   * and isn't, which the verification reports (round 1, F5).
   */
  keyId?: string;
}

export function signerFromPem(privateKeyPem: string, keyId?: string): LogSigner {
  const key = crypto.createPrivateKey(privateKeyPem);
  return { sign: (m) => crypto.sign('sha256', m, key).toString('base64'), ...(keyId ? { keyId } : {}) };
}

/**
 * Where a signer comes from. A function, so a key paired AFTER the broker started is picked
 * up on the next line rather than at the next restart. This file never reads the key
 * itself: the broker passes `logSignerFromIdentity` from its key module, and a guard test keeps
 * key access to the broker's own files.
 */
export type SignerSource = () => LogSigner | null;

// ── field hygiene ─────────────────────────────────────────────────────────────

/** Strip control characters (a line is one line) and bound the length. */
function clean(s: unknown, max: number): string | undefined {
  if (s === undefined || s === null) return undefined;
  // eslint-disable-next-line no-control-regex
  const t = String(s).replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, ' ').trim();
  return t ? t.slice(0, max) : undefined;
}

/**
 * Names of query parameters that usually carry a credential. Their VALUES are not kept: the
 * log is for a year, and the address the agent asked for can hold tokens other than the
 * vault key the broker scrubs — a reset link, a signed URL (round 3, B2).
 */
const SENSITIVE_PARAM = /(^|[_-])(token|key|secret|password|passwd|pwd|auth|authorization|sig|signature|code|credential|session|sid|apikey|api_key|access_token|refresh_token|x-amz-signature|x-amz-credential|x-goog-signature)$/i;

/** Remove user:password@ and the values of credential-looking query parameters. */
export function redactAddress(address: string): string {
  let out = address.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@?#]*@/i, '$1[REDACTED]@');
  const q = out.indexOf('?');
  if (q < 0) return out;
  const hash = out.indexOf('#', q);
  const query = out.slice(q + 1, hash < 0 ? undefined : hash);
  const kept = query.split('&').map((pair) => {
    const eq = pair.indexOf('=');
    if (eq < 0) return pair;
    let name = pair.slice(0, eq);
    try { name = decodeURIComponent(name); } catch { /* as written */ }
    return SENSITIVE_PARAM.test(name) ? `${pair.slice(0, eq)}=[REDACTED]` : pair;
  }).join('&');
  out = `${out.slice(0, q + 1)}${kept}${hash < 0 ? '' : out.slice(hash)}`;
  return out;
}

function cleanRecord(r: ActivityRecord): ActivityRecord {
  const extra: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(r.extra ?? {}).slice(0, 12)) {
    const key = clean(k, 40);
    if (!key) continue;
    extra[key] = typeof v === 'string' ? (clean(v, MAX_SHORT) ?? '') : v;
  }
  return {
    kind: r.kind,
    outcome: clean(r.outcome, 40) ?? 'unknown',
    agent: clean(r.agent, MAX_SHORT),
    entry_id: clean(r.entry_id, MAX_SHORT),
    key: clean(r.key, MAX_SHORT),
    method: clean(r.method, 16),
    address: r.address === undefined ? undefined : clean(redactAddress(String(r.address)), MAX_ADDRESS),
    body_sha256: clean(r.body_sha256, 64),
    reason: clean(r.reason, MAX_REASON),
    tier: clean(r.tier, 8),
    approval: r.approval,
    status: Number.isInteger(r.status) ? r.status : undefined,
    detail: clean(r.detail, MAX_DETAIL),
    extra: Object.keys(extra).length ? extra : undefined,
  };
}

// ── the file ──────────────────────────────────────────────────────────────────

/**
 * One writer at a time.
 *
 * Only the broker writes this file, and only one broker can run (`refuseIfAlreadyServing`),
 * so in practice this lock is never contended. It exists for the case that should not
 * happen — a second daemon started by mistake — and for a lock left behind by a crash.
 *
 * A crash's lock names a process that is gone, so it is taken over AT ONCE rather than after
 * a wait (round 1, F2: a crash left every call after a restart stalled for five seconds).
 * If a LIVE process holds it for over a second, the line is written anyway: a line that
 * might share a number with another is reported by the verification as a problem, which is
 * honest; a line silently not written is a gap nobody sees.
 */
function lockHolderAlive(lockPath: string): boolean {
  try {
    const pid = Number(fs.readFileSync(lockPath, 'utf8').trim());
    if (!Number.isInteger(pid) || pid <= 0) return false;
    if (pid === process.pid) return false; // our own leftover from an earlier failure
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM'; // alive, but not ours to signal
  }
}

function withLock<T>(file: string, fn: () => T): T {
  const lockPath = `${file}.lock`;
  try { fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 }); } catch { /* below */ }
  const deadline = Date.now() + 1000;
  let fd: number | undefined;
  for (;;) {
    try {
      fd = fs.openSync(lockPath, 'wx');
      try { fs.writeSync(fd, String(process.pid)); } catch { /* an empty lock still locks */ }
      break;
    } catch {
      try {
        const old = Date.now() - fs.statSync(lockPath).mtimeMs > 30_000;
        if (old || !lockHolderAlive(lockPath)) { fs.unlinkSync(lockPath); continue; }
      } catch { /* vanished: retry */ }
      if (Date.now() > deadline) {
        console.error('[wundervault-agent] The activity log is locked by another live process; writing anyway.');
        return fn();
      }
      const until = Date.now() + 5;
      while (Date.now() < until) { /* millisecond-scale section */ }
    }
  }
  try { return fn(); } finally {
    try { fs.closeSync(fd!); } catch { /* ignore */ }
    try { fs.unlinkSync(lockPath); } catch { /* ignore */ }
  }
}

/** Parse one line, or null when it is not a well-formed log line. */
export function parseLine(text: string): ActivityLine | null {
  try {
    const o = JSON.parse(text) as ActivityLine;
    if (!o || o.v !== 1 || !Number.isInteger(o.seq) || typeof o.hash !== 'string'
        || typeof o.prev !== 'string' || typeof o.ts !== 'string') return null;
    return o;
  } catch { return null; }
}

/**
 * No real line comes near this: every field is capped and a line is a few kilobytes. A
 * longer stretch with no newline is damage (or tampering), reported as one damaged line,
 * and is not allowed to make the reader hold it all in memory (round 2, B4).
 */
const MAX_LINE_BYTES = 256 * 1024;

/** The offset of the last newline byte before `end`, scanning backwards in 64 KiB steps, or -1. */
function newlineBefore(fd: number, end: number): number {
  const step = 64 * 1024;
  const buf = Buffer.alloc(step);
  for (let hi = end; hi > 0; hi -= step) {
    const lo = Math.max(0, hi - step);
    fs.readSync(fd, buf, 0, hi - lo, lo);
    const at = buf.subarray(0, hi - lo).lastIndexOf(0x0a);
    if (at >= 0) return lo + at;
  }
  return -1;
}

/**
 * The last complete line, and the byte length of the file up to and including it.
 *
 * A crash mid-append leaves a partial line with no newline. That fragment was never a
 * signed line, so the next append cuts it off rather than gluing a new line onto it —
 * which would make BOTH unreadable.
 *
 * Worked on BYTES, not decoded text (round 1, F8), and by scanning backwards in fixed steps
 * for the two newlines that bound the last line (round 3, F2): a huge fragment with no
 * newline, from a crash or from tampering, costs time to step over but never memory.
 */
function tail(file: string): { last: ActivityLine | null; goodLength: number; size: number } {
  let size = 0;
  try { size = fs.statSync(file).size; } catch { return { last: null, goodLength: 0, size: 0 }; }
  if (size === 0) return { last: null, goodLength: 0, size: 0 };
  const fd = fs.openSync(file, 'r');
  try {
    const endNl = newlineBefore(fd, size);
    if (endNl < 0) return { last: null, goodLength: 0, size };
    const before = newlineBefore(fd, endNl);
    const len = endNl - (before + 1);
    if (len > MAX_LINE_BYTES) return { last: null, goodLength: endNl + 1, size };
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, before + 1);
    return { last: parseLine(buf.toString('utf8')), goodLength: endNl + 1, size };
  } finally { fs.closeSync(fd); }
}

const STOP = Symbol('stop');

/**
 * Read a file line by line in fixed-size chunks, without holding it all in memory.
 *
 * Split on the newline BYTE and decoded a whole line at a time (round 1, F8): decoding each
 * chunk separately corrupted a character that straddled two chunks, and the line then
 * failed its own hash.
 */
export function forEachLineIn(file: string, fn: (line: ActivityLine | null, lineNo: number) => void): void {
  let fd: number;
  try { fd = fs.openSync(file, 'r'); } catch { return; }
  try {
    const chunk = Buffer.alloc(1024 * 1024);
    let carry: Buffer = Buffer.alloc(0);
    let lineNo = 0;
    let oversized = false;
    for (;;) {
      const n = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (n === 0) break;
      const buf = carry.length ? Buffer.concat([carry, chunk.subarray(0, n)]) : Buffer.from(chunk.subarray(0, n));
      let from = 0;
      for (let nl = buf.indexOf(0x0a, from); nl >= 0; nl = buf.indexOf(0x0a, from)) {
        lineNo += 1;
        fn(nl - from > MAX_LINE_BYTES ? null : parseLine(buf.subarray(from, nl).toString('utf8')), lineNo);
        from = nl + 1;
        oversized = false;
      }
      carry = Buffer.from(buf.subarray(from));
      if (carry.length > MAX_LINE_BYTES) {
        // Drop the bytes, remember the line was damaged, keep reading to its end.
        if (!oversized) { lineNo += 1; fn(null, lineNo); oversized = true; }
        carry = Buffer.alloc(0);
      }
    }
    // An unfinished last line (a crash mid-append) is reported as damaged, not skipped.
    if (carry.length && !oversized) { lineNo += 1; fn(parseLine(carry.toString('utf8')), lineNo); }
  } finally { fs.closeSync(fd); }
}

export class ActivityLog {
  private signerCache: LogSigner | null = null;
  /** Lines that could not be written since the last one that could (disk full, permissions). */
  private failed = 0;

  constructor(
    readonly file: string = activityLogPath(),
    private readonly signerSource: SignerSource = () => null,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /** Cached once found. Until then asked again each line, which is a missing-file check. */
  private signer(): LogSigner | null {
    if (!this.signerCache) this.signerCache = this.signerSource();
    return this.signerCache;
  }

  /**
   * Append one line. Returns it, or null if it could not be written (said on stderr).
   *
   * A line that could not be written is not allowed to vanish without trace (round 1, B3):
   * the next line that CAN be written is preceded by a 'gap' line saying how many were
   * lost, so a disk that filled up shows in the log rather than as a clean chain with holes.
   */
  append(record: ActivityRecord): ActivityLine | null {
    try {
      return withLock(this.file, () => {
        if (this.failed > 0) {
          this.appendLocked(cleanRecord({ kind: 'gap', outcome: 'lost', extra: { lines: this.failed } }));
          this.failed = 0;
        }
        return this.appendLocked(cleanRecord(record));
      });
    } catch (e) {
      this.failed += 1;
      console.error(`[wundervault-agent] Could not write the activity log: ${(e as Error).message}`);
      return null;
    }
  }

  /**
   * `carry` continues the chain from a line that is no longer in the file: used once, by the
   * prune, when every line was old enough to go (round 1, F6).
   */
  private appendLocked(record: ActivityRecord, carry?: { seq: number; hash: string }): ActivityLine {
    const { last, goodLength, size } = tail(this.file);
    if (goodLength < size) {
      fs.truncateSync(this.file, goodLength);
      console.error(`[wundervault-agent] Cut ${size - goodLength} bytes of an unfinished line off the activity log.`);
    }
    const line = this.buildLine(record, last ?? carry ?? null);
    const created = !fs.existsSync(this.file);
    fs.appendFileSync(this.file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    if (created) { try { fs.chmodSync(this.file, 0o600); } catch { /* best effort */ } }
    return line;
  }

  /** A complete, chained, signed line following `prior` (or the genesis value). */
  private buildLine(record: ActivityRecord, prior: { seq: number; hash: string } | null): ActivityLine {
    const signer = this.signer();
    const line: ActivityLine = {
      v: 1,
      seq: prior ? prior.seq + 1 : 1,
      ts: this.now().toISOString(),
      salt: crypto.randomBytes(16).toString('hex'),
      ...(signer?.keyId ? { key_fp: signer.keyId } : {}),
      ...record,
      prev: prior ? prior.hash : GENESIS_PREV,
      hash: '',
      sig: '',
    };
    line.hash = chainHash(line.prev, digestOf(line));
    line.sig = signer ? signer.sign(signedMessage(line.hash)) : '';
    return line;
  }

  /** Every line in order. Lines that do not parse come back as null, in place. */
  readAll(): (ActivityLine | null)[] {
    const out: (ActivityLine | null)[] = [];
    forEachLineIn(this.file, (l) => out.push(l));
    return out;
  }

  lastLine(): ActivityLine | null {
    return tail(this.file).last;
  }

  /** Call `fn` for every line in order, reading in chunks: a year of lines can be large. */
  forEachLine(fn: (line: ActivityLine | null, lineNo: number) => void): void {
    forEachLineIn(this.file, fn);
  }

  firstLine(): ActivityLine | null {
    let first: ActivityLine | null = null;
    try {
      forEachLineIn(this.file, (l) => { first = l; throw STOP; });
    } catch (e) { if (e !== STOP) throw e; }
    return first;
  }

  /**
   * The lines after `seq`, oldest first, read backwards from the end of the file.
   *
   * For the usual case: a handful of new lines at the end. Stops at the first line it cannot
   * parse, because a damaged line is not something to send a digest of: the verification
   * reports it. For a long backlog use `linesBetween`, which streams forward with a limit.
   */
  linesAfter(seq: number): ActivityLine[] {
    let size = 0;
    try { size = fs.statSync(this.file).size; } catch { return []; }
    if (size === 0) return [];
    const fd = fs.openSync(this.file, 'r');
    try {
      for (let window = 64 * 1024; ; window *= 4) {
        const start = Math.max(0, size - window);
        const buf = Buffer.alloc(size - start);
        fs.readSync(fd, buf, 0, buf.length, start);
        const rows: Buffer[] = [];
        let from = 0;
        for (let nl = buf.indexOf(0x0a, from); nl >= 0; nl = buf.indexOf(0x0a, from)) {
          rows.push(buf.subarray(from, nl)); from = nl + 1;
        }
        if (from < buf.length) rows.push(buf.subarray(from)); // an unfinished last line
        if (start > 0) rows.shift(); // the window began inside a line
        const out: ActivityLine[] = [];
        let reached = start === 0;
        for (let i = rows.length - 1; i >= 0; i -= 1) {
          const l = parseLine(rows[i].toString('utf8'));
          if (!l) { reached = true; break; }
          if (l.seq <= seq) { reached = true; break; }
          out.push(l);
        }
        if (reached) return out.reverse();
      }
    } finally { fs.closeSync(fd); }
  }

  /**
   * Up to `limit` lines after `seq`, oldest first, streaming forward (round 1, B2): a
   * computer that was offline for weeks catches up in bounded batches instead of loading
   * the whole backlog. Stops at a line it cannot parse, like `linesAfter`.
   */
  linesBetween(seq: number, limit: number): ActivityLine[] {
    const out: ActivityLine[] = [];
    try {
      forEachLineIn(this.file, (l) => {
        if (!l) { if (out.length) throw STOP; return; }
        if (l.seq <= seq) return;
        out.push(l);
        if (out.length >= limit) throw STOP;
      });
    } catch (e) { if (e !== STOP) throw e; }
    return out;
  }

  /**
   * Remove lines older than a year, then record that it happened.
   *
   * Only ever the OLDEST lines, and — when the broker is paired — only lines our server
   * has held for over a year (`maxSeq`, from the anchor; round 1, F1 and B1). Without that,
   * deleting the start of the log would look exactly like a prune, and a computer offline
   * for a year would cut the lines that link its log to our copy.
   *
   * The first line kept still names its predecessor in `prev`. If every line is old enough
   * to go, they all go and the removal record carries the chain on from the last of them
   * (round 1, F6). Streams the file: a year of lines is not read into memory.
   */
  prune(retentionMs = RETENTION_MS, maxSeq: number | null = null): number {
    try {
      return withLock(this.file, () => {
        if (!fs.existsSync(this.file)) return 0;
        const cutoff = this.now().getTime() - retentionMs;
        // Pass 1: how many leading lines may go.
        let drop = 0;
        let lastDropped: ActivityLine | null = null;
        try {
          forEachLineIn(this.file, (l) => {
            const t = l ? Date.parse(l.ts) : NaN;
            // Stop at the first line that is young enough, that cannot be dated, or that
            // our server has not held for a year: never remove what we cannot account for.
            if (!l || !(t < cutoff) || (maxSeq !== null && l.seq > maxSeq)) throw STOP;
            drop += 1; lastDropped = l;
          });
        } catch (e) { if (e !== STOP) throw e; }
        if (drop === 0 || !lastDropped) return 0;
        const dropped: ActivityLine = lastDropped;
        // Pass 2: copy everything after the dropped lines to a new file, add the signed removal
        // record to IT, and only then swap it in — so lines are never gone without the record
        // saying so (round 2, B3). Bytes are copied in chunks from the cut point; nothing is
        // gathered into lines, so a damaged stretch in the middle is copied, not held (round 3, F2).
        const { last: keptLast, goodLength } = tail(this.file);
        const tmp = `${this.file}.tmp-${process.pid}`;
        const out = fs.openSync(tmp, 'w', 0o600);
        try {
          const fd = fs.openSync(this.file, 'r');
          let copied = 0;
          try {
            const chunk = Buffer.alloc(1024 * 1024);
            // Find the byte just after the drop-th newline.
            let seen = 0; let pos = 0; let cut = -1;
            while (cut < 0) {
              const r = fs.readSync(fd, chunk, 0, chunk.length, pos);
              if (r === 0) break;
              for (let k = 0; k < r; k += 1) {
                if (chunk[k] === 0x0a && ++seen === drop) { cut = pos + k + 1; break; }
              }
              pos += r;
            }
            if (cut < 0) throw new Error('the lines to remove were not where they were counted');
            // Copy [cut, goodLength): an unfinished last fragment is dropped exactly as the next
            // append would drop it.
            for (let at = cut; at < goodLength; ) {
              const r = fs.readSync(fd, chunk, 0, Math.min(chunk.length, goodLength - at), at);
              if (r === 0) break;
              fs.writeSync(out, chunk, 0, r);
              at += r; copied += r;
            }
          } finally { fs.closeSync(fd); }
          const prior = copied > 0 && keptLast ? keptLast : { seq: dropped.seq, hash: dropped.hash };
          const record = this.buildLine(cleanRecord({
            kind: 'pruned', outcome: 'removed',
            extra: { lines: drop, through_seq: dropped.seq, through_ts: dropped.ts },
          }), prior);
          fs.writeSync(out, `${JSON.stringify(record)}\n`);
          fs.fsyncSync(out);
        } finally { fs.closeSync(out); }
        fs.renameSync(tmp, this.file);
        return drop;
      });
    } catch (e) {
      console.error(`[wundervault-agent] Could not prune the activity log: ${(e as Error).message}`);
      return 0;
    }
  }
}

// ── verification ──────────────────────────────────────────────────────────────

export interface Problem { lineNo: number; seq?: number; what: string }

export interface Verification {
  lines: number;
  firstSeq?: number;
  lastSeq?: number;
  signed: number;
  unsigned: number;
  /** Capped; `problemCount` is the full count. */
  problems: Problem[];
  problemCount: number;
  /** seq -> stored hash, for every line whose own hash checked out. */
  hashes: Map<number, string>;
}

/**
 * Check every line: it parses, its hash is right for its content and its `prev`, its `prev`
 * is the previous line's hash, its number follows on, and its signature verifies.
 *
 * The first line's `prev` is taken as given — it names a line that was pruned, or the
 * genesis value. The server's anchor is what confirms where the chain started.
 *
 * Fed one line at a time, so a year of history is checked without loading it.
 */
export class Verifier {
  private prevLine: ActivityLine | null = null;
  private n = 0;
  readonly result: Verification = { lines: 0, signed: 0, unsigned: 0, problems: [], problemCount: 0, hashes: new Map() };

  constructor(private readonly publicKey: crypto.KeyObject | null, private readonly maxProblems = 200,
              /** Keep hashes only from this seq on, to bound memory on a long log. */
              private readonly keepHashesFrom = 0) {}

  private flag(lineNo: number, what: string, seq?: number): void {
    const v = this.result;
    v.problemCount += 1;
    if (v.problems.length < this.maxProblems) v.problems.push({ lineNo, what, ...(seq !== undefined ? { seq } : {}) });
  }

  push(l: ActivityLine | null): void {
    const v = this.result;
    this.n += 1;
    v.lines = this.n;
    const n = this.n;
    if (!l) { this.flag(n, 'This line is damaged and cannot be read.'); this.prevLine = null; return; }
    if (v.firstSeq === undefined) v.firstSeq = l.seq;
    v.lastSeq = l.seq;
    const hashOk = chainHash(l.prev, digestOf(l)) === l.hash;
    if (!hashOk) this.flag(n, 'This line was changed after it was written.', l.seq);
    const p = this.prevLine;
    if (p) {
      if (l.seq !== p.seq + 1) this.flag(n, `Line numbers jump from ${p.seq} to ${l.seq}: lines are missing or out of order.`, l.seq);
      if (l.prev !== p.hash) this.flag(n, 'This line does not follow the one before it: a line was removed, added or changed.', l.seq);
    }
    if (l.key_fp && !l.sig) {
      this.flag(n, 'This line was signed when it was written, and its signature has been removed.', l.seq);
    }
    if (l.sig) {
      let ok = true;
      if (this.publicKey) {
        try { ok = crypto.verify('sha256', signedMessage(l.hash), this.publicKey, Buffer.from(l.sig, 'base64')); } catch { ok = false; }
        if (!ok) this.flag(n, 'The signature on this line is not this broker\'s.', l.seq);
      }
      if (ok) v.signed += 1;
    } else {
      v.unsigned += 1;
    }
    if (hashOk && l.seq >= this.keepHashesFrom) v.hashes.set(l.seq, l.hash);
    this.prevLine = l;
  }
}

export function verifyLines(
  lines: (ActivityLine | null)[], publicKey: crypto.KeyObject | null, maxProblems = 200,
): Verification {
  const ver = new Verifier(publicKey, maxProblems);
  for (const l of lines) ver.push(l);
  return ver.result;
}

/** Verify the whole file, streaming. */
export function verifyFile(file: string, publicKey: crypto.KeyObject | null, keepHashesFrom = 0): Verification {
  const ver = new Verifier(publicKey, 200, keepHashesFrom);
  forEachLineIn(file, (l) => ver.push(l));
  return ver.result;
}
