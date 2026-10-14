/**
 * Keeping the server's copy of the activity log's chain, and checking the log against it.
 *
 * WHAT THE SERVER GETS: for each line, its digest — a sha256 over the line's content,
 * which includes a random salt, so the digest cannot be confirmed by guessing what the line
 * said. Never the line. The server folds each digest into its own copy of the chain
 * (`hash = sha256("wv-activity-chain-v1\n" + prev + "\n" + digest)`), computing the hash
 * itself rather than taking ours, and refuses anything that does not continue from where
 * its copy ends.
 *
 * WHY THAT CATCHES AN ADMINISTRATOR. Someone with administrator rights can read the broker
 * key, rewrite the file and re-sign every line, so the file checks out on its own. But
 * every line's hash depends on every line before it: change one, and the hash at the
 * server's last line changes too. The server will not accept a new starting point from the
 * broker, so the rewritten file can never be made to agree with it. The same holds for
 * lines cut off the end: the server's copy is longer than the file.
 *
 * WHAT IT DOES NOT CATCH: lines that were never anchored — written in the minute before a
 * rewrite, or while the machine was offline — and a broker that is stopped from reporting.
 * The dashboard shows when the server last heard from each machine, so silence is visible.
 *
 * Owner's choice, 2026-10-13: "Signed + checked by us".
 */
import fs from 'node:fs';
import type crypto from 'node:crypto';
import { ActivityLog, activityCheckPath, verifyFile, digestOf, chainHash,
         type ActivityLine } from './activity-log.js';
import type { AnchorState } from './api-client.js';

export interface AnchorClient {
  /** Which agent this goes through, for messages only. */
  readonly label: string;
  getActivityAnchor(): Promise<AnchorState>;
  postActivityAnchor(body: { from_seq: number; start_prev?: string; digests: string[] }): Promise<AnchorState>;
  /** `retry: true` when the owner could not be emailed yet, so the broker reports again. */
  reportActivityMismatch(body: { problem: 'changed' | 'missing' | 'damaged'; server_seq: number; local_last_seq: number | null }): Promise<{ retry?: boolean } | void>;
}

export interface StreamStatus {
  stream: string;
  server_seq: number | null;
  /** The server's hash at server_seq, so the viewer can recompare the file it is showing. */
  server_head?: string | null;
  server_updated_at?: string | null;
  /** true: the log agrees with the server. false: it does not. null: could not tell. */
  matched: boolean | null;
  problem?: string;
}

export interface CheckResult {
  checked_at: string;
  /** true only when EVERY stream matched; false when any did not; otherwise null (not confirmed). */
  ok: boolean | null;
  local_last_seq: number | null;
  streams: StreamStatus[];
  /** Local verification of the file itself (chain and signatures). */
  local?: { lines: number; problems: number; signed: number; unsigned: number };
  note?: string;
}

/** The most digests in one request. The server enforces the same cap. */
export const MAX_DIGESTS = 1000;

export class Anchorer {
  private timer: NodeJS.Timeout | null = null;
  private lastFlush = 0;
  private running: Promise<CheckResult> | null = null;
  private streams = new Map<string, AnchorClient>();
  private streamsAt = 0;
  /** Streams already reported in this process, so one mismatch is one alert, not one per minute. */
  private reported = new Set<string>();
  /** A run that could not send everything sets this; the next run is scheduled after it ends. */
  private morePending = false;

  constructor(
    private readonly log: ActivityLog,
    private readonly clients: () => AnchorClient[],
    private readonly opts: {
      minIntervalMs: number; delayMs: number; checkFile?: string;
      /** For the local signature check. Passed in: this module never reads the key. */
      publicKey?: () => crypto.KeyObject | null;
    } = { minIntervalMs: 60_000, delayMs: 2_000 },
  ) {}

  /** Called after each append: anchor soon, but at most once a minute while busy. */
  notify(): void {
    if (this.timer) return;
    const wait = Math.max(this.opts.delayMs, this.lastFlush + this.opts.minIntervalMs - Date.now());
    this.timer = setTimeout(() => { this.timer = null; void this.flush(); }, wait);
    (this.timer as unknown as { unref?: () => void }).unref?.();
  }

  stop(): void {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
  }

  /** Anchor whatever is new, and check the log against the server. One run at a time. */
  flush(opts: { verifyLocal?: boolean } = {}): Promise<CheckResult> {
    if (this.running) return this.running;
    this.running = this.run(opts.verifyLocal === true)
      .catch((e): CheckResult => ({
        checked_at: new Date().toISOString(), ok: null, local_last_seq: null, streams: [],
        note: `The check could not run: ${(e as Error).message}`,
      }))
      .then((r) => { this.writeCheck(r); return r; })
      .finally(() => {
        this.running = null;
        this.lastFlush = Date.now();
        // Scheduled only now, from this run's end, so a backlog is sent at most once a
        // minute (round 3, F1: it used to restart two seconds later).
        if (this.morePending) { this.morePending = false; this.notify(); }
      });
    return this.running;
  }

  /**
   * One agent per stream. A stream is one account's chain for this machine; a machine whose
   * agents all belong to one account has one. Asked of every agent, because the broker does
   * not otherwise know which account an agent belongs to, and refreshed every ten minutes so
   * an agent enrolled later is picked up.
   */
  /** Set by resolveStreams: whether any agent failed for a reason other than "not paired". */
  private unreachable = false;

  private async resolveStreams(force = false): Promise<Map<string, AnchorClient>> {
    if (!force && this.streams.size > 0 && Date.now() - this.streamsAt < 10 * 60_000) return this.streams;
    const out = new Map<string, AnchorClient>();
    let unreachable = false;
    for (const c of this.clients()) {
      try {
        const st = await c.getActivityAnchor();
        if (st && typeof st.stream === 'string' && !out.has(st.stream)) out.set(st.stream, c);
      } catch (e) {
        // 403: this agent is not held by a paired broker, so it has no chain. Anything else
        // (offline, revoked, a server error) means we could not ask.
        if ((e as { status?: number }).status !== 403) unreachable = true;
      }
    }
    this.streams = out;
    this.streamsAt = Date.now();
    this.unreachable = unreachable;
    return out;
  }

  /**
   * How far the daily prune may go: the lowest `prunable_through` across this machine's
   * chains, so no line is removed before every account's copy has held it for a year.
   * null when no agent here is paired (nothing to check against: prune by age alone);
   * 0 when paired but our server could not be asked (prune nothing today).
   */
  async pruneLimit(): Promise<number | null> {
    const streams = await this.resolveStreams(true);
    // Any account we could not ask might still need the oldest lines: prune nothing today
    // (round 2, F1).
    if (this.unreachable) return 0;
    if (streams.size === 0) return null;
    let limit = Number.MAX_SAFE_INTEGER;
    for (const c of streams.values()) {
      try {
        const st = await c.getActivityAnchor();
        limit = Math.min(limit, typeof st.prunable_through === 'number' ? st.prunable_through : 0);
      } catch { return 0; }
    }
    return limit === Number.MAX_SAFE_INTEGER ? 0 : limit;
  }

  private async run(verifyLocal: boolean): Promise<CheckResult> {
    const result: CheckResult = {
      checked_at: new Date().toISOString(), ok: null,
      local_last_seq: this.log.lastLine()?.seq ?? null, streams: [],
    };
    if (verifyLocal) {
      const v = verifyFile(this.log.file, this.opts.publicKey?.() ?? null, Number.MAX_SAFE_INTEGER);
      result.local = { lines: v.lines, problems: v.problemCount, signed: v.signed, unsigned: v.unsigned };
    }
    const streams = await this.resolveStreams();
    if (streams.size === 0) {
      result.note = 'No paired agent could reach Wundervault, so nothing was checked against it.';
      return result;
    }
    for (const [stream, client] of streams) {
      result.streams.push(await this.anchorOne(stream, client));
    }
    // Damage inside the log (a line removed from the middle, an edit) is found by the local
    // verification, not by comparing end points. It is reported like a mismatch, so the
    // owner hears about it the same way (round 2, F2).
    if (result.local && result.local.problems > 0) {
      for (const [stream, client] of streams) {
        const st = result.streams.find((x) => x.stream === stream);
        if (st && st.matched !== false) {
          await this.mismatch(client, st, 'damaged', st.server_seq ?? 0, result.local_last_seq,
            `${result.local.problems} line${result.local.problems === 1 ? '' : 's'} in this computer's log were changed, removed or reordered.`);
        }
      }
    }
    // Confirmed only if EVERY account's copy was checked and matched (round 1, F3).
    result.ok = result.streams.some((s) => s.matched === false) ? false
      : result.streams.every((s) => s.matched === true) ? true : null;
    if (this.unreachable && result.ok === true) result.ok = null;
    if (result.local && result.local.problems > 0) result.ok = false;
    return result;
  }

  private async anchorOne(stream: string, client: AnchorClient): Promise<StreamStatus> {
    let state = await client.getActivityAnchor();
    const status: StreamStatus = { stream, server_seq: state.seq, server_updated_at: state.updated_at, matched: null };
    const last = this.log.lastLine();

    // Compare first: is what we have consistent with what the server already holds?
    if (state.seq !== null && state.head) {
      if (!last || last.seq < state.seq) {
        return this.mismatch(client, status, 'missing', state.seq, last?.seq ?? null,
          `The server has lines up to ${state.seq}; this computer's log ends at ${last?.seq ?? 'nothing'}.`);
      }
      // The start of the log: lines may only be missing there if our server has held them
      // for over a year. Otherwise someone removed them (round 1, F1).
      const first = this.log.firstLine();
      if (first && typeof state.prunable_through === 'number' && first.seq - 1 > state.prunable_through) {
        return this.mismatch(client, status, 'missing', state.seq, last.seq,
          `Lines before ${first.seq} are gone from this computer's log, but Wundervault has not held them for a year yet.`);
      }
      const at = this.lineAt(state.seq);
      if (at === undefined) {
        // Pruned past the server's point (a machine offline for a year): nothing to compare.
        status.problem = `Line ${state.seq} is no longer in the log, so it could not be compared.`;
      } else if (!at || at.hash !== state.head) {
        return this.mismatch(client, status, 'changed', state.seq, last.seq,
          `Line ${state.seq} on this computer is not the line the server recorded.`);
      }
    }

    // Then extend the server's copy with whatever is new.
    let pending: ActivityLine[];
    let startPrev: string | undefined;
    if (state.seq === null) {
      const first = this.log.firstLine();
      if (!first) { status.matched = true; return status; }
      startPrev = first.prev;
      pending = this.log.linesBetween(first.seq - 1, 20 * MAX_DIGESTS);
    } else if (last && last.seq - state.seq > 5000) {
      // A long backlog (a computer that was offline): bounded batches, more next run.
      pending = this.log.linesBetween(state.seq, 20 * MAX_DIGESTS);
    } else {
      pending = this.log.linesAfter(state.seq);
    }
    if (pending.length > 0 && state.seq !== null && pending[0].seq !== state.seq + 1) {
      status.problem = `The log cannot continue the server's copy: the next line it has is ${pending[0].seq}.`;
      return status;
    }
    for (let i = 0; i < pending.length; i += MAX_DIGESTS) {
      const batch = pending.slice(i, i + MAX_DIGESTS);
      const body: { from_seq: number; start_prev?: string; digests: string[] } = {
        from_seq: batch[0].seq, digests: batch.map(digestOf),
      };
      if (i === 0 && startPrev !== undefined) body.start_prev = startPrev;
      try {
        state = await client.postActivityAnchor(body);
      } catch (e) {
        const err = e as { status?: number; message?: string };
        // 409: someone else extended it first (another agent of this account, a second run).
        // The next run starts from the server's new position and compares again.
        status.problem = err.status === 409
          ? 'The server moved on while this was sending; it will be compared on the next run.'
          : `Could not reach Wundervault: ${err.message ?? 'unknown error'}`;
        return status;
      }
      const sent = batch[batch.length - 1];
      // The server computed this itself. If it does not equal ours, our own lines disagree
      // with their stored hashes, which the verification will name.
      if (state.seq !== sent.seq || state.head !== sent.hash) {
        return this.mismatch(client, status, 'changed', state.seq ?? sent.seq, this.log.lastLine()?.seq ?? null,
          `The server's copy of line ${sent.seq} came out different from this computer's.`);
      }
    }
    status.server_seq = state.seq;
    status.server_head = state.head;
    status.server_updated_at = state.updated_at;
    status.matched = true;
    // More left than one run sends: come back for it, once this run is over.
    if ((this.log.lastLine()?.seq ?? 0) > (state.seq ?? 0)) this.morePending = true;
    return status;
  }

  /** The line with this seq, null if present but unreadable, undefined if not in the file. */
  private lineAt(seq: number): ActivityLine | null | undefined {
    // Streamed forward to that one line when it is far back (round 2, F3): reading backwards
    // from the end would hold the whole backlog after it.
    const lastSeq = this.log.lastLine()?.seq ?? 0;
    const after = lastSeq - seq > 5000 ? this.log.linesBetween(seq - 1, 1) : this.log.linesAfter(seq - 1);
    if (after.length > 0 && after[0].seq === seq) {
      // Recheck the hash from the content: a stored hash alone proves nothing about the line.
      const l = after[0];
      return chainHash(l.prev, digestOf(l)) === l.hash ? l : null;
    }
    const first = this.log.firstLine();
    if (first && seq < first.seq) return undefined;
    return null;
  }

  private async mismatch(
    client: AnchorClient, status: StreamStatus, problem: 'changed' | 'missing' | 'damaged',
    serverSeq: number, localLast: number | null, message: string,
  ): Promise<StreamStatus> {
    status.matched = false;
    status.problem = message;
    if (!this.reported.has(status.stream)) {
      try {
        const r = await client.reportActivityMismatch({ problem, server_seq: serverSeq, local_last_seq: localLast });
        // Remembered only once the owner has been told: the server says when its email did
        // not go, and the next run reports again (round 2, F4).
        if (!(r && r.retry)) this.reported.add(status.stream);
      } catch { /* reported on the next run */ }
    }
    console.error(`[wundervault-agent] ACTIVITY LOG DOES NOT MATCH WUNDERVAULT'S COPY: ${message}`);
    return status;
  }

  private writeCheck(r: CheckResult): void {
    const file = this.opts.checkFile ?? activityCheckPath();
    try {
      const tmp = `${file}.tmp-${process.pid}`;
      fs.writeFileSync(tmp, JSON.stringify(r, null, 2), { mode: 0o600 });
      fs.renameSync(tmp, file);
    } catch { /* the viewer will say there is no recent check */ }
  }
}

/** The last check written by the broker, or null. */
export function readCheck(file = activityCheckPath()): CheckResult | null {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')) as CheckResult; } catch { return null; }
}
