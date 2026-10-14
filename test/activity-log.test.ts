/**
 * The full, signed activity log and the server's copy of its chain (owner, 2026-10-13).
 *
 * Every tamper case is driven, not assumed: edit, delete, reorder, a foreign signature, a
 * cut-off tail, and a rewrite RE-SIGNED with the broker's own key — the case only the
 * server's copy can catch. The fake server below implements exactly what
 * app/routes/agent.py does: it folds digests itself and never lets the start move.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  ActivityLog, verifyLines, verifyFile, chainHash, digestOf, signerFromPem, shortFingerprint,
  GENESIS_PREV, signedMessage, redactAddress, type ActivityLine,
} from '../src/activity-log.js';
import { Anchorer, readCheck, type AnchorClient } from '../src/activity-anchor.js';
import { renderViewer, collectActivity, verdictOf } from '../src/log-viewer.js';
import type { AnchorState } from '../src/api-client.js';

let dir: string;
let file: string;
let clock: number;
const now = () => new Date(clock);

function keypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { pem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), pub: publicKey };
}

const K = keypair();
const call = (n: number, extra: Partial<ActivityLine> = {}) => ({
  kind: 'call' as const, outcome: 'sent', agent: 'Byte', key: 'Stripe', method: 'POST',
  address: `https://api.stripe.com:443/v1/charges?n=${n}`, reason: `charge ${n}`, status: 200, ...extra,
});

function lines(): string[] { return fs.readFileSync(file, 'utf8').trim().split('\n'); }
function writeLines(rows: string[]): void { fs.writeFileSync(file, rows.join('\n') + '\n'); }

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-activity-'));
  file = path.join(dir, 'activity.log');
  clock = Date.UTC(2026, 9, 13, 12, 0, 0);
});
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

describe('writing the log', () => {
  it('writes one signed line per use, each linked to the one before', () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 5; i += 1) { log.append(call(i)); clock += 1000; }
    const all = log.readAll();
    expect(all.map((l) => l!.seq)).toEqual([1, 2, 3, 4, 5]);
    expect(all[0]!.prev).toBe(GENESIS_PREV);
    for (let i = 1; i < 5; i += 1) expect(all[i]!.prev).toBe(all[i - 1]!.hash);
    const v = verifyLines(all, K.pub);
    expect(v.problemCount).toBe(0);
    expect(v.signed).toBe(5);
    expect(crypto.verify('sha256', signedMessage(all[2]!.hash), K.pub, Buffer.from(all[2]!.sig, 'base64'))).toBe(true);
  });

  it('is written owner-only', () => {
    new ActivityLog(file, () => null, now).append(call(1));
    if (process.platform !== 'win32') expect(fs.statSync(file).mode & 0o077).toBe(0);
  });

  it('keeps each line on one line and bounds what an agent can write into it', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1, { reason: `line one\nline two ${'x'.repeat(5000)}`, address: 'a'.repeat(9000) }));
    const l = log.readAll()[0]!;
    expect(lines()).toHaveLength(1);
    expect(l.reason!.includes('\n')).toBe(false);
    expect(l.reason!.length).toBeLessThanOrEqual(500);
    expect(l.address!.length).toBeLessThanOrEqual(2048);
  });

  it('writes unsigned lines, and says so, when this machine has no broker key yet', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1)); log.append(call(2));
    const v = verifyLines(log.readAll(), K.pub);
    expect(v.problemCount).toBe(0);
    expect(v.unsigned).toBe(2);
  });

  it('starts signing as soon as a key appears, without a restart', () => {
    let key: string | null = null;
    const log = new ActivityLog(file, () => (key ? signerFromPem(key) : null), now);
    log.append(call(1));
    key = K.pem;
    log.append(call(2));
    const v = verifyLines(log.readAll(), K.pub);
    expect([v.unsigned, v.signed, v.problemCount]).toEqual([1, 1, 0]);
  });

  it('cuts off an unfinished line from a crash instead of gluing the next line onto it', () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    log.append(call(1)); log.append(call(2));
    fs.appendFileSync(file, '{"v":1,"seq":3,"ts":"2026');
    log.append(call(3));
    const all = log.readAll();
    expect(all.map((l) => l?.seq)).toEqual([1, 2, 3]);
    expect(verifyLines(all, K.pub).problemCount).toBe(0);
  });
});

describe('finding tampering in the file', () => {
  const build = (n = 6) => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= n; i += 1) { log.append(call(i)); clock += 1000; }
    return log;
  };

  it('finds an edited line', () => {
    const log = build();
    const rows = lines();
    const l = JSON.parse(rows[2]); l.address = 'https://evil.example:443/'; rows[2] = JSON.stringify(l);
    writeLines(rows);
    const v = verifyLines(log.readAll(), K.pub);
    expect(v.problems.map((p) => p.seq)).toContain(3);
    expect(v.problems[0].what).toMatch(/changed/);
  });

  it('finds a removed line', () => {
    const log = build();
    const rows = lines(); rows.splice(3, 1); writeLines(rows);
    const v = verifyLines(log.readAll(), K.pub);
    expect(v.problemCount).toBeGreaterThan(0);
    expect(v.problems.some((p) => /jump|removed/.test(p.what))).toBe(true);
  });

  it('finds reordered lines', () => {
    const log = build();
    const rows = lines(); [rows[1], rows[2]] = [rows[2], rows[1]]; writeLines(rows);
    expect(verifyLines(log.readAll(), K.pub).problemCount).toBeGreaterThan(0);
  });

  it('finds a line signed by some other key', () => {
    const log = build();
    const other = keypair();
    const rows = lines();
    const l = JSON.parse(rows[1]);
    l.sig = crypto.sign('sha256', signedMessage(l.hash), crypto.createPrivateKey(other.pem)).toString('base64');
    rows[1] = JSON.stringify(l); writeLines(rows);
    const v = verifyLines(log.readAll(), K.pub);
    expect(v.problems.find((p) => p.seq === 2)?.what).toMatch(/signature/);
  });

  it('cannot see lines cut off the end on its own — that is the server copy\'s job', () => {
    const log = build();
    writeLines(lines().slice(0, 4));
    expect(verifyLines(log.readAll(), K.pub).problemCount).toBe(0);
  });

  it('streams the same verdict as it gives in memory', () => {
    const log = build(20);
    const rows = lines(); rows.splice(7, 1); writeLines(rows);
    expect(verifyFile(file, K.pub).problemCount).toBe(verifyLines(log.readAll(), K.pub).problemCount);
  });
});

describe('round 1 fixes', () => {
  it('finds a signature that was stripped off (F5)', () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem, 'TEST-KEY0'), now);
    log.append(call(1)); log.append(call(2));
    const rows = lines(); const l = JSON.parse(rows[1]); l.sig = ''; rows[1] = JSON.stringify(l); writeLines(rows);
    const v = verifyLines(log.readAll(), K.pub);
    expect(v.problems.find((p) => p.seq === 2)?.what).toMatch(/signature has been removed/);
  });

  it('reads a character split across two read chunks correctly (F8)', () => {
    // Unsigned lines, so every line's length is fixed by its content and a probe can find
    // the reason length that puts a two-byte "é" exactly across the 1 MiB read boundary.
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1, { reason: 'y'.repeat(450) }));
    let n = 2;
    while (fs.statSync(file).size < 1024 * 1024 - 1500) { log.append(call(n, { reason: 'y'.repeat(450) })); n += 1; }
    const size = fs.statSync(file).size;
    let placed = false;
    // In the address, which keeps up to 2,048 characters (a reason keeps 500).
    for (let pad = 0; pad < 2000 && !placed; pad += 1) {
      const probeFile = path.join(dir, 'probe.log');
      fs.copyFileSync(file, probeFile);
      new ActivityLog(probeFile, () => null, now).append(call(n, { address: 'https://x/' + 'z'.repeat(pad) + 'é' }));
      if (fs.readFileSync(probeFile).indexOf(Buffer.from('é'), size) === 1024 * 1024 - 1) {
        log.append(call(n, { address: 'https://x/' + 'z'.repeat(pad) + 'é' }));
        placed = true;
      }
    }
    expect(placed).toBe(true);
    expect(fs.readFileSync(file).indexOf(Buffer.from('é'), size)).toBe(1024 * 1024 - 1);
    expect(verifyFile(file, null).problemCount).toBe(0);
    expect(log.lastLine()!.address!.endsWith('é')).toBe(true);
  });

  it('reads past a huge stretch with no newline as ONE damaged line (round 2, B4)', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1));
    fs.appendFileSync(file, 'x'.repeat(600 * 1024) + '\n');
    log.append(call(2));
    const v = verifyFile(file, null);
    expect(v.lines).toBe(3);
    expect(v.problemCount).toBeGreaterThan(0);
    expect(v.problems[0].what).toMatch(/damaged/);
  });

  it('takes over a lock left by a process that is gone, without waiting (F2)', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1));
    fs.writeFileSync(`${file}.lock`, '999999');
    const t = Date.now();
    log.append(call(2));
    expect(Date.now() - t).toBeLessThan(200);
    expect(log.readAll()).toHaveLength(2);
  });

  it('writes a gap line for lines that could not be written (B3)', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1));
    fs.mkdirSync(`${file}.tmpdir`);
    const blocked = new ActivityLog(`${file}.tmpdir`, () => null, now); // a directory: appends fail
    expect(blocked.append(call(2))).toBeNull();
    (log as unknown as { failed: number }).failed = 2;
    log.append(call(3));
    const all = log.readAll();
    expect(all[1]).toMatchObject({ kind: 'gap', outcome: 'lost', extra: { lines: 2 } });
    expect(all[2]!.kind).toBe('call');
  });
});

describe('keeping a year', () => {
  it('removes only lines older than a year, records that it did, and stays verifiable', () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    const start = clock;
    for (let i = 1; i <= 6; i += 1) { log.append(call(i)); clock += 100 * 24 * 3600 * 1000; }
    clock = start + 400 * 24 * 3600 * 1000;
    const removed = log.prune();
    expect(removed).toBe(1);
    const all = log.readAll();
    expect(all[0]!.seq).toBe(2);
    expect(all[all.length - 1]!.kind).toBe('pruned');
    expect(all[all.length - 1]!.extra).toMatchObject({ lines: 1, through_seq: 1 });
    expect(verifyLines(all, K.pub).problemCount).toBe(0);
  });

  it('removes every line when all are old, and the removal record carries the chain on', () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem, 'TEST-KEY0'), now);
    log.append(call(1)); log.append(call(2));
    const last = log.lastLine()!;
    clock += 800 * 24 * 3600 * 1000;
    expect(log.prune()).toBe(2);
    const all = log.readAll();
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ kind: 'pruned', seq: last.seq + 1, prev: last.hash });
    expect(verifyLines(all, K.pub).problemCount).toBe(0);
  });

  it('never removes a line it cannot date', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1)); log.append(call(2));
    const rows = lines(); const l = JSON.parse(rows[0]); l.ts = 'not a date'; rows[0] = JSON.stringify(l); writeLines(rows);
    clock += 800 * 24 * 3600 * 1000;
    expect(log.prune()).toBe(0);
  });

  it('removes nothing our server has not held for a year', () => {
    const log = new ActivityLog(file, () => null, now);
    for (let i = 1; i <= 5; i += 1) log.append(call(i));
    clock += 800 * 24 * 3600 * 1000;
    expect(log.prune(undefined, 2)).toBe(2);
    expect(log.readAll()[0]!.seq).toBe(3);
    expect(log.prune(undefined, 0)).toBe(0);
  });
});

// ── the server's copy ────────────────────────────────────────────────────────

/** What app/routes/agent.py does, in memory. */
class FakeServer {
  chain: { seq: number; head: string } | null = null;
  mismatches: unknown[] = [];
  /** What the real server derives from its per-day marks; set by a test. */
  prunableThrough = 0;
  failPosts = false;
  emailFails = false;
  client(stream = 's1'): AnchorClient {
    return {
      label: 'Byte',
      getActivityAnchor: async (): Promise<AnchorState> => ({
        stream, seq: this.chain?.seq ?? null, head: this.chain?.head ?? null, prunable_through: this.prunableThrough,
      }),
      postActivityAnchor: async (b) => {
        if (this.failPosts) throw Object.assign(new Error('offline'), { status: 0 });
        if (!this.chain) {
          if (!b.start_prev) throw Object.assign(new Error('409'), { status: 409 });
          let h = b.start_prev; for (const d of b.digests) h = chainHash(h, d);
          this.chain = { seq: b.from_seq + b.digests.length - 1, head: h };
        } else {
          if (b.start_prev !== undefined || b.from_seq !== this.chain.seq + 1) throw Object.assign(new Error('409'), { status: 409 });
          let h = this.chain.head; for (const d of b.digests) h = chainHash(h, d);
          this.chain = { seq: this.chain.seq + b.digests.length, head: h };
        }
        return { stream, seq: this.chain.seq, head: this.chain.head };
      },
      reportActivityMismatch: async (b) => { this.mismatches.push(b); return { retry: this.emailFails }; },
    };
  }
}

function anchorer(log: ActivityLog, srv: FakeServer) {
  return new Anchorer(log, () => [srv.client()], {
    minIntervalMs: 0, delayMs: 0, checkFile: path.join(dir, 'check.json'), publicKey: () => K.pub,
  });
}

describe('the server\'s copy of the chain', () => {
  it('receives digests, never lines, and ends up with the same hash as the file', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 4; i += 1) log.append(call(i));
    const srv = new FakeServer();
    const r = await anchorer(log, srv).flush({ verifyLocal: true });
    expect(r.ok).toBe(true);
    expect(srv.chain).toEqual({ seq: 4, head: log.lastLine()!.hash });
    for (let i = 5; i <= 7; i += 1) log.append(call(i));
    expect((await anchorer(log, srv).flush()).ok).toBe(true);
    expect(srv.chain!.seq).toBe(7);
    expect(readCheck(path.join(dir, 'check.json'))!.ok).toBe(true);
  });

  it('a digest reveals nothing guessable: two identical uses get different digests', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1)); log.append(call(1));
    const [a, b] = log.readAll();
    const strip = (l: ActivityLine) => ({ ...l, seq: 0, prev: '', hash: '', sig: '' });
    expect(digestOf(strip(a!) as ActivityLine)).not.toBe(digestOf(strip(b!) as ActivityLine));
  });

  it('catches a rewrite RE-SIGNED with the broker\'s own key, and reports it once', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 5; i += 1) log.append(call(i));
    const srv = new FakeServer();
    await anchorer(log, srv).flush();
    // An administrator rewrites line 2 and re-chains and re-signs everything after it.
    const all = log.readAll() as ActivityLine[];
    all[1].address = 'https://elsewhere.example:443/';
    for (let i = 1; i < all.length; i += 1) {
      if (i > 1) all[i].prev = all[i - 1].hash;
      all[i].hash = chainHash(all[i].prev, digestOf(all[i]));
      all[i].sig = signerFromPem(K.pem).sign(signedMessage(all[i].hash));
    }
    writeLines(all.map((l) => JSON.stringify(l)));
    expect(verifyLines(log.readAll(), K.pub).problemCount).toBe(0); // the file alone looks fine
    const a = anchorer(log, srv);
    const r = await a.flush();
    expect(r.ok).toBe(false);
    expect(r.streams[0].problem).toMatch(/not the line the server recorded/);
    await a.flush();
    expect(srv.mismatches).toHaveLength(1);
    expect(srv.mismatches[0]).toMatchObject({ problem: 'changed', server_seq: 5 });
  });

  it('catches lines cut off the end', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 5; i += 1) log.append(call(i));
    const srv = new FakeServer();
    await anchorer(log, srv).flush();
    writeLines(lines().slice(0, 3));
    const r = await anchorer(log, srv).flush();
    expect(r.ok).toBe(false);
    expect(srv.mismatches[0]).toMatchObject({ problem: 'missing', server_seq: 5, local_last_seq: 3 });
  });

  it('cannot be fooled by starting over: the server never accepts a new start', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 3; i += 1) log.append(call(i));
    const srv = new FakeServer();
    await anchorer(log, srv).flush();
    fs.rmSync(file);
    const fresh = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 6; i += 1) fresh.append(call(100 + i));
    const r = await anchorer(fresh, srv).flush();
    expect(r.ok).toBe(false);
  });

  it('catches lines removed from the START that our server has not held for a year (F1)', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem, 'TEST-KEY0'), now);
    for (let i = 1; i <= 8; i += 1) log.append(call(i));
    const srv = new FakeServer();
    await anchorer(log, srv).flush();
    writeLines(lines().slice(3)); // lines 1-3 gone; the rest untouched and still anchored
    expect(verifyLines(log.readAll(), K.pub).problemCount).toBe(0);
    const r = await anchorer(log, srv).flush();
    expect(r.ok).toBe(false);
    expect(srv.mismatches[0]).toMatchObject({ problem: 'missing' });
    srv.prunableThrough = 3; // a year later: those three may go
    srv.mismatches = [];
    expect((await anchorer(log, srv).flush()).ok).toBe(true);
  });

  it('is not "all good" when one account\'s copy could not be checked (F3)', async () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1));
    const a = new FakeServer(); const b = new FakeServer();
    await new Anchorer(log, () => [a.client('A')], { minIntervalMs: 0, delayMs: 0, checkFile: path.join(dir, 'c.json') }).flush();
    log.append(call(2));
    b.failPosts = true;
    const r = await new Anchorer(log, () => [a.client('A'), b.client('B')], { minIntervalMs: 0, delayMs: 0, checkFile: path.join(dir, 'c.json') }).flush();
    expect(r.streams.find((s) => s.stream === 'A')!.matched).toBe(true);
    expect(r.streams.find((s) => s.stream === 'B')!.matched).toBeNull();
    expect(r.ok).toBeNull();
  });

  it('prunes by age alone when unpaired, and not at all when our server cannot be asked', async () => {
    const log = new ActivityLog(file, () => null, now);
    const unpaired = { label: 'x', getActivityAnchor: async () => { throw Object.assign(new Error('403'), { status: 403 }); },
      postActivityAnchor: async () => { throw new Error('no'); }, reportActivityMismatch: async () => {} } as AnchorClient;
    const offline = { ...unpaired, getActivityAnchor: async () => { throw Object.assign(new Error('down'), { status: 0 }); } } as AnchorClient;
    expect(await new Anchorer(log, () => [unpaired], { minIntervalMs: 0, delayMs: 0, checkFile: path.join(dir, 'c.json') }).pruneLimit()).toBeNull();
    expect(await new Anchorer(log, () => [offline], { minIntervalMs: 0, delayMs: 0, checkFile: path.join(dir, 'c.json') }).pruneLimit()).toBe(0);
  });

  it('reports lines removed from the MIDDLE to the server, not only locally (round 2, F2)', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem, 'TEST-KEY0'), now);
    for (let i = 1; i <= 10; i += 1) log.append(call(i));
    const srv = new FakeServer();
    await anchorer(log, srv).flush();
    const rows = lines(); rows.splice(2, 4); writeLines(rows); // first and last untouched
    const r = await anchorer(log, srv).flush({ verifyLocal: true });
    expect(r.ok).toBe(false);
    expect(srv.mismatches[0]).toMatchObject({ problem: 'damaged' });
  });

  it('keeps reporting until the owner has actually been emailed (round 2, F4)', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem, 'TEST-KEY0'), now);
    for (let i = 1; i <= 4; i += 1) log.append(call(i));
    const srv = new FakeServer();
    const a = anchorer(log, srv);
    await a.flush();
    writeLines(lines().slice(0, 2));
    srv.emailFails = true;
    await a.flush();
    await a.flush();
    expect(srv.mismatches).toHaveLength(2);
    srv.emailFails = false;
    await a.flush();
    await a.flush();
    expect(srv.mismatches).toHaveLength(3);
  });

  it('prunes nothing while any account could not be asked (round 2, F1)', async () => {
    const log = new ActivityLog(file, () => null, now);
    const srv = new FakeServer(); srv.prunableThrough = 100;
    const down = { label: 'x', getActivityAnchor: async () => { throw Object.assign(new Error('down'), { status: 0 }); },
      postActivityAnchor: async () => { throw new Error('no'); }, reportActivityMismatch: async () => {} } as AnchorClient;
    const a = new Anchorer(log, () => [srv.client('A'), down], { minIntervalMs: 0, delayMs: 0, checkFile: path.join(dir, 'c.json') });
    expect(await a.pruneLimit()).toBe(0);
  });

  it('catches up a long offline backlog in bounded batches and still matches (round 2, F3)', async () => {
    const log = new ActivityLog(file, () => null, now);
    for (let i = 1; i <= 50; i += 1) log.append(call(i));
    const srv = new FakeServer();
    const a = anchorer(log, srv);
    await a.flush();
    for (let i = 51; i <= 6200; i += 1) log.append(call(i));
    const r = await a.flush();
    expect(r.ok).toBe(true);
    expect(srv.chain!.seq).toBe(6200);
    expect(srv.chain!.head).toBe(log.lastLine()!.hash);
  });

  it('reports a local problem as not ok even when the server copy matches', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 4; i += 1) log.append(call(i));
    const srv = new FakeServer();
    await anchorer(log, srv).flush();
    const rows = lines(); const l = JSON.parse(rows[0]); l.reason = 'edited'; rows[0] = JSON.stringify(l); writeLines(rows);
    const r = await anchorer(log, srv).flush({ verifyLocal: true });
    expect(r.local!.problems).toBeGreaterThan(0);
    expect(r.ok).toBe(false);
  });

  it('says it could not check, rather than that all is well, when no agent can reach us', async () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1));
    const r = await new Anchorer(log, () => [], { minIntervalMs: 0, delayMs: 0, checkFile: path.join(dir, 'c.json') }).flush();
    expect(r.ok).toBeNull();
    expect(r.note).toMatch(/nothing was checked/);
  });
});

describe('the page the owner reads', () => {
  it('shows every use with its line fingerprint, and the verdict in words', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 3; i += 1) log.append(call(i));
    const srv = new FakeServer();
    await anchorer(log, srv).flush();
    const view = collectActivity(file, K.pub, readCheck(path.join(dir, 'check.json')));
    const html = renderViewer({ version: 1, seen: [] }, path.join(dir, 'network.json'), view);
    expect(html).toContain(shortFingerprint(log.lastLine()!.hash));
    expect(html).toContain('charge 3');
    expect(verdictOf(view).level).toBe('ok');
    expect(verdictOf(view).lines.join(' ')).toMatch(/matches Wundervault's copy up to line 3/);
  });

  it('does not repeat an old "all good" once lines have been cut off since (F9)', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem, 'TEST-KEY0'), now);
    for (let i = 1; i <= 6; i += 1) log.append(call(i));
    await anchorer(log, new FakeServer()).flush();
    writeLines(lines().slice(0, 3));
    const v = verdictOf(collectActivity(file, K.pub, readCheck(path.join(dir, 'check.json'))));
    expect(v.level).toBe('bad');
    expect(v.lines[0]).toMatch(/ends at line 3.*reaches line 6/);
  });

  it('lists 2,000 at a time with a way to see more (F7)', () => {
    const html = renderViewer({ version: 1, seen: [] }, 'x', collectActivity(file, null, null));
    expect(html).toContain('id="use-more"');
    expect(html).toContain('usesShown += 2000');
  });

  it('says plainly when the log was changed', () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem), now);
    for (let i = 1; i <= 3; i += 1) log.append(call(i));
    const rows = lines(); rows.splice(1, 1); writeLines(rows);
    const v = verdictOf(collectActivity(file, K.pub, null));
    expect(v.level).toBe('bad');
    expect(v.lines[0]).toMatch(/changed or damaged/);
  });

  it('cannot be scripted by what an agent wrote into a line', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1, { reason: '</script><img src=x onerror=PWNED>' }));
    const html = renderViewer({ version: 1, seen: [] }, 'x', collectActivity(file, null, null));
    const scripts = html.split('<script>')[1];
    expect(scripts).not.toContain('</script><img');
  });
});


describe('round 3 fixes', () => {
  it('keeps tokens other than the vault key out of the address (B2)', () => {
    expect(redactAddress('https://user:pw@api.example.com:443/reset?token=abc&page=2&X-Amz-Signature=f00#x'))
      .toBe('https://[REDACTED]@api.example.com:443/reset?token=[REDACTED]&page=2&X-Amz-Signature=[REDACTED]#x');
    expect(redactAddress('https://api.example.com:443/v1/charges?limit=5')).toBe('https://api.example.com:443/v1/charges?limit=5');
    expect(redactAddress('https://a.example:443/x?monkey=1&api_key=2')).toBe('https://a.example:443/x?monkey=1&api_key=[REDACTED]');
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1, { address: 'https://h.example:443/p?access_token=secret-value' }));
    expect(fs.readFileSync(file, 'utf8')).not.toContain('secret-value');
  });

  it('steps over a huge unfinished fragment at the end without reading it in (F2)', () => {
    const log = new ActivityLog(file, () => null, now);
    log.append(call(1));
    fs.appendFileSync(file, 'x'.repeat(3 * 1024 * 1024));
    log.append(call(2));
    const all = log.readAll();
    expect(all.map((l) => l?.seq)).toEqual([1, 2]);
    expect(verifyLines(all, null).problemCount).toBe(0);
  });

  it('keeps a damaged stretch in the middle when it prunes, without holding it (F2)', () => {
    const log = new ActivityLog(file, () => null, now);
    for (let i = 1; i <= 3; i += 1) log.append(call(i));
    fs.appendFileSync(file, 'y'.repeat(2 * 1024 * 1024) + '\n');
    clock += 400 * 24 * 3600 * 1000;
    log.append(call(4));
    clock += 1000;
    expect(log.prune()).toBe(3);
    expect(fs.readFileSync(file, 'utf8')).toContain('y'.repeat(1000));
    const all = log.readAll();
    expect(all[0]).toBeNull();                  // the damaged stretch, still there
    expect(all[all.length - 1]!.kind).toBe('pruned');
  });

  it('sends a long backlog at most once per interval, scheduled from the END of a run (F1)', async () => {
    const log = new ActivityLog(file, () => null, now);
    for (let i = 1; i <= 20_300; i += 1) log.append(call(i));
    const srv = new FakeServer();
    const a = new Anchorer(log, () => [srv.client()], { minIntervalMs: 400, delayMs: 0, checkFile: path.join(dir, 'c.json') });
    await a.flush();
    expect(srv.chain!.seq).toBe(20_000);
    await new Promise((r) => setTimeout(r, 150));
    expect(srv.chain!.seq).toBe(20_000);       // not two seconds later, not at once
    await new Promise((r) => setTimeout(r, 600));
    expect(srv.chain!.seq).toBe(20_300);
    a.stop();
  }, 30_000);

  it('says the log was rewritten when a line the last check vouched for has changed (B3)', async () => {
    const log = new ActivityLog(file, () => signerFromPem(K.pem, 'TEST-KEY0'), now);
    for (let i = 1; i <= 4; i += 1) log.append(call(i));
    await anchorer(log, new FakeServer()).flush();
    // Same length, re-chained and re-signed with the broker's own key.
    const all = log.readAll() as ActivityLine[];
    all[1].reason = 'charge X';
    for (let i = 1; i < all.length; i += 1) {
      if (i > 1) all[i].prev = all[i - 1].hash;
      all[i].hash = chainHash(all[i].prev, digestOf(all[i]));
      all[i].sig = signerFromPem(K.pem).sign(signedMessage(all[i].hash));
    }
    writeLines(all.map((l) => JSON.stringify(l)));
    const v = verdictOf(collectActivity(file, K.pub, readCheck(path.join(dir, 'check.json'))));
    expect(v.level).toBe('bad');
    expect(v.lines[0]).toMatch(/rewritten since it was last checked/);
  });
});
