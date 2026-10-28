/**
 * Read the local destination log in a browser, without any of it leaving the machine.
 *
 * The record of where an agent's secrets go was deliberately taken off the server, and
 * this is the other half of that decision: a record nobody can read is not much better
 * than no record. A JSON file on disk is technically readable and practically is not —
 * "which destinations did this key reach last Tuesday" is not a question anyone answers
 * by scrolling raw JSON.
 *
 * WHAT THIS DELIBERATELY IS NOT
 *
 * 1. NOT a page on wundervault.com that you paste the file into. That would send the
 *    whole profile to the server we just spent the effort not sending it to, and would be
 *    worse than never having moved it, because it would arrive in one piece rather than a
 *    call at a time.
 *
 * 2. NOT a localhost web server. This is the variant that looks convenient and quietly
 *    undoes phase 4. Once the store moves to a daemon-owned path the agent's uid can no
 *    longer read it — but anything on the machine can connect to 127.0.0.1, including the
 *    agent. A local server would hand back over a socket exactly what the uid split took
 *    away, and it would do it without the agent needing any privilege at all.
 *
 * 3. NOT a page that loads anything. No CDN, no web fonts, no analytics. Everything is
 *    inlined, and the page carries a Content-Security-Policy of `default-src 'none'` with
 *    no `connect-src`, so it cannot make a network request even if someone edits it later
 *    or tricks it into trying. The page holds a behavioural profile; it should be
 *    structurally incapable of sending one.
 *
 * What it IS: one self-contained HTML file with the data already inside it, written
 * 0600 next to the store, which you open with your own browser and delete when done.
 */
import { writeFileSync, readFileSync, mkdirSync, chmodSync, accessSync, existsSync,
         openSync, closeSync, renameSync, unlinkSync, statSync, constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import * as path from 'node:path';
import { load, defaultStorePath, type NetworkShape } from './network-store.js';
import { viewerPath } from './paths.js';
import { WORDMARK_PATH, WORDMARK_VIEWBOX } from './brand.js';
import type { KeyObject } from 'node:crypto';
import { forEachLineIn, Verifier, shortFingerprint, type ActivityLine, type Problem } from './activity-log.js';
import type { CheckResult } from './activity-anchor.js';
import { sudoHint } from './launcher.js';

/**
 * The full activity log, as the page shows it (2026-10-13). Read as root by the CLI, verified
 * here, and embedded like the destination summary: the page still loads nothing.
 */
export interface ActivityView {
  logPath: string;
  /** The most recent lines, oldest first. The page holds at most `maxLines`. */
  lines: ActivityLine[];
  total: number;
  problems: Problem[];
  problemCount: number;
  signed: number;
  unsigned: number;
  /** False when this computer's broker key could not be read, so signatures were not checked. */
  keyAvailable: boolean;
  check: CheckResult | null;
  missing?: boolean;
  /** The last line in the file now, to set against the last check (round 1, F9). */
  lastSeq?: number;
  /** For each line the last check named: does the file's line there still have that hash? */
  checkpointsMatch?: boolean;
}

/** Verify the whole log, streaming, and keep the newest lines for the page. */
export function collectActivity(
  logPath: string, publicKey: KeyObject | null, check: CheckResult | null, maxLines = 20_000,
): ActivityView {
  const ver = new Verifier(publicKey, 200, Number.MAX_SAFE_INTEGER);
  const keep: ActivityLine[] = [];
  let missing = false;
  try { statSync(logPath); } catch { missing = true; }
  // The lines the last check vouched for, and the hashes it saw there (round 3, B3): a file
  // rewritten since — even to the same length, even re-signed — no longer has those hashes.
  const want = new Map<number, string>();
  for (const st of check?.streams ?? []) {
    if (st.matched === true && typeof st.server_seq === 'number' && st.server_head) want.set(st.server_seq, st.server_head);
  }
  let checkpointsMatch = true;
  forEachLineIn(logPath, (l) => {
    ver.push(l);
    if (l) {
      keep.push(l); if (keep.length > maxLines) keep.shift();
      const h = want.get(l.seq);
      if (h !== undefined && h !== l.hash) checkpointsMatch = false;
    }
  });
  const v = ver.result;
  return {
    logPath, lines: keep, total: v.lines, problems: v.problems, problemCount: v.problemCount,
    signed: v.signed, unsigned: v.unsigned, keyAvailable: publicKey !== null, check, missing,
    lastSeq: v.lastSeq,
    checkpointsMatch,
  };
}

/** One plain sentence, or a few, about whether the log can be trusted. Text only. */
export function verdictOf(a: ActivityView): { level: 'ok' | 'bad' | 'unknown'; lines: string[] } {
  const out: string[] = [];
  // The last check is a snapshot. If our server's copy reached further than the file does
  // NOW, lines were removed since — whatever that check said at the time (round 1, F9).
  const reach = Math.max(0, ...(a.check?.streams ?? []).map((s) => s.server_seq ?? 0));
  if (reach > 0 && (a.missing || (a.lastSeq ?? 0) < reach)) {
    return { level: 'bad', lines: [
      a.missing
        ? `This computer's log is gone, but Wundervault's copy reaches line ${reach}.`
        : `This log ends at line ${a.lastSeq ?? 0}, but Wundervault's copy reaches line ${reach}: lines were removed.`,
    ] };
  }
  if (a.missing) return { level: 'unknown', lines: ['There is no activity log on this computer yet. It starts with the first use of a secret.'] };
  if (a.checkpointsMatch === false) {
    return { level: 'bad', lines: ['This log has been rewritten since it was last checked: a line no longer matches what Wundervault recorded for it.'] };
  }
  if (a.problemCount > 0) {
    out.push(`This log has been changed or damaged: ${a.problemCount} problem${a.problemCount === 1 ? '' : 's'} found.`);
    for (const p of a.problems.slice(0, 20)) out.push(`Line ${p.seq ?? `#${p.lineNo} in the file`}: ${p.what}`);
    return { level: 'bad', lines: out };
  }
  const c = a.check;
  const bad = c?.streams.find((s) => s.matched === false);
  if (c && c.ok === false && bad) {
    out.push(`This log does not match Wundervault's copy: ${bad.problem ?? 'they differ.'}`);
    out.push(`Checked ${new Date(c.checked_at).toLocaleString()}.`);
    return { level: 'bad', lines: out };
  }
  out.push(`All ${a.total} line${a.total === 1 ? '' : 's'} are linked to the one before${a.keyAvailable ? ', and every signed line is signed by this computer\'s broker' : ''}.`);
  if (!a.keyAvailable) out.push("This computer's broker key could not be read, so the signatures were not checked.");
  if (a.unsigned > 0) out.push(`${a.unsigned} line${a.unsigned === 1 ? ' was' : 's were'} written before this broker had a key, and ${a.unsigned === 1 ? 'is' : 'are'} not signed.`);
  const good = c?.streams.find((s) => s.matched === true);
  const unchecked = c?.streams.find((s) => s.matched === null);
  if (c && c.ok === true && good && !unchecked) {
    out.push(`It matches Wundervault's copy up to line ${good.server_seq ?? 0} (checked ${new Date(c.checked_at).toLocaleString()}).`);
    return { level: 'ok', lines: out };
  }
  out.push(c ? `Not confirmed against Wundervault's copy: ${c.note ?? c.streams.find((s) => s.problem)?.problem ?? 'the last check could not tell.'}`
             : "Not yet checked against Wundervault's copy. The broker checks within a minute of starting, and daily.");
  return { level: 'unknown', lines: out };
}

/** Escape for embedding inside an HTML text node or attribute. */
/**
 * Direction controls (U+061C, U+200E/F, U+202A-202E, U+2066-2069) are invisible and make text
 * DISPLAY in a different order from the one recorded: an address or a reason written with one
 * can read as something else. This page is where an owner checks what an agent did, so the
 * controls are shown as visible codes, never obeyed. The same expression is in the page script.
 */
const BIDI = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
function showBidi(s: string): string {
  return String(s).replace(BIDI, (c) => `⟨U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}⟩`);
}

function esc(s: string): string {
  return showBidi(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Embed JSON inside a <script> without letting its contents end the script.
 *
 * A purpose string is agent-written, so it is attacker-influenced text being placed in a
 * page the OWNER opens. `</script>` inside it would close the block early and everything
 * after would parse as markup — which is script injection into the one tool someone uses
 * when they already suspect their agent. Escaping the sequences that can break out is
 * what keeps this a viewer rather than a payload.
 */
function embedJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
    // Direction controls as JSON escapes: the page still gets the exact value, and the file
    // never carries one raw (a viewer of the source would be fooled by it as well).
    .replace(BIDI, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

/** The check's result in words, shown above its sentences; the colour only repeats it. */
const VERDICT_LABEL = { ok: 'Checks out', bad: 'Problem found', unknown: 'Not confirmed' } as const;

export function renderViewer(shape: NetworkShape, storePath: string, activity?: ActivityView): string {
  const verdict = activity ? verdictOf(activity) : null;
  const uses = (activity?.lines ?? []).slice().reverse().map((l) => ({
    seq: l.seq, ts: l.ts, fp: shortFingerprint(l.hash), kind: l.kind, agent: l.agent ?? '',
    key: l.key ?? l.entry_id ?? '', method: l.method ?? '', address: l.address ?? '',
    reason: l.reason ?? '', outcome: l.outcome, status: l.status ?? null, approval: l.approval ?? '',
    detail: l.detail ?? '', extra: l.extra ?? {}, signed: !!l.sig,
  }));
  // Each row is normalised here, so a damaged record shows as a damaged value instead of
  // stopping the page script (purposes: [null] used to throw in render(), which also kept the
  // activity table from appearing) or carrying a raw string into a sum.
  const str = (v: unknown) => (typeof v === 'string' ? v : v == null ? '' : String(v));
  // A record that is not an object at all (null, a number) is still a row: marked damaged.
  const rows = shape.seen.map((rec) => (rec && typeof rec === 'object' ? rec
    : { entryId: '(damaged record)' } as unknown as NetworkShape['seen'][number])).map((s) => ({
    entryId: str(s.entryId),
    origin: str(s.origin),
    firstSeen: str(s.firstSeen),
    lastSeen: str(s.lastSeen),
    count: Number.isFinite(Number(s.count)) ? Number(s.count) : 0,
    purposes: Array.isArray(s.purposes) ? s.purposes.filter((x): x is string => typeof x === 'string') : [],
  }));

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- No network. Not "does not use the network" — cannot. There is no connect-src, no
     img-src and no font-src, so a fetch, an XHR, a WebSocket, a beacon and a tracking
     pixel are all refused by the browser rather than by this page's good intentions. -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Wundervault — your broker's log</title>
<meta name="color-scheme" content="dark light">
<script>
  // Before first paint, so a saved Light or Dark does not flash the other one. A file page may
  // refuse storage outright; then the page simply starts on Auto.
  try { var m = localStorage.getItem('wv-log-theme');
        if (m === 'light' || m === 'dark') document.documentElement.setAttribute('data-theme', m); } catch (e) {}
</script>
<style>
  /* Wundervault's own tokens (burnbox app/static/css/site.css, 1.0). Dark is the default, as on
     the site. Green is a text colour only in dark: on white it is 1.7:1, so light mode draws
     text and thin lines in ink and keeps the green for fills — the site's own rule. The site's
     dimmest grey (#5d7a6c) is not used for text: it is 3.9:1 on the dark panels. */
  :root{
    color-scheme:dark;
    --bg:#060a08; --panel:#0b1014; --panel2:#0d141a; --fg:#d8efe2; --muted:#a2b9ac;
    --border:#19261f; --border-strong:#4b6a5a; --brand:#3ce078; --brand-on:#04130a;
    --label:#3ce078; --focus:#3ce078; --danger:#ff5a5a; --danger-on:#04130a;
    --grid:rgba(60,224,120,.055);
    --glow:drop-shadow(0 0 7px rgba(60,224,120,.55)) drop-shadow(0 0 18px rgba(60,224,120,.25));
    --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    --read:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  }
  @media (prefers-color-scheme: light){:root:not([data-theme="dark"]){
    color-scheme:light;
    --bg:#fafafa; --panel:#fff; --panel2:#f3f4f4; --fg:#0e1410; --muted:#526058;
    --border:#dee1de; --border-strong:#8a958f; --label:#0e1410; --focus:#0e1410; --danger:#c2261c; --danger-on:#fff;
    --grid:rgba(60,224,120,.11); --glow:none;
  }}
  :root[data-theme="light"]{
    color-scheme:light;
    --bg:#fafafa; --panel:#fff; --panel2:#f3f4f4; --fg:#0e1410; --muted:#526058;
    --border:#dee1de; --border-strong:#8a958f; --label:#0e1410; --focus:#0e1410; --danger:#c2261c; --danger-on:#fff;
    --grid:rgba(60,224,120,.11); --glow:none;
  }
  *{box-sizing:border-box}
  html{background:var(--bg)}
  body{margin:0;color:var(--fg);font:15px/1.6 var(--read);background-color:var(--bg);
    background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
    background-size:40px 40px}
  ::selection{background:var(--brand);color:var(--brand-on)}
  .top{border-bottom:1px solid var(--border);background:var(--bg)}
  .top-in,.wrap{max-width:1040px;margin:0 auto;padding-inline:20px}
  .top-in{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;padding-block:18px}
  .wordmark{display:block;height:17px;width:auto;color:var(--label);filter:var(--glow);flex:none}
  .theme{display:inline-flex;border:1px solid var(--border-strong);border-radius:6px;overflow:hidden}
  .theme button{border:0;border-radius:0;background:transparent;color:var(--muted);padding:7px 12px;
    font:600 12px/1 var(--mono);letter-spacing:.06em;text-transform:uppercase}
  .theme button+button{border-left:1px solid var(--border-strong)}
  .theme button[aria-pressed="true"]{background:var(--brand);color:var(--brand-on)}
  .wrap{padding-block:36px 72px}
  .eyebrow{margin:0 0 10px;font:600 12px/1.4 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--label)}
  h1{font:700 clamp(26px,4.5vw,40px)/1.15 var(--mono);letter-spacing:-.01em;margin:0 0 12px}
  .sub{color:var(--muted);margin:0 0 6px;max-width:70ch;font-size:16px}
  .path{font:12px/1.5 var(--mono);color:var(--muted);word-break:break-all;margin:0 0 24px}
  .seal{border:1px solid var(--border);border-left:3px solid var(--brand);background:var(--panel);
    padding:12px 16px;margin:0 0 26px;font-size:13.5px;color:var(--muted);border-radius:6px}
  .bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 18px}
  input[type=search]{flex:1 1 260px;min-width:0;padding:10px 12px;font:14px var(--read);
    background:var(--panel);color:var(--fg);border:1px solid var(--border-strong);border-radius:6px}
  input[type=search]::placeholder{color:var(--muted)}
  button{padding:9px 14px;font:600 12px/1.2 var(--mono);letter-spacing:.06em;background:var(--panel);color:var(--fg);
    border:1px solid var(--border-strong);border-radius:6px;cursor:pointer}
  button:hover{border-color:var(--brand)}
  :focus-visible{outline:2px solid var(--focus);outline-offset:2px}
  /* Inside the group, which clips its corners: draw the ring inside the button, and on the
     pressed (green) one in the dark ink that reads on green. */
  .theme button:focus-visible{outline-offset:-4px}
  .theme button[aria-pressed="true"]:focus-visible{outline-color:var(--brand-on)}
  /* High-contrast modes replace our colours, so the chosen mode also gets a mark that survives. */
  @media (forced-colors: active){.theme button[aria-pressed="true"]{outline:2px solid CanvasText;outline-offset:-4px;text-decoration:underline}}
  .count{font-size:13px;color:var(--muted)}
  .tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:6px;background:var(--panel)}
  table{border-collapse:collapse;width:100%;min-width:640px;background:var(--panel);font-size:13.5px}
  th,td{text-align:left;padding:10px 13px;border-bottom:1px solid var(--border);vertical-align:top}
  th{font:600 11px/1.4 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
    background:var(--panel2);cursor:pointer;white-space:nowrap;user-select:none}
  tbody tr:hover td{background:var(--panel2)}
  tr:last-child td{border-bottom:none}
  td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;font-family:var(--mono)}
  .origin{font-family:var(--mono);word-break:break-all}
  .when{white-space:nowrap;color:var(--muted);font-size:12.5px}
  .why{margin:8px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:4px}
  .why li{font-size:12.5px;color:var(--muted);border-left:2px solid var(--border-strong);padding-left:9px}
  .why time{color:var(--fg)}
  mark{background:var(--brand);color:var(--brand-on);border-radius:2px;padding:0 2px}
  .empty{padding:36px 16px;text-align:center;color:var(--muted)}
  footer{margin-top:30px;padding-top:18px;border-top:1px solid var(--border);font-size:12px;color:var(--muted);line-height:1.7}
  .foot-mark{display:block;margin-bottom:4px;font:700 12px/1.4 var(--mono);letter-spacing:.16em;color:var(--fg)}
  h2{font:700 18px/1.3 var(--mono);margin:36px 0 12px}
  .verdict{border:1px solid var(--border);border-left:3px solid var(--muted);background:var(--panel);
    padding:12px 16px;margin:0 0 18px;font-size:14px;border-radius:6px}
  .verdict p{margin:0 0 4px}
  .wrap > p,.verdict p,.seal,footer{overflow-wrap:anywhere}
  .verdict.ok{border-left-color:var(--brand)} .verdict.bad{border-left-color:var(--danger)}
  .verdict .state{display:inline-block;margin:0 0 8px;padding:3px 8px;border-radius:4px;
    font:700 11px/1.3 var(--mono);letter-spacing:.1em;text-transform:uppercase;
    background:var(--panel2);color:var(--muted);border:1px solid var(--border-strong)}
  .verdict.ok .state{background:var(--brand);color:var(--brand-on);border-color:var(--brand)}
  .verdict.bad .state{background:var(--danger);color:var(--danger-on);border-color:var(--danger)}
  .res.bad{color:var(--danger);font-weight:600}
  .fp{font:12px/1.5 var(--mono);color:var(--muted);white-space:nowrap}
  .minor{display:block;font-size:12.5px;color:var(--muted)}
  @media (max-width:560px){table{min-width:480px}}
  @media (max-width:420px){.wordmark{height:12px} .theme button{padding:7px 7px;font-size:10.5px;letter-spacing:.04em}
    .top-in{gap:8px} .top-in,.wrap{padding-inline:16px}}
</style>
</head><body>
<header class="top">
  <div class="top-in">
    <svg class="wordmark" role="img" aria-label="Wundervault" viewBox="${WORDMARK_VIEWBOX}"><path fill="currentColor" d="${WORDMARK_PATH}"/></svg>
    <div class="theme" role="group" aria-label="Appearance">
      <button type="button" data-mode="light" aria-pressed="false">Light</button>
      <button type="button" data-mode="dark" aria-pressed="false">Dark</button>
      <button type="button" data-mode="auto" aria-pressed="true">Auto</button>
    </div>
  </div>
</header>
<div class="wrap">
  <p class="eyebrow">Broker log · this computer</p>
  <h1>Your broker's log</h1>
  <p class="sub">Every use of a secret by an agent on this computer: when, which agent and secret,
  where it went, the reason it gave, and what happened. Wundervault holds none of it, only a
  fingerprint of each line that proves the log hasn't been changed.</p>
  <p class="path">${esc(activity?.logPath ?? storePath)}</p>

  <div class="seal">This page contains no links, loads nothing, and is blocked by its own
  content-security policy from making any network request at all. It is safe to keep, and
  safe to delete — the store it was built from is unchanged.</div>

  <div class="bar">
    <input type="search" id="q" placeholder="Search agent, secret, destination, or reason…" autocomplete="off">
    <span class="count" id="count"></span>
  </div>

  ${activity ? `<h2>Every use</h2>
  <div class="verdict ${verdict!.level}" id="verdict"><p class="state">${VERDICT_LABEL[verdict!.level]}</p>${verdict!.lines.map((x) => `<p>${esc(x)}</p>`).join('')}</div>
  <div class="tablewrap" tabindex="0" role="region" aria-label="Every use">
    <table>
      <thead><tr><th>When</th><th>Agent · secret</th><th>What</th><th>Result</th><th>Line</th></tr></thead>
      <tbody id="uses"></tbody>
    </table>
  </div>
  <div class="empty" id="use-empty" hidden>Nothing matches that.</div>
  <p class="count" id="use-count"></p>
  <button id="use-more" type="button" hidden>Show 2,000 more</button>
  <h2>Destinations, at a glance</h2>` : ''}
  <div class="tablewrap" tabindex="0" role="region" aria-label="Destinations">
    <table>
      <thead><tr>
        <th data-k="origin">Destination</th>
        <th data-k="entryId">Entry</th>
        <th data-k="count" class="num">Calls</th>
        <th data-k="firstSeen">First seen</th>
        <th data-k="lastSeen">Last seen</th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <div class="empty" id="empty" hidden>Nothing matches that.</div>

  <footer>
    <span class="foot-mark">WUNDERVAULT</span>
    A snapshot of the broker's files, made ${esc(new Date().toISOString())}. It does not update:
    run the command again to see newer activity.<br>
    The "Line" column shows each line's number and fingerprint, so you can compare a line with
    the one your vault page shows for this computer.
  </footer>
</div>
<script>
const DATA = ${embedJson(rows)};
const USES = ${embedJson(uses)};
let sortKey = 'lastSeen', sortDir = -1;

const $ = (id) => document.getElementById(id);
// Direction controls are shown, not obeyed (see showBidi in log-viewer.ts).
const BIDI = /[\\u061C\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069]/g;
const show = (s) => String(s).replace(BIDI, (c) => '⟨U+' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + '⟩');
// A real date is formatted by the browser, and some locales (Arabic, Hebrew) put direction
// marks in it. Those come from the browser, not the agent, so they are dropped rather than shown.
// A value that itself carries a direction control is never parsed: Date() can accept a string
// with a "(comment)" and drop the comment, control and all.
const fmt = (iso) => {
  const raw = String(iso ?? '');
  if (raw.search(BIDI) >= 0) return show(raw);
  const d = new Date(raw); return isNaN(+d) ? show(raw) : d.toLocaleString().replace(BIDI, '');
};

// Build every cell with textContent, never innerHTML. Origins and purposes are written by
// the agent, and this page is opened by someone who may already suspect that agent.
function text(tag, cls, s){ const e = document.createElement(tag); if (cls) e.className = cls; e.textContent = show(s); return e; }

function mark(el, q){
  if (!q) return el;
  const i = el.textContent.toLowerCase().indexOf(q);
  if (i < 0) return el;
  const t = el.textContent, out = el.cloneNode(false);
  out.appendChild(document.createTextNode(t.slice(0, i)));
  const m = document.createElement('mark'); m.textContent = t.slice(i, i + q.length);
  out.appendChild(m);
  out.appendChild(document.createTextNode(t.slice(i + q.length)));
  return out;
}

function render(){
  const q = $('q').value.trim().toLowerCase();
  // Searched as shown: a direction control is on screen as ⟨U+202E⟩, so searching "U+202E" finds it.
  const hit = (r) => !q || show(r.origin).toLowerCase().includes(q) || show(r.entryId).toLowerCase().includes(q)
    || r.purposes.some(p => show(p).toLowerCase().includes(q));
  const rows = DATA.filter(hit).sort((a, b) => {
    const x = a[sortKey], y = b[sortKey];
    if (x === y) return 0;
    return (x > y ? 1 : -1) * sortDir;
  });

  const body = $('rows');
  body.replaceChildren();
  for (const r of rows){
    const tr = document.createElement('tr');
    const dest = document.createElement('td');
    dest.appendChild(mark(text('span', 'origin', r.origin), q));
    // The reasons the agent gave, newest last — an incident is read backwards.
    if (r.purposes.length){
      const ul = document.createElement('ul'); ul.className = 'why';
      for (const p of r.purposes.slice().reverse()){
        const sp = p.indexOf(' ');
        const when = sp > 0 ? p.slice(0, sp) : '';
        const what = sp > 0 ? p.slice(sp + 1) : p;
        const li = document.createElement('li');
        if (when){ const t = document.createElement('time'); t.textContent = fmt(when) + ' — '; li.appendChild(t); }
        li.appendChild(mark(text('span', null, what), q));
        ul.appendChild(li);
      }
      dest.appendChild(ul);
    }
    tr.appendChild(dest);
    tr.appendChild(mark(text('td', null, r.entryId), q));
    tr.appendChild(text('td', 'num', String(r.count)));
    tr.appendChild(text('td', 'when', fmt(r.firstSeen)));
    tr.appendChild(text('td', 'when', fmt(r.lastSeen)));
    body.appendChild(tr);
  }
  $('empty').hidden = rows.length > 0;
  const calls = rows.reduce((n, r) => n + r.count, 0);
  $('count').textContent = rows.length + ' of ' + DATA.length + ' destinations · ' + calls + ' calls';
}

const KIND = { call: 'Call', ssh: 'SSH session', ssh_closed: 'SSH session ended', pay: 'Payment', sign: 'Signature', pruned: 'Old lines removed' };
const OUTCOME = { sent: 'Sent', failed: 'Failed', refused: 'Refused', error: 'Error', opened: 'Opened', closed: 'Closed', signed: 'Signed', removed: 'Removed' };
const BAD_OUTCOME = new Set(['failed', 'refused', 'error']);
const APPROVAL = { asked: 'asked you', approved: 'you approved', not_approved: 'not approved' };
let usesShown = 2000;
function renderUses(){
  const body = $('uses'); if (!body) return;
  const q = $('q').value.trim().toLowerCase();
  const hay = (u) => show([u.agent, u.key, u.address, u.reason, u.outcome, u.detail, u.method, String(u.seq), u.fp].join(' ')).toLowerCase();
  const rows = USES.filter((u) => !q || hay(u).includes(q));
  body.replaceChildren();
  for (const u of rows.slice(0, usesShown)){
    const tr = document.createElement('tr');
    tr.appendChild(text('td', 'when', fmt(u.ts)));
    const who = document.createElement('td');
    who.appendChild(mark(text('span', null, u.agent || '—'), q));
    who.appendChild(mark(text('span', 'minor', u.key), q));
    tr.appendChild(who);
    const what = document.createElement('td');
    const label = (KIND[u.kind] || u.kind) + (u.method ? ' ' + u.method : '');
    what.appendChild(text('span', 'minor', label));
    if (u.address) what.appendChild(mark(text('span', 'origin', u.address), q));
    if (u.reason) what.appendChild(mark(text('span', 'minor', '“' + u.reason + '”'), q));
    const x = u.extra || {};
    const ex = u.kind === 'pay' ? (x.amount_usdc + ' USDC to ' + x.payee + ' on ' + x.network + (x.inside_rules ? ' · within your rules' : ''))
      : u.kind === 'ssh_closed' ? (x.signs + ' signature' + (x.signs === 1 ? '' : 's'))
      : u.kind === 'sign' ? ((x.algorithm ? x.algorithm + ' · ' : '') + 'data ' + String(x.data_sha256 || '').slice(0, 12) + '…')
      : u.kind === 'pruned' ? (x.lines + ' line' + (x.lines === 1 ? '' : 's') + ' older than a year removed, up to line ' + x.through_seq)
      : u.kind === 'ssh' ? '' : Object.entries(x).map(([k, v]) => k + ': ' + v).join(' · ');
    if (ex) what.appendChild(text('span', 'minor', ex));
    tr.appendChild(what);
    const res = document.createElement('td');
    res.appendChild(text('span', BAD_OUTCOME.has(u.outcome) ? 'res bad' : 'res', (OUTCOME[u.outcome] || u.outcome) + (u.status ? ' · HTTP ' + u.status : '')));
    if (APPROVAL[u.approval]) res.appendChild(text('span', 'minor', APPROVAL[u.approval]));
    if (u.detail) res.appendChild(mark(text('span', 'minor', u.detail), q));
    tr.appendChild(res);
    tr.appendChild(text('td', 'fp', '#' + u.seq + ' · ' + u.fp + (u.signed ? '' : ' · unsigned')));
    body.appendChild(tr);
  }
  $('use-empty').hidden = rows.length > 0;
  const listed = Math.min(rows.length, usesShown);
  $('use-count').textContent = 'Showing ' + listed + ' of ' + rows.length + (q ? ' matching' : '') + ' uses' + (USES.length > rows.length ? ' (' + USES.length + ' in all)' : '') + '.';
  $('use-more').hidden = rows.length <= usesShown;
}

$('q').addEventListener('input', () => { usesShown = 2000; render(); renderUses(); });
if ($('use-more')) $('use-more').addEventListener('click', () => { usesShown += 2000; renderUses(); });
document.querySelectorAll('th[data-k]').forEach(th => th.addEventListener('click', () => {
  const k = th.dataset.k;
  sortDir = (k === sortKey) ? -sortDir : (k === 'count' || k.endsWith('Seen') ? -1 : 1);
  sortKey = k;
  render();
}));
// Light / Dark / Auto. Auto is no attribute at all: the stylesheet follows the system setting
// by itself, live. Remembered when the browser allows storage on a file page; when it throws,
// the choice still holds for this visit.
function setMode(m, save){
  if (m === 'light' || m === 'dark') document.documentElement.setAttribute('data-theme', m);
  else { m = 'auto'; document.documentElement.removeAttribute('data-theme'); }
  document.querySelectorAll('.theme button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === m)));
  if (save) { try { localStorage.setItem('wv-log-theme', m); } catch (e) {} }
}
setMode(document.documentElement.getAttribute('data-theme'), false);
document.querySelectorAll('.theme button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.mode, true)));
render();
renderUses();
</script>
</body></html>`;
}

/**
 * Write the viewer beside the store, readable only by its owner.
 *
 * Next to the store rather than in /tmp on purpose: the page contains the same profile the
 * store does, and a world-readable temp directory is the wrong home for it. 0600 for the
 * same reason, and the caller is told the path rather than the file being opened
 * automatically — this is a daemon, and a daemon that launches a browser is a daemon doing
 * something nobody asked it to.
 */
export function writeViewer(storePath = defaultStorePath(), outPath?: string,
                            shapeOverride?: NetworkShape, activity?: ActivityView): string {
  const shape = shapeOverride ?? load(storePath);
  // The USER's directory, not the daemon's. After the split the store lives somewhere the
  // person running this cannot write, and dropping the page beside it would fail — or,
  // worse, succeed for the one user who still owns both.
  const target = outPath ?? viewerPath();
  mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });

  // Write a NEW file, then rename over the target.
  //
  // Writing straight to `target` looked safe because of the `mode` option, but that option
  // applies only when the call CREATES the file: an existing destinations.html at 0644 is
  // truncated and refilled with the whole destination record while still world-readable,
  // and a kill before the chmod leaves it that way permanently. The temp file is created
  // exclusively, so it cannot be an attacker's pre-placed symlink either, and rename is
  // atomic — a reader sees the old page or the new one, never a half-written record.
  const tmp = `${target}.tmp-${process.pid}`;
  try { unlinkSync(tmp); } catch { /* nothing to clear */ }
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    writeFileSync(fd, renderViewer(shape, storePath, activity));
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, target);

  return target;
}

/**
 * Open the page, then destroy it.
 *
 * The store is protected; this page is a COPY of it, and it lands in a directory every
 * agent can read — they run as the owner, so a 0600 file in the owner's home is a 0600
 * file they can open. Protecting the vault and then leaving a snapshot beside it is a
 * strange place to stop.
 *
 * So the copy is temporary: written, opened, and shredded when the viewer is done with it.
 * The exposure goes from permanent to the length of time somebody is actually looking, and
 * a browser has the file content in memory by then anyway, so nothing is lost by removing
 * it from disk.
 *
 * It is NOT put in /tmp. That directory is world-traversable and shared with every other
 * user on the machine; the owner's own directory, 0600, is a smaller audience than that
 * even before the file disappears.
 */
export interface ViewerStamp { ino: number; mtimeMs: number }

export function shredViewer(target: string, expect?: ViewerStamp): void {
  try {
    if (!existsSync(target)) return;

    // Only shred the file WE wrote. The path is fixed, so a second invocation — or the same
    // one run with --keep — can put a different page there; deleting by name alone would
    // let one command destroy another's deliberately kept output.
    //
    // The inode ALONE is not enough, which a test caught: unlink the file and the very next
    // create can be handed the same inode number back, so a genuinely different file matches.
    // Pairing it with the modification time makes a collision require both a reused inode
    // and an identical timestamp.
    const st = statSync(target);
    if (expect && (st.ino !== expect.ino || st.mtimeMs !== expect.mtimeMs)) return;

    // The unlink is the point and it happens whatever the overwrite does.
    //
    // These used to share one try block, so an allocation failure on randomBytes(size) —
    // entirely possible for a large log on a small machine — skipped the unlink, swallowed
    // the error, and left the complete readable page behind while the command reported a
    // clean exit. The overwrite is a nice-to-have; the removal is the reason this exists.
    try {
      if (st.size > 0) writeFileSync(target, randomBytes(st.size));
    } catch { /* could not overwrite: still remove it */ }

    unlinkSync(target);
  } catch { /* best effort: a leftover page is the thing being avoided, not a crash */ }
}

/**
 * Hand the page to a browser without waiting on one.
 *
 * `xdg-open` returns as soon as it has handed off, so it cannot tell us when the reader is
 * finished — which is why the caller waits on a signal or a timeout rather than on this.
 * Failure is not fatal: on a headless box there is no opener, and printing the path is a
 * perfectly good outcome.
 */
export function openInBrowser(target: string): boolean {
  const opener = process.platform === 'darwin' ? 'open'
    : process.platform === 'win32' ? 'start' : 'xdg-open';
  try {
    // Detached and unref'd, NOT execFileSync.
    //
    // A synchronous spawn blocks this process's event loop — the same loop that has to run
    // the ten-minute cleanup timer and the SIGINT handler. xdg-open can sit waiting on a
    // browser helper, and if that helper ignores the timeout signal the command never
    // returns, ctrl-C cannot run the JavaScript handler, and the plaintext page stays on
    // disk indefinitely. The cleanup must not depend on the browser behaving.
    const child = spawn(opener, [target], { stdio: 'ignore', detached: true });
    child.on('error', () => { /* no opener on this box; the caller prints the path */ });
    child.unref();
    return true;
  } catch { return false; }
}

/** What resolveSudoUser reads from the machine — injectable, so every platform is testable anywhere. */
export interface SudoLookup {
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  uid: number | undefined;
  run: (cmd: string, args: string[]) => string;
}

function liveLookup(): SudoLookup {
  return {
    platform: process.platform,
    env: process.env,
    uid: (process as unknown as { getuid?: () => number }).getuid?.(),
    // Bounded: a stalled directory service (LDAP, SSSD, Open Directory) must end in the refusal
    // below, not leave a root command hanging.
    run: (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8', timeout: 10_000 }),
  };
}

/**
 * One account's uid, gid and home, through the system's own account lookup — never by
 * reading /etc/passwd, which only sees local accounts (an LDAP or SSSD user is a valid sudo
 * user with no line there).
 *
 * Linux: `getent passwd`, which goes through the name service switch. macOS has no getent
 * (2026-10-28: `--destinations` refused on every Mac with "spawnSync getent ENOENT"); its
 * equivalent is `dscacheutil -q user`, which goes through Directory Services. It is named by
 * its full path because this runs as root: a bare name would be looked up on a PATH that sudo
 * may have kept from the user, and anything the user's agents can write to could answer it.
 */
/** A whole number written as digits, or NaN. Number('') is 0, which would read an empty field as root. */
function digits(s: string | undefined): number {
  return s !== undefined && /^\d+$/.test(s.trim()) ? Number(s.trim()) : NaN;
}

function lookupAccount(name: string, l: SudoLookup): { uid: number; gid: number; home: string } | null {
  if (l.platform === 'darwin') {
    const out = l.run('/usr/bin/dscacheutil', ['-q', 'user', '-a', 'name', name]);
    const rec: Record<string, string> = {};
    for (const line of out.split('\n')) {
      if (!line.trim()) { if (Object.keys(rec).length) break; continue; }   // first record only
      const i = line.indexOf(':');
      if (i > 0) rec[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    if (rec.name !== name) return null;
    return { uid: digits(rec.uid), gid: digits(rec.gid), home: rec.dir ?? '' };
  }
  const f = l.run('getent', ['passwd', name]).trim().split(':');
  if (f.length < 6) return null;
  return { uid: digits(f[2]), gid: digits(f[3]), home: f[5] };
}

/** Who invoked sudo, through the system's account lookup (lookupAccount). */
export function resolveSudoUser(l: SudoLookup = liveLookup()): { uid: number; gid: number; home: string } | null {
  const sudoUser = l.env.SUDO_USER;
  if (l.uid !== 0 || !sudoUser || sudoUser === 'root') return null;
  // A SUDO_USER that is PRESENT but unresolvable is an error, not a non-sudo run.
  //
  // Returning null there meant carrying on as root and writing the page through root's own
  // path resolution — the caller cannot open the result, and the root path-following this
  // whole change removed would be back. If we were invoked under sudo we either become
  // that user or we stop.
  let who: { uid: number; gid: number; home: string } | null;
  try {
    who = lookupAccount(sudoUser, l);
  } catch (e) {
    throw new Error(
      `Ran under sudo as '${sudoUser}', but that account could not be resolved ` +
      `(${(e as Error).message}).\n` +
      `Refusing to continue as root: this command writes into your home directory and ` +
      `must not do that with root's authority.`,
    );
  }
  // Group 0 is refused as well as user 0: dropping to it would keep root's group.
  if (!who || !Number.isInteger(who.uid) || !Number.isInteger(who.gid) || who.uid === 0 || who.gid === 0 || !who.home) {
    throw new Error(
      `Ran under sudo as '${sudoUser}', but its account entry is unusable. ` +
      `Refusing to continue as root.`,
    );
  }
  // sudo records the invoking uid itself. A name that resolves to a different account is not
  // the person who ran the command, so do not become it.
  if (l.env.SUDO_UID !== undefined && Number(l.env.SUDO_UID) !== who.uid) {
    throw new Error(
      `Ran under sudo as '${sudoUser}' (uid ${l.env.SUDO_UID}), but that name resolves to uid ` +
      `${who.uid}. Refusing to continue as root.`,
    );
  }
  return who;
}

/**
 * Become the user who invoked sudo, irreversibly, before touching their home directory.
 *
 * This replaces a chown, and the difference is the whole point. Writing as root into a
 * directory an agent can rearrange means root follows whatever it finds there: an agent
 * that swapped the output file for a symlink to /etc/cron.d had root create that file and
 * hand it over. Verified as a working escalation before this changed.
 *
 * Dropping first removes the class rather than the instance. After this call the process
 * has exactly the authority the person already had, so a symlink they control points at
 * something they could have written anyway. Order matters: supplementary groups, then the
 * gid, then the uid — after setuid there is no privilege left to drop the others with.
 */
export interface ProcessIds {
  setgroups?: (g: number[]) => void;
  setgid?: (g: number) => void;
  setuid?: (u: number) => void;
  getuid?: () => number;
  getgid?: () => number;
  getgroups?: () => number[];
}

export function dropToSudoUser(who: { uid: number; gid: number },
                               p: ProcessIds = process as unknown as ProcessIds): void {
  const refuse = (why: string) => new Error(`Refusing to continue: could not drop root privileges before writing (${why}).`);
  // Root's supplementary groups go first, and that is not optional: a process that changed
  // its uid but kept group 0 (or macOS's admin) can still read and write what those groups
  // can. Until 2.0.2 a failure here was ignored.
  try { p.setgroups?.([who.gid]); } catch (e) { throw refuse(`setgroups: ${(e as Error).message}`); }
  p.setgid?.(who.gid);
  p.setuid?.(who.uid);
  if (p.getuid?.() !== who.uid) throw refuse('uid');
  if (p.getgid && p.getgid() !== who.gid) throw refuse('gid');
  if (p.getgroups && p.getgroups().includes(0)) throw refuse('still in group 0');
}

/**
 * Get the destinations — by reading the file, as root.
 *
 * This used to ask the daemon over the management socket. That worked while the socket sat
 * behind a locked directory, and stopped being safe the moment the lock came off: the
 * socket is world-connectable now, because the authorisation for enrolment moved to the
 * server-issued setup link and a directory mode that keeps agents out keeps the OWNER out
 * too — they are the same uid. Anything served on that socket is served to every agent on
 * the machine.
 *
 * A roster of agent names is a small thing to hand over. The destination store is not: it
 * is the record of where all of this machine's agents have sent secrets, and one agent
 * reading the others' history is exactly the cross-agent leak the store exists to make
 * visible. It is also, per the spec's D3, an integrity control — the party being audited
 * must not be able to read, and thereby learn to work around, the audit.
 *
 * So there is no network path to it. The file belongs to the daemon's account at 0700, and
 * reading it means being root. That costs the owner one `sudo` to see their own record,
 * and it costs an agent everything, which is the right way round.
 *
 * `load()` is not called on the failure path: it swallows a read error and returns an
 * empty shape, which would render a page telling someone their agents have never sent a
 * secret anywhere — to the person looking precisely because they want to know.
 */
export async function collectShape(
  storePath = defaultStorePath(),
): Promise<{ shape: NetworkShape; source: 'daemon' | 'file' }> {
  // "Not there yet" and "not allowed" are different answers and were being given the same
  // one. On a fresh install the store does not exist until the first vault call records a
  // destination, and root was being told to go and check the file's owner and mode — for a
  // file that was simply not there. The distinction is whether the daemon's DIRECTORY can
  // be read: if it can, and the store is absent, then nothing has been recorded and saying
  // so is the truth rather than an empty page pretending to be data.
  const dir = path.dirname(storePath);
  if (!existsSync(storePath)) {
    let dirReadable = true;
    try { accessSync(dir, constants.R_OK | constants.X_OK); } catch { dirReadable = false; }
    if (dirReadable) {
      return { shape: { version: 1, seen: [] }, source: 'file' };
    }
    throw new Error(
      `Cannot read the destination log.\n` +
      `  store: ${storePath}\n` +
      `It belongs to the broker's own account, which is what stops your agents\n` +
      `reading where every other agent has sent its secrets.\n\n` +
      `  ${sudoHint('--destinations')}\n`,
    );
  }

  try {
    accessSync(storePath, constants.R_OK);
  } catch {
    const uid = (process as unknown as { getuid?: () => number }).getuid?.();
    throw new Error(
      `Cannot read the destination log.\n` +
      `  store: ${storePath}\n` +
      (uid === 0
        ? `You are root and still cannot read it. Check the file's owner and mode — it\n` +
          `should belong to the broker's wundervault account at 0700.\n`
        : `It belongs to the broker's own account, which is what stops your agents\n` +
          `reading where every other agent has sent its secrets.\n\n` +
          `  ${sudoHint('--destinations')}\n`) +
      `Refusing to show you an empty page, which is what this used to do.`,
    );
  }
  // load() turns a read or parse failure into an empty shape, which is right for a vault
  // call — one damaged store must not break every request — and wrong here. A truncated
  // network.json after a crash would render as "0 destinations" to someone looking at it
  // precisely to find out where their keys went. Parse it here so a damaged audit record
  // announces itself.
  let raw: string;
  try {
    raw = readFileSync(storePath, 'utf8');
  } catch (e) {
    throw new Error(`Cannot read ${storePath}: ${(e as Error).message}`);
  }
  // Validated and RETURNED from the same read. An earlier version validated `raw` and then
  // called load(), which re-opens and re-parses — so a store that was fine on the first
  // read and truncated by the second passed validation and came back as an empty log,
  // which is the exact lie this check exists to prevent.
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
    const p = parsed as { version?: unknown; seen?: unknown };
    if (!p || p.version !== 1 || !Array.isArray(p.seen)) {
      throw new Error('not a version-1 destination store');
    }
  } catch (e) {
    throw new Error(
      `The destination log at ${storePath} is damaged: ${(e as Error).message}.\n` +
      `Refusing to show an empty page — this is the record of where your agents sent\n` +
      `secrets, and "none" is a very different answer from "unreadable".`,
    );
  }
  return { shape: parsed as NetworkShape, source: 'file' };
}

