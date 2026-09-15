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
import { writeFileSync, mkdirSync, chmodSync, accessSync, constants } from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { load, defaultStorePath, type NetworkShape } from './network-store.js';
import { mgmtSocketPath, viewerPath } from './paths.js';

/** Escape for embedding inside an HTML text node or attribute. */
function esc(s: string): string {
  return String(s)
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
    .replace(/\u2029/g, '\\u2029');
}

export function renderViewer(shape: NetworkShape, storePath: string): string {
  const rows = shape.seen.map((s) => ({
    entryId: s.entryId,
    origin: s.origin,
    firstSeen: s.firstSeen,
    lastSeen: s.lastSeen,
    count: s.count,
    purposes: Array.isArray(s.purposes) ? s.purposes : [],
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
<title>Wundervault — local destination log</title>
<style>
  :root{
    --paper:#EFEEE9; --surface:#FBFAF7; --surface-2:#E6E5DE;
    --ink:#1C2124; --ink-2:#414A4C; --muted:#6B7470;
    --rule:#D3D2C9; --rule-strong:#B6B5AA; --accent:#2E6F63; --warn:#96661A;
  }
  @media (prefers-color-scheme: dark){:root:not([data-theme="light"]){
    --paper:#121517; --surface:#191D20; --surface-2:#22272A;
    --ink:#E9E7E1; --ink-2:#C2C7C5; --muted:#8F9996;
    --rule:#2C3236; --rule-strong:#414A4E; --accent:#63B3A2; --warn:#D7A448;
  }}
  :root[data-theme="dark"]{
    --paper:#121517; --surface:#191D20; --surface-2:#22272A;
    --ink:#E9E7E1; --ink-2:#C2C7C5; --muted:#8F9996;
    --rule:#2C3236; --rule-strong:#414A4E; --accent:#63B3A2; --warn:#D7A448;
  }
  *{box-sizing:border-box}
  body{background:var(--paper);color:var(--ink);margin:0;padding:0 20px;
    font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
  .wrap{max-width:1000px;margin:0 auto;padding-block:40px 80px}
  h1{font-size:clamp(22px,4vw,30px);margin:0 0 6px;letter-spacing:-.01em}
  .sub{color:var(--ink-2);margin:0 0 4px;max-width:70ch}
  .path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted);
    word-break:break-all;margin:0 0 24px}
  .seal{border:1px solid var(--rule);border-left:3px solid var(--accent);background:var(--surface);
    padding:12px 16px;margin:0 0 26px;font-size:13.5px;color:var(--ink-2);border-radius:0 3px 3px 0}
  .bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 18px}
  input[type=search]{flex:1 1 260px;min-width:0;padding:9px 12px;font:inherit;font-size:14px;
    background:var(--surface);color:var(--ink);border:1px solid var(--rule-strong);border-radius:3px}
  button{padding:9px 12px;font:inherit;font-size:13px;background:var(--surface);color:var(--ink);
    border:1px solid var(--rule-strong);border-radius:3px;cursor:pointer}
  button:hover{background:var(--surface-2)}
  .count{font-size:13px;color:var(--muted)}
  .tablewrap{overflow-x:auto;border:1px solid var(--rule);border-radius:3px}
  table{border-collapse:collapse;width:100%;min-width:640px;background:var(--surface);font-size:13.5px}
  th,td{text-align:left;padding:10px 13px;border-bottom:1px solid var(--rule);vertical-align:top}
  th{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
    background:var(--surface-2);cursor:pointer;white-space:nowrap;user-select:none}
  tr:last-child td{border-bottom:none}
  td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
  .origin{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
  .when{white-space:nowrap;color:var(--ink-2);font-size:12.5px}
  .why{margin:8px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:4px}
  .why li{font-size:12.5px;color:var(--muted);border-left:2px solid var(--rule);padding-left:9px}
  .why time{color:var(--ink-2)}
  mark{background:var(--warn);color:var(--paper);border-radius:2px;padding:0 2px}
  .empty{padding:36px 16px;text-align:center;color:var(--muted)}
  footer{margin-top:26px;font-size:12px;color:var(--muted);line-height:1.7}
  @media (max-width:560px){table{min-width:480px}}
</style>
</head><body>
<div class="wrap">
  <h1>Where your secrets went</h1>
  <p class="sub">Every destination an agent on this machine reached with a vault entry,
  and the reason it gave. This is the whole record — Wundervault holds none of it.</p>
  <p class="path">${esc(storePath)}</p>

  <div class="seal">This page contains no links, loads nothing, and is blocked by its own
  content-security policy from making any network request at all. It is safe to keep, and
  safe to delete — the store it was built from is unchanged.</div>

  <div class="bar">
    <input type="search" id="q" placeholder="Search destination, entry, or reason…" autocomplete="off">
    <button id="theme" type="button">Light / dark</button>
    <span class="count" id="count"></span>
  </div>

  <div class="tablewrap">
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
    Generated ${esc(new Date().toISOString())} from the local store.<br>
    Until the daemon owns this file, an agent running as your user can edit it — so treat
    it as a record of what happened, not as proof.
  </footer>
</div>
<script>
const DATA = ${embedJson(rows)};
let sortKey = 'lastSeen', sortDir = -1;

const $ = (id) => document.getElementById(id);
const fmt = (iso) => { const d = new Date(iso); return isNaN(+d) ? String(iso ?? '') : d.toLocaleString(); };

// Build every cell with textContent, never innerHTML. Origins and purposes are written by
// the agent, and this page is opened by someone who may already suspect that agent.
function text(tag, cls, s){ const e = document.createElement(tag); if (cls) e.className = cls; e.textContent = s; return e; }

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
  const hit = (r) => !q || r.origin.toLowerCase().includes(q) || r.entryId.toLowerCase().includes(q)
    || r.purposes.some(p => p.toLowerCase().includes(q));
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

$('q').addEventListener('input', render);
document.querySelectorAll('th[data-k]').forEach(th => th.addEventListener('click', () => {
  const k = th.dataset.k;
  sortDir = (k === sortKey) ? -sortDir : (k === 'count' || k.endsWith('Seen') ? -1 : 1);
  sortKey = k;
  render();
}));
$('theme').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme');
  const dark = cur ? cur === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.setAttribute('data-theme', dark ? 'light' : 'dark');
});
render();
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
                            shapeOverride?: NetworkShape): string {
  const shape = shapeOverride ?? load(storePath);
  // The USER's directory, not the daemon's. After the split the store lives somewhere the
  // person running this cannot write, and dropping the page beside it would fail — or,
  // worse, succeed for the one user who still owns both.
  const target = outPath ?? viewerPath();
  mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  writeFileSync(target, renderViewer(shape, storePath), { mode: 0o600 });
  try { chmodSync(target, 0o600); } catch { /* best effort */ }
  return target;
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
  try {
    accessSync(storePath, constants.R_OK);
  } catch {
    const uid = (process as unknown as { getuid?: () => number }).getuid?.();
    throw new Error(
      `Cannot read the destination log.\n` +
      `  store: ${storePath}\n` +
      (uid === 0
        ? `You are root and still cannot read it. Check the file's owner and mode — it\n` +
          `should belong to the wundervault account at 0700.\n`
        : `It belongs to the daemon's own account, which is what stops your agents\n` +
          `reading where every other agent has sent its secrets.\n\n` +
          `  sudo wundervault-agent --destinations\n`) +
      `Refusing to show you an empty page, which is what this used to do.`,
    );
  }
  return { shape: load(storePath), source: 'file' };
}

