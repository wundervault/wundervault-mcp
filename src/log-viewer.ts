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
    writeFileSync(fd, renderViewer(shape, storePath));
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

/**
 * Who invoked sudo, resolved through NSS rather than by reading /etc/passwd.
 *
 * `getent` goes through the name service switch, so it sees accounts from LDAP, SSSD and
 * anything else the machine is configured with. Parsing /etc/passwd directly only sees
 * local accounts, and on an enterprise host that means a valid user resolves to nothing.
 */
export function resolveSudoUser(): { uid: number; gid: number; home: string } | null {
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  const sudoUser = process.env.SUDO_USER;
  if (uid !== 0 || !sudoUser || sudoUser === 'root') return null;
  // A SUDO_USER that is PRESENT but unresolvable is an error, not a non-sudo run.
  //
  // Returning null there meant carrying on as root and writing the page through root's own
  // path resolution — the caller cannot open the result, and the root path-following this
  // whole change removed would be back. If we were invoked under sudo we either become
  // that user or we stop.
  let out: string;
  try {
    out = execFileSync('getent', ['passwd', sudoUser], { encoding: 'utf8' }).trim();
  } catch (e) {
    throw new Error(
      `Ran under sudo as '${sudoUser}', but that account could not be resolved ` +
      `(${(e as Error).message}).\n` +
      `Refusing to continue as root: this command writes into your home directory and ` +
      `must not do that with root's authority.`,
    );
  }
  const f = out.split(':');
  const u = Number(f[2]); const g = Number(f[3]);
  if (f.length < 6 || !Number.isInteger(u) || !Number.isInteger(g) || u === 0 || !f[5]) {
    throw new Error(
      `Ran under sudo as '${sudoUser}', but its passwd entry is unusable. ` +
      `Refusing to continue as root.`,
    );
  }
  return { uid: u, gid: g, home: f[5] };
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
export function dropToSudoUser(who: { uid: number; gid: number }): void {
  const p = process as unknown as {
    setgroups?: (g: number[]) => void;
    setgid?: (g: number) => void;
    setuid?: (u: number) => void;
    getuid?: () => number;
  };
  try { p.setgroups?.([who.gid]); } catch { /* not always permitted; the uid drop is what matters */ }
  p.setgid?.(who.gid);
  p.setuid?.(who.uid);
  if (p.getuid?.() !== who.uid) {
    throw new Error('Refusing to continue: could not drop root privileges before writing.');
  }
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
      `  sudo wundervault-agent --destinations\n`,
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
          `  sudo wundervault-agent --destinations\n`) +
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

