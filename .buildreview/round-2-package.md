# Review package — round 2
generated 2026-09-09T00:00:49+00:00

## Spec — judge the build against THIS

# SPEC — wundervault MCP single-instance lock hardening

## Context

`@wundervault/mcp-server` is a stdio MCP server. Each instance is an independent client
of a local `wundervault-agent` daemon (unix socket `~/.wundervault/agents/<Agent>.sock`)
which holds the credentials. `WUNDERVAULT_AGENT_NAME` identifies the agent; the lock is
per agent name, file `~/.wundervault/mcp-<Agent_Slug>.lock`.

Multiple agents run on one box (Claude, Hermes, Byte), and multiple *copies* of the
package exist at different paths — some frozen in a `node_modules`, some symlinked to
this git source. Copies at other paths are NOT being rebuilt as part of this change.

## The invariant this exists to protect

**ONE CONNECTED AGENT PER CREDENTIAL AT A TIME.** This is a security rule from the vault
product, not an implementation convenience. Two live MCP processes under the same agent
name both able to call vault tools is a defect of the highest severity here. Where the
code cannot determine the truth, it must fail CLOSED (refuse to serve the vault) rather
than open.

## The two defects being fixed

**D1. The lock could be silently lost.** Enforcement depended entirely on the lock file
existing. If the file was deleted while a holder was still connected — a stray `rm`, a
cutover runbook that clears locks, a short-lived probe process — the next instance
started and the invariant was broken with no warning. Related: `releaseLock()` unlinked
on a bare PID match, so a recycled PID could delete a live holder's lock.

**D2. The refusal was undiagnosable.** A blocked instance printed to stderr and called
`process.exit(0)` DURING the MCP handshake. Every MCP client can only render that as
"Connection closed" — indistinguishable from a crash, a bad path, or a broken install.
This cost an hour of misdirected debugging against the site and the daemon.

## Acceptance checks

1. A second instance under the same agent name never gets vault tools while a first live
   instance holds the credential.
2. Deleting the lock file while a live holder is running does NOT let a second instance
   serve vault tools.
3. `releaseLock()` removes the lock file only when this exact process incarnation owns
   it — identity is (pid, kernel start time). A refused instance, a recycled PID, or an
   unrelated process must not be able to unlink a live holder's lock.
4. Two instances starting simultaneously resolve deterministically: exactly one serves
   the vault, and it is never the case that both do OR that both stand down.
5. A blocked instance completes the MCP `initialize` handshake and stays connected. It
   must NOT exit during the handshake.
6. A blocked instance advertises NO vault tools. Any vault tool call returns an error
   explaining the credential is held. It exposes exactly one diagnostic tool,
   `vault_status`, which re-checks live state rather than replaying a startup snapshot.
7. The refusal message identifies the holder well enough to act on: PID, start time, and
   a hint at the owning session.
8. Lock file line 1 remains a bare PID. Older builds of this package parse the file with
   `parseInt` and treat `NaN` as "no lock" — a pure-JSON file would make every older copy
   on the box ignore the lock and start alongside a live holder. Metadata is line 2 JSON.
9. Nothing regresses on the normal path: a free credential yields all six vault tools and
   a working `vault_entries_list`, and a clean exit releases the lock.
10. Behaviour degrades safely where `/proc` is unavailable (non-Linux): the file remains
    the fallback authority; the process must still start and serve when nothing holds it.
11. No secret, token, or credential value is written to stderr, the lock file, or any
    tool response by this change.

## Out of scope

- Committing, version-bumping, or publishing to npm; updating frozen copies elsewhere.
- `@wundervault/mcp-context`. It is a DIFFERENT product — context-bundle delivery
  (SOUL.md, AGENTS.md, MEMORY.md), not vault credentials — and its lock is a single
  global `mcp-context.lock` with no agent-name keying at all. The invariant above does
  not apply to it. It shares only D2's exit-0-during-handshake pattern.
- The 3 pre-existing failures in `test/integration.test.ts` (`loadCredentials` is imported
  from `src/server.js` but is not defined anywhere in `src/`).
- Any change to the vault protocol, the daemon, or the six vault tools themselves.


## What was built this round, and how it was tested

Round 2. All six round-1 findings were triaged; see round-1-triage.json. F1, F3, F4, F5, F6 fixed; F2 deferred as unfixable from inside this repo (an older frozen copy cannot be taught to scan); B2 rejected on the compatibility constraint; B1/B3 deferred as known boundaries.

KEY CHANGES SINCE ROUND 1:
- F1 was the important one and my first patch for it was WRONG. Identification of a lock-file holder no longer uses the command line at all — it compares the START TOKEN recorded in the lock file against /proc/<pid>/stat field 22. A match proves that exact incarnation still runs; only a genuine mismatch proves PID reuse; a legacy file with no token fails closed. The scan's cmdline pattern is now only a negative filter and the agent-name environ match is what identifies us.
- F3: startedBefore() is now a total order over (start, pid).
- F5: releaseLock() refuses to unlink when the file records a token we cannot verify.
- F6: held-mode processes write a marker file recording (pid, start token); the scan skips a peer only when BOTH match, so a leaked marker cannot vouch for a PID-reusing process. vault_status rebuilds its message from the fresh re-check.

RE-VERIFIED LIVE against the real daemon, agent 'Claude 0512', with this Claude Code session's own MCP as the genuine holder (PID 1614475): two probe instances both entered held mode and both wrote markers; a second held process correctly named the REAL holder rather than the first held process; markers were removed on exit; the parent hint printed as '1596878 (claude)' with no argv. npm test 45 pass (3 pre-existing failures in integration.test.ts, unrelated).

STILL NOT TESTED: non-Linux, a real same-tick race, real PID reuse.

Focus this round on: (a) any remaining path to TWO live instances serving vault tools; (b) whether the marker mechanism introduces a fail-open; (c) TOCTOU between currentHolder() and writeLock(); (d) correctness of the start-token comparison itself.

## Diff

```diff
diff --git a/src/index.ts b/src/index.ts
index fb7bdf3..bb01cb8 100644
--- a/src/index.ts
+++ b/src/index.ts
@@ -1,63 +1,21 @@
 #!/usr/bin/env node
 
-import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
-import path from 'node:path';
-import os from 'node:os';
 import { parseArgs } from 'node:util';
+import { Server } from '@modelcontextprotocol/sdk/server/index.js';
 import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
+import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
 import { createServer } from './server.js';
 import { VERSION, semverLt } from './version.js';
-
-// Lock file is keyed by agent name so multiple agents can run simultaneously.
-function getLockFile(): string {
-  const agentName = process.env.WUNDERVAULT_AGENT_NAME;
-  if (agentName) {
-    const slug = agentName.replace(/[^a-zA-Z0-9_-]/g, '_');
-    return path.join(os.homedir(), '.wundervault', `mcp-${slug}.lock`);
-  }
-  return path.join(os.homedir(), '.wundervault', 'mcp.lock');
-}
-
-const LOCK_FILE = getLockFile();
-
-function acquireLock(): boolean {
-  try {
-    if (existsSync(LOCK_FILE)) {
-      const pidStr = readFileSync(LOCK_FILE, 'utf8').trim();
-      const pid = parseInt(pidStr, 10);
-      if (!isNaN(pid) && pid !== process.pid) {
-        try {
-          process.kill(pid, 0);
-          console.error(`[wundervault-mcp] Another instance is already running (PID ${pid}). Exiting.`);
-          return false;
-        } catch {
-          // stale lock
-        }
-      }
-    }
-    writeFileSync(LOCK_FILE, String(process.pid), 'utf8');
-    return true;
-  } catch {
-    return true;
-  }
-}
-
-function releaseLock(): void {
-  try {
-    if (existsSync(LOCK_FILE)) {
-      const pidStr = readFileSync(LOCK_FILE, 'utf8').trim();
-      if (pidStr === String(process.pid)) {
-        unlinkSync(LOCK_FILE);
-      }
-    }
-  } catch {
-    // ignore
-  }
-}
-
-process.on('exit', releaseLock);
-process.on('SIGINT', () => { releaseLock(); process.exit(0); });
-process.on('SIGTERM', () => { releaseLock(); process.exit(0); });
+import {
+  currentHolder,
+  describeHolder,
+  writeLock,
+  releaseLock,
+  writeHeldMarker,
+  clearHeldMarker,
+  agentName,
+  type Holder,
+} from './lock.js';
 
 // ── CLI ────────────────────────────────────────────────────────────────────────
 
@@ -88,12 +46,109 @@ Run onboard.py to register an agent with the daemon.
   process.exit(0);
 }
 
+// ── Held-credential mode ──────────────────────────────────────────────────────
+
+/**
+ * The vault allows one connected agent per credential at a time. When another
+ * instance already holds this agent name we must not serve vault tools — but we
+ * must not exit either.
+ *
+ * Exiting mid-handshake is what the previous version did, and it is invisible:
+ * every MCP client can only report the death of the process as "Connection
+ * closed", which is indistinguishable from a crash, a bad path, or a broken
+ * install. Diagnosing one such case cost an hour. So instead we COMPLETE the
+ * handshake and connect honestly, advertising a single diagnostic tool and no
+ * vault tools. The refusal is unchanged; only its legibility is.
+ */
+async function serveHeldNotice(holder: Holder): Promise<void> {
+  const agent = agentName() || '(unnamed agent)';
+  const detail =
+    `The wundervault credential for "${agent}" is already checked out by another ` +
+    `MCP instance (${describeHolder(holder)}).\n\n` +
+    `The vault permits one connected agent per credential at a time, so this ` +
+    `session has no vault tools. This is the vault enforcing that rule — not a ` +
+    `crash, and not a broken install.\n\n` +
+    `To take the credential: close the session that owns the process above, then ` +
+    `reconnect this MCP server (/mcp in Claude Code).`;
+
+  console.error(`[wundervault-mcp] ${detail.replace(/\n+/g, ' ')}`);
+
+  // Publish a marker so other instances can tell this process apart from a real
+  // holder. Without it, one blocked session keeps the credential locked out for
+  // everyone after the true holder exits.
+  writeHeldMarker();
+  process.on('exit', clearHeldMarker);
+  process.on('SIGINT', () => { clearHeldMarker(); process.exit(0); });
+  process.on('SIGTERM', () => { clearHeldMarker(); process.exit(0); });
+
+  const server = new Server(
+    { name: 'wundervault-mcp', version: VERSION },
+    {
+      capabilities: { tools: {} },
+      instructions:
+        `Vault tools are UNAVAILABLE in this session: ${detail} ` +
+        `Do not report this as a server error; call vault_status for the current state.`,
+    },
+  );
+
+  server.setRequestHandler(ListToolsRequestSchema, async () => ({
+    tools: [
+      {
+        name: 'vault_status',
+        description:
+          'Report why vault tools are unavailable in this session and whether the ' +
+          'credential has since been released. Returns no secrets.',
+        inputSchema: { type: 'object', properties: {} },
+      },
+    ],
+  }));
+
+  server.setRequestHandler(CallToolRequestSchema, async (req) => {
+    if (req.params.name !== 'vault_status') {
+      return {
+        isError: true,
+        content: [{ type: 'text' as const, text: `Vault tools are unavailable. ${detail}` }],
+      };
+    }
+    // Re-check, and describe what we just found. Appending the startup snapshot
+    // here would report two different holders in one breath, the newer of which
+    // may have taken over from the one named at startup.
+    const still = currentHolder();
+    const text = still
+      ? `Vault tools are unavailable in this session. The credential for ` +
+        `"${agent}" is currently held by another MCP instance ` +
+        `(${describeHolder(still)}). The vault permits one connected agent per ` +
+        `credential at a time; this is that rule, not a crash. To take it, close ` +
+        `the session that owns that process, then reconnect this MCP server ` +
+        `(/mcp in Claude Code).`
+      : `The credential for "${agent}" is now FREE. This process cannot upgrade ` +
+        `itself mid-session — reconnect this MCP server (/mcp in Claude Code) to ` +
+        `get the vault tools.`;
+    return { content: [{ type: 'text' as const, text }] };
+  });
+
+  process.stdin.on('end', () => process.exit(0));
+  await server.connect(new StdioServerTransport());
+}
+
 // ── Run ──────────────────────────────────────────────────────────────────────
 
-if (!acquireLock()) {
-  process.exit(0);
+const holder = currentHolder();
+if (holder) {
+  // Never acquired the lock, so the exit handlers below are deliberately not
+  // installed: this process must not touch the holder's lock file.
+  await serveHeldNotice(holder);
+} else {
+  await serveVault();
 }
 
+async function serveVault(): Promise<void> {
+
+writeLock(VERSION);
+process.on('exit', releaseLock);
+process.on('SIGINT', () => { releaseLock(); process.exit(0); });
+process.on('SIGTERM', () => { releaseLock(); process.exit(0); });
+
 // Exit when the host closes stdin (MCP client disconnected / session ended).
 // NOTE: do NOT call process.stdin.resume() here. Resuming puts stdin in
 // flowing mode before StdioServerTransport is attached; any bytes the client
@@ -133,3 +188,5 @@ server.connect(transport).catch((err: Error) => {
   console.error('Self-check error:', err.message);
   /* non-fatal: transport is already attached */
 });
+
+}

```

## File: src/lock.ts

```
/**
 * Single-instance lock for the MCP server.
 *
 * The vault's rule is ONE CONNECTED AGENT PER CREDENTIAL AT A TIME, so this
 * lock is a security control, not hygiene. Two things make the naive
 * "write a pidfile" version leak that invariant, and both are handled here:
 *
 *  1. The pidfile can go missing while a holder is still connected — a stray
 *     `rm`, a cutover runbook that clears locks, a short-lived probe. The file
 *     is therefore only a hint: the authoritative check is a scan for a live
 *     MCP process running under the same agent name (Linux `/proc`). No file,
 *     no enforcement was the old behaviour; now the process itself is proof.
 *
 *  2. A pidfile can be unlinked by a process that never owned it. Ownership is
 *     now (pid, start-time), so a recycled PID cannot release another
 *     instance's lock, and a refused instance cannot delete the holder's file.
 *
 * FILE FORMAT — first line is the bare PID, and it must stay that way.
 * Older builds (<=1.7.0, including frozen copies in other agents' node_modules)
 * read this file with `parseInt`. A pure-JSON file parses as NaN there, which
 * makes those builds skip the lock check entirely and start alongside a live
 * holder — the exact failure this module exists to prevent. Metadata goes on
 * line 2 as JSON, which old readers ignore harmlessly.
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, statSync, readdirSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export interface LockMeta {
  pid: number;
  /** Kernel start-time token; distinguishes a recycled PID from the real owner. */
  start: string | null;
  agent: string;
  since: string | null;
  version: string;
}

export interface Holder {
  pid: number;
  start: string | null;
  since: string | null;
  /** Best-effort hint at the owning session, e.g. the parent's command line. */
  parent: string | null;
}

const PROC = '/proc';

export function agentName(): string {
  return process.env.WUNDERVAULT_AGENT_NAME || '';
}

export function lockFilePath(): string {
  const agent = agentName();
  const name = agent ? `mcp-${agent.replace(/[^a-zA-Z0-9_-]/g, '_')}.lock` : 'mcp.lock';
  return path.join(os.homedir(), '.wundervault', name);
}

/** Field 22 of /proc/<pid>/stat: start time in clock ticks since boot. */
export function procStart(pid: number): string | null {
  try {
    const stat = readFileSync(path.join(PROC, String(pid), 'stat'), 'utf8');
    // comm (field 2) is parenthesised and may itself contain spaces or ')'.
    const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    return rest[19] ?? null; // field 22 = index 19 after pid and comm
  } catch {
    return null;
  }
}

function procSince(pid: number): string | null {
  try {
    return statSync(path.join(PROC, String(pid))).mtime.toISOString();
  } catch {
    return null;
  }
}

function procCmdline(pid: number): string | null {
  try {
    return readFileSync(path.join(PROC, String(pid), 'cmdline'), 'utf8').replace(/\0/g, ' ').trim() || null;
  } catch {
    return null;
  }
}

function procEnvValue(pid: number, key: string): string | null {
  try {
    const raw = readFileSync(path.join(PROC, String(pid), 'environ'), 'utf8');
    for (const pair of raw.split('\0')) {
      const eq = pair.indexOf('=');
      if (eq > 0 && pair.slice(0, eq) === key) return pair.slice(eq + 1);
    }
    return null;
  } catch {
    return null; // not ours, or /proc unavailable
  }
}

/**
 * A hint at the owning session: parent PID and executable name only.
 *
 * Deliberately NOT the parent's full command line. This string is written to
 * stderr and returned in an MCP tool response, both of which land in agent
 * transcripts — and a parent's argv can carry tokens, keys, or connection
 * strings. In a vault product that is not a hint worth the exposure. The PID is
 * enough for the user to run `ps -p <pid> -o args=` themselves if they need it.
 */
function procParent(pid: number): string | null {
  try {
    const stat = readFileSync(path.join(PROC, String(pid), 'stat'), 'utf8');
    const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    const ppid = Number(rest[1]);
    if (!ppid || ppid <= 1) return null;
    let exe: string | null = null;
    try {
      exe = path.basename(readFileSync(path.join(PROC, String(ppid), 'comm'), 'utf8').trim()) || null;
    } catch { /* gone, or not readable */ }
    return exe ? `${ppid} (${exe})` : String(ppid);
  } catch {
    return null;
  }
}

export function procAvailable(): boolean {
  return existsSync(path.join(PROC, 'self', 'stat'));
}

export function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Is `pid` a wundervault MCP server for `agent`?
 * Returns null when /proc cannot answer (non-Linux, or a process we cannot read).
 */
export function isOurInstance(pid: number, agent: string): boolean | null {
  const cmd = procCmdline(pid);
  if (cmd === null) return null;
  // Invocation forms seen in the wild: the bin shim (`wundervault-mcp`), an
  // absolute path into the package, and a bare `node dist/index.js` from the
  // package directory. The last matches no wundervault string at all, so the
  // agent-name environment variable below is what actually identifies us; this
  // pattern only rules out obviously unrelated processes.
  const looksLikeUs = /wundervault[-/\\]mcp|@wundervault[/\\]mcp-server|dist[/\\]index\.js/.test(cmd);
  if (!looksLikeUs) return false;
  const theirAgent = procEnvValue(pid, 'WUNDERVAULT_AGENT_NAME');
  if (theirAgent === null) return null;
  return theirAgent === agent;
}

/**
 * The authoritative check: every OTHER live MCP process holding this agent name.
 * Independent of the lock file, so deleting the file does not free the credential.
 */
export function findLiveInstances(agent: string, selfPid: number): Holder[] {
  if (!procAvailable()) return [];
  let pids: string[];
  try {
    pids = readdirSync(PROC);
  } catch {
    return [];
  }
  const found: Holder[] = [];
  for (const entry of pids) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    if (pid === selfPid) continue;
    if (isOurInstance(pid, agent) === true) {
      const start = procStart(pid);
      if (isHeldMode(pid, start)) continue; // serving nothing; not a holder
      found.push({ pid, start, since: procSince(pid), parent: procParent(pid) });
    }
  }
  return found;
}

/**
 * Strict "a is older than b", as a TOTAL order over live processes.
 *
 * Start time alone is not total: two processes born in the same kernel tick
 * compare equal, both conclude no peer is older, and both proceed — two live
 * instances on one credential, which is the whole thing this file prevents.
 * PIDs are unique among live processes, so they break the remaining tie.
 * Unknowable start times sort as older, to fail safe.
 */
function startedBefore(a: Holder | Self, b: Holder | Self): boolean {
  if (a.start === null && b.start === null) return a.pid < b.pid;
  if (a.start === null) return true;
  if (b.start === null) return false;
  const [ta, tb] = [Number(a.start), Number(b.start)];
  if (ta !== tb) return ta < tb;
  return a.pid < b.pid;
}

interface Self { pid: number; start: string | null; }

// ── Held-mode markers ────────────────────────────────────────────────────────
//
// A process in held mode is a live instance of ours, so a naive scan counts it
// as a holder — which means one blocked session can keep the credential locked
// out after the real holder exits. A marker file lets the scan skip it.
//
// The marker records (pid, start token) and is only honoured when BOTH match
// the live process. A leaked marker from a crash therefore cannot vouch for a
// later process that reuses its PID: mismatched start token, marker ignored,
// and we fall back to counting that process as a holder. The unsafe direction
// (skipping a real holder) needs an exact incarnation match, so it fails closed.

function markerPath(pid: number): string {
  const file = lockFilePath();
  return file.replace(/\.lock$/, `.held-${pid}`);
}

export function writeHeldMarker(): void {
  try {
    writeFileSync(markerPath(process.pid), procStart(process.pid) ?? '', 'utf8');
  } catch { /* best effort: without it we merely stay conservative */ }
}

export function clearHeldMarker(): void {
  try { unlinkSync(markerPath(process.pid)); } catch { /* already gone */ }
}

function isHeldMode(pid: number, start: string | null): boolean {
  try {
    const recorded = readFileSync(markerPath(pid), 'utf8').trim();
    if (!recorded || start === null) return false;
    return recorded === start;
  } catch {
    return false;
  }
}

function readLock(file: string): { pid: number; meta: LockMeta | null } | null {
  try {
    const raw = readFileSync(file, 'utf8');
    const pid = parseInt(raw.trim().split('\n')[0], 10);
    if (isNaN(pid)) return null;
    let meta: LockMeta | null = null;
    const nl = raw.indexOf('\n');
    if (nl > 0) {
      try { meta = JSON.parse(raw.slice(nl + 1)); } catch { /* old plain-pid file */ }
    }
    return { pid, meta };
  } catch {
    return null;
  }
}

/**
 * The holder blocking us, or null if the credential is free to take.
 *
 * Arbitration is by PROCESS, not by file, because the file can go missing while
 * a holder is still connected. Two live instances starting at the same instant
 * would otherwise each see the other and both stand down, so ties break on
 * start time: the older process keeps the credential, deterministically, and
 * exactly one side proceeds.
 *
 * Known trade-off: a lingering held-mode process is itself a live instance, so
 * it can keep a genuinely free credential blocked until its session closes.
 * That fails SAFE (nobody gets the vault) rather than open (two do), which is
 * the correct bias for this invariant, and vault_status names the PID and its
 * owning session so it is obvious what to close.
 */
export function currentHolder(): Holder | null {
  const agent = agentName();
  const peers = findLiveInstances(agent, process.pid);

  if (peers.length === 0) {
    const entry = readLock(lockFilePath());
    if (!entry || entry.pid === process.pid || !alive(entry.pid)) return null;

    // The file names a live PID that the scan did not claim. Deciding this on
    // the process's command line would be wrong: an instance launched as
    // `node dist/index.js` matches no wundervault string, so "not recognised"
    // does not mean "not a holder", and treating it as free hands out a second
    // live credential. The start token settles it exactly — the file records
    // the writer's incarnation, so a match means that very process is still
    // running and still holds the lock, and only a genuine mismatch proves the
    // PID was recycled.
    //
    // With no recorded token (a legacy plain-PID file) there is no evidence
    // either way, and unknown fails closed.
    const recorded = entry.meta?.start ?? null;
    if (recorded !== null) {
      const actual = procStart(entry.pid);
      if (actual !== null && actual !== recorded) return null; // PID reused
    }

    return {
      pid: entry.pid,
      start: recorded,
      since: entry.meta?.since ?? null,
      parent: procParent(entry.pid),
    };
  }

  // A peer named by the lock file is the established holder, no tiebreak needed.
  const entry = readLock(lockFilePath());
  if (entry) {
    const owner = peers.find((p) => p.pid === entry.pid);
    if (owner) return owner;
  }

  // No file (deleted out-of-band, or a simultaneous start): oldest process wins.
  const self: Self = { pid: process.pid, start: procStart(process.pid) };
  const older = peers.filter((p) => startedBefore(p, self));
  if (older.length === 0) return null;
  return older.reduce((a, b) => (startedBefore(a, b) ? a : b));
}

export function writeLock(version: string): void {
  const meta: LockMeta = {
    pid: process.pid,
    start: procStart(process.pid),
    agent: agentName(),
    since: new Date().toISOString(),
    version,
  };
  try {
    // Line 1 stays a bare PID for older readers. See the file-format note above.
    writeFileSync(lockFilePath(), `${process.pid}\n${JSON.stringify(meta)}\n`, 'utf8');
  } catch {
    /* best effort; the process scan is the real guard */
  }
}

/** Release only a lock this exact process incarnation owns. */
export function releaseLock(): void {
  try {
    const file = lockFilePath();
    const entry = readLock(file);
    if (!entry || entry.pid !== process.pid) return;
    // The file records an incarnation, so prove we are it. Failing to read our
    // own start time is not proof, and unlinking on a bare PID match is exactly
    // how a live holder's lock gets deleted by someone else's process.
    if (entry.meta?.start) {
      const ourStart = procStart(process.pid);
      if (ourStart === null || ourStart !== entry.meta.start) return;
    }
    unlinkSync(file);
  } catch {
    /* ignore */
  }
}

export function describeHolder(h: Holder): string {
  const bits = [`PID ${h.pid}`];
  if (h.since) bits.push(`running since ${h.since}`);
  if (h.parent) bits.push(`owned by process ${h.parent}`);
  return bits.join(', ');
}

```

## File: src/index.ts

```
#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createServer } from './server.js';
import { VERSION, semverLt } from './version.js';
import {
  currentHolder,
  describeHolder,
  writeLock,
  releaseLock,
  writeHeldMarker,
  clearHeldMarker,
  agentName,
  type Holder,
} from './lock.js';

// ── CLI ────────────────────────────────────────────────────────────────────────

const { values } = parseArgs({
  options: {
    url: { type: 'string', short: 'u' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (values.help) {
  console.log(`
Wundervault MCP Server
=====================
Secure vault tool provider for AI agents via MCP protocol.

Usage: wundervault-mcp [options]

Options:
  --url <url>   API base URL override (default: from daemon)
  --help        Show this help

Credentials are loaded from the wundervault-agent daemon.
Set WUNDERVAULT_AGENT_NAME in your MCP config to identify this agent.
Run onboard.py to register an agent with the daemon.
`);
  process.exit(0);
}

// ── Held-credential mode ──────────────────────────────────────────────────────

/**
 * The vault allows one connected agent per credential at a time. When another
 * instance already holds this agent name we must not serve vault tools — but we
 * must not exit either.
 *
 * Exiting mid-handshake is what the previous version did, and it is invisible:
 * every MCP client can only report the death of the process as "Connection
 * closed", which is indistinguishable from a crash, a bad path, or a broken
 * install. Diagnosing one such case cost an hour. So instead we COMPLETE the
 * handshake and connect honestly, advertising a single diagnostic tool and no
 * vault tools. The refusal is unchanged; only its legibility is.
 */
async function serveHeldNotice(holder: Holder): Promise<void> {
  const agent = agentName() || '(unnamed agent)';
  const detail =
    `The wundervault credential for "${agent}" is already checked out by another ` +
    `MCP instance (${describeHolder(holder)}).\n\n` +
    `The vault permits one connected agent per credential at a time, so this ` +
    `session has no vault tools. This is the vault enforcing that rule — not a ` +
    `crash, and not a broken install.\n\n` +
    `To take the credential: close the session that owns the process above, then ` +
    `reconnect this MCP server (/mcp in Claude Code).`;

  console.error(`[wundervault-mcp] ${detail.replace(/\n+/g, ' ')}`);

  // Publish a marker so other instances can tell this process apart from a real
  // holder. Without it, one blocked session keeps the credential locked out for
  // everyone after the true holder exits.
  writeHeldMarker();
  process.on('exit', clearHeldMarker);
  process.on('SIGINT', () => { clearHeldMarker(); process.exit(0); });
  process.on('SIGTERM', () => { clearHeldMarker(); process.exit(0); });

  const server = new Server(
    { name: 'wundervault-mcp', version: VERSION },
    {
      capabilities: { tools: {} },
      instructions:
        `Vault tools are UNAVAILABLE in this session: ${detail} ` +
        `Do not report this as a server error; call vault_status for the current state.`,
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'vault_status',
        description:
          'Report why vault tools are unavailable in this session and whether the ' +
          'credential has since been released. Returns no secrets.',
        inputSchema: { type: 'object', properties: {} },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (req.params.name !== 'vault_status') {
      return {
        isError: true,
        content: [{ type: 'text' as const, text: `Vault tools are unavailable. ${detail}` }],
      };
    }
    // Re-check, and describe what we just found. Appending the startup snapshot
    // here would report two different holders in one breath, the newer of which
    // may have taken over from the one named at startup.
    const still = currentHolder();
    const text = still
      ? `Vault tools are unavailable in this session. The credential for ` +
        `"${agent}" is currently held by another MCP instance ` +
        `(${describeHolder(still)}). The vault permits one connected agent per ` +
        `credential at a time; this is that rule, not a crash. To take it, close ` +
        `the session that owns that process, then reconnect this MCP server ` +
        `(/mcp in Claude Code).`
      : `The credential for "${agent}" is now FREE. This process cannot upgrade ` +
        `itself mid-session — reconnect this MCP server (/mcp in Claude Code) to ` +
        `get the vault tools.`;
    return { content: [{ type: 'text' as const, text }] };
  });

  process.stdin.on('end', () => process.exit(0));
  await server.connect(new StdioServerTransport());
}

// ── Run ──────────────────────────────────────────────────────────────────────

const holder = currentHolder();
if (holder) {
  // Never acquired the lock, so the exit handlers below are deliberately not
  // installed: this process must not touch the holder's lock file.
  await serveHeldNotice(holder);
} else {
  await serveVault();
}

async function serveVault(): Promise<void> {

writeLock(VERSION);
process.on('exit', releaseLock);
process.on('SIGINT', () => { releaseLock(); process.exit(0); });
process.on('SIGTERM', () => { releaseLock(); process.exit(0); });

// Exit when the host closes stdin (MCP client disconnected / session ended).
// NOTE: do NOT call process.stdin.resume() here. Resuming puts stdin in
// flowing mode before StdioServerTransport is attached; any bytes the client
// sends in that window (notably the `initialize` handshake) are read and
// discarded, so the transport never sees them and tools never register.
// StdioServerTransport manages the stream itself once connected.
process.stdin.on('end', () => { releaseLock(); process.exit(0); });

// Attach the transport FIRST so the client handshake is never lost. The
// CIP-024 version self-check runs in the background and only hard-stops on a
// definitive "too old" verdict (server-side 426 is the backstop otherwise).
const server = createServer({ url: values.url });
const transport = new StdioServerTransport();
server.connect(transport).catch((err: Error) => {
  console.error('Server error:', err.message);
  process.exit(1);
});

(async () => {
  // CIP-024 §3.4: best-effort version self-check. Never block on transient
  // network/parse errors; hard-stop ONLY on a definitive "too old" verdict.
  try {
    const base = values.url || 'https://wundervault.com';
    const r = await fetch(`${base}/api/v1/mcp/requirements`, { signal: AbortSignal.timeout(5000) });
    if (r.ok) {
      const req = await r.json() as { min_mcp_version?: string; upgrade_cmd?: string };
      if (req.min_mcp_version && semverLt(VERSION, req.min_mcp_version)) {
        process.stderr.write(
          `\n[wundervault-mcp] FATAL: this MCP is v${VERSION} but the server ` +
          `requires >= v${req.min_mcp_version}. Vault tools are unavailable until you update:\n` +
          `  ${req.upgrade_cmd || 'npm install -g @wundervault/mcp-server@latest'}\n\n`);
        process.exit(1);
      }
    }
  } catch { /* transient — proceed; server-side 426 is the backstop */ }
})().catch((err: Error) => {
  console.error('Self-check error:', err.message);
  /* non-fatal: transport is already attached */
});

}

```

## File: test/lock.test.ts

```
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// lock.ts resolves paths from os.homedir() at call time, so point HOME at a
// scratch dir before importing anything that touches it.
let home: string;
let lock: typeof import('../src/lock.js');
const realHomedir = os.homedir;
const realAgent = process.env.WUNDERVAULT_AGENT_NAME;

beforeEach(async () => {
  home = mkdtempSync(path.join(os.tmpdir(), 'wv-lock-'));
  (os as any).homedir = () => home;
  mkdirSync(path.join(home, '.wundervault'), { recursive: true });
  lock = await import('../src/lock.js');
});

afterEach(() => {
  (os as any).homedir = realHomedir;
  if (realAgent === undefined) delete process.env.WUNDERVAULT_AGENT_NAME;
  else process.env.WUNDERVAULT_AGENT_NAME = realAgent;
  rmSync(home, { recursive: true, force: true });
});

describe('lock file format', () => {
  it('keeps a bare PID on line 1 so pre-1.7.1 readers still see the lock', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'Test Agent';
    lock.writeLock('9.9.9');
    const raw = readFileSync(lock.lockFilePath(), 'utf8');

    // This is exactly what older builds do. A pure-JSON file yields NaN there,
    // which makes them ignore the lock and start alongside a live holder.
    expect(parseInt(raw.trim().split('\n')[0], 10)).toBe(process.pid);

    const meta = JSON.parse(raw.slice(raw.indexOf('\n') + 1));
    expect(meta.pid).toBe(process.pid);
    expect(meta.agent).toBe('Test Agent');
    expect(meta.version).toBe('9.9.9');
  });

  it('names the file after the agent, slugged', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'Claude 0512';
    expect(path.basename(lock.lockFilePath())).toBe('mcp-Claude_0512.lock');
  });
});

describe('releaseLock ownership guard', () => {
  beforeEach(() => { process.env.WUNDERVAULT_AGENT_NAME = 'Test Agent'; });

  it('removes a lock this process owns', () => {
    lock.writeLock('9.9.9');
    lock.releaseLock();
    expect(existsSync(lock.lockFilePath())).toBe(false);
  });

  it('leaves another process’s lock alone', () => {
    // The observed bug: a refused or short-lived instance unlinking the live
    // holder's file, silently disabling one-agent-per-credential.
    writeFileSync(lock.lockFilePath(), '999999\n{"pid":999999,"start":"1","agent":"Test Agent"}\n');
    lock.releaseLock();
    expect(existsSync(lock.lockFilePath())).toBe(true);
  });

  it('leaves a lock alone when our PID matches but the start time does not', () => {
    // PID reuse: same number, different process incarnation.
    writeFileSync(
      lock.lockFilePath(),
      `${process.pid}\n${JSON.stringify({ pid: process.pid, start: '1', agent: 'Test Agent' })}\n`,
    );
    lock.releaseLock();
    expect(existsSync(lock.lockFilePath())).toBe(true);
  });

  it('tolerates a legacy plain-PID file it owns', () => {
    writeFileSync(lock.lockFilePath(), String(process.pid));
    lock.releaseLock();
    expect(existsSync(lock.lockFilePath())).toBe(false);
  });
});

describe('currentHolder', () => {
  it('ignores a lock file naming a dead PID', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'Nobody Runs This Agent';
    writeFileSync(lock.lockFilePath(), '999999\n');
    expect(lock.currentHolder()).toBeNull();
  });

  it('treats a live PID that is demonstrably not an MCP server as a recycled PID', () => {
    // The lockout case: without this, a lock file left behind by a dead holder
    // whose PID got reused would block the agent forever.
    process.env.WUNDERVAULT_AGENT_NAME = 'Nobody Runs This Agent';
    writeFileSync(lock.lockFilePath(), '1'); // pid 1 is alive and is not us
    expect(lock.isOurInstance(1, 'Nobody Runs This Agent')).toBe(false);
    expect(lock.currentHolder()).toBeNull();
  });

  it('does not report ourselves as the holder', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'Nobody Runs This Agent';
    writeFileSync(lock.lockFilePath(), String(process.pid));
    expect(lock.currentHolder()).toBeNull();
  });
});

```

## Already ruled on in earlier rounds

Do not raise these again unless you have new evidence, and name the evidence if you do.

- [round 1 F2] deferred: Delete the lock file, start a frozen OLDER copy of the package, and it starts alongside a live holder because it has no process scan.
  reason: True and unfixable from inside this repo — an old build cannot be taught to scan. Explicitly out of scope per the spec (frozen copies are not being rebuilt), but it means the invariant is only restored box-wide once Byte's copy in ~/.openclaw/workspace/node_modules is updated. Raised to the user as a real remaining gap, not closed.
- [round 1 B2] rejected: Agent names 'Team A' and 'Team?A' both slug to mcp-Team_A.lock and can clobber each other's lock.
  reason: Real but not fixable under this spec's compatibility constraint: changing the filename breaks every older copy on the box that reads mcp-<slug>.lock, which is a strictly worse failure. Impact is now small because arbitration is by process and the scan compares the RAW agent name from environ, not the slug. Documented, not changed.
- [round 1 B1] deferred: Containers with disjoint /proc views sharing one home directory cannot be disambiguated by a host-local (pid, start) pair.
  reason: Correct, and out of scope — no such deployment exists here. Worth recording as a known boundary of the design rather than pretending the lock is namespace-safe.
- [round 1 B3] deferred: On non-Linux there is no incarnation evidence, so a stale lock naming a reused PID refuses forever and points at the wrong process.
  reason: Accurate. Mitigated in practice by fix 2 of this build: the refusal is now legible and names the PID, so an operator can see it is wrong and delete the lock, instead of staring at CONNECTION_CLOSED. A real fix needs a non-/proc incarnation source; noted, not built.
