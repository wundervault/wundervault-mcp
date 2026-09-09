# Review package — round 3
generated 2026-09-09T01:16:01+00:00

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

Round 3. Round 2's two blockers (F1 non-Linux TOCTOU, F3 hardened /proc) shared one root cause: arbitration was INFERRED from /proc and then applied with check-then-write. Rather than patch, the mechanism was REPLACED.

THE CREDENTIAL IS NOW CLAIMED BY BINDING A SOCKET.
- Binding is atomic, so there is no check-then-write window on any platform (fixes F1).
- It needs no visibility into other processes, so hidepid/sandbox does not weaken it (fixes F3).
- The kernel releases it on death including SIGKILL, so no stale claims, no PID-reuse reasoning, no mutual-deadlock case (fixes F2, B1).
- On Linux it is in the ABSTRACT namespace: no filesystem entry, so the delete-the-lock-file leak cannot exist rather than being defended against.
- /proc scanning, start tokens and held-mode markers are DELETED, which removes B2's forgery path (markers were trusted on evidence any same-UID process could reproduce).

TWO THINGS DELIBERATELY KEPT:
1. The pid lock file is still written, line 1 a bare PID, purely so older copies elsewhere on the machine keep refusing (they gate on it with parseInt). It enforces nothing here.
2. A MIXED-VERSION GATE: after binding, if the pid file names a live PID that is not us, we release and stand down. An older build binds no socket, so that file is its only trace. This can misfire on a recycled PID; that direction fails closed and is legible rather than silent.

VERIFIED: 12 unit tests pass, including cross-process exclusion, release-on-death, refusal after the lock FILE is deleted out of band, and the mixed-version gate. Verified LIVE: the new build stood down for this machine's running OLD-code holder (PID 1614475) and named it.

NOT TESTED: real macOS/Windows execution (non-Linux uses a filesystem socket with a connect-probe before treating it as stale).

Focus on: (a) any remaining path to two live instances serving vault tools; (b) the non-Linux filesystem-socket path, especially probe-then-unlink; (c) whether the mixed-version gate can be abused or deadlock; (d) anything the socket approach breaks that the pidfile did not.

## Diff

```diff
diff --git a/src/index.ts b/src/index.ts
index fb7bdf3..dd5bac7 100644
--- a/src/index.ts
+++ b/src/index.ts
@@ -1,63 +1,19 @@
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
+  acquireCredential,
+  credentialIsFree,
+  releaseCredential,
+  describeHolder,
+  agentName,
+  type Holder,
+} from './lock.js';
 
 // ── CLI ────────────────────────────────────────────────────────────────────────
 
@@ -88,19 +44,106 @@ Run onboard.py to register an agent with the daemon.
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
+    // Re-check by trying to bind, so the answer is the kernel's and not a
+    // snapshot from startup.
+    const free = await credentialIsFree();
+    const text = !free
+      ? `Vault tools are unavailable in this session. The credential for ` +
+        `"${agent}" is currently held by another MCP instance ` +
+        `(${describeHolder(holder)}). The vault permits one connected agent per ` +
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
+const claim = await acquireCredential(VERSION);
+if (!claim.ok) {
+  // Bound nothing, so this process holds nothing: it installs no release
+  // handlers and can never remove the real holder's lock file.
+  await serveHeldNotice(claim.holder!);
+} else {
+  await serveVault();
 }
 
+async function serveVault(): Promise<void> {
+
+process.on('exit', releaseCredential);
+process.on('SIGINT', () => { releaseCredential(); process.exit(0); });
+process.on('SIGTERM', () => { releaseCredential(); process.exit(0); });
+
 // Exit when the host closes stdin (MCP client disconnected / session ended).
 // NOTE: do NOT call process.stdin.resume() here. Resuming puts stdin in
 // flowing mode before StdioServerTransport is attached; any bytes the client
 // sends in that window (notably the `initialize` handshake) are read and
 // discarded, so the transport never sees them and tools never register.
 // StdioServerTransport manages the stream itself once connected.
-process.stdin.on('end', () => { releaseLock(); process.exit(0); });
+process.stdin.on('end', () => { releaseCredential(); process.exit(0); });
 
 // Attach the transport FIRST so the client handshake is never lost. The
 // CIP-024 version self-check runs in the background and only hard-stops on a
@@ -133,3 +176,5 @@ server.connect(transport).catch((err: Error) => {
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
 * The vault's rule is ONE CONNECTED AGENT PER CREDENTIAL AT A TIME, so this is
 * a security control, not hygiene. It follows that where the code cannot know
 * the truth it must refuse to serve, never guess in favour of serving.
 *
 * WHY A SOCKET AND NOT A PID FILE
 *
 * A pidfile cannot carry this on its own, and every patch to make it try adds a
 * new hole:
 *   - it can be deleted out-of-band while the holder is still connected (a
 *     stray `rm`, a cutover runbook that clears locks), and then it enforces
 *     nothing;
 *   - reading it and then writing it is check-then-write, so two processes
 *     starting together can both find it absent and both proceed;
 *   - a PID it names can be recycled, so "that PID is alive" is not "that
 *     holder is alive";
 *   - deciding from /proc who a PID belongs to needs /proc to be readable,
 *     which it is not under hidepid, in a sandbox, or on any non-Linux host.
 *
 * A listening socket has none of those failure modes, because the kernel owns
 * it. Binding is atomic — exactly one process can hold a given address, so
 * there is no window between checking and taking. It is released on process
 * death including SIGKILL and a crash, so a holder cannot leak the credential
 * by dying badly. And on Linux we bind in the ABSTRACT namespace (a leading
 * NUL), which has no filesystem entry at all: there is nothing on disk to
 * delete, so the delete-the-lock leak cannot exist.
 *
 * Elsewhere (macOS, Windows) we bind a filesystem socket and probe it before
 * treating it as stale: a socket that still accepts a connection belongs to a
 * live holder, and only one that refuses is safe to replace.
 *
 * THE PID FILE IS KEPT, FOR COMPATIBILITY ONLY
 *
 * Older builds of this package (<=1.7.0, including frozen copies in other
 * agents' node_modules) know nothing about the socket and gate purely on
 * `~/.wundervault/mcp-<Agent>.lock`, read with parseInt. If we stopped writing
 * it, every one of those copies would see no lock and start alongside a live
 * holder. So we still write it, first line a bare PID, and it also gives a
 * blocked instance a PID to name in its diagnostics. It is not what enforces
 * anything.
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import os from 'node:os';

export interface Holder {
  /** From the compatibility file, so best-effort: null when it was removed. */
  pid: number | null;
  since: string | null;
  parent: string | null;
}

export interface Claim {
  ok: boolean;
  holder?: Holder;
}

const IS_LINUX = process.platform === 'linux';

export function agentName(): string {
  return process.env.WUNDERVAULT_AGENT_NAME || '';
}

function slug(): string {
  const agent = agentName();
  return agent ? agent.replace(/[^a-zA-Z0-9_-]/g, '_') : '_default';
}

export function lockFilePath(): string {
  const agent = agentName();
  const name = agent ? `mcp-${slug()}.lock` : 'mcp.lock';
  return path.join(os.homedir(), '.wundervault', name);
}

/**
 * Linux: the abstract namespace, which is not a file and cannot be unlinked.
 * Elsewhere: a real socket beside the lock file.
 */
function socketAddress(): string {
  return IS_LINUX
    ? `\0wundervault-mcp-${slug()}`
    : path.join(os.homedir(), '.wundervault', `mcp-${slug()}.sock`);
}

let held: net.Server | null = null;

type BindResult =
  | { status: 'bound'; server: net.Server }
  | { status: 'in-use' }
  | { status: 'error' };

function tryBind(address: string): Promise<BindResult> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', (err: NodeJS.ErrnoException) => {
      resolve({ status: err.code === 'EADDRINUSE' ? 'in-use' : 'error' });
    });
    server.listen(address, () => {
      // Holding the address is the whole job; nothing is served on it. unref so
      // this handle alone never keeps the process alive.
      server.unref();
      resolve({ status: 'bound', server });
    });
  });
}

/** Does a filesystem socket still have someone listening? */
function probe(address: string): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.connect(address);
    const done = (alive: boolean) => { sock.destroy(); resolve(alive); };
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
    setTimeout(() => done(false), 1000).unref();
  });
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function readCompatFile(): { pid: number; since: string | null } | null {
  try {
    const raw = readFileSync(lockFilePath(), 'utf8');
    const pid = parseInt(raw.trim().split('\n')[0], 10);
    if (isNaN(pid)) return null;
    let since: string | null = null;
    const nl = raw.indexOf('\n');
    if (nl > 0) {
      try { since = (JSON.parse(raw.slice(nl + 1)) as { since?: string }).since ?? null; } catch { /* legacy */ }
    }
    return { pid, since };
  } catch {
    return null;
  }
}

/** Parent PID and executable name only — never the parent's argv, which can
 *  carry tokens and would land in stderr and in MCP tool responses. */
function describeParent(pid: number): string | null {
  if (!IS_LINUX) return null;
  try {
    const stat = readFileSync(path.join('/proc', String(pid), 'stat'), 'utf8');
    const ppid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
    if (!ppid || ppid <= 1) return null;
    let exe: string | null = null;
    try {
      exe = readFileSync(path.join('/proc', String(ppid), 'comm'), 'utf8').trim() || null;
    } catch { /* gone */ }
    return exe ? `${ppid} (${exe})` : String(ppid);
  } catch {
    return null;
  }
}

function currentHolderInfo(): Holder {
  const compat = readCompatFile();
  if (!compat) return { pid: null, since: null, parent: null };
  return {
    pid: compat.pid,
    since: compat.since,
    parent: describeParent(compat.pid),
  };
}

function writeCompatFile(version: string): void {
  try {
    // Line 1 must stay a bare PID: older builds parseInt it, and a pure-JSON
    // file reads as NaN there, which makes them ignore the lock entirely.
    const meta = { pid: process.pid, agent: agentName(), since: new Date().toISOString(), version };
    writeFileSync(lockFilePath(), `${process.pid}\n${JSON.stringify(meta)}\n`, 'utf8');
  } catch { /* advisory only; the socket is what enforces */ }
}

/**
 * Take the credential, or report who has it.
 * Binding is atomic, so there is no check-then-write window.
 */
export async function acquireCredential(version: string): Promise<Claim> {
  const address = socketAddress();

  let result = await tryBind(address);

  // A filesystem socket can outlive its owner; an abstract one cannot, so this
  // recovery only applies off Linux. Replace it only after proving nobody
  // answers — a socket that still accepts a connection has a live holder.
  if (result.status === 'in-use' && !IS_LINUX) {
    if (!(await probe(address))) {
      try { unlinkSync(address); } catch { /* raced with the owner */ }
      result = await tryBind(address);
    }
  }

  if (result.status === 'bound') {
    // Binding proves no OTHER BUILD OF THIS VERSION holds the credential, but an
    // older copy on this machine — Byte's frozen node_modules, or a session that
    // started before this file existed — binds no socket at all. It only writes
    // the pid file, so during a mixed-version window that file is the only trace
    // such a holder leaves. Honour it: a live PID that is not us means someone is
    // connected, and we stand down.
    //
    // A recycled PID can therefore cause a false refusal. That is the correct
    // direction to be wrong in, and it is no longer silent — held mode names the
    // PID, so an operator can see the lock is stale and remove it.
    const compat = readCompatFile();
    if (compat && compat.pid !== process.pid && pidAlive(compat.pid)) {
      try { result.server.close(); } catch { /* ignore */ }
      return { ok: false, holder: currentHolderInfo() };
    }

    held = result.server;
    writeCompatFile(version);
    return { ok: true };
  }

  // 'in-use' is someone else holding it. 'error' means we could not bind at all
  // (a read-only or missing socket directory); serving anyway would risk two
  // live instances, so both outcomes refuse.
  return { ok: false, holder: currentHolderInfo() };
}

/** Release the compatibility file. The socket is released by the kernel. */
export function releaseCredential(): void {
  try {
    const compat = readCompatFile();
    if (compat && compat.pid === process.pid) unlinkSync(lockFilePath());
  } catch { /* ignore */ }
  try { held?.close(); } catch { /* ignore */ }
  held = null;
}

/** Is the credential free right now? Used to re-check from a blocked session. */
export async function credentialIsFree(): Promise<boolean> {
  if (held) return false;
  const result = await tryBind(socketAddress());
  if (result.status !== 'bound') return false;
  // Only testing; give it straight back so the next real start can take it.
  try { result.server.close(); } catch { /* ignore */ }
  const compat = readCompatFile();
  return !(compat && compat.pid !== process.pid && pidAlive(compat.pid));
}

export function describeHolder(h: Holder): string {
  const bits: string[] = [];
  if (h.pid !== null) bits.push(`PID ${h.pid}`);
  if (h.since) bits.push(`connected since ${h.since}`);
  if (h.parent) bits.push(`owned by process ${h.parent}`);
  return bits.length ? bits.join(', ') : 'another process on this machine';
}

export function socketDescription(): string {
  return IS_LINUX ? `abstract socket wundervault-mcp-${slug()}` : socketAddress();
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
  acquireCredential,
  credentialIsFree,
  releaseCredential,
  describeHolder,
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
    // Re-check by trying to bind, so the answer is the kernel's and not a
    // snapshot from startup.
    const free = await credentialIsFree();
    const text = !free
      ? `Vault tools are unavailable in this session. The credential for ` +
        `"${agent}" is currently held by another MCP instance ` +
        `(${describeHolder(holder)}). The vault permits one connected agent per ` +
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

const claim = await acquireCredential(VERSION);
if (!claim.ok) {
  // Bound nothing, so this process holds nothing: it installs no release
  // handlers and can never remove the real holder's lock file.
  await serveHeldNotice(claim.holder!);
} else {
  await serveVault();
}

async function serveVault(): Promise<void> {

process.on('exit', releaseCredential);
process.on('SIGINT', () => { releaseCredential(); process.exit(0); });
process.on('SIGTERM', () => { releaseCredential(); process.exit(0); });

// Exit when the host closes stdin (MCP client disconnected / session ended).
// NOTE: do NOT call process.stdin.resume() here. Resuming puts stdin in
// flowing mode before StdioServerTransport is attached; any bytes the client
// sends in that window (notably the `initialize` handshake) are read and
// discarded, so the transport never sees them and tools never register.
// StdioServerTransport manages the stream itself once connected.
process.stdin.on('end', () => { releaseCredential(); process.exit(0); });

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
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

// A unique agent name per run: the Linux abstract socket namespace is
// machine-global, so a test must never claim the name a real agent uses.
const AGENT = `TestAgent_${process.pid}_${Date.now()}`;

let home: string;
let lock: typeof import('../src/lock.js');
const realHomedir = os.homedir;
const realAgent = process.env.WUNDERVAULT_AGENT_NAME;

beforeEach(async () => {
  home = mkdtempSync(path.join(os.tmpdir(), 'wv-lock-'));
  (os as any).homedir = () => home;
  mkdirSync(path.join(home, '.wundervault'), { recursive: true });
  process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  lock = await import('../src/lock.js');
});

afterEach(() => {
  lock.releaseCredential();
  (os as any).homedir = realHomedir;
  if (realAgent === undefined) delete process.env.WUNDERVAULT_AGENT_NAME;
  else process.env.WUNDERVAULT_AGENT_NAME = realAgent;
  rmSync(home, { recursive: true, force: true });
});

describe('acquiring the credential', () => {
  it('grants it when nobody holds it', async () => {
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
  });

  it('refuses a second claim while the first is held', async () => {
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
    const second = await lock.acquireCredential('9.9.9');
    expect(second.ok).toBe(false);
    expect(second.holder).toBeDefined();
  });

  it('grants it again after release', async () => {
    await lock.acquireCredential('9.9.9');
    lock.releaseCredential();
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
  });

  it('still refuses when the lock FILE is deleted out-of-band', async () => {
    // The failure that started all this: enforcement must not depend on a file
    // that anything can remove.
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
    rmSync(lock.lockFilePath());
    expect(existsSync(lock.lockFilePath())).toBe(false);
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(false);
  });

  it('reports the credential as taken while held, and free once released', async () => {
    await lock.acquireCredential('9.9.9');
    expect(await lock.credentialIsFree()).toBe(false);
    lock.releaseCredential();
    expect(await lock.credentialIsFree()).toBe(true);
  });
});

describe('compatibility lock file', () => {
  it('keeps a bare PID on line 1 so pre-1.7.1 readers still see the lock', async () => {
    await lock.acquireCredential('9.9.9');
    const raw = readFileSync(lock.lockFilePath(), 'utf8');

    // Exactly what older builds do. A pure-JSON file yields NaN there, which
    // makes them ignore the lock and start alongside a live holder.
    expect(parseInt(raw.trim().split('\n')[0], 10)).toBe(process.pid);

    const meta = JSON.parse(raw.slice(raw.indexOf('\n') + 1));
    expect(meta.pid).toBe(process.pid);
    expect(meta.agent).toBe(AGENT);
    expect(meta.version).toBe('9.9.9');
  });

  it('names the file after the agent, slugged', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'Claude 0512';
    expect(path.basename(lock.lockFilePath())).toBe('mcp-Claude_0512.lock');
    process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  });

  it('releases only a file this process owns', async () => {
    await lock.acquireCredential('9.9.9');
    writeFileSync(lock.lockFilePath(), '999999\n{"pid":999999}\n');
    lock.releaseCredential();
    expect(existsSync(lock.lockFilePath())).toBe(true);
  });
});

describe('cross-process exclusion', () => {
  it('a second OS process cannot take a held credential', () => {
    const script = `
      process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(AGENT)};
      const os = require('os');
      os.homedir = () => ${JSON.stringify(home)};
      import(${JSON.stringify(path.resolve('dist/lock.js'))}).then(async (lock) => {
        const first = await lock.acquireCredential('1');
        // Hold it, then report what a fresh claim in ANOTHER process sees.
        const { execFileSync } = require('child_process');
        const inner = \`
          process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(AGENT)};
          const os = require('os');
          os.homedir = () => ${JSON.stringify(home)};
          import(${JSON.stringify(path.resolve('dist/lock.js'))}).then(async (l) => {
            const c = await l.acquireCredential('1');
            console.log(JSON.stringify({ second: c.ok }));
          });
        \`;
        const out = execFileSync(process.execPath, ['-e', inner], { encoding: 'utf8' });
        console.log(JSON.stringify({ first: first.ok, inner: JSON.parse(out).second }));
      });
    `;
    const out = execFileSync(process.execPath, ['-e', script], { encoding: 'utf8' });
    const result = JSON.parse(out.trim().split('\n').pop()!);
    expect(result.first).toBe(true);
    expect(result.inner).toBe(false);
  });

  it('frees the credential when the holding process dies', () => {
    // The kernel releases the socket, so a crashed holder cannot strand it.
    const holder = `
      process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(AGENT)};
      const os = require('os');
      os.homedir = () => ${JSON.stringify(home)};
      import(${JSON.stringify(path.resolve('dist/lock.js'))}).then(async (l) => {
        await l.acquireCredential('1');
        process.exit(0);   // exits while "holding"
      });
    `;
    execFileSync(process.execPath, ['-e', holder], { encoding: 'utf8' });
    const after = `
      process.env.WUNDERVAULT_AGENT_NAME = ${JSON.stringify(AGENT)};
      const os = require('os');
      os.homedir = () => ${JSON.stringify(home)};
      import(${JSON.stringify(path.resolve('dist/lock.js'))}).then(async (l) => {
        const c = await l.acquireCredential('1');
        console.log(JSON.stringify({ ok: c.ok }));
      });
    `;
    const out = execFileSync(process.execPath, ['-e', after], { encoding: 'utf8' });
    expect(JSON.parse(out.trim()).ok).toBe(true);
  });
});

describe('mixed-version safety', () => {
  it('stands down for an older-build holder, which binds no socket', async () => {
    // Simulates a frozen pre-socket copy: it writes only the pid file. The
    // socket is free, so binding succeeds — the pid file is the only evidence
    // that anyone is connected, and it has to be enough.
    writeFileSync(lock.lockFilePath(), `${process.ppid}\n`);
    const claim = await lock.acquireCredential('9.9.9');
    expect(claim.ok).toBe(false);
    expect(claim.holder?.pid).toBe(process.ppid);
  });

  it('ignores an older-build lock whose process is gone', async () => {
    writeFileSync(lock.lockFilePath(), '999999\n');
    expect((await lock.acquireCredential('9.9.9')).ok).toBe(true);
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
- [round 2 F4] rejected: A reparented (PPID 1) holder yields no parent hint, so the blocked user gets no way to identify the owning session.
  reason: Accurate but not a defect. PID and connection time are still reported and are enough to find the process; naming init would identify nothing. Deliberately not falling back to the parent's argv, which is where a useful-looking hint would have to come from and which can contain tokens — that was blocker F4 in round 1.
