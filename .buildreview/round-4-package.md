# Review package — round 4
generated 2026-09-09T01:49:49+00:00

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

Round 4. Round 3 returned 3 blockers, 3 majors and 1 minor; all fixed. Triage in round-3-triage.json.

F1+F2 (non-Linux): the filesystem socket is gone. Its pathname could be unlinked while still bound — reintroducing the exact delete-the-lock leak the Linux path was built to make impossible — and stale recovery was a non-atomic probe-then-unlink. Windows was worse: a home-directory path is not a valid IPC address there at all, so a FREE credential would fail to bind and be reported as held. Non-Linux now claims a LOOPBACK TCP PORT derived from the agent name: no filesystem entry, kernel-released on death, atomic to bind. Same properties as the Linux abstract socket, and one code path instead of three address formats.

F3: binding then failing to write the compatibility pid file used to serve anyway — which is precisely the state in which an older frozen copy sees no lock and joins us. It now closes the address and refuses, naming the path.

F4: releaseCredential() deleted on a bare PID match. The file now carries a random per-run token and release requires an exact match, so a replaced file, a restored file or a recycled PID cannot trigger it. A legacy tokenless file is never ours and is never removed.

F5: vault_status replayed the startup holder. It now asks who holds it AT CALL TIME, which is the case that matters — a blocked session sitting connected while the credential changes hands.

F6: THE HOLDER NOW ANSWERS FOR ITSELF. It replies to any connection on the address it already holds with a one-line identity banner (pid, agent, connect time — never a secret, never the parent's argv). That cannot be deleted, so the refusal stays actionable with no lock file at all. The message states which source it used.

F7 + B2: the address carries a SHA-256 digest of the RAW agent name, so 'Team A' and 'Team?A' — distinct credentials — no longer exclude each other, and it is length-bounded (32-char slug prefix + 12-char digest) so a long name or home path cannot blow the 108-byte address limit.

VERIFIED: 20 unit tests pass, including cross-process exclusion, release-on-death, refusal after the lock file is deleted out of band, the holder banner with no lock file present, the release guard against both a foreign token and a legacy tokenless file, distinct-agent address separation, a 500-character agent name, and refusal when the lock file cannot be written. Verified LIVE against the real daemon: a new instance correctly stood down for this machine's running OLD-code holder and named it, with provenance 'reported by its lock file' since an old build binds no address and cannot answer the banner.

STILL NOT EXECUTED: macOS or Windows. The TCP path is reasoned, not run — and every non-Linux finding in rounds 2 and 3 was correct, so treat that as the weak spot.

Focus on: (a) any remaining path to two live instances serving vault tools; (b) the loopback TCP claim — port collisions with unrelated services, and what happens when something else already owns the port; (c) whether the identity banner can be abused or leak; (d) the mixed-version gate.

## Diff

```diff
diff --git a/src/index.ts b/src/index.ts
index fb7bdf3..619704b 100644
--- a/src/index.ts
+++ b/src/index.ts
@@ -1,63 +1,20 @@
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
+  whoHolds,
+  releaseCredential,
+  describeHolder,
+  agentName,
+  type Holder,
+} from './lock.js';
 
 // ── CLI ────────────────────────────────────────────────────────────────────────
 
@@ -88,19 +45,109 @@ Run onboard.py to register an agent with the daemon.
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
+    // Re-check with the kernel, and ask whoever holds it NOW who they are.
+    // Replaying the startup snapshot would name the wrong process as soon as
+    // the credential changed hands while this session sat blocked.
+    const free = await credentialIsFree();
+    const current = free ? null : await whoHolds();
+    const text = current
+      ? `Vault tools are unavailable in this session. The credential for ` +
+        `"${agent}" is currently held by another MCP instance ` +
+        `(${describeHolder(current)}). The vault permits one connected agent per ` +
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
+  if (claim.reason) console.error(`[wundervault-mcp] ${claim.reason}`);
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
@@ -133,3 +180,5 @@ server.connect(transport).catch((err: Error) => {
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
 * a security control. Where the code cannot know the truth it refuses to serve.
 *
 * WHY NOT A PID FILE
 *
 * A pidfile cannot carry this: it can be deleted while the holder is still
 * connected, reading-then-writing it is a race, the PID it names can be
 * recycled, and deciding who a PID belongs to needs a readable /proc, which
 * does not exist under hidepid, in a sandbox, or off Linux.
 *
 * THE CLAIM IS A BOUND ADDRESS
 *
 * Binding is atomic — the kernel lets exactly one process hold an address, so
 * there is no window between checking and taking — and it is released on death
 * including SIGKILL, so a holder cannot leak the credential by dying badly.
 *
 *   Linux:  the ABSTRACT namespace (leading NUL). No filesystem entry exists,
 *           so there is nothing to delete and the delete-the-lock leak cannot
 *           happen rather than being defended against.
 *   Others: a loopback TCP port. A filesystem socket was tried and rejected —
 *           its pathname can be unlinked while it is still bound, after which a
 *           second process binds the same path and both serve, and recovering
 *           from a stale one means probe-then-unlink, which is itself a race.
 *           A port has the same properties as an abstract socket: no filesystem
 *           entry, kernel-released. It also avoids Windows, where a filesystem
 *           path is not a valid IPC address at all (\\.\pipe\... is) and the
 *           bind would simply fail, stranding a free credential.
 *
 * THE HOLDER ANSWERS FOR ITSELF
 *
 * The bound address is also how a blocked instance learns WHO holds it: the
 * holder replies to any connection with a one-line identity banner. That does
 * not depend on a file anyone can remove, so the refusal stays actionable even
 * when the compatibility file is gone. The banner carries pid, connect time and
 * agent name — never a secret, and never the parent's argv.
 *
 * THE PID FILE IS KEPT, FOR COMPATIBILITY ONLY
 *
 * Older builds (<=1.7.0, including frozen copies in other agents' node_modules)
 * gate purely on `~/.wundervault/mcp-<Agent>.lock`, read with parseInt. If we
 * stopped writing it they would see no lock and start alongside a live holder,
 * so we still write it — and if we CANNOT write it we do not serve, because an
 * unwritten file is exactly the state in which an older copy joins us.
 */

import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import os from 'node:os';

export interface Holder {
  pid: number | null;
  since: string | null;
  agent: string | null;
  /** How we learned this: the holder itself, or the compatibility file. */
  source: 'holder' | 'lock-file' | 'unknown';
}

export interface Claim {
  ok: boolean;
  holder?: Holder;
  /** Set when we refused because we could not establish a claim safely. */
  reason?: string;
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
  // Filename is unchanged: older copies look for exactly this.
  const name = agent ? `mcp-${slug()}.lock` : 'mcp.lock';
  return path.join(os.homedir(), '.wundervault', name);
}

/**
 * Address key. Slugging is lossy — "Team A" and "Team?A" both slug to Team_A —
 * and two DIFFERENT credentials must not exclude each other, so the key carries
 * a digest of the RAW name. Truncated because an address has a length limit
 * (108 bytes for a unix path) that a long agent name or home directory would
 * otherwise blow past.
 */
function addressKey(): string {
  const digest = createHash('sha256').update(agentName()).digest('hex').slice(0, 12);
  return `${slug().slice(0, 32)}-${digest}`;
}

/** Deterministic loopback port in the dynamic/private range. */
function addressPort(): number {
  const digest = createHash('sha256').update(`wundervault-mcp:${agentName()}`).digest();
  return 49152 + (digest.readUInt16BE(0) % 16384);
}

let held: net.Server | null = null;
let identityLine = '';

function listenOptions(): net.ListenOptions {
  return IS_LINUX
    ? { path: `\0wundervault-mcp-${addressKey()}` }
    : { host: '127.0.0.1', port: addressPort() };
}

type BindResult =
  | { status: 'bound'; server: net.Server }
  | { status: 'in-use' }
  | { status: 'error'; message: string };

function tryBind(): Promise<BindResult> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', (err: NodeJS.ErrnoException) => {
      resolve(
        err.code === 'EADDRINUSE'
          ? { status: 'in-use' }
          : { status: 'error', message: err.code || err.message },
      );
    });
    server.listen(listenOptions(), () => {
      server.unref();
      resolve({ status: 'bound', server });
    });
  });
}

/** Ask whoever holds the address who they are. */
function askHolder(): Promise<Holder | null> {
  return new Promise((resolve) => {
    let buf = '';
    let settled = false;
    const done = (h: Holder | null) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(h);
    };
    const sock = net.connect(listenOptions() as net.NetConnectOpts);
    sock.setEncoding('utf8');
    sock.on('data', (d: string) => {
      buf += d;
      if (buf.includes('\n')) {
        try {
          const o = JSON.parse(buf.slice(0, buf.indexOf('\n')));
          if (o && o.protocol === 'wundervault-mcp-holder') {
            done({ pid: o.pid ?? null, since: o.since ?? null, agent: o.agent ?? null, source: 'holder' });
            return;
          }
        } catch { /* not ours */ }
        done(null);
      }
    });
    sock.on('error', () => done(null));
    sock.on('close', () => done(null));
    setTimeout(() => done(null), 1000).unref();
  });
}

function readCompatFile(): { pid: number; since: string | null; token: string | null } | null {
  try {
    const raw = readFileSync(lockFilePath(), 'utf8');
    const pid = parseInt(raw.trim().split('\n')[0], 10);
    if (isNaN(pid)) return null;
    let since: string | null = null;
    let token: string | null = null;
    const nl = raw.indexOf('\n');
    if (nl > 0) {
      try {
        const meta = JSON.parse(raw.slice(nl + 1)) as { since?: string; token?: string };
        since = meta.since ?? null;
        token = meta.token ?? null;
      } catch { /* legacy plain-pid file */ }
    }
    return { pid, since, token };
  } catch {
    return null;
  }
}

/** Our incarnation token, so only this exact run can release the lock file. */
let ourToken = '';

function writeCompatFile(version: string): boolean {
  try {
    ourToken = randomUUID();
    const meta = {
      pid: process.pid,
      agent: agentName(),
      since: new Date().toISOString(),
      version,
      token: ourToken,
    };
    // Line 1 must stay a bare PID: older builds parseInt it, and a pure-JSON
    // file reads as NaN there, which makes them ignore the lock entirely.
    writeFileSync(lockFilePath(), `${process.pid}\n${JSON.stringify(meta)}\n`, 'utf8');
    return true;
  } catch {
    return false;
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function holderFromFile(): Holder {
  const compat = readCompatFile();
  if (!compat) return { pid: null, since: null, agent: null, source: 'unknown' };
  return { pid: compat.pid, since: compat.since, agent: agentName() || null, source: 'lock-file' };
}

/** Who holds the credential right now, asked of the holder first. */
export async function whoHolds(): Promise<Holder> {
  return (await askHolder()) ?? holderFromFile();
}

export async function acquireCredential(version: string): Promise<Claim> {
  const result = await tryBind();

  if (result.status === 'in-use') return { ok: false, holder: await whoHolds() };

  if (result.status === 'error') {
    // Could not bind at all. Serving anyway risks two live instances.
    return {
      ok: false,
      holder: await whoHolds(),
      reason: `could not claim the credential (${result.message})`,
    };
  }

  // Bound. But an OLDER copy on this machine binds no address at all — it only
  // writes the pid file, so that file is the only trace it leaves. Honour it.
  const compat = readCompatFile();
  if (compat && compat.pid !== process.pid && pidAlive(compat.pid)) {
    try { result.server.close(); } catch { /* ignore */ }
    return { ok: false, holder: holderFromFile() };
  }

  if (!writeCompatFile(version)) {
    // An older copy gates on this file. Unwritten, it sees no lock and starts
    // alongside us — so failing to write it is failing to hold the credential.
    try { result.server.close(); } catch { /* ignore */ }
    return {
      ok: false,
      holder: { pid: null, since: null, agent: null, source: 'unknown' },
      reason: `could not write ${lockFilePath()}, which older copies rely on`,
    };
  }

  identityLine = JSON.stringify({
    protocol: 'wundervault-mcp-holder',
    pid: process.pid,
    agent: agentName(),
    since: new Date().toISOString(),
  }) + '\n';
  result.server.on('connection', (sock) => {
    try { sock.end(identityLine); } catch { /* ignore */ }
  });

  held = result.server;
  return { ok: true };
}

/** Release only a lock file this exact incarnation wrote. */
export function releaseCredential(): void {
  try {
    const compat = readCompatFile();
    // A PID match alone is not proof — the file may have been replaced, or the
    // PID recycled. The token is generated once per run and never reused, so it
    // is the only thing that identifies THIS incarnation. A file with no token
    // was written by an older build, never by us, so it is never ours to remove.
    if (compat && ourToken !== '' && compat.token === ourToken) {
      unlinkSync(lockFilePath());
    }
  } catch { /* ignore */ }
  try { held?.close(); } catch { /* ignore */ }
  held = null;
}

/** Is the credential free right now? */
export async function credentialIsFree(): Promise<boolean> {
  if (held) return false;
  const result = await tryBind();
  if (result.status !== 'bound') return false;
  try { result.server.close(); } catch { /* ignore */ }
  const compat = readCompatFile();
  return !(compat && compat.pid !== process.pid && pidAlive(compat.pid));
}

export function describeHolder(h: Holder): string {
  const bits: string[] = [];
  if (h.pid !== null) bits.push(`PID ${h.pid}`);
  if (h.since) bits.push(`connected since ${h.since}`);
  if (!bits.length) return 'another process on this machine';
  if (h.source === 'lock-file') bits.push('reported by its lock file');
  return bits.join(', ');
}

export function addressDescription(): string {
  return IS_LINUX
    ? `abstract socket wundervault-mcp-${addressKey()}`
    : `127.0.0.1:${addressPort()}`;
}

export function lockFileExists(): boolean {
  return existsSync(lockFilePath());
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
  whoHolds,
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
    // Re-check with the kernel, and ask whoever holds it NOW who they are.
    // Replaying the startup snapshot would name the wrong process as soon as
    // the credential changed hands while this session sat blocked.
    const free = await credentialIsFree();
    const current = free ? null : await whoHolds();
    const text = current
      ? `Vault tools are unavailable in this session. The credential for ` +
        `"${agent}" is currently held by another MCP instance ` +
        `(${describeHolder(current)}). The vault permits one connected agent per ` +
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
  if (claim.reason) console.error(`[wundervault-mcp] ${claim.reason}`);
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

describe('holder identity', () => {
  it('answers who it is over the bound address, with no lock file involved', async () => {
    await lock.acquireCredential('9.9.9');
    rmSync(lock.lockFilePath());          // the file anyone could delete
    const who = await lock.whoHolds();
    expect(who.source).toBe('holder');    // learned from the holder, not the file
    expect(who.pid).toBe(process.pid);
    expect(who.agent).toBe(AGENT);
  });

  it('falls back to the lock file when nobody answers', async () => {
    writeFileSync(lock.lockFilePath(), `${process.ppid}\n${JSON.stringify({ since: 'x' })}\n`);
    const who = await lock.whoHolds();
    expect(who.source).toBe('lock-file');
    expect(who.pid).toBe(process.ppid);
  });

  it('never puts a secret or a parent command line in the banner', async () => {
    await lock.acquireCredential('9.9.9');
    const who = await lock.whoHolds();
    expect(Object.keys(who).sort()).toEqual(['agent', 'pid', 'since', 'source']);
  });
});

describe('release guard', () => {
  it('does not remove a lock file written by a different incarnation', async () => {
    await lock.acquireCredential('9.9.9');
    // Same PID, different token — a replaced or restored file.
    writeFileSync(
      lock.lockFilePath(),
      `${process.pid}\n${JSON.stringify({ pid: process.pid, token: 'someone-elses-token' })}\n`,
    );
    lock.releaseCredential();
    expect(existsSync(lock.lockFilePath())).toBe(true);
  });

  it('does not remove a legacy tokenless lock file', async () => {
    await lock.acquireCredential('9.9.9');
    writeFileSync(lock.lockFilePath(), String(process.pid));
    lock.releaseCredential();
    expect(existsSync(lock.lockFilePath())).toBe(true);
  });
});

describe('distinct agents that slug the same', () => {
  it('share a lock FILENAME but claim different addresses', async () => {
    // 'Team A' and 'Team?A' both slug to mcp-Team_A. They are DIFFERENT
    // credentials, so they must not exclude each other — but the lock filename
    // has to stay slug-based for older copies. Hence the address, and only the
    // address, carries a digest of the raw name.
    process.env.WUNDERVAULT_AGENT_NAME = 'Team A';
    const fileA = lock.lockFilePath();
    const addrA = lock.addressDescription();

    process.env.WUNDERVAULT_AGENT_NAME = 'Team?A';
    const fileB = lock.lockFilePath();
    const addrB = lock.addressDescription();

    expect(fileA).toBe(fileB);        // unchanged, for older readers
    expect(addrA).not.toBe(addrB);    // distinct credentials, distinct claims
    process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  });

  it('bounds the address length however long the agent name is', () => {
    process.env.WUNDERVAULT_AGENT_NAME = 'A'.repeat(500);
    // A unix socket address is capped at 108 bytes; an unbounded name would
    // make the claim fail to bind and a free credential look held.
    expect(lock.addressDescription().length).toBeLessThan(100);
    process.env.WUNDERVAULT_AGENT_NAME = AGENT;
  });
});

describe('refusing when the claim cannot be made safely', () => {
  it('does not serve when the lock file cannot be written', async () => {
    // An older copy gates on that file; unwritten, it would start alongside us.
    (os as any).homedir = () => path.join(home, 'does', 'not', 'exist');
    const claim = await lock.acquireCredential('9.9.9');
    (os as any).homedir = () => home;
    expect(claim.ok).toBe(false);
    expect(claim.reason).toMatch(/could not write/);
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
- [round 3 B1] deferred: Any local process can bind the predictable address and impersonate occupancy without being an MCP server.
  reason: True and inherent to any same-UID lock — a process that can bind your address can also read your lock file, your socket and your home directory. It denies service rather than granting it, which is the safe direction, and the identity banner now makes an impostor visible (it cannot produce the protocol line, so the refusal reports the holder as unknown rather than pretending). Not fixable without an authenticated channel, which is out of proportion here.
- [round 3 B3] deferred: The suite covers the lock module and cross-process behaviour but not full MCP initialization, tool listing, tool rejection, or holder turnover.
  reason: Fair. Those paths ARE exercised, but by hand against the live daemon rather than in the suite — handshake, vault_status only, vault-tool rejection, and standing down for this machine's older-build holder. Worth turning into a spawned-server integration test; noted rather than done, and called out to the owner as the weakest part of the coverage.
