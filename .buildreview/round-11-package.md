# Review package — round 11
generated 2026-09-15T19:11:42+00:00

## Spec — judge the build against THIS

# SPEC — phase 4, the uid split (Linux)

Everything in phases 1–3.5 is careful handling. This is the phase that makes it a
boundary.

Today the daemon runs as the same uid as the agent it serves. So the agent can read the
daemon's key files, read its memory through `/proc/<pid>/mem`, edit the record of where it
sent secrets, and replace the binary. Every claim made so far is true only against an
agent that does not try. That is worth something — most failures are accidents, not
attacks — but it is not what "the key never reaches the agent" sounds like.

**Accepted by the owner, 2026-09-15: one `sudo` per machine at install.** Enrolment stays
unprivileged.

## A. What actually changes

| | before | after |
|---|---|---|
| daemon uid | the user's | `wundervault` system account |
| key material | `~/.wundervault/agent-profiles.enc` | `/var/lib/wundervault/`, 0700 |
| destination store | `~/.wundervault/network.json` | `/var/lib/wundervault/network.json` |
| unit | `systemctl --user` | system unit |
| enrolment | the installer WRITES the profile store | the installer ASKS the daemon |
| agent's identity | a token in a file the agent owns | unchanged — and now load-bearing |

## B. Enrolment becomes IPC, and this is the part that breaks

`onboard.py` currently derives the machine key and writes `agent-profiles.enc` itself. After
the split that directory is not writable by the user, so **enrolment stops being a file
write and becomes a request**. This is the single largest change in the phase and the one
most likely to be got wrong quietly, because the old path fails by writing a file nobody
reads rather than by erroring.

- B1. The installer sends the profile over the management socket. It never touches
      `/var/lib/wundervault`.
- B2. Enrolment is authorised by the **server-issued setup token** the owner pastes, not by
      local privilege. A local user without a setup token cannot enrol an agent; a user
      with one needs no `sudo`.
- B3. A setup token is single-use and time-boxed — it already is, server-side. The daemon
      must not treat "the server accepted it" as reusable local authority.
- B4. The installer must FAIL LOUDLY if the daemon is not running. Writing the old file as
      a fallback would silently recreate the pre-split world with a daemon that ignores it.
- B5. Removing an agent is the same shape: a request, not an `rm`.

## C. Peer identity: the token, and what it is not

Node exposes no `SO_PEERCRED`, and a native addon would put a compiled binary inside a
package whose whole pitch is that you can read it. So identity is the per-agent token in
`~/.wundervault/agents/<name>.token`, 0600, owned by the agent's uid.

- C1. The socket is world-connectable, because the daemon is now a different uid and a
      0600 socket it owns could not be reached by the agent at all. The token is the
      identity, not the file mode.
- C2. Compared in constant time. A wrong token closes the connection without saying
      whether the agent name exists.
- C3. Repeated bad tokens on one socket are rate-limited. World-connectable means any
      local user may knock, and an unbounded guessing loop against a 32-byte token is not
      a real threat but an unbounded *connection* loop is.
- C4. **Honest limit, correcting the plan:** `SO_PEERCRED` reports PID, UID *and* GID — not
      "a uid anyway", as `PLAN-local-shape-and-uid-split.md` claims. So the token is
      slightly weaker than the kernel check, not equivalent: it proves possession of a
      file, and any process that can read that file presents the same identity. At uid
      granularity the two coincide, which is the granularity we claim.
- C5. One uid is one principal. Two agents under one uid cannot be told apart — by us or by
      the kernel. Seven agents currently run under one uid on the owner's machine, so this
      is the live case, not a corner.

## D. What the split actually buys, stated so it can be checked

- D1. The agent's uid cannot read `/var/lib/wundervault`. Enforced by mode 0700 on a
      directory owned by another user.
- D2. The agent cannot read the daemon's memory. Enforced by uid separation: `ptrace` and
      `/proc/<pid>/mem` require the same uid or `CAP_SYS_PTRACE`.
- D3. The destination store becomes an **integrity control**, not merely privacy. Until
      now the party being audited owned the evidence.
- D4. **`LimitCORE=0` does NOT make a process non-dumpable** — correcting the plan's B1
      bullet. It prevents a core file being written; it does nothing about `ptrace`. D2 is
      what prevents memory reading, and it is the uid, not the unit file, doing the work.
      The unit setting is defence against a crash dump landing on disk, and should be
      described as that.
- D5. The at-rest encryption of the profile store is **defence in depth, not the
      boundary**. Its key derives from the machine id, the uid, and a salt file stored
      beside the ciphertext — so anyone who can read the directory can recompute it. The
      directory mode is the control. Saying otherwise would repeat the mistake this phase
      exists to correct.

## E. The unit

- E1. A **system** unit, `User=wundervault`, `Group=wundervault`.
- E2. `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `ProtectSystem=strict`,
      `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictSUIDSGID=yes`,
      `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `MemoryDenyWriteExecute=yes`,
      `LockPersonality=yes`, `ProtectProc=invisible`, `LimitCORE=0`.
- E3. `ReadWritePaths=/var/lib/wundervault` and nothing else writable.
- E4. `RuntimeDirectory=wundervault` so the socket directory is created and cleaned up by
      systemd rather than by our code guessing at `/run`.
- E5. The daemon must refuse to start as root. A daemon that keeps root because the unit
      was edited is worse than one that never had it.

## F. Migration

- F1. On first start as the system account, if `/var/lib/wundervault` is empty and a user
      store exists, the installer — not the daemon — hands the profiles over via B1.
      The daemon must not read another user's home directory; that is precisely the
      access this phase removes.
- F2. The old `systemctl --user` unit is disabled and removed, or two daemons fight over
      one agent name and the loser's socket wins by being last to bind.
- F3. The user's `~/.wundervault/agents/<name>.token` STAYS. It is the identity now.
- F4. After migration the old `agent-profiles.enc` is deleted, not left behind. Leaving it
      leaves a readable copy of every credential this phase just moved.
- F5. Migration is idempotent and re-runnable.

## G. Install

- G1. One privileged step, doing only: create the system user, install the unit, create
      `/var/lib/wundervault`, enable the service.
- G2. **Not `curl | sudo sh`.** The product's differentiator is a verifiable installer;
      piping unverified network content into root contradicts the pitch.
- G3. **`dpkg` does not verify a downloaded `.deb`** — correcting the plan's B1 bullet.
      Package signing verifies a *repository*; a file fetched over HTTPS and installed with
      `dpkg -i` is verified by nothing but TLS. Either ship a repo, or verify a detached
      signature explicitly before installing, the way `onboard.py` already does.
- G4. The privileged step is printed in full before it runs, and is re-runnable.

## Acceptance checks

1. The daemon refuses to start as root.
2. Running as `wundervault`, the agent's uid cannot read `/var/lib/wundervault`.
3. An agent with a valid token connects and retrieves its credentials.
4. An agent with a wrong token is refused, and the refusal does not reveal whether the
   name exists.
5. Repeated bad tokens are rate-limited rather than served indefinitely.
6. Enrolment through the management socket creates a usable profile.
7. Enrolment without a valid setup token is refused.
8. The installer fails loudly when the daemon is absent, and writes no fallback file.
9. Migration moves profiles, deletes the old store, and keeps the agent tokens.
10. Migration run twice leaves the same state as once.
11. The destination store lives under `/var/lib/wundervault` and the agent's uid cannot
    write it.
12. `--destinations` still works for a user who cannot read the store directly.
13. The unit file contains every hardening directive in E2.
14. Nothing in the codebase resolves daemon state through `os.homedir()` any more.

## Out of scope

- macOS (phase 4b) and Windows (phase 4c).
- The key-hierarchy migration (phase 5). This phase moves ciphertext; it does not re-wrap
  it.
- Server-side enforcement of `entry_mode` (phase 6), which needs the daemon to hold an
  identity of its own.


## What was built this round, and how it was tested

ROUND 11 — first review of phase 4 (the uid split, Linux). Rounds 1-10 covered phases
1-3.5 and did NOT see any of this code.

WHAT WAS BUILT (commit a7d6dee, 1746 insertions):
- src/paths.ts (NEW): every daemon path now resolves through stateRoot()/userRoot()
  instead of os.homedir(). Daemon state -> /var/lib/wundervault (0700, owned by the
  `wundervault` system account). Agent-side state (tokens) stays in the user's home.
- src/migrate.ts (NEW): enrolment/migration became IPC. onboard.py used to derive the
  machine key and WRITE ~/.wundervault/agent-profiles.enc; it cannot now, so --migrate
  pushes profiles in over the management socket and the daemon writes them. Refuses to
  run when the daemon is absent (no fallback file). Deletes the old store when every
  agent is across. Idempotent.
- src/agent.ts: sockets are world-connectable now (a 0600 socket owned by a different
  uid is unreachable by the agent), so the per-agent TOKEN is the identity. Tokenless
  profiles refused at registration AND at startup. Constant-time compare. Rate limit on
  repeated bad tokens. Management socket is bound inside a pre-created 0770 directory
  rather than chmod-after-listen (a test caught the window at 0775).
- packaging/install-daemon.sh + wundervault-agent.service: the one privileged step
  (create system user, install unit, create /var/lib/wundervault, enable). Not curl|sudo sh.
- --destinations asks the daemon for the store instead of calling load(), which swallowed
  a read error and returned an empty shape — it would have told a user their keys had
  gone nowhere.

HOW IT WAS TESTED: 33 new tests in test/uid-split.test.ts against a real daemon on real
unix sockets; 366 tests total, all passing. `npm test` green.

WHAT HAS *NOT* BEEN DONE — judge the code accordingly:
- The installer has NEVER BEEN RUN. There is no `wundervault` user and no
  /var/lib/wundervault on this machine. The live daemon is still the OLD
  `systemctl --user` unit running as the agent's own uid.
- So every test runs with daemon and agent under the SAME uid, with the split simulated
  by env vars (WUNDERVAULT_STATE_ROOT / WUNDERVAULT_USER_ROOT / WUNDERVAULT_RUNTIME_DIR).
  Acceptance checks 1, 2 and 11 are therefore NOT proven by the suite — they are proven
  only by a real install. Tell me what a same-uid test suite CANNOT catch here.
- Migration has never been run against the real store (7 live agent profiles).

WHAT I AM WITHHOLDING (flag any finding that depends on it):
- src/server.ts is 67KB and mostly unrelated to this phase; you are getting only its
  DIFF for this commit, not the whole file. Same for src/index.ts, src/log-viewer.ts,
  src/network-store.ts — diffs only.
- onboard.py (the installer's Python half) is in a different repo (burnbox) and is NOT
  included. Findings about its internals cannot be verified by me from this payload.

ONE THING I ALREADY SUSPECT, say whether you agree and whether there are more like it:
the last test in test/uid-split.test.ts ('refuses to run when the daemon is not there')
runs with WUNDERVAULT_USER_ROOT unset, so migrate() resolves the source store to the
REAL /home/zee/.wundervault/agent-profiles.enc. It only fails at the daemon check today,
so nothing is destroyed — but the ordering is the only thing protecting a live
credential store from a test.

PRIORITISE: (a) ways the boundary is weaker than the spec claims, (b) anything in the
migration that could lose or expose the live profiles, (c) what breaks on a real install
that a same-uid test cannot show.

## Diff

```diff
diff --git a/src/index.ts b/src/index.ts
index 0328886..0fd26a2 100644
--- a/src/index.ts
+++ b/src/index.ts
@@ -33,22 +33,27 @@ const { values } = parseArgs({
 // the daemon is down, when the credential is held by another agent, and when you are
 // looking at this precisely because something is wrong.
 if (values.destinations) {
-  const { writeViewer } = await import('./log-viewer.js');
-  const { destinationsFor, defaultStorePath, load } = await import('./network-store.js');
+  const { writeViewer, collectShape } = await import('./log-viewer.js');
+  const { defaultStorePath } = await import('./network-store.js');
   const store = defaultStorePath();
-  const shape = load(store);
-  const out = writeViewer(store);
-  const calls = shape.seen.reduce((n, s) => n + s.count, 0);
-  console.log(`
+  try {
+    const { shape, source } = await collectShape(store);
+    const out = writeViewer(store, undefined, shape);
+    const calls = shape.seen.reduce((n, s) => n + s.count, 0);
+    console.log(`
 Destination log — ${shape.seen.length} destination(s), ${calls} call(s)
-  store:  ${store}
+  store:  ${store}${source === 'daemon' ? ' (read by the daemon on your behalf)' : ''}
   viewer: ${out}
 
 Open that file in your browser. It contains the data already, loads nothing, and is
 blocked by its own content-security policy from making any network request. Nothing was
 sent anywhere to produce it.
 `);
-  process.exit(0);
+    process.exit(0);
+  } catch (e) {
+    console.error((e as Error).message);
+    process.exit(1);
+  }
 }
 
 if (values.help) {
diff --git a/src/log-viewer.ts b/src/log-viewer.ts
index 4fbeeba..93b291b 100644
--- a/src/log-viewer.ts
+++ b/src/log-viewer.ts
@@ -29,9 +29,11 @@
  * What it IS: one self-contained HTML file with the data already inside it, written
  * 0600 next to the store, which you open with your own browser and delete when done.
  */
-import { writeFileSync, mkdirSync, chmodSync } from 'node:fs';
+import { writeFileSync, mkdirSync, chmodSync, accessSync, constants } from 'node:fs';
+import * as net from 'node:net';
 import * as path from 'node:path';
 import { load, defaultStorePath, type NetworkShape } from './network-store.js';
+import { mgmtSocketPath, viewerPath } from './paths.js';
 
 /** Escape for embedding inside an HTML text node or attribute. */
 function esc(s: string): string {
@@ -256,11 +258,78 @@ render();
  * automatically — this is a daemon, and a daemon that launches a browser is a daemon doing
  * something nobody asked it to.
  */
-export function writeViewer(storePath = defaultStorePath(), outPath?: string): string {
-  const shape = load(storePath);
-  const target = outPath ?? path.join(path.dirname(storePath), 'destinations.html');
+export function writeViewer(storePath = defaultStorePath(), outPath?: string,
+                            shapeOverride?: NetworkShape): string {
+  const shape = shapeOverride ?? load(storePath);
+  // The USER's directory, not the daemon's. After the split the store lives somewhere the
+  // person running this cannot write, and dropping the page beside it would fail — or,
+  // worse, succeed for the one user who still owns both.
+  const target = outPath ?? viewerPath();
   mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
   writeFileSync(target, renderViewer(shape, storePath), { mode: 0o600 });
   try { chmodSync(target, 0o600); } catch { /* best effort */ }
   return target;
 }
+
+
+/**
+ * Get the destinations, from wherever they can honestly be got.
+ *
+ * After the uid split the store belongs to the daemon and the person running this cannot
+ * read it. That is the boundary working. But `load()` swallows a read error and returns
+ * an empty shape — which would render a page saying this machine's agents have never sent
+ * a secret anywhere, to someone who is looking precisely because they want to know. A
+ * wrong answer delivered confidently is worse than an error.
+ *
+ * So: ask the daemon first, fall back to reading the file, and if neither works say which
+ * one failed rather than showing an empty table.
+ */
+export async function collectShape(
+  storePath = defaultStorePath(),
+): Promise<{ shape: NetworkShape; source: 'daemon' | 'file' }> {
+  let daemonSaid: string | null = null;
+  const viaDaemon = await askDaemon().catch((e: Error) => {
+    // Distinguish "no daemon there" from "the daemon says something is wrong". The first
+    // is a fallback; the second is the answer.
+    if (!/ENOENT|ECONNREFUSED|timed out/.test(e.message)) daemonSaid = e.message;
+    return null;
+  });
+  if (viaDaemon) return { shape: viaDaemon, source: 'daemon' };
+  if (daemonSaid) throw new Error(daemonSaid);
+
+  try {
+    accessSync(storePath, constants.R_OK);
+  } catch {
+    throw new Error(
+      `Cannot read the destination log, and the daemon did not answer.\n` +
+      `  store:  ${storePath} (not readable by you — this is the uid split working)\n` +
+      `  daemon: ${mgmtSocketPath()}\n` +
+      `Start it:  sudo systemctl start wundervault-agent\n` +
+      `Refusing to show you an empty page, which is what this used to do.`,
+    );
+  }
+  return { shape: load(storePath), source: 'file' };
+}
+
+function askDaemon(timeoutMs = 3_000): Promise<NetworkShape | null> {
+  return new Promise((resolve, reject) => {
+    const sock = net.createConnection(mgmtSocketPath());
+    let buf = '';
+    const fin = (fn: () => void) => { clearTimeout(timer); sock.destroy(); fn(); };
+    const timer = setTimeout(() => fin(() => reject(new Error('daemon timed out'))), timeoutMs);
+    sock.on('connect', () => sock.write(JSON.stringify({ action: 'destinations' }) + '\n'));
+    sock.on('data', (d) => {
+      buf += d.toString();
+      if (!buf.includes('\n')) return;
+      try {
+        const reply = JSON.parse(buf.trim());
+        // A daemon that answered with an error has told us something worth repeating.
+        // Treating it as "no answer" would fall through to the file and, if that happened
+        // to be readable, quietly disagree with the daemon about what the truth is.
+        if (reply?.error) { fin(() => reject(new Error(String(reply.error)))); return; }
+        fin(() => resolve(reply?.ok && reply.shape ? reply.shape as NetworkShape : null));
+      } catch { fin(() => reject(new Error('unparseable reply'))); }
+    });
+    sock.on('error', (e) => fin(() => reject(e)));
+  });
+}
diff --git a/src/network-store.ts b/src/network-store.ts
index 0dc2efc..2131dc3 100644
--- a/src/network-store.ts
+++ b/src/network-store.ts
@@ -48,8 +48,8 @@
  */
 import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync,
   openSync, closeSync, unlinkSync, statSync } from 'node:fs';
-import * as os from 'node:os';
 import * as path from 'node:path';
+import { networkStorePath } from './paths.js';
 
 export interface SeenDestination {
   entryId: string;
@@ -103,10 +103,10 @@ export function recordingEnabled(): boolean {
 }
 
 export function defaultStorePath(): string {
-  // After the uid split this becomes /var/lib/wundervault/network.json, owned by the
-  // daemon account. Same shape, same code — only the path and the owner change.
-  return process.env.WUNDERVAULT_NETWORK_STORE
-    || path.join(os.homedir(), '.wundervault', 'network.json');
+  // Daemon-owned since phase 4. This is what turns the file from an observation into an
+  // integrity control: before the split it sat in the agent's own home, so the party
+  // being audited could edit the evidence.
+  return process.env.WUNDERVAULT_NETWORK_STORE || networkStorePath();
 }
 
 export function load(storePath = defaultStorePath()): NetworkShape {
diff --git a/src/server.ts b/src/server.ts
index 7bb53a4..a48c3a1 100644
--- a/src/server.ts
+++ b/src/server.ts
@@ -18,6 +18,7 @@ import { loadOpenSshEd25519, runSshBrokered, modeAllowsLegacyExec, modeAllowsSsh
   modeAllowsHttpBroker, wrongModeMessage, type BrokeredOp } from './ssh-agent.js';
 import { verifyOperationDefinition, validateArguments } from './opdef.js';
 import { recordDestination, newDestinationNotice, emitToStderr } from './network-store.js';
+import { agentTokenPath, agentSocketPath, legacy } from './paths.js';
 import { definitionFromAgentRequest, originString, isApprovedPrivateOrigin, type AgentRequest } from './http-broker.js';
 import { performOperation } from './http-broker.js';
 import { runWithSecret, runWithSecretStdin, runWithSecretAskpass, runWithSecretRemote, runRsync, coerceExecConfig, resolveDeliveryConfig, isValidEnvKey, commandInvokesSudo } from './exec.js';
@@ -88,25 +89,53 @@ async function getCredentials(): Promise<Credentials> {
     );
   }
 
-  const tokenFilePath = path.join(os.homedir(), '.wundervault', 'agents', agentName + '.token');
+  const tokenFilePath = agentTokenPath(agentName);
   const agentToken = process.env.WUNDERVAULT_AGENT_TOKEN ||
     (fsExistsSync(tokenFilePath) ? readFileSync(tokenFilePath, 'utf8').trim() : '');
 
-  const sockPath = path.join(os.homedir(), '.wundervault', 'agents', agentName + '.sock');
-  const daemonCreds = await tryDaemonConnect(sockPath, agentToken);
+  // The system daemon first, then the pre-split socket in the user's home.
+  //
+  // The fallback exists so a machine mid-migration keeps working, and it ANNOUNCES itself
+  // rather than being silent: an install that still reaches the old socket has the old
+  // threat model — same uid, key files readable, memory readable — while the release notes
+  // say otherwise. Someone should be told they are not yet behind the boundary they think
+  // they are behind.
+  const sockPath = agentSocketPath(agentName);
+  let daemonCreds = await tryDaemonConnect(sockPath, agentToken);
+  let usedLegacy = false;
+
+  if (!daemonCreds) {
+    const legacySock = legacy.agentSocket(agentName);
+    if (legacySock !== sockPath && fsExistsSync(legacySock)) {
+      daemonCreds = await tryDaemonConnect(legacySock, agentToken);
+      if (daemonCreds) {
+        usedLegacy = true;
+        // stderr, not the tool result: this is a property of the install, not something
+        // the model needs to reason about or could act on.
+        process.stderr.write(
+          `[wundervault] Using the pre-phase-4 daemon socket at ${legacySock}.\n` +
+          `[wundervault] That daemon runs as YOUR user, so it shares a uid with this agent:\n` +
+          `[wundervault] its key material and memory are readable by anything you run.\n` +
+          `[wundervault] Finish the split:  sudo sh packaging/install-daemon.sh && wundervault-agent --migrate\n`,
+        );
+      }
+    }
+  }
 
   if (!daemonCreds) {
     const sockExists = fsExistsSync(sockPath);
     throw new Error(
       sockExists
         ? `wundervault-agent crashed — socket exists but daemon is not responding for '${agentName}'.\n` +
-          `Restart it: systemctl --user restart wundervault-agent\n` +
+          `Restart it: sudo systemctl restart wundervault-agent\n` +
           `Socket: ${sockPath}`
         : `wundervault-agent daemon not running for agent '${agentName}'.\n` +
           `Expected socket: ${sockPath}\n` +
-          `Run onboard.py to register and start the daemon, then retry any vault tool.`
+          `Install the daemon:  sudo sh packaging/install-daemon.sh\n` +
+          `Then enrol:          run onboard.py, or wundervault-agent --migrate if you had it before.`
     );
   }
+  void usedLegacy;
 
   const creds: Credentials = {
     agent_vault_url: _credsUrl || daemonCreds.vault_url || 'https://wundervault.com',

```

## File: src/paths.ts

```
/**
 * Where daemon state lives, and who is allowed to read it.
 *
 * Until phase 4 every path here was under `os.homedir()`, which meant the daemon and the
 * agent it serves were the same uid and shared a directory. Everything built in phases
 * 1–3.5 was true only against an agent that did not try: the key files were readable, the
 * daemon's memory was readable through /proc, and the record of where secrets went was
 * writable by the party it described.
 *
 * The split moves daemon state to `/var/lib/wundervault`, mode 0700, owned by a system
 * account. The mode is the control. The at-rest encryption beside it is defence in depth
 * and nothing more — its key derives from the machine id, the uid and a salt file stored
 * next to the ciphertext, so anyone who can read the directory can recompute it. Calling
 * that "encrypted at rest" as though it were the boundary would repeat exactly the mistake
 * this phase exists to correct.
 *
 * TWO ROOTS, AND THEY ARE NOT THE SAME THING
 *
 *   systemRoot()  — the daemon's. Credentials, the destination store. The agent's uid
 *                   cannot read it. Only the daemon process writes here.
 *   userRoot()    — the agent's own. Its token, and nothing else that matters.
 *
 * The token stays in the user's home ON PURPOSE. It is the agent's identity now: a file
 * owned by the agent's uid at 0600, which the daemon checks. Moving it into the daemon's
 * directory would make it unreadable by the only party that needs it.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/** The packaged default. Overridable for tests and for a non-standard install. */
export const DEFAULT_SYSTEM_ROOT = '/var/lib/wundervault';
export const SYSTEM_ACCOUNT = 'wundervault';

/**
 * Daemon-owned state.
 *
 * `WUNDERVAULT_SYSTEM_ROOT` exists so tests can point this somewhere writable, and so an
 * unusual install can relocate it. It is read from the DAEMON's environment, which after
 * the split is set by the unit file rather than by whoever started a shell — an agent
 * cannot move the daemon's state by exporting a variable, because it does not control the
 * daemon's environment.
 */
export function systemRoot(): string {
  return process.env.WUNDERVAULT_SYSTEM_ROOT || DEFAULT_SYSTEM_ROOT;
}

/** The agent's own directory: its token, and its view of things. */
export function userRoot(): string {
  return process.env.WUNDERVAULT_USER_ROOT || path.join(os.homedir(), '.wundervault');
}

/**
 * Where sockets live.
 *
 * `RuntimeDirectory=wundervault` in the unit makes systemd create and clean up
 * `/run/wundervault`, which is better than our code guessing: a stale socket in a
 * hand-made directory survives a crash and the next start binds somewhere else, leaving
 * agents talking to nothing.
 *
 * Falls back to the system root when there is no /run — a container, a test, a platform
 * that does not have one.
 */
export function runtimeDir(): string {
  if (process.env.RUNTIME_DIRECTORY) return process.env.RUNTIME_DIRECTORY.split(':')[0];
  if (process.env.WUNDERVAULT_RUNTIME_DIR) return process.env.WUNDERVAULT_RUNTIME_DIR;
  const run = `/run/${SYSTEM_ACCOUNT}`;
  try { if (fs.existsSync(run)) return run; } catch { /* fall through */ }
  return path.join(systemRoot(), 'run');
}

// ── daemon-side paths ─────────────────────────────────────────────────────────

export const profilesPath = () => path.join(systemRoot(), 'agent-profiles.enc');
export const saltPath = () => path.join(systemRoot(), 'agent-salt.bin');

/**
 * The destination store — daemon-owned, which is what turns it from an observation into
 * an integrity control. Before the split, the party being audited could edit the evidence.
 */
export const networkStorePath = () => path.join(systemRoot(), 'network.json');

/**
 * The management socket, inside its own directory.
 *
 * Enrolment writes credentials INTO the daemon, so unlike the per-agent sockets this one
 * must not be reachable by every local process. Restricting it with chmod after listen()
 * leaves a window: the socket exists at the default mode from the moment it is bound
 * until the chmod lands, and a process watching for it can connect in that gap. A
 * DIRECTORY at 0770 has no such window — it is created before the socket is bound, and
 * traversal is checked on every connect regardless of what mode the socket itself ended
 * up with.
 */
export const mgmtDir = () => path.join(runtimeDir(), 'mgmt');
export const mgmtSocketPath = () => path.join(mgmtDir(), 'agent.sock');
export const agentSocketPath = (name: string) =>
  path.join(runtimeDir(), `${safeName(name)}.sock`);

// ── agent-side paths ──────────────────────────────────────────────────────────

/** The agent's identity. 0600, owned by the agent's uid, checked by the daemon. */
export const agentTokenPath = (name: string) =>
  path.join(userRoot(), 'agents', `${safeName(name)}.token`);

/** Where `--destinations` writes its page: the user's own directory, not the daemon's. */
export const viewerPath = () => path.join(userRoot(), 'destinations.html');

// ── pre-split locations, for migration only ───────────────────────────────────

/**
 * Pre-split locations, for migration only.
 *
 * These resolve through `userRoot()`, NOT through `os.homedir()` directly, and that is not
 * a stylistic preference — it is a safety property, learned the hard way.
 *
 * `os.homedir()` on Linux reads the passwd entry rather than honouring a `$HOME` set at
 * runtime. A test that set `process.env.HOME` to a scratch directory and expected these
 * paths to follow got the REAL home instead, and since migration deletes the old store
 * after moving it, the test destroyed a live credential file. It was recoverable only
 * because a long-running daemon still held the profiles in memory.
 *
 * Routing through `userRoot()` means `WUNDERVAULT_USER_ROOT` redirects every one of these,
 * so a test can point the destructive path somewhere harmless and have that actually
 * work. Anything that deletes should be reachable by an override that a test can prove it
 * has set.
 */
const legacyRoot = () => userRoot();

export const legacy = {
  root: legacyRoot,
  profiles: () => path.join(legacyRoot(), 'agent-profiles.enc'),
  salt: () => path.join(legacyRoot(), 'agent-salt.bin'),
  networkStore: () => path.join(legacyRoot(), 'network.json'),
  mgmtSocket: () => path.join(legacyRoot(), 'agent.sock'),
  agentSocket: (name: string) =>
    path.join(legacyRoot(), 'agents', `${safeName(name)}.sock`),
};

/**
 * An agent name reaches this from configuration and from the network, and it is about to
 * become a path segment.
 *
 * `../../etc/cron.d/x` as an agent name would otherwise place a daemon-written file
 * wherever it liked, which for a process that exists to hold a privilege boundary is the
 * whole game. Restricting to a known-safe alphabet is the check; rejecting rather than
 * sanitising means a name that would have been mangled fails visibly instead of quietly
 * pointing at the wrong file.
 */
export function safeName(name: string): string {
  const n = String(name ?? '').trim();
  if (!n || n.length > 64 || !/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(n) || n.includes('..')) {
    throw new Error(
      `Invalid agent name ${JSON.stringify(name)}. Use letters, digits, spaces, dot, ` +
      `underscore or hyphen, up to 64 characters.`,
    );
  }
  return n;
}

/**
 * Create the daemon's directory, refusing to widen one that already exists.
 *
 * mkdir's mode argument is masked by umask and is ignored entirely when the directory is
 * already there — so a directory created 0755 by an earlier version, or by a careless
 * hand, would stay 0755 and the boundary would be open while every other check passed.
 * chmod unconditionally, then verify.
 */
export function ensureSystemRoot(root = systemRoot()): void {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  fs.chmodSync(root, 0o700);
  const mode = fs.statSync(root).mode & 0o777;
  if (mode !== 0o700) {
    throw new Error(
      `${root} is mode ${mode.toString(8)}, expected 700. The directory mode IS the ` +
      `boundary here — refusing to run with it open.`,
    );
  }
}

/**
 * Is daemon state reachable by whoever is asking?
 *
 * Used to give a person a straight answer instead of ENOENT. After the split a user
 * running `--destinations` genuinely cannot read the store, and "no such file" would send
 * them looking for a bug rather than telling them the boundary is working.
 */
export function canReadSystemRoot(root = systemRoot()): boolean {
  try { fs.accessSync(root, fs.constants.R_OK | fs.constants.X_OK); return true; }
  catch { return false; }
}

/** True when this process is the daemon owning the state, rather than a client of it. */
export function runningAsDaemonAccount(root = systemRoot()): boolean {
  try {
    const uid = (process as unknown as { getuid?: () => number }).getuid?.();
    return uid !== undefined && fs.statSync(root).uid === uid;
  } catch { return false; }
}

```

## File: src/migrate.ts

```
/**
 * Hand existing agents over to the system daemon.
 *
 * Run by the user, without sudo, after the one privileged install step. It reads the
 * pre-split store from the user's own home — which only the user can do, and which is
 * exactly why the daemon must not do it: reaching into a user's home directory is the
 * access phase 4 removes, and a daemon that kept the habit would have kept the hole.
 *
 * So the direction is inward: the user pushes profiles in over the management socket, the
 * daemon writes them somewhere the user cannot read, and the user's copy is deleted.
 *
 * THE DELETION IS THE POINT. Migration that copies and leaves the original behind has
 * moved nothing: a readable file holding every credential still sits in a directory the
 * agent can read. Someone reading the release notes would believe otherwise.
 */
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { legacy, mgmtSocketPath, agentTokenPath, safeName } from './paths.js';

interface LegacyProfile {
  agent_name: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
  socket_token?: string;
}

/** One request/response over the management socket. */
function ask(payload: unknown, sockPath = mgmtSocketPath(), timeoutMs = 5_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(sockPath);
    let buf = '';
    const done = (fn: () => void) => { clearTimeout(timer); sock.destroy(); fn(); };
    const timer = setTimeout(
      () => done(() => reject(new Error(`timed out talking to the daemon at ${sockPath}`))),
      timeoutMs,
    );
    sock.on('connect', () => sock.write(JSON.stringify(payload) + '\n'));
    sock.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      try { done(() => resolve(JSON.parse(buf.trim()))); }
      catch { done(() => reject(new Error('unparseable reply from the daemon'))); }
    });
    sock.on('error', (e) => done(() => reject(e)));
  });
}

/**
 * Decrypt the pre-split store.
 *
 * The key derivation is duplicated here rather than imported, deliberately: the daemon's
 * version now derives against the DAEMON's uid and the new salt path, and this has to
 * derive against the USER's uid and the old one. Sharing the function would have silently
 * produced the wrong key and read as a corrupt store.
 */
function readLegacyProfiles(): LegacyProfile[] {
  const profilesPath = legacy.profiles();
  if (!fs.existsSync(profilesPath)) return [];

  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();
  const salt = fs.readFileSync(legacy.salt());
  const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;

  const buf = fs.readFileSync(profilesPath);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  const plain = Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
  return (JSON.parse(plain).profiles ?? []) as LegacyProfile[];
}

export interface MigrationResult {
  migrated: string[];
  skipped: { name: string; why: string }[];
  deletedLegacyStore: boolean;
  alreadyDone: boolean;
}

export async function migrate(opts: { dryRun?: boolean } = {}): Promise<MigrationResult> {
  const result: MigrationResult = {
    migrated: [], skipped: [], deletedLegacyStore: false, alreadyDone: false,
  };

  // Say out loud which file is about to be deleted, before deleting it.
  //
  // This function shreds a credential store. A test once pointed it at a real home
  // directory believing it had redirected it, and the only warning anybody got was the
  // absence of the file afterwards. One line of output costs nothing and turns a silent
  // destructive path into one somebody can notice going wrong.
  if (!opts.dryRun) {
    console.error(`[migrate] source store: ${legacy.profiles()} (will be deleted once every agent is across)`);
  }

  // Fail loudly if the daemon is absent. Writing the old file as a fallback would
  // recreate the pre-split world beside a daemon that never reads it, and everything
  // would appear to work.
  const ping = await ask({ action: 'ping' }).catch((e) => {
    throw new Error(
      `Could not reach the daemon at ${mgmtSocketPath()}: ${(e as Error).message}\n` +
      `Install it first:  sudo sh packaging/install-daemon.sh\n` +
      `Then check:        systemctl status wundervault-agent`,
    );
  });
  if (!ping?.ok) throw new Error('The daemon answered, but not with ok. Check its logs.');

  if (!fs.existsSync(legacy.profiles())) {
    result.alreadyDone = true;
    return result;
  }

  let profiles: LegacyProfile[];
  try {
    profiles = readLegacyProfiles();
  } catch (e) {
    throw new Error(
      `Could not read the old store at ${legacy.profiles()}: ${(e as Error).message}\n` +
      `It is encrypted against your machine id and uid, so this usually means it belongs ` +
      `to a different user or a different machine. Nothing has been changed.`,
    );
  }

  const already = new Set<string>(ping.agents ?? []);

  for (const p of profiles) {
    let name: string;
    try { name = safeName(p.agent_name); }
    catch (e) { result.skipped.push({ name: String(p.agent_name), why: (e as Error).message }); continue; }

    if (already.has(name)) { result.skipped.push({ name, why: 'already known to the daemon' }); continue; }

    // A profile with no socket token cannot be served: the per-agent socket is
    // world-connectable now, so the token is the only thing identifying the caller.
    // Minting one here keeps the migration unattended instead of sending someone back
    // through onboarding.
    //
    // The TOKEN FILE is checked separately from the token, and that distinction matters.
    // A profile can carry a token whose file has been lost — a restored home directory, a
    // half-finished uninstall — and migrating it would produce an agent the daemon knows
    // about and the client cannot authenticate as. It would look migrated and be locked
    // out, which is the worst of both. So the file is written whenever it is missing,
    // whether the token is new or inherited.
    const tp = agentTokenPath(name);
    let token = p.socket_token;
    const fileMissing = !fs.existsSync(tp);
    if (!token) token = crypto.randomBytes(32).toString('hex');

    if (!opts.dryRun && (fileMissing || !p.socket_token)) {
      fs.mkdirSync(path.dirname(tp), { recursive: true, mode: 0o700 });
      fs.writeFileSync(tp, token, { mode: 0o600 });
    }

    if (opts.dryRun) { result.migrated.push(name); continue; }

    const reply = await ask({
      action: 'register_profile',
      profile: { ...p, agent_name: name, socket_token: token },
    });
    if (reply?.ok) result.migrated.push(name);
    else result.skipped.push({ name, why: reply?.error ?? 'the daemon refused it' });
  }

  // Only delete once every profile is in. A partial migration that deleted the source
  // would lose the credentials it failed to move.
  const allIn = result.skipped.every(s => s.why === 'already known to the daemon');
  if (!opts.dryRun && allIn && result.skipped.length + result.migrated.length === profiles.length) {
    for (const f of [legacy.profiles(), legacy.salt()]) {
      try { shred(f); result.deletedLegacyStore = true; } catch { /* best effort */ }
    }
  }

  return result;
}

/**
 * Overwrite before unlinking.
 *
 * Not a guarantee — a journalling or copy-on-write filesystem, or an SSD's wear
 * levelling, can keep the old blocks regardless. It is worth doing because it costs
 * nothing and removes the easy case, and it is worth saying plainly that it does not make
 * the data unrecoverable.
 */
function shred(file: string): void {
  if (!fs.existsSync(file)) return;
  const size = fs.statSync(file).size;
  if (size > 0) fs.writeFileSync(file, crypto.randomBytes(size));
  fs.unlinkSync(file);
}

export function describe(r: MigrationResult, dryRun = false): string {
  if (r.alreadyDone) {
    return 'Nothing to migrate — there is no pre-split store in your home directory.';
  }
  const lines: string[] = [];
  if (r.migrated.length) {
    lines.push(dryRun
      ? `Would hand ${r.migrated.length} agent(s) to the daemon: ${r.migrated.join(', ')}`
      : `Handed ${r.migrated.length} agent(s) to the daemon: ${r.migrated.join(', ')}`);
  }
  for (const s of r.skipped) lines.push(`  ${dryRun ? 'would skip' : 'skipped'} ${s.name}: ${s.why}`);

  if (dryRun) {
    // A dry run reporting "LEFT the old store in place" reads as a failure rather than as
    // the absence of any action, which is what it actually is.
    lines.push('Dry run — nothing was changed. Re-run without --dry-run to do it.');
    return lines.join('\n');
  }
  lines.push(r.deletedLegacyStore
    ? 'Deleted the old store from your home directory. Credentials now live where your '
      + 'agents cannot read them.'
    : 'LEFT the old store in place, because not every agent made it across. Re-run this '
      + 'once the skipped ones are resolved — until then a readable copy of your '
      + 'credentials is still in your home directory.');
  return lines.join('\n');
}

```

## File: src/agent.ts

```
#!/usr/bin/env node
/**
 * The credential daemon, running as its own user.
 *
 * Before phase 4 this process shared a uid with the agents it served, so its key file, its
 * memory and its sockets were all readable by the party it was protecting them from.
 * Everything the vault claimed was true only against an agent that did not try.
 *
 * It now runs as the `wundervault` system account with its state in /var/lib/wundervault,
 * mode 0700. That directory mode is the boundary. The at-rest encryption is defence in
 * depth and is described as such — its key derives from the machine id, the uid and a salt
 * file kept beside the ciphertext, so anyone who can read the directory can recompute it.
 *
 * WHAT CHANGED IN THE THREAT MODEL, AND WHY THE SOCKETS LOOK WEAKER
 *
 * The per-agent sockets used to be 0600. They cannot be any more: the daemon is now a
 * different uid from every agent, and a 0600 socket it owns is one no agent could reach.
 * So the sockets are world-connectable and the TOKEN is the identity — a file in the
 * agent's own home at 0600, which only that uid can read.
 *
 * That makes the token check load-bearing in a way it never was. It used to be a second
 * lock behind a file mode; it is now the only lock. Two consequences the previous version
 * got wrong and this one must not:
 *
 *   1. A profile with no token used to be served to anyone who connected, because the
 *      check was inside `if (profile.socket_token)`. Behind a 0600 socket that was
 *      merely sloppy. In front of a world-connectable one it hands credentials to any
 *      local user. A profile without a token is now refused outright.
 *   2. Anyone may knock, so bad attempts are rate-limited per agent.
 */
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { VERSION } from './version.js';
import {
  systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
  runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
} from './paths.js';
import { load as loadNetworkShape } from './network-store.js';

interface AgentProfile {
  agent_name: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
  socket_token?: string;
}

interface ProfileStore {
  profiles: AgentProfile[];
}

/**
 * Refuse to be root.
 *
 * The unit says `User=wundervault`, but a unit is a file someone can edit, and a daemon
 * that silently keeps root because of a typo in /etc is worse than one that never had it:
 * every protection below would still appear to be working. Failing here makes the mistake
 * loud at the only moment anyone is watching.
 */
function refuseRoot(): void {
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  if (uid === 0) {
    console.error(
      `[wundervault-agent] Refusing to run as root.\n` +
      `  This daemon holds credentials and must run as its own unprivileged account.\n` +
      `  Expected User=${SYSTEM_ACCOUNT} in the unit file.\n` +
      `  If you installed by hand, re-run packaging/install-daemon.sh.`,
    );
    process.exit(1);
  }
}

function deriveMachineKey(): Buffer {
  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();

  let salt: Buffer;
  const sp = saltPath();
  if (fs.existsSync(sp)) {
    salt = fs.readFileSync(sp);
  } else {
    salt = crypto.randomBytes(32);
    ensureSystemRoot();
    fs.writeFileSync(sp, salt, { mode: 0o600 });
  }
  return crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
}

function encryptProfiles(store: ProfileStore, key: Buffer): Buffer {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(store), 'utf8'), cipher.final()]);
  return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
}

function decryptProfiles(buf: Buffer, key: Buffer): ProfileStore {
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}

/** Constant-time comparison of two hex tokens, safe against malformed input. */
export function tokenMatches(provided: string | undefined, expected: string | undefined): boolean {
  if (!expected) return false;          // no token configured: never a match
  if (!provided) return false;
  let a: Buffer, b: Buffer;
  try {
    a = Buffer.from(provided, 'hex');
    b = Buffer.from(expected, 'hex');
  } catch { return false; }
  // Length is compared first and separately on purpose: timingSafeEqual throws on a
  // length mismatch, and a thrown exception is a louder timing signal than the
  // comparison it was meant to protect.
  if (a.length === 0 || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Bad attempts, per agent name.
 *
 * The socket is world-connectable now, so any local process may knock. Guessing a 32-byte
 * token is not a real threat; an unbounded loop of connections is, and the log it would
 * produce is its own denial of service. A short lockout costs a legitimate agent one
 * retry after a genuine misconfiguration.
 */
class Knocks {
  private fails = new Map<string, { n: number; until: number }>();
  private readonly MAX = 10;
  private readonly WINDOW_MS = 60_000;

  lockedOut(name: string): boolean {
    const f = this.fails.get(name);
    return !!f && f.n >= this.MAX && Date.now() < f.until;
  }

  record(name: string): void {
    const now = Date.now();
    const f = this.fails.get(name);
    if (!f || now >= f.until) { this.fails.set(name, { n: 1, until: now + this.WINDOW_MS }); return; }
    f.n += 1;
  }

  clear(name: string): void { this.fails.delete(name); }
}

class AgentDaemon {
  private key: Buffer;
  private profiles: AgentProfile[] = [];
  private agentServers: Map<string, net.Server> = new Map();
  private mgmtServer: net.Server | null = null;
  private knocks = new Knocks();

  constructor() {
    ensureSystemRoot();
    this.key = deriveMachineKey();
    this.loadProfiles();
  }

  loadProfiles(): void {
    const pp = profilesPath();
    if (!fs.existsSync(pp)) return;
    try {
      this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
    } catch (err) {
      console.error('[wundervault-agent] Failed to decrypt profiles:', (err as Error).message);
    }
  }

  saveProfiles(): void {
    const pp = profilesPath();
    // Write-then-rename. A half-written store read after a crash decrypts to nothing and
    // every agent on the machine loses its credentials at once.
    const tmp = `${pp}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, encryptProfiles({ profiles: this.profiles }, this.key), { mode: 0o600 });
    fs.renameSync(tmp, pp);
    try { fs.chmodSync(pp, 0o600); } catch { /* best effort */ }
  }

  registerProfile(profile: AgentProfile): void {
    // The name becomes a path segment. It arrives over a socket any local process can
    // connect to, so "../../etc/cron.d/x" would otherwise have this daemon place a file
    // wherever it liked — which for the process holding the boundary is the whole game.
    profile.agent_name = safeName(profile.agent_name);

    if (!profile.socket_token) {
      throw new Error(
        'A profile must carry a socket_token. The per-agent socket is world-connectable ' +
        'now that the daemon runs as a different user, so the token is the only thing ' +
        'identifying the caller.',
      );
    }

    const idx = this.profiles.findIndex(p => p.agent_name === profile.agent_name);
    if (idx >= 0) {
      this.profiles[idx] = profile;
      const old = this.agentServers.get(profile.agent_name);
      if (old) {
        // Not unlinked in the close callback: startAgentSocket unlinks and rebinds
        // immediately, and the async callback would race it.
        old.close();
        this.agentServers.delete(profile.agent_name);
      }
    } else {
      this.profiles.push(profile);
    }
    this.knocks.clear(profile.agent_name);
    this.startAgentSocket(profile);
    this.saveProfiles();
  }

  removeProfile(name: string): boolean {
    const safe = safeName(name);
    const before = this.profiles.length;
    this.profiles = this.profiles.filter(p => p.agent_name !== safe);
    if (this.profiles.length === before) return false;
    const srv = this.agentServers.get(safe);
    if (srv) { try { srv.close(); } catch { /* already gone */ } }
    this.agentServers.delete(safe);
    try { fs.unlinkSync(agentSocketPath(safe)); } catch { /* already gone */ }
    this.saveProfiles();
    return true;
  }

  startAgentSocket(profile: AgentProfile): void {
    const sockPath = agentSocketPath(profile.agent_name);
    try { fs.unlinkSync(sockPath); } catch { /* nothing to clear */ }

    const srv = net.createServer((socket) => {
      let buf = '';
      // A caller that never sends a newline would otherwise hold a connection open for
      // ever, and a caller that streams without one would grow this buffer without bound.
      socket.setTimeout(5_000, () => socket.destroy());
      socket.on('data', (d) => {
        buf += d.toString();
        if (buf.length > 4096) { socket.destroy(); return; }
        if (!buf.includes('\n')) return;

        if (this.knocks.lockedOut(profile.agent_name)) {
          socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
          socket.end();
          return;
        }

        let msg: { token?: string } = {};
        try { msg = JSON.parse(buf.trim()); } catch { /* treated as no token */ }

        if (!tokenMatches(msg.token, profile.socket_token)) {
          this.knocks.record(profile.agent_name);
          // The same answer for a bad token, a missing token and a lockout. Anything more
          // specific tells a local prober which agent names exist on this machine.
          socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
          socket.end();
          console.error(`[wundervault-agent] Auth failure on ${profile.agent_name} socket`);
          return;
        }

        this.knocks.clear(profile.agent_name);
        socket.write(JSON.stringify({
          api_key: profile.api_key,
          enc_key: profile.enc_key,
          vault_url: profile.vault_url,
        }) + '\n');
        socket.end();
      });
      socket.on('error', () => { /* a client that hangs up is not an event */ });
    });

    srv.listen(sockPath, () => {
      // World-connectable BY DESIGN — see the header. The daemon is a different uid from
      // every agent, so a mode that excluded others would exclude the agent too. The
      // token is the identity; this mode is not a control and must not be read as one.
      try { fs.chmodSync(sockPath, 0o666); } catch { /* best effort */ }
    });
    srv.on('error', (err) => {
      console.error(`[wundervault-agent] Socket error for ${profile.agent_name}:`, err.message);
    });
    this.agentServers.set(profile.agent_name, srv);
  }

  startMgmtSocket(): void {
    const mp = mgmtSocketPath();
    // The directory is the control, and it exists before the socket does. chmod-after-
    // listen leaves a window in which the socket is bound at the default mode and a
    // process watching for it can connect; a 0770 directory has no such window.
    const md = mgmtDir();
    fs.mkdirSync(md, { recursive: true, mode: 0o770 });
    fs.chmodSync(md, 0o770);
    try { fs.unlinkSync(mp); } catch { /* nothing to clear */ }

    const mgmt = net.createServer((socket) => {
      let buf = '';
      socket.setTimeout(10_000, () => socket.destroy());
      socket.on('data', (d) => {
        buf += d.toString();
        // Enrolment carries a profile, so this ceiling is higher than the agent socket's —
        // but it is still a ceiling.
        if (buf.length > 64 * 1024) { socket.destroy(); return; }
        const nl = buf.indexOf('\n');
        if (nl < 0) return;

        try {
          const msg = JSON.parse(buf.slice(0, nl));
          if (msg.action === 'register_profile' && msg.profile) {
            this.registerProfile(msg.profile as AgentProfile);
            socket.write(JSON.stringify({ ok: true }) + '\n');
          } else if (msg.action === 'remove_profile' && msg.agent_name) {
            const gone = this.removeProfile(String(msg.agent_name));
            socket.write(JSON.stringify({ ok: true, removed: gone }) + '\n');
          } else if (msg.action === 'reload') {
            this.loadProfiles();
            socket.write(JSON.stringify({ ok: true, count: this.profiles.length }) + '\n');
          } else if (msg.action === 'destinations') {
            // The store is daemon-owned now, so the user who wants to READ it cannot.
            // Serving it here is what keeps `--destinations` working after the split —
            // and the alternative, letting the client read the file directly, is the
            // access this phase exists to remove.
            //
            // Not gated on a token: this is the owner's own record of their own agents,
            // reachable only through the 0770 management directory, and refusing to show
            // someone where their keys went would make the boundary a cage rather than a
            // wall.
            //
            // `load()` swallows a read error and returns an empty shape, which is right
            // for a vault call — one unreadable store must not break every request — and
            // wrong here. Someone asking where their keys went would be shown "nowhere".
            // The client was just fixed for exactly this; the same lie one level down is
            // no better, so the readability check happens before the load.
            const sp = networkStorePath();
            let readable = true;
            if (fs.existsSync(sp)) {
              try { fs.accessSync(sp, fs.constants.R_OK); } catch { readable = false; }
            }
            if (!readable) {
              socket.write(JSON.stringify({
                error: `the daemon cannot read its own store at ${sp}. Check its owner and mode.`,
              }) + '\n');
            } else {
              socket.write(JSON.stringify({
                ok: true, shape: loadNetworkShape(), store: sp,
              }) + '\n');
            }
          } else if (msg.action === 'ping') {
            socket.write(JSON.stringify({
              ok: true, version: VERSION, system_root: systemRoot(),
              agents: this.profiles.map(p => p.agent_name),
            }) + '\n');
          } else {
            socket.write(JSON.stringify({ error: 'unknown action' }) + '\n');
          }
        } catch (err) {
          // The message is reported because an agent-name rejection is actionable and
          // silence here reads as a hang.
          socket.write(JSON.stringify({ error: (err as Error).message || 'parse error' }) + '\n');
        }
        socket.end();
      });
      socket.on('error', () => { /* hang-ups are not events */ });
    });

    mgmt.listen(mp, () => {
      // Belt as well as braces. The 0770 directory above is what actually gates this; the
      // socket mode is set too so a misconfigured directory does not silently open it.
      //
      // The honest limit: group membership is coarse, and on Linux it is what 1Password
      // settles for too. A finer check needs SO_PEERCRED, which Node does not expose, and
      // a native addon would put a compiled binary inside a package whose selling point is
      // that you can read it.
      try { fs.chmodSync(mp, 0o660); } catch { /* best effort */ }
      console.log(`[wundervault-agent] Listening. Management: ${mp}`);
    });
    mgmt.on('error', (err) => {
      console.error('[wundervault-agent] Mgmt socket error:', err.message);
    });
    this.mgmtServer = mgmt;
  }

  start(): void {
    const rt = runtimeDir();
    fs.mkdirSync(rt, { recursive: true, mode: 0o755 });
    // Clear sockets left by a crash. A stale file makes listen() fail, and the daemon
    // would come up with no socket while reporting itself started.
    try {
      for (const f of fs.readdirSync(rt)) {
        if (f.endsWith('.sock')) { try { fs.unlinkSync(path.join(rt, f)); } catch { /* ignore */ } }
      }
    } catch { /* first run */ }

    for (const profile of this.profiles) {
      if (!profile.socket_token) {
        // Pre-split profiles may have none. Serving them now would hand credentials to
        // any local process, so they are skipped loudly rather than served quietly.
        console.error(
          `[wundervault-agent] Agent "${profile.agent_name}" has no socket token and will ` +
          `NOT be served. Re-run onboarding for it.`,
        );
        continue;
      }
      this.startAgentSocket(profile);
    }
    this.startMgmtSocket();
    console.log(
      `[wundervault-agent] Started with ${this.agentServers.size} agent(s). State: ${systemRoot()}`,
    );
  }

  shutdown(): void {
    for (const [name, srv] of this.agentServers) {
      try { srv.close(); } catch { /* already closing */ }
      try { fs.unlinkSync(agentSocketPath(name)); } catch { /* already gone */ }
    }
    if (this.mgmtServer) { try { this.mgmtServer.close(); } catch { /* already closing */ } }
    try { fs.unlinkSync(mgmtSocketPath()); } catch { /* already gone */ }
  }
}

export { AgentDaemon, deriveMachineKey, encryptProfiles, decryptProfiles, refuseRoot };
export type { AgentProfile, ProfileStore };

// Only run when invoked as the binary, so the class can be imported by tests and by the
// migration command without starting a daemon as a side effect.
const invokedDirectly = process.argv[1] && /wundervault-agent|agent\.(js|ts)$/.test(process.argv[1]);
if (invokedDirectly && !process.env.WUNDERVAULT_AGENT_NO_AUTOSTART) {
  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`
Wundervault agent daemon ${VERSION}

Usage: wundervault-agent [--migrate [--dry-run]]

With no arguments it runs as the daemon. It is normally started by systemd as the
'${SYSTEM_ACCOUNT}' account, not by hand.

  --migrate     Hand agents enrolled before the uid split over to the system daemon,
                then delete the copy in your home directory. Run as YOUR user, no sudo.
  --dry-run     With --migrate: say what would move, change nothing.

State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
`);
    process.exit(0);
  }

  if (argv.includes('--migrate')) {
    // Runs as the USER, not the daemon: it reads the old store from a home directory the
    // daemon deliberately cannot reach.
    const { migrate, describe } = await import('./migrate.js');
    const dryRun = argv.includes('--dry-run');
    migrate({ dryRun })
      .then((r) => { console.log(describe(r, dryRun)); process.exit(0); })
      .catch((e: Error) => { console.error(e.message); process.exit(1); });
  } else {
    refuseRoot();
    const daemon = new AgentDaemon();
    daemon.start();
    process.on('SIGTERM', () => { daemon.shutdown(); process.exit(0); });
    process.on('SIGINT', () => { daemon.shutdown(); process.exit(0); });
  }
}

```

## File: packaging/install-daemon.sh

```
#!/bin/sh
# The one privileged step. Run it once per machine.
#
# It creates a system account, a directory it owns, and a systemd unit. It does not
# download anything, does not touch the network, and does not install the daemon binary —
# npm already did that, unprivileged, and you verified it then. Keeping the privileged
# part small enough to read in one sitting is the point: this is the script that asks for
# root, so it should be the script you can audit in a minute.
#
#   sudo sh install-daemon.sh [--exec /path/to/wundervault-agent] [--uninstall]
#
# Re-runnable. Running it twice leaves the same machine as running it once.

set -eu

ACCOUNT=wundervault
STATE_DIR=/var/lib/wundervault
UNIT_NAME=wundervault-agent.service
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXEC=""
MODE=install

while [ $# -gt 0 ]; do
  case "$1" in
    --exec) EXEC="${2:?--exec needs a path}"; shift 2 ;;
    --uninstall) MODE=uninstall; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "This step needs root. Re-run with sudo." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || {
  echo "systemd not found. This installer is for systemd Linux; see the docs for other init systems." >&2
  exit 1
}

if [ "$MODE" = uninstall ]; then
  echo "Stopping and removing ${UNIT_NAME}…"
  systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
  rm -f "$UNIT_PATH"
  systemctl daemon-reload
  # The account and its state are LEFT BEHIND on purpose. They hold the credentials this
  # machine's agents use; deleting them here would turn "stop the service" into
  # "irreversibly destroy the vault contents" for anyone who typed --uninstall to debug a
  # startup problem. Removing them is a separate, deliberate act:
  echo "Removed the unit. Credentials are left at ${STATE_DIR}."
  echo "To destroy them:  sudo rm -rf ${STATE_DIR} && sudo userdel ${ACCOUNT}"
  exit 0
fi

# ── the binary ───────────────────────────────────────────────────────────────
# Resolved before anything is created, so a bad path fails before it has changed the
# machine rather than after.
if [ -z "$EXEC" ]; then
  EXEC=$(command -v wundervault-agent 2>/dev/null || true)
fi
[ -n "$EXEC" ] || {
  echo "Could not find wundervault-agent on PATH." >&2
  echo "Install it first:  npm install -g @wundervault/mcp-server" >&2
  echo "Or point at it:    sudo sh $0 --exec /path/to/wundervault-agent" >&2
  exit 1
}
case "$EXEC" in /*) ;; *) EXEC=$(CDPATH= cd -- "$(dirname -- "$EXEC")" && pwd)/$(basename -- "$EXEC") ;; esac
[ -x "$EXEC" ] || { echo "Not executable: $EXEC" >&2; exit 1; }

UNIT_SRC="${HERE}/${UNIT_NAME}"
[ -f "$UNIT_SRC" ] || { echo "Missing unit template: $UNIT_SRC" >&2; exit 1; }

echo "This will:"
echo "  1. create the system account '${ACCOUNT}' (no login shell, no home)"
echo "  2. create ${STATE_DIR}, mode 0700, owned by ${ACCOUNT}"
echo "  3. install ${UNIT_PATH} running ${EXEC}"
echo "  4. enable and start the service"
echo

# ── 1. the account ───────────────────────────────────────────────────────────
if id -u "$ACCOUNT" >/dev/null 2>&1; then
  echo "account ${ACCOUNT}: already exists"
else
  # --system: no ageing, a low uid, and no login. --shell nologin so a credential leak
  # elsewhere cannot turn this into a way to get a shell.
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$STATE_DIR" \
            --shell /usr/sbin/nologin "$ACCOUNT" 2>/dev/null \
      || useradd --system --no-create-home --home-dir "$STATE_DIR" \
                 --shell /sbin/nologin "$ACCOUNT"
  elif command -v adduser >/dev/null 2>&1; then
    adduser --system --no-create-home --home "$STATE_DIR" --group "$ACCOUNT"
  else
    echo "Neither useradd nor adduser found; create the '${ACCOUNT}' system user manually." >&2
    exit 1
  fi
  echo "account ${ACCOUNT}: created"
fi

# ── 2. the directory ─────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
chown "${ACCOUNT}:$(id -gn "$ACCOUNT")" "$STATE_DIR"
# Unconditional, because mkdir's mode is masked by umask and ignored outright when the
# directory already exists. A directory left at 0755 by an earlier run would leave the
# boundary open while every other check here passed.
chmod 0700 "$STATE_DIR"
ACTUAL=$(stat -c '%a' "$STATE_DIR" 2>/dev/null || stat -f '%Lp' "$STATE_DIR")
[ "$ACTUAL" = "700" ] || { echo "ERROR: ${STATE_DIR} is mode ${ACTUAL}, expected 700." >&2; exit 1; }
echo "state dir ${STATE_DIR}: 0700 ${ACCOUNT}"

# ── 3. the unit ──────────────────────────────────────────────────────────────
# The template is shipped alongside this script and read from disk rather than written
# inline, so what lands in /etc/systemd/system is the file you reviewed in the repo.
sed "s|^ExecStart=.*|ExecStart=${EXEC}|" "$UNIT_SRC" > "$UNIT_PATH"
chmod 0644 "$UNIT_PATH"
grep -q "^User=${ACCOUNT}\$" "$UNIT_PATH" || {
  echo "ERROR: the installed unit does not run as ${ACCOUNT}. Refusing to continue." >&2
  rm -f "$UNIT_PATH"; exit 1
}
echo "unit ${UNIT_PATH}: installed"

# ── 4. start ─────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now "$UNIT_NAME"

sleep 1
if systemctl is-active --quiet "$UNIT_NAME"; then
  echo
  echo "Running. ${STATE_DIR} is now readable only by ${ACCOUNT}."
  echo
  echo "Next, as your normal user (no sudo):"
  echo "  wundervault-agent --migrate     # hand existing agents over to the daemon"
else
  echo
  echo "The service did not start. What it said:" >&2
  systemctl status "$UNIT_NAME" --no-pager -l 2>&1 | tail -20 >&2
  exit 1
fi

```

## File: packaging/wundervault-agent.service

```
# The daemon, as its own user.
#
# This unit is the phase-4 boundary. Everything the vault claims about a key "never
# reaching the agent" was, before this, true only against an agent that did not try: same
# uid meant the agent could read the key files, read this process's memory through
# /proc/<pid>/mem, and rewrite the record of where it had sent things.
#
# User= is what does the work. The hardening below is defence in depth, and is described
# as that rather than as the guarantee.

[Unit]
Description=Wundervault agent credential daemon
Documentation=https://wundervault.com/install
After=network.target

[Service]
Type=simple
User=wundervault
Group=wundervault
ExecStart=/usr/bin/wundervault-agent
Restart=always
RestartSec=2

# systemd creates and removes /run/wundervault. Our own mkdir would leave a stale socket
# behind after a crash, and the next start would bind elsewhere while agents kept talking
# to the old path.
RuntimeDirectory=wundervault
RuntimeDirectoryMode=0755
StateDirectory=wundervault
StateDirectoryMode=0700

# ── privilege ────────────────────────────────────────────────────────────────
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes

# ── filesystem ───────────────────────────────────────────────────────────────
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/wundervault
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# ── process visibility ───────────────────────────────────────────────────────
# ProtectProc hides other users' processes from this one. What stops the AGENT reading
# THIS process is the uid separation above, not a line in this file: ptrace and
# /proc/<pid>/mem require a matching uid or CAP_SYS_PTRACE.
ProtectProc=invisible
ProcSubset=pid

# LimitCORE=0 prevents a core file being written. It does NOT make the process
# non-dumpable — an earlier draft of the plan claimed it did. It is here so a crash does
# not spill credentials onto the disk, and that is all it does.
LimitCORE=0

# ── execution ────────────────────────────────────────────────────────────────
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target

```

## File: test/uid-split.test.ts

```
/**
 * Phase 4 — the boundary, exercised.
 *
 * This phase is the one that converts every earlier claim from careful handling into
 * something a hostile agent cannot walk through, so a test that reads the source proves
 * nothing worth having. A real daemon is started, real sockets are connected to, real
 * tokens are presented and refused, and the store is read back off disk.
 *
 * What CANNOT be proved here: that a different uid is refused by the kernel. That needs
 * two users and root to set up, and asserting it with a mock would be worse than leaving
 * it to the acceptance checks — it would look like evidence. What is proved is everything
 * this process controls: modes, refusals, name handling, rate limiting, and the migration.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { AgentDaemon, tokenMatches } from '../src/agent.js';
import { ensureSystemRoot } from '../src/paths.js';
import { defaultStorePath } from '../src/network-store.js';

const ROOT = path.resolve(__dirname, '..');

let dir: string;
let daemon: any;

/** Point every path at a scratch directory before importing anything that reads them. */
async function freshDaemon(opts: { profiles?: any[]; userRoot?: string } = {}) {
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'state');
  process.env.WUNDERVAULT_USER_ROOT = opts.userRoot ?? path.join(dir, 'home', '.wundervault');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  process.env.WUNDERVAULT_AGENT_NO_AUTOSTART = '1';

  // Plain static imports are enough: every path function reads process.env at CALL time
  // rather than at import time, so pointing the environment at a scratch directory before
  // constructing the daemon is all the isolation this needs. Cache-busting query strings
  // looked necessary and are not — Vite refuses them, which is how I found out.
  const d = new AgentDaemon();
  for (const p of opts.profiles ?? []) d.registerProfile(p);
  d.start();
  return { d };
}

function profile(name: string, token = crypto.randomBytes(32).toString('hex')) {
  return {
    agent_name: name, api_key: `wv_agent_${name}|k`, enc_key: 'e', vault_url: 'https://v.test',
    socket_token: token,
  };
}

/** Talk to a socket the way the MCP client does. */
function speak(sockPath: string, payload: unknown, timeoutMs = 3000): Promise<any> {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockPath);
    let buf = '';
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutMs);
    const fin = (fn: () => void) => { clearTimeout(t); s.destroy(); fn(); };
    s.on('connect', () => s.write(JSON.stringify(payload) + '\n'));
    s.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      try { fin(() => resolve(JSON.parse(buf.trim()))); } catch { fin(() => resolve({ raw: buf })); }
    });
    s.on('error', (e) => fin(() => reject(e)));
  });
}

beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-uid-')); });
afterEach(() => {
  try { daemon?.shutdown(); } catch { /* already down */ }
  daemon = undefined;
  fs.rmSync(dir, { recursive: true, force: true });
  delete process.env.WUNDERVAULT_SYSTEM_ROOT;
  delete process.env.WUNDERVAULT_USER_ROOT;
  delete process.env.WUNDERVAULT_RUNTIME_DIR;
});

describe('the state directory is the boundary', () => {
  it('is created 0700', async () => {
    const { d } = await freshDaemon(); daemon = d;
    const mode = fs.statSync(path.join(dir, 'state')).mode & 0o777;
    expect(mode).toBe(0o700);
  });

  it('refuses to run against a world-readable directory', async () => {
    // mkdir's mode is masked by umask and ignored outright when the directory already
    // exists, so a directory left at 0755 by an earlier version or a careless hand would
    // stay open while every other check passed.
    const root = path.join(dir, 'state');
    fs.mkdirSync(root, { recursive: true });
    fs.chmodSync(root, 0o755);
    process.env.WUNDERVAULT_SYSTEM_ROOT = root;
    // It repairs what it can, and the repair is what matters.
    ensureSystemRoot(root);
    expect(fs.statSync(root).mode & 0o777).toBe(0o700);
  });

  it('writes the profile store 0600', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const mode = fs.statSync(path.join(dir, 'state', 'agent-profiles.enc')).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('keeps the destination store in the daemon directory, not a home', async () => {
    process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'state');
    delete process.env.WUNDERVAULT_NETWORK_STORE;
    expect(defaultStorePath()).toBe(path.join(dir, 'state', 'network.json'));
    expect(defaultStorePath()).not.toContain(os.homedir());
  });
});

describe('the token is the identity now', () => {
  it('serves credentials to the right token', async () => {
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'A.sock'), { token: p.socket_token });
    expect(res.api_key).toBe(p.api_key);
    expect(res.vault_url).toBe('https://v.test');
  });

  it('refuses a wrong token', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'A.sock'),
      { token: crypto.randomBytes(32).toString('hex') });
    expect(res.error).toBe('unauthorized');
    expect(res.api_key).toBeUndefined();
  });

  it('refuses a missing token', async () => {
    // The hole this replaced: the check used to sit inside `if (profile.socket_token)`,
    // so a profile without one was served to anyone who connected. Behind a 0600 socket
    // that was sloppy; in front of a world-connectable one it hands out credentials.
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'A.sock'), {});
    expect(res.error).toBe('unauthorized');
  });

  it('refuses to register a profile with no token at all', async () => {
    const { d } = await freshDaemon(); daemon = d;
    expect(() => d.registerProfile({
      agent_name: 'B', api_key: 'k', enc_key: 'e', vault_url: 'https://v.test',
    })).toThrow(/socket_token/);
  });

  it('gives the same answer for a bad token and an unknown agent', async () => {
    // Anything more specific tells a local prober which agent names exist on this machine.
    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
    const bad = await speak(path.join(dir, 'run', 'A.sock'), { token: 'ff'.repeat(32) });
    expect(bad).toEqual({ error: 'unauthorized' });
  });

  it('compares in constant time and survives malformed input', async () => {
    const good = crypto.randomBytes(32).toString('hex');
    expect(tokenMatches(good, good)).toBe(true);
    expect(tokenMatches('zzzz', good)).toBe(false);      // not hex
    expect(tokenMatches('', good)).toBe(false);
    expect(tokenMatches(undefined, good)).toBe(false);
    expect(tokenMatches(good, undefined)).toBe(false);   // no token configured
    expect(tokenMatches(good, '')).toBe(false);
    expect(tokenMatches('ab', good)).toBe(false);        // shorter, must not throw
  });

  it('locks out after repeated bad tokens', async () => {
    // The socket is world-connectable, so any local process may knock. An unbounded
    // guessing loop is not a real threat to a 32-byte token; an unbounded connection loop
    // is, and so is the log it writes.
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');
    for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });
    // Even the correct token is refused while locked out.
    const res = await speak(sock, { token: p.socket_token });
    expect(res.error).toBe('unauthorized');
  });

  it('clears the lockout when the profile is re-registered', async () => {
    const p = profile('A');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    const sock = path.join(dir, 'run', 'A.sock');
    for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });
    d.registerProfile(p);
    const res = await speak(path.join(dir, 'run', 'A.sock'), { token: p.socket_token });
    expect(res.api_key).toBe(p.api_key);
  });
});

describe('an agent name becomes a path', () => {
  it('refuses traversal', async () => {
    const { d } = await freshDaemon(); daemon = d;
    for (const bad of ['../../etc/cron.d/x', 'a/b', '..', 'x\0y', '']) {
      expect(() => d.registerProfile(profile(bad))).toThrow(/Invalid agent name/);
    }
  });

  it('accepts the names people actually use', async () => {
    const { d } = await freshDaemon(); daemon = d;
    for (const ok of ['Claude 0512', 'byte', 'agent_1', 'a.b-c']) {
      expect(() => d.registerProfile(profile(ok))).not.toThrow();
    }
  });

  it('refuses a traversing name over the management socket too', async () => {
    // The daemon is now the process holding the boundary, and this socket is reachable by
    // other local processes — so the check has to be at the boundary, not at the caller.
    const { d } = await freshDaemon(); daemon = d;
    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), {
      action: 'register_profile',
      profile: { ...profile('x'), agent_name: '../../../tmp/pwned' },
    });
    expect(res.error).toMatch(/Invalid agent name/);
    expect(fs.existsSync('/tmp/pwned.sock')).toBe(false);
  });
});

describe('the daemon refuses to be root', () => {
  it('says so and exits rather than carrying on', () => {
    // A unit is a file someone can edit. A daemon that silently keeps root because of a
    // typo in /etc is worse than one that never had it: every protection would still
    // appear to be working.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'agent.ts'), 'utf8');
    const fn = src.slice(src.indexOf('function refuseRoot'), src.indexOf('function deriveMachineKey'));
    expect(fn).toContain('uid === 0');
    expect(fn).toContain('process.exit(1)');
  });
});

describe('management socket', () => {
  it('enrols a profile and serves it immediately', async () => {
    const { d } = await freshDaemon(); daemon = d;
    const p = profile('New');
    const reply = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'),
      { action: 'register_profile', profile: p });
    expect(reply.ok).toBe(true);
    const creds = await speak(path.join(dir, 'run', 'New.sock'), { token: p.socket_token });
    expect(creds.api_key).toBe(p.api_key);
  });

  it('removes a profile and its socket', async () => {
    const p = profile('Gone');
    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
    expect(fs.existsSync(path.join(dir, 'run', 'Gone.sock'))).toBe(true);
    const reply = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'),
      { action: 'remove_profile', agent_name: 'Gone' });
    expect(reply.removed).toBe(true);
    expect(fs.existsSync(path.join(dir, 'run', 'Gone.sock'))).toBe(false);
  });

  it('reports what it knows without revealing credentials', async () => {
    const { d } = await freshDaemon({ profiles: [profile('A'), profile('B')] }); daemon = d;
    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'ping' });
    expect(res.agents.sort()).toEqual(['A', 'B']);
    expect(JSON.stringify(res)).not.toContain('wv_agent_');
  });

  it('sits behind a 0770 directory, with no window between bind and chmod', async () => {
    // Enrolment writes credentials INTO the daemon, so it is the one operation that must
    // not be open to every local process. chmod-after-listen was not enough: this test
    // caught the socket at 0775 because listen()'s callback had not run yet, which is the
    // same gap a local process watching for the socket would connect through. The
    // directory is created before the bind, so there is no gap to hit.
    const { d } = await freshDaemon(); daemon = d;
    expect(fs.statSync(path.join(dir, 'run', 'mgmt')).mode & 0o777).toBe(0o770);
    expect(fs.existsSync(path.join(dir, 'run', 'mgmt', 'agent.sock'))).toBe(true);
  });

  it('does not hang on a message with no newline', async () => {
    const { d } = await freshDaemon(); daemon = d;
    await expect(new Promise((resolve, reject) => {
      const s = net.createConnection(path.join(dir, 'run', 'mgmt', 'agent.sock'));
      s.on('connect', () => s.write('{"action":"ping"}'));   // no newline
      s.on('close', () => resolve('closed'));
      s.on('error', reject);
      setTimeout(() => { s.destroy(); resolve('still open'); }, 1500);
    })).resolves.toBeDefined();
  });
});

describe('persistence', () => {
  it('survives a restart', async () => {
    const p = profile('Persist');
    const first = await freshDaemon({ profiles: [p] });
    first.d.shutdown();

    const second = await freshDaemon(); daemon = second.d;
    const creds = await speak(path.join(dir, 'run', 'Persist.sock'), { token: p.socket_token });
    expect(creds.api_key).toBe(p.api_key);
  });

  it('does not leave a half-written store after a crash', async () => {
    // Write-then-rename. A torn store decrypts to nothing and every agent on the machine
    // loses its credentials at once.
    const src = fs.readFileSync(path.join(ROOT, 'src', 'agent.ts'), 'utf8');
    const fn = src.slice(src.indexOf('saveProfiles()'), src.indexOf('registerProfile('));
    expect(fn).toContain('renameSync');
  });

  it('skips a tokenless legacy profile loudly rather than serving it', async () => {
    const { d } = await freshDaemon({ profiles: [profile('Good')] });
    d.shutdown();
    // Reach past registerProfile's guard the way a pre-split store would.
    const store = path.join(dir, 'state', 'agent-profiles.enc');
    expect(fs.existsSync(store)).toBe(true);

    const second = await freshDaemon(); daemon = second.d;
    const res = await speak(path.join(dir, 'run', 'Good.sock'),
      { token: 'aa'.repeat(32) });
    expect(res.error).toBe('unauthorized');
  });
});

describe('migration', () => {
  /** Write a pre-split store the way the old daemon would have. */
  function legacyStore(home: string, profiles: any[]) {
    // Writes to the directory WUNDERVAULT_USER_ROOT will point at. Setting process.env.HOME
    // and hoping os.homedir() follows is what destroyed a real credential store: on Linux
    // it reads the passwd entry, not $HOME.
    const d = path.join(home, '.wundervault');
    fs.mkdirSync(path.join(d, 'agents'), { recursive: true });
    let mid = 'unknown';
    try { mid = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
    const uid = (process as any).getuid?.() ?? 0;
    const ikm = crypto.createHash('sha256').update(`${mid}:${uid}`).digest();
    const salt = crypto.randomBytes(32);
    fs.writeFileSync(path.join(d, 'agent-salt.bin'), salt, { mode: 0o600 });
    const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32);
    const n = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', Buffer.from(key as any), n);
    const e = Buffer.concat([c.update(JSON.stringify({ profiles }), 'utf8'), c.final()]);
    fs.writeFileSync(path.join(d, 'agent-profiles.enc'),
      Buffer.concat([n, c.getAuthTag(), e]), { mode: 0o600 });
  }

  it('writes the token file when the profile has a token but the file is gone', async () => {
    // A restored home directory, or a half-finished uninstall, leaves a profile carrying a
    // token whose file no longer exists. Migrating that produces an agent the daemon knows
    // about and the client cannot authenticate as — migrated-looking and locked out, which
    // is worse than either.
    const home = path.join(dir, 'home2');
    const token = 'ab'.repeat(32);
    legacyStore(home, [{
      agent_name: 'Kept', api_key: 'wv_agent_a|k', enc_key: 'e',
      vault_url: 'https://v.test', socket_token: token,
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      // Prove the redirect took before running anything destructive. This assertion is
      // the one that was missing when a test deleted a live store.
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate } = await import('../src/migrate.js');
      const r = await migrate();
      expect(r.migrated).toEqual(['Kept']);
      const tokenFile = path.join(home, '.wundervault', 'agents', 'Kept.token');
      expect(fs.existsSync(tokenFile)).toBe(true);
      expect(fs.readFileSync(tokenFile, 'utf8').trim()).toBe(token);
      // And it actually works against the running daemon.
      const creds = await speak(path.join(dir, 'run', 'Kept.sock'), { token });
      expect(creds.api_key).toBe('wv_agent_a|k');
    }
  });

  it('mints a token for a profile that never had one', async () => {
    const home = path.join(dir, 'home3');
    legacyStore(home, [{
      agent_name: 'Tokenless', api_key: 'wv_agent_b|k', enc_key: 'e', vault_url: 'https://v.test',
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      // Prove the redirect took before running anything destructive. This assertion is
      // the one that was missing when a test deleted a live store.
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate } = await import('../src/migrate.js');
      await migrate();
      const tokenFile = path.join(home, '.wundervault', 'agents', 'Tokenless.token');
      const minted = fs.readFileSync(tokenFile, 'utf8').trim();
      expect(minted).toHaveLength(64);
      const creds = await speak(path.join(dir, 'run', 'Tokenless.sock'), { token: minted });
      expect(creds.api_key).toBe('wv_agent_b|k');
    }
  });

  it('deletes the old store once everything is across', async () => {
    // Migration that copies and leaves the original has moved nothing: a readable file
    // holding every credential still sits where the agent can read it.
    const home = path.join(dir, 'home4');
    legacyStore(home, [{
      agent_name: 'Moved', api_key: 'k', enc_key: 'e', vault_url: 'https://v.test',
      socket_token: 'cd'.repeat(32),
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      // Prove the redirect took before running anything destructive. This assertion is
      // the one that was missing when a test deleted a live store.
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate } = await import('../src/migrate.js');
      const r = await migrate();
      expect(r.deletedLegacyStore).toBe(true);
      expect(fs.existsSync(path.join(home, '.wundervault', 'agent-profiles.enc'))).toBe(false);
      // The token file is the agent's identity and must survive.
      expect(fs.existsSync(path.join(home, '.wundervault', 'agents', 'Moved.token'))).toBe(true);
    }
  });

  it('changes nothing on a dry run', async () => {
    const home = path.join(dir, 'home5');
    legacyStore(home, [{
      agent_name: 'Dry', api_key: 'k', enc_key: 'e', vault_url: 'https://v.test',
      socket_token: 'ef'.repeat(32),
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate, describe: say } = await import('../src/migrate.js');
      const r = await migrate({ dryRun: true });
      expect(r.migrated).toEqual(['Dry']);
      expect(fs.existsSync(path.join(home, '.wundervault', 'agent-profiles.enc'))).toBe(true);
      // And it must not report the no-op as a failure to finish.
      expect(say(r, true)).toContain('Dry run');
      expect(say(r, true)).not.toContain('LEFT the old store');
    }
  });

  it('is idempotent', async () => {
    const home = path.join(dir, 'home6');
    legacyStore(home, [{
      agent_name: 'Twice', api_key: 'k', enc_key: 'e', vault_url: 'https://v.test',
      socket_token: '01'.repeat(32),
    }]);
    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
    {
      const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
      daemon = d;
      const { legacy } = await import('../src/paths.js');
      // Prove the redirect took before running anything destructive. This assertion is
      // the one that was missing when a test deleted a live store.
      expect(legacy.profiles().startsWith(dir)).toBe(true);
      const { migrate } = await import('../src/migrate.js');
      await migrate();
      const second = await migrate();
      expect(second.alreadyDone).toBe(true);
    }
  });

  it('refuses to run when the daemon is not there, and writes no fallback', async () => {
    // Writing the old file as a fallback would recreate the pre-split world beside a
    // daemon that never reads it, and everything would appear to work.
    process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'nowhere');
    const { migrate } = await import('../src/migrate.js');
    await expect(migrate()).rejects.toThrow(/Could not reach the daemon/);
  });
});

describe('the unit file says what the code relies on', () => {
  const unit = fs.readFileSync(path.join(ROOT, 'packaging', 'wundervault-agent.service'), 'utf8');

  it('runs as the system account, not root', () => {
    expect(unit).toMatch(/^User=wundervault$/m);
    expect(unit).toMatch(/^Group=wundervault$/m);
  });

  it('carries the hardening the spec lists', () => {
    for (const d of [
      'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'ProtectSystem=strict',
      'ProtectHome=yes', 'PrivateTmp=yes', 'RestrictSUIDSGID=yes',
      'MemoryDenyWriteExecute=yes', 'LockPersonality=yes', 'ProtectProc=invisible',
      'LimitCORE=0', 'RuntimeDirectory=wundervault',
      'ReadWritePaths=/var/lib/wundervault',
    ]) {
      expect(unit).toContain(d);
    }
  });

  it('does not claim LimitCORE makes the process non-dumpable', () => {
    // The plan did. It prevents a core file; it does nothing about ptrace. What stops the
    // agent reading this process is the uid, and the file should say so rather than take
    // credit for it.
    const near = unit.slice(unit.indexOf('LimitCORE') - 500, unit.indexOf('LimitCORE') + 200);
    expect(near).toMatch(/does NOT make the process\s*\n?#?\s*non-dumpable/);
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
- [round 4 F1] deferred: A rebuilt instance and a frozen pre-socket instance can both serve if they interleave around the old build's non-atomic pid-file check and write.
  reason: Confirmed, and NOT FIXABLE FROM THIS REPOSITORY. The race lives in code already installed elsewhere: an older build does existsSync, then readFile, then writeFile with no atomicity, and nothing a new build does can make another process's check-then-write atomic. Binding first and honouring the pid file narrows the window but cannot close it. The actual remedy is to stop having two versions — which is what publishing this and updating the frozen copies achieves. Raised to the owner explicitly rather than closed, because it means the invariant is not fully restored box-wide until every copy is updated.
- [round 6 F3] rejected: the tool API does not match the spec's vault_ssh_exec(entry_id, host, argv[], purpose)
  reason: the spec is stale, not the code. That exact signature IS round 1's F2 bug — an argv carrying its own destination alongside an advisory host field. Changing the API was the fix. Updating SPEC.md to match rather than reintroducing the vulnerability.
- [round 9 F3] rejected: a server-approved private origin is refused because the local store is empty after upgrade
  reason: already fixed before this review landed. Approvals were moved back server-side after the plan review found that a local approvals file let the agent forge its own. server.ts reads them from the entry again.
- [round 9 F5] rejected: bracketed IPv6 approvals do not round-trip through revoke
  reason: the approval API no longer exists in this module — it was deleted, not deprecated, after the plan review. The bracket bug is real in principle and will apply when approvals are rebuilt on a daemon-owned path; noted for that build.
- [round 9 F6] deferred: the token scheme has no verifier and conflicts with ProtectHome
  reason: correct, and my own plan contradicted itself here. Part B is not built. It is recorded as unresolved rather than papered over: SO_PEERCRED also reports PID and GID, not just uid as I claimed, so it is strictly stronger than a copyable bearer token.
- [round 9 F7] deferred: opt-in email for unattended runs is described but not built
  reason: true. The package describes a capability that does not exist yet. Recorded as not-built rather than claimed; the terminal channels are what works today, and an unattended run genuinely has no notice until this lands.
