# Review package — round 17
generated 2026-09-15T21:56:23+00:00

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
unprivileged — authorised by a setup link from the website, not by local privilege.
Reading the destination store is the one exception and does need sudo (D3).

## A. What actually changes

| | before | after |
|---|---|---|
| daemon uid | the user's | `wundervault` system account |
| key material | `~/.wundervault/agent-profiles.enc` | `/var/lib/wundervault/`, 0700 |
| destination store | `~/.wundervault/network.json` | `/var/lib/wundervault/network.json` |
| unit | `systemctl --user` | system unit |
| enrolment | the installer WRITES the profile store | the daemon redeems a server-issued setup link |
| agent's identity | a token in a file the agent owns | unchanged — and now load-bearing |

## B. Enrolment is authorised by the server, not by the machine

`onboard.py` used to derive the machine key and write `agent-profiles.enc` itself. After
the split that directory is not writable by the user, so enrolment had to become a request
to the daemon. The first version of that took a profile from whoever asked — and **that is
unfixable with local permissions**, because agents run as the machine's owner. The kernel
cannot separate the owner's shell from a process running as the owner, so any lock the
owner can open, an agent can open. An agent could register a name with a token it chose
and then read that agent's credentials from its own socket.

What the owner has that an agent does not is something from **outside the machine**: a
setup link, issued by the server to a person logged in to the website. So the daemon
redeems the link itself.

- B1. The only way a profile enters the daemon is `enrol`, carrying a setup link. There is
      no `register_profile`. Not guarded — absent.
- B2. The daemon performs the exchange: `GET /api/setup/agent/<token>`, PBKDF2-SHA256 over
      the fragment passphrase (salt `wv-agent-setup-v1`, 100,000 rounds), AES-256-GCM, then
      `POST .../burn`. The credentials never enter the calling process — an improvement on
      the pre-split world, where `onboard.py` held them in plaintext as the user.
- B2a. **The ORIGIN is the security property.** A link is accepted only from an origin in
      the daemon's own configuration (`WUNDERVAULT_SETUP_ORIGIN`, default
      `https://wundervault.com`), set by the unit file and not by the caller. Accepting any
      https origin — or http on loopback, for the convenience of a test — lets an agent run
      its own server, serve a blob it encrypted with a passphrase it chose, and mint the one
      credential this design assumes it cannot obtain. Every cryptographic check passes in
      that attack; only the origin refuses it.
- B2b. The link is read from **stdin, never argv**. `/proc/<pid>/cmdline` is world-readable,
      so a link on the command line is visible to every agent for as long as the command
      runs, and redemption is not instantaneous.
- B2c. Redirects are refused (`redirect: 'error'`) — the token is a bearer credential in the
      URL path — and a non-JSON content-type is refused rather than parsed.
- B3. Single-use and time-boxed are enforced server-side and are not re-derived here. The
      link is valid for 15 minutes.
- B4. The burn happens **after the profile is stored**, not merely after a successful
      decrypt. Anything that can fail in between — a missing socket token, a disk error —
      would otherwise spend a single-use link and produce no agent.
- B4a. One enrolment per connection. The handler re-parses on every `data` event, so
      without this a caller could send one valid line and then dribble bytes, re-running a
      100,000-round PBKDF2 and a fetch on each one, on the event loop every agent shares.
- B5. Migration is the same path. **Repair** in the dashboard rotates an agent's
      credentials and issues a fresh setup link while keeping its identity and every vault
      grant, so moving a pre-split agent across is: repair, then `--enrol`. No credential is
      carried, and no special case is carved for migration.
- B6. Removing an agent is authorised by that agent's own token. The socket is connectable
      by anyone, so an unauthenticated remove would let any local user delete another's
      agents.

## C. Peer identity: the token, and what it is not

Node exposes no `SO_PEERCRED`, and a native addon would put a compiled binary inside a
package whose whole pitch is that you can read it. So identity is the per-agent token in
`~/.wundervault/agents/<name>.token`, 0600, owned by the agent's uid.

- C1. The sockets are world-connectable, because the daemon is now a different uid and a
      0600 socket it owns could not be reached by the agent at all. **This includes the
      management socket.** It sat behind a 0770 directory until that was shown to lock the
      owner out too — the installer's own closing instruction, `--migrate` with no sudo,
      could not open the door it had just locked, and adding the owner to the group would
      have added all seven of their agents. Nothing behind that socket is protected by
      being hard to reach; each action carries its own proof.
- C2. Compared in constant time. A wrong token closes the connection without saying
      whether the agent name exists.
- C3. A wrong token costs the **failing caller** an exponential delay, and a valid token is
      always served. The first design locked out the agent NAME after ten failures and
      checked that before comparing the token, so any local process could take the real
      agent off the air for a minute at a time, indefinitely. A per-connection absolute
      deadline bounds resources instead; there is deliberately **no `maxConnections`**,
      since a ceiling is itself a way to exclude the legitimate agent.
- C4. **Honest limit:** `SO_PEERCRED` reports PID, UID *and* GID — so the token is slightly
      weaker than the kernel check, not equivalent: it proves possession of a file, and any
      process that can read that file presents the same identity. At uid granularity the
      two coincide, which is the granularity we claim.
- C5. One uid is one principal. Two agents under one uid cannot be told apart — by us or by
      the kernel. Seven agents currently run under one uid on the owner's machine, so this
      is the live case, not a corner. **Everything in B follows from this.**

## D. What the split actually buys, stated so it can be checked

- D1. The agent's uid cannot read `/var/lib/wundervault`. Enforced by mode 0700 on a
      directory owned by another user.
- D2. The agent cannot read the daemon's memory. Enforced by uid separation: `ptrace` and
      `/proc/<pid>/mem` require the same uid or `CAP_SYS_PTRACE`.
- D3. The destination store becomes an **integrity control**, not merely privacy. Until
      now the party being audited owned the evidence. It is therefore **not served over the
      management socket** — that socket is connectable by every agent, and one agent
      reading where the others sent secrets is the leak the store exists to expose.
      `--destinations` reads the file as root.
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
      `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`,
      `LockPersonality=yes`, `ProtectProc=invisible`, `LimitCORE=0`.
- E2a. **`MemoryDenyWriteExecute` must NOT be set.** It forbids writable-and-executable
      memory, which is what V8 needs to compile. With it on, the daemon dies at startup
      with SIGTRAP before reaching our code — verified on a real install and reproduced with
      a unit running nothing but `node -e console.log`. It was in this list for two commits,
      so the test that asserted the list was enforcing the setting that broke the service.
      No test had ever started it.
- E3. `ReadWritePaths=/var/lib/wundervault` and nothing else writable.
- E4. `RuntimeDirectory=wundervault` so the socket directory is created and cleaned up by
      systemd rather than by our code guessing at `/run`.
- E5. The daemon must refuse to start as root. A daemon that keeps root because the unit
      was edited is worse than one that never had it.

## F. Migration

- F1. Migration carries **no credentials**. The pre-split store is read only for the list
      of agent names, so the owner can be told which agents still need repairing. Repair
      invalidates the old credentials server-side, so the pre-split copy is worthless as
      soon as an agent is across.
- F2. The old `systemctl --user` unit is disabled and removed, or two daemons fight over
      one agent name and the loser's socket wins by being last to bind.
- F3. The user's `~/.wundervault/agents/<name>.token` STAYS, and migration must PRESERVE
      its value. Repair rotates the vault credentials; the socket token is a separate local
      identity, and replacing it would lock out any agent process that read it at startup —
      refused by the daemon that had just enrolled it, with 'unauthorized' as the only clue.
- F4. The old `agent-profiles.enc` is deleted once every agent is across — refused while
      any are pending, since an un-repaired agent's only credentials are in it.
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
5. A valid token is served even while another caller is flooding that socket with wrong
   ones, and the wrong ones are the only party that pays.
6. Enrolment with a valid setup link creates a usable profile, and the credentials never
   enter the calling process.
7. There is no way to enrol without a setup link. `register_profile` does not exist.
8. A used, expired or mistyped link is refused, and a wrong passphrase does not burn it.
9. The owner can reach the management socket with no group membership and no sudo.
10. `--migrate` names the agents still to be repaired; `--migrate --finish` refuses while
    any remain.
11. The destination store lives under `/var/lib/wundervault`, the agent's uid cannot write
    it, and it is not served over the management socket.
12. `--destinations` refuses rather than showing an empty page to a user who cannot read
    the store, and names sudo as the way through.
13. The unit file contains every hardening directive in E2.
14. Nothing in the codebase resolves daemon state through `os.homedir()` any more.
15. The installer refuses an `ExecStart` under a home directory, symlinks resolved.
16. Removing an agent requires that agent's token.
17. A setup link from any origin but the configured one is refused, including a server the
    caller started on loopback.
18. The setup link never appears in `argv`.
19. A failure after redemption does not burn the link, and one connection cannot trigger
    more than one enrolment.
20. `--destinations` is dispatched by the binary every message names, and does not refuse
    to run as root.
21. Enrolment preserves an agent's existing socket token, so a running agent is not locked
    out by the move.
22. No instruction anywhere tells a user to pass the setup link as an argument.
23. A failed burn is reported to the caller rather than reported as success.
24. A management connection cannot be held open indefinitely by a slow sender.

## Out of scope

- macOS (phase 4b) and Windows (phase 4c).
- The key-hierarchy migration (phase 5). This phase moves ciphertext; it does not re-wrap
  it.
- Server-side enforcement of `entry_mode` (phase 6), which needs the daemon to hold an
  identity of its own.


## What was built this round, and how it was tested

ROUND 17 — three changes since round 16, all found by the owner asking questions rather than
by review. Read round-15-triage.json and round-16-triage.json; do not re-raise deferred items.

1. PLATFORM GATE (the serious one). Phase 4 is Linux-only by spec, but for three commits
   "out of scope" meant BROKEN: the daemon constructor calls ensureSystemRoot() with no
   platform check, so on macOS it did mkdir /var/lib/wundervault as a normal user and died
   with EACCES where it previously used ~/.wundervault. On Windows the same path resolves to
   C:\var\lib\wundervault, the mkdir SUCCEEDS, and it then tries to bind unix domain sockets
   there. Now: SPLIT_AVAILABLE = process.platform === 'linux'; off Linux systemRoot() and
   runtimeDir() return the user's own directory, agentSocketPath/mgmtDir use the pre-split
   layout, ensureSystemRoot skips the mode assertion, the daemon prints that it holds no
   boundary on this platform, and install-daemon.sh refuses on non-Linux.

2. EPHEMERAL DESTINATION VIEWER. The store is protected but the rendered page was a full copy
   of it, 0600 in the owner's home — and agents run as the owner, so they can read it. The
   page is now written, opened via xdg-open/open/start, and shredded on exit, SIGINT, SIGTERM,
   SIGHUP or a 10-minute timeout. `--keep` opts out and says what keeping it means. Verified:
   killing the command with `timeout` still removed the page.

3. OS SELECTOR in the dashboard onboarding panel (burnbox repo, JS + CSS — NOT INCLUDED here,
   described only). Linux instructions are four steps including the sudo install and
   `--enrol`; macOS/Windows are two steps plus a paragraph stating the daemon runs as the
   same user and there is no boundary yet. Windows gets curl.exe/python/%TEMP%.

WHAT I MOST WANT ATTACKED:
(a) The platform gate. Is SPLIT_AVAILABLE consulted everywhere it must be? Look for any
    remaining assumption of /run, /var/lib, systemd, or a second uid that is now reachable
    on macOS. Note agent.ts is sent as an EXTRACT, so say if you need more of it.
(b) The ephemeral viewer's cleanup. process.on('exit') plus signal handlers plus a timer —
    what path leaves the file behind? SIGKILL obviously; anything else? Is opening the file
    and then deleting it racy against a browser that has not finished reading it?
(c) openInBrowser uses execFileSync with a 5s timeout and stdio ignore. On a desktop Linux
    box xdg-open can block. Is a synchronous call here a mistake?
(d) shredViewer overwrites then unlinks. Is the overwrite worth doing, or is it theatre
    that might mislead someone into thinking the bytes are unrecoverable?
(e) Does the non-Linux path now create any NEW risk, e.g. by reusing pre-split paths while
    the rest of the code assumes post-split semantics?

TESTS: 398 passing, no skips. All Linux behaviour re-verified on a real container install
(two uids, real systemd, real server): boundary holds, enrol works, repair preserves the
token, the rogue-origin attack and the symlink escalation are both refused.

WITHHELD: src/agent.ts is 40KB and sent as a marked EXTRACT of the --destinations dispatch
and the platform announcement only. src/server.ts and the burnbox repo are not included.

## Diff

```diff
diff --git a/packaging/install-daemon.sh b/packaging/install-daemon.sh
index 5ad6c09..96ca2ec 100644
--- a/packaging/install-daemon.sh
+++ b/packaging/install-daemon.sh
@@ -31,6 +31,13 @@ while [ $# -gt 0 ]; do
 done
 
 [ "$(id -u)" = "0" ] || { echo "This step needs root. Re-run with sudo." >&2; exit 1; }
+case "$(uname -s)" in
+  Linux) ;;
+  *)
+    echo "This installer is for Linux. The uid split is not available on $(uname -s) yet —" >&2
+    echo "the daemon there runs as you, with the pre-split threat model. Nothing to install." >&2
+    exit 1 ;;
+esac
 command -v systemctl >/dev/null 2>&1 || {
   echo "systemd not found. This installer is for systemd Linux; see the docs for other init systems." >&2
   exit 1
diff --git a/src/agent.ts b/src/agent.ts
index c631116..30ee84d 100644
--- a/src/agent.ts
+++ b/src/agent.ts
@@ -37,6 +37,7 @@ import { redeemSetupLink, peekAgentName } from './enrol.js';
 import {
   systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
   runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
+  splitAvailable,
 } from './paths.js';
 import { load as loadNetworkShape } from './network-store.js';
 
@@ -60,6 +61,27 @@ interface ProfileStore {
  * every protection below would still appear to be working. Failing here makes the mistake
  * loud at the only moment anyone is watching.
  */
+/**
+ * Say which world this daemon is actually running in.
+ *
+ * On Linux after the install it holds a real boundary: a different uid, a directory the
+ * agent cannot open, memory the agent cannot read. Everywhere else it is the same uid as
+ * the agents it serves, which is careful handling and nothing more. Printing that at
+ * startup is the difference between a limitation and a false claim — the release notes say
+ * "the key never reaches the agent", and on macOS today that is true only of an agent that
+ * does not try.
+ */
+function announceBoundary(): void {
+  if (splitAvailable()) return;
+  console.error(
+    `[wundervault-agent] Running on ${process.platform}, where the uid split is not yet\n` +
+    `[wundervault-agent] available. State is in your own directory and this daemon runs as\n` +
+    `[wundervault-agent] YOU — so its key material and memory are readable by anything you\n` +
+    `[wundervault-agent] run, including your agents. That is the pre-split threat model.\n` +
+    `[wundervault-agent] The boundary is Linux-only for now.`,
+  );
+}
+
 function refuseRoot(): void {
   const uid = (process as unknown as { getuid?: () => number }).getuid?.();
   if (uid === 0) {
@@ -665,8 +687,10 @@ With no arguments it runs as the daemon. It is normally started by systemd as th
                 credentials never pass through this process.
   --migrate     Show which pre-split agents still need moving across, and how.
   --finish      With --migrate: delete the pre-split store, once every agent is across.
-  --destinations  Write the page showing where your agents have sent secrets.
-                Needs sudo: the record belongs to the daemon so your agents cannot read it.
+  --destinations  Show where your agents have sent secrets. Needs sudo: the record
+                belongs to the daemon so your agents cannot read it. The page is opened
+                and then DELETED, because it is a copy your agents could otherwise read.
+  --keep        With --destinations: leave the page on disk instead.
 
 State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
 `);
@@ -682,8 +706,8 @@ State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
     // refuseRoot is deliberately NOT called on this path: reading the store is the one
     // thing that requires being root, because the file belongs to the daemon's account and
     // that is what stops the agents reading it.
-    const { writeViewer, collectShape, resolveSudoUser, dropToSudoUser } =
-      await import('./log-viewer.js');
+    const { writeViewer, collectShape, resolveSudoUser, dropToSudoUser,
+            shredViewer, openInBrowser } = await import('./log-viewer.js');
     const { defaultStorePath } = await import('./network-store.js');
     const pathMod = await import('node:path');
     const store = defaultStorePath();
@@ -709,12 +733,42 @@ State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
         }
         const out = writeViewer(store, target, shape);
         const calls = shape.seen.reduce((n: number, x: { count: number }) => n + x.count, 0);
+        const keep = argv.includes('--keep');
+
         console.log(
           `\nDestination log — ${shape.seen.length} destination(s), ${calls} call(s)\n` +
-          `  store:  ${store}\n  viewer: ${out}\n\n` +
-          `Open that file in your browser. It contains the data already, loads nothing, and\n` +
-          `is blocked by its own content-security policy from making any network request.\n`);
-        process.exit(0);
+          `  store:  ${store}\n  viewer: ${out}\n`);
+
+        if (keep) {
+          // Deliberate, and said plainly. Someone may want the page to keep or to send.
+          console.log(
+            `Kept on disk at your request. It is a full copy of the record above, and your\n` +
+            `agents run as you — so anything you run can read it until you delete it.\n`);
+          process.exit(0);
+        }
+
+        // Removed on the way out however we leave: a clean exit, a ctrl-C, or the timeout.
+        // Leaving the copy behind is the thing being avoided, so it must not depend on the
+        // user choosing the tidy path.
+        let gone = false;
+        const cleanup = () => { if (!gone) { gone = true; shredViewer(out); } };
+        process.on('exit', cleanup);
+        for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
+          process.on(sig, () => { cleanup(); process.exit(0); });
+        }
+
+        const opened = openInBrowser(out);
+        console.log(opened
+          ? `Opened in your browser. The copy is removed when you close this command —\n` +
+            `press ctrl-C when you are done, or it clears itself in 10 minutes.\n` +
+            `(--keep leaves it on disk instead.)\n`
+          : `Could not open a browser. Open the file above, then press ctrl-C here to\n` +
+            `remove it. It clears itself in 10 minutes. (--keep leaves it on disk.)\n`);
+        console.log(
+          `It is deleted because it is a COPY of a record your agents cannot otherwise\n` +
+          `read: they run as you, so a file in your home is a file they can open.\n`);
+
+        setTimeout(() => { cleanup(); process.exit(0); }, 10 * 60 * 1000);
       })
       .catch((e: Error) => { console.error(e.message); process.exit(1); });
   } else if (argv.includes('--enrol')) {
@@ -777,6 +831,7 @@ State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
     }
   } else {
     refuseRoot();
+    announceBoundary();
     const daemon = new AgentDaemon();
     daemon.start();
     process.on('SIGTERM', () => { daemon.shutdown(); process.exit(0); });
diff --git a/src/log-viewer.ts b/src/log-viewer.ts
index 8ebf255..0251053 100644
--- a/src/log-viewer.ts
+++ b/src/log-viewer.ts
@@ -30,7 +30,8 @@
  * 0600 next to the store, which you open with your own browser and delete when done.
  */
 import { writeFileSync, readFileSync, mkdirSync, chmodSync, accessSync, existsSync,
-         openSync, closeSync, renameSync, unlinkSync, constants } from 'node:fs';
+         openSync, closeSync, renameSync, unlinkSync, statSync, constants } from 'node:fs';
+import { randomBytes } from 'node:crypto';
 import { execFileSync } from 'node:child_process';
 import * as net from 'node:net';
 import * as path from 'node:path';
@@ -291,6 +292,51 @@ export function writeViewer(storePath = defaultStorePath(), outPath?: string,
   return target;
 }
 
+/**
+ * Open the page, then destroy it.
+ *
+ * The store is protected; this page is a COPY of it, and it lands in a directory every
+ * agent can read — they run as the owner, so a 0600 file in the owner's home is a 0600
+ * file they can open. Protecting the vault and then leaving a snapshot beside it is a
+ * strange place to stop.
+ *
+ * So the copy is temporary: written, opened, and shredded when the viewer is done with it.
+ * The exposure goes from permanent to the length of time somebody is actually looking, and
+ * a browser has the file content in memory by then anyway, so nothing is lost by removing
+ * it from disk.
+ *
+ * It is NOT put in /tmp. That directory is world-traversable and shared with every other
+ * user on the machine; the owner's own directory, 0600, is a smaller audience than that
+ * even before the file disappears.
+ */
+export function shredViewer(target: string): void {
+  try {
+    if (!existsSync(target)) return;
+    const size = statSync(target).size;
+    // Overwrite before unlinking. Not a guarantee on a journalling or copy-on-write
+    // filesystem, and worth saying so rather than implying the bytes are gone.
+    if (size > 0) writeFileSync(target, randomBytes(size));
+    unlinkSync(target);
+  } catch { /* best effort: a leftover page is the thing we were avoiding, not a crash */ }
+}
+
+/**
+ * Hand the page to a browser without waiting on one.
+ *
+ * `xdg-open` returns as soon as it has handed off, so it cannot tell us when the reader is
+ * finished — which is why the caller waits on a signal or a timeout rather than on this.
+ * Failure is not fatal: on a headless box there is no opener, and printing the path is a
+ * perfectly good outcome.
+ */
+export function openInBrowser(target: string): boolean {
+  const opener = process.platform === 'darwin' ? 'open'
+    : process.platform === 'win32' ? 'start' : 'xdg-open';
+  try {
+    execFileSync(opener, [target], { stdio: 'ignore', timeout: 5_000 });
+    return true;
+  } catch { return false; }
+}
+
 /**
  * Who invoked sudo, resolved through NSS rather than by reading /etc/passwd.
  *
diff --git a/src/paths.ts b/src/paths.ts
index 2714b67..f381609 100644
--- a/src/paths.ts
+++ b/src/paths.ts
@@ -41,8 +41,33 @@ export const SYSTEM_ACCOUNT = 'wundervault';
  * cannot move the daemon's state by exporting a variable, because it does not control the
  * daemon's environment.
  */
+/**
+ * Is the uid split actually available here?
+ *
+ * Phase 4 is Linux, and macOS (4b) and Windows (4c) are deliberately later. But OUT OF
+ * SCOPE HAS TO MEAN UNCHANGED, not broken — and for two commits it meant broken. The
+ * daemon's constructor calls ensureSystemRoot() unconditionally, so on macOS it tried to
+ * mkdir /var/lib/wundervault as a normal user and died with EACCES where it had previously
+ * used the home directory. On Windows it is quieter and worse: /var/lib/wundervault
+ * resolves to C:\var\lib\wundervault, the mkdir SUCCEEDS, and the daemon then tries to
+ * bind unix domain sockets there, which Windows does not have.
+ *
+ * Every non-Linux platform therefore keeps the pre-split layout exactly: state in the
+ * user's own directory, daemon as the user. That is the old threat model, and the code
+ * says so out loud rather than letting anyone infer a boundary that is not there.
+ */
+export const SPLIT_AVAILABLE = process.platform === 'linux';
+
+/** True where the daemon holds a real privilege boundary rather than merely tidy habits. */
+export function splitAvailable(): boolean {
+  return SPLIT_AVAILABLE;
+}
+
 export function systemRoot(): string {
-  return process.env.WUNDERVAULT_SYSTEM_ROOT || DEFAULT_SYSTEM_ROOT;
+  if (process.env.WUNDERVAULT_SYSTEM_ROOT) return process.env.WUNDERVAULT_SYSTEM_ROOT;
+  // Off Linux there is no system account and no unit: the daemon is the user, as before.
+  if (!SPLIT_AVAILABLE) return userRoot();
+  return DEFAULT_SYSTEM_ROOT;
 }
 
 /**
@@ -77,6 +102,8 @@ export function userRoot(): string {
 export function runtimeDir(): string {
   if (process.env.RUNTIME_DIRECTORY) return process.env.RUNTIME_DIRECTORY.split(':')[0];
   if (process.env.WUNDERVAULT_RUNTIME_DIR) return process.env.WUNDERVAULT_RUNTIME_DIR;
+  // /run is a Linux thing, and so is the systemd RuntimeDirectory that manages it.
+  if (!SPLIT_AVAILABLE) return userRoot();
   const run = `/run/${SYSTEM_ACCOUNT}`;
   try { if (fs.existsSync(run)) return run; } catch { /* fall through */ }
   return path.join(systemRoot(), 'run');
@@ -112,10 +139,13 @@ export const networkStorePath = () => path.join(systemRoot(), 'network.json');
  * per-agent ones, and every action behind it carries its own proof — a setup link to
  * enrol, the agent's own token to remove. Nothing is protected by being hard to reach.
  */
-export const mgmtDir = () => path.join(runtimeDir(), 'mgmt');
+export const mgmtDir = () =>
+  SPLIT_AVAILABLE ? path.join(runtimeDir(), 'mgmt') : runtimeDir();
 export const mgmtSocketPath = () => path.join(mgmtDir(), 'agent.sock');
 export const agentSocketPath = (name: string) =>
-  path.join(runtimeDir(), `${safeName(name)}.sock`);
+  SPLIT_AVAILABLE
+    ? path.join(runtimeDir(), `${safeName(name)}.sock`)
+    : path.join(runtimeDir(), 'agents', `${safeName(name)}.sock`);
 
 // ── agent-side paths ──────────────────────────────────────────────────────────
 
@@ -189,6 +219,11 @@ export function safeName(name: string): string {
 export function ensureSystemRoot(root = systemRoot()): void {
   fs.mkdirSync(root, { recursive: true, mode: 0o700 });
   fs.chmodSync(root, 0o700);
+  // The mode check is the BOUNDARY on Linux and merely hygiene elsewhere, where the
+  // directory belongs to the same user the agents run as. Refusing to start over it off
+  // Linux would block a daemon on a platform that never claimed the boundary — Windows in
+  // particular reports modes that do not mean what they say.
+  if (!SPLIT_AVAILABLE) return;
   const mode = fs.statSync(root).mode & 0o777;
   if (mode !== 0o700) {
     throw new Error(

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
/**
 * Is the uid split actually available here?
 *
 * Phase 4 is Linux, and macOS (4b) and Windows (4c) are deliberately later. But OUT OF
 * SCOPE HAS TO MEAN UNCHANGED, not broken — and for two commits it meant broken. The
 * daemon's constructor calls ensureSystemRoot() unconditionally, so on macOS it tried to
 * mkdir /var/lib/wundervault as a normal user and died with EACCES where it had previously
 * used the home directory. On Windows it is quieter and worse: /var/lib/wundervault
 * resolves to C:\var\lib\wundervault, the mkdir SUCCEEDS, and the daemon then tries to
 * bind unix domain sockets there, which Windows does not have.
 *
 * Every non-Linux platform therefore keeps the pre-split layout exactly: state in the
 * user's own directory, daemon as the user. That is the old threat model, and the code
 * says so out loud rather than letting anyone infer a boundary that is not there.
 */
export const SPLIT_AVAILABLE = process.platform === 'linux';

/** True where the daemon holds a real privilege boundary rather than merely tidy habits. */
export function splitAvailable(): boolean {
  return SPLIT_AVAILABLE;
}

export function systemRoot(): string {
  if (process.env.WUNDERVAULT_SYSTEM_ROOT) return process.env.WUNDERVAULT_SYSTEM_ROOT;
  // Off Linux there is no system account and no unit: the daemon is the user, as before.
  if (!SPLIT_AVAILABLE) return userRoot();
  return DEFAULT_SYSTEM_ROOT;
}

/**
 * The agent's own directory: its token, and its view of things.
 *
 * Deliberately does NOT consult `SUDO_USER`. An earlier version did, so that
 * `sudo wundervault-agent --destinations` would write its page into the invoking user's
 * home rather than root's — and that turned a root process into one that resolves a path
 * through a directory the agent controls. The result was a working root escalation: an
 * agent replaced `~/.wundervault/destinations.html` with a symlink to `/etc/cron.d/x`, root
 * followed it, and the chown handed the agent a file it could fill with a root cron job.
 *
 * The sudo case is handled where it belongs — by dropping privileges before writing
 * anything into a user's home (see `dropToSudoUser` in log-viewer.ts). A root process must
 * not follow paths that an unprivileged account can rearrange under it.
 */
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
  // /run is a Linux thing, and so is the systemd RuntimeDirectory that manages it.
  if (!SPLIT_AVAILABLE) return userRoot();
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
 * This directory was 0770, on the reasoning that enrolment writes credentials INTO the
 * daemon and so must not be reachable by every local process. The reasoning was right and
 * the mechanism could not deliver it. Agents run as the machine's owner, so a mode that
 * excludes agents excludes the owner, and the installer's own closing instruction —
 * `wundervault-agent --migrate`, no sudo — could not open the door it had just locked.
 * Adding the owner to the group would have added all seven of their agents with them.
 *
 * There is no local permission that separates the owner from a process running as the
 * owner. So the lock moved off the directory entirely and onto the thing an agent cannot
 * obtain: a setup link, issued by the server to someone logged in to the website,
 * single-use and valid for fifteen minutes. The daemon redeems it itself.
 *
 * The directory is therefore traversable and the socket connectable, exactly like the
 * per-agent ones, and every action behind it carries its own proof — a setup link to
 * enrol, the agent's own token to remove. Nothing is protected by being hard to reach.
 */
export const mgmtDir = () =>
  SPLIT_AVAILABLE ? path.join(runtimeDir(), 'mgmt') : runtimeDir();
export const mgmtSocketPath = () => path.join(mgmtDir(), 'agent.sock');
export const agentSocketPath = (name: string) =>
  SPLIT_AVAILABLE
    ? path.join(runtimeDir(), `${safeName(name)}.sock`)
    : path.join(runtimeDir(), 'agents', `${safeName(name)}.sock`);

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
  // The mode check is the BOUNDARY on Linux and merely hygiene elsewhere, where the
  // directory belongs to the same user the agents run as. Refusing to start over it off
  // Linux would block a daemon on a platform that never claimed the boundary — Windows in
  // particular reports modes that do not mean what they say.
  if (!SPLIT_AVAILABLE) return;
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

## File: src/log-viewer.ts

```
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
import { execFileSync } from 'node:child_process';
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
export function shredViewer(target: string): void {
  try {
    if (!existsSync(target)) return;
    const size = statSync(target).size;
    // Overwrite before unlinking. Not a guarantee on a journalling or copy-on-write
    // filesystem, and worth saying so rather than implying the bytes are gone.
    if (size > 0) writeFileSync(target, randomBytes(size));
    unlinkSync(target);
  } catch { /* best effort: a leftover page is the thing we were avoiding, not a crash */ }
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
    execFileSync(opener, [target], { stdio: 'ignore', timeout: 5_000 });
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
      `It belongs to the daemon's own account, which is what stops your agents\n` +
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
          `should belong to the wundervault account at 0700.\n`
        : `It belongs to the daemon's own account, which is what stops your agents\n` +
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


```

## File: /tmp/claude-1000/-home-zee/0131dbc2-3fef-4799-a27b-babe9c4f7002/scratchpad/agent-extract.txt

```
EXTRACT of src/agent.ts — two regions only. The rest of this 40KB file is unchanged
this round and was NOT sent. Flag findings that depend on code you were not shown.

--- lines 64-98 ---
64	/**
65	 * Say which world this daemon is actually running in.
66	 *
67	 * On Linux after the install it holds a real boundary: a different uid, a directory the
68	 * agent cannot open, memory the agent cannot read. Everywhere else it is the same uid as
69	 * the agents it serves, which is careful handling and nothing more. Printing that at
70	 * startup is the difference between a limitation and a false claim — the release notes say
71	 * "the key never reaches the agent", and on macOS today that is true only of an agent that
72	 * does not try.
73	 */
74	function announceBoundary(): void {
75	  if (splitAvailable()) return;
76	  console.error(
77	    `[wundervault-agent] Running on ${process.platform}, where the uid split is not yet\n` +
78	    `[wundervault-agent] available. State is in your own directory and this daemon runs as\n` +
79	    `[wundervault-agent] YOU — so its key material and memory are readable by anything you\n` +
80	    `[wundervault-agent] run, including your agents. That is the pre-split threat model.\n` +
81	    `[wundervault-agent] The boundary is Linux-only for now.`,
82	  );
83	}
84	
85	function refuseRoot(): void {
86	  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
87	  if (uid === 0) {
88	    console.error(
89	      `[wundervault-agent] Refusing to run as root.\n` +
90	      `  This daemon holds credentials and must run as its own unprivileged account.\n` +
91	      `  Expected User=${SYSTEM_ACCOUNT} in the unit file.\n` +
92	      `  If you installed by hand, re-run packaging/install-daemon.sh.`,
93	    );
94	    process.exit(1);
95	  }
96	}
97	
98	function deriveMachineKey(): Buffer {

--- lines 697-774 ---
697	    process.exit(0);
698	  }
699	
700	  if (argv.includes('--destinations')) {
701	    // Dispatched here as well as in the MCP binary, because every message that mentions
702	    // this names THIS command — `sudo wundervault-agent --destinations`. It was only wired
703	    // into wundervault-mcp, so the advice printed by the daemon and the log viewer led
704	    // straight into refuseRoot and a message about not running as root.
705	    //
706	    // refuseRoot is deliberately NOT called on this path: reading the store is the one
707	    // thing that requires being root, because the file belongs to the daemon's account and
708	    // that is what stops the agents reading it.
709	    const { writeViewer, collectShape, resolveSudoUser, dropToSudoUser,
710	            shredViewer, openInBrowser } = await import('./log-viewer.js');
711	    const { defaultStorePath } = await import('./network-store.js');
712	    const pathMod = await import('node:path');
713	    const store = defaultStorePath();
714	    // Read as root — that is the only reason this needs privilege — then give it up before
715	    // writing anything into a home directory. Root must not follow paths an agent can
716	    // rearrange under it; doing so was a working escalation to a root cron job.
717	    // resolveSudoUser throws when SUDO_USER is set but cannot be resolved — refusing to
718	    // carry on as root is correct, but it has to read as a message rather than a stack
719	    // trace, and it happens before the promise chain that handles everything else.
720	    let sudoUser: { uid: number; gid: number; home: string } | null = null;
721	    try {
722	      sudoUser = resolveSudoUser();
723	    } catch (e) {
724	      console.error((e as Error).message);
725	      process.exit(1);
726	    }
727	    collectShape(store)
728	      .then(({ shape }) => {
729	        let target: string | undefined;
730	        if (sudoUser) {
731	          target = pathMod.join(sudoUser.home, '.wundervault', 'destinations.html');
732	          dropToSudoUser(sudoUser);
733	        }
734	        const out = writeViewer(store, target, shape);
735	        const calls = shape.seen.reduce((n: number, x: { count: number }) => n + x.count, 0);
736	        const keep = argv.includes('--keep');
737	
738	        console.log(
739	          `\nDestination log — ${shape.seen.length} destination(s), ${calls} call(s)\n` +
740	          `  store:  ${store}\n  viewer: ${out}\n`);
741	
742	        if (keep) {
743	          // Deliberate, and said plainly. Someone may want the page to keep or to send.
744	          console.log(
745	            `Kept on disk at your request. It is a full copy of the record above, and your\n` +
746	            `agents run as you — so anything you run can read it until you delete it.\n`);
747	          process.exit(0);
748	        }
749	
750	        // Removed on the way out however we leave: a clean exit, a ctrl-C, or the timeout.
751	        // Leaving the copy behind is the thing being avoided, so it must not depend on the
752	        // user choosing the tidy path.
753	        let gone = false;
754	        const cleanup = () => { if (!gone) { gone = true; shredViewer(out); } };
755	        process.on('exit', cleanup);
756	        for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
757	          process.on(sig, () => { cleanup(); process.exit(0); });
758	        }
759	
760	        const opened = openInBrowser(out);
761	        console.log(opened
762	          ? `Opened in your browser. The copy is removed when you close this command —\n` +
763	            `press ctrl-C when you are done, or it clears itself in 10 minutes.\n` +
764	            `(--keep leaves it on disk instead.)\n`
765	          : `Could not open a browser. Open the file above, then press ctrl-C here to\n` +
766	            `remove it. It clears itself in 10 minutes. (--keep leaves it on disk.)\n`);
767	        console.log(
768	          `It is deleted because it is a COPY of a record your agents cannot otherwise\n` +
769	          `read: they run as you, so a file in your home is a file they can open.\n`);
770	
771	        setTimeout(() => { cleanup(); process.exit(0); }, 10 * 60 * 1000);
772	      })
773	      .catch((e: Error) => { console.error(e.message); process.exit(1); });
774	  } else if (argv.includes('--enrol')) {

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
- [round 11 F1] deferred: On a real install the owner cannot traverse the 0770 mgmt directory, so --migrate and --destinations fail
  reason: CONFIRMED, and proved the mechanism locally against /var/cache/cups (root:lp 0770) -> Permission denied. Deferred to the same change as F2, not because it is minor but because the obvious fix (usermod -aG wundervault) hands F2's re-key attack to every agent: agents run as the owner's uid, so any permission the owner has the agent has. Needs the owner's decision on the read side; see the question put to the user.
- [round 11 F2] deferred: register_profile accepts no setup token; B2/B3/check 7 unimplemented
  reason: CONFIRMED. registerProfile (agent.ts:200) overwrites an existing profile by name INCLUDING socket_token, so whoever reaches the mgmt socket can re-key an agent and read its credentials off the per-agent socket. Fix is an auth redesign spanning onboard.py in the burnbox repo; putting the shape to the owner before building it rather than guessing.
- [round 11 B2] deferred: No test runs the installed unit with two real uids under the real systemd sandbox
  reason: Correct, and it is the reason every one of these blockers survived 366 passing tests. A real two-uid install test is the next piece of work, but it needs the install to be performed on this machine first - which is the owner's call, not mine.
- [round 11 B5] deferred: Agent names and sockets are machine-global across multiple human users
  reason: Real, but out of scope for this spec: the product targets one human per machine today and the spec's C5 already states one uid is one principal. Noted for the owner.
- [round 12 F1] rejected: Telling the user to sudo npm install into /usr/local contradicts G1's single privileged step
  reason: REJECTED on the security merits. The reviewer's implied alternative - accept the home path and bind-mount it back past ProtectHome - is worse than the problem: a directory under the user's home is writable by everything running as that user, agents included, so the daemon would execute code its own agents can replace. That hands over the process guarding the credentials, not just the credentials. G1 scopes what the INSTALLER does; where the package itself lives is a separate, pre-existing choice. Kept the refusal and added the reasoning to the message so nobody 'fixes' it later.
- [round 14 B1] deferred: The link is out of argv but still in the enrolment client's memory, under the same uid as the agents
  reason: True and irreducible at this layer: the owner has to paste the link into SOME process running as them. What the fix bought is real - argv is world-readable to every process continuously, process memory needs ptrace of a short-lived process at the right moment. Worth stating in the docs rather than pretending it is closed.
- [round 14 B2] deferred: Profile-store writes are not fsynced before rename
  reason: Real durability gap - a crash between rename and writeback can leave a truncated store. Out of scope for this phase, which is about who can read the file, not whether it survives power loss. Noted for the owner.
- [round 14 B3] deferred: Concurrent enrolments for the same link are not serialised
  reason: Real but now much narrower: the server enforces single-use, and the local window is one round trip. The remaining case needs a burn failure AND a concurrent caller, and F4 now surfaces the burn failure. Not worth a lock in this phase.
- [round 15 B1] deferred: The generated destinations HTML is a full copy of the protected audit store, written into a directory the agents can read
  reason: Real and worth stating: the page is 0600 and owned by the human, but every agent runs as that human, so any agent can read it. The store itself stays protected; what leaks is a snapshot the owner deliberately asked for. Not silently acceptable - it belongs in the docs and possibly behind a --output flag defaulting somewhere else. Raising with the owner rather than deciding alone.
- [round 15 B2] deferred: The installer refuses a home-directory ExecStart but never checks the package tree is not writable by the agent uid
  reason: Real gap with the same shape as the /home rule: a globally-installed tree that happens to be group- or world-writable lets an agent replace the daemon's own code. Worth a check in the installer. Out of scope for this round; noted.
- [round 15 B3] deferred: The rehearsal covers one systemd and kernel version
  reason: True, and MemoryDenyWriteExecute is proof the risk is not theoretical - it was in the list for two commits. The remaining directives now run verified on Ubuntu 24.04 / systemd 255. Broader coverage needs more images than this session should spend; noted for the owner.
- [round 16 B1] deferred: The privilege drop discards the invoking user's supplementary groups rather than restoring their normal set
  reason: True. setgroups([gid]) is deliberately narrow - it drops root's groups, which is the safety property - but it is not the user's real group set either. For writing one file into their own home that is sufficient and arguably safer. Worth initgroups() if this path ever does more; noted rather than changed.
- [round 16 B2] deferred: A low-uid non-login wundervault account may belong to an unrelated service
  reason: Real, and not distinguishable from the outside - an existing nologin account named wundervault could be another vendor's. The installer now says which account it is adopting and its uid. A --account flag would be the proper answer; noted for the owner.
- [round 16 B3] deferred: getent is a synchronous unbounded NSS call on the viewer path
  reason: True but confined to the short-lived CLI, never the daemon. A hung NSS lookup delays one interactive command the user can ctrl-C. Not worth async plumbing here.
- [round 16 B4] deferred: Store validation checks version and that seen is an array, not the field types the generated JS consumes
  reason: Fair - a store with the right shape and wrong field types renders a broken page rather than an error. The page is generated from our own daemon's writes, so this is corruption-only, and the honest-vs-empty distinction that mattered is fixed. Deeper schema validation noted.
