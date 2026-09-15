# Review package — round 15
generated 2026-09-15T21:10:22+00:00

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

ROUND 15 — changes made AFTER a live rehearsal on a real install. Rounds 11-14 reviewed the
design; this round reviews what a real two-uid install found, which the test suite could
not reach. Read round-13-triage.json and round-14-triage.json before re-raising anything.

THE REHEARSAL: a throwaway systemd container, two real accounts (root, `owner` uid 1001,
and the `wundervault` system account the installer creates), against a real local burnbox
on 127.0.0.1:8090. Ran the actual installer as root, created an agent through the real
create-agent endpoint, enrolled it, repaired it through the real repair endpoint, enrolled
again.

FIVE FAILURES FOUND AND FIXED — all five re-verified in the container:
1. `packaging/` was missing from package.json "files", so install-daemon.sh — which every
   message tells the user to run — was not in the published package at all. Added.
2. MemoryDenyWriteExecute=yes made the daemon die at startup with SIGTRAP: it forbids W+X
   memory and V8 compiles at runtime. It was in the spec's E2 hardening list, so the unit
   test asserting that list was enforcing the setting that broke the service. Reproduced
   with a unit running only `node -e console.log`. Removed from unit and spec; the test now
   asserts its ABSENCE and the unit carries a comment saying why.
3. `--destinations` as root on a fresh install said "you are root and still cannot read it,
   check the file's owner and mode" — for a file that simply did not exist yet, because the
   store is not created until the first vault call. Now distinguishes absent from forbidden
   by whether the daemon's DIRECTORY is readable, and returns an honest empty shape when
   the store is genuinely not there.
4. Reading the store needs root, so it runs under sudo — where os.homedir() is /root, so
   the page landed where the person who asked could not open it. userRoot() now honours
   SUDO_USER by reading /etc/passwd, but ONLY when actually running as uid 0.
5. Once it landed in the right home it was root-owned 0600 and still unopenable. writeViewer
   now chowns the file and its directory to the SUDO_USER.

WHAT THE REHEARSAL PROVED (two real uids, not assertions): owner cannot read or write
/var/lib/wundervault; /proc/<daemon-pid>/mem denied; daemon refuses to run as root; owner
reaches the mgmt socket with no group membership and no sudo; a setup link enrols end to
end and a replay is refused as already used; a wrong token is refused; repair PRESERVES the
agent's existing socket token; and an agent that stands up its own HTTP server on loopback
to mint a setup link is refused on the origin.

ALSO since round 14: the https requirement was restored ON TOP of the origin allowlist. The
allowlist had replaced the protocol check outright, which meant a configured origin could
have been plain http to a remote host — and the setup token is a bearer credential in the
URL path. Loopback stays exempt so a local rehearsal is possible.

WHAT I MOST WANT ATTACKED:
(a) The SUDO_USER handling in userRoot(). It parses /etc/passwd by hand and is gated on
    getuid()===0. Is there any way an agent influences it, or any way it picks the wrong
    home? Note userRoot() also backs agentTokenPath() and the `legacy` migration paths.
(b) giveBackToSudoUser() chowns a file and a DIRECTORY to a uid parsed from /etc/passwd.
    Symlink races, wrong-parse, a SUDO_USER that is not what it looks like.
(c) The absent-vs-forbidden logic in collectShape: is returning an empty shape when the
    store does not exist a lie in any case I have not thought of?
(d) Removing MemoryDenyWriteExecute — is any of the remaining hardening also incompatible
    with Node, such that the daemon works now but fails on another distro or kernel?
(e) Anything about shipping packaging/ in the npm package that is a bad idea.

TESTS: 387 passing, no skips.

WITHHELD: src/server.ts (67KB) and the burnbox repo — diffs/description only.

## Diff

```diff
diff --git a/package.json b/package.json
index dd241af..ddb22cd 100644
--- a/package.json
+++ b/package.json
@@ -6,7 +6,8 @@
   "files": [
     "dist",
     "README.md",
-    "README-AGENTS.md"
+    "README-AGENTS.md",
+    "packaging"
   ],
   "scripts": {
     "build": "tsc",
diff --git a/packaging/wundervault-agent.service b/packaging/wundervault-agent.service
index 68e2328..38ee0c4 100644
--- a/packaging/wundervault-agent.service
+++ b/packaging/wundervault-agent.service
@@ -60,7 +60,22 @@ ProcSubset=pid
 LimitCORE=0
 
 # ── execution ────────────────────────────────────────────────────────────────
-MemoryDenyWriteExecute=yes
+# MemoryDenyWriteExecute is NOT set, and must not be added back.
+#
+# It forbids memory that is both writable and executable, which is exactly what a JIT
+# needs. This daemon is Node, so V8 compiles at runtime: with the setting on, the process
+# dies during startup with SIGTRAP and "Fatal javascript OOM in MemoryChunk allocation
+# failed during deserialization" — before it runs a line of our code. Verified on a real
+# install, and separately with a unit that does nothing but `node -e console.log`, which
+# core-dumps the same way.
+#
+# It was in the spec's hardening list and in the unit for two commits, which meant the test
+# asserting the list was enforcing a setting that made the daemon unable to start. The only
+# reason nothing caught it is that no test had ever launched the service.
+#
+# The protection it offers is real but not available to us here; a runtime that compiles
+# cannot run under W^X enforcement. The uid split, not this, is what keeps the agent out of
+# this process.
 LockPersonality=yes
 RestrictRealtime=yes
 RestrictNamespaces=yes
diff --git a/src/enrol.ts b/src/enrol.ts
index 13100ea..078612d 100644
--- a/src/enrol.ts
+++ b/src/enrol.ts
@@ -91,6 +91,16 @@ export function parseSetupUrl(raw: string): ParsedLink {
   // So: exactly one origin, from the DAEMON's own environment, which systemd sets and no
   // agent controls. The test override lives there too and is therefore unreachable by a
   // caller — an agent cannot set the daemon's environment any more than it can set its uid.
+  // https everywhere except loopback, ON TOP of the allowlist. The allowlist replaced the
+  // old protocol check outright, which quietly meant a configured origin could be plain
+  // http to any host on the network — the token is a bearer credential in the URL path, so
+  // that hands it to anything on the wire. Loopback stays permitted because a local
+  // rehearsal against a development server is a real need and never leaves the machine.
+  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(u.hostname);
+  if (u.protocol !== 'https:' && !loopback) {
+    throw new Error(`A setup link must be https. Got ${u.protocol.replace(':', '')}.`);
+  }
+
   const allowed = allowedOrigins();
   if (!allowed.includes(u.origin)) {
     throw new Error(
diff --git a/src/log-viewer.ts b/src/log-viewer.ts
index 47bdaab..b70c13a 100644
--- a/src/log-viewer.ts
+++ b/src/log-viewer.ts
@@ -29,7 +29,7 @@
  * What it IS: one self-contained HTML file with the data already inside it, written
  * 0600 next to the store, which you open with your own browser and delete when done.
  */
-import { writeFileSync, mkdirSync, chmodSync, accessSync, constants } from 'node:fs';
+import { writeFileSync, readFileSync, mkdirSync, chmodSync, chownSync, accessSync, existsSync, constants } from 'node:fs';
 import * as net from 'node:net';
 import * as path from 'node:path';
 import { load, defaultStorePath, type NetworkShape } from './network-store.js';
@@ -268,9 +268,29 @@ export function writeViewer(storePath = defaultStorePath(), outPath?: string,
   mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
   writeFileSync(target, renderViewer(shape, storePath), { mode: 0o600 });
   try { chmodSync(target, 0o600); } catch { /* best effort */ }
+
+  // Reading the store requires root, so this normally runs under sudo — and a page written
+  // 0600 root:root in someone's home is one they cannot open. Handing it back to the user
+  // who asked is the difference between the feature working and appearing to.
+  giveBackToSudoUser(target);
+  giveBackToSudoUser(path.dirname(target));
   return target;
 }
 
+/** chown a path to the user who invoked sudo. A no-op when not running as root. */
+function giveBackToSudoUser(target: string): void {
+  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
+  const sudoUser = process.env.SUDO_USER;
+  if (uid !== 0 || !sudoUser || sudoUser === 'root') return;
+  try {
+    const entry = readFileSync('/etc/passwd', 'utf8')
+      .split('\n').find(l => l.startsWith(`${sudoUser}:`));
+    const parts = entry?.split(':');
+    if (!parts) return;
+    chownSync(target, Number(parts[2]), Number(parts[3]));
+  } catch { /* best effort: a readable page in the wrong ownership still beats no page */ }
+}
+
 
 /**
  * Get the destinations — by reading the file, as root.
@@ -299,6 +319,28 @@ export function writeViewer(storePath = defaultStorePath(), outPath?: string,
 export async function collectShape(
   storePath = defaultStorePath(),
 ): Promise<{ shape: NetworkShape; source: 'daemon' | 'file' }> {
+  // "Not there yet" and "not allowed" are different answers and were being given the same
+  // one. On a fresh install the store does not exist until the first vault call records a
+  // destination, and root was being told to go and check the file's owner and mode — for a
+  // file that was simply not there. The distinction is whether the daemon's DIRECTORY can
+  // be read: if it can, and the store is absent, then nothing has been recorded and saying
+  // so is the truth rather than an empty page pretending to be data.
+  const dir = path.dirname(storePath);
+  if (!existsSync(storePath)) {
+    let dirReadable = true;
+    try { accessSync(dir, constants.R_OK | constants.X_OK); } catch { dirReadable = false; }
+    if (dirReadable) {
+      return { shape: { version: 1, seen: [] }, source: 'file' };
+    }
+    throw new Error(
+      `Cannot read the destination log.\n` +
+      `  store: ${storePath}\n` +
+      `It belongs to the daemon's own account, which is what stops your agents\n` +
+      `reading where every other agent has sent its secrets.\n\n` +
+      `  sudo wundervault-agent --destinations\n`,
+    );
+  }
+
   try {
     accessSync(storePath, constants.R_OK);
   } catch {
diff --git a/src/paths.ts b/src/paths.ts
index 5bc1238..94dfd9f 100644
--- a/src/paths.ts
+++ b/src/paths.ts
@@ -45,9 +45,30 @@ export function systemRoot(): string {
   return process.env.WUNDERVAULT_SYSTEM_ROOT || DEFAULT_SYSTEM_ROOT;
 }
 
-/** The agent's own directory: its token, and its view of things. */
+/**
+ * The agent's own directory: its token, and its view of things.
+ *
+ * Under `sudo`, `os.homedir()` is /root — so `sudo wundervault-agent --destinations`, which
+ * is the ONLY supported way to read the destination log, wrote its page into root's home
+ * where the person who asked for it cannot open it. `SUDO_USER` is honoured so the output
+ * lands in the home of whoever invoked sudo.
+ *
+ * Only consulted when actually running as root: an agent cannot use it to redirect
+ * anything, because setting SUDO_USER without being root changes nothing here.
+ */
 export function userRoot(): string {
-  return process.env.WUNDERVAULT_USER_ROOT || path.join(os.homedir(), '.wundervault');
+  if (process.env.WUNDERVAULT_USER_ROOT) return process.env.WUNDERVAULT_USER_ROOT;
+  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
+  const sudoUser = process.env.SUDO_USER;
+  if (uid === 0 && sudoUser && sudoUser !== 'root') {
+    try {
+      const entry = fs.readFileSync('/etc/passwd', 'utf8')
+        .split('\n').find(l => l.startsWith(`${sudoUser}:`));
+      const dir = entry?.split(':')[5];
+      if (dir) return path.join(dir, '.wundervault');
+    } catch { /* fall through to root's own home */ }
+  }
+  return path.join(os.homedir(), '.wundervault');
 }
 
 /**
diff --git a/test/uid-split.test.ts b/test/uid-split.test.ts
index 7558fb1..b747d43 100644
--- a/test/uid-split.test.ts
+++ b/test/uid-split.test.ts
@@ -484,7 +484,7 @@ describe('the unit file says what the code relies on', () => {
     for (const d of [
       'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'ProtectSystem=strict',
       'ProtectHome=yes', 'PrivateTmp=yes', 'RestrictSUIDSGID=yes',
-      'MemoryDenyWriteExecute=yes', 'LockPersonality=yes', 'ProtectProc=invisible',
+      'LockPersonality=yes', 'ProtectProc=invisible',
       'LimitCORE=0', 'RuntimeDirectory=wundervault',
       'ReadWritePaths=/var/lib/wundervault',
     ]) {
@@ -492,6 +492,15 @@ describe('the unit file says what the code relies on', () => {
     }
   });
 
+  it('does NOT set MemoryDenyWriteExecute, which would stop the daemon booting', () => {
+    // This was in the hardening list, so this very test file was asserting a directive that
+    // made the service die at startup with SIGTRAP — V8 compiles at runtime and cannot run
+    // without writable-executable memory. Nothing caught it because no test had ever
+    // launched the unit. Asserting its ABSENCE is what stops it coming back.
+    expect(unit).not.toMatch(/^MemoryDenyWriteExecute=yes$/m);
+    expect(unit).toMatch(/MemoryDenyWriteExecute is NOT set/);
+  });
+
   it('does not claim LimitCORE makes the process non-dumpable', () => {
     // The plan did. It prevents a core file; it does nothing about ptrace. What stops the
     // agent reading this process is the uid, and the file should say so rather than take

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

/**
 * The agent's own directory: its token, and its view of things.
 *
 * Under `sudo`, `os.homedir()` is /root — so `sudo wundervault-agent --destinations`, which
 * is the ONLY supported way to read the destination log, wrote its page into root's home
 * where the person who asked for it cannot open it. `SUDO_USER` is honoured so the output
 * lands in the home of whoever invoked sudo.
 *
 * Only consulted when actually running as root: an agent cannot use it to redirect
 * anything, because setting SUDO_USER without being root changes nothing here.
 */
export function userRoot(): string {
  if (process.env.WUNDERVAULT_USER_ROOT) return process.env.WUNDERVAULT_USER_ROOT;
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  const sudoUser = process.env.SUDO_USER;
  if (uid === 0 && sudoUser && sudoUser !== 'root') {
    try {
      const entry = fs.readFileSync('/etc/passwd', 'utf8')
        .split('\n').find(l => l.startsWith(`${sudoUser}:`));
      const dir = entry?.split(':')[5];
      if (dir) return path.join(dir, '.wundervault');
    } catch { /* fall through to root's own home */ }
  }
  return path.join(os.homedir(), '.wundervault');
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
import { writeFileSync, readFileSync, mkdirSync, chmodSync, chownSync, accessSync, existsSync, constants } from 'node:fs';
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

  // Reading the store requires root, so this normally runs under sudo — and a page written
  // 0600 root:root in someone's home is one they cannot open. Handing it back to the user
  // who asked is the difference between the feature working and appearing to.
  giveBackToSudoUser(target);
  giveBackToSudoUser(path.dirname(target));
  return target;
}

/** chown a path to the user who invoked sudo. A no-op when not running as root. */
function giveBackToSudoUser(target: string): void {
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  const sudoUser = process.env.SUDO_USER;
  if (uid !== 0 || !sudoUser || sudoUser === 'root') return;
  try {
    const entry = readFileSync('/etc/passwd', 'utf8')
      .split('\n').find(l => l.startsWith(`${sudoUser}:`));
    const parts = entry?.split(':');
    if (!parts) return;
    chownSync(target, Number(parts[2]), Number(parts[3]));
  } catch { /* best effort: a readable page in the wrong ownership still beats no page */ }
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
  return { shape: load(storePath), source: 'file' };
}


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
# MemoryDenyWriteExecute is NOT set, and must not be added back.
#
# It forbids memory that is both writable and executable, which is exactly what a JIT
# needs. This daemon is Node, so V8 compiles at runtime: with the setting on, the process
# dies during startup with SIGTRAP and "Fatal javascript OOM in MemoryChunk allocation
# failed during deserialization" — before it runs a line of our code. Verified on a real
# install, and separately with a unit that does nothing but `node -e console.log`, which
# core-dumps the same way.
#
# It was in the spec's hardening list and in the unit for two commits, which meant the test
# asserting the list was enforcing a setting that made the daemon unable to start. The only
# reason nothing caught it is that no test had ever launched the service.
#
# The protection it offers is real but not available to us here; a runtime that compiles
# cannot run under W^X enforcement. The uid split, not this, is what keeps the agent out of
# this process.
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

# Resolve symlinks BEFORE the ProtectHome check. `npm install -g` into a user prefix
# leaves ~/.local/bin/wundervault-agent pointing at ~/.local/lib/node_modules/..., so a
# path that looks fine can still land the real file under /home.
REAL_EXEC=$(readlink -f "$EXEC" 2>/dev/null || echo "$EXEC")

# ProtectHome=yes makes /home, /root and /run/user empty FOR THIS SERVICE. An ExecStart
# under any of them does not fail at install time — it fails at start with 203/EXEC, after
# the account and the state directory already exist, and the message points at the binary
# rather than at the sandbox that hid it. Node resolves its package directory at runtime
# too, so a launcher outside /home whose library sits inside it fails the same way, one
# step later and even less legibly. Refuse both here, where the fix is still cheap.
for CANDIDATE in "$EXEC" "$REAL_EXEC"; do
  case "$CANDIDATE" in
    /home/*|/root/*|/run/user/*)
      echo "ERROR: $CANDIDATE is inside a home directory." >&2
      # A plain `a && b` list here would return non-zero whenever the symlink note does
      # not apply, and `set -e` would take that as a failure and exit before the
      # explanation below ever printed — leaving only "ERROR:" and no way forward.
      if [ "$CANDIDATE" = "$REAL_EXEC" ] && [ "$EXEC" != "$REAL_EXEC" ]; then
        echo "       (reached via the symlink $EXEC)" >&2
      fi
      cat >&2 <<EOM
The unit sets ProtectHome=yes, which makes /home invisible to the service, so this
would install cleanly and then fail to start with status=203/EXEC.

Install the package somewhere the service can see it:

  sudo npm install -g --prefix /usr/local @wundervault/mcp-server
  sudo sh $0 --exec /usr/local/bin/wundervault-agent

ProtectHome is not negotiable here: it is what stops the daemon reading the home
directories of the agents it holds credentials for.

And no, this cannot be solved by bind-mounting the path back in. A directory under your
home is WRITABLE by everything that runs as you, agents included — so the daemon would be
executing code its own agents can replace. That is a worse hole than the one this whole
step exists to close: it would hand over not just the credentials but the process that
guards them. The package has to live somewhere the agent cannot write.
EOM
      exit 1 ;;
  esac
done

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

## File: src/enrol.ts

```
/**
 * Enrolment, done by the daemon instead of by the agent's own process.
 *
 * This is the piece that lets the uid split mean anything. Before it, the management
 * socket accepted `register_profile` from anyone who could reach it — and since agents run
 * as the same user as the person who owns them, "anyone who could reach it" included every
 * agent on the machine. An agent could register a name with a token it chose and then
 * collect that agent's credentials from its own socket. The boundary held for files and
 * memory and leaked at the front door.
 *
 * The fix is not a tighter local permission. There isn't one: the kernel cannot tell the
 * owner's shell from an agent running as the owner, so any lock the owner can open, an
 * agent can open. What the owner has that an agent does not is something from OUTSIDE the
 * machine — a setup link, issued by the server, to a person logged into the website.
 *
 * So the setup link is the authorisation, and the daemon redeems it itself:
 *
 *   https://wundervault.com/setup/agent/<token>#<passphrase>
 *                                        ^path          ^fragment, never sent to a server
 *
 *   1. GET  /api/setup/agent/<token>   -> the encrypted blob
 *   2. PBKDF2(passphrase) -> AES-256-GCM -> api_key + encryption_key
 *   3. POST /api/setup/agent/<token>/burn
 *
 * The client hands over a URL and gets back a name. The credentials exist only inside the
 * daemon and the file it owns — they are never in the address space of the process that
 * asked, which is an improvement on the pre-split world too, where onboard.py held them in
 * plaintext as the user.
 *
 * The parameters below are fixed by what the server already does (see onboard.py, which
 * this deliberately mirrors rather than reinvents). They are not ours to choose.
 */
import crypto from 'node:crypto';

const DEFAULT_ORIGIN = 'https://wundervault.com';

/**
 * Where a setup link is allowed to come from.
 *
 * Read from the daemon's environment, which after the uid split is set by the unit file.
 * That is the point: the caller hands over a URL, but it does not get to say which server
 * is trusted. `WUNDERVAULT_SETUP_ORIGIN` exists for self-hosted installs and for tests,
 * and in both cases it is set by whoever starts the daemon, never by whoever calls it.
 */
export function allowedOrigins(): string[] {
  const configured = process.env.WUNDERVAULT_SETUP_ORIGIN;
  if (!configured) return [DEFAULT_ORIGIN];
  return configured.split(',').map(o => o.trim()).filter(Boolean);
}

const PBKDF2_SALT = 'wv-agent-setup-v1';
const PBKDF2_ROUNDS = 100_000;
const UA = 'WunderVault-Agent-Daemon/1.0';
/** A credential blob is a couple of hundred bytes. This is three orders of magnitude of slack. */
const MAX_RESPONSE_BYTES = 256 * 1024;

export interface EnrolledCredentials {
  agent_name: string;
  agent_id: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
}

interface ParsedLink { baseUrl: string; token: string; passphrase: string; }

/**
 * Pull the three parts out of a setup link.
 *
 * The passphrase lives in the URL fragment precisely because browsers never transmit it,
 * so the server stores a blob it cannot itself read. That property is worth preserving on
 * this side of the wire too: it is why the passphrase is never put in a query string, a
 * header, or a log line here.
 */
export function parseSetupUrl(raw: string): ParsedLink {
  let u: URL;
  try { u = new URL(String(raw ?? '').trim()); }
  catch { throw new Error('That does not look like a setup link. Paste the whole URL, including the # at the end.'); }

  // THE ORIGIN IS THE WHOLE SECURITY PROPERTY, so it is checked against an allowlist the
  // caller cannot influence.
  //
  // The first version of this accepted any https origin, plus http on loopback so a test
  // could run a real server. That defeated the entire design in one line: a malicious
  // agent could start its own listener on 127.0.0.1, serve a blob it had encrypted with a
  // passphrase it chose, and hand the daemon `http://127.0.0.1:9999/setup/agent/x#p`. The
  // daemon would decrypt it perfectly, believe it, and register whatever profile the agent
  // named — including overwriting a real one. The "setup link an agent cannot obtain"
  // becomes a setup link an agent can simply mint.
  //
  // So: exactly one origin, from the DAEMON's own environment, which systemd sets and no
  // agent controls. The test override lives there too and is therefore unreachable by a
  // caller — an agent cannot set the daemon's environment any more than it can set its uid.
  // https everywhere except loopback, ON TOP of the allowlist. The allowlist replaced the
  // old protocol check outright, which quietly meant a configured origin could be plain
  // http to any host on the network — the token is a bearer credential in the URL path, so
  // that hands it to anything on the wire. Loopback stays permitted because a local
  // rehearsal against a development server is a real need and never leaves the machine.
  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(u.hostname);
  if (u.protocol !== 'https:' && !loopback) {
    throw new Error(`A setup link must be https. Got ${u.protocol.replace(':', '')}.`);
  }

  const allowed = allowedOrigins();
  if (!allowed.includes(u.origin)) {
    throw new Error(
      `A setup link must come from ${allowed.join(' or ')}. Got ${u.origin}.\n` +
      `A link from anywhere else is not a Wundervault setup link, whatever it looks like.`,
    );
  }

  const m = u.pathname.match(/\/setup\/agent\/([^/]+)\/?$/);
  if (!m) throw new Error('That URL has no setup token in it. Copy the link from the dashboard again.');

  const passphrase = decodeURIComponent(u.hash.replace(/^#/, ''));
  if (!passphrase) {
    throw new Error(
      'That link is missing the part after the #. It is the only thing that can decrypt ' +
      'your credentials, and it is never sent to the server — so a link without it is ' +
      'useless. Copy the whole URL.',
    );
  }
  return { baseUrl: u.origin, token: decodeURIComponent(m[1]), passphrase };
}

async function httpJson(url: string, method: 'GET' | 'POST'): Promise<any> {
  // `redirect: 'error'` rather than the default 'follow'. The setup token is a bearer
  // credential sitting in the URL PATH, so a 302 would hand it to whatever host the
  // response named — and this runs inside the process that holds every agent's
  // credentials. There is no legitimate reason for the setup endpoints to redirect, so
  // refusing is free, and the failure is visible rather than silent.
  // Bounded on both axes. This runs inside the process holding every agent's credentials,
  // so a server that never answers must not park a request there for ever, and one that
  // answers for ever must not be read into memory without limit.
  const res = await fetch(url, {
    method,
    headers: { 'User-Agent': UA },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) {
    const known: Record<number, string> = {
      404: 'That setup link is not valid. Check you copied all of it.',
      410: 'That setup link has already been used, or it has expired. ' +
           'Repair the agent in the dashboard to get a fresh one — it keeps the agent\'s ' +
           'existing vault access.',
    };
    throw new Error(known[res.status] ?? `The server answered ${res.status} for the setup link.`);
  }
  // `includes('json')` was not a media-type test: it accepted `text/notjson` and rejected
  // `Application/JSON`, which is the same string with different case and perfectly valid.
  // Parse the type properly — drop parameters, lowercase, then match exactly or on the
  // structured `+json` suffix.
  const ctype = String(res.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
  if (ctype !== 'application/json' && !ctype.endsWith('+json')) {
    // A captive portal or a proxy answering 200 with an HTML login page would otherwise
    // reach JSON.parse and surface as a confusing syntax error.
    throw new Error(`The setup link did not return JSON (content-type: ${ctype || 'none'}).`);
  }

  // A response with no declared length, or an absurd one, is refused before it is read.
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_RESPONSE_BYTES) {
    throw new Error(`The setup endpoint returned ${declared} bytes; refusing to read it.`);
  }
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES) {
    throw new Error('The setup endpoint returned more data than a credential blob can be.');
  }
  return JSON.parse(text);
}

/**
 * Ask the server which agent a link belongs to, redeeming nothing.
 *
 * The GET endpoint deliberately does not burn the token — the server's own comment says so,
 * because a link may be previewed. That lets enrolment learn the agent's name BEFORE it
 * commits to anything, which is what removes the two-step dance this used to require: mint
 * a token, enrol, discover the name from the reply, then swap the token back. That dance
 * had a window where a dropped connection left an agent registered under a token the
 * caller had not saved, and no way to recover it.
 */
export async function peekAgentName(rawUrl: string): Promise<string> {
  const { baseUrl, token } = parseSetupUrl(rawUrl);
  const server = await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}`, 'GET');
  return String(server?.agent_name ?? '');
}

/**
 * Redeem a setup link.
 *
 * The burn is a separate call AFTER the credentials are decrypted, and that order matters:
 * burning first would mean a wrong passphrase or a network blip consumed a single-use link
 * and left the agent with nothing, forcing another trip to the dashboard. Burning last
 * means the only way to lose the link is to have already succeeded with it.
 */
export async function redeemSetupLink(
  rawUrl: string,
): Promise<{ creds: EnrolledCredentials; burn: () => Promise<boolean> }> {
  const { baseUrl, token, passphrase } = parseSetupUrl(rawUrl);

  const server = await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}`, 'GET');
  if (!server?.encrypted_blob) throw new Error('The server returned no credentials for that link.');

  // base64url -> base64, then pad. The server emits the URL-safe alphabet.
  let b64 = String(server.encrypted_blob).replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  const blob = Buffer.from(b64, 'base64');
  if (blob.length < 29) throw new Error('The credential blob is too short to be valid.');

  const key = crypto.pbkdf2Sync(passphrase, PBKDF2_SALT, PBKDF2_ROUNDS, 32, 'sha256');
  let plain: Buffer;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    // GCM in this format carries its tag at the END of the ciphertext, the way the Python
    // AESGCM.decrypt() on the other side expects to find it.
    const ct = blob.subarray(12, blob.length - 16);
    decipher.setAuthTag(blob.subarray(blob.length - 16));
    plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error(
      'Could not decrypt those credentials — the part of the link after the # is wrong, ' +
      'or the link was mangled in transit. Nothing has been changed and the link is unused.',
    );
  }

  const raw = JSON.parse(plain.toString('utf8'));
  const creds: EnrolledCredentials = {
    agent_name: server.agent_name ?? 'unknown',
    agent_id: server.agent_id,
    api_key: raw.api_key ?? raw.agent_vault_api_key ?? '',
    enc_key: raw.encryption_key ?? raw.agent_encryption_key ?? '',
    vault_url: baseUrl,
  };
  if (!creds.api_key || !creds.enc_key) {
    throw new Error('The decrypted credentials are missing a key. Repair the agent and try again.');
  }

  // The burn is HANDED BACK rather than done here, so the caller can do it only after the
  // profile is actually stored. Burning at this point consumed the link on any later
  // failure — a missing socket token, a disk error — leaving the owner with a spent link
  // and no agent.
  //
  // It stays non-fatal once called: the credentials are already in hand and filed, and
  // failing an enrolment that has already succeeded because the "mark as used" call timed
  // out would be the worse outcome. A link that stays live for the rest of its fifteen
  // minutes is the smaller problem, and it is logged.
  const burn = async (): Promise<boolean> => {
    try {
      await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}/burn`, 'POST');
      return true;
    } catch {
      console.error(
        '[wundervault-agent] Enrolled, but could not mark the setup link as used. ' +
        'It stays valid until it expires — repair the agent again if that worries you.',
      );
      return false;
    }
  };

  return { creds, burn };
}

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
