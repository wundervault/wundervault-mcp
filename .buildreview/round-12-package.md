# Review package — round 12
generated 2026-09-15T19:26:45+00:00

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

ROUND 12 — fixes for round 11. Read .buildreview/round-11-triage.json first; do not
re-raise anything marked rejected or deferred without new evidence.

FIXED SINCE ROUND 11:
- F8 (install would have failed on this machine): install-daemon.sh now resolves symlinks
  with readlink -f and refuses an ExecStart under /home, /root or /run/user, because
  ProtectHome=yes hides those from the service and it would fail at start with 203/EXEC
  AFTER creating the account and state dir. Also fixed a `set -e` bug in my own first
  version of that guard: a bare `a && b && echo` list returned non-zero when the symlink
  note did not apply, so the script exited before printing the explanation.
- F6 + B3 (the DoS this phase introduced): the lockout is gone. It was keyed on the agent
  NAME and checked BEFORE the token was compared, so ten wrong guesses from any local
  process denied the real agent its credentials for 60s, repeatable forever. Now the token
  is compared first and a valid token is ALWAYS served; the cost is an exponential delay
  (50ms doubling to 2s, sliding 60s window) charged to the failing caller only. Added
  srv.maxConnections = 64 because delaying failures holds sockets open, which would
  otherwise have made the C3 "unbounded connection loop" worse rather than better.
- F3: migration no longer treats a name in the daemon's list as proof. daemonCopyMatches()
  presents the legacy socket_token on the agent's own socket and compares the credentials
  that come back against the plaintext being held. A mismatch is reported and the legacy
  store is NOT shredded.
- F4: migrate() now runs `systemctl --user disable --now wundervault-agent.service` BEFORE
  shredding, and verifies with is-active rather than trusting the exit code.
- F7: the token file and its directory are chmod'd unconditionally (0600/0700) whether or
  not they were written. Two mode bugs, not one: mkdir's mode is masked by umask and
  ignored on an existing dir, and writeFileSync's mode applies only on create.
- F5 (partial): `ping` no longer returns the agent roster; it is liveness plus a
  store_unreadable flag. A new `known_agents` action carries the names for migration. The
  world-listable /run/wundervault directory is accepted and documented as inherent to
  per-name sockets.
- B4: a profile store that fails to decrypt no longer leaves an empty in-memory list that
  the next save overwrites. loadProfiles records the failure, saveProfiles throws, and
  ping reports it.
- B1: the daemon-absent migration test pinned WUNDERVAULT_USER_ROOT into the scratch root
  (it was resolving to the REAL ~/.wundervault), plus a standing guard test asserting the
  legacy paths never resolve outside the scratch dir. Verified: every `source store:` line
  in a full test run is now under /tmp.

STILL OPEN, DELIBERATELY — the owner is being asked, do not spend findings on re-arguing
that they are broken, I know:
- F1: on a real install the owner cannot traverse the 0770 mgmt directory, so --migrate
  and --destinations fail. Proven locally against /var/cache/cups (root:lp 0770).
- F2: register_profile takes no setup token, and overwrites an existing profile by name
  INCLUDING its socket_token.
  These interlock: the obvious fix to F1 (put the owner in the wundervault group) hands
  F2's re-key attack to every agent, because agents run as the owner's uid. What I want
  from you on these two: is the "daemon exchanges the server-issued setup token itself,
  so credentials never pass through the enrolling process" shape correct, and what does
  it get WRONG that I have not seen? Migration cannot use a setup token (those profiles
  predate the split); I propose allowing an unauthenticated register only for a name the
  daemon does not already hold, while the legacy store still exists. Attack that.

TESTS: 376 passing, up from 366. New tests cover each fix above, including one that
asserts the real agent is still served while a guesser is hammering the socket — the old
test asserted the OPPOSITE and passed, which is how the DoS shipped.

STILL NOT DONE: the installer has never been run. No wundervault user, no
/var/lib/wundervault. Every test is same-uid with the split simulated by env vars, so
acceptance checks 1, 2 and 11 remain unproven by the suite.

WITHHELD (flag findings that depend on it): src/server.ts whole file (67KB) — diff only.
onboard.py lives in another repo and is not included.

## Diff

```diff
diff --git a/packaging/install-daemon.sh b/packaging/install-daemon.sh
index b1ae047..1c0fc4c 100644
--- a/packaging/install-daemon.sh
+++ b/packaging/install-daemon.sh
@@ -65,6 +65,43 @@ fi
 case "$EXEC" in /*) ;; *) EXEC=$(CDPATH= cd -- "$(dirname -- "$EXEC")" && pwd)/$(basename -- "$EXEC") ;; esac
 [ -x "$EXEC" ] || { echo "Not executable: $EXEC" >&2; exit 1; }
 
+# Resolve symlinks BEFORE the ProtectHome check. `npm install -g` into a user prefix
+# leaves ~/.local/bin/wundervault-agent pointing at ~/.local/lib/node_modules/..., so a
+# path that looks fine can still land the real file under /home.
+REAL_EXEC=$(readlink -f "$EXEC" 2>/dev/null || echo "$EXEC")
+
+# ProtectHome=yes makes /home, /root and /run/user empty FOR THIS SERVICE. An ExecStart
+# under any of them does not fail at install time — it fails at start with 203/EXEC, after
+# the account and the state directory already exist, and the message points at the binary
+# rather than at the sandbox that hid it. Node resolves its package directory at runtime
+# too, so a launcher outside /home whose library sits inside it fails the same way, one
+# step later and even less legibly. Refuse both here, where the fix is still cheap.
+for CANDIDATE in "$EXEC" "$REAL_EXEC"; do
+  case "$CANDIDATE" in
+    /home/*|/root/*|/run/user/*)
+      echo "ERROR: $CANDIDATE is inside a home directory." >&2
+      # A plain `a && b` list here would return non-zero whenever the symlink note does
+      # not apply, and `set -e` would take that as a failure and exit before the
+      # explanation below ever printed — leaving only "ERROR:" and no way forward.
+      if [ "$CANDIDATE" = "$REAL_EXEC" ] && [ "$EXEC" != "$REAL_EXEC" ]; then
+        echo "       (reached via the symlink $EXEC)" >&2
+      fi
+      cat >&2 <<EOM
+The unit sets ProtectHome=yes, which makes /home invisible to the service, so this
+would install cleanly and then fail to start with status=203/EXEC.
+
+Install the package somewhere the service can see it:
+
+  sudo npm install -g --prefix /usr/local @wundervault/mcp-server
+  sudo sh $0 --exec /usr/local/bin/wundervault-agent
+
+ProtectHome is not negotiable here: it is what stops the daemon reading the home
+directories of the agents it holds credentials for.
+EOM
+      exit 1 ;;
+  esac
+done
+
 UNIT_SRC="${HERE}/${UNIT_NAME}"
 [ -f "$UNIT_SRC" ] || { echo "Missing unit template: $UNIT_SRC" >&2; exit 1; }
 
diff --git a/src/agent.ts b/src/agent.ts
index bfc99b6..83310fe 100644
--- a/src/agent.ts
+++ b/src/agent.ts
@@ -130,14 +130,44 @@ export function tokenMatches(provided: string | undefined, expected: string | un
  * produce is its own denial of service. A short lockout costs a legitimate agent one
  * retry after a genuine misconfiguration.
  */
+/**
+ * Make guessing expensive without letting a guesser deny the real agent.
+ *
+ * The first shape of this was a lockout: ten bad tokens for an agent name and that name
+ * was refused for sixty seconds. Behind a 0600 socket that was defensible. It is not
+ * defensible now — this phase made the per-agent sockets world-connectable, because the
+ * daemon is a different uid and a 0600 socket it owns is one no agent could reach. So any
+ * local process could send ten wrong tokens and take the LEGITIMATE agent off the air,
+ * repeatedly, for as long as it liked. The mechanism meant to slow an attacker down had
+ * become the cheapest attack available, and this phase is what introduced it.
+ *
+ * The rule now: a correct token is ALWAYS served. Nothing an attacker sends can change
+ * what the holder of the real token gets back. The cost falls on the failing caller
+ * instead, as a delay that doubles per consecutive failure — which is what actually
+ * throttles guessing, since it is the attacker's own connection that has to wait.
+ *
+ * The delay is per agent name, and that is a deliberate, stated limit: a unix socket
+ * carries no address to attribute failures to, and Node exposes no SO_PEERCRED to
+ * identify the caller. So a persistent guesser does slow down a legitimate client that
+ * is ALSO failing — but a legitimate client that is failing has the wrong token, and
+ * telling it so a second later costs nothing.
+ */
 class Knocks {
   private fails = new Map<string, { n: number; until: number }>();
-  private readonly MAX = 10;
   private readonly WINDOW_MS = 60_000;
-
-  lockedOut(name: string): boolean {
+  // Overridable so the tests can exercise the growth curve without sitting through it.
+  // Production values are the defaults; nothing in the shipped path sets these.
+  private readonly BASE_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_BASE_MS) || 50;
+  private readonly MAX_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_MAX_MS) || 2_000;
+
+  /**
+   * How long to make a FAILING caller wait. Never consulted before a token is checked:
+   * a valid token must not be delayed or refused because somebody else guessed wrong.
+   */
+  penaltyMs(name: string): number {
     const f = this.fails.get(name);
-    return !!f && f.n >= this.MAX && Date.now() < f.until;
+    if (!f || Date.now() >= f.until) return 0;
+    return Math.min(this.BASE_DELAY_MS * 2 ** Math.min(f.n, 16), this.MAX_DELAY_MS);
   }
 
   record(name: string): void {
@@ -145,6 +175,9 @@ class Knocks {
     const f = this.fails.get(name);
     if (!f || now >= f.until) { this.fails.set(name, { n: 1, until: now + this.WINDOW_MS }); return; }
     f.n += 1;
+    // Sliding, not fixed: a guesser that keeps knocking keeps paying, rather than
+    // getting a clean slate sixty seconds after its first attempt.
+    f.until = now + this.WINDOW_MS;
   }
 
   clear(name: string): void { this.fails.delete(name); }
@@ -163,17 +196,52 @@ class AgentDaemon {
     this.loadProfiles();
   }
 
+  /**
+   * A store we could not read is NOT an empty store.
+   *
+   * This used to log the failure and carry on with `this.profiles` still `[]`. The daemon
+   * would come up serving nobody, which looks like a bad day — and then the first
+   * enrolment called saveProfiles(), which wrote a store containing ONLY that profile,
+   * over the ciphertext holding every other agent's credentials. A recoverable problem
+   * (a changed /etc/machine-id, a recreated wundervault account, a damaged file — all of
+   * which leave the plaintext retrievable) became permanent loss, silently.
+   *
+   * So a decrypt failure is now a refusal: the daemon will not serve and will not save
+   * until a person has looked at it. Refusing to start is a visible, reversible failure.
+   * Overwriting is neither.
+   */
+  private unreadableStore: string | null = null;
+
   loadProfiles(): void {
     const pp = profilesPath();
-    if (!fs.existsSync(pp)) return;
+    if (!fs.existsSync(pp)) { this.unreadableStore = null; return; }
     try {
       this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
+      this.unreadableStore = null;
     } catch (err) {
-      console.error('[wundervault-agent] Failed to decrypt profiles:', (err as Error).message);
+      this.unreadableStore = (err as Error).message;
+      this.profiles = [];
+      console.error(
+        `[wundervault-agent] Could not read the profile store at ${pp}: ${this.unreadableStore}\n` +
+        `[wundervault-agent] It is encrypted against this machine's id and the daemon's uid.\n` +
+        `[wundervault-agent] REFUSING to serve or to overwrite it. The credentials are still\n` +
+        `[wundervault-agent] in that file; starting fresh would destroy them. Restore the file,\n` +
+        `[wundervault-agent] or move it aside deliberately if you mean to start over.`,
+      );
     }
   }
 
+  /** True when the store exists but could not be read. Nothing may be written in this state. */
+  get storeUnreadable(): boolean { return this.unreadableStore !== null; }
+
   saveProfiles(): void {
+    if (this.unreadableStore) {
+      throw new Error(
+        `Refusing to write the profile store: it exists but could not be decrypted ` +
+        `(${this.unreadableStore}). Writing now would replace every credential in it ` +
+        `with only what is in memory.`,
+      );
+    }
     const pp = profilesPath();
     // Write-then-rename. A half-written store read after a crash decrypts to nothing and
     // every agent on the machine loses its credentials at once.
@@ -242,22 +310,31 @@ class AgentDaemon {
         if (buf.length > 4096) { socket.destroy(); return; }
         if (!buf.includes('\n')) return;
 
-        if (this.knocks.lockedOut(profile.agent_name)) {
-          socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
-          socket.end();
-          return;
-        }
-
         let msg: { token?: string } = {};
         try { msg = JSON.parse(buf.trim()); } catch { /* treated as no token */ }
 
+        // The token is checked FIRST, before any penalty is consulted. The previous order
+        // let a stranger's wrong guesses decide what the real agent got back.
         if (!tokenMatches(msg.token, profile.socket_token)) {
+          const wait = this.knocks.penaltyMs(profile.agent_name);
           this.knocks.record(profile.agent_name);
-          // The same answer for a bad token, a missing token and a lockout. Anything more
-          // specific tells a local prober which agent names exist on this machine.
-          socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
-          socket.end();
           console.error(`[wundervault-agent] Auth failure on ${profile.agent_name} socket`);
+          // The same answer for a bad token and a missing one. Anything more specific
+          // tells a local prober which agent names exist on this machine.
+          const refuse = () => {
+            try {
+              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
+              socket.end();
+            } catch { /* the prober hung up while waiting, which is fine */ }
+          };
+          if (wait > 0) {
+            const t = setTimeout(refuse, wait);
+            // Do not hold the event loop open on behalf of someone guessing tokens.
+            (t as unknown as { unref?: () => void }).unref?.();
+            socket.on('close', () => clearTimeout(t));
+          } else {
+            refuse();
+          }
           return;
         }
 
@@ -272,6 +349,13 @@ class AgentDaemon {
       socket.on('error', () => { /* a client that hangs up is not an event */ });
     });
 
+    // Delaying a failing caller keeps its connection open, so the guessing loop the delay
+    // is meant to discourage now costs US a socket for as long as it costs them. A ceiling
+    // turns that back around: past it the kernel refuses new connections outright, which is
+    // cheaper for the daemon than for the prober. This is the "unbounded connection loop"
+    // the spec's C3 actually worried about — the delay alone would have made it worse.
+    srv.maxConnections = 64;
+
     srv.listen(sockPath, () => {
       // World-connectable BY DESIGN — see the header. The daemon is a different uid from
       // every agent, so a mode that excluded others would exclude the agent too. The
@@ -347,8 +431,16 @@ class AgentDaemon {
               }) + '\n');
             }
           } else if (msg.action === 'ping') {
+            // Liveness only. This used to return every agent name on the machine, which
+            // is a roster of what holds credentials here, handed to anyone who could
+            // reach the socket. Migration is the only caller that needs the names, and it
+            // asks for them explicitly below.
+            socket.write(JSON.stringify({
+              ok: true, version: VERSION, store_unreadable: this.storeUnreadable,
+            }) + '\n');
+          } else if (msg.action === 'known_agents') {
             socket.write(JSON.stringify({
-              ok: true, version: VERSION, system_root: systemRoot(),
+              ok: true, system_root: systemRoot(),
               agents: this.profiles.map(p => p.agent_name),
             }) + '\n');
           } else {
diff --git a/src/migrate.ts b/src/migrate.ts
index 5a29fda..6710b04 100644
--- a/src/migrate.ts
+++ b/src/migrate.ts
@@ -17,7 +17,8 @@ import fs from 'node:fs';
 import net from 'node:net';
 import path from 'node:path';
 import crypto from 'node:crypto';
-import { legacy, mgmtSocketPath, agentTokenPath, safeName } from './paths.js';
+import { execFile } from 'node:child_process';
+import { legacy, mgmtSocketPath, agentSocketPath, agentTokenPath, safeName } from './paths.js';
 
 interface LegacyProfile {
   agent_name: string;
@@ -79,11 +80,73 @@ export interface MigrationResult {
   skipped: { name: string; why: string }[];
   deletedLegacyStore: boolean;
   alreadyDone: boolean;
+  oldUnitStopped: boolean;
+}
+
+/**
+ * Does the daemon's copy of this agent actually match the one we are about to destroy?
+ *
+ * A name appearing in the daemon's list is NOT proof of that. The daemon may hold a stale
+ * profile under the same name — from an abandoned enrolment, a restored backup, a machine
+ * that was set up twice — and treating the name as proof would count that agent as safely
+ * across and shred the only correct copy of its credentials.
+ *
+ * We cannot ask the daemon to show us what it holds; refusing to hand credentials back to
+ * a caller that has not proved it is the agent is the whole point of the phase. But we do
+ * not need it to: we have the agent's token from the legacy store, so we can present that
+ * on the agent's own socket exactly as the agent would, and compare what comes back.
+ * Nothing is trusted that has not been checked against the plaintext we are holding.
+ */
+async function daemonCopyMatches(p: LegacyProfile): Promise<boolean> {
+  if (!p.socket_token) return false;
+  try {
+    const got = await ask(
+      { token: p.socket_token },
+      agentSocketPath(safeName(p.agent_name)),
+      3_000,
+    );
+    return !!got
+      && got.api_key === p.api_key
+      && got.enc_key === p.enc_key;
+  } catch {
+    return false;
+  }
+}
+
+/**
+ * Turn off the daemon this one replaces.
+ *
+ * Deleting the old store does not stop the old daemon: it read the profiles at startup
+ * and serves them from memory, on a socket in the user's home that the client still falls
+ * back to by design. Leave it running and the machine reports itself migrated, keeps
+ * working, and is still entirely pre-split — same uid, key material and process memory
+ * readable by every agent on the box. That is the worst available outcome, because
+ * everything looks right.
+ *
+ * `systemctl --user` because that is how the pre-split daemon was installed. A failure
+ * here is reported rather than thrown: the migration itself has already succeeded at this
+ * point, and the honest thing is to tell someone the old one is still up, not to pretend
+ * the whole migration failed.
+ */
+function stopOldUserUnit(): Promise<boolean> {
+  return new Promise((resolve) => {
+    execFile('systemctl', ['--user', 'disable', '--now', 'wundervault-agent.service'],
+      { timeout: 10_000 },
+      (err) => {
+        if (err) { resolve(false); return; }
+        // Trust the verification, not the exit code: `disable` succeeds on a unit that is
+        // not there, and we want to know the process is actually gone.
+        execFile('systemctl', ['--user', 'is-active', 'wundervault-agent.service'],
+          { timeout: 5_000 },
+          (_e, stdout) => resolve(String(stdout).trim() !== 'active'));
+      });
+  });
 }
 
 export async function migrate(opts: { dryRun?: boolean } = {}): Promise<MigrationResult> {
   const result: MigrationResult = {
     migrated: [], skipped: [], deletedLegacyStore: false, alreadyDone: false,
+    oldUnitStopped: false,
   };
 
   // Say out loud which file is about to be deleted, before deleting it.
@@ -124,14 +187,29 @@ export async function migrate(opts: { dryRun?: boolean } = {}): Promise<Migratio
     );
   }
 
-  const already = new Set<string>(ping.agents ?? []);
+  // `ping` is liveness only now — it used to hand the full roster of agent names to
+  // anything that could reach the socket. The names are asked for explicitly here.
+  const roster = await ask({ action: 'known_agents' }).catch(() => ({ agents: [] }));
+  const already = new Set<string>(roster.agents ?? []);
 
   for (const p of profiles) {
     let name: string;
     try { name = safeName(p.agent_name); }
     catch (e) { result.skipped.push({ name: String(p.agent_name), why: (e as Error).message }); continue; }
 
-    if (already.has(name)) { result.skipped.push({ name, why: 'already known to the daemon' }); continue; }
+    if (already.has(name)) {
+      // Verified against the daemon's actual answer, never against the name alone.
+      if (await daemonCopyMatches(p)) {
+        result.skipped.push({ name, why: 'already across, and the daemon returns the same credentials' });
+      } else {
+        result.skipped.push({
+          name,
+          why: 'the daemon already has this name but returns DIFFERENT credentials — ' +
+               'not overwriting it, and not deleting your copy. Resolve this one by hand.',
+        });
+      }
+      continue;
+    }
 
     // A profile with no socket token cannot be served: the per-agent socket is
     // world-connectable now, so the token is the only thing identifying the caller.
@@ -149,9 +227,21 @@ export async function migrate(opts: { dryRun?: boolean } = {}): Promise<Migratio
     const fileMissing = !fs.existsSync(tp);
     if (!token) token = crypto.randomBytes(32).toString('hex');
 
-    if (!opts.dryRun && (fileMissing || !p.socket_token)) {
-      fs.mkdirSync(path.dirname(tp), { recursive: true, mode: 0o700 });
-      fs.writeFileSync(tp, token, { mode: 0o600 });
+    if (!opts.dryRun) {
+      // Written when missing — and chmod'd ALWAYS, whether we wrote it or not.
+      //
+      // Two ways the mode silently ends up wrong, both of them live on this machine:
+      // mkdir's mode argument is masked by umask and ignored outright when the directory
+      // already exists (which is why ~/.wundervault/agents sits at 0775 today), and
+      // writeFileSync's mode argument applies only when it CREATES the file, so rewriting
+      // an existing 0644 token leaves it at 0644. Before the split that was untidy. Now
+      // this file is the agent's identity in front of a world-connectable socket, so a
+      // readable token is a readable credential.
+      const dir = path.dirname(tp);
+      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
+      fs.chmodSync(dir, 0o700);
+      if (fileMissing || !p.socket_token) fs.writeFileSync(tp, token, { mode: 0o600 });
+      fs.chmodSync(tp, 0o600);
     }
 
     if (opts.dryRun) { result.migrated.push(name); continue; }
@@ -164,10 +254,19 @@ export async function migrate(opts: { dryRun?: boolean } = {}): Promise<Migratio
     else result.skipped.push({ name, why: reply?.error ?? 'the daemon refused it' });
   }
 
-  // Only delete once every profile is in. A partial migration that deleted the source
-  // would lose the credentials it failed to move.
-  const allIn = result.skipped.every(s => s.why === 'already known to the daemon');
-  if (!opts.dryRun && allIn && result.skipped.length + result.migrated.length === profiles.length) {
+  // Only delete once every profile is VERIFIED in. A partial migration that deleted the
+  // source would lose the credentials it failed to move — and a name-only match is not
+  // verification, which is why the skip reasons are matched exactly rather than by
+  // prefix. Anything that is not a confirmed match keeps the source file alive.
+  const allIn = result.skipped.every(
+    s => s.why === 'already across, and the daemon returns the same credentials');
+  const accountedFor = result.skipped.length + result.migrated.length === profiles.length;
+
+  if (!opts.dryRun && allIn && accountedFor) {
+    // The old daemon goes FIRST. It holds these profiles in memory and serves them on a
+    // socket the client still falls back to, so shredding the file while it runs would
+    // leave the machine looking migrated and behaving exactly as it did before.
+    result.oldUnitStopped = await stopOldUserUnit();
     for (const f of [legacy.profiles(), legacy.salt()]) {
       try { shred(f); result.deletedLegacyStore = true; } catch { /* best effort */ }
     }
diff --git a/test/uid-split.test.ts b/test/uid-split.test.ts
index 9f1127f..c9694e3 100644
--- a/test/uid-split.test.ts
+++ b/test/uid-split.test.ts
@@ -32,6 +32,9 @@ async function freshDaemon(opts: { profiles?: any[]; userRoot?: string } = {}) {
   process.env.WUNDERVAULT_USER_ROOT = opts.userRoot ?? path.join(dir, 'home', '.wundervault');
   process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
   process.env.WUNDERVAULT_AGENT_NO_AUTOSTART = '1';
+  // Small penalties: the growth curve is what is under test, not the wall-clock wait.
+  process.env.WUNDERVAULT_KNOCK_BASE_MS = '5';
+  process.env.WUNDERVAULT_KNOCK_MAX_MS = '80';
 
   // Plain static imports are enough: every path function reads process.env at CALL time
   // rather than at import time, so pointing the environment at a scratch directory before
@@ -50,6 +53,24 @@ function profile(name: string, token = crypto.randomBytes(32).toString('hex')) {
   };
 }
 
+/** Build a pre-split store on disk, encrypted the way the old daemon wrote it. */
+function writeLegacyStore(home: string, profiles: any[]) {
+  const root = path.join(home, '.wundervault');
+  fs.mkdirSync(root, { recursive: true });
+  let machineId = 'unknown';
+  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
+  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
+  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();
+  const salt = crypto.randomBytes(32);
+  fs.writeFileSync(path.join(root, 'agent-salt.bin'), salt);
+  const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
+  const iv = crypto.randomBytes(12);
+  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
+  const body = Buffer.concat([c.update(JSON.stringify({ profiles }), 'utf8'), c.final()]);
+  fs.writeFileSync(path.join(root, 'agent-profiles.enc'),
+    Buffer.concat([iv, c.getAuthTag(), body]), { mode: 0o600 });
+}
+
 /** Talk to a socket the way the MCP client does. */
 function speak(sockPath: string, payload: unknown, timeoutMs = 3000): Promise<any> {
   return new Promise((resolve, reject) => {
@@ -75,6 +96,8 @@ afterEach(() => {
   delete process.env.WUNDERVAULT_SYSTEM_ROOT;
   delete process.env.WUNDERVAULT_USER_ROOT;
   delete process.env.WUNDERVAULT_RUNTIME_DIR;
+  delete process.env.WUNDERVAULT_KNOCK_BASE_MS;
+  delete process.env.WUNDERVAULT_KNOCK_MAX_MS;
 });
 
 describe('the state directory is the boundary', () => {
@@ -162,20 +185,59 @@ describe('the token is the identity now', () => {
     expect(tokenMatches('ab', good)).toBe(false);        // shorter, must not throw
   });
 
-  it('locks out after repeated bad tokens', async () => {
-    // The socket is world-connectable, so any local process may knock. An unbounded
-    // guessing loop is not a real threat to a 32-byte token; an unbounded connection loop
-    // is, and so is the log it writes.
+  it('still serves the real agent while somebody else is guessing', async () => {
+    // THE regression test for this phase. The first version of this code locked out the
+    // agent NAME after ten bad tokens and checked that lockout before comparing the
+    // token — so any local process could send ten wrong guesses and take the legitimate
+    // agent off the air for a minute, over and over. Making the socket world-connectable
+    // is what created that, and this phase is what made the socket world-connectable.
+    //
+    // The old test asserted the bug: it sent twelve bad tokens, then presented the CORRECT
+    // one, and expected 'unauthorized'. It passed, and the denial-of-service passed with it.
     const p = profile('A');
     const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
     const sock = path.join(dir, 'run', 'A.sock');
     for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });
-    // Even the correct token is refused while locked out.
+
     const res = await speak(sock, { token: p.socket_token });
-    expect(res.error).toBe('unauthorized');
+    expect(res.api_key).toBe(p.api_key);
+  });
+
+  it('makes the guesser wait, and the delay grows', async () => {
+    // The cost has to land on the failing caller — that is the only party a unix socket
+    // lets us charge, since it carries no address and Node exposes no SO_PEERCRED.
+    const p = profile('A');
+    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
+    const sock = path.join(dir, 'run', 'A.sock');
+
+    const first = Date.now();
+    await speak(sock, { token: 'aa'.repeat(32) });
+    const firstMs = Date.now() - first;
+
+    for (let i = 0; i < 8; i++) await speak(sock, { token: 'aa'.repeat(32) });
+
+    const later = Date.now();
+    await speak(sock, { token: 'aa'.repeat(32) });
+    const laterMs = Date.now() - later;
+
+    expect(laterMs).toBeGreaterThan(firstMs);
+    expect(laterMs).toBeGreaterThanOrEqual(20);
   });
 
-  it('clears the lockout when the profile is re-registered', async () => {
+  it("does not make the real agent pay the guesser's penalty", async () => {
+    const p = profile('A');
+    const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
+    const sock = path.join(dir, 'run', 'A.sock');
+    for (let i = 0; i < 12; i++) await speak(sock, { token: 'aa'.repeat(32) });
+
+    const t = Date.now();
+    const res = await speak(sock, { token: p.socket_token });
+    expect(res.api_key).toBe(p.api_key);
+    // Served promptly, not after the penalty the guesser earned.
+    expect(Date.now() - t).toBeLessThan(200);
+  });
+
+  it('clears the penalty when the profile is re-registered', async () => {
     const p = profile('A');
     const { d } = await freshDaemon({ profiles: [p] }); daemon = d;
     const sock = path.join(dir, 'run', 'A.sock');
@@ -247,9 +309,20 @@ describe('management socket', () => {
     expect(fs.existsSync(path.join(dir, 'run', 'Gone.sock'))).toBe(false);
   });
 
-  it('reports what it knows without revealing credentials', async () => {
+  it('answers ping with liveness only, not a roster of what holds credentials', async () => {
+    // ping used to return every agent name on the machine. That is a list of what is
+    // worth attacking here, handed to anything that can reach the socket, for no reason
+    // beyond convenience in one caller.
     const { d } = await freshDaemon({ profiles: [profile('A'), profile('B')] }); daemon = d;
     const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'ping' });
+    expect(res.ok).toBe(true);
+    expect(res.agents).toBeUndefined();
+    expect(JSON.stringify(res)).not.toContain('wv_agent_');
+  });
+
+  it('gives the names only when they are asked for, and still no credentials', async () => {
+    const { d } = await freshDaemon({ profiles: [profile('A'), profile('B')] }); daemon = d;
+    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'known_agents' });
     expect(res.agents.sort()).toEqual(['A', 'B']);
     expect(JSON.stringify(res)).not.toContain('wv_agent_');
   });
@@ -457,10 +530,140 @@ describe('migration', () => {
   it('refuses to run when the daemon is not there, and writes no fallback', async () => {
     // Writing the old file as a fallback would recreate the pre-split world beside a
     // daemon that never reads it, and everything would appear to work.
+    //
+    // WUNDERVAULT_USER_ROOT is pinned here rather than inherited. Without it this test ran
+    // with the variable cleared by afterEach, so migrate() resolved its source store to
+    // the REAL ~/.wundervault/agent-profiles.enc and printed that path — and the only
+    // thing standing between a live credential store and the shredder was the order of
+    // two statements. That exact accident has already destroyed one store on this
+    // machine. Prove the redirect took before running anything that can delete.
+    process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'home-absent', '.wundervault');
     process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'nowhere');
+    const { legacy } = await import('../src/paths.js');
+    expect(legacy.profiles().startsWith(dir)).toBe(true);
+
     const { migrate } = await import('../src/migrate.js');
     await expect(migrate()).rejects.toThrow(/Could not reach the daemon/);
   });
+
+  it('never resolves the shredder at a path outside the scratch root', async () => {
+    // A standing guard rather than a test of one code path: any future test in this file
+    // that forgets to redirect, or any reordering that clears the variable early, fails
+    // here instead of in somebody's home directory.
+    process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'home-guard', '.wundervault');
+    const { legacy } = await import('../src/paths.js');
+    for (const resolved of [legacy.profiles(), legacy.salt(), legacy.root()]) {
+      expect(resolved.startsWith(dir)).toBe(true);
+      expect(resolved.startsWith(os.homedir())).toBe(false);
+    }
+  });
+});
+
+describe('a store it could not read is not an empty store', () => {
+  it('refuses to save over ciphertext it failed to decrypt', async () => {
+    // The failure that motivates this: decrypt throws, the daemon carries on with an
+    // empty in-memory list, and the next enrolment writes a store containing only that
+    // one profile — over the credentials of every other agent on the machine. A changed
+    // /etc/machine-id or a recreated system account is enough to trigger it, and both are
+    // recoverable until the moment the file is overwritten.
+    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
+    const storePath = path.join(dir, 'state', 'agent-profiles.enc');
+    const before = fs.readFileSync(storePath);
+
+    fs.writeFileSync(storePath, Buffer.concat([before.subarray(0, 28), crypto.randomBytes(64)]));
+    d.loadProfiles();
+    expect(d.storeUnreadable).toBe(true);
+
+    expect(() => d.registerProfile(profile('B'))).toThrow(/Refusing to write/);
+    // The ciphertext is untouched, so the credentials are still recoverable.
+    expect(fs.readFileSync(storePath).length).toBeGreaterThan(28);
+    expect(fs.readFileSync(storePath).subarray(0, 28)).toEqual(before.subarray(0, 28));
+  });
+
+  it('says so on ping rather than looking healthy and empty', async () => {
+    const { d } = await freshDaemon({ profiles: [profile('A')] }); daemon = d;
+    const storePath = path.join(dir, 'state', 'agent-profiles.enc');
+    fs.writeFileSync(storePath, crypto.randomBytes(120));
+    d.loadProfiles();
+    const res = await speak(path.join(dir, 'run', 'mgmt', 'agent.sock'), { action: 'ping' });
+    expect(res.store_unreadable).toBe(true);
+  });
+});
+
+describe('a name is not proof the agent is across', () => {
+  it('keeps the legacy store when the daemon returns different credentials', async () => {
+    // The daemon holds agent A, but with stale credentials. Counting the name as migrated
+    // and shredding would destroy the only correct copy and leave A broken.
+    const home = path.join(dir, 'home-mismatch');
+    const good = profile('A');
+    const stale = { ...good, api_key: 'wv_agent_A|STALE' };
+
+    writeLegacyStore(home, [good]);
+    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
+    const { d } = await freshDaemon({ profiles: [stale], userRoot: path.join(home, '.wundervault') });
+    daemon = d;
+
+    const { legacy } = await import('../src/paths.js');
+    expect(legacy.profiles().startsWith(dir)).toBe(true);
+
+    const { migrate } = await import('../src/migrate.js');
+    const r = await migrate();
+
+    expect(r.deletedLegacyStore).toBe(false);
+    expect(fs.existsSync(legacy.profiles())).toBe(true);
+    expect(r.skipped[0].why).toMatch(/DIFFERENT credentials/);
+  });
+});
+
+describe('the token file is the identity, so its mode is load-bearing', () => {
+  it('repairs a token file and directory left world-readable', async () => {
+    const home = path.join(dir, 'home-modes');
+    const p = profile('A');
+    writeLegacyStore(home, [p]);
+
+    // The shape this is really guarding: ~/.wundervault/agents is 0775 on the owner's
+    // machine today, because mkdir's mode argument is masked by umask and ignored outright
+    // on a directory that already exists. writeFileSync's mode has the same property for
+    // files — it applies on create only — so rewriting an existing 0644 token leaves it
+    // at 0644.
+    const agentsDir = path.join(home, '.wundervault', 'agents');
+    fs.mkdirSync(agentsDir, { recursive: true });
+    fs.chmodSync(agentsDir, 0o775);
+    fs.writeFileSync(path.join(agentsDir, 'A.token'), p.socket_token);
+    fs.chmodSync(path.join(agentsDir, 'A.token'), 0o644);
+
+    process.env.WUNDERVAULT_USER_ROOT = path.join(home, '.wundervault');
+    const { d } = await freshDaemon({ userRoot: path.join(home, '.wundervault') });
+    daemon = d;
+    const { migrate } = await import('../src/migrate.js');
+    await migrate();
+
+    expect(fs.statSync(path.join(agentsDir, 'A.token')).mode & 0o777).toBe(0o600);
+    expect(fs.statSync(agentsDir).mode & 0o777).toBe(0o700);
+  });
+});
+
+describe('the installer refuses what the sandbox would hide', () => {
+  const script = fs.readFileSync(path.join(ROOT, 'packaging', 'install-daemon.sh'), 'utf8');
+
+  it('rejects an ExecStart under a home directory', () => {
+    // ProtectHome=yes makes /home empty for the service, so a home-based ExecStart installs
+    // cleanly and then fails at start with 203/EXEC. On the owner's own machine
+    // `wundervault-agent` resolves to ~/.local/bin, so this is the default path, not an
+    // edge case.
+    expect(script).toMatch(/\/home\/\*\|\/root\/\*\|\/run\/user\/\*/);
+    expect(script).toContain('readlink -f');
+  });
+
+  it('does not let set -e swallow the explanation', () => {
+    // A bare `a && b && echo` list returns non-zero when the note does not apply, and
+    // `set -e` would exit on it — printing "ERROR:" and nothing that says what to do.
+    // The guard must be an `if ...; then` — a bare list is the bug. Matching on "not a
+    // bare list" is what the first version of this test got wrong: the corrected `if` form
+    // contains the same bracket text, so the negative regex matched it too and failed.
+    expect(script).toMatch(/if \[ "\$CANDIDATE" = "\$REAL_EXEC" \] && \[ "\$EXEC" != "\$REAL_EXEC" \]; then/);
+    expect(script).not.toMatch(/^\s*\[ "\$CANDIDATE" = "\$REAL_EXEC" \] && \[ [^\n]*\] && \\$/m);
+  });
 });
 
 describe('the unit file says what the code relies on', () => {

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
import { execFile } from 'node:child_process';
import { legacy, mgmtSocketPath, agentSocketPath, agentTokenPath, safeName } from './paths.js';

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
  oldUnitStopped: boolean;
}

/**
 * Does the daemon's copy of this agent actually match the one we are about to destroy?
 *
 * A name appearing in the daemon's list is NOT proof of that. The daemon may hold a stale
 * profile under the same name — from an abandoned enrolment, a restored backup, a machine
 * that was set up twice — and treating the name as proof would count that agent as safely
 * across and shred the only correct copy of its credentials.
 *
 * We cannot ask the daemon to show us what it holds; refusing to hand credentials back to
 * a caller that has not proved it is the agent is the whole point of the phase. But we do
 * not need it to: we have the agent's token from the legacy store, so we can present that
 * on the agent's own socket exactly as the agent would, and compare what comes back.
 * Nothing is trusted that has not been checked against the plaintext we are holding.
 */
async function daemonCopyMatches(p: LegacyProfile): Promise<boolean> {
  if (!p.socket_token) return false;
  try {
    const got = await ask(
      { token: p.socket_token },
      agentSocketPath(safeName(p.agent_name)),
      3_000,
    );
    return !!got
      && got.api_key === p.api_key
      && got.enc_key === p.enc_key;
  } catch {
    return false;
  }
}

/**
 * Turn off the daemon this one replaces.
 *
 * Deleting the old store does not stop the old daemon: it read the profiles at startup
 * and serves them from memory, on a socket in the user's home that the client still falls
 * back to by design. Leave it running and the machine reports itself migrated, keeps
 * working, and is still entirely pre-split — same uid, key material and process memory
 * readable by every agent on the box. That is the worst available outcome, because
 * everything looks right.
 *
 * `systemctl --user` because that is how the pre-split daemon was installed. A failure
 * here is reported rather than thrown: the migration itself has already succeeded at this
 * point, and the honest thing is to tell someone the old one is still up, not to pretend
 * the whole migration failed.
 */
function stopOldUserUnit(): Promise<boolean> {
  return new Promise((resolve) => {
    execFile('systemctl', ['--user', 'disable', '--now', 'wundervault-agent.service'],
      { timeout: 10_000 },
      (err) => {
        if (err) { resolve(false); return; }
        // Trust the verification, not the exit code: `disable` succeeds on a unit that is
        // not there, and we want to know the process is actually gone.
        execFile('systemctl', ['--user', 'is-active', 'wundervault-agent.service'],
          { timeout: 5_000 },
          (_e, stdout) => resolve(String(stdout).trim() !== 'active'));
      });
  });
}

export async function migrate(opts: { dryRun?: boolean } = {}): Promise<MigrationResult> {
  const result: MigrationResult = {
    migrated: [], skipped: [], deletedLegacyStore: false, alreadyDone: false,
    oldUnitStopped: false,
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

  // `ping` is liveness only now — it used to hand the full roster of agent names to
  // anything that could reach the socket. The names are asked for explicitly here.
  const roster = await ask({ action: 'known_agents' }).catch(() => ({ agents: [] }));
  const already = new Set<string>(roster.agents ?? []);

  for (const p of profiles) {
    let name: string;
    try { name = safeName(p.agent_name); }
    catch (e) { result.skipped.push({ name: String(p.agent_name), why: (e as Error).message }); continue; }

    if (already.has(name)) {
      // Verified against the daemon's actual answer, never against the name alone.
      if (await daemonCopyMatches(p)) {
        result.skipped.push({ name, why: 'already across, and the daemon returns the same credentials' });
      } else {
        result.skipped.push({
          name,
          why: 'the daemon already has this name but returns DIFFERENT credentials — ' +
               'not overwriting it, and not deleting your copy. Resolve this one by hand.',
        });
      }
      continue;
    }

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

    if (!opts.dryRun) {
      // Written when missing — and chmod'd ALWAYS, whether we wrote it or not.
      //
      // Two ways the mode silently ends up wrong, both of them live on this machine:
      // mkdir's mode argument is masked by umask and ignored outright when the directory
      // already exists (which is why ~/.wundervault/agents sits at 0775 today), and
      // writeFileSync's mode argument applies only when it CREATES the file, so rewriting
      // an existing 0644 token leaves it at 0644. Before the split that was untidy. Now
      // this file is the agent's identity in front of a world-connectable socket, so a
      // readable token is a readable credential.
      const dir = path.dirname(tp);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.chmodSync(dir, 0o700);
      if (fileMissing || !p.socket_token) fs.writeFileSync(tp, token, { mode: 0o600 });
      fs.chmodSync(tp, 0o600);
    }

    if (opts.dryRun) { result.migrated.push(name); continue; }

    const reply = await ask({
      action: 'register_profile',
      profile: { ...p, agent_name: name, socket_token: token },
    });
    if (reply?.ok) result.migrated.push(name);
    else result.skipped.push({ name, why: reply?.error ?? 'the daemon refused it' });
  }

  // Only delete once every profile is VERIFIED in. A partial migration that deleted the
  // source would lose the credentials it failed to move — and a name-only match is not
  // verification, which is why the skip reasons are matched exactly rather than by
  // prefix. Anything that is not a confirmed match keeps the source file alive.
  const allIn = result.skipped.every(
    s => s.why === 'already across, and the daemon returns the same credentials');
  const accountedFor = result.skipped.length + result.migrated.length === profiles.length;

  if (!opts.dryRun && allIn && accountedFor) {
    // The old daemon goes FIRST. It holds these profiles in memory and serves them on a
    // socket the client still falls back to, so shredding the file while it runs would
    // leave the machine looking migrated and behaving exactly as it did before.
    result.oldUnitStopped = await stopOldUserUnit();
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
/**
 * Make guessing expensive without letting a guesser deny the real agent.
 *
 * The first shape of this was a lockout: ten bad tokens for an agent name and that name
 * was refused for sixty seconds. Behind a 0600 socket that was defensible. It is not
 * defensible now — this phase made the per-agent sockets world-connectable, because the
 * daemon is a different uid and a 0600 socket it owns is one no agent could reach. So any
 * local process could send ten wrong tokens and take the LEGITIMATE agent off the air,
 * repeatedly, for as long as it liked. The mechanism meant to slow an attacker down had
 * become the cheapest attack available, and this phase is what introduced it.
 *
 * The rule now: a correct token is ALWAYS served. Nothing an attacker sends can change
 * what the holder of the real token gets back. The cost falls on the failing caller
 * instead, as a delay that doubles per consecutive failure — which is what actually
 * throttles guessing, since it is the attacker's own connection that has to wait.
 *
 * The delay is per agent name, and that is a deliberate, stated limit: a unix socket
 * carries no address to attribute failures to, and Node exposes no SO_PEERCRED to
 * identify the caller. So a persistent guesser does slow down a legitimate client that
 * is ALSO failing — but a legitimate client that is failing has the wrong token, and
 * telling it so a second later costs nothing.
 */
class Knocks {
  private fails = new Map<string, { n: number; until: number }>();
  private readonly WINDOW_MS = 60_000;
  // Overridable so the tests can exercise the growth curve without sitting through it.
  // Production values are the defaults; nothing in the shipped path sets these.
  private readonly BASE_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_BASE_MS) || 50;
  private readonly MAX_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_MAX_MS) || 2_000;

  /**
   * How long to make a FAILING caller wait. Never consulted before a token is checked:
   * a valid token must not be delayed or refused because somebody else guessed wrong.
   */
  penaltyMs(name: string): number {
    const f = this.fails.get(name);
    if (!f || Date.now() >= f.until) return 0;
    return Math.min(this.BASE_DELAY_MS * 2 ** Math.min(f.n, 16), this.MAX_DELAY_MS);
  }

  record(name: string): void {
    const now = Date.now();
    const f = this.fails.get(name);
    if (!f || now >= f.until) { this.fails.set(name, { n: 1, until: now + this.WINDOW_MS }); return; }
    f.n += 1;
    // Sliding, not fixed: a guesser that keeps knocking keeps paying, rather than
    // getting a clean slate sixty seconds after its first attempt.
    f.until = now + this.WINDOW_MS;
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

  /**
   * A store we could not read is NOT an empty store.
   *
   * This used to log the failure and carry on with `this.profiles` still `[]`. The daemon
   * would come up serving nobody, which looks like a bad day — and then the first
   * enrolment called saveProfiles(), which wrote a store containing ONLY that profile,
   * over the ciphertext holding every other agent's credentials. A recoverable problem
   * (a changed /etc/machine-id, a recreated wundervault account, a damaged file — all of
   * which leave the plaintext retrievable) became permanent loss, silently.
   *
   * So a decrypt failure is now a refusal: the daemon will not serve and will not save
   * until a person has looked at it. Refusing to start is a visible, reversible failure.
   * Overwriting is neither.
   */
  private unreadableStore: string | null = null;

  loadProfiles(): void {
    const pp = profilesPath();
    if (!fs.existsSync(pp)) { this.unreadableStore = null; return; }
    try {
      this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
      this.unreadableStore = null;
    } catch (err) {
      this.unreadableStore = (err as Error).message;
      this.profiles = [];
      console.error(
        `[wundervault-agent] Could not read the profile store at ${pp}: ${this.unreadableStore}\n` +
        `[wundervault-agent] It is encrypted against this machine's id and the daemon's uid.\n` +
        `[wundervault-agent] REFUSING to serve or to overwrite it. The credentials are still\n` +
        `[wundervault-agent] in that file; starting fresh would destroy them. Restore the file,\n` +
        `[wundervault-agent] or move it aside deliberately if you mean to start over.`,
      );
    }
  }

  /** True when the store exists but could not be read. Nothing may be written in this state. */
  get storeUnreadable(): boolean { return this.unreadableStore !== null; }

  saveProfiles(): void {
    if (this.unreadableStore) {
      throw new Error(
        `Refusing to write the profile store: it exists but could not be decrypted ` +
        `(${this.unreadableStore}). Writing now would replace every credential in it ` +
        `with only what is in memory.`,
      );
    }
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

        let msg: { token?: string } = {};
        try { msg = JSON.parse(buf.trim()); } catch { /* treated as no token */ }

        // The token is checked FIRST, before any penalty is consulted. The previous order
        // let a stranger's wrong guesses decide what the real agent got back.
        if (!tokenMatches(msg.token, profile.socket_token)) {
          const wait = this.knocks.penaltyMs(profile.agent_name);
          this.knocks.record(profile.agent_name);
          console.error(`[wundervault-agent] Auth failure on ${profile.agent_name} socket`);
          // The same answer for a bad token and a missing one. Anything more specific
          // tells a local prober which agent names exist on this machine.
          const refuse = () => {
            try {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
              socket.end();
            } catch { /* the prober hung up while waiting, which is fine */ }
          };
          if (wait > 0) {
            const t = setTimeout(refuse, wait);
            // Do not hold the event loop open on behalf of someone guessing tokens.
            (t as unknown as { unref?: () => void }).unref?.();
            socket.on('close', () => clearTimeout(t));
          } else {
            refuse();
          }
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

    // Delaying a failing caller keeps its connection open, so the guessing loop the delay
    // is meant to discourage now costs US a socket for as long as it costs them. A ceiling
    // turns that back around: past it the kernel refuses new connections outright, which is
    // cheaper for the daemon than for the prober. This is the "unbounded connection loop"
    // the spec's C3 actually worried about — the delay alone would have made it worse.
    srv.maxConnections = 64;

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
            // Liveness only. This used to return every agent name on the machine, which
            // is a roster of what holds credentials here, handed to anyone who could
            // reach the socket. Migration is the only caller that needs the names, and it
            // asks for them explicitly below.
            socket.write(JSON.stringify({
              ok: true, version: VERSION, store_unreadable: this.storeUnreadable,
            }) + '\n');
          } else if (msg.action === 'known_agents') {
            socket.write(JSON.stringify({
              ok: true, system_root: systemRoot(),
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
