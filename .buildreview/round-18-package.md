# Review package — round 18
generated 2026-09-16T01:42:13+00:00

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

ROUND 18 — the store key is now sealed, and the setup-link KDF was raised. Read
round-17-triage.json first. This round is about CRYPTOGRAPHY and KEY HANDLING; earlier rounds
covered the uid boundary and enrolment.

WHAT CHANGED:
1. The store key was NOT a secret. It was HKDF(sha256(machine-id : uid)) with the salt stored
   beside the ciphertext — every input readable by anyone who could read the directory, so the
   key was recomputable and a stolen disk gave up everything. It is now a random 32-byte key
   sealed with `systemd-creds` (TPM where present, root-only host key otherwise) and handed to
   the broker by systemd via LoadCredentialEncrypted. The broker never touches /dev/tpmrm0.
   The sealed value is HKDF-expanded (info "wundervault-store-v2") rather than used raw.
2. MIGRATION: a store that fails against the sealed key is retried against the old derived key,
   and if it opens it is immediately rewritten sealed and the old salt unlinked.
3. FALLBACK: where nothing can seal, the old derived key is used, and the mode is printed at
   every start and reported on `ping` as key_mode. The installer asks the broker which key it
   actually used and warns explicitly not to call the machine sealed if the answer is wrong.
4. The setup-link KDF went from PBKDF2 100,000 to 600,000 iterations, version carried in the
   salt (wv-agent-setup-v2), decryptors try v2 then v1 so links in flight during a deploy
   still open.

WHAT I MOST WANT ATTACKED:
(a) The migration path. It decrypts with a key, and on failure decrypts with ANOTHER key, then
    writes. What can go wrong — a partially-written store, a crash between read and save, a
    store that happens to decrypt under the wrong key (GCM makes that vanishingly unlikely, but
    say so if I am wrong), the salt being deleted while something still needs it?
(b) Is `HKDF(sealed_bytes, salt=empty, info="wundervault-store-v2")` the right construction? I
    used an empty salt deliberately since the IKM is already 32 random bytes. Argue with that.
(c) The fallback. Is silently continuing on a weaker key the right call at all, versus refusing
    to start? I chose to continue and shout, on the grounds that a broker that will not start is
    worse — but that is a judgement and I want it challenged.
(d) The v1/v2 KDF fallback in enrol.ts: trying two keys against the same ciphertext. Any
    oracle, timing, or downgrade concern? Could an attacker force v1?
(e) Anything about systemd-creds I have assumed wrongly — particularly what happens on a
    machine whose TPM state changes (firmware update, PCR change, disk moved).

VERIFIED ON A REAL INSTALL: sealing produces a blob; the blob decrypts; the installer's
"sealed but not in use" warning fires correctly in a container where systemd sets
CREDENTIALS_DIRECTORY but does not materialise the file. Both KDF versions cross-checked
against real Python AESGCM output.

NOT VERIFIED: end-to-end credential delivery on a machine with a working TPM — the rehearsal
container cannot materialise credentials. Say what that leaves untested.

TESTS: 404 passing.

WITHHELD: src/agent.ts is 40KB; sent as an EXTRACT of the key-handling and migration regions
only. src/server.ts and the burnbox repo are not included.

## Diff

```diff
diff --git a/packaging/install-daemon.sh b/packaging/install-daemon.sh
index d338142..0ba5f62 100644
--- a/packaging/install-daemon.sh
+++ b/packaging/install-daemon.sh
@@ -210,10 +210,56 @@ ACTUAL=$(stat -c '%a' "$STATE_DIR" 2>/dev/null || stat -f '%Lp' "$STATE_DIR")
 [ "$ACTUAL" = "700" ] || { echo "ERROR: ${STATE_DIR} is mode ${ACTUAL}, expected 700." >&2; exit 1; }
 echo "state dir ${STATE_DIR}: 0700 ${ACCOUNT}"
 
+# ── 2b. the sealed store key ─────────────────────────────────────────────────
+#
+# A random 32-byte key, sealed so that the file on disk is useless on its own.
+#
+# What this replaces: a key DERIVED from /etc/machine-id and the account's uid, with the
+# salt stored beside the ciphertext. Every input to that is readable by anyone who can read
+# the directory, so the key was recomputable — the directory mode was doing all the work and
+# the encryption was decoration. Someone who walked off with the disk had everything.
+#
+# `systemd-creds encrypt` seals to the TPM where there is one, and to the root-only host key
+# otherwise. Either way the blob does not open on another machine, and the broker never needs
+# TPM access itself: systemd unseals it as root at start and hands it over through a private
+# tmpfs (LoadCredentialEncrypted= in the unit).
+SEALED_KEY="${STATE_DIR}/store.key.cred"
+if [ -f "$SEALED_KEY" ]; then
+  echo "store key: already sealed at ${SEALED_KEY}"
+elif command -v systemd-creds >/dev/null 2>&1; then
+  TPM_STATE=$(systemd-creds has-tpm2 2>/dev/null | head -1 || echo no)
+  if head -c 32 /dev/urandom \
+      | systemd-creds encrypt --name=wv-store-key - "$SEALED_KEY" 2>/dev/null; then
+    chown "${ACCOUNT}:$(id -gn "$ACCOUNT")" "$SEALED_KEY"
+    chmod 0600 "$SEALED_KEY"
+    case "$TPM_STATE" in
+      yes) echo "store key: sealed to this machine's TPM" ;;
+      *)   echo "store key: sealed to the host key (no TPM found — still not portable,"
+           echo "           but a disk copy plus root would open it)" ;;
+    esac
+  else
+    echo "WARNING: could not seal a store key with systemd-creds." >&2
+    echo "         The broker will fall back to a key derived from /etc/machine-id and its" >&2
+    echo "         uid, which anyone able to read ${STATE_DIR} can recompute. The directory" >&2
+    echo "         mode still protects it; the encryption does not." >&2
+  fi
+else
+  echo "WARNING: systemd-creds not found, so the store key cannot be sealed." >&2
+  echo "         The broker falls back to a derived, recomputable key. See the docs." >&2
+fi
+
 # ── 3. the unit ──────────────────────────────────────────────────────────────
 # The template is shipped alongside this script and read from disk rather than written
 # inline, so what lands in /etc/systemd/system is the file you reviewed in the repo.
 sed "s|^ExecStart=.*|ExecStart=${EXEC}|" "$UNIT_SRC" > "$UNIT_PATH"
+
+# No sealed key on this machine? Then the unit must not ask systemd for one: a missing
+# credential source is fatal (243/CREDENTIALS), and a broker that will not start is worse
+# than one running on the derived key and saying so.
+if [ ! -f "$SEALED_KEY" ]; then
+  sed -i '/^LoadCredentialEncrypted=wv-store-key:/d' "$UNIT_PATH"
+  echo "unit: no sealed key, so the credential line was removed"
+fi
 chmod 0644 "$UNIT_PATH"
 grep -q "^User=${ACCOUNT}\$" "$UNIT_PATH" || {
   echo "ERROR: the installed unit does not run as ${ACCOUNT}. Refusing to continue." >&2
@@ -231,6 +277,25 @@ systemctl enable "$UNIT_NAME"
 systemctl restart "$UNIT_NAME"
 
 sleep 1
+
+# Did the sealing actually take EFFECT? Sealing a key and delivering it are separate things,
+# and the gap between them is silent: systemd can set CREDENTIALS_DIRECTORY and still fail to
+# materialise the file, which leaves the broker on the derived key while a sealed blob sits
+# on disk looking like proof of something. Ask the broker what key it is actually using.
+if [ -f "$SEALED_KEY" ] && systemctl is-active --quiet "$UNIT_NAME"; then
+  sleep 1
+  if journalctl -u "$UNIT_NAME" -n 20 --no-pager 2>/dev/null | grep -q "Store key: DERIVED"; then
+    echo >&2
+    echo "WARNING: a sealed key exists but the broker is NOT using it." >&2
+    echo "         systemd did not deliver the credential — check:" >&2
+    echo "           systemd-creds decrypt --name=wv-store-key ${SEALED_KEY} -" >&2
+    echo "           journalctl -u ${UNIT_NAME} | grep -i credential" >&2
+    echo "         The store is running on a key derived from /etc/machine-id and the" >&2
+    echo "         broker's uid, which anyone able to read ${STATE_DIR} can recompute." >&2
+    echo "         Do not describe this machine as having a sealed store." >&2
+  fi
+fi
+
 if systemctl is-active --quiet "$UNIT_NAME"; then
   echo
   echo "The secret broker is running. ${STATE_DIR} is readable only by ${ACCOUNT},"
diff --git a/packaging/wundervault-agent.service b/packaging/wundervault-agent.service
index 72b7498..75dec09 100644
--- a/packaging/wundervault-agent.service
+++ b/packaging/wundervault-agent.service
@@ -24,6 +24,12 @@ RestartSec=2
 # systemd creates and removes /run/wundervault. Our own mkdir would leave a stale socket
 # behind after a crash, and the next start would bind elsewhere while agents kept talking
 # to the old path.
+# The store key, unsealed by systemd (as root) and handed to this service in a private
+# tmpfs at $CREDENTIALS_DIRECTORY. The broker therefore never touches /dev/tpmrm0 and never
+# needs the host key; it just reads a file only it can see. Absent on a machine that could
+# not seal one, in which case the broker falls back to a derived key and says so loudly.
+LoadCredentialEncrypted=wv-store-key:/var/lib/wundervault/store.key.cred
+
 RuntimeDirectory=wundervault
 RuntimeDirectoryMode=0755
 StateDirectory=wundervault
diff --git a/src/agent.ts b/src/agent.ts
index 2986b79..464c67a 100644
--- a/src/agent.ts
+++ b/src/agent.ts
@@ -37,7 +37,7 @@ import { redeemSetupLink, peekAgentName } from './enrol.js';
 import {
   systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
   runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
-  splitAvailable,
+  splitAvailable, systemdCredential,
 } from './paths.js';
 import { load as loadNetworkShape } from './network-store.js';
 
@@ -95,7 +95,32 @@ function refuseRoot(): void {
   }
 }
 
-function deriveMachineKey(): Buffer {
+/**
+ * The key the profile store is encrypted with.
+ *
+ * TWO MODES, AND THE DIFFERENCE IS THE WHOLE POINT.
+ *
+ * SEALED (preferred). systemd unseals a random 32-byte key for us — sealed to this
+ * machine's TPM where there is one, to the root-only host key otherwise — and drops it in a
+ * private tmpfs only this service can read. The key is not derived from anything; it is a
+ * secret. Copy the disk to another machine and the store does not open, because the TPM
+ * that sealed it is not there.
+ *
+ * DERIVED (fallback, and what this used to be exclusively). HKDF over
+ * sha256(machine-id : uid) with a salt stored beside the ciphertext. Every input to that is
+ * readable by anyone who can read the directory, so the key is RECOMPUTABLE: it is not a
+ * secret, it is an obfuscation, and the directory mode was doing all the real work. That is
+ * fine as defence in depth and was always described as such — it is not fine as the only
+ * thing standing between a stolen disk and every credential on it.
+ *
+ * Both are supported because the fallback has to exist: no TPM, an older systemd, a
+ * container, a hand-started broker. What must not happen is a machine silently sitting in
+ * the weaker mode while the release notes describe the stronger one, so the mode in force is
+ * reported at startup and by `ping`.
+ */
+type KeyMode = 'sealed' | 'derived';
+
+function legacyDerivedKey(): Buffer {
   let machineId = 'unknown';
   try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
   const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
@@ -113,6 +138,22 @@ function deriveMachineKey(): Buffer {
   return crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
 }
 
+function sealedKey(): Buffer | null {
+  const raw = systemdCredential();
+  if (!raw) return null;
+  // Expanded rather than used raw, so the stored secret is never the working key and can be
+  // re-purposed later (a second context string gives a second independent key).
+  return crypto.hkdfSync(
+    'sha256', raw, Buffer.alloc(0), Buffer.from('wundervault-store-v2'), 32,
+  ) as unknown as Buffer;
+}
+
+function deriveMachineKey(): { key: Buffer; mode: KeyMode } {
+  const sealed = sealedKey();
+  if (sealed) return { key: sealed, mode: 'sealed' };
+  return { key: legacyDerivedKey(), mode: 'derived' };
+}
+
 function encryptProfiles(store: ProfileStore, key: Buffer): Buffer {
   const nonce = crypto.randomBytes(12);
   const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
@@ -215,10 +256,15 @@ class AgentDaemon {
 
   constructor() {
     ensureSystemRoot();
-    this.key = deriveMachineKey();
+    const { key, mode } = deriveMachineKey();
+    this.key = key;
+    this.keyMode = mode;
     this.loadProfiles();
   }
 
+  /** 'sealed' when the key came from the TPM via systemd; 'derived' when it is recomputable. */
+  keyMode: KeyMode = 'derived';
+
   /**
    * A store we could not read is NOT an empty store.
    *
@@ -241,7 +287,28 @@ class AgentDaemon {
     try {
       this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
       this.unreadableStore = null;
+      return;
     } catch (err) {
+      // Before giving up: a store written under the OLD derived key is not corrupt, it is
+      // just addressed to a key we have stopped using. Try that key, and if it opens,
+      // rewrite the store under the sealed one immediately. Migration has to be automatic —
+      // an upgrade that leaves every existing install unable to start is not an upgrade, and
+      // one that needs a manual step is one most people will not take.
+      if (this.keyMode === 'sealed') {
+        try {
+          const viaLegacy = decryptProfiles(fs.readFileSync(pp), legacyDerivedKey()).profiles;
+          this.profiles = viaLegacy;
+          this.unreadableStore = null;
+          this.saveProfiles();
+          console.error(
+            '[wundervault-agent] Re-sealed the profile store: it was encrypted with a key ' +
+            'derived from public inputs, and is now sealed to this machine.',
+          );
+          // The old salt is no longer an input to anything. Leaving it implies otherwise.
+          try { fs.unlinkSync(saltPath()); } catch { /* already gone */ }
+          return;
+        } catch { /* genuinely unreadable; fall through to the refusal below */ }
+      }
       this.unreadableStore = (err as Error).message;
       this.profiles = [];
       console.error(
@@ -561,6 +628,7 @@ class AgentDaemon {
             // asks for them explicitly below.
             socket.write(JSON.stringify({
               ok: true, version: VERSION, store_unreadable: this.storeUnreadable,
+              key_mode: this.keyMode,
             }) + '\n');
           } else if (msg.action === 'known_agents') {
             // Names only, never credentials. This is what lets migration tell you which of
@@ -624,6 +692,20 @@ class AgentDaemon {
     console.log(
       `[wundervault-agent] Started with ${this.agentServers.size} agent(s). State: ${systemRoot()}`,
     );
+    // Said out loud, every start. A machine quietly running in the weaker mode while the
+    // documentation describes the stronger one is the failure this line exists to prevent.
+    if (this.keyMode === 'sealed') {
+      console.log(
+        '[wundervault-agent] Store key: SEALED to this machine (systemd/TPM). ' +
+        'A copy of the disk does not open it.',
+      );
+    } else {
+      console.error(
+        '[wundervault-agent] Store key: DERIVED from machine-id and uid, which are not secret.\n' +
+        '[wundervault-agent] Anyone who can read this directory can recompute it, so the\n' +
+        '[wundervault-agent] directory mode is what protects the store — not the encryption.',
+      );
+    }
   }
 
   shutdown(): void {
diff --git a/src/enrol.ts b/src/enrol.ts
index 078612d..a6609c5 100644
--- a/src/enrol.ts
+++ b/src/enrol.ts
@@ -48,8 +48,22 @@ export function allowedOrigins(): string[] {
   return configured.split(',').map(o => o.trim()).filter(Boolean);
 }
 
-const PBKDF2_SALT = 'wv-agent-setup-v1';
-const PBKDF2_ROUNDS = 100_000;
+/**
+ * The setup-link KDF, v2 first and v1 behind it.
+ *
+ * 600,000 iterations, up from 100,000: the same figure the vault passphrase uses and the
+ * current OWASP recommendation for PBKDF2-HMAC-SHA256. The link lives fifteen minutes, which
+ * bounds the window but says nothing about what a captured link costs to attack inside it —
+ * and there was no reason for this one path to be six times weaker than everything else.
+ *
+ * The version lives in the salt so both can be understood at once. A link minted just before
+ * the deploy is v1 and still has its fifteen minutes; this tries v2 and falls back. The v1
+ * entry can be removed once no v1 link can possibly still exist.
+ */
+const KDF_VERSIONS: ReadonlyArray<{ salt: string; rounds: number }> = [
+  { salt: 'wv-agent-setup-v2', rounds: 600_000 },
+  { salt: 'wv-agent-setup-v1', rounds: 100_000 },
+];
 const UA = 'WunderVault-Agent-Daemon/1.0';
 /** A credential blob is a couple of hundred bytes. This is three orders of magnitude of slack. */
 const MAX_RESPONSE_BYTES = 256 * 1024;
@@ -208,16 +222,20 @@ export async function redeemSetupLink(
   const blob = Buffer.from(b64, 'base64');
   if (blob.length < 29) throw new Error('The credential blob is too short to be valid.');
 
-  const key = crypto.pbkdf2Sync(passphrase, PBKDF2_SALT, PBKDF2_ROUNDS, 32, 'sha256');
-  let plain: Buffer;
-  try {
-    const decipher = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
-    // GCM in this format carries its tag at the END of the ciphertext, the way the Python
-    // AESGCM.decrypt() on the other side expects to find it.
-    const ct = blob.subarray(12, blob.length - 16);
-    decipher.setAuthTag(blob.subarray(blob.length - 16));
-    plain = Buffer.concat([decipher.update(ct), decipher.final()]);
-  } catch {
+  let plain: Buffer | null = null;
+  for (const { salt, rounds } of KDF_VERSIONS) {
+    const key = crypto.pbkdf2Sync(passphrase, salt, rounds, 32, 'sha256');
+    try {
+      const decipher = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
+      // GCM in this format carries its tag at the END of the ciphertext, the way the Python
+      // AESGCM.decrypt() on the other side expects to find it.
+      const ct = blob.subarray(12, blob.length - 16);
+      decipher.setAuthTag(blob.subarray(blob.length - 16));
+      plain = Buffer.concat([decipher.update(ct), decipher.final()]);
+      break;
+    } catch { /* wrong version or wrong passphrase; try the next */ }
+  }
+  if (!plain) {
     throw new Error(
       'Could not decrypt those credentials — the part of the link after the # is wrong, ' +
       'or the link was mangled in transit. Nothing has been changed and the link is unused.',
diff --git a/src/paths.ts b/src/paths.ts
index f381609..b8998bb 100644
--- a/src/paths.ts
+++ b/src/paths.ts
@@ -109,6 +109,29 @@ export function runtimeDir(): string {
   return path.join(systemRoot(), 'run');
 }
 
+/**
+ * Where systemd drops credentials it has unsealed for us.
+ *
+ * `LoadCredentialEncrypted=` in the unit has systemd decrypt a sealed blob AS ROOT and place
+ * the plaintext in a private tmpfs readable only by this service. That is the whole trick:
+ * the broker never needs access to /dev/tpmrm0 or to the host key, and the sealed file on
+ * disk is useless to anyone who copies it — on another machine the TPM will not unseal it,
+ * and on this one it takes root.
+ */
+export const CREDENTIAL_NAME = 'wv-store-key';
+
+export function systemdCredential(name = CREDENTIAL_NAME): Buffer | null {
+  const dir = process.env.CREDENTIALS_DIRECTORY;
+  if (!dir) return null;
+  try {
+    const buf = fs.readFileSync(path.join(dir, name));
+    return buf.length >= 32 ? buf : null;
+  } catch { return null; }
+}
+
+/** The sealed blob on disk. Written by the installer, read by systemd, never by us. */
+export const sealedKeyPath = () => path.join(systemRoot(), 'store.key.cred');
+
 // ── daemon-side paths ─────────────────────────────────────────────────────────
 
 export const profilesPath = () => path.join(systemRoot(), 'agent-profiles.enc');

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

/**
 * The setup-link KDF, v2 first and v1 behind it.
 *
 * 600,000 iterations, up from 100,000: the same figure the vault passphrase uses and the
 * current OWASP recommendation for PBKDF2-HMAC-SHA256. The link lives fifteen minutes, which
 * bounds the window but says nothing about what a captured link costs to attack inside it —
 * and there was no reason for this one path to be six times weaker than everything else.
 *
 * The version lives in the salt so both can be understood at once. A link minted just before
 * the deploy is v1 and still has its fifteen minutes; this tries v2 and falls back. The v1
 * entry can be removed once no v1 link can possibly still exist.
 */
const KDF_VERSIONS: ReadonlyArray<{ salt: string; rounds: number }> = [
  { salt: 'wv-agent-setup-v2', rounds: 600_000 },
  { salt: 'wv-agent-setup-v1', rounds: 100_000 },
];
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

  let plain: Buffer | null = null;
  for (const { salt, rounds } of KDF_VERSIONS) {
    const key = crypto.pbkdf2Sync(passphrase, salt, rounds, 32, 'sha256');
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
      // GCM in this format carries its tag at the END of the ciphertext, the way the Python
      // AESGCM.decrypt() on the other side expects to find it.
      const ct = blob.subarray(12, blob.length - 16);
      decipher.setAuthTag(blob.subarray(blob.length - 16));
      plain = Buffer.concat([decipher.update(ct), decipher.final()]);
      break;
    } catch { /* wrong version or wrong passphrase; try the next */ }
  }
  if (!plain) {
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

/**
 * Where systemd drops credentials it has unsealed for us.
 *
 * `LoadCredentialEncrypted=` in the unit has systemd decrypt a sealed blob AS ROOT and place
 * the plaintext in a private tmpfs readable only by this service. That is the whole trick:
 * the broker never needs access to /dev/tpmrm0 or to the host key, and the sealed file on
 * disk is useless to anyone who copies it — on another machine the TPM will not unseal it,
 * and on this one it takes root.
 */
export const CREDENTIAL_NAME = 'wv-store-key';

export function systemdCredential(name = CREDENTIAL_NAME): Buffer | null {
  const dir = process.env.CREDENTIALS_DIRECTORY;
  if (!dir) return null;
  try {
    const buf = fs.readFileSync(path.join(dir, name));
    return buf.length >= 32 ? buf : null;
  } catch { return null; }
}

/** The sealed blob on disk. Written by the installer, read by systemd, never by us. */
export const sealedKeyPath = () => path.join(systemRoot(), 'store.key.cred');

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

## File: packaging/install-daemon.sh

```
#!/bin/sh
# The one privileged step: install the secret broker. Run it once per machine.
#
# The broker is the process that holds your agents' credentials. It gets its own account
# so that the agents — which run as you — cannot read what it holds.
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
case "$(uname -s)" in
  Linux) ;;
  *)
    echo "This installer is for Linux. The uid split is not available on $(uname -s) yet —" >&2
    echo "the daemon there runs as you, with the pre-split threat model. Nothing to install." >&2
    exit 1 ;;
esac
command -v systemctl >/dev/null 2>&1 || {
  echo "systemd not found. This installer is for systemd Linux; see the docs for other init systems." >&2
  exit 1
}

if [ "$MODE" = uninstall ]; then
  echo "Stopping and removing the secret broker (${UNIT_NAME})…"
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
echo "  1. create the system account '${ACCOUNT}' for the secret broker (no login, no home)"
echo "  2. create ${STATE_DIR}, mode 0700, owned by ${ACCOUNT}"
echo "  3. install ${UNIT_PATH}, which runs the broker: ${EXEC}"
echo "  4. enable and start the broker"
echo

# ── 1. the account ───────────────────────────────────────────────────────────
if id -u "$ACCOUNT" >/dev/null 2>&1; then
  # An existing account is NOT automatically the right account.
  #
  # If a human logs in as `wundervault` — their own uid, the uid their agents run as — then
  # skipping creation here chowns the credential store to that uid and starts the daemon as
  # them. The agent can then read the store and the daemon's memory, and the install prints
  # "Running. /var/lib/wundervault is now readable only by wundervault." The boundary is
  # gone and every message says it is there, which is worse than not installing at all.
  EXISTING_UID=$(id -u "$ACCOUNT")
  EXISTING_SHELL=$(getent passwd "$ACCOUNT" | cut -d: -f7)
  INVOKER_UID=""
  [ -n "${SUDO_UID:-}" ] && INVOKER_UID="$SUDO_UID"

  # The decisive test is NOT the uid number.
  #
  # An earlier version refused only uid >= 1000, on the assumption that below that means a
  # system account. That is a convention, not a rule — plenty of hosts have human logins at
  # uid 500 — and getting it wrong means running the daemon as the very account its agents
  # use, with the installer printing that the directory is readable only by wundervault.
  #
  # So: refuse if this is the account that invoked us, and refuse if it can log in. A
  # daemon account has no shell; if it has one, a person can become it, and everything this
  # phase builds rests on nobody being able to.
  if [ -n "$INVOKER_UID" ] && [ "$EXISTING_UID" = "$INVOKER_UID" ]; then
    echo "ERROR: '${ACCOUNT}' is the account you are running as (uid ${EXISTING_UID})." >&2
    echo "       The broker must not run as the account its agents run as — that is the" >&2
    echo "       entire boundary. Use a different account name for the daemon." >&2
    exit 1
  fi

  case "$EXISTING_SHELL" in
    */nologin|*/false) ;;
    *)
      cat >&2 <<EOM
ERROR: an account named '${ACCOUNT}' already exists with uid ${EXISTING_UID} and login
shell ${EXISTING_SHELL:-<none>}.

The broker's account must not be able to log in. This one can, so a person can become it
and read every credential the broker holds — while the install reports that the directory
is readable only by ${ACCOUNT}. That is worse than not installing at all.

If this account is meant to be the daemon's:
  sudo usermod -s /usr/sbin/nologin ${ACCOUNT}
If it belongs to a person or another service, the daemon needs a different name.
EOM
      exit 1 ;;
  esac

  if [ "$EXISTING_UID" -ge 1000 ] 2>/dev/null; then
    echo "NOTE: ${ACCOUNT} has uid ${EXISTING_UID}, which is usually a login range." >&2
    echo "      It has no login shell, so continuing." >&2
  fi
  echo "account ${ACCOUNT}: already exists (uid ${EXISTING_UID}, system account)"
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

# ── 2b. the sealed store key ─────────────────────────────────────────────────
#
# A random 32-byte key, sealed so that the file on disk is useless on its own.
#
# What this replaces: a key DERIVED from /etc/machine-id and the account's uid, with the
# salt stored beside the ciphertext. Every input to that is readable by anyone who can read
# the directory, so the key was recomputable — the directory mode was doing all the work and
# the encryption was decoration. Someone who walked off with the disk had everything.
#
# `systemd-creds encrypt` seals to the TPM where there is one, and to the root-only host key
# otherwise. Either way the blob does not open on another machine, and the broker never needs
# TPM access itself: systemd unseals it as root at start and hands it over through a private
# tmpfs (LoadCredentialEncrypted= in the unit).
SEALED_KEY="${STATE_DIR}/store.key.cred"
if [ -f "$SEALED_KEY" ]; then
  echo "store key: already sealed at ${SEALED_KEY}"
elif command -v systemd-creds >/dev/null 2>&1; then
  TPM_STATE=$(systemd-creds has-tpm2 2>/dev/null | head -1 || echo no)
  if head -c 32 /dev/urandom \
      | systemd-creds encrypt --name=wv-store-key - "$SEALED_KEY" 2>/dev/null; then
    chown "${ACCOUNT}:$(id -gn "$ACCOUNT")" "$SEALED_KEY"
    chmod 0600 "$SEALED_KEY"
    case "$TPM_STATE" in
      yes) echo "store key: sealed to this machine's TPM" ;;
      *)   echo "store key: sealed to the host key (no TPM found — still not portable,"
           echo "           but a disk copy plus root would open it)" ;;
    esac
  else
    echo "WARNING: could not seal a store key with systemd-creds." >&2
    echo "         The broker will fall back to a key derived from /etc/machine-id and its" >&2
    echo "         uid, which anyone able to read ${STATE_DIR} can recompute. The directory" >&2
    echo "         mode still protects it; the encryption does not." >&2
  fi
else
  echo "WARNING: systemd-creds not found, so the store key cannot be sealed." >&2
  echo "         The broker falls back to a derived, recomputable key. See the docs." >&2
fi

# ── 3. the unit ──────────────────────────────────────────────────────────────
# The template is shipped alongside this script and read from disk rather than written
# inline, so what lands in /etc/systemd/system is the file you reviewed in the repo.
sed "s|^ExecStart=.*|ExecStart=${EXEC}|" "$UNIT_SRC" > "$UNIT_PATH"

# No sealed key on this machine? Then the unit must not ask systemd for one: a missing
# credential source is fatal (243/CREDENTIALS), and a broker that will not start is worse
# than one running on the derived key and saying so.
if [ ! -f "$SEALED_KEY" ]; then
  sed -i '/^LoadCredentialEncrypted=wv-store-key:/d' "$UNIT_PATH"
  echo "unit: no sealed key, so the credential line was removed"
fi
chmod 0644 "$UNIT_PATH"
grep -q "^User=${ACCOUNT}\$" "$UNIT_PATH" || {
  echo "ERROR: the installed unit does not run as ${ACCOUNT}. Refusing to continue." >&2
  rm -f "$UNIT_PATH"; exit 1
}
echo "unit ${UNIT_PATH}: installed"

# ── 4. start ─────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
# restart, not `enable --now`. `--now` starts a stopped unit and leaves a RUNNING one
# exactly as it was — so re-running the installer after a package upgrade rewrote the unit,
# reported "Running", and left the old process going under the old configuration, including
# an ExecStart pointing at the previous binary.
systemctl restart "$UNIT_NAME"

sleep 1

# Did the sealing actually take EFFECT? Sealing a key and delivering it are separate things,
# and the gap between them is silent: systemd can set CREDENTIALS_DIRECTORY and still fail to
# materialise the file, which leaves the broker on the derived key while a sealed blob sits
# on disk looking like proof of something. Ask the broker what key it is actually using.
if [ -f "$SEALED_KEY" ] && systemctl is-active --quiet "$UNIT_NAME"; then
  sleep 1
  if journalctl -u "$UNIT_NAME" -n 20 --no-pager 2>/dev/null | grep -q "Store key: DERIVED"; then
    echo >&2
    echo "WARNING: a sealed key exists but the broker is NOT using it." >&2
    echo "         systemd did not deliver the credential — check:" >&2
    echo "           systemd-creds decrypt --name=wv-store-key ${SEALED_KEY} -" >&2
    echo "           journalctl -u ${UNIT_NAME} | grep -i credential" >&2
    echo "         The store is running on a key derived from /etc/machine-id and the" >&2
    echo "         broker's uid, which anyone able to read ${STATE_DIR} can recompute." >&2
    echo "         Do not describe this machine as having a sealed store." >&2
  fi
fi

if systemctl is-active --quiet "$UNIT_NAME"; then
  echo
  echo "The secret broker is running. ${STATE_DIR} is readable only by ${ACCOUNT},"
  echo "which means your agents cannot read the credentials it holds."
  echo
  echo "Next, as your normal user (no sudo):"
  echo "  wundervault-agent --migrate     # hand existing agents over to the daemon"
else
  echo
  echo "The secret broker did not start. What it said:" >&2
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
Description=Wundervault secret broker (holds agent credentials)
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
# The store key, unsealed by systemd (as root) and handed to this service in a private
# tmpfs at $CREDENTIALS_DIRECTORY. The broker therefore never touches /dev/tpmrm0 and never
# needs the host key; it just reads a file only it can see. Absent on a machine that could
# not seal one, in which case the broker falls back to a derived key and says so loudly.
LoadCredentialEncrypted=wv-store-key:/var/lib/wundervault/store.key.cred

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

## File: /tmp/claude-1000/-home-zee/0131dbc2-3fef-4799-a27b-babe9c4f7002/scratchpad/agent-key-extract.txt

```
EXTRACT of src/agent.ts — key handling and store migration only.
The rest of this 40KB file was reviewed in rounds 11-17 and is unchanged here.
Flag any finding that depends on code you were not shown.

--- lines 91-215 ---
91	      `  Expected User=${SYSTEM_ACCOUNT} in the unit file.\n` +
92	      `  If you installed by hand, re-run packaging/install-daemon.sh.`,
93	    );
94	    process.exit(1);
95	  }
96	}
97	
98	/**
99	 * The key the profile store is encrypted with.
100	 *
101	 * TWO MODES, AND THE DIFFERENCE IS THE WHOLE POINT.
102	 *
103	 * SEALED (preferred). systemd unseals a random 32-byte key for us — sealed to this
104	 * machine's TPM where there is one, to the root-only host key otherwise — and drops it in a
105	 * private tmpfs only this service can read. The key is not derived from anything; it is a
106	 * secret. Copy the disk to another machine and the store does not open, because the TPM
107	 * that sealed it is not there.
108	 *
109	 * DERIVED (fallback, and what this used to be exclusively). HKDF over
110	 * sha256(machine-id : uid) with a salt stored beside the ciphertext. Every input to that is
111	 * readable by anyone who can read the directory, so the key is RECOMPUTABLE: it is not a
112	 * secret, it is an obfuscation, and the directory mode was doing all the real work. That is
113	 * fine as defence in depth and was always described as such — it is not fine as the only
114	 * thing standing between a stolen disk and every credential on it.
115	 *
116	 * Both are supported because the fallback has to exist: no TPM, an older systemd, a
117	 * container, a hand-started broker. What must not happen is a machine silently sitting in
118	 * the weaker mode while the release notes describe the stronger one, so the mode in force is
119	 * reported at startup and by `ping`.
120	 */
121	type KeyMode = 'sealed' | 'derived';
122	
123	function legacyDerivedKey(): Buffer {
124	  let machineId = 'unknown';
125	  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
126	  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
127	  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();
128	
129	  let salt: Buffer;
130	  const sp = saltPath();
131	  if (fs.existsSync(sp)) {
132	    salt = fs.readFileSync(sp);
133	  } else {
134	    salt = crypto.randomBytes(32);
135	    ensureSystemRoot();
136	    fs.writeFileSync(sp, salt, { mode: 0o600 });
137	  }
138	  return crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
139	}
140	
141	function sealedKey(): Buffer | null {
142	  const raw = systemdCredential();
143	  if (!raw) return null;
144	  // Expanded rather than used raw, so the stored secret is never the working key and can be
145	  // re-purposed later (a second context string gives a second independent key).
146	  return crypto.hkdfSync(
147	    'sha256', raw, Buffer.alloc(0), Buffer.from('wundervault-store-v2'), 32,
148	  ) as unknown as Buffer;
149	}
150	
151	function deriveMachineKey(): { key: Buffer; mode: KeyMode } {
152	  const sealed = sealedKey();
153	  if (sealed) return { key: sealed, mode: 'sealed' };
154	  return { key: legacyDerivedKey(), mode: 'derived' };
155	}
156	
157	function encryptProfiles(store: ProfileStore, key: Buffer): Buffer {
158	  const nonce = crypto.randomBytes(12);
159	  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
160	  const encrypted = Buffer.concat([cipher.update(JSON.stringify(store), 'utf8'), cipher.final()]);
161	  return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
162	}
163	
164	function decryptProfiles(buf: Buffer, key: Buffer): ProfileStore {
165	  const nonce = buf.subarray(0, 12);
166	  const tag = buf.subarray(12, 28);
167	  const data = buf.subarray(28);
168	  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
169	  decipher.setAuthTag(tag);
170	  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
171	}
172	
173	/** Constant-time comparison of two hex tokens, safe against malformed input. */
174	export function tokenMatches(provided: string | undefined, expected: string | undefined): boolean {
175	  if (!expected) return false;          // no token configured: never a match
176	  if (!provided) return false;
177	  let a: Buffer, b: Buffer;
178	  try {
179	    a = Buffer.from(provided, 'hex');
180	    b = Buffer.from(expected, 'hex');
181	  } catch { return false; }
182	  // Length is compared first and separately on purpose: timingSafeEqual throws on a
183	  // length mismatch, and a thrown exception is a louder timing signal than the
184	  // comparison it was meant to protect.
185	  if (a.length === 0 || a.length !== b.length) return false;
186	  return crypto.timingSafeEqual(a, b);
187	}
188	
189	/**
190	 * Bad attempts, per agent name.
191	 *
192	 * The socket is world-connectable now, so any local process may knock. Guessing a 32-byte
193	 * token is not a real threat; an unbounded loop of connections is, and the log it would
194	 * produce is its own denial of service. A short lockout costs a legitimate agent one
195	 * retry after a genuine misconfiguration.
196	 */
197	/**
198	 * Make guessing expensive without letting a guesser deny the real agent.
199	 *
200	 * The first shape of this was a lockout: ten bad tokens for an agent name and that name
201	 * was refused for sixty seconds. Behind a 0600 socket that was defensible. It is not
202	 * defensible now — this phase made the per-agent sockets world-connectable, because the
203	 * daemon is a different uid and a 0600 socket it owns is one no agent could reach. So any
204	 * local process could send ten wrong tokens and take the LEGITIMATE agent off the air,
205	 * repeatedly, for as long as it liked. The mechanism meant to slow an attacker down had
206	 * become the cheapest attack available, and this phase is what introduced it.
207	 *
208	 * The rule now: a correct token is ALWAYS served. Nothing an attacker sends can change
209	 * what the holder of the real token gets back. The cost falls on the failing caller
210	 * instead, as a delay that doubles per consecutive failure — which is what actually
211	 * throttles guessing, since it is the attacker's own connection that has to wait.
212	 *
213	 * The delay is per agent name, and that is a deliberate, stated limit: a unix socket
214	 * carries no address to attribute failures to, and Node exposes no SO_PEERCRED to
215	 * identify the caller. So a persistent guesser does slow down a legitimate client that

--- lines 264-353 ---
264	
265	  /** 'sealed' when the key came from the TPM via systemd; 'derived' when it is recomputable. */
266	  keyMode: KeyMode = 'derived';
267	
268	  /**
269	   * A store we could not read is NOT an empty store.
270	   *
271	   * This used to log the failure and carry on with `this.profiles` still `[]`. The daemon
272	   * would come up serving nobody, which looks like a bad day — and then the first
273	   * enrolment called saveProfiles(), which wrote a store containing ONLY that profile,
274	   * over the ciphertext holding every other agent's credentials. A recoverable problem
275	   * (a changed /etc/machine-id, a recreated wundervault account, a damaged file — all of
276	   * which leave the plaintext retrievable) became permanent loss, silently.
277	   *
278	   * So a decrypt failure is now a refusal: the daemon will not serve and will not save
279	   * until a person has looked at it. Refusing to start is a visible, reversible failure.
280	   * Overwriting is neither.
281	   */
282	  private unreadableStore: string | null = null;
283	
284	  loadProfiles(): void {
285	    const pp = profilesPath();
286	    if (!fs.existsSync(pp)) { this.unreadableStore = null; return; }
287	    try {
288	      this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
289	      this.unreadableStore = null;
290	      return;
291	    } catch (err) {
292	      // Before giving up: a store written under the OLD derived key is not corrupt, it is
293	      // just addressed to a key we have stopped using. Try that key, and if it opens,
294	      // rewrite the store under the sealed one immediately. Migration has to be automatic —
295	      // an upgrade that leaves every existing install unable to start is not an upgrade, and
296	      // one that needs a manual step is one most people will not take.
297	      if (this.keyMode === 'sealed') {
298	        try {
299	          const viaLegacy = decryptProfiles(fs.readFileSync(pp), legacyDerivedKey()).profiles;
300	          this.profiles = viaLegacy;
301	          this.unreadableStore = null;
302	          this.saveProfiles();
303	          console.error(
304	            '[wundervault-agent] Re-sealed the profile store: it was encrypted with a key ' +
305	            'derived from public inputs, and is now sealed to this machine.',
306	          );
307	          // The old salt is no longer an input to anything. Leaving it implies otherwise.
308	          try { fs.unlinkSync(saltPath()); } catch { /* already gone */ }
309	          return;
310	        } catch { /* genuinely unreadable; fall through to the refusal below */ }
311	      }
312	      this.unreadableStore = (err as Error).message;
313	      this.profiles = [];
314	      console.error(
315	        `[wundervault-agent] Could not read the profile store at ${pp}: ${this.unreadableStore}\n` +
316	        `[wundervault-agent] It is encrypted against this machine's id and the daemon's uid.\n` +
317	        `[wundervault-agent] REFUSING to serve or to overwrite it. The credentials are still\n` +
318	        `[wundervault-agent] in that file; starting fresh would destroy them. Restore the file,\n` +
319	        `[wundervault-agent] or move it aside deliberately if you mean to start over.`,
320	      );
321	    }
322	  }
323	
324	  /** True when the store exists but could not be read. Nothing may be written in this state. */
325	  get storeUnreadable(): boolean { return this.unreadableStore !== null; }
326	
327	  saveProfiles(): void {
328	    if (this.unreadableStore) {
329	      throw new Error(
330	        `Refusing to write the profile store: it exists but could not be decrypted ` +
331	        `(${this.unreadableStore}). Writing now would replace every credential in it ` +
332	        `with only what is in memory.`,
333	      );
334	    }
335	    const pp = profilesPath();
336	    // Write-then-rename. A half-written store read after a crash decrypts to nothing and
337	    // every agent on the machine loses its credentials at once.
338	    const tmp = `${pp}.tmp-${process.pid}`;
339	    fs.writeFileSync(tmp, encryptProfiles({ profiles: this.profiles }, this.key), { mode: 0o600 });
340	    fs.renameSync(tmp, pp);
341	    try { fs.chmodSync(pp, 0o600); } catch { /* best effort */ }
342	  }
343	
344	  registerProfile(profile: AgentProfile): void {
345	    // The name becomes a path segment. It arrives over a socket any local process can
346	    // connect to, so "../../etc/cron.d/x" would otherwise have this daemon place a file
347	    // wherever it liked — which for the process holding the boundary is the whole game.
348	    profile.agent_name = safeName(profile.agent_name);
349	
350	    // Refuse before touching anything. Saving first was not enough on its own: by the time
351	    // saveProfiles() threw, the in-memory list had already been rewritten and the previous
352	    // agent's socket closed, so a rejected enrolment still took a working agent off the
353	    // air. The state a failure leaves behind has to be the state it started from.

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
