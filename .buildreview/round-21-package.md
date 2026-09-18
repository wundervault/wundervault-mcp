# Review package — round 21
generated 2026-09-18T15:14:54+00:00

## Spec — judge the build against THIS

# Phase 7 — the secret broker on macOS

Written 2026-09-18. Follows `SPEC-key-custody.md` (phase 5) and
`SPEC-phase6-server-enforcement.md` (phase 6). Ships in the same cutover as everything
from 16–18 September; nothing here deploys on its own.

Phase 4 gave the broker its own uid on Linux and said so out loud: `SPLIT_AVAILABLE =
process.platform === 'linux'`, and on every other platform the daemon keeps the pre-split
layout and prints a warning that its key material is readable by anything the owner runs.
That warning is currently true on macOS. This phase makes it false.

---

## 0. What the boundary is, and what it is not

**The boundary is a second uid.** A LaunchDaemon running as `_wundervault`, a state
directory at mode 0700 owned by that account, and agents that run as the owner and
therefore cannot open it. That is the same claim phase 4 makes on Linux, resting on the
same mechanism, and it is the only claim this phase makes.

**Rejected: Keychain ACLs as the boundary, in place of sudo.** `PLAN-local-shape-and-uid-
split.md` §B2 proposed trading a privileged install for code signing — a Keychain ACL
binds an item to a *signed binary*, so another program running as the same user cannot
read it. The mechanism is real and it does not reach us:

- An ACL records the **designated requirement** of the trusted executable. Our daemon is a
  JavaScript file that Node executes, so the identity recorded is **Node's**. Every agent
  on the machine runs as the owner and can also run Node, so `node -e '…'` satisfies the
  same ACL. It separates programs; it cannot separate two invocations of one interpreter.
- Making the ACL name *us* means shipping a signed, notarised standalone binary: an Apple
  Developer account, a signing identity in CI, and a distribution channel that is not npm.
  It also works against `/verify#installer`, which exists so a customer can read what they
  are installing.
- A process not on the ACL raises a **GUI consent prompt**. A headless LaunchDaemon cannot
  answer one.

The signed-binary path stays on the roadmap as **phase 9**, where it buys "which program",
not merely "which user" — a stronger claim than Linux makes. It is not a prerequisite for
uid separation and must not block it.

**Out of scope, and out of scope means unchanged:** Windows (phase 8) keeps the pre-split
shape and its warning, byte for byte.

---

## 1. Part A — the platform decision becomes observable and injectable

`SPLIT_AVAILABLE` is a module constant evaluated at import. No test can flip it, so the
macOS paths added by this phase would be unreachable from CI on Linux and verifiable only
by hand on one machine. That is how the port lock in Part D shipped broken.

**A1.** `platformShape()` returns `'linux' | 'darwin' | 'none'`, overridable for tests by
`WUNDERVAULT_PLATFORM_SHAPE`. It selects **paths and layout only**.

**A2.** `splitAvailable()` returns true only when the **real** `process.platform` is one
that supports a uid split AND the shape says so. The override can therefore make a Linux
box exercise the darwin *layout*; it can never make a platform claim a separation it
cannot perform.

**A3.** A new `boundaryIsReal()` reports on **observed facts**, not on the platform: the
state root exists, is mode 0700, is owned by our euid, and our euid is neither 0 nor the
uid of the invoking owner. `announceBoundary()` keys off this instead of off the platform.

> This closes a gap that predates macOS. On Linux today, a daemon started by hand with
> `WUNDERVAULT_SYSTEM_ROOT` pointed into the owner's home prints nothing at all, because
> the platform is Linux and the platform is all the check consults.

### Acceptance

1. With `WUNDERVAULT_PLATFORM_SHAPE=darwin` on Linux, `systemRoot()`, `runtimeDir()`,
   `mgmtSocketPath()` and `agentSocketPath()` return the macOS layout of §2.
2. With `WUNDERVAULT_PLATFORM_SHAPE=linux` and a stubbed real platform of `win32`,
   `splitAvailable()` is **false**. The override cannot manufacture a boundary.
3. `boundaryIsReal()` is false for a state root owned by the calling uid; true for one
   owned by another uid at 0700. Both directions asserted, with two uids.
4. `announceBoundary()` prints the pre-split warning whenever `boundaryIsReal()` is false,
   **including on Linux**, and prints nothing when it is true.
5. Sabotage: forcing `boundaryIsReal()` to return a constant `true` fails at least one
   test. Forcing `platformShape()` to a constant fails at least one test.

---

## 2. Part B — where daemon state lives on macOS

**B1. State root: `/var/lib/wundervault`, mode 0700, owned by `_wundervault`.** Same path
as Linux, deliberately: one path in the docs, one path in the support answers. `/var` is a
symlink to `/private/var` on macOS, so every check that compares a path against this root
must compare **realpaths**, not strings.

**B2. Runtime directory: `/var/lib/wundervault/run`.** macOS has no `/run`, and `/var/run`
is cleared at boot and not writable by the service account, so there is no analogue of
systemd's `RuntimeDirectory=`. The existing fallback inside `systemRoot()` is correct
here; it must be reached by the shape, not by an `existsSync` accident. Longest resulting
socket path is well inside the 104-byte `sun_path` limit on macOS — asserted, not assumed.

**B3. The store key.** Linux seals with `systemd-creds` (TPM where present, systemd's
root-only host key otherwise). macOS has neither. This phase writes a **random 32-byte key**
to `/var/lib/wundervault/store.key`, mode 0600, owned by the service account, created by
the installer under `umask 077`. `key_mode` is `local-file`.

> **What that is worth, stated exactly.** It is strictly better than the derived key,
> which is recomputable by anyone who can read the directory. It is *not* sealed: a copy
> of the disk plus root opens it. That is the same promise systemd's **host-key** tier
> makes, and the copy must use the same words rather than borrowing the TPM sentence.
> FileVault is what protects it against a stolen disk, so the installer reports
> `fdesetup status` and does not claim it. Secure Enclave sealing needs a signed binary →
> phase 9.
>
> The System keychain was considered as the store. It is root-only, so the daemon — which
> is deliberately not root — cannot read it without a privileged unseal step, and it lands
> on the same "same disk plus root" promise because `/var/db/SystemKey` is on that disk.
> Two mechanisms, one guarantee, one more moving part. Rejected.

**B4. A bug this uncovers.** The derived-key fallback reads `/etc/machine-id`, which does
not exist on macOS, and falls back to the literal string `unknown`. Every Mac running the
same uid therefore derives the **same** store key. On macOS the fallback must use the
hardware UUID (`IOPlatformUUID`); where no machine identity can be read at all, the daemon
must say so rather than proceeding on a shared constant.

### Acceptance

6. Under the darwin shape, `systemRoot()` is `/var/lib/wundervault` and `runtimeDir()` is
   `/var/lib/wundervault/run` — with no `/run` on the box and none consulted.
7. Every socket path the darwin shape can produce, for a 64-character agent name (the
   longest `safeName` permits), is ≤ 103 bytes.
8. Path containment checks resolve `/var/…` and `/private/var/…` to the same location; a
   test asserts a realpath comparison, not a prefix match.
9. The store key is read from `store.key` when present, `key_mode` is `local-file`, and
   the startup line for it says "not sealed" and names the disk-copy limit.
10. With no machine identity available, the derived fallback **refuses** rather than
    deriving from a constant. On darwin it derives from `IOPlatformUUID`, and two
    different UUIDs yield two different keys.
11. Sabotage: making `IOPlatformUUID` lookup return a fixed string fails check 10.

---

## 3. Part C — the account, the LaunchDaemon, and the installer

`packaging/install-daemon-macos.sh` and `packaging/com.wundervault.agent.plist`. The Linux
script's platform gate stops saying "nothing to install" on Darwin and points here.

**C1.** Creates group and user `_wundervault` with `dscl`, `UserShell=/usr/bin/false`,
`NFSHomeDirectory=/var/empty`, `IsHidden=1`, at the first free uid/gid in 200–400.

**C2.** Carries over **every refusal the Linux installer makes**, which are the checks that
keep the install from reporting a boundary it did not build:
- refuse if the account is the invoking user (`SUDO_UID`);
- refuse if the account has a usable login shell;
- refuse an ExecStart path under `/Users/` — on macOS this is not the `ProtectHome`
  argument, it is the stronger one: a directory writable by the owner means the daemon
  executes code its own agents can replace.

**C3.** The plist runs a **root wrapper** only if a privileged pre-step is ever needed; as
specified in B3 there is none, so `UserName`/`GroupName` are `_wundervault` directly,
`RunAtLoad`, `KeepAlive`, and `EnvironmentVariables` carrying `WUNDERVAULT_SYSTEM_ROOT`.

**C4.** The installer verifies, after `launchctl bootstrap`, that the running process is
**not root** and that the state directory is mode 0700 owned by the account — by asking the
daemon over the management socket, exactly as the Linux installer does, rather than by
grepping a log that can scroll.

**C5. What macOS does not give us, written into the plist as a comment and into
`/limitations`.** The systemd unit's sandboxing — `ProtectSystem=strict`, `ProtectHome`,
`ProtectProc`, `SystemCallFilter`, `CapabilityBoundingSet` — has **no launchd analogue**.
The uid split is the boundary on both platforms; on macOS the defence in depth around it is
thinner, and the daemon's filesystem reach is wider. Say so; do not imply parity.

### Acceptance

12. `--uninstall` removes the job and leaves the account and the state directory, with the
    same "to destroy them" instruction the Linux script prints.
13. Re-running the installer leaves the machine as one run does, including after the plist
    template changes (it must `bootout` then `bootstrap`, not assume a reload).
14. Running it twice does not create a second account or move the uid.
15. `shellcheck` clean, and the script parses under `sh` and `bash`.
16. Every refusal in C2 has a test that drives the **refusal**, not merely the success
    path → `feedback_a_passing_suite_does_not_prove_the_guard_is_there`.

---

## 4. Part D — the single-instance lock, which is broken on macOS today

`HANDOFF-lock-on-non-linux.md` records two assertions that fail on macOS CI and are gated
off. The cause is now identified and it is not `askHolder`.

**The candidates are derived into 49152–65535.** That is exactly macOS's default ephemeral
range (`net.inet.ip.portrange.first` = 49152), so an unrelated outbound connection
transiently owns a candidate. `tryBind` sees EADDRINUSE, `askHolder` gets no protocol
answer from a stranger, and the walk moves to the next candidate — by design. Claim 1
lands on candidate 1; candidate 0 is released moments later; claim 2 binds candidate 0 and
returns `ok: true`. **Two live holders of one credential, which is the control this module
exists to enforce.** Linux is unaffected because it binds an abstract socket and never
consults a port, and Linux's own ephemeral range (32768–60999) would not have collided
anyway.

**D1. One address, not eight.** The walk goes. A single port derived into **20000–32767**,
below the ephemeral range on macOS and Windows both, so the address is stable rather than
contended.

**D2. An occupied port is a hard error naming the port**, not a silent move to another
address — a stranger there is an operator problem with an operator-visible message, and
`WUNDERVAULT_LOCK_PORT` overrides it.

**D3.** The port path becomes reachable from Linux tests (`WUNDERVAULT_LOCK_STRATEGY=port`)
so the semantics are asserted on every CI run rather than on one platform.

**D4.** `test/lock.test.ts` drops its `LINUX_ONLY` gate for everything that is not
genuinely abstract-socket-specific.

### Acceptance

17. Under the port strategy on Linux, a second in-process `acquireCredential` while the
    first is held returns `ok: false` with a holder whose `source` is `'holder'`.
18. Under the port strategy, `whoHolds()` with no live holder returns `source:
    'lock-file'`.
19. A stranger occupying the derived port (a plain listener that speaks nothing) makes
    `acquireCredential` return `ok: false` with a `reason` naming the port — and **not**
    `ok: true` on some other port.
20. `WUNDERVAULT_LOCK_PORT` moves the address, and two processes with different overrides
    do not exclude each other.
21. The derived port is in 20000–32767 for 1000 random agent names — asserted over a
    sample, not on one name.
22. Sabotage: restoring the candidate walk fails checks 17 and 19.

---

## 5. Part E — the copy, which ships in the same push

Phase 7 makes several sentences newly true and several newly wrong. None of this ships
before the cutover, and all of it ships with it.

**E1.** `README.md` — "Linux is the verified platform. macOS works for secret delivery"
becomes a two-platform statement, with the phase-8 gap named.
**E2.** `README-AGENTS.md` — "every agent on **macOS and Windows** today" runs on the
unsigned path. macOS comes off that list once its agents are repaired; Windows stays.
**E3.** `RELEASE-HIGHLIGHTS.md` — "macOS and Windows brokers. Linux only." is now half
wrong.
**E4.** `burnbox/LIMITATIONS.md` — both directions: the new guarantee, and C5's honest
limit about launchd's missing sandbox.
**E5.** `HANDOFF-lock-on-non-linux.md` is resolved by Part D and is deleted, not left to
be read as open.
**E6.** `paths.ts`'s header comment documents the pre-split fallback as covering "macOS
and Windows". It covers Windows.

### Acceptance

23. No shipped file claims the broker is Linux-only.
24. No shipped file claims macOS has launchd hardening equivalent to the systemd unit.
25. `grep -rn "Linux only\|Linux-only"` over the shipped docs returns only statements that
    are still true (phase 8, and the sandboxing of C5).

---

## 6. What phase 7 does NOT close

- **A compromised broker**, unchanged from phase 6. It holds the private key.
- **One uid is one principal.** Two agents under the owner's uid cannot be told apart, by
  us or by the kernel, on either platform.
- **launchd has no sandboxing equivalent** to the systemd unit's. C5.
- **The store key is not sealed to hardware.** B3.
- **Agents are not migrated by installing.** Every macOS agent stays on the unsigned
  phase-6 path until it is repaired, one at a time, by the owner.
- **Windows.** Phase 8, unchanged and still warning.

---

## 7. How this is verified without a Mac

Parts A, B and D are exercised from Linux through the shape and strategy overrides, which
is the point of A1 and D3. Part C cannot be: `dscl` and `launchctl` do not exist here.

`packaging/verify-macos.sh` is therefore part of the deliverable — a script the owner runs
on the Mac that asserts checks 6, 7, 9, 12, 13, 14 and 17–20 **against the real install**
and prints a pass/fail line for each. Until it has been run on a Mac, phase 7 is BUILT and
UNVERIFIED on its target platform, and the handoff must say exactly that.


## What was built this round, and how it was tested

PHASE 7: the secret broker on macOS. THIS ROUND COVERS THE CODE ONLY — you are NOT being shown packaging/install-daemon-macos.sh, packaging/com.wundervault.agent.plist, or packaging/verify-macos.sh (payload cap; they go to round 22). Do not raise findings that depend on the installer's contents; DO flag anything in the code that implies a contract the installer must honour.

WHAT I BUILT
Part A: platform detection split in two. platformShape() ('linux'|'darwin'|'none', overridable via WUNDERVAULT_PLATFORM_SHAPE) decides WHERE THINGS GO. splitAvailableFor(realPlatform, shape) — pure — decides WHETHER a boundary is possible, and the REAL platform is a veto so the override can never manufacture one. New boundaryIsReal() reports on observed facts (dir exists, mode exactly 0700, owned by our euid, euid not 0, euid != SUDO_UID, and the root is NOT the pre-split location) instead of on process.platform. announceBoundary() now keys off boundaryIsReal().
Part B: macOS layout. systemRoot() /var/lib/wundervault; runtimeDir() /var/lib/wundervault/run (macOS has no /run; /var/run is wiped at boot and unwritable by the service account). New pure runtimeDirFor(shape, root, linuxRunExists). New isInside() resolves realpaths because /var is a symlink to /private/var on macOS. Store key: new 'local-file' KeyMode read from systemRoot()/store.key, sealKind() reports 'tpm'|'host'|'local-file'|null, each with its OWN startup sentence.
Part B4 (a bug found on the way): legacyDerivedKey() read /etc/machine-id, swallowed the failure, and fell back to the literal string 'unknown'. On macOS that file does not exist, so EVERY MAC derived the same store key (HKDF over sha256('unknown:501'), 501 being macOS's first uid). New machineIdentity() uses /etc/machine-id, then IOPlatformUUID via ioreg on darwin, then null. New derivedKeyFor(identity) for new stores; legacyDerivedKey() is KEPT verbatim, only for opening stores written before this (loadProfiles already has that fallback path). No identity at all => mode 'derived-shared', which does NOT refuse to start (that would make an existing install unrecoverable) but DOES refuse registerProfile().
Also fixed: crypto.hkdfSync returns ArrayBuffer and four call sites cast it 'as unknown as Buffer', so .length read undefined on values the code treats as Buffers. Now Buffer.from().
Part D: the single-instance lock. THE REAL BUG — it derived EIGHT candidate ports into 49152-65535 and walked them. That is exactly macOS's default ephemeral range (net.inet.ip.portrange.first = 49152), so an unrelated outbound socket transiently owns a candidate; claim 1 lands on candidate 1, candidate 0 frees, claim 2 binds candidate 0 and returns ok:true. TWO LIVE HOLDERS OF ONE CREDENTIAL. Now: ONE port derived into 20000-32767 (below the ephemeral range on macOS and Windows both), no walk, a stranger on the address is a hard refusal naming the port, WUNDERVAULT_LOCK_PORT overrides. lockStrategy() ('abstract'|'port') is overridable so the port path is exercised on Linux CI. Also procStart() returned null off Linux, making the PID-recycling check inert there; macOS now answers with 'ps -o lstart='.

HOW I TESTED IT
Full suite 496 passing (was 461). New: test/lock-port.test.ts (10), test/macos-shape.test.ts (14), test/machine-identity.test.ts (8).
EVERY fix was checked by SABOTAGE, not by a green suite:
- randomising addressPort (simulating the spread claim) => 3 lock tests fail
- putting the port back in 49152+ => 1 fails
- making a stranger cause a walk to the next port => 2 fail
- boundaryIsReal pinned to true => 5 shape tests fail
- isInside as a string prefix test => 1 fails
TWO SABOTAGES INITIALLY PASSED and I had to strengthen the tests: pinning platformShape() to 'linux', and deleting the darwin branch from runtimeDir(), both left the suite green — because on a box with no /run/wundervault the darwin branch and the Linux fallback return THE SAME STRING. I extracted runtimeDirFor() as a pure function so the DECISION is observable rather than only its result; both sabotages now fail.
Separately I replaced a source-grep test on the migration guard with a behavioural one (WUNDERVAULT_PLATFORM_SHAPE=none => status() and cleanup() reject). Removing BOTH guards fails it; removing only cleanup()'s changes no behaviour at all, because cleanup() calls status(), so I kept a narrow source assertion for that one and labelled it as the weaker check it is.

WHAT I HAVE NOT DONE
No Mac available yet, so nothing here has run on darwin. dscl/launchctl/ioreg are unexercised. packaging/verify-macos.sh is the acceptance script for that and is round 22's problem.

WHAT I WANT YOU TO ATTACK
1. Is splitAvailableFor's real-platform veto actually sufficient, or can WUNDERVAULT_PLATFORM_SHAPE be used by an AGENT (which runs as the owner, and does NOT control the daemon's environment) to weaken something?
2. boundaryIsReal: is there a state where it returns true and there is no boundary, or false where there is one? The pre-split case is handled; what else?
3. The lock: is ONE port with a hard refusal actually safe, or have I traded a concurrency bug for an availability bug that will bite someone at 20000-32767?
4. The store key migration: an existing macOS store is encrypted under the shared 'unknown' key. Is the loadProfiles legacy fallback enough to carry it across, and is re-saving under the new key the right move or a data-loss risk?
5. 'derived-shared' refusing enrolment but not startup — right call or a half-measure?

## Diff

```diff
diff --git a/src/agent.ts b/src/agent.ts
index 2c78768..93fcd94 100644
--- a/src/agent.ts
+++ b/src/agent.ts
@@ -32,12 +32,13 @@ import net from 'node:net';
 import fs from 'node:fs';
 import path from 'node:path';
 import crypto from 'node:crypto';
+import { execFileSync } from 'node:child_process';
 import { VERSION } from './version.js';
 import { redeemSetupLink, peekAgentName } from './enrol.js';
 import {
   systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
   runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
-  splitAvailable, systemdCredential, sealedWithTpm,
+  splitAvailable, systemdCredential, sealKind, boundaryIsReal,
 } from './paths.js';
 import { load as loadNetworkShape } from './network-store.js';
 import { BrokerOps } from './broker-ops.js';
@@ -105,13 +106,30 @@ interface ProfileStore {
  * does not try.
  */
 function announceBoundary(): void {
-  if (splitAvailable()) return;
+  if (boundaryIsReal()) return;
+
+  // Two different situations, and telling them apart is the whole value of the message.
+  if (!splitAvailable()) {
+    console.error(
+      `[wundervault-agent] Running on ${process.platform}, where the secret broker cannot\n` +
+      `[wundervault-agent] have its own account. State is in your own directory and it runs as\n` +
+      `[wundervault-agent] YOU — so its key material and memory are readable by anything you\n` +
+      `[wundervault-agent] run, including your agents. That is the pre-split threat model.`,
+    );
+    return;
+  }
+
+  // The platform CAN do this and the install has not been done — or has been undone. Said
+  // separately because the fix is a command, not a wait for a future release.
+  const installer = process.platform === 'darwin'
+    ? 'sudo sh packaging/install-daemon-macos.sh'
+    : 'sudo sh packaging/install-daemon.sh';
   console.error(
-    `[wundervault-agent] Running on ${process.platform}, where the secret broker cannot yet\n` +
-    `[wundervault-agent] have its own account. State is in your own directory and it runs as\n` +
-    `[wundervault-agent] YOU — so its key material and memory are readable by anything you\n` +
-    `[wundervault-agent] run, including your agents. That is the pre-split threat model.\n` +
-    `[wundervault-agent] The boundary is Linux-only for now.`,
+    `[wundervault-agent] No privilege boundary: ${systemRoot()} is not a 0700 directory\n` +
+    `[wundervault-agent] owned by a separate account, so this daemon is running as the same\n` +
+    `[wundervault-agent] user as the agents it serves. Its key material and memory are\n` +
+    `[wundervault-agent] readable by anything you run.\n` +
+    `[wundervault-agent]   ${installer}`,
   );
 }
 
@@ -151,24 +169,107 @@ function refuseRoot(): void {
  * the weaker mode while the release notes describe the stronger one, so the mode in force is
  * reported at startup and by `ping`.
  */
-type KeyMode = 'sealed-tpm' | 'sealed-host' | 'derived';
+type KeyMode = 'sealed-tpm' | 'sealed-host' | 'local-file' | 'derived' | 'derived-shared';
+
+/**
+ * This machine's identity, or null when it has none we can read.
+ *
+ * `/etc/machine-id` is a Linux file. On macOS the read fails, and the ORIGINAL code
+ * swallowed that and carried on with the literal string `unknown` — so the derived store
+ * key on a Mac was HKDF over sha256("unknown:501"), and 501 is the first account macOS
+ * creates. Every Mac in the world running this daemon derived the SAME store key. The
+ * fallback was documented as "recomputable by anyone who can read the directory"; on macOS
+ * it was computable by anyone who could read this source file.
+ *
+ * The macOS equivalent is the hardware UUID from the IOKit registry. It is not a secret
+ * either — nothing about the derived mode is — but it is per-machine, which is the entire
+ * property the derivation was supposed to have.
+ */
+export function machineIdentity(): string | null {
+  const override = process.env.WUNDERVAULT_MACHINE_ID;
+  if (override && override.trim()) return override.trim();
+
+  try {
+    const id = fs.readFileSync('/etc/machine-id', 'utf8').trim();
+    if (id) return id;
+  } catch { /* not linux, or a container without one */ }
+
+  if (process.platform === 'darwin') {
+    try {
+      const out = execFileSync('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], {
+        encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'],
+      });
+      const uuid = parseIOPlatformUUID(out);
+      if (uuid) return uuid;
+    } catch { /* no ioreg, or it failed */ }
+  }
+
+  return null;
+}
+
+/**
+ * Pull the hardware UUID out of ioreg's output.
+ *
+ * Separated from the exec so the parsing — the part that can silently return the wrong
+ * thing — is testable somewhere other than a Mac. A regex that quietly fails to match
+ * lands us straight back on the shared key, which is the bug this replaced.
+ */
+export function parseIOPlatformUUID(ioregOutput: string): string | null {
+  const m = ioregOutput.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
+  if (!m || !m[1]) return null;
+  // ioreg prints a canonical UUID. Anything else means the format moved and we should say
+  // we have no identity rather than derive a key from a surprise.
+  const v = m[1].trim();
+  return /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/.test(v)
+    ? v
+    : null;
+}
 
-function legacyDerivedKey(): Buffer {
+/**
+ * The OLD derived key, kept for ONE purpose: opening a store written before this changed.
+ *
+ * It contains the `unknown` constant deliberately. Removing it would leave every existing
+ * macOS store unopenable, which turns an upgrade into silent data loss — the failure mode
+ * this file already refuses elsewhere. New stores are never written under it.
+ */
+export function legacyDerivedKey(): Buffer {
   let machineId = 'unknown';
   try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
   const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
   const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();
 
-  let salt: Buffer;
+  // Buffer.from, not a cast: hkdfSync returns an ArrayBuffer, and the `as unknown as
+  // Buffer` this replaced made `.length` read undefined on a value the rest of the file
+  // treats as a Buffer. It happened to work because nothing asked.
+  return Buffer.from(crypto.hkdfSync(
+    'sha256', ikm, readOrCreateSalt(), Buffer.from('wundervault-agent-v1'), 32,
+  ));
+}
+
+function readOrCreateSalt(): Buffer {
   const sp = saltPath();
-  if (fs.existsSync(sp)) {
-    salt = fs.readFileSync(sp);
-  } else {
-    salt = crypto.randomBytes(32);
-    ensureSystemRoot();
-    fs.writeFileSync(sp, salt, { mode: 0o600 });
-  }
-  return crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
+  if (fs.existsSync(sp)) return fs.readFileSync(sp);
+  const salt = crypto.randomBytes(32);
+  ensureSystemRoot();
+  fs.writeFileSync(sp, salt, { mode: 0o600 });
+  return salt;
+}
+
+/**
+ * The derived key for a machine that HAS an identity. Same construction, real input.
+ *
+ * Shares the salt file with the legacy key deliberately: the salt is not the secret and a
+ * second salt would mean a second file to lose.
+ */
+export function derivedKeyFor(identity: string): Buffer {
+  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
+  const ikm = crypto.createHash('sha256').update(`${identity}:${uid}`).digest();
+  // Buffer.from, not a cast: hkdfSync returns an ArrayBuffer, and the `as unknown as
+  // Buffer` this replaced made `.length` read undefined on a value the rest of the file
+  // treats as a Buffer. It happened to work because nothing asked.
+  return Buffer.from(crypto.hkdfSync(
+    'sha256', ikm, readOrCreateSalt(), Buffer.from('wundervault-agent-v1'), 32,
+  ));
 }
 
 function sealedKey(): Buffer | null {
@@ -176,15 +277,31 @@ function sealedKey(): Buffer | null {
   if (!raw) return null;
   // Expanded rather than used raw, so the stored secret is never the working key and can be
   // re-purposed later (a second context string gives a second independent key).
-  return crypto.hkdfSync(
+  return Buffer.from(crypto.hkdfSync(
     'sha256', raw, Buffer.alloc(0), Buffer.from('wundervault-store-v2'), 32,
-  ) as unknown as Buffer;
+  ));
 }
 
 function deriveMachineKey(): { key: Buffer; mode: KeyMode } {
   const sealed = sealedKey();
-  if (sealed) return { key: sealed, mode: sealedWithTpm() ? 'sealed-tpm' : 'sealed-host' };
-  return { key: legacyDerivedKey(), mode: 'derived' };
+  if (sealed) {
+    const kind = sealKind();
+    const mode: KeyMode =
+      kind === 'tpm' ? 'sealed-tpm' : kind === 'local-file' ? 'local-file' : 'sealed-host';
+    return { key: sealed, mode };
+  }
+
+  const identity = machineIdentity();
+  if (identity) return { key: derivedKeyFor(identity), mode: 'derived' };
+
+  // No sealed key and no machine identity. The legacy derivation still works here, and it
+  // is the same value on every machine with this uid — so the store is readable by anyone
+  // holding a copy of the ciphertext and this source file.
+  //
+  // It does NOT refuse to start. A daemon that will not come up is how an existing install
+  // becomes unrecoverable, and the directory mode is still a real boundary. What it refuses
+  // is ENROLMENT: committing a NEW secret to a key that is not one.
+  return { key: legacyDerivedKey(), mode: 'derived-shared' };
 }
 
 function encryptProfiles(store: ProfileStore, key: Buffer): Buffer {
@@ -401,6 +518,17 @@ class AgentDaemon {
       );
     }
 
+    // A key that is identical on every machine with this uid is not a key. Existing agents
+    // keep working — pulling them off the air would be a worse answer than the one this
+    // refuses — but a NEW credential must not be committed to it.
+    if (this.keyMode === 'derived-shared') {
+      throw new Error(
+        `Refusing to enrol: this machine has no identity to derive a store key from, so ` +
+        `the key protecting the store is the same on every machine with this uid. ` +
+        `Install the broker, or set WUNDERVAULT_MACHINE_ID to a per-machine value.`,
+      );
+    }
+
     if (!profile.socket_token) {
       throw new Error(
         'A profile must carry a socket_token. The per-agent socket is world-connectable ' +
@@ -1065,6 +1193,24 @@ class AgentDaemon {
         '[wundervault-agent] WOULD open the store. It stops a casual file read, not a\n' +
         '[wundervault-agent] stolen disk. A TPM is what makes the disk copy useless.',
       );
+    } else if (this.keyMode === 'local-file') {
+      // macOS. Not sealed to anything, and deliberately NOT given the TPM sentence. What it
+      // is: a random key, so it cannot be recomputed. What it is not: protected against
+      // someone holding the disk. FileVault covers that and FileVault is not ours to claim.
+      console.log(
+        '[wundervault-agent] Store key: a random key in a 0600 file owned by this account.\n' +
+        '[wundervault-agent] It is NOT sealed to hardware — a copy of the disk plus root\n' +
+        '[wundervault-agent] WOULD open the store. It is not recomputable, which the old\n' +
+        '[wundervault-agent] derived key was. FileVault is what covers a stolen disk.',
+      );
+    } else if (this.keyMode === 'derived-shared') {
+      console.error(
+        '[wundervault-agent] Store key: DERIVED, and this machine has no identity to derive\n' +
+        '[wundervault-agent] from — so the key is THE SAME on every machine with this uid.\n' +
+        '[wundervault-agent] Anyone holding a copy of the store can open it without this\n' +
+        '[wundervault-agent] machine. Enrolment is refused until that is fixed: install the\n' +
+        '[wundervault-agent] broker, or set WUNDERVAULT_MACHINE_ID to something per-machine.',
+      );
     } else {
       console.error(
         '[wundervault-agent] Store key: DERIVED from machine-id and uid, which are not secret.\n' +
diff --git a/src/broker-sign.ts b/src/broker-sign.ts
index 73c4fcf..d4c3e9f 100644
--- a/src/broker-sign.ts
+++ b/src/broker-sign.ts
@@ -90,8 +90,8 @@ export class BrokerSigner {
 /**
  * A signer from this machine's broker identity, or null when there is no identity.
  *
- * Null is the honest answer on a machine that has never paired, and on macOS and Windows
- * until phases 7 and 8. The server accepts unsigned requests from an agent it has no
+ * Null is the honest answer on a machine that has never paired, and on Windows until
+ * phase 8. The server accepts unsigned requests from an agent it has no
  * broker bond for, so returning null degrades to the pre-split shape rather than breaking
  * — and the server, not this, is what decides which agents may take that path.
  */
diff --git a/src/lock.ts b/src/lock.ts
index 4e984e1..d896996 100644
--- a/src/lock.ts
+++ b/src/lock.ts
@@ -20,7 +20,7 @@
  *   Linux:  the ABSTRACT namespace (leading NUL). No filesystem entry exists,
  *           so there is nothing to delete and the delete-the-lock leak cannot
  *           happen rather than being defended against.
- *   Others: a loopback TCP port. A filesystem socket was tried and rejected —
+ *   Others: ONE loopback TCP port. A filesystem socket was tried and rejected —
  *           its pathname can be unlinked while it is still bound, after which a
  *           second process binds the same path and both serve, and recovering
  *           from a stale one means probe-then-unlink, which is itself a race.
@@ -29,6 +29,29 @@
  *           path is not a valid IPC address at all (\\.\pipe\... is) and the
  *           bind would simply fail, stranding a free credential.
  *
+ * WHY ONE PORT AND NOT EIGHT — A REAL BUG, NOT A TIDY-UP
+ *
+ * This used to derive EIGHT candidate ports and walk them, on the reasoning
+ * that a single derived port is a guess about a shared resource and an
+ * unrelated occupant should not read as "held". The reasoning was right; the
+ * range was not. The candidates landed in 49152-65535, which is exactly the
+ * DEFAULT EPHEMERAL RANGE ON macOS (net.inet.ip.portrange.first = 49152), so
+ * any outbound connection on the machine transiently owned one of them.
+ *
+ * The walk then did what it was told. Claim 1 finds candidate 0 momentarily
+ * taken by somebody's outbound socket, gets no protocol answer, and binds
+ * candidate 1. The ephemeral socket closes. Claim 2 starts at candidate 0,
+ * finds it free, and binds it. TWO LIVE HOLDERS OF ONE CREDENTIAL — the exact
+ * condition this module exists to prevent, arrived at by spreading the claim
+ * across eight addresses instead of one. It showed up as two flaky macOS CI
+ * assertions that were gated off as unexplained for a release.
+ *
+ * So: one port, derived into 20000-32767, which is below the ephemeral range on
+ * macOS and Windows both. A stranger there is now a HARD ERROR naming the port
+ * rather than a silent move to another address, because an operator can fix a
+ * port conflict they are told about and cannot fix a second holder they are
+ * not.
+ *
  * THE HOLDER ANSWERS FOR ITSELF
  *
  * The bound address is also how a blocked instance learns WHO holds it: the
@@ -49,6 +72,7 @@
 import { createHash, randomUUID } from 'node:crypto';
 import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
 import net from 'node:net';
+import { execFileSync } from 'node:child_process';
 import path from 'node:path';
 import os from 'node:os';
 
@@ -67,7 +91,22 @@ export interface Claim {
   reason?: string;
 }
 
-const IS_LINUX = process.platform === 'linux';
+/**
+ * Which primitive claims the credential.
+ *
+ * Overridable so the PORT path is reachable from Linux CI. It was not, which is why a
+ * concurrency bug in it survived four rounds of review on the abstract-socket path and was
+ * found only by a CI job on a platform nobody could reproduce on.
+ */
+export type LockStrategy = 'abstract' | 'port';
+
+export function lockStrategy(): LockStrategy {
+  const override = process.env.WUNDERVAULT_LOCK_STRATEGY;
+  if (override === 'abstract' || override === 'port') return override;
+  if (override) throw new Error(`WUNDERVAULT_LOCK_STRATEGY must be 'abstract' or 'port'.`);
+  // The abstract namespace is a Linux feature. Everywhere else, the port.
+  return process.platform === 'linux' ? 'abstract' : 'port';
+}
 
 export function agentName(): string {
   return process.env.WUNDERVAULT_AGENT_NAME || '';
@@ -107,35 +146,51 @@ function addressKey(): string {
 }
 
 /**
- * Deterministic loopback ports, as a CANDIDATE LIST rather than one number.
+ * ONE deterministic loopback port, in 20000-32767.
+ *
+ * The range is the fix. 49152-65535 is the default ephemeral range on macOS and on
+ * Windows, and Linux's is 32768-60999 — so a port derived below 32768 is not handed out to
+ * unrelated outbound connections on any of the three. What remains is a collision with a
+ * SERVICE that binds the same number, which is stable, diagnosable, and reported rather
+ * than worked around.
  *
- * A single derived port is a guess about a shared resource: the dynamic range
- * is 16,384 wide and anything on the machine may already own our number. Read
- * as "held", that turns an unrelated service into a permanent outage for a
- * credential nobody holds. So we try several, and EADDRINUSE alone never
- * settles it — the occupant is asked to identify itself, and only a real
- * holder stops the search.
+ * WUNDERVAULT_LOCK_PORT exists for that case, and for tests that need two claims on one
+ * machine not to exclude each other.
  */
-const PORT_CANDIDATES = 8;
-
-function addressPorts(): number[] {
+function addressPort(): number {
+  const override = process.env.WUNDERVAULT_LOCK_PORT;
+  if (override) {
+    const n = Number(override);
+    if (!Number.isInteger(n) || n < 1 || n > 65535) {
+      throw new Error(`WUNDERVAULT_LOCK_PORT=${JSON.stringify(override)} is not a port number.`);
+    }
+    return n;
+  }
+  // The port range is MACHINE-global, not per-user, so the uid belongs in the digest:
+  // without it two OS accounts on one box exclude each other over credentials they do not
+  // share.
   const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
   const digest = createHash('sha256').update(`wundervault-mcp:${uid}:${agentName()}`).digest();
-  const ports: number[] = [];
-  for (let i = 0; i < PORT_CANDIDATES; i++) {
-    ports.push(49152 + (digest.readUInt16BE(i * 2) % 16384));
-  }
-  return ports;
+  return 20000 + (digest.readUInt16BE(0) % 12768);
 }
 
+/** Exported for the test that asserts the range over a sample of names, not one name. */
+export { addressPort as _addressPortForTests };
+
 let held: net.Server | null = null;
 let identityLine = '';
-let heldPort: number | undefined;
 
-function listenOptions(port?: number): net.ListenOptions {
-  return IS_LINUX
+function listenOptions(): net.ListenOptions {
+  return lockStrategy() === 'abstract'
     ? { path: `\0wundervault-mcp-${addressKey()}` }
-    : { host: '127.0.0.1', port: port ?? addressPorts()[0] };
+    : { host: '127.0.0.1', port: addressPort() };
+}
+
+/** How to name the address in a message a person has to act on. */
+function addressLabel(): string {
+  return lockStrategy() === 'abstract'
+    ? `the abstract socket wundervault-mcp-${addressKey()}`
+    : `127.0.0.1:${addressPort()}`;
 }
 
 type BindResult =
@@ -143,7 +198,7 @@ type BindResult =
   | { status: 'in-use' }
   | { status: 'error'; message: string };
 
-function tryBind(port?: number): Promise<BindResult> {
+function tryBind(): Promise<BindResult> {
   return new Promise((resolve) => {
     const server = net.createServer();
     server.once('error', (err: NodeJS.ErrnoException) => {
@@ -153,7 +208,7 @@ function tryBind(port?: number): Promise<BindResult> {
           : { status: 'error', message: err.code || err.message },
       );
     });
-    server.listen(listenOptions(port), () => {
+    server.listen(listenOptions(), () => {
       server.unref();
       resolve({ status: 'bound', server });
     });
@@ -167,7 +222,7 @@ function closed(server: net.Server): Promise<void> {
 }
 
 /** Ask whoever holds the address who they are. */
-function askHolder(port?: number): Promise<Holder | null> {
+function askHolder(): Promise<Holder | null> {
   return new Promise((resolve) => {
     let buf = '';
     let settled = false;
@@ -177,7 +232,7 @@ function askHolder(port?: number): Promise<Holder | null> {
       try { sock.destroy(); } catch { /* ignore */ }
       resolve(h);
     };
-    const sock = net.connect(listenOptions(port) as net.NetConnectOpts);
+    const sock = net.connect(listenOptions() as net.NetConnectOpts);
     sock.setEncoding('utf8');
     sock.on('data', (d: string) => {
       buf += d;
@@ -210,15 +265,41 @@ interface CompatFile {
   start: string | null;
 }
 
-/** /proc/<pid>/stat field 22: start time in clock ticks since boot. */
+/**
+ * An identifier for THIS INCARNATION of a pid, so a recycled pid is not mistaken for the
+ * process that wrote the lock file.
+ *
+ * Linux: /proc/<pid>/stat field 22, start time in clock ticks since boot.
+ * macOS: `ps -o lstart=`, the process's start time to the second. There is no /proc, and
+ *        this returned null there — so on a Mac the recycling check was INERT and a
+ *        recycled pid refused a free credential until someone deleted the file by hand.
+ *        Second granularity is enough: a pid is not recycled and re-bound inside one
+ *        second, and a false MATCH is the safe direction anyway (we stand down).
+ *
+ * Anything else returns null, which the caller treats as "cannot tell" and fails closed.
+ */
 function procStart(pid: number): string | null {
-  if (!IS_LINUX) return null;
-  try {
-    const stat = readFileSync(path.join('/proc', String(pid), 'stat'), 'utf8');
-    return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19] ?? null;
-  } catch {
-    return null;
+  if (process.platform === 'linux') {
+    try {
+      const stat = readFileSync(path.join('/proc', String(pid), 'stat'), 'utf8');
+      return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19] ?? null;
+    } catch {
+      return null;
+    }
   }
+
+  if (process.platform === 'darwin') {
+    try {
+      const out = execFileSync('/bin/ps', ['-o', 'lstart=', '-p', String(pid)], {
+        encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'],
+      }).trim();
+      return out || null;
+    } catch {
+      return null;
+    }
+  }
+
+  return null;
 }
 
 function readCompatFile(): CompatFile | null {
@@ -313,49 +394,44 @@ function legacyHolder(): Holder | null {
 
 /** Who holds the credential right now, asked of the holder first. */
 export async function whoHolds(): Promise<Holder> {
-  const ports = IS_LINUX ? [undefined] : addressPorts();
-  for (const port of ports) {
-    const h = await askHolder(port as number | undefined);
-    if (h) return h;
-  }
+  const h = await askHolder();
+  if (h) return h;
   return holderFromFile();
 }
 
 export async function acquireCredential(version: string): Promise<Claim> {
-  const candidates: (number | undefined)[] = IS_LINUX ? [undefined] : addressPorts();
+  const result = await tryBind();
   let bound: net.Server | null = null;
-  let boundPort: number | undefined;
-
-  for (const port of candidates) {
-    const result = await tryBind(port);
-
-    if (result.status === 'bound') {
-      bound = result.server;
-      boundPort = port;
-      break;
-    }
 
-    if (result.status === 'in-use') {
-      // EADDRINUSE is not proof that OUR credential is taken — on a shared
-      // loopback range the occupant is usually somebody else entirely. Ask.
-      // Only a process that speaks our protocol is a holder; anything else is
-      // just in the way, so we move to the next candidate rather than
-      // reporting a free credential as held.
-      const who = await askHolder(port);
-      if (who) return { ok: false, holder: who };
-      continue;
-    }
-
-    // Some other bind error on this candidate; try the next one.
+  if (result.status === 'bound') {
+    bound = result.server;
+  } else if (result.status === 'in-use') {
+    // EADDRINUSE on OUR one address. Ask who is there: a process that speaks our
+    // protocol is the holder, and the caller is told who to stop.
+    const who = await askHolder();
+    if (who) return { ok: false, holder: who };
+
+    // A stranger. This used to move to another candidate port, and moving is what
+    // allowed two live holders — the second claim simply landed somewhere else and
+    // reported success. Refusing is the only answer that keeps one-agent-per-credential,
+    // and it is actionable in a way the silent move never was.
+    return {
+      ok: false,
+      holder: holderFromFile(),
+      reason:
+        `${addressLabel()} is occupied by something that is not a wundervault holder, ` +
+        `so the credential cannot be claimed safely. Free that address, or set ` +
+        `WUNDERVAULT_LOCK_PORT to move this agent's lock.`,
+    };
   }
 
   if (!bound) {
     return {
       ok: false,
       holder: await whoHolds(),
-      reason: IS_LINUX
-        ? 'could not claim the credential address'
-        : `every candidate port on 127.0.0.1 is occupied by something else (${addressPorts().join(', ')})`,
+      reason: `could not claim ${addressLabel()}: ${
+        result.status === 'error' ? result.message : 'unknown error'
+      }`,
     };
   }
 
@@ -387,7 +463,6 @@ export async function acquireCredential(version: string): Promise<Claim> {
   });
 
   held = bound;
-  heldPort = boundPort;
   return { ok: true };
 }
 
@@ -416,7 +491,6 @@ export function releaseCredential(): Promise<void> {
 
   const server = held;
   held = null;
-  heldPort = undefined;
   if (!server) return Promise.resolve();
 
   return new Promise<void>((resolve) => {
@@ -431,9 +505,8 @@ export function releaseCredential(): Promise<void> {
 /** Is the credential free right now? */
 export async function credentialIsFree(): Promise<boolean> {
   if (held) return false;
-  const candidates: (number | undefined)[] = IS_LINUX ? [undefined] : addressPorts();
-  for (const port of candidates) {
-    const result = await tryBind(port);
+  {
+    const result = await tryBind();
     if (result.status === 'bound') {
       // Wait for the probe socket to actually be gone. close() is asynchronous,
       // and this function's whole job is to answer a question the caller acts on
@@ -443,7 +516,7 @@ export async function credentialIsFree(): Promise<boolean> {
       await closed(result.server);
       return legacyHolder() === null;
     }
-    if (result.status === 'in-use' && (await askHolder(port))) return false;
+    if (result.status === 'in-use' && (await askHolder())) return false;
   }
   return false;
 }
@@ -458,11 +531,7 @@ export function describeHolder(h: Holder): string {
 }
 
 export function addressDescription(): string {
-  if (IS_LINUX) return `abstract socket wundervault-mcp-${addressKey()}`;
-  const ports = addressPorts();
-  return heldPort !== undefined
-    ? `127.0.0.1:${heldPort}`
-    : `127.0.0.1:${ports[0]} (+${ports.length - 1} fallbacks)`;
+  return addressLabel();
 }
 
 export function lockFileExists(): boolean {
diff --git a/src/migrate.ts b/src/migrate.ts
index 45aebeb..0c503af 100644
--- a/src/migrate.ts
+++ b/src/migrate.ts
@@ -69,7 +69,9 @@ export function legacyAgentNames(): string[] {
   const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
   const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();
   const salt = fs.readFileSync(legacy.salt());
-  const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
+  const key = Buffer.from(
+    crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32),
+  );
 
   const buf = fs.readFileSync(profilesPath);
   const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
@@ -133,26 +135,30 @@ export interface MigrationStatus {
 
 /** What still needs doing. Reads; changes nothing. */
 /**
- * Migration is a Linux-only operation, and saying so prevents data loss.
+ * Migration only means anything where there is a split to migrate TO, and saying so
+ * prevents data loss.
+ *
+ * Without one, systemRoot() returns the user's own directory, which means
+ * `profilesPath()` and `legacy.profiles()` are THE SAME FILE. Every agent the daemon knows
+ * about therefore appears "already across", nothing is pending, and `--migrate --finish`
+ * shreds the store the running daemon is actually using. A cleanup step that deletes the
+ * live credential file because it mistook it for a leftover is about the worst outcome
+ * available here, and it would have looked like a successful migration.
  *
- * Off Linux there is no split to migrate TO: systemRoot() returns the user's own directory,
- * which means `profilesPath()` and `legacy.profiles()` are THE SAME FILE. Every agent the
- * daemon knows about therefore appears "already across", nothing is pending, and
- * `--migrate --finish` shreds the store the running daemon is actually using. A cleanup
- * step that deletes the live credential file because it mistook it for a leftover is about
- * the worst outcome available here, and it would have looked like a successful migration.
+ * Linux and macOS both qualify since phase 7. Windows does not.
  */
-function refuseOffLinux(): void {
+function refuseWithoutSplit(): void {
   if (splitAvailable()) return;
   throw new Error(
-    `Migration is Linux-only. On ${process.platform} the daemon already stores credentials ` +
-    `in your own directory and there is nothing to move — the source and destination are ` +
-    `the same file, so continuing would delete the store this machine is using.`,
+    `Migration needs a secret broker with its own account, and ${process.platform} cannot ` +
+    `have one yet. The daemon here stores credentials in your own directory and there is ` +
+    `nothing to move — the source and destination are the same file, so continuing would ` +
+    `delete the store this machine is using.`,
   );
 }
 
 export async function status(): Promise<MigrationStatus> {
-  refuseOffLinux();
+  refuseWithoutSplit();
   const oldStorePath = legacy.profiles();
   const ping = await ask({ action: 'ping' }).catch((e) => {
     throw new Error(
@@ -328,7 +334,7 @@ export interface CleanupResult { deleted: boolean; oldUnitStopped: boolean; pend
  * way back except creating a new one.
  */
 export async function cleanup(): Promise<CleanupResult> {
-  refuseOffLinux();
+  refuseWithoutSplit();
   const st = await status();
   if (st.alreadyDone) {
     // The store is already gone, but the old unit may not be — an earlier --finish could
diff --git a/src/paths.ts b/src/paths.ts
index c08388b..806702c 100644
--- a/src/paths.ts
+++ b/src/paths.ts
@@ -8,11 +8,16 @@
  * writable by the party it described.
  *
  * The split moves daemon state to `/var/lib/wundervault`, mode 0700, owned by a system
- * account. The mode is the control. The at-rest encryption beside it is defence in depth
- * and nothing more — its key derives from the machine id, the uid and a salt file stored
- * next to the ciphertext, so anyone who can read the directory can recompute it. Calling
- * that "encrypted at rest" as though it were the boundary would repeat exactly the mistake
- * this phase exists to correct.
+ * account — `wundervault` under a systemd unit on Linux, `_wundervault` under a
+ * LaunchDaemon on macOS. The mode is the control. The at-rest encryption beside it is
+ * defence in depth and nothing more; calling it "encrypted at rest" as though it were the
+ * boundary would repeat exactly the mistake this phase exists to correct.
+ *
+ * ON macOS THE BOUNDARY IS THE SAME AND THE DEFENCE AROUND IT IS THINNER. The systemd unit
+ * carries ProtectSystem=strict, ProtectHome, ProtectProc=invisible, a system-call filter
+ * and an empty capability set. launchd has no equivalent for any of them, so the uid split
+ * there is very nearly the whole of it. Written down here and in /limitations rather than
+ * left for someone to infer parity that does not exist.
  *
  * TWO ROOTS, AND THEY ARE NOT THE SAME THING
  *
@@ -42,31 +47,83 @@ export const SYSTEM_ACCOUNT = 'wundervault';
  * daemon's environment.
  */
 /**
- * Is the uid split actually available here?
+ * Is the uid split actually available here, and which layout are we using?
  *
- * Phase 4 is Linux, and macOS (4b) and Windows (4c) are deliberately later. But OUT OF
- * SCOPE HAS TO MEAN UNCHANGED, not broken — and for two commits it meant broken. The
+ * Phase 4 was Linux; phase 7 adds macOS; Windows (phase 8) is deliberately later. But OUT
+ * OF SCOPE HAS TO MEAN UNCHANGED, not broken — and for two commits it meant broken. The
  * daemon's constructor calls ensureSystemRoot() unconditionally, so on macOS it tried to
  * mkdir /var/lib/wundervault as a normal user and died with EACCES where it had previously
  * used the home directory. On Windows it is quieter and worse: /var/lib/wundervault
  * resolves to C:\var\lib\wundervault, the mkdir SUCCEEDS, and the daemon then tries to
  * bind unix domain sockets there, which Windows does not have.
  *
- * Every non-Linux platform therefore keeps the pre-split layout exactly: state in the
- * user's own directory, daemon as the user. That is the old threat model, and the code
- * says so out loud rather than letting anyone infer a boundary that is not there.
+ * Windows therefore keeps the pre-split layout exactly: state in the user's own directory,
+ * daemon as the user. That is the old threat model, and the code says so out loud rather
+ * than letting anyone infer a boundary that is not there.
+ *
+ * TWO QUESTIONS, NOT ONE — AND KEEPING THEM APART IS THE POINT
+ *
+ * `platformShape()` decides WHERE THINGS GO. It is overridable, because otherwise the
+ * macOS layout is unreachable from CI on Linux and verifiable only by hand on one
+ * machine — which is precisely how the port lock in lock.ts shipped broken and stayed
+ * broken for a release.
+ *
+ * `splitAvailable()` decides WHETHER A BOUNDARY IS POSSIBLE. It consults the REAL
+ * platform, so the override can make a Linux box exercise the darwin paths but can never
+ * make a platform claim a separation it cannot perform.
+ *
+ * And neither of them is what we tell the user. That is `boundaryIsReal()`, below, which
+ * looks at the directory rather than at the operating system.
+ */
+export type PlatformShape = 'linux' | 'darwin' | 'none';
+
+/** Platforms on which a second uid is actually reachable. NOT overridable. */
+const SPLIT_CAPABLE = new Set(['linux', 'darwin']);
+
+function shapeFor(platform: string): PlatformShape {
+  if (platform === 'linux') return 'linux';
+  if (platform === 'darwin') return 'darwin';
+  return 'none';
+}
+
+/**
+ * Which layout to use. `WUNDERVAULT_PLATFORM_SHAPE` exists so a test on one platform can
+ * exercise another's paths. An unrecognised value is a typo, not a request for the
+ * pre-split layout, so it throws rather than silently dropping the boundary.
  */
-export const SPLIT_AVAILABLE = process.platform === 'linux';
+export function platformShape(): PlatformShape {
+  const override = process.env.WUNDERVAULT_PLATFORM_SHAPE;
+  if (override) {
+    if (override !== 'linux' && override !== 'darwin' && override !== 'none') {
+      throw new Error(
+        `WUNDERVAULT_PLATFORM_SHAPE=${JSON.stringify(override)} is not one of ` +
+        `linux, darwin, none.`,
+      );
+    }
+    return override;
+  }
+  return shapeFor(process.platform);
+}
 
-/** True where the daemon holds a real privilege boundary rather than merely tidy habits. */
+/**
+ * Pure, so the combination can be asserted directly rather than by stubbing a global.
+ *
+ * The real platform is the veto. A shape of 'linux' on Windows yields FALSE: the override
+ * relocates state, it does not conjure an account the operating system cannot give us.
+ */
+export function splitAvailableFor(realPlatform: string, shape: PlatformShape): boolean {
+  return SPLIT_CAPABLE.has(realPlatform) && shape !== 'none';
+}
+
+/** True where the daemon CAN hold a real privilege boundary. Not that it does. */
 export function splitAvailable(): boolean {
-  return SPLIT_AVAILABLE;
+  return splitAvailableFor(process.platform, platformShape());
 }
 
 export function systemRoot(): string {
   if (process.env.WUNDERVAULT_SYSTEM_ROOT) return process.env.WUNDERVAULT_SYSTEM_ROOT;
   // Off Linux there is no system account and no unit: the daemon is the user, as before.
-  if (!SPLIT_AVAILABLE) return userRoot();
+  if (!splitAvailable()) return userRoot();
   return DEFAULT_SYSTEM_ROOT;
 }
 
@@ -103,10 +160,34 @@ export function runtimeDir(): string {
   if (process.env.RUNTIME_DIRECTORY) return process.env.RUNTIME_DIRECTORY.split(':')[0];
   if (process.env.WUNDERVAULT_RUNTIME_DIR) return process.env.WUNDERVAULT_RUNTIME_DIR;
   // /run is a Linux thing, and so is the systemd RuntimeDirectory that manages it.
-  if (!SPLIT_AVAILABLE) return userRoot();
+  if (!splitAvailable()) return userRoot();
   const run = `/run/${SYSTEM_ACCOUNT}`;
-  try { if (fs.existsSync(run)) return run; } catch { /* fall through */ }
-  return path.join(systemRoot(), 'run');
+  let linuxRunExists = false;
+  try { linuxRunExists = fs.existsSync(run); } catch { /* treat as absent */ }
+  return runtimeDirFor(platformShape(), systemRoot(), linuxRunExists);
+}
+
+/**
+ * Pure, and pure for a reason that cost a round to learn.
+ *
+ * The darwin branch and the Linux fallback return THE SAME STRING on a box that has no
+ * /run/wundervault — which is every development box. So a test asserting the returned path
+ * passed whether the darwin branch was there or not: deleting it entirely left the suite
+ * green. What distinguishes the two is the DECISION, not the result, and a decision is only
+ * observable if the inputs can be supplied.
+ *
+ * macOS has no /run, and /var/run is cleared at boot and unwritable by the service account,
+ * so there is no analogue of systemd's RuntimeDirectory=. The runtime directory lives inside
+ * the state directory, which the account already owns.
+ */
+export function runtimeDirFor(
+  shape: PlatformShape,
+  root: string,
+  linuxRunExists: boolean,
+): string {
+  if (shape === 'darwin') return path.join(root, 'run');
+  if (linuxRunExists) return `/run/${SYSTEM_ACCOUNT}`;
+  return path.join(root, 'run');
 }
 
 /**
@@ -129,6 +210,11 @@ export function systemdCredential(name = CREDENTIAL_NAME): Buffer | null {
   const dir = process.env.CREDENTIALS_DIRECTORY;
   if (dir) candidates.push(path.join(dir, name));
   candidates.push(path.join(runtimeDir(), 'store.key'));
+  // macOS has no systemd and nothing that unseals on our behalf, so the installer writes a
+  // RANDOM key into the state directory at 0600, owned by the daemon account. It is not
+  // sealed and the startup report must not say it is — but it is not DERIVED either, which
+  // is the difference that matters: nobody can recompute it from public inputs.
+  if (platformShape() === 'darwin') candidates.push(storeKeyPath());
 
   for (const p of candidates) {
     try {
@@ -151,9 +237,38 @@ export function systemdCredential(name = CREDENTIAL_NAME): Buffer | null {
  * was being printed.
  */
 export function sealedWithTpm(): boolean {
-  return process.env.WUNDERVAULT_SEAL_KIND === 'tpm';
+  return sealKind() === 'tpm';
 }
 
+/**
+ * Which mechanism produced the store key, so the startup report can make the RIGHT promise.
+ *
+ *   'tpm'        — sealed to this machine's TPM. A copy of the disk does not open it.
+ *   'host'       — sealed to systemd's host key, which is on the same disk. Root plus a
+ *                  disk copy does open it.
+ *   'local-file' — macOS. A random key in a 0600 file owned by the daemon account. Same
+ *                  promise as 'host': not recomputable, not sealed to hardware. FileVault
+ *                  is what covers the stolen-disk case, and FileVault is not ours to claim.
+ *
+ * Three names because three different sentences are true, and the failure this codebase
+ * keeps having is one sentence being reused for a weaker mechanism.
+ */
+export type SealKind = 'tpm' | 'host' | 'local-file' | null;
+
+export function sealKind(): SealKind {
+  const declared = process.env.WUNDERVAULT_SEAL_KIND;
+  if (declared === 'tpm' || declared === 'host' || declared === 'local-file') return declared;
+  // Undeclared on darwin but the file is there: the installer wrote it and did not get to
+  // set the variable, or the daemon was started by hand. Report what is actually in use.
+  if (platformShape() === 'darwin') {
+    try { if (fs.statSync(storeKeyPath()).size >= 32) return 'local-file'; } catch { /* none */ }
+  }
+  return null;
+}
+
+/** The macOS store key: written by the installer, read by us, 0600 and never shared. */
+export const storeKeyPath = () => path.join(systemRoot(), 'store.key');
+
 /** The sealed blob on disk. Written by the installer, read by systemd, never by us. */
 export const sealedKeyPath = () => path.join(systemRoot(), 'store.key.cred');
 
@@ -188,10 +303,10 @@ export const networkStorePath = () => path.join(systemRoot(), 'network.json');
  * enrol, the agent's own token to remove. Nothing is protected by being hard to reach.
  */
 export const mgmtDir = () =>
-  SPLIT_AVAILABLE ? path.join(runtimeDir(), 'mgmt') : runtimeDir();
+  splitAvailable() ? path.join(runtimeDir(), 'mgmt') : runtimeDir();
 export const mgmtSocketPath = () => path.join(mgmtDir(), 'agent.sock');
 export const agentSocketPath = (name: string) =>
-  SPLIT_AVAILABLE
+  splitAvailable()
     ? path.join(runtimeDir(), `${safeName(name)}.sock`)
     : path.join(runtimeDir(), 'agents', `${safeName(name)}.sock`);
 
@@ -271,7 +386,7 @@ export function ensureSystemRoot(root = systemRoot()): void {
   // directory belongs to the same user the agents run as. Refusing to start over it off
   // Linux would block a daemon on a platform that never claimed the boundary — Windows in
   // particular reports modes that do not mean what they say.
-  if (!SPLIT_AVAILABLE) return;
+  if (!splitAvailable()) return;
   const mode = fs.statSync(root).mode & 0o777;
   if (mode !== 0o700) {
     throw new Error(
@@ -300,3 +415,79 @@ export function runningAsDaemonAccount(root = systemRoot()): boolean {
     return uid !== undefined && fs.statSync(root).uid === uid;
   } catch { return false; }
 }
+
+/**
+ * Is there ACTUALLY a boundary here, right now?
+ *
+ * Every other function in this file answers a question about the operating system. This
+ * one answers the question the user is actually asking, and it answers it by looking at
+ * the directory rather than at `process.platform`.
+ *
+ * The distinction is not academic. Before this existed, the startup warning keyed off the
+ * platform alone — so a daemon started by hand on Linux with WUNDERVAULT_SYSTEM_ROOT
+ * pointed into the owner's home printed NOTHING, while running as the same uid as the
+ * agents it served. The platform was Linux, and the platform was all the check consulted.
+ * The same shape of mistake on macOS would be a broker that had never been installed
+ * reporting a separation it did not have.
+ *
+ * Five things, all observed:
+ *   - the state root exists and is a directory;
+ *   - its mode is exactly 0700 — anything wider is not a boundary whatever owns it;
+ *   - it is owned by OUR euid, so we are the daemon account rather than a visitor;
+ *   - our euid is not 0, because root is not a boundary against anything, and is not the
+ *     uid that invoked us under sudo, because that is the owner's own account;
+ *   - the state root is NOT the pre-split location.
+ *
+ * That last one is not belt-and-braces, it is the check that makes the rest mean anything.
+ * Pre-split, state lives in the owner's own `~/.wundervault`, which ensureSystemRoot()
+ * chmods to 0700 — so it is a 0700 directory owned by the euid running the daemon, and the
+ * first four tests all pass while the agent and the daemon are the same account. The
+ * boundary is not "a private directory"; it is "a directory belonging to somebody the
+ * agent is not". When the state root IS the agent's own directory, there is nobody else.
+ */
+export function boundaryIsReal(root = systemRoot()): boolean {
+  const geteuid = (process as unknown as { geteuid?: () => number }).geteuid;
+  if (typeof geteuid !== 'function') return false; // Windows: no uids, no boundary.
+  const euid = geteuid.call(process);
+  if (euid === 0) return false;
+
+  // Running under `sudo` as the invoking user's own account is the one case that looks
+  // right from the inside and is not: the agent runs as that uid too.
+  const sudoUid = process.env.SUDO_UID ? Number(process.env.SUDO_UID) : NaN;
+  if (Number.isInteger(sudoUid) && sudoUid === euid) return false;
+
+  // The pre-split layout, which passes every other test here while being the exact thing
+  // this function exists to deny.
+  if (isInside(userRoot(), root) || isInside(root, userRoot())) return false;
+
+  try {
+    const st = fs.statSync(root);
+    if (!st.isDirectory()) return false;
+    if ((st.mode & 0o777) !== 0o700) return false;
+    return st.uid === euid;
+  } catch {
+    return false;
+  }
+}
+
+/**
+ * Does `child` live inside `parent`?
+ *
+ * Both sides are resolved before they are compared, because on macOS `/var` is a symlink
+ * to `/private/var`. `/var/lib/wundervault` and `/private/var/lib/wundervault` are the
+ * same directory, and a string prefix test says they are not — so a containment check
+ * written the obvious way passes on Linux, fails on a Mac, and fails in the direction that
+ * refuses legitimate paths rather than admitting illegitimate ones.
+ *
+ * Falls back to the unresolved path when a component does not exist yet: realpath throws
+ * on a path that is about to be created, and refusing to answer would be worse than
+ * answering about the lexical path.
+ */
+export function isInside(parent: string, child: string): boolean {
+  const resolve = (p: string) => {
+    try { return fs.realpathSync(p); } catch { return path.resolve(p); }
+  };
+  const p = resolve(parent);
+  const c = resolve(child);
+  return c === p || c.startsWith(p.endsWith(path.sep) ? p : p + path.sep);
+}

```

## File: test/lock-port.test.ts

```
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

/**
 * The PORT path of the single-instance lock, driven from Linux.
 *
 * This file exists because the port path was unreachable from CI on the only platform
 * anyone ran CI on. It shipped with a concurrency bug that four rounds of review on the
 * abstract-socket path could not have found, and the two macOS assertions that did catch
 * it were gated off as unexplained — see the deleted HANDOFF-lock-on-non-linux.md.
 *
 * The bug: eight candidate ports derived into 49152-65535, which is macOS's default
 * ephemeral range, walked until one bound. An unrelated outbound socket transiently owning
 * a candidate made the first claim land on candidate 1 and the second claim — finding
 * candidate 0 free again — land on candidate 0 and report SUCCESS. Two holders.
 *
 * Every test here fails against that implementation.
 */

const AGENT = `PortLockTest_${process.pid}_${Date.now()}`;

let home: string;
let lock: typeof import('../src/lock.js');
const realHomedir = os.homedir;
const saved: Record<string, string | undefined> = {};

function setEnv(k: string, v: string | undefined) {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
}

/** A port nothing is listening on, taken and released so the number is known-free. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen({ host: '127.0.0.1', port: 0 }, () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });
}

/** Something on the address that is NOT us: accepts, says nothing, never answers. */
function stranger(port: number): Promise<net.Server> {
  return new Promise((resolve, reject) => {
    const s = net.createServer(() => { /* accept and stay silent */ });
    s.once('error', reject);
    s.listen({ host: '127.0.0.1', port }, () => resolve(s));
  });
}

function closeServer(s: net.Server): Promise<void> {
  return new Promise((r) => { try { s.close(() => r()); } catch { r(); } });
}

beforeEach(async () => {
  home = mkdtempSync(path.join(os.tmpdir(), 'wv-portlock-'));
  (os as any).homedir = () => home;
  mkdirSync(path.join(home, '.wundervault'), { recursive: true });
  setEnv('WUNDERVAULT_AGENT_NAME', AGENT);
  setEnv('WUNDERVAULT_LOCK_STRATEGY', 'port');
  setEnv('WUNDERVAULT_LOCK_PORT', undefined);
  lock = await import('../src/lock.js');
});

afterEach(async () => {
  await lock.releaseCredential();
  (os as any).homedir = realHomedir;
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
  rmSync(home, { recursive: true, force: true });
});

describe('the port lock claims ONE address', () => {
  it('derives a port below the ephemeral range, for any agent name', () => {
    // 49152-65535 is ephemeral on macOS and Windows; 32768-60999 on Linux. A port derived
    // below 32768 is handed out by none of them. Asserted over a sample rather than on one
    // name, because the old range failed for every name and a single-name test would have
    // passed just as happily on a range that was wrong for most of them.
    setEnv('WUNDERVAULT_LOCK_PORT', undefined);
    for (let i = 0; i < 1000; i++) {
      setEnv('WUNDERVAULT_AGENT_NAME', `sample-${i}-${Math.random()}`);
      const port = lock._addressPortForTests();
      expect(port).toBeGreaterThanOrEqual(20000);
      expect(port).toBeLessThanOrEqual(32767);
    }
    setEnv('WUNDERVAULT_AGENT_NAME', AGENT);
  });

  it('gives the same agent the same port and different agents different ports', () => {
    setEnv('WUNDERVAULT_AGENT_NAME', 'alpha');
    const a1 = lock._addressPortForTests();
    setEnv('WUNDERVAULT_AGENT_NAME', 'beta');
    const b = lock._addressPortForTests();
    setEnv('WUNDERVAULT_AGENT_NAME', 'alpha');
    const a2 = lock._addressPortForTests();
    expect(a1).toBe(a2);
    expect(a1).not.toBe(b);
    setEnv('WUNDERVAULT_AGENT_NAME', AGENT);
  });

  it('refuses a second claim while the first is held, and names the holder', async () => {
    // THE regression. Against the candidate walk this returned ok: true whenever the first
    // claim had been pushed off candidate 0.
    const first = await lock.acquireCredential('test');
    expect(first.ok).toBe(true);

    const second = await lock.acquireCredential('test');
    expect(second.ok).toBe(false);
    expect(second.holder?.source).toBe('holder');
    expect(second.holder?.pid).toBe(process.pid);
  });

  it('reports the lock file when nobody answers the address', async () => {
    // The second assertion macOS CI failed. With no holder listening, whoHolds() must fall
    // back to the compatibility file rather than finding some other candidate's occupant.
    writeFileSync(
      path.join(home, '.wundervault', `mcp-${AGENT}.lock`),
      `4242\n${JSON.stringify({ pid: 4242, since: '2026-01-01T00:00:00.000Z', agent: AGENT })}\n`,
      'utf8',
    );
    const who = await lock.whoHolds();
    expect(who.source).toBe('lock-file');
    expect(who.pid).toBe(4242);
  });
});

describe('a stranger on the address is an error, not a detour', () => {
  it('refuses rather than binding somewhere else', async () => {
    // The old behaviour was to walk on. Walking on is what produced two holders: the
    // claim succeeded at a different address and the caller was told it held the
    // credential. Refusing is the only answer that preserves one-agent-per-credential.
    const port = lock._addressPortForTests();
    const squatter = await stranger(port);
    try {
      const claim = await lock.acquireCredential('test');
      expect(claim.ok).toBe(false);
      expect(claim.reason).toContain(String(port));
      expect(claim.reason).toMatch(/not a wundervault holder/);
    } finally {
      await closeServer(squatter);
    }
  }, 10_000);

  it('does not leave a claim behind after refusing', async () => {
    const port = lock._addressPortForTests();
    const squatter = await stranger(port);
    try {
      await lock.acquireCredential('test');
    } finally {
      await closeServer(squatter);
    }
    // The refusal must not have half-claimed: once the squatter is gone the address is
    // free and a real claim succeeds.
    const claim = await lock.acquireCredential('test');
    expect(claim.ok).toBe(true);
  }, 10_000);
});

describe('WUNDERVAULT_LOCK_PORT', () => {
  it('moves the address', async () => {
    const moved = await freePort();
    setEnv('WUNDERVAULT_LOCK_PORT', String(moved));
    const claim = await lock.acquireCredential('test');
    expect(claim.ok).toBe(true);
    expect(lock.addressDescription()).toBe(`127.0.0.1:${moved}`);
  });

  it('rejects a value that is not a port', () => {
    setEnv('WUNDERVAULT_LOCK_PORT', 'not-a-port');
    expect(() => lock._addressPortForTests()).toThrow(/not a port number/);
    setEnv('WUNDERVAULT_LOCK_PORT', '70000');
    expect(() => lock._addressPortForTests()).toThrow(/not a port number/);
  });
});

describe('the strategy is chosen, not assumed', () => {
  it('rejects an unrecognised strategy instead of silently picking one', () => {
    setEnv('WUNDERVAULT_LOCK_STRATEGY', 'sockets-maybe');
    expect(() => lock.lockStrategy()).toThrow(/must be/);
  });

  it('defaults to the abstract socket only on Linux', () => {
    setEnv('WUNDERVAULT_LOCK_STRATEGY', undefined);
    expect(lock.lockStrategy()).toBe(process.platform === 'linux' ? 'abstract' : 'port');
  });
});

```

## File: test/macos-shape.test.ts

```
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, chmodSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Phase 7: the macOS layout, exercised from Linux.
 *
 * The point of WUNDERVAULT_PLATFORM_SHAPE is that these paths are reachable in CI. Before
 * it existed, everything macOS-specific in this codebase was verifiable only by hand on
 * one machine, and the two things that were in that position — the port lock and the
 * derived store key — were both broken, one of them for every Mac in the world.
 */

let paths: typeof import('../src/paths.js');
const saved: Record<string, string | undefined> = {};

function setEnv(k: string, v: string | undefined) {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
}

beforeEach(async () => {
  paths = await import('../src/paths.js');
  setEnv('WUNDERVAULT_SYSTEM_ROOT', undefined);
  setEnv('WUNDERVAULT_RUNTIME_DIR', undefined);
  setEnv('RUNTIME_DIRECTORY', undefined);
  setEnv('WUNDERVAULT_PLATFORM_SHAPE', undefined);
});

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
});

describe('the shape override reaches the macOS layout', () => {
  it('puts daemon state and the runtime directory where macOS can have them', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'darwin');
    expect(paths.platformShape()).toBe('darwin');
    expect(paths.systemRoot()).toBe('/var/lib/wundervault');
    // macOS has no /run, and /var/run is cleared at boot and unwritable by the service
    // account. The runtime directory therefore lives inside the state directory.
    expect(paths.runtimeDir()).toBe('/var/lib/wundervault/run');
    expect(paths.mgmtSocketPath()).toBe('/var/lib/wundervault/run/mgmt/agent.sock');
    expect(paths.agentSocketPath('Claude 0512')).toBe('/var/lib/wundervault/run/Claude 0512.sock');
  });

  it('does not consult /run on the darwin shape even when one exists', () => {
    // Asserted on the DECISION, not the result. On a box with no /run/wundervault the
    // darwin branch and the Linux fallback return the same string, so deleting the darwin
    // branch left an earlier version of this test green. Supplying linuxRunExists=true is
    // what separates them.
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'darwin');
    expect(paths.platformShape()).toBe('darwin');
    expect(paths.runtimeDirFor('darwin', '/var/lib/wundervault', true))
      .toBe('/var/lib/wundervault/run');
    // …and the Linux shape, given the same inputs, does the opposite.
    expect(paths.runtimeDirFor('linux', '/var/lib/wundervault', true))
      .toBe('/run/wundervault');
    expect(paths.runtimeDirFor('linux', '/var/lib/wundervault', false))
      .toBe('/var/lib/wundervault/run');
  });

  it('keeps the Linux layout under the linux shape', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'linux');
    expect(paths.platformShape()).toBe('linux');
    expect(paths.systemRoot()).toBe('/var/lib/wundervault');
    expect(paths.mgmtSocketPath()).toMatch(/\/mgmt\/agent\.sock$/);
  });

  it('rejects an unrecognised shape rather than quietly dropping the boundary', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'macos');
    expect(() => paths.platformShape()).toThrow(/not one of/);
  });

  it('keeps every macOS socket path inside the 104-byte sun_path limit', () => {
    setEnv('WUNDERVAULT_PLATFORM_SHAPE', 'darwin');
    // safeName permits 64 characters, so that is the longest an agent socket can get.
    const longest = 'a'.repeat(64);
    expect(paths.agentSocketPath(longest).length).toBeLessThanOrEqual(103);
    expect(paths.mgmtSocketPath().length).toBeLessThanOrEqual(103);
  });
});

describe('the override cannot manufacture a boundary', () => {
  it('is false on a platform that has no second uid to offer, whatever the shape says', () => {
    // The shape relocates state. It does not conjure an account the OS cannot give us.
    expect(paths.splitAvailableFor('win32', 'linux')).toBe(false);
    expect(paths.splitAvailableFor('win32', 'darwin')).toBe(false);
    expect(paths.splitAvailableFor('win32', 'none')).toBe(false);
  });

  it('is true only where the real platform can actually do it', () => {
    expect(paths.splitAvailableFor('linux', 'linux')).toBe(true);
    expect(paths.splitAvailableFor('darwin', 'darwin')).toBe(true);
    // A capable platform told to use the pre-split layout still has no boundary.
    expect(paths.splitAvailableFor('linux', 'none')).toBe(false);
    expect(paths.splitAvailableFor('darwin', 'none')).toBe(false);
  });
});

describe('boundaryIsReal looks at the directory, not the operating system', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'wv-boundary-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('is true for a 0700 directory owned by us that is not our own agent directory', () => {
    const root = path.join(dir, 'state');
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    expect(paths.boundaryIsReal(root)).toBe(true);
  });

  it('is false when the directory is wider than 0700', () => {
    const root = path.join(dir, 'open');
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o755);
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    expect(statSync(root).mode & 0o777).toBe(0o755);
    expect(paths.boundaryIsReal(root)).toBe(false);
  });

  it('is false when the state root IS the pre-split location', () => {
    // The case that passes every other check while there is no boundary at all: the
    // daemon running as the owner, with its state in the owner's own directory at 0700.
    const root = path.join(dir, 'home');
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
    setEnv('WUNDERVAULT_USER_ROOT', root);
    expect(paths.boundaryIsReal(root)).toBe(false);
  });

  it('is false for a directory owned by somebody else', () => {
    // We are not that uid, so we are a visitor, not the daemon account.
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    const notOurs = statSync('/').uid === process.geteuid!() ? null : '/';
    if (notOurs) expect(paths.boundaryIsReal(notOurs)).toBe(false);
  });

  it('is false when the directory does not exist', () => {
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    expect(paths.boundaryIsReal(path.join(dir, 'nope'))).toBe(false);
  });

  it('is false when running as the account that invoked sudo', () => {
    const root = path.join(dir, 'state2');
    mkdirSync(root, { mode: 0o700 });
    chmodSync(root, 0o700);
    setEnv('WUNDERVAULT_USER_ROOT', path.join(dir, 'home'));
    setEnv('SUDO_UID', String(process.geteuid!()));
    expect(paths.boundaryIsReal(root)).toBe(false);
  });
});

describe('/var and /private/var are the same directory on macOS', () => {
  it('compares resolved paths, not string prefixes', () => {
    // A lexical prefix test says /private/var/lib/wundervault is not inside
    // /var/lib/wundervault. On a Mac they are the same directory, and the check would
    // refuse the daemon's own state root.
    const real = mkdtempSync(path.join(os.tmpdir(), 'wv-real-'));
    const sub = path.join(real, 'inner');
    mkdirSync(sub);
    try {
      expect(paths.isInside(real, sub)).toBe(true);
      expect(paths.isInside(real, real)).toBe(true);
      expect(paths.isInside(sub, real)).toBe(false);
      // The trap a prefix test falls into: a sibling whose name starts with the parent's.
      const sibling = `${real}-elsewhere`;
      mkdirSync(sibling);
      try {
        expect(paths.isInside(real, sibling)).toBe(false);
      } finally {
        rmSync(sibling, { recursive: true, force: true });
      }
    } finally {
      rmSync(real, { recursive: true, force: true });
    }
  });
});

```

## File: test/machine-identity.test.ts

```
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * The store key's derived fallback, and the identity it derives from.
 *
 * The bug this covers: `legacyDerivedKey` read `/etc/machine-id`, swallowed the failure,
 * and carried on with the literal string `unknown`. On macOS that file does not exist, so
 * the derived store key on every Mac was HKDF over sha256("unknown:501") — and 501 is the
 * uid macOS gives the first account it creates. The fallback was documented as
 * "recomputable by anyone who can read the directory". On a Mac it was computable by
 * anyone who could read this repository.
 */

let agent: typeof import('../src/agent.js');
let root: string;
const saved: Record<string, string | undefined> = {};

function setEnv(k: string, v: string | undefined) {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
}

beforeEach(async () => {
  root = mkdtempSync(path.join(os.tmpdir(), 'wv-ident-'));
  setEnv('WUNDERVAULT_AGENT_NO_AUTOSTART', '1');
  setEnv('WUNDERVAULT_SYSTEM_ROOT', root);
  setEnv('WUNDERVAULT_MACHINE_ID', undefined);
  agent = await import('../src/agent.js');
});

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
  rmSync(root, { recursive: true, force: true });
});

describe('parsing the hardware UUID out of ioreg', () => {
  // Real output, trimmed. Kept verbatim so a change in ioreg's format shows up here
  // rather than as a silently shared key on every Mac.
  const REAL = `+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000253, registered>
    {
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
      "IOPlatformUUID" = "4C4C4544-0051-4610-8051-B4C04F4D3332"
      "IOPlatformSerialNumber" = "C02XY0ABJGH5"
      "platform-name" = <"t8103">
    }`;

  it('finds the UUID', () => {
    expect(agent.parseIOPlatformUUID(REAL)).toBe('4C4C4544-0051-4610-8051-B4C04F4D3332');
  });

  it('returns null rather than a surprise when the format moves', () => {
    // Failing to match must mean "no identity", which is loud, rather than falling through
    // to a constant, which is silent and shared.
    expect(agent.parseIOPlatformUUID('nothing here')).toBeNull();
    expect(agent.parseIOPlatformUUID('"IOPlatformUUID" = ""')).toBeNull();
    expect(agent.parseIOPlatformUUID('"IOPlatformUUID" = "not-a-uuid"')).toBeNull();
    expect(agent.parseIOPlatformUUID('"IOPlatformSerialNumber" = "C02XY0ABJGH5"')).toBeNull();
  });
});

describe('the derived key is per-machine', () => {
  it('differs for two different machine identities', () => {
    // The property the old derivation was supposed to have and did not have on macOS.
    const a = agent.derivedKeyFor('4C4C4544-0051-4610-8051-B4C04F4D3332');
    const b = agent.derivedKeyFor('11111111-2222-3333-4444-555555555555');
    expect(a.length).toBe(32);
    expect(a.equals(b)).toBe(false);
  });

  it('is stable for one identity', () => {
    const a = agent.derivedKeyFor('4C4C4544-0051-4610-8051-B4C04F4D3332');
    const b = agent.derivedKeyFor('4C4C4544-0051-4610-8051-B4C04F4D3332');
    expect(a.equals(b)).toBe(true);
  });

  it('is not the key the old code would have used on a Mac', () => {
    // If these ever match, the identity is not reaching the derivation and every Mac is
    // back on one key.
    const real = agent.derivedKeyFor('4C4C4544-0051-4610-8051-B4C04F4D3332');
    const shared = agent.legacyDerivedKey();
    expect(real.equals(shared)).toBe(false);
  });
});

describe('machineIdentity', () => {
  it('honours an explicit per-machine value', () => {
    setEnv('WUNDERVAULT_MACHINE_ID', 'a-specific-machine');
    expect(agent.machineIdentity()).toBe('a-specific-machine');
  });

  it('ignores a blank override rather than deriving from empty', () => {
    setEnv('WUNDERVAULT_MACHINE_ID', '   ');
    expect(agent.machineIdentity()).not.toBe('   ');
  });

  it('never returns the string the old code fell back to', () => {
    expect(agent.machineIdentity()).not.toBe('unknown');
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
- [round 18 B1] deferred: No end-to-end test with a credential materialised by a working TPM
  reason: True and unavoidable here: the rehearsal container has no TPM firmware and could not materialise credentials at all under LoadCredentialEncrypted. The ExecStartPre path IS now verified in-container with host-key sealing, which exercises the same delivery and fallback logic; only the TPM branch is untested. Flagged for the owner's own machine, which does have a TPM.
- [round 18 B2] deferred: Backup and restore semantics for the sealed store are undefined
  reason: Real and worth a runbook entry: a backup of /var/lib/wundervault restored onto different hardware will not decrypt under a TPM-sealed key. The recovery path exists - repair each agent and re-enrol - but it is not written down. Belongs in RESTORE.md; noted for the owner rather than invented now.
- [round 18 B3] deferred: No procedure to rotate or reseal the store key before TPM maintenance
  reason: Same family as B2. The mechanism supports it (delete the blob, re-run the installer, let the store migrate) but there is no documented drill. Worth writing alongside B2.
- [round 19 B1] deferred: listEntries and settings forward API response objects with no output-field allowlist
  reason: Real and worth doing, but it is a change to what the server may send rather than to what this build introduced — the same fields crossed the same boundary before, in the agent's own process. Recorded for the user as an open item rather than changed under this spec.
- [round 19 B2] deferred: No cancellation propagation or per-agent operation queue after a client disconnects
  reason: Real. An authenticated caller can start expensive work and hang up. Out of scope for this spec, which is about key custody rather than resource control, and the caller is already authenticated — so this is a cost question, not a boundary one. Recorded as an open item.
- [round 19 B3] rejected: recordDestination runs before tier approval and the SSRF check, so a refused request is still recorded as a destination
  reason: Correct about the ordering and wrong about it being a defect — it is deliberate and documented at the call site. A first sighting recorded only on success would alert again on every retry of a tier-2 request the owner had not yet answered. The store records ATTEMPTS, which is what an exposure review needs; recording only deliveries would hide precisely the attempts worth looking at. The reviewer's underlying point — that the store's meaning should be stated — is fair, and the comment already says so.
- [round 19 B4] deferred: Decrypted credentials become immutable JS strings; only the byte buffers are wiped
  reason: True and unfixable in this language. Already recorded as a known limit in the phase-5 handoff for the browser side; the same applies in the broker. Wiping the buffers is worth doing anyway and is done. Noted for the user rather than pretended away.
- [round 20 F2] rejected: server.ts still sends the old {token} request, so every agent breaks against the new broker
  reason: Wrong in fact, and correctly hedged by the reviewer ('if src/server.ts remains as described'). server.ts WAS rewritten: getCredentials and tryDaemonConnect are gone, every tool handler calls src/broker-client.ts, which sends {token, op, ...}. Evidence: grep shows zero occurrences of decryptVaultKey/decryptSecretContent/loadEncryptionKey and zero of AgentVaultAPI in server.ts, and test/key-custody.test.ts asserts the whole tool surface over the new protocol. The diff was withheld from this package for the payload cap and the notes said so — this is the blind-spot-shaped finding that arrives when you withhold a file, which is why the notes ask for exactly that flagging.
