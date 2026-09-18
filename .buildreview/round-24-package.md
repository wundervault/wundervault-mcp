# Review package — round 24
generated 2026-09-18T20:41:48+00:00

## Spec — judge the build against THIS

# Phase 8 — the secret broker on Windows

Written 2026-09-18, after `SPEC-phase7-macos.md`. Joins the same unshipped cutover
(`project_wundervault_v2_cutover_plan`).

**Unlike phase 7, this one was measured on the target platform before a line was written.**
Every claim in §0 was observed on `win199` (Windows 10 22H2, build 19045.6466, Node
v22.23.2) on 2026-09-18, and the observations changed the design twice.

---

## 0. What is actually true on Windows today — measured, not assumed

These are the findings that set the scope. Each one is reproducible on win199.

**W1 — `npm install -g @wundervault/mcp-server` FAILS on Windows, and has since the first
public release.** `postinstall` is `chmod +x dist/agent.js dist/index.js 2>/dev/null ||
true`. cmd.exe runs it and dies:

```
npm error command C:\Windows\system32\cmd.exe /d /s /c chmod +x dist/agent.js dist/index.js 2>/dev/null || true
npm error The system cannot find the path specified.
npm error 'true' is not recognized as an internal or external command
npm error code 1
```

Verified against the **published** `@wundervault/mcp-server@latest` (1.7.2), not only the
working tree. npm then rolls the package directory back **but leaves the `wundervault-mcp`
and `wundervault-agent` shims on PATH**, so the documented next command fails with
`MODULE_NOT_FOUND` rather than "not installed". A customer following the install page on
Windows cannot get past step one, and the wreckage points them at the wrong problem.

**W2 — the daemon refuses to start on Windows.** `machineIdentity()` reads
`/etc/machine-id` (Linux) or `ioreg` (darwin) and has no Windows branch, so it returns
`null`. With no store key and no identity and no existing store, `keyModeFor()` returns
`refuse`. Observed:

```
[wundervault-agent] Refusing to start: there is no store key and this machine has no
identity to derive one from...
```

That branch arrived in phase 7 (`a1578f9`), whose spec said Windows stays **unchanged**.
The comment above `keyModeFor` — "the no-identity branch ... is unreachable on any machine
that has /etc/machine-id or ioreg, which is all of them" — is false. Windows has neither.

**W3 — the broker's sockets have never worked on Windows.** `net.Server.listen()` on a
filesystem path is not a thing on Windows; libuv wants a named pipe. Observed:

```
listen EACCES: permission denied C:\Users\Zack\.wvprobe\probe.sock
```

`server.ts` has no fallback: every tool call goes through `brokerClient()`. So even past
W1 and W2, every Windows install is a broker that cannot be reached. **Named pipes and
loopback TCP both work.**

**W4 — a named pipe created by Node is NOT reachable by a non-administrator.** libuv calls
`CreateNamedPipeW` with a NULL security descriptor and Node exposes no way to supply one.
Measured with three accounts: pipe server as the non-admin local account `wvprobe`, then

- client as `Zack` (a **local administrator**): `connect=OK`, round trip `PONG`;
- client as `wvclient` (non-admin, no groups but Users): **`EPERM: connect`**.

The first result is the trap: it succeeds only because the client is an administrator. A
design validated on an admin account would ship an agent transport that breaks for every
customer whose agents run unprivileged — and "it works on my machine" would be literally
true. **This killed named pipes as the transport.**

**W5 — `chmod` is a no-op.** `fs.chmodSync(p, 0o600)` then `statSync(p).mode & 0o777`
returns `666`; a directory chmod'd 0700 also reads `666`; `statSync().uid` is `0`. Every
mode-based check in `paths.ts` is meaningless here, which `ensureSystemRoot` already half
knew ("Windows in particular reports modes that do not mean what they say").

**W6 — an NTFS ACL IS a real boundary.** A directory with inheritance removed, granted to
`{the account, SYSTEM, Administrators}` only, read from the non-admin `wvclient`:

```
READ DENIED: UnauthorizedAccessException: Access is denied
LIST DENIED: Access to the path ... is denied
```

This is the Windows equivalent of mode 0700 and it is what phase 8 builds on.

**W7 — the SMBIOS UUID on real hardware can be degenerate.** win199 reports
`00000000-0000-0000-0000-AC1F6B1C4252`: twelve zero bytes and the NIC's MAC. It is still
unique to the machine, but the naive "use `Win32_ComputerSystemProduct.UUID`" answer walks
straight back into the macOS bug on any board that reports all-zeros or all-FFs. The
identity must combine sources and reject degenerate ones.

**W8 — `process.getuid()` is `undefined`, so the `?? 0` fallbacks make every Windows
account the same principal.** `lock.ts` derives its port from `sha256("wundervault-mcp:" +
uid + ":" + agentName)` and says in a comment that the uid is there so "two OS accounts on
one box [do not] exclude each other over credentials they do not share". On Windows every
account gets uid 0, so that is exactly what happens. The same `?? 0` is in
`legacyDerivedKey()` and `derivedKeyFor()`.

**W9 — a scheduled task running as a dedicated account needs `SeBatchLogonRight`, and
`schtasks` does not grant it.** Observed: `WARNING: The task is registered, but may fail to
start. Batch logon privilege needs to be enabled for the task principal.` The task silently
does nothing until the right is granted (via `secedit /export` + `/configure`, which
worked).

**W10 — non-ASCII in the daemon's console output mojibakes.** The em-dash in the startup
warning rendered as `?"` on the Windows console.

---

## 1. What phase 8 claims when it is done

The same claim as Linux and macOS, by the same mechanism, with one difference stated out
loud: **the secret broker runs as its own account, and the account the agents run as
cannot open its state directory.**

The boundary is an **NTFS ACL** rather than a file mode (W5, W6). Its strength against an
administrator is the same as 0700's against root: none. That is not new and is already how
`/limitations` describes Linux.

**Out of scope, and out of scope means unchanged:** Linux and macOS behaviour, the wire
protocol over unix sockets, the server side, pairing, re-key, and the phase-9 signed-binary
work.

---

## 2. Design decisions, and why the measurements forced them

### 2.1 Transport: loopback TCP with a daemon-owned discovery file

Named pipes are out (W4). The remaining in-box option is loopback TCP, and it lands on the
model this codebase already argues for in `paths.ts`: *"the sockets are world-connectable
and the TOKEN is the identity. Nothing is protected by being hard to reach — so nothing
legitimate may be made hard to reach either."* A 0666 unix socket and a 127.0.0.1 port have
the same exposure: any local process can connect, and the token decides what it gets.

The daemon binds `127.0.0.1:0` — an OS-assigned port, not a derived one. **Deriving the
port is the macOS lock bug waiting to happen again** (`SPEC-phase7-macos.md` §: eight
candidates landing inside the ephemeral range, two live holders of one credential), and a
derived port has a birthday bound that an OS-assigned one does not.

Discovery is a file in the run directory, which the daemon owns and everyone can read:

```
%ProgramData%\wundervault\run\mgmt.port
%ProgramData%\wundervault\run\<agent>.port     {"port":51234,"pid":9876,"server_id":"<hex>"}
%ProgramData%\wundervault\run\broker.pub       base64 SPKI of the broker's P-256 key
```

**Squatting, stated precisely.** A rogue local process cannot write the discovery file (the
run directory is daemon-write-only), so it cannot redirect an agent to itself while the
daemon is up. It CAN bind a port the daemon has released after a crash, and answer as the
broker. On Linux that is not possible, because the socket path lives in a directory only
the daemon can write — so this is one axis on which a port is weaker than a path.

It is closed rather than documented away, because the machinery already exists. Before an
agent sends its token it sends a nonce; the daemon answers with an ECDSA-P-256 signature
over `wv-broker-hello-v1:<nonce>:<port>:<server_id>` made with the broker identity key from
phase 6, and the agent verifies it against `broker.pub`. A squatter holds no private key,
so the agent refuses and says the broker is not running rather than handing over a
credential.

**This handshake is Windows-only.** The unix-socket path is untouched, on purpose: a change
to the transport on all three platforms to fix a Windows-only hole is how a phase that was
supposed to leave two platforms unchanged breaks them.

**What the handshake does NOT buy.** A rogue running as the owner can already read every
agent's token out of `%USERPROFILE%\.wundervault\agents\*.token`, because all agents run as
the owner — "one uid is one principal", unchanged from phase 6 and 7. The handshake stops a
stale port being answered by a stranger; it does not make one agent safe from another.

### 2.2 Hosting: a scheduled task, not a Windows service

A real Windows service must implement the Service Control Handler and answer the SCM within
30 seconds. `node.exe` does not, so `sc create` on it produces error 1053. Every route to a
real service goes through a third-party wrapper binary (WinSW, NSSM, `node-windows`), which
means shipping an executable a customer cannot diff — directly against `/verify#installer`,
where the whole trust story is "the installer is one readable file, mirrored on GitHub".

So: a **Scheduled Task** with an `AtStartup` trigger, running as the dedicated account at
`Limited` run level. It needs `SeBatchLogonRight` granted explicitly (W9). It brings one
thing launchd could not offer — a restart count with a give-up limit, so the
`ConfigurationRefusal` spin that had to be engineered around on macOS cannot happen here.

A real service, under the signed binary, is **phase 9's** business.

### 2.3 Machine identity: two sources, combined, degenerate values rejected

`identity = sha256("wv-win:" + <smbios uuid or ""> + ":" + <MachineGuid or "">)`, where a
source is dropped if it is absent or degenerate (all-zero, all-FF, or a known placeholder).
If both drop out, identity is `null` and the existing `refuse` logic applies — correctly
this time, because it will be a real absence rather than a missing branch.

Combining rather than choosing is the answer to W7: `MachineGuid` travels with a disk image
(the macOS `/etc/machine-id` lesson) and the SMBIOS UUID can be degenerate, but a machine
where **both** fail is rare and is told the truth rather than silently sharing a key.

### 2.4 Principal: a SID-shaped id, not `uid ?? 0`

`principalId()` returns the uid on POSIX and the current account's **SID** on Windows,
falling back to the lowercased username if the SID cannot be read. Every `getuid?.() ?? 0`
in `lock.ts`, `legacyDerivedKey()` and `derivedKeyFor()` routes through it.

`legacyDerivedKey()` is the exception and must stay **bit-for-bit as it is** — it exists
only to open a store written under the old derivation, and "fixing" it makes existing
stores unopenable. The Windows case is handled by never writing a new store under it.

### 2.5 `boundaryIsReal()` on Windows checks the ACL, because the mode is a lie

uid and mode are both unavailable (W5). The Windows branch asserts, all observed:

- we are running as the expected account **by name** (`WUNDERVAULT_SYSTEM_ACCOUNT`, else
  `wundervault`);
- the state root exists, and is **not** the pre-split location;
- `icacls` on the state root shows inheritance disabled and grants **only** principals in
  `{the account, SYSTEM, Administrators, TrustedInstaller}` — anything else, including
  `Users`, `Authenticated Users` or `Everyone`, means no boundary.

The `icacls` call is a subprocess at startup, once. It is the actual check rather than a
proxy for it, which is the property phase 7 had to learn twice.

---

## 3. Layout

```
%ProgramData%\wundervault           read+traverse for everyone; holds nothing readable
%ProgramData%\wundervault\state     THE BOUNDARY — account + SYSTEM + Administrators only
%ProgramData%\wundervault\run       everyone reads; only the account writes
%USERPROFILE%\.wundervault          each agent's own: its token, and nothing that matters
```

Run is a **sibling** of state, never a child — the same reason as macOS, for a different
mechanism: agents must reach the discovery files, and the state ACL denies them.

---

## 4. Acceptance checks

Numbered so a review round can be answered against them rather than against a vibe. Checks
marked **[win199]** must be observed on the real box; the rest must pass in CI on Linux via
`WUNDERVAULT_PLATFORM_SHAPE=windows`.

**Install and start**

1. `npm install -g <tarball>` on Windows exits **0**, with no `chmod` and no `|| true`.
   **[win199]**
2. The same install on Linux and macOS still sets the executable bit on `dist/agent.js` and
   `dist/index.js`.
3. `wundervault-agent` on a fresh Windows box with no broker installed **starts** and
   serves, printing the pre-split warning — it does not refuse. **[win199]**
4. `machineIdentity()` on Windows returns a stable non-null value across two runs, and it
   is not the value any other machine would produce. **[win199]**
5. `machineIdentityFromSources(smbios, machineGuid)` — pure — returns `null` when both
   sources are absent or degenerate, and drops a degenerate source while keeping a good
   one. Asserted for all-zero, all-FF, the win199 value, and a normal value.

**Transport**

6. With no broker installed, an agent on Windows completes a real tool call against a
   daemon running as the same user. **[win199]**
7. The daemon writes `<agent>.port` and `mgmt.port` containing the port it actually bound,
   and **deletes them on clean exit**.
8. A daemon that cannot bind, or cannot write a discovery file, **refuses loudly** and does
   not fall back to another port.
9. An agent whose discovery file names a port answered by a process that cannot produce the
   broker's signature **refuses and reports the broker as unavailable** — it does not send
   its token. Driven by standing up a fake listener on the named port.
10. The handshake is Windows-only: with shape `linux` or `darwin`, no nonce is sent and the
    unix-socket path is byte-for-byte what it was before this phase.

**The boundary**

11. **[win199]** With the broker installed, a **non-administrator** account that is not the
    service account is denied read and list on `%ProgramData%\wundervault\state`. Two
    accounts, one denied, observed — not inferred from the ACL text.
12. **[win199]** That same non-administrator account **can** read the run directory,
    connect to the daemon, and complete a tool call with its own token.
13. `boundaryIsReal()` returns **false** on Windows when: the state root is the pre-split
    location; or we are not running as the expected account; or the ACL grants any
    principal outside the allowed set; or inheritance is enabled; or inheritance is merely
    **unused rather than switched off** (`AreAccessRulesProtected` is false); or the
    directory's **owner** is outside the allowed set — an owner holds `WRITE_DAC`
    implicitly, so a directory owned by the agents' account is one they can unlock.
    *(The last two added after review round 23.)*
14. `boundaryIsReal()` returns **true** only in the installed configuration. **[win199]**
15. Granting `Users:(R)` on the state root after a correct install flips check 13 to false
    at the next start. **[win199]**

31. A second broker **refuses to start** while one is already serving. On a unix socket
    this is free — two daemons cannot bind one path — and on a port it is not: `listen(0)`
    always succeeds, so the second daemon overwrote the first's discovery files and took
    every agent with it. *(Added after review round 23; observed during this phase's own
    testing, when a mistyped flag started a second broker.)*
32. An **unrecognised option** does not start a broker. *(Added after review round 23.)*
33. The hello handshake decodes **no partial UTF-8**: bytes that arrive with the banner are
    handed on as bytes, never through a string round trip. *(Added after review round 23.)*
34. A connection that never completes the handshake is **closed on a deadline**, not held.
    *(Added after review round 23.)*

**Install script**

16. `packaging/install-daemon-windows.ps1` is idempotent: running it twice leaves the same
    account, task, ACLs and store key, and does not rotate the store key. **[win199]**
17. It grants `SeBatchLogonRight` to the account and sets deny-interactive and deny-network
    logon, and the task runs. **[win199]**
18. It creates the account with a random password it never writes to disk and does not
    return.
19. It writes `state\store.key` as 32 random bytes with the state ACL, and `sealKind()`
    reports `local-file`. It reports BitLocker status via `manage-bde` rather than claiming
    a stolen disk does not open.
20. It refuses to run without administrator rights, naming the elevation it needs.
21. The root-write symlink hazard round 22 found on macOS is closed here too: the installer
    must not follow a pre-existing reparse point at `store.key` or `broker-key.pem`.

**Verifier**

22. `packaging/verify-windows.ps1` exits non-zero if any required check fails, and a check
    that is skipped is not counted as a pass — `need()` fails, `skip()` means "not
    applicable". (Round 22's finding, carried across deliberately.)
23. The verifier performs the **two-account** test of check 11 itself rather than reading
    the ACL, creating and removing its own unprivileged probe account. **[win199]**

**Leaving the other platforms alone**

24. The full existing suite passes unchanged on Linux.
25. `platformShape()` still throws on an unrecognised override, now accepting `windows`.
26. **AMENDED after review round 23.** As first written this said `splitAvailableFor('linux',
    'windows')` must be **false**. That is wrong, and the spec was wrong rather than the
    code: a Linux box MUST be able to take the windows layout, or the Windows paths are
    unreachable from CI and verifiable only by hand on one machine — which is precisely how
    the port lock shipped broken to macOS and stayed broken for a release.
    What the check was really protecting is intact and is what is asserted now:
    - `splitAvailableFor('win32', 'linux')` and `('win32', 'darwin')` are **false** —
      Windows cannot host a layout whose sockets are filesystem paths;
    - `splitAvailableFor('linux', 'windows')` is **true**, and `boundaryIsReal()` there is
      nonetheless **false**, because it looks at the directory: it wants `icacls`, and a
      Linux box does not have one. The override relocates state; it never manufactures a
      boundary, and that is now asserted directly rather than by proxy.
27. Migration on Windows is permitted only when the source and destination are genuinely
    different places — the existing same-place refusal still fires.

**Honesty**

28. Non-ASCII characters do not appear in daemon console output on Windows. **[win199]**
29. `/limitations` gains the Windows row, and says plainly: the boundary is an ACL, an
    administrator is outside it exactly as root is on Linux, there is no sandboxing
    equivalent to the systemd unit's, and the store key is not sealed to hardware.
30. No customer-facing copy calls Windows supported until checks 1, 3, 6, 11, 12, 14 and 23
    have been observed on a real Windows machine.

---

## 5. Known open, not closed by this phase

- **No sandboxing.** The systemd unit's `ProtectSystem=strict`, `ProtectProc=invisible`,
  syscall filter and empty capability set have no Task Scheduler equivalent, exactly as on
  macOS. The uid split is very nearly the whole defence.
- **The store key is not sealed to hardware.** No TPM use. BitLocker covers the stolen
  disk, and BitLocker is not ours to claim. DPAPI scoped to the service account would be a
  real improvement and is deliberately not in this phase.
- **The daemon's log has no rotation** — the same gap as macOS, still wanting one fix for
  both.
- **An administrator is not excluded**, and neither is `SYSTEM`.
- **One account is one principal**, unchanged: any agent can read any other agent's token.
- **A real Windows service, under a signed binary** — phase 9.


## What was built this round, and how it was tested

PHASE 8 ROUND 2 (round 24 overall) -- THE DAEMON AND THE PACKAGING.

WHAT YOU HAVE
- The diff of src/agent.ts (the daemon).
- The FULL text of packaging/install-daemon-windows.ps1 and packaging/verify-windows.ps1.

WHAT YOU HAVE NOT SEEN, and must flag any dependent finding as unverified:
- src/paths.ts, src/endpoint.ts, src/broker-client.ts -- these were round 23's subject and
  are already revised. Do not re-derive findings about them.
- test/windows-shape.test.ts (42 tests), the rest of agent.ts outside the diff.

ROUND 23 ALREADY FOUND AND I ALREADY FIXED (do not repeat):
- the state-directory OWNER was unchecked (an owner holds WRITE_DAC implicitly) -- the ACL
  report now carries OWNER, the installer sets it with /setowner, the verifier checks it;
- inheritance was checked per-entry rather than via AreAccessRulesProtected;
- the uninstalled state-root check accepted a directory a second local user had laid as a
  trap;
- WUNDERVAULT_PRINCIPAL_ID let the environment answer "who am I" -- removed;
- the hello wrapper decoded per-chunk and re-encoded the remainder (multi-byte corruption);
- no handshake deadline before hand-off;
- nothing stopped a SECOND broker publishing over the first's discovery files -- now an
  unrecognised option exits 2, and the daemon probes the recorded port before publishing.

MEASURED ON A REAL WINDOWS 10 22H2 BOX (facts; a finding contradicting one is wrong):
- chmod is a no-op; stat reports 666 for everything; process.getuid is undefined.
- PowerShell 5.1 reads .ps1 as ANSI unless the file has a UTF-8 BOM. Em-dashes in an
  earlier draft of the installer produced a stray double quote that desynchronised the
  parser into nine cascading syntax errors. Both scripts are now pure ASCII and a unit
  test enforces it.
- $ErrorActionPreference='Stop' turns a native program's stderr into a terminating error.
  `schtasks /delete` on a missing task killed both scripts mid-run. Both now route native
  programs through a Native helper that decides on the EXIT CODE.
- schtasks does NOT grant SeBatchLogonRight; the task registers, reports success, and
  silently never runs. secedit grants it.
- New-LocalUser -Description is capped at 48 characters and REFUSES rather than truncating.
- Register-ScheduledTask puts -Password in the -User parameter set, not with -Principal.

WHAT WAS RUN END TO END ON THAT BOX, ALL PASSING:
- npm install -g exits 0 (it exited 1 on every Windows box since the first public release).
- The installer completes; the broker runs as its own account 'wundervault'; state lands in
  %ProgramData%\wundervault\state and discovery files in ...\run.
- verify-windows.ps1: 24 passed, 0 failed, 0 n/a, exit 0 -- including, from a THIRD
  non-admin account created and destroyed by the script: cannot list the state directory,
  cannot read store.key, CAN list the run directory, CANNOT write it, CAN reach the broker
  and gets a SIGNED answer.
- Granting Users:(RX) on the state directory flips the reported boundary to false at next
  start while the broker KEEPS SERVING; removing the grant flips it back to true.
- Running the installer twice is idempotent and does NOT rotate the store key.
- 554 unit tests pass on Linux.

SPECIFIC THINGS I WANT ATTACKED
1. The installer's failure modes. It creates an account, grants a logon right, sets ACLs
   and registers a task, in that order. Where does a failure leave a half-built machine,
   and is any of it unsafe rather than merely untidy?
2. The random password: generated, used to create the account and register the task, then
   nulled. Is it exposed anywhere -- process list, event log, task XML, PowerShell history?
3. secedit: I export USER_RIGHTS, append a SID to four rights, and re-import ONLY the
   [Privilege Rights] section. Can that clobber a right I did not mean to touch?
4. Assert-NotReparsePoint: does it actually close the root-write-through-a-symlink hole,
   given the check and the write are not atomic?
5. The verifier: does it prove what it claims, or does anything pass vacuously? A check
   that cannot fail is the failure mode I care most about.
6. The daemon diff: machineIdentity's Windows branch, the refuseIfAlreadyServing probe, the
   unknown-option refusal, and the store-key/boundary messages. Is anything said there
   untrue on Windows?

## Diff

```diff
diff --git a/src/agent.ts b/src/agent.ts
index d734f23..13f60c6 100644
--- a/src/agent.ts
+++ b/src/agent.ts
@@ -30,6 +30,7 @@
  */
 import net from 'node:net';
 import fs from 'node:fs';
+import os from 'node:os';
 import path from 'node:path';
 import crypto from 'node:crypto';
 import { execFileSync } from 'node:child_process';
@@ -38,9 +39,15 @@ import { redeemSetupLink, peekAgentName } from './enrol.js';
 import {
   systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
   runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
-  splitAvailable, systemdCredential, sealKind, boundaryIsReal,
+  splitAvailable, systemdCredential, sealKind, boundaryIsReal, principalId, platformShape,
   type SealKind,
 } from './paths.js';
+import {
+  agentEndpoint, mgmtEndpoint, listenOn, withHello, releaseEndpoint, publishBrokerPublicKey,
+  helloSignerFrom, usesPortFiles, anotherBrokerIsServing, endpointLabel,
+  type Endpoint, type HelloSigner,
+} from './endpoint.js';
+import { loadOrCreateIdentity } from './broker-key.js';
 import { load as loadNetworkShape } from './network-store.js';
 import { BrokerOps } from './broker-ops.js';
 import type { BrokeredOp } from './ssh-agent.js';
@@ -106,12 +113,73 @@ interface ProfileStore {
  * "the key never reaches the agent", and on macOS today that is true only of an agent that
  * does not try.
  */
+/**
+ * The Windows console does not render what we write.
+ *
+ * Node writes UTF-8; `cmd.exe` and the default PowerShell host read the machine's OEM code
+ * page, so the em-dash in the startup warning came out as `?"` on Windows 10 — observed.
+ * A boundary warning that looks like a mis-decoded string is a boundary warning people
+ * stop reading.
+ *
+ * Transliteration rather than `chcp 65001`, because changing the console's code page is a
+ * side effect on the user's terminal that outlives the process, and this is six characters.
+ */
+export function consoleSafe(text: string): string {
+  if (process.platform !== 'win32') return text;
+  return text
+    .replace(/[\u2014\u2013]/g, '-')
+    .replace(/[\u2018\u2019]/g, "'")
+    .replace(/[\u201c\u201d]/g, '"')
+    .replace(/\u2026/g, '...')
+    .replace(/\u00a0/g, ' ');
+}
+
+/** Every daemon message goes through here, so the transliteration cannot be forgotten. */
+function say(text: string): void { console.error(consoleSafe(text)); }
+
+/**
+ * Apply it to EVERYTHING, once, at the stream.
+ *
+ * Routing each console.error through consoleSafe() by hand is the version of this fix that
+ * decays: there are twenty of them, new ones get added, and the one that matters is
+ * whichever message a person is reading when something has gone wrong. Wrapping the two
+ * streams catches those, the ones thrown from inside errors, and the ones written by code
+ * that has not been born yet.
+ *
+ * Windows only, and a no-op that returns false everywhere else — the streams on Linux and
+ * macOS are not touched at all.
+ */
+export function installConsoleTransliteration(): boolean {
+  if (process.platform !== 'win32') return false;
+  for (const stream of [process.stdout, process.stderr]) {
+    const original = stream.write.bind(stream);
+    (stream as unknown as { write: (...a: unknown[]) => boolean }).write =
+      (chunk: unknown, ...rest: unknown[]): boolean => {
+        if (typeof chunk === 'string') {
+          return (original as (...a: unknown[]) => boolean)(consoleSafe(chunk), ...rest);
+        }
+        return (original as (...a: unknown[]) => boolean)(chunk, ...rest);
+      };
+  }
+  return true;
+}
+
+/** The privileged install command for this platform. */
+export function installerCommand(platform: string = process.platform): string {
+  if (platform === 'darwin') return 'sudo sh packaging/install-daemon-macos.sh';
+  if (platform === 'win32') {
+    return 'powershell -ExecutionPolicy Bypass -File packaging\\install-daemon-windows.ps1'
+      + '   (in an Administrator prompt)';
+  }
+  return 'sudo sh packaging/install-daemon.sh';
+}
+
 function announceBoundary(): void {
   if (boundaryIsReal()) return;
 
   // Two different situations, and telling them apart is the whole value of the message.
   if (!splitAvailable()) {
-    console.error(
+    say(
       `[wundervault-agent] Running on ${process.platform}, where the secret broker cannot\n` +
       `[wundervault-agent] have its own account. State is in your own directory and it runs as\n` +
       `[wundervault-agent] YOU — so its key material and memory are readable by anything you\n` +
@@ -122,15 +190,19 @@ function announceBoundary(): void {
 
   // The platform CAN do this and the install has not been done — or has been undone. Said
   // separately because the fix is a command, not a wait for a future release.
-  const installer = process.platform === 'darwin'
-    ? 'sudo sh packaging/install-daemon-macos.sh'
-    : 'sudo sh packaging/install-daemon.sh';
-  console.error(
-    `[wundervault-agent] No privilege boundary: ${systemRoot()} is not a 0700 directory\n` +
-    `[wundervault-agent] owned by a separate account, so this daemon is running as the same\n` +
-    `[wundervault-agent] user as the agents it serves. Its key material and memory are\n` +
-    `[wundervault-agent] readable by anything you run.\n` +
-    `[wundervault-agent]   ${installer}`,
+  //
+  // The Windows sentence says ACL rather than 0700, because 0700 is meaningless there:
+  // chmod is a no-op and stat reports 666 for every file on the volume. Telling a Windows
+  // user to look for a mode would send them hunting something that cannot exist.
+  const shape = platformShape();
+  const what = shape === 'windows'
+    ? `is not a directory whose ACL is limited to the broker's own account`
+    : `is not a 0700 directory\n[wundervault-agent] owned by a separate account`;
+  say(
+    `[wundervault-agent] No privilege boundary: ${systemRoot()} ${what},\n` +
+    `[wundervault-agent] so this daemon is running as the same user as the agents it\n` +
+    `[wundervault-agent] serves. Its key material and memory are readable by anything you run.\n` +
+    `[wundervault-agent]   ${installerCommand()}`,
   );
 }
 
@@ -227,6 +299,15 @@ export function machineIdentity(): string | null {
     } catch { /* no ioreg, or it failed */ }
   }
 
+  // WINDOWS HAS NEITHER OF THE OTHER TWO, AND SAYING SO IS THE WHOLE POINT.
+  //
+  // Before this branch existed machineIdentity() returned null on every Windows machine,
+  // and phase 7's keyModeFor() turns a null identity with no existing store into `refuse`.
+  // So the daemon did not start at all on a fresh Windows box — observed on Windows 10
+  // 22H2, 2026-09-18. The comment above keyModeFor called that branch "unreachable on any
+  // machine that has /etc/machine-id or ioreg, which is all of them". Windows is not.
+  if (process.platform === 'win32') return windowsMachineIdentity();
+
   try {
     const id = fs.readFileSync('/etc/machine-id', 'utf8').trim();
     if (id) return id;
@@ -235,6 +316,90 @@ export function machineIdentity(): string | null {
   return null;
 }
 
+/**
+ * TWO SOURCES, COMBINED, BECAUSE EACH ONE FAILS IN A DIFFERENT WAY.
+ *
+ * `MachineGuid` (HKLM\SOFTWARE\Microsoft\Cryptography) is generated when Windows is
+ * installed. It is the exact shape of thing the macOS bug was about: it travels with a
+ * disk image, so two machines cloned from one image share it.
+ *
+ * The SMBIOS UUID (`Win32_ComputerSystemProduct.UUID`) is hardware and does not travel —
+ * but on real boards it is often junk. win199, a Supermicro machine, reports
+ * `00000000-0000-0000-0000-AC1F6B1C4252`: twelve zero bytes and the NIC's MAC address.
+ * That one is still unique; all-zeros and all-FFs, which other vendors ship, are not, and
+ * trusting them blindly puts every such machine on one derived key. That IS the macOS bug.
+ *
+ * So: drop a source that is absent or degenerate, hash what is left, and return null only
+ * when NOTHING usable remains — at which point `refuse` is the correct answer rather than
+ * an accident.
+ *
+ * Pure, and separated from the two subprocesses that collect the values, because the part
+ * that can silently return the wrong thing is the part that has to be testable off
+ * Windows.
+ */
+export function machineIdentityFromSources(
+  smbiosUuid: string | null,
+  machineGuid: string | null,
+): string | null {
+  const parts: string[] = [];
+  const s = usableWindowsId(smbiosUuid);
+  const g = usableWindowsId(machineGuid);
+  if (s) parts.push(`smbios=${s}`);
+  if (g) parts.push(`machineguid=${g}`);
+  if (parts.length === 0) return null;
+  return crypto.createHash('sha256').update(`wv-win:${parts.join(':')}`).digest('hex');
+}
+
+/**
+ * Is this value actually per-machine?
+ *
+ * Rejects what is not a UUID at all, and the placeholder values that many machines share.
+ * Deliberately does NOT reject win199's mostly-zero UUID: it is ugly and it is unique,
+ * and a rule tight enough to exclude it would exclude a large slice of real hardware for
+ * no gain. The test is "could another machine produce this", not "does it look tidy".
+ */
+function usableWindowsId(raw: string | null): string | null {
+  const v = String(raw ?? '').trim().toLowerCase();
+  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v)) return null;
+  const hex = v.replace(/-/g, '');
+  if (/^0+$/.test(hex)) return null;                 // all zeros: the commonest placeholder
+  if (/^f+$/.test(hex)) return null;                 // all FFs: an unprogrammed field
+  // Known vendor placeholders, shipped identically on every unit of a model.
+  if (hex === '03000200040005000006000700080009') return null;
+  return v;
+}
+
+/**
+ * Collect the two Windows sources. Subprocesses, so kept away from the pure part above.
+ *
+ * `reg query` for MachineGuid because it is fast and always present. PowerShell for the
+ * SMBIOS UUID because `wmic` is deprecated and unreliable on current builds. Both are
+ * bounded by a timeout and both failures are survivable — losing one source is exactly the
+ * case machineIdentityFromSources is built for.
+ */
+function windowsMachineIdentity(): string | null {
+  let smbios: string | null = null;
+  let guid: string | null = null;
+
+  try {
+    const out = execFileSync('powershell', [
+      '-NoProfile', '-NonInteractive', '-Command',
+      '(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID',
+    ], { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] });
+    smbios = out.trim() || null;
+  } catch { /* no PowerShell, or CIM is unwell */ }
+
+  try {
+    const out = execFileSync('reg', [
+      'query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid',
+    ], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
+    const m = out.match(/MachineGuid\s+REG_SZ\s+(\S+)/i);
+    guid = m ? m[1] : null;
+  } catch { /* registry read failed */ }
+
+  return machineIdentityFromSources(smbios, guid);
+}
+
 /**
  * Pull the hardware UUID out of ioreg's output.
  *
@@ -300,8 +465,11 @@ function readOrCreateSalt(): Buffer {
  * second salt would mean a second file to lose.
  */
 export function derivedKeyFor(identity: string): Buffer {
-  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
-  const ikm = crypto.createHash('sha256').update(`${identity}:${uid}`).digest();
+  // principalId(), not `getuid() ?? 0`. On POSIX it returns the uid as a string, so this
+  // is bit-for-bit what it always was and no existing store moves. On Windows getuid is
+  // undefined and the old fallback made every account on the box principal 0 — one derived
+  // key shared by every user of the machine, which is the macOS bug in a second costume.
+  const ikm = crypto.createHash('sha256').update(`${identity}:${principalId()}`).digest();
   // Buffer.from, not a cast: hkdfSync returns an ArrayBuffer, and the `as unknown as
   // Buffer` this replaced made `.length` read undefined on a value the rest of the file
   // treats as a Buffer. It happened to work because nothing asked.
@@ -475,6 +643,14 @@ class AgentDaemon {
   private profiles: AgentProfile[] = [];
   private agentServers: Map<string, net.Server> = new Map();
   private mgmtServer: net.Server | null = null;
+  /**
+   * How this daemon proves it is this daemon, on a platform reached by a port.
+   *
+   * Null everywhere else, and null is the honest value: the unix-socket platforms do not
+   * need it, because a socket path lives in a directory only the daemon can write and
+   * nobody else can put something there for an agent to find.
+   */
+  private helloSigner: HelloSigner | null = null;
   private knocks = new Knocks();
   /**
    * One operations object per agent, built on first use and kept.
@@ -645,7 +821,7 @@ class AgentDaemon {
     if (srv) { try { srv.close(); } catch { /* already gone */ } }
     this.agentServers.delete(safe);
     this.dropOps(safe);
-    try { fs.unlinkSync(agentSocketPath(safe)); } catch { /* already gone */ }
+    releaseEndpoint(agentEndpoint(safe));
     this.saveProfiles();
     return true;
   }
@@ -765,10 +941,10 @@ class AgentDaemon {
   }
 
   startAgentSocket(profile: AgentProfile): void {
-    const sockPath = agentSocketPath(profile.agent_name);
-    try { fs.unlinkSync(sockPath); } catch { /* nothing to clear */ }
+    const ep = agentEndpoint(profile.agent_name);
+    releaseEndpoint(ep);
 
-    const srv = net.createServer((socket) => {
+    const srv: net.Server = net.createServer(withHello((socket) => {
       // BUFFERS, not a string, and the reasons are two separate bugs.
       //
       // 1. `buf.length` on a string counts UTF-16 code units, not bytes. A request of
@@ -921,7 +1097,10 @@ class AgentDaemon {
           });
       });
       socket.on('error', () => { /* a client that hangs up is not an event */ });
-    });
+    }, this.helloSigner, () => {
+      const a = srv.address();
+      return a && typeof a !== 'string' ? a.port : 0;
+    }));
 
     // NO maxConnections here, deliberately — the second version of this code had one, and
     // it recreated the denial of service it was meant to prevent one layer down. A ceiling
@@ -934,29 +1113,60 @@ class AgentDaemon {
     // fixed time after it was accepted, whatever it sends. Slots cannot be held, so they
     // do not need to be rationed, and nothing an attacker does can make the daemon refuse
     // a connection it has not yet authenticated.
-    srv.listen(sockPath, () => {
-      // World-connectable BY DESIGN — see the header. The daemon is a different uid from
-      // every agent, so a mode that excluded others would exclude the agent too. The
-      // token is the identity; this mode is not a control and must not be read as one.
-      try { fs.chmodSync(sockPath, 0o666); } catch { /* best effort */ }
-    });
+    listenOn(
+      srv, ep, this.helloSigner,
+      () => { /* the per-agent endpoint is not announced; the mgmt line covers the start */ },
+      (message) => {
+        // A per-agent endpoint that cannot be published is an agent nobody can reach. It
+        // is reported and the server is dropped, rather than left bound to a port no
+        // discovery file names — which reads as "running" and serves nobody.
+        console.error(`[wundervault-agent] ${profile.agent_name}: ${message}`);
+        try { srv.close(); } catch { /* already gone */ }
+        this.agentServers.delete(profile.agent_name);
+      },
+    );
     srv.on('error', (err) => {
       console.error(`[wundervault-agent] Socket error for ${profile.agent_name}:`, err.message);
     });
     this.agentServers.set(profile.agent_name, srv);
   }
 
+  /**
+   * Refuse to become the second broker on a machine that already has one.
+   *
+   * Awaited before start(), because on a port-addressed platform there is no EADDRINUSE to
+   * stop us: two daemons run happily and the second overwrites the first's discovery
+   * files, taking every agent with it. Observed during phase 8's own testing.
+   */
+  static async refuseIfAlreadyServing(): Promise<void> {
+    if (!usesPortFiles()) return;
+    const ep = mgmtEndpoint();
+    if (await anotherBrokerIsServing(ep)) {
+      throw new ConfigurationRefusal(
+        `Another secret broker is already serving on this machine.\n` +
+        `  ${endpointLabel(ep)} names a port that is answering, so starting a second\n` +
+        `  broker would overwrite the address every agent here is using and point them\n` +
+        `  at this process instead.\n` +
+        `  Stop the running one first, or let the scheduled task manage it:\n` +
+        `    schtasks /end /tn wundervault-agent`,
+      );
+    }
+  }
+
   startMgmtSocket(): void {
-    const mp = mgmtSocketPath();
+    const ep = mgmtEndpoint();
     // The directory is the control, and it exists before the socket does. chmod-after-
     // listen leaves a window in which the socket is bound at the default mode and a
     // process watching for it can connect; a 0770 directory has no such window.
     const md = mgmtDir();
     fs.mkdirSync(md, { recursive: true, mode: 0o755 });
-    fs.chmodSync(md, 0o755);
-    try { fs.unlinkSync(mp); } catch { /* nothing to clear */ }
+    // chmod is a no-op on Windows — measured, it reports 666 whatever is asked — so it is
+    // skipped rather than run for the look of it. The Windows equivalent is the ACL the
+    // installer puts on the run directory, and it is the installer's job.
+    if (!usesPortFiles()) fs.chmodSync(md, 0o755);
+    releaseEndpoint(ep);
 
-    const mgmt = net.createServer((socket) => {
+    const mgmt: net.Server = net.createServer(withHello((socket) => {
       let buf = '';
       // An ABSOLUTE deadline as well as the inactivity one. setTimeout() below is reset by
       // any traffic, so a byte every nine seconds held a management connection for days —
@@ -1185,6 +1395,13 @@ class AgentDaemon {
             socket.write(JSON.stringify({
               ok: true, version: VERSION, store_unreadable: this.storeUnreadable,
               key_mode: this.keyMode,
+              // Whether there is ACTUALLY a boundary here, from the daemon's own mouth.
+              // The startup warning says this too, but a warning is a line in a log that
+              // nothing can assert on; an installer's verifier needs an answer it can
+              // read. Observed rather than inferred -- boundaryIsReal() looks at the
+              // directory, not at process.platform.
+              boundary: boundaryIsReal(),
+              account: (() => { try { return os.userInfo().username; } catch { return null; } })(),
             }) + '\n');
           } else if (msg.action === 'known_agents') {
             // Names only, never credentials. This is what lets migration tell you which of
@@ -1205,16 +1422,21 @@ class AgentDaemon {
         socket.end();
       });
       socket.on('error', () => { /* hang-ups are not events */ });
-    });
-
-    mgmt.listen(mp, () => {
-      // Connectable by anyone, like the per-agent sockets, and for the same reason: the
-      // daemon is a different uid, so a socket it owns at 0660 is one no agent could
-      // reach. What guards the actions behind it is a server-issued setup link to enrol
-      // and the agent's own token to remove — neither of which a file mode can supply.
-      try { fs.chmodSync(mp, 0o666); } catch { /* best effort */ }
-      console.log(`[wundervault-agent] Listening. Management: ${mp}`);
-    });
+    }, this.helloSigner, () => {
+      const a = mgmt.address();
+      return a && typeof a !== 'string' ? a.port : 0;
+    }));
+
+    listenOn(
+      mgmt, ep, this.helloSigner,
+      (label) => { console.log(`[wundervault-agent] Listening. Management: ${label}`); },
+      (message) => {
+        // The management endpoint is how an agent is enrolled and removed. A daemon that
+        // cannot publish it has nothing to offer, and saying so is better than a process
+        // that looks alive.
+        throw new ConfigurationRefusal(message);
+      },
+    );
     mgmt.on('error', (err) => {
       console.error('[wundervault-agent] Mgmt socket error:', err.message);
     });
@@ -1234,23 +1456,41 @@ class AgentDaemon {
     // The directory being traversable costs nothing. The sockets inside it are
     // world-connectable by design and each carries its own token — nothing here is
     // protected by being hard to reach.
-    fs.chmodSync(rt, 0o755);
-    const rtMode = fs.statSync(rt).mode & 0o777;
-    if ((rtMode & 0o011) !== 0o011) {
-      throw new ConfigurationRefusal(
-        `${rt} is mode ${rtMode.toString(8)}. Agents run as the machine's owner and need ` +
-        `search permission on this directory to reach their sockets; at this mode every ` +
-        `connection would fail with EACCES.`,
-      );
+    // WINDOWS HAS NO MODE TO CHECK. chmod there is a no-op and stat() reports 666 for
+    // everything, measured — so running this check would either pass vacuously or, worse,
+    // refuse to start on a correct install. The Windows equivalent is the run directory's
+    // ACL, which the installer sets and verify-windows.ps1 proves from a second account.
+    if (!usesPortFiles()) {
+      fs.chmodSync(rt, 0o755);
+      const rtMode = fs.statSync(rt).mode & 0o777;
+      if ((rtMode & 0o011) !== 0o011) {
+        throw new ConfigurationRefusal(
+          `${rt} is mode ${rtMode.toString(8)}. Agents run as the machine's owner and need ` +
+          `search permission on this directory to reach their sockets; at this mode every ` +
+          `connection would fail with EACCES.`,
+        );
+      }
     }
-    // Clear sockets left by a crash. A stale file makes listen() fail, and the daemon
-    // would come up with no socket while reporting itself started.
+    // Clear endpoints left by a crash. A stale socket makes listen() fail; a stale PORT
+    // FILE is worse than that, because it does not fail — it names a port this daemon no
+    // longer holds, which anything local may now have bound. Both go.
     try {
       for (const f of fs.readdirSync(rt)) {
-        if (f.endsWith('.sock')) { try { fs.unlinkSync(path.join(rt, f)); } catch { /* ignore */ } }
+        if (f.endsWith('.sock') || f.endsWith('.port') || f.endsWith('.port.tmp')) {
+          try { fs.unlinkSync(path.join(rt, f)); } catch { /* ignore */ }
+        }
       }
     } catch { /* first run */ }
 
+    // The identity, and the half of it agents verify against. Only where the transport
+    // needs it: on the unix-socket platforms nothing reads broker.pub and publishing it
+    // would be a file with no reader and a question for whoever found it.
+    if (usesPortFiles()) {
+      const identity = loadOrCreateIdentity();
+      this.helloSigner = helloSignerFrom(identity.privateKeyPem);
+      publishBrokerPublicKey(identity.publicKeyB64);
+    }
+
     for (const profile of this.profiles) {
       if (!profile.socket_token) {
         // Pre-split profiles may have none. Serving them now would hand credentials to
@@ -1304,21 +1544,38 @@ class AgentDaemon {
         '[wundervault-agent] broker, or set WUNDERVAULT_MACHINE_ID to something per-machine.',
       );
     } else {
-      console.error(
-        '[wundervault-agent] Store key: DERIVED from machine-id and uid, which are not secret.\n' +
-        '[wundervault-agent] Anyone who can read this directory can recompute it, so the\n' +
-        '[wundervault-agent] directory mode is what protects the store — not the encryption.',
+      // THREE PLATFORMS, THREE TRUE SENTENCES, and the third one was being told the first
+      // one's. On Windows there is no machine-id, no uid, and no directory mode — chmod is
+      // a no-op there and stat reports 666 whatever is asked. Printing "the directory mode
+      // is what protects the store" on a Windows box names a control that does not exist
+      // and points the reader away from the one that does, which is the ACL.
+      const source = process.platform === 'win32'
+        ? 'this machine\'s hardware id and your account SID'
+        : process.platform === 'darwin'
+          ? 'the hardware UUID and uid'
+          : 'machine-id and uid';
+      const control = platformShape() === 'windows'
+        ? 'the directory\'s ACL is what protects the store'
+        : 'the directory mode is what protects the store';
+      say(
+        `[wundervault-agent] Store key: DERIVED from ${source}, which are not secret.\n` +
+        `[wundervault-agent] Anyone who can read this directory can recompute it, so\n` +
+        `[wundervault-agent] ${control} — not the encryption.`,
       );
     }
   }
 
   shutdown(): void {
+    // The discovery file goes with the server. A port file that outlives its daemon names
+    // an address anything local may now bind, and an agent that read it would be talking
+    // to a stranger — which the hello handshake catches, but only because this also
+    // happens on the paths where it can.
     for (const [name, srv] of this.agentServers) {
       try { srv.close(); } catch { /* already closing */ }
-      try { fs.unlinkSync(agentSocketPath(name)); } catch { /* already gone */ }
+      releaseEndpoint(agentEndpoint(name));
     }
     if (this.mgmtServer) { try { this.mgmtServer.close(); } catch { /* already closing */ } }
-    try { fs.unlinkSync(mgmtSocketPath()); } catch { /* already gone */ }
+    releaseEndpoint(mgmtEndpoint());
   }
 }
 
@@ -1388,6 +1645,8 @@ function readLinkFromStdin(): Promise<string> {
 // migration command without starting a daemon as a side effect.
 const invokedDirectly = process.argv[1] && /wundervault-agent|agent\.(js|ts)$/.test(process.argv[1]);
 if (invokedDirectly && !process.env.WUNDERVAULT_AGENT_NO_AUTOSTART) {
+  // Before anything writes a byte. A warning nobody can read is a warning nobody reads.
+  installConsoleTransliteration();
   const argv = process.argv.slice(2);
 
   if (argv.includes('--help') || argv.includes('-h')) {
@@ -1651,10 +1910,34 @@ State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
         .catch((e: Error) => { console.error(e.message); process.exit(1); });
     }
   } else {
+    // AN UNRECOGNISED FLAG MUST NOT START A BROKER.
+    //
+    // Everything that is not a known subcommand fell through to here and launched a
+    // daemon in the foreground. So `wundervault-agent --ping` -- a flag that does not
+    // exist, and which this project's own verifier script asked for -- started a SECOND
+    // broker, as the wrong user, which then sat there for ever. On Windows that second
+    // broker overwrites the discovery files the real one published, so a typo silently
+    // repoints every agent on the machine at a daemon running as the person who typed it.
+    //
+    // Found by running the verifier on Windows. It is not a Windows bug: a typo has
+    // started a stray broker on every platform since phase 4.
+    const unknown = argv.filter(a => a.startsWith('-'));
+    if (unknown.length > 0) {
+      console.error(
+        `[wundervault-agent] Unrecognised option${unknown.length > 1 ? 's' : ''}: ` +
+        `${unknown.join(', ')}\n` +
+        `  Refusing to start a broker, because that is almost certainly not what you meant.\n` +
+        `  Run with --help to see what this command accepts.`,
+      );
+      process.exit(2);
+    }
     refuseRoot();
     announceBoundary();
     let daemon: AgentDaemon;
     try {
+      // Before anything is constructed or published. A second broker that has already
+      // written its discovery files has already stolen the agents.
+      await AgentDaemon.refuseIfAlreadyServing();
       daemon = new AgentDaemon();
       daemon.start();
     } catch (err) {

```

## File: packaging/install-daemon-windows.ps1

```
<#
    Give the secret broker its own account on Windows.

    Run from an Administrator prompt:

        powershell -ExecutionPolicy Bypass -File packaging\install-daemon-windows.ps1

    WHAT THIS BUILDS, AND WHY EACH PIECE IS THE SHAPE IT IS

    A local account `wundervault`, a state directory it alone can open, a run directory
    everyone can read, and a scheduled task that starts it at boot as that account. After
    this, the agents you run cannot open the directory holding your credentials -- which is
    the same claim Linux and macOS make, by a different mechanism.

    THE BOUNDARY IS AN NTFS ACL, NOT A FILE MODE. chmod on Windows is a no-op: ask for
    0700 and stat reports 666, every time. Measured on Windows 10 22H2. So nothing here
    sets a mode, and the daemon does not check one.

    A SCHEDULED TASK, NOT A SERVICE, and it is a considered choice rather than a shortcut.
    A real Windows service must answer the Service Control Manager within 30 seconds;
    node.exe does not, so `sc create` on it fails with error 1053. Every route to a real
    service goes through a third-party wrapper executable, and this product's trust story
    is that the installer is one readable file you can diff against the copy on GitHub at
    /verify#installer. Shipping a binary you cannot read to win a nicer service entry is
    the wrong trade. A real service, under a signed binary, is phase 9.

    ADMINISTRATORS AND SYSTEM ARE INSIDE THE WALL. They are outside every boundary on this
    operating system, exactly as root is on Linux, and the daemon's own check allows them
    deliberately. /limitations says so in the same words.
#>

[CmdletBinding()]
param(
    [string] $Account   = 'wundervault',
    [string] $TaskName  = 'wundervault-agent',
    [string] $NodePath  = '',
    [string] $AgentPath = '',
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Base  = Join-Path $env:ProgramData 'wundervault'
$State = Join-Path $Base 'state'
$Run   = Join-Path $Base 'run'

# Well-known SIDs, because names are localised and these are not. An installer that grants
# "Administrators" by name does nothing at all on a German Windows.
$SID_SYSTEM  = 'S-1-5-18'
$SID_ADMINS  = 'S-1-5-32-544'
$SID_USERS   = 'S-1-5-32-545'

function Say    { param($m) Write-Host "  $m" }
function Step   { param($m) Write-Host "`n== $m" -ForegroundColor Cyan }
function Fail   { param($m) Write-Host "`nFAILED: $m" -ForegroundColor Red; exit 1 }

<#
    Run a console program without letting its chatter kill the script.

    `$ErrorActionPreference = 'Stop'` is right for cmdlets and WRONG for native commands:
    PowerShell turns anything a native program writes to stderr into a terminating error,
    so `schtasks /delete` on a task that does not exist -- an expected, harmless outcome
    that this script relies on for idempotence -- killed the installer four fifths of the
    way through, after it had already created the account and the directories. Observed on
    Windows 10.

    So native programs go through here: stderr is captured rather than thrown, and the EXIT
    CODE is what decides. `-AllowFail` is for the calls whose failure is the normal case.
#>
function Native {
    param([Parameter(Mandatory)][string] $Exe,
          [string[]] $Arguments = @(),
          [switch] $AllowFail,
          [string] $What = '')
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $old }
    if (-not $AllowFail -and $code -ne 0) {
        $label = if ($What) { $What } else { "$Exe $($Arguments -join ' ')" }
        Fail "$label failed (exit $code):`n$(($out | Out-String).Trim())"
    }
    return $out
}

# -- 0. refuse without the rights this needs -----------------------------------
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail @"
This needs Administrator rights: it creates a local account, grants it a logon right, and
writes under $env:ProgramData.

Open an Administrator PowerShell (right-click > Run as administrator) and run:
  powershell -ExecutionPolicy Bypass -File packaging\install-daemon-windows.ps1
"@
}

# -- uninstall -----------------------------------------------------------------
if ($Uninstall) {
    Step "Removing the broker"
    Native schtasks @('/end', '/tn', $TaskName) -AllowFail | Out-Null
    Native schtasks @('/delete', '/tn', $TaskName, '/f') -AllowFail | Out-Null
    Say "task removed"
    Say "The account and $Base are LEFT IN PLACE on purpose: they hold your credentials."
    Say "Remove them deliberately when you have finished with them:"
    Say "  Remove-LocalUser $Account ; Remove-Item -Recurse -Force '$Base'"
    exit 0
}

# -- 1. find node and the agent ------------------------------------------------
Step "Locating node and the broker"
if (-not $NodePath) {
    $c = Get-Command node.exe -ErrorAction SilentlyContinue
    if ($c) { $NodePath = $c.Source }
}
if (-not $NodePath -or -not (Test-Path -LiteralPath $NodePath)) {
    Fail "Could not find node.exe. Pass -NodePath 'C:\path\to\node.exe'."
}
if (-not $AgentPath) {
    # THE INSTALLER SHIPS INSIDE THE PACKAGE, so the broker is next door. This is the only
    # lookup that is right by construction: `npm root -g` has to be run through the right
    # node, survives neither nvm-windows nor a custom prefix without care, and the first
    # version of this line tried to run npm.cmd as a JavaScript file.
    #
    # It also means the installer always installs THE COPY IT CAME WITH, rather than
    # whichever copy npm happens to point at -- which is what you want when you are about
    # to register something to run at boot.
    $AgentPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'dist\agent.js'
}
if (-not (Test-Path -LiteralPath $AgentPath)) {
    Fail @"
Could not find the broker at:
  $AgentPath

Install it first:  npm install -g @wundervault/mcp-server
Or pass its path:  -AgentPath 'C:\...\dist\agent.js'
"@
}
Say "node:   $NodePath"
Say "broker: $AgentPath"

# -- 2. the account ------------------------------------------------------------
Step "The broker's own account"
$existing = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue
# A random password, used to create the account and to register the task, and never
# written anywhere. Task Scheduler stores what it needs in the LSA; nothing else needs to
# know it again, and an installer that saved it would be handing out the account it just
# built a wall around.
$bytes = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$plain = [Convert]::ToBase64String($bytes) + '!aA1'
$pw = ConvertTo-SecureString $plain -AsPlainText -Force

if ($existing) {
    Say "account '$Account' exists -- resetting its password so the task can be registered"
    Set-LocalUser -Name $Account -Password $pw
} else {
    New-LocalUser -Name $Account -Password $pw `
        -FullName 'Wundervault secret broker' `
        -Description 'Wundervault secret broker. No logon.' `
        -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    Say "created local account '$Account'"
}
# Deliberately a member of nothing. Windows puts new local users in Users; removing them
# would break the run directory's read grant, which is granted to Users on purpose.
$AccountSid = (Get-LocalUser -Name $Account).SID.Value
Say "sid: $AccountSid"

# -- 3. logon rights -----------------------------------------------------------
Step "Logon rights"
# SeBatchLogonRight is REQUIRED and schtasks does not grant it. Without it the task
# registers, reports success, and silently never runs -- observed, with the warning
# "Batch logon privilege needs to be enabled for the task principal" buried in the output
# of a command that still exits 0.
#
# The three deny rights are the other half: this account exists to run one process, and an
# account that can be logged into is a second way in.
$secDir = Join-Path $env:TEMP ("wv-sec-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $secDir -Force | Out-Null
try {
    $cur = Join-Path $secDir 'cur.inf'
    Native secedit @('/export', '/cfg', $cur, '/areas', 'USER_RIGHTS') -What 'reading the current logon rights' | Out-Null
    $lines = Get-Content $cur

    function RightWith {
        param($name, $sid, $lines)
        $line = $lines | Where-Object { $_ -match "^$name\s*=" }
        $vals = if ($line) { ($line -split '=', 2)[1].Trim() } else { '' }
        if ($vals -match [regex]::Escape($sid)) { return $vals }
        if ($vals) { return "$vals,*$sid" } else { return "*$sid" }
    }

    $batch      = RightWith 'SeBatchLogonRight'                 $AccountSid $lines
    $denyInter  = RightWith 'SeDenyInteractiveLogonRight'       $AccountSid $lines
    $denyNet    = RightWith 'SeDenyNetworkLogonRight'           $AccountSid $lines
    $denyRemote = RightWith 'SeDenyRemoteInteractiveLogonRight' $AccountSid $lines

    $inf = Join-Path $secDir 'apply.inf'
    @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeBatchLogonRight = $batch
SeDenyInteractiveLogonRight = $denyInter
SeDenyNetworkLogonRight = $denyNet
SeDenyRemoteInteractiveLogonRight = $denyRemote
"@ | Out-File -FilePath $inf -Encoding unicode

    Native secedit @('/configure', '/db', (Join-Path $secDir 'apply.sdb'), '/cfg', $inf,
                     '/areas', 'USER_RIGHTS') -What 'applying the logon rights' | Out-Null
    Say "granted: log on as a batch job"
    Say "denied:  interactive, network and remote-interactive logon"
} finally {
    Remove-Item -Recurse -Force $secDir -ErrorAction SilentlyContinue
}

# -- 4. the directories --------------------------------------------------------
Step "Directories and ACLs"

function Set-ExplicitAcl {
    param([string] $Path, [string[]] $Grants)
    # THE OWNER FIRST, and it is not cosmetic. On Windows an owner always holds
    # READ_CONTROL and WRITE_DAC implicitly, whatever the DACL says -- so a directory owned
    # by the account the agents run as is a directory those agents can unlock at will. The
    # installer runs elevated, so a directory it creates is owned by Administrators by
    # default on most systems and by the creating account on some; setting it explicitly
    # means the daemon's own boundary check has something it can rely on.
    Native icacls @($Path, '/setowner', "*${SID_ADMINS}") -What "setting the owner of $Path" | Out-Null
    # /inheritance:r FIRST. Without it the directory keeps whatever ProgramData says, and
    # ProgramData lets every account create and read. An inherited ACE also means the
    # access can change later without anyone touching this directory, which is why the
    # daemon treats any inherited entry as "no boundary" and refuses to claim one.
    Native icacls @($Path, '/inheritance:r') -What "removing inherited permissions from $Path" | Out-Null
    foreach ($g in $Grants) {
        Native icacls @($Path, '/grant', $g) -What "granting $g on $Path" | Out-Null
    }
}

New-Item -ItemType Directory -Path $Base  -Force | Out-Null
New-Item -ItemType Directory -Path $State -Force | Out-Null
New-Item -ItemType Directory -Path $Run   -Force | Out-Null

# Traversable, and holds nothing readable.
Set-ExplicitAcl -Path $Base -Grants @(
    "*${SID_SYSTEM}:(OI)(CI)(F)", "*${SID_ADMINS}:(OI)(CI)(F)",
    "*${AccountSid}:(OI)(CI)(F)", "*${SID_USERS}:(RX)"
)
# THE BOUNDARY. Nobody but the account and the operating system.
Set-ExplicitAcl -Path $State -Grants @(
    "*${SID_SYSTEM}:(OI)(CI)(F)", "*${SID_ADMINS}:(OI)(CI)(F)", "*${AccountSid}:(OI)(CI)(F)"
)
# The agents must reach their discovery files, so Users read here -- and ONLY read. A run
# directory an agent could write is a run directory an agent could use to point another
# agent at a port of its choosing.
Set-ExplicitAcl -Path $Run -Grants @(
    "*${SID_SYSTEM}:(OI)(CI)(F)", "*${SID_ADMINS}:(OI)(CI)(F)",
    "*${AccountSid}:(OI)(CI)(F)", "*${SID_USERS}:(OI)(CI)(RX)"
)
Say "$Base   traversable"
Say "$State  the boundary -- $Account, SYSTEM, Administrators"
Say "$Run    readable by all, writable only by $Account"

# -- 5. the store key ----------------------------------------------------------
Step "Store key"
$KeyPath = Join-Path $State 'store.key'

function Assert-NotReparsePoint {
    param([string] $Path)
    # A ROOT-WRITE THROUGH A SYMLINK THE SERVICE ACCOUNT PLANTED.
    #
    # This runs as Administrator and writes into a directory the service account owns.
    # That account could place a reparse point at store.key before a reinstall; this
    # script would follow it as an administrator, create or clobber whatever it pointed
    # at, and the ACL applied afterwards would hand that target to the service account.
    # Found on macOS in review round 22 and closed here at the same time.
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Fail @"
$Path is a reparse point (a symlink or junction), not a file.

Refusing to write through it: this script runs as an administrator, and following a link
placed by a less privileged account would write wherever that link points. Remove it by
hand and look into how it got there.
"@
        }
    }
}

Assert-NotReparsePoint -Path $KeyPath
Assert-NotReparsePoint -Path (Join-Path $State 'broker-key.pem')

if (Test-Path -LiteralPath $KeyPath) {
    # NEVER ROTATED. The profile store is encrypted under this key; replacing it on a
    # reinstall would make every credential on the machine unreadable, and an installer
    # that destroys data when run twice is an installer nobody can run twice.
    Say "store key already present -- left alone (rotating it would orphan the store)"
} else {
    $kb = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($kb)
    [IO.File]::WriteAllBytes($KeyPath, $kb)
    Say "wrote a random 32-byte store key"
}
Native icacls @($KeyPath, '/setowner', "*${SID_ADMINS}") -What 'setting the store key owner' | Out-Null
Native icacls @($KeyPath, '/inheritance:r') -What 'locking the store key' | Out-Null
Native icacls @($KeyPath, '/grant', "*${SID_SYSTEM}:(F)", "*${SID_ADMINS}:(F)",
                "*${AccountSid}:(F)") -What 'granting on the store key' | Out-Null

# What actually protects it, said honestly rather than claimed.
$bit = (Native 'manage-bde' @('-status', $env:SystemDrive) -AllowFail | Out-String)
if ($bit -match 'Protection\s+On') {
    Say "BitLocker: On for $env:SystemDrive -- a stolen disk does not open this key."
} else {
    Say "BitLocker: NOT on for $env:SystemDrive."
    Say "  The store key is a file on this disk. It is not sealed to hardware and there is"
    Say "  no TPM step here, so anyone who takes the disk and can read it as an"
    Say "  administrator can read the key. BitLocker is what covers that, and it is not"
    Say "  something this installer can claim on your behalf."
}

# -- 6. the task ---------------------------------------------------------------
Step "Scheduled task"
Native schtasks @('/end', '/tn', $TaskName) -AllowFail | Out-Null
Native schtasks @('/delete', '/tn', $TaskName, '/f') -AllowFail | Out-Null

$action  = New-ScheduledTaskAction -Execute $NodePath -Argument "`"$AgentPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
# NOT a New-ScheduledTaskPrincipal. Register-ScheduledTask's parameter sets put -Password
# with -User, and passing it alongside -Principal fails with "Parameter set cannot be
# resolved using the specified named parameters" -- a message that names nothing useful.
# RestartCount is the thing launchd could not offer. A daemon that refuses to start for a
# reason a restart cannot fix must not respawn for ever filling a log nobody watches; three
# attempts and then stop is a give-up count, which is what was missing on macOS.
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -User "$env:COMPUTERNAME\$Account" -Password $plain `
    -RunLevel Limited -Force | Out-Null
Say "registered '$TaskName', starts at boot as $Account"

# The password has done its two jobs. Overwrite the variables rather than leaving them for
# whatever reads this session's memory next.
$plain = $null; $pw = $null; $bytes = $null
[GC]::Collect()

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 4
$info = Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo
Say "state: $((Get-ScheduledTask -TaskName $TaskName).State), last result: $($info.LastTaskResult)"

# -- 7. what to do next --------------------------------------------------------
Step "Done -- and not finished"
Write-Host @"
  Next, in this order:

  1. PROVE IT. Nothing above has been verified from a second account:
       powershell -ExecutionPolicy Bypass -File packaging\verify-windows.ps1

  2. Pair this machine, once, in a terminal no agent is driving:
       wundervault-agent --pair

  3. Hand your agents over, ONE AT A TIME, checking each before the next:
       wundervault-agent --migrate

  What this does NOT give you, stated plainly:
    - Administrators and SYSTEM can open the state directory. So can anyone who takes the
      disk if BitLocker is off. That is the same as root on Linux.
    - There is no sandboxing. The Linux unit restricts the daemon's filesystem, syscalls
      and capabilities; Task Scheduler has no equivalent, so the account split is very
      nearly the whole of the defence here.
    - Any agent you run can read any other agent's token, because they all run as you.
"@ -ForegroundColor Gray

```

## File: packaging/verify-windows.ps1

```
<#
    Prove the Windows install, from a second account.

        powershell -ExecutionPolicy Bypass -File packaging\verify-windows.ps1

    WHY THIS EXISTS AND WHAT IT REFUSES TO DO

    Reading the ACL back and finding it tidy proves that icacls did what icacls was asked.
    It does not prove that another account is shut out -- and the difference is not
    theoretical: the named-pipe transport this phase rejected passed every test written
    from an administrator account and failed for every unprivileged one. So this script
    CREATES A THROWAWAY NON-ADMINISTRATOR ACCOUNT, makes it try, and reads the answer.

    A CHECK THAT DOES NOT RUN IS NOT A CHECK THAT PASSED. `need` fails the script; `skip`
    means "not applicable here" and is reported as neither. Review round 22 found the macOS
    verifier exiting 0 with required checks SKIPped, and that shape is not repeated.
#>

[CmdletBinding()]
param(
    [string] $Account   = 'wundervault',
    [string] $TaskName  = 'wundervault-agent',
    [string] $ProbeUser = 'wv-verify-probe'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Base  = Join-Path $env:ProgramData 'wundervault'
$State = Join-Path $Base 'state'
$Run   = Join-Path $Base 'run'

$script:Failures = 0
$script:Passes   = 0
$script:Skips    = 0
$script:NativeExit = 0

function need {
    param([string] $What, [scriptblock] $Test)
    try {
        $r = & $Test
        if ($r) { Write-Host "  PASS  $What" -ForegroundColor Green; $script:Passes++ }
        else    { Write-Host "  FAIL  $What" -ForegroundColor Red;   $script:Failures++ }
    } catch {
        Write-Host "  FAIL  $What" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkGray
        $script:Failures++
    }
}
function skip {
    param([string] $What, [string] $Why)
    Write-Host "  n/a   $What  ($Why)" -ForegroundColor DarkGray
    $script:Skips++
}
function section { param($m) Write-Host "`n== $m" -ForegroundColor Cyan }

<#
    Run a console program without letting its chatter kill the script.

    Same trap as the installer: with $ErrorActionPreference = 'Stop', anything a native
    program writes to stderr becomes a terminating error. `schtasks /delete` on a task that
    does not exist is the normal case here -- it is how the cleanup is made idempotent --
    and it killed the verifier in its finally block, after thirteen checks had passed and
    before the one that actually matters had run.
#>
function Native {
    param([Parameter(Mandatory)][string] $Exe, [string[]] $Arguments = @())
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $Exe @Arguments 2>&1; $script:NativeExit = $LASTEXITCODE }
    finally { $ErrorActionPreference = $old }
    return $out
}

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This needs Administrator rights: it creates and removes a probe account." -ForegroundColor Red
    exit 1
}

# -- the install itself --------------------------------------------------------
section "The install"

need "the account '$Account' exists" { [bool](Get-LocalUser -Name $Account -ErrorAction SilentlyContinue) }

need "'$Account' is not an administrator" {
    $members = @(Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544') -ErrorAction SilentlyContinue)
    -not ($members | Where-Object { $_.Name -like "*\$Account" })
}

need "the state directory exists" { Test-Path -LiteralPath $State }
need "the run directory exists"   { Test-Path -LiteralPath $Run }

need "the state ACL has no inherited entries" {
    $acl = Get-Acl -LiteralPath $State
    -not ($acl.Access | Where-Object { $_.IsInherited })
}

need "inheritance is switched OFF, not merely unused" {
    # Not the same question. A directory can have inheritance enabled and show no
    # inherited entries today, because its parent has no inheritable ones yet -- and the
    # day the parent gains one, it flows in.
    (Get-Acl -LiteralPath $State).AreAccessRulesProtected -eq $true
}

need "the state directory is owned by Administrators or the broker's account" {
    # An owner holds WRITE_DAC implicitly, so a directory owned by the agents' account is
    # one those agents can unlock whenever they like.
    $sid = (Get-LocalUser -Name $Account).SID.Value
    $owner = (Get-Acl -LiteralPath $State).GetOwner([Security.Principal.SecurityIdentifier]).Value
    $owner -eq 'S-1-5-32-544' -or $owner -eq $sid -or $owner -eq 'S-1-5-18'
}

need "the state ACL names only the account, SYSTEM and Administrators" {
    $sid = (Get-LocalUser -Name $Account).SID.Value
    $allowed = @('S-1-5-18', 'S-1-5-32-544', $sid,
                 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $acl = Get-Acl -LiteralPath $State
    $bad = $acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' } | ForEach-Object {
        $s = try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
             catch { $_.IdentityReference.Value }
        if ($allowed -notcontains $s) { $s }
    }
    -not $bad
}

need "the account has SeBatchLogonRight" {
    $sid = (Get-LocalUser -Name $Account).SID.Value
    $tmp = Join-Path $env:TEMP ("wv-verify-" + [guid]::NewGuid().ToString('N') + ".inf")
    try {
        Native secedit @('/export', '/cfg', $tmp, '/areas', 'USER_RIGHTS') | Out-Null
        $line = Get-Content $tmp | Where-Object { $_ -match '^SeBatchLogonRight' }
        # secedit may render the account by NAME rather than SID on export, so both count.
        [bool]($line -match [regex]::Escape($sid) -or $line -match "\b$([regex]::Escape($Account))\b")
    } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
}

need "the task exists and is registered to run as '$Account'" {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $t -and ($t.Principal.UserId -like "*$Account")
}

need "the task is running" {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $t -and $t.State -eq 'Running'
}

need "the broker is running AS '$Account', not as anyone else" {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object {
        $_.CommandLine -and $_.CommandLine -match 'agent\.js'
    })
    if ($procs.Count -eq 0) { throw "no broker process found" }
    $owners = $procs | ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User }
    [bool]($owners -contains $Account)
}

need "the broker published its management endpoint" {
    Test-Path -LiteralPath (Join-Path $Run 'mgmt\mgmt.port')
}

need "the broker published a public key for agents to verify against" {
    $p = Join-Path $Run 'broker.pub'
    (Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p).Length -gt 32)
}

need "the store key is 32 bytes and is not a reparse point" {
    $p = Join-Path $State 'store.key'
    $i = Get-Item -LiteralPath $p -Force
    ($i.Length -eq 32) -and -not ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

# -- the boundary, proved from a second account --------------------------------
section "The boundary, from an account that is not yours and not the broker's"

$probeMade = $false
$probePw   = $null
try {
    $bytes = New-Object byte[] 36
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $probePw = [Convert]::ToBase64String($bytes) + '!aA1'
    $sec = ConvertTo-SecureString $probePw -AsPlainText -Force

    if (Get-LocalUser -Name $ProbeUser -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name $ProbeUser -Password $sec
    } else {
        New-LocalUser -Name $ProbeUser -Password $sec `
            -Description 'temporary: wundervault install verification' `
            -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    }
    $probeMade = $true
    $probeSid = (Get-LocalUser -Name $ProbeUser).SID.Value

    # The probe needs the batch logon right to run at all -- the same right the broker's
    # account needs, and the same trap: schtasks does not grant it and says so quietly.
    $secDir = Join-Path $env:TEMP ("wv-vprobe-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $secDir -Force | Out-Null
    try {
        $cur = Join-Path $secDir 'cur.inf'
        Native secedit @('/export', '/cfg', $cur, '/areas', 'USER_RIGHTS') | Out-Null
        $line = Get-Content $cur | Where-Object { $_ -match '^SeBatchLogonRight' }
        $vals = if ($line) { ($line -split '=', 2)[1].Trim() } else { '' }
        if ($vals -notmatch [regex]::Escape($probeSid)) {
            $vals = if ($vals) { "$vals,*$probeSid" } else { "*$probeSid" }
        }
        $inf = Join-Path $secDir 'apply.inf'
        @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeBatchLogonRight = $vals
"@ | Out-File -FilePath $inf -Encoding unicode
        Native secedit @('/configure', '/db', (Join-Path $secDir 'apply.sdb'), '/cfg', $inf,
                         '/areas', 'USER_RIGHTS') | Out-Null
    } finally { Remove-Item -Recurse -Force $secDir -ErrorAction SilentlyContinue }

    $work = Join-Path $env:TEMP ("wv-verify-work-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    Native icacls @($work, '/grant', "*${probeSid}:(OI)(CI)F") | Out-Null
    $out = Join-Path $work 'probe.txt'

    $probeScript = Join-Path $work 'probe.ps1'
    @"
`$ErrorActionPreference = 'Continue'
`$lines = @()
`$lines += "user=`$env:USERNAME"
try { Get-ChildItem -LiteralPath '$State' -ErrorAction Stop | Out-Null; `$lines += 'state_list=ALLOWED' }
catch { `$lines += 'state_list=DENIED' }
try { [IO.File]::ReadAllBytes((Join-Path '$State' 'store.key')) | Out-Null; `$lines += 'key_read=ALLOWED' }
catch { `$lines += 'key_read=DENIED' }
try { Get-ChildItem -LiteralPath '$Run' -ErrorAction Stop | Out-Null; `$lines += 'run_list=ALLOWED' }
catch { `$lines += 'run_list=DENIED' }
try {
  `$f = Join-Path '$Run' ('probe-' + [guid]::NewGuid().ToString('N') + '.port')
  [IO.File]::WriteAllText(`$f, 'x'); Remove-Item -LiteralPath `$f -Force
  `$lines += 'run_write=ALLOWED'
} catch { `$lines += 'run_write=DENIED' }
# AND THE HALF THAT MUST WORK. A boundary that also shuts out the agents is an outage,
# not a boundary -- and this is the exact shape of the failure that killed the named-pipe
# transport: reachable from an administrator, EPERM from everybody else.
try {
  `$rec = Get-Content -LiteralPath (Join-Path '$Run' 'mgmt\mgmt.port') -Raw | ConvertFrom-Json
  `$c = New-Object Net.Sockets.TcpClient
  `$c.Connect('127.0.0.1', [int]`$rec.port)
  `$st = `$c.GetStream()
  `$w = New-Object IO.StreamWriter(`$st); `$r = New-Object IO.StreamReader(`$st)
  `$w.NewLine = "``n"; `$w.AutoFlush = `$true
  `$w.WriteLine('{"hello":"wv-broker-hello-v1","nonce":"probe0123456789"}')
  `$banner = `$r.ReadLine()
  `$w.WriteLine('{"action":"ping"}')
  `$pong = `$r.ReadLine()
  `$c.Close()
  if (`$pong -match '"ok":true') { `$lines += 'broker_reach=ALLOWED' } else { `$lines += "broker_reach=ODD:`$pong" }
  if (`$banner -match '"sig"') { `$lines += 'broker_signed=YES' } else { `$lines += 'broker_signed=NO' }
} catch { `$lines += "broker_reach=FAILED:`$(`$_.Exception.Message)" }
`$lines | Set-Content -LiteralPath '$out'
"@ | Out-File -FilePath $probeScript -Encoding UTF8

    Native schtasks @('/delete', '/tn', 'wv-verify-probe', '/f') | Out-Null
    Native schtasks @('/create', '/tn', 'wv-verify-probe',
        '/tr', "powershell -NoProfile -ExecutionPolicy Bypass -File `"$probeScript`"",
        '/sc', 'once', '/st', '00:00', '/ru', $ProbeUser, '/rp', $probePw,
        '/rl', 'limited', '/f') | Out-Null
    if ($script:NativeExit -ne 0) { throw "could not register the probe task" }
    Native schtasks @('/run', '/tn', 'wv-verify-probe') | Out-Null

    $deadline = (Get-Date).AddSeconds(45)
    while (-not (Test-Path -LiteralPath $out) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }

    if (-not (Test-Path -LiteralPath $out)) {
        need "the probe account ran at all" { throw "the probe task produced no output within 45s" }
    } else {
        $res = @{}
        foreach ($l in Get-Content -LiteralPath $out) {
            $kv = $l -split '=', 2
            if ($kv.Count -eq 2) { $res[$kv[0]] = $kv[1] }
        }
        Write-Host "  (probe ran as '$($res['user'])')" -ForegroundColor DarkGray

        need "a non-administrator CANNOT list the state directory" { $res['state_list'] -eq 'DENIED' }
        need "a non-administrator CANNOT read the store key"       { $res['key_read']   -eq 'DENIED' }
        need "a non-administrator CAN list the run directory"      { $res['run_list']   -eq 'ALLOWED' }
        need "a non-administrator CANNOT write to the run directory" { $res['run_write'] -eq 'DENIED' }
        # The other half. Everything above is the wall; this is the door.
        need "a non-administrator CAN reach the broker and get an answer" { $res['broker_reach'] -eq 'ALLOWED' }
        need "the broker proves itself to a non-administrator too"        { $res['broker_signed'] -eq 'YES' }
    }
} finally {
    Native schtasks @('/end', '/tn', 'wv-verify-probe') | Out-Null
    Native schtasks @('/delete', '/tn', 'wv-verify-probe', '/f') | Out-Null
    if ($probeMade) { Remove-LocalUser -Name $ProbeUser -ErrorAction SilentlyContinue }
    Get-ChildItem $env:TEMP -Filter 'wv-verify-work-*' -Directory -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $probePw = $null
    Write-Host "  (probe account and task removed)" -ForegroundColor DarkGray
}

# -- the daemon's own opinion --------------------------------------------------
section "What the broker says about itself"

# TALKS TO THE BROKER DIRECTLY, rather than through the CLI.
#
# The first version of this ran `wundervault-agent --ping`. That flag does not exist, and
# an unrecognised flag fell through to "start a broker in the foreground" -- so the
# verifier started a SECOND broker, as the verifying user, and hung for ever. The daemon
# now refuses unknown options, and this asks the management endpoint the question directly:
# one TCP connect to the port the broker published, one JSON line, one answer.
#
# It also proves something the ACL checks cannot: that the OWNER'S account can reach the
# endpoint. A boundary that also shuts out the people who are supposed to get through is
# not a boundary, it is an outage.
$mgmtFile = Join-Path $Run 'mgmt\mgmt.port'
if (-not (Test-Path -LiteralPath $mgmtFile)) {
    need "the broker answers on its management endpoint" { throw "no mgmt.port at $mgmtFile" }
} else {
    $rec = Get-Content -LiteralPath $mgmtFile -Raw | ConvertFrom-Json

    $reply = $null
    try {
        $client = New-Object Net.Sockets.TcpClient
        $client.Connect('127.0.0.1', [int]$rec.port)
        $stream = $client.GetStream()
        $writer = New-Object IO.StreamWriter($stream)
        $reader = New-Object IO.StreamReader($stream)
        $writer.NewLine = "`n"; $writer.AutoFlush = $true
        # The hello first, exactly as an agent does it, then the request.
        $nonce = -join (1..32 | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
        $writer.WriteLine((@{ hello = 'wv-broker-hello-v1'; nonce = $nonce } | ConvertTo-Json -Compress))
        $banner = $reader.ReadLine()
        $writer.WriteLine((@{ action = 'ping' } | ConvertTo-Json -Compress))
        $reply = $reader.ReadLine()
        $client.Close()
    } catch { $reply = $null }

    need "the broker answers on the port it published" { [bool]$reply }

    if ($reply) {
        $p = $reply | ConvertFrom-Json
        need "the broker signs the handshake" {
            $b = $banner | ConvertFrom-Json
            $b.server_id -eq $rec.server_id -and $b.sig -and $b.sig.Length -gt 40
        }
        need "the broker reports a REAL boundary" { $p.boundary -eq $true }
        need "the broker reports running as '$Account'" { $p.account -eq $Account }
        need "the store key is a real key, not a derived one" {
            $p.key_mode -eq 'local-file' -or $p.key_mode -eq 'sealed-tpm' -or $p.key_mode -eq 'sealed-host'
        }
        Write-Host "  (broker $($p.version), key_mode=$($p.key_mode), boundary=$($p.boundary))" -ForegroundColor DarkGray
    }
}

# -- verdict -------------------------------------------------------------------
Write-Host ""
Write-Host "  $($script:Passes) passed, $($script:Failures) failed, $($script:Skips) not applicable"
if ($script:Failures -gt 0) {
    Write-Host "`nThe boundary is NOT verified on this machine." -ForegroundColor Red
    Write-Host "Do not describe Windows as supported until this exits clean." -ForegroundColor Red
    exit 1
}
Write-Host "`nVerified: the broker runs as its own account and yours cannot open its state." -ForegroundColor Green
exit 0

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
- [round 21 F3] rejected: The legacy fallback cannot open a pre-phase-7 macOS store after the uid split, because the old store was keyed on the owner uid and the daemon now runs as another
  reason: The arithmetic is right and the conclusion does not follow, because nothing ever asks the daemon to open that store. Migration deliberately carries no credentials: `--migrate` runs as the OWNER, and legacyAgentNames() in migrate.ts derives with the owner's uid to read only the agent NAMES; the credentials are replaced by REPAIR in the dashboard, which is the phase-4 design. The daemon's loadProfiles fallback exists for a store THIS ACCOUNT wrote under the previous derivation, not for the pre-split user store. Reviewer was not shown migrate.ts. What it did catch is a comment of mine that implied the fallback carried a macOS store across — that overclaim is now corrected in the source, with an explicit note not to 'fix' it into reaching across the uid boundary.
- [round 21 F7] rejected: The Windows pre-split warning changed, though the spec requires it byte-for-byte unchanged
  reason: The text did change and it had to. The removed sentence was 'The boundary is Linux-only for now.', which this phase makes FALSE — keeping it byte-for-byte would ship a statement the release contradicts. The spec's 'byte for byte' was about Windows BEHAVIOUR being untouched, which it is: shape 'none', splitAvailable() false, pre-split layout, warning printed. Spec amended to say behaviour rather than bytes, so the next round is not told the same thing.
- [round 22 F2] rejected: Umask 63 makes Node create the unix sockets at 0700, so agents get EACCES connecting
  reason: The code explicitly chmods every socket to 0666 in its listen callback — src/agent.ts:941 for the per-agent sockets, :1215 for the management socket — and chmod is absolute, so umask does not apply to it. The reviewer was not shown agent.ts this round, which is exactly the case I asked it to flag rather than assume, and it was right to raise it. What is real and smaller: between listen() and the chmod there is a brief window at the umask-masked mode, which fails CLOSED (an agent connecting in that window is refused and retries), so it is not worth a startup-ordering change. The same reviewer reflex found the genuine version of this bug in the DIRECTORIES, which is fixed.
