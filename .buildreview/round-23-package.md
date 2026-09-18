# Review package — round 23
generated 2026-09-18T20:31:31+00:00

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
    principal outside the allowed set; or inheritance is enabled.
14. `boundaryIsReal()` returns **true** only in the installed configuration. **[win199]**
15. Granting `Users:(R)` on the state root after a correct install flips check 13 to false
    at the next start. **[win199]**

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
26. `splitAvailableFor('linux', 'windows')` is **false** and `splitAvailableFor('win32',
    'linux')` is **false**: the override relocates state, it never manufactures a boundary.
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

PHASE 8 ROUND 1 (round 23 overall) -- THE TRANSPORT AND THE PATH LAYER.

src/agent.ts and the two PowerShell scripts go to round 24. Do not report their absence as
a finding; do flag any finding that DEPENDS on them as unverified.

WHAT YOU HAVE AND WHAT YOU DO NOT
- Full text of the NEW module src/endpoint.ts.
- A diff of src/ and package.json. src/paths.ts and src/agent.ts are LARGE and are sent as
  diff only -- you have not seen their unchanged parts. If a finding depends on code you
  were not shown, SAY SO and flag it as unverified rather than asserting it.
- You have NOT seen: src/agent.ts (the daemon itself -- it calls listenOn/withHello and
  owns machineIdentity, the startup warning and the key-mode report),
  packaging/install-daemon-windows.ps1, packaging/verify-windows.ps1,
  test/windows-shape.test.ts, src/server.ts, src/enrol.ts, src/broker-sign.ts.

WHAT WAS MEASURED ON A REAL WINDOWS 10 22H2 BOX (win199, Node 22) -- these are facts, not
assumptions, and a finding that contradicts one of them is wrong:
- net.Server.listen() on a filesystem path returns EACCES. Unix sockets do not exist here.
- A named pipe created by Node running as a NON-ADMIN service account was connectable by an
  ADMINISTRATOR but returned EPERM to a genuinely non-admin account. Node cannot supply a
  security descriptor. This is why the transport is loopback TCP.
- chmod is a no-op: chmod(0o700) then stat() reports 666. statSync().uid is 0.
  process.getuid is undefined.
- An NTFS ACL with inheritance removed DID deny a non-admin read and list.
- The SMBIOS UUID on this real machine is 00000000-0000-0000-0000-AC1F6B1C4252.
- PowerShell 5.1 reads .ps1 as ANSI without a BOM.

WHAT WAS RUN END TO END ON THAT BOX, ALL PASSING:
- npm install -g exits 0 (it exited 1 on every Windows machine since the first release;
  postinstall was `chmod +x ... 2>/dev/null || true`, which cmd.exe cannot run). The
  postinstall was REMOVED rather than made portable, after proving npm's own bin-linking
  sets the exec bit: packed the tarball with dist/*.js at mode 644, installed with
  --ignore-scripts, and the installed files came out 0755.
- The daemon starts, runs as its own account 'wundervault', writes state to
  %ProgramData%\wundervault\state and discovery files to ...\run.
- The verifier passes 24/24, including from a THIRD, non-admin account: it cannot list the
  state directory or read store.key, and it CAN reach the broker and get a signed answer.
- Granting Users:(RX) on the state directory flips the daemon's reported boundary to false
  at the next start while it KEEPS SERVING; removing the grant flips it back to true.
- 550 unit tests pass on Linux.

SIX GUARDS WERE SABOTAGE-TESTED (broken deliberately; the suite caught each one): the
degenerate-UUID rejection, the inherited-ACE rejection, the handshake signature check, the
server_id match, listenOn's refusal when the discovery file cannot be written, and
withHello's POSIX passthrough.

SPECIFIC THINGS I WANT ATTACKED
1. The hello handshake in endpoint.ts. Is the signed material sufficient? Can a squatter
   replay anything? Is the socket handed to the caller in a state where a partial banner
   could be misread as a reply?
2. withHello's hand-off: it removes its own data listener, calls onConnection, then
   re-emits buffered bytes via socket.emit('data', ...). Is there an ordering or
   backpressure hazard, or a path where bytes are lost or delivered twice?
3. principalId() replaced `getuid?.() ?? 0` in derivedKeyFor and lock.ts. Does that change
   any EXISTING POSIX-derived value? It must not.
4. windowsStateRoot()'s rule: use the installed root if we are the service account, else
   only if the ACL is restricted. Is there a case where a rogue gets the daemon to store
   credentials somewhere it should not?
5. The ACL parsing (parseAclReport/windowsAclIsPrivate/windowsAclIsRestricted). Can a
   crafted or localised report read as private when it is not?
6. Anything that reaches Linux or macOS behaviour. This phase must leave both unchanged.

## Diff

```diff
diff --git a/package.json b/package.json
index ddb22cd..981433f 100644
--- a/package.json
+++ b/package.json
@@ -12,8 +12,7 @@
   "scripts": {
     "build": "tsc",
     "test": "vitest run",
-    "prepublishOnly": "npm run build && npm test",
-    "postinstall": "chmod +x dist/agent.js dist/index.js 2>/dev/null || true"
+    "prepublishOnly": "npm run build && npm test"
   },
   "keywords": [
     "mcp",
diff --git a/src/broker-client.ts b/src/broker-client.ts
index 79594f6..055b6d3 100644
--- a/src/broker-client.ts
+++ b/src/broker-client.ts
@@ -13,9 +13,12 @@
  * "fix" a future bug here is to fetch the ciphertext and open it locally, which would
  * quietly reinstate the thing the phase removed.
  */
-import net from 'node:net';
 import { existsSync, readFileSync } from 'node:fs';
 import { agentSocketPath, agentTokenPath, legacy } from './paths.js';
+import {
+  agentEndpoint, connectToEndpoint, endpointLabel, usesPortFiles,
+  BrokerNotAuthentic, type Endpoint,
+} from './endpoint.js';
 
 /** Long enough for a brokered HTTP call (30s upstream) and a tier-2 wait (~90s). */
 const RPC_TIMEOUT_MS = 150_000;
@@ -26,14 +29,31 @@ export class BrokerUpgradeRequired extends Error {}
 
 export interface BrokerReply { [k: string]: unknown; error?: string; code?: string }
 
-function socketCandidates(agentName: string): Array<{ path: string; legacy: boolean }> {
-  const primary = agentSocketPath(agentName);
-  const out = [{ path: primary, legacy: false }];
-  const old = legacy.agentSocket(agentName);
-  if (old !== primary) out.push({ path: old, legacy: true });
+/**
+ * Every address this agent's broker might be at, best first.
+ *
+ * The pre-split socket in the user's home is still tried, because a machine mid-migration
+ * has to keep working. On Windows there is no pre-split socket to try: `listen()` on a
+ * filesystem path has never worked there, so no Windows machine has ever had one, and
+ * offering it would be a candidate that cannot exist.
+ */
+function endpointCandidates(agentName: string): Array<{ ep: Endpoint; legacy: boolean }> {
+  const out: Array<{ ep: Endpoint; legacy: boolean }> = [
+    { ep: agentEndpoint(agentName), legacy: false },
+  ];
+  if (!usesPortFiles()) {
+    const primary = agentSocketPath(agentName);
+    const old = legacy.agentSocket(agentName);
+    if (old !== primary) out.push({ ep: { kind: 'path', address: old }, legacy: true });
+  }
   return out;
 }
 
+/** Is there anything at this address to try? */
+function endpointExists(ep: Endpoint): boolean {
+  return existsSync(ep.kind === 'path' ? ep.address : ep.file);
+}
+
 export class BrokerClient {
   private token: string;
   private warnedLegacy = false;
@@ -52,9 +72,14 @@ export class BrokerClient {
    * call costs a unix-socket connect and removes a whole class of "it worked until it
    * had been idle for two minutes" bug.
    */
-  private rpc(sockPath: string, payload: Record<string, unknown>): Promise<BrokerReply> {
+  private async rpc(ep: Endpoint, payload: Record<string, unknown>): Promise<BrokerReply> {
+    // CONNECT FIRST, AND ON WINDOWS DO NOT SPEAK UNTIL THE FAR END HAS PROVED ITSELF.
+    // connectToEndpoint resolves only after the hello is verified, so by the time this
+    // function writes a token it is writing it to something holding the broker's private
+    // key. On the unix-socket platforms it is a plain connect and nothing has changed.
+    const socket = await connectToEndpoint(ep, RPC_TIMEOUT_MS);
+    const label = endpointLabel(ep);
     return new Promise((resolve, reject) => {
-      const socket = net.createConnection(sockPath);
       let buf = '';
       let done = false;
       const finish = (fn: () => void) => {
@@ -69,9 +94,7 @@ export class BrokerClient {
           `The secret broker did not answer within ${Math.round(RPC_TIMEOUT_MS / 1000)}s.`))),
         RPC_TIMEOUT_MS,
       );
-      socket.on('connect', () => {
-        socket.write(JSON.stringify({ token: this.token, ...payload }) + '\n');
-      });
+      socket.write(JSON.stringify({ token: this.token, ...payload }) + '\n');
       socket.on('data', (d) => {
         buf += d.toString();
         // A reply is bounded so a broken or hostile socket cannot grow this without end.
@@ -88,7 +111,7 @@ export class BrokerClient {
         });
       });
       socket.on('error', (e) => finish(() => reject(new BrokerUnavailable(
-        `Could not reach the secret broker at ${sockPath}: ${(e as Error).message}`))));
+        `Could not reach the secret broker at ${label}: ${(e as Error).message}`))));
       socket.on('end', () => {
         if (!buf.includes('\n')) {
           finish(() => reject(new BrokerUnavailable('The broker closed the connection without replying.')));
@@ -111,14 +134,14 @@ export class BrokerClient {
         + `or WUNDERVAULT_AGENT_TOKEN. Re-run enrolment: wundervault-agent --enrol`);
     }
     let lastErr: Error | null = null;
-    for (const cand of socketCandidates(this.agentName)) {
-      if (!existsSync(cand.path)) continue;
+    for (const cand of endpointCandidates(this.agentName)) {
+      if (!endpointExists(cand.ep)) continue;
       try {
-        const reply = await this.rpc(cand.path, { op, ...payload });
+        const reply = await this.rpc(cand.ep, { op, ...payload });
         if (cand.legacy && !this.warnedLegacy) {
           this.warnedLegacy = true;
           process.stderr.write(
-            `[wundervault] Using the pre-split broker socket at ${cand.path}.\n`
+            `[wundervault] Using the pre-split broker socket at ${endpointLabel(cand.ep)}.\n`
             + `[wundervault] That process runs as YOUR user, so its key material and memory\n`
             + `[wundervault] are readable by anything you run, including your agents.\n`
             + `[wundervault] Finish the split: sudo sh packaging/install-daemon.sh\n`);
@@ -129,14 +152,18 @@ export class BrokerClient {
         return reply;
       } catch (e) {
         if (e instanceof BrokerUpgradeRequired) throw e;
+        // A far end that could not prove it is the broker is not a candidate that failed;
+        // it is a stranger holding the address. Stop, and say so — falling through to the
+        // next candidate would be the moment a token gets offered somewhere else.
+        if (e instanceof BrokerNotAuthentic) throw e;
         lastErr = e as Error;
       }
     }
     throw new BrokerUnavailable(
       lastErr?.message
       ?? `wundervault-agent is not running for agent '${this.agentName}'.\n`
-         + `Expected socket: ${agentSocketPath(this.agentName)}\n`
-         + `Install the broker: sudo sh packaging/install-daemon.sh\n`
+         + `Expected at: ${endpointLabel(agentEndpoint(this.agentName))}\n`
+         + `Install the broker: ${installerHint()}\n`
          + `Then enrol:        wundervault-agent --enrol`);
   }
 
@@ -174,3 +201,12 @@ export function brokerClient(): BrokerClient {
 
 /** Test seam. */
 export function _resetBrokerClient(): void { _client = null; }
+
+/** The install command for this platform, for a message someone has to act on. */
+function installerHint(): string {
+  if (process.platform === 'win32') {
+    return 'powershell -ExecutionPolicy Bypass -File packaging\\install-daemon-windows.ps1  (as Administrator)';
+  }
+  if (process.platform === 'darwin') return 'sudo sh packaging/install-daemon-macos.sh';
+  return 'sudo sh packaging/install-daemon.sh';
+}
diff --git a/src/broker-key.ts b/src/broker-key.ts
index a5ccd4d..8589ce4 100644
--- a/src/broker-key.ts
+++ b/src/broker-key.ts
@@ -110,11 +110,21 @@ export function loadOrCreateIdentity(): BrokerIdentity {
     if (!st.isFile()) {
       throw new Error(`${p} is not a regular file.`);
     }
-    if ((st.mode & 0o077) !== 0) {
+    // A MODE CHECK, ON THE PLATFORMS THAT HAVE MODES.
+    //
+    // Windows does not. chmod there is a no-op and stat reports 666 for every file on the
+    // volume, so this check fired on every Windows machine -- correctly installed or not --
+    // and refused to start with advice to run `sudo chmod 600`, on an operating system with
+    // neither command. Observed on Windows 10, running as the service account, inside a
+    // directory whose ACL was exactly right.
+    //
+    // What guards this file on Windows is the state directory's ACL, which boundaryIsReal()
+    // checks and verify-windows.ps1 proves from a second account.
+    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
       throw new Error(
         `${p} is mode ${(st.mode & 0o777).toString(8)}, which is readable beyond its owner. `
         + `That key is what every sealed credential on this machine depends on. `
-        + `Fix it with: sudo chmod 600 ${p}`);
+        + `Fix it with: chmod 600 ${p}`);
     }
     privateKeyPem = fs.readFileSync(p, 'utf8');
   } else {
diff --git a/src/lock.ts b/src/lock.ts
index e748241..50d7cda 100644
--- a/src/lock.ts
+++ b/src/lock.ts
@@ -75,6 +75,7 @@ import net from 'node:net';
 import { execFileSync } from 'node:child_process';
 import path from 'node:path';
 import os from 'node:os';
+import { principalId } from './paths.js';
 
 export interface Holder {
   pid: number | null;
@@ -140,8 +141,8 @@ function addressKey(): string {
   // The abstract namespace and the loopback port range are MACHINE-global, not
   // per-user, so the uid belongs in the key: without it two OS accounts on one
   // box exclude each other over credentials they do not share.
-  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
-  const digest = createHash('sha256').update(`${uid}:${agentName()}`).digest('hex').slice(0, 12);
+  const digest = createHash('sha256')
+    .update(`${principalId()}:${agentName()}`).digest('hex').slice(0, 12);
   return `${slug().slice(0, 32)}-${digest}`;
 }
 
@@ -169,8 +170,13 @@ function addressPort(): number {
   // The port range is MACHINE-global, not per-user, so the uid belongs in the digest:
   // without it two OS accounts on one box exclude each other over credentials they do not
   // share.
-  const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
-  const digest = createHash('sha256').update(`wundervault-mcp:${uid}:${agentName()}`).digest();
+  // principalId(), not `getuid() : 0`. The comment two lines up is the specification and
+  // on Windows the code contradicted it: getuid is undefined there, so every account got
+  // principal 0, and two users running an agent of the same name derived the SAME PORT —
+  // each telling the other its credential was already in use, over credentials they do not
+  // share. Measured on Windows 10, 2026-09-18.
+  const digest = createHash('sha256')
+    .update(`wundervault-mcp:${principalId()}:${agentName()}`).digest();
   return 20000 + (digest.readUInt16BE(0) % 12768);
 }
 
diff --git a/src/migrate.ts b/src/migrate.ts
index 1b623a9..ad56731 100644
--- a/src/migrate.ts
+++ b/src/migrate.ts
@@ -26,29 +26,58 @@
  */
 import fs from 'node:fs';
 import path from 'node:path';
-import net from 'node:net';
 import crypto from 'node:crypto';
 import { execFile } from 'node:child_process';
 import { legacy, mgmtSocketPath, splitAvailable, systemRoot, isInside } from './paths.js';
+import { mgmtEndpoint, connectToEndpoint, endpointLabel, type Endpoint } from './endpoint.js';
 
-/** One request/response over a socket. */
-export function ask(payload: unknown, sockPath = mgmtSocketPath(), timeoutMs = 30_000): Promise<any> {
+/**
+ * One request/response to the management endpoint.
+ *
+ * Takes an ENDPOINT rather than a path, because on Windows the broker is reached by a port
+ * and the connection is not complete until the far end has signed a nonce. The signature
+ * check lives in connectToEndpoint, so everything that talks to the broker inherits it
+ * instead of each caller remembering.
+ *
+ * The `sockPath` overload is kept for the tests that stand up a socket of their own.
+ */
+export function ask(
+  payload: unknown,
+  where: string | Endpoint = mgmtEndpoint(),
+  timeoutMs = 30_000,
+): Promise<any> {
+  const ep: Endpoint = typeof where === 'string' ? { kind: 'path', address: where } : where;
+  const label = endpointLabel(ep);
   return new Promise((resolve, reject) => {
-    const sock = net.createConnection(sockPath);
-    let buf = '';
-    const done = (fn: () => void) => { clearTimeout(timer); sock.destroy(); fn(); };
+    let settled = false;
     const timer = setTimeout(
-      () => done(() => reject(new Error(`timed out talking to the daemon at ${sockPath}`))),
+      () => { if (!settled) { settled = true; reject(new Error(`timed out talking to the daemon at ${label}`)); } },
       timeoutMs,
     );
-    sock.on('connect', () => sock.write(JSON.stringify(payload) + '\n'));
-    sock.on('data', (d) => {
-      buf += d.toString();
-      if (!buf.includes('\n')) return;
-      try { done(() => resolve(JSON.parse(buf.trim()))); }
-      catch { done(() => reject(new Error('unparseable reply from the daemon'))); }
+    connectToEndpoint(ep, timeoutMs).then((sock) => {
+      if (settled) { try { sock.destroy(); } catch { /* gone */ } return; }
+      let buf = '';
+      const done = (fn: () => void) => {
+        if (settled) return;
+        settled = true;
+        clearTimeout(timer);
+        sock.destroy();
+        fn();
+      };
+      sock.on('data', (d) => {
+        buf += d.toString();
+        if (!buf.includes('\n')) return;
+        try { const v = JSON.parse(buf.trim()); done(() => resolve(v)); }
+        catch { done(() => reject(new Error('unparseable reply from the daemon'))); }
+      });
+      sock.on('error', (e) => done(() => reject(e)));
+      sock.write(JSON.stringify(payload) + '\n');
+    }).catch((e: Error) => {
+      if (settled) return;
+      settled = true;
+      clearTimeout(timer);
+      reject(e);
     });
-    sock.on('error', (e) => done(() => reject(e)));
   });
 }
 
@@ -191,7 +220,7 @@ export async function status(): Promise<MigrationStatus> {
   const oldStorePath = legacy.profiles();
   const ping = await ask({ action: 'ping' }).catch((e) => {
     throw new Error(
-      `Could not reach the secret broker at ${mgmtSocketPath()}: ${(e as Error).message}\n` +
+      `Could not reach the secret broker at ${endpointLabel(mgmtEndpoint())}: ${(e as Error).message}\n` +
       `Install it first:  sudo sh packaging/install-daemon.sh\n` +
       `Then check:        systemctl status wundervault-agent`,
     );
diff --git a/src/paths.ts b/src/paths.ts
index 90029a5..a85378e 100644
--- a/src/paths.ts
+++ b/src/paths.ts
@@ -32,6 +32,7 @@
 import * as fs from 'node:fs';
 import * as os from 'node:os';
 import * as path from 'node:path';
+import { execFileSync } from 'node:child_process';
 
 /** The packaged default. Overridable for tests and for a non-standard install. */
 export const DEFAULT_SYSTEM_ROOT = '/var/lib/wundervault';
@@ -62,6 +63,27 @@ export const DARWIN_BASE = '/var/lib/wundervault';
 export const DARWIN_SYSTEM_ROOT = `${DARWIN_BASE}/state`;
 export const DARWIN_ACCOUNT = '_wundervault';
 
+/**
+ * Windows, where the same shape is built out of a different mechanism.
+ *
+ *   %ProgramData%\wundervault        everyone may traverse; holds nothing readable
+ *   %ProgramData%\wundervault\state  THE BOUNDARY — an ACL, not a mode
+ *   %ProgramData%\wundervault\run    everyone reads; only the account writes
+ *
+ * Run is a SIBLING of state for the same reason as macOS and by a different route: on
+ * macOS 0700 denies search permission to the agents, on Windows the state ACL simply does
+ * not name them. Either way the agents must reach their endpoint, and the endpoint must
+ * not live behind the boundary.
+ *
+ * `%ProgramData%` rather than `/var/lib`, which on Windows silently becomes `C:\var\lib`
+ * — a directory the daemon would create successfully and then fail to use, which is the
+ * quiet version of this bug that `platformShape()` already warns about below.
+ */
+export const WINDOWS_BASE = (): string =>
+  path.join(process.env.ProgramData || 'C:\\ProgramData', 'wundervault');
+export const WINDOWS_SYSTEM_ROOT = (): string => path.join(WINDOWS_BASE(), 'state');
+export const WINDOWS_ACCOUNT = 'wundervault';
+
 /**
  * Daemon-owned state.
  *
@@ -100,14 +122,15 @@ export const DARWIN_ACCOUNT = '_wundervault';
  * And neither of them is what we tell the user. That is `boundaryIsReal()`, below, which
  * looks at the directory rather than at the operating system.
  */
-export type PlatformShape = 'linux' | 'darwin' | 'none';
+export type PlatformShape = 'linux' | 'darwin' | 'windows' | 'none';
 
 /** Platforms on which a second uid is actually reachable. NOT overridable. */
-const SPLIT_CAPABLE = new Set(['linux', 'darwin']);
+const SPLIT_CAPABLE = new Set(['linux', 'darwin', 'win32']);
 
 function shapeFor(platform: string): PlatformShape {
   if (platform === 'linux') return 'linux';
   if (platform === 'darwin') return 'darwin';
+  if (platform === 'win32') return 'windows';
   return 'none';
 }
 
@@ -119,10 +142,11 @@ function shapeFor(platform: string): PlatformShape {
 export function platformShape(): PlatformShape {
   const override = process.env.WUNDERVAULT_PLATFORM_SHAPE;
   if (override) {
-    if (override !== 'linux' && override !== 'darwin' && override !== 'none') {
+    if (override !== 'linux' && override !== 'darwin' && override !== 'windows'
+        && override !== 'none') {
       throw new Error(
         `WUNDERVAULT_PLATFORM_SHAPE=${JSON.stringify(override)} is not one of ` +
-        `linux, darwin, none.`,
+        `linux, darwin, windows, none.`,
       );
     }
     return override;
@@ -137,7 +161,22 @@ export function platformShape(): PlatformShape {
  * relocates state, it does not conjure an account the operating system cannot give us.
  */
 export function splitAvailableFor(realPlatform: string, shape: PlatformShape): boolean {
-  return SPLIT_CAPABLE.has(realPlatform) && shape !== 'none';
+  if (shape === 'none') return false;
+  if (!SPLIT_CAPABLE.has(realPlatform)) return false;
+  // WINDOWS CANNOT HOST A POSIX LAYOUT, and this is not pedantry about tidiness. The
+  // linux and darwin shapes put unix domain sockets at filesystem paths, and `listen()`
+  // on a filesystem path returns EACCES on Windows — measured, Node 22 on Windows 10.
+  // Under either override a Windows daemon would bind nothing at all, so there is no
+  // boundary to claim and the pre-split layout is the right answer.
+  //
+  // The reverse is deliberately permitted: a Linux box may be told to use the darwin or
+  // windows layout, because exercising another platform's paths from CI is the only
+  // defence against the failure mode that put this project here twice — code on a path
+  // nobody can run until a customer runs it. What stops that becoming a false claim is
+  // boundaryIsReal(), which looks at the directory: under the windows shape it wants
+  // icacls, which a Linux box does not have, and answers false.
+  if (realPlatform === 'win32') return shape === 'windows';
+  return true;
 }
 
 /** True where the daemon CAN hold a real privilege boundary. Not that it does. */
@@ -150,9 +189,77 @@ export function systemRoot(): string {
   // Where there is no system account and no unit, the daemon is the user, as before.
   if (!splitAvailable()) return userRoot();
   if (platformShape() === 'darwin') return DARWIN_SYSTEM_ROOT;
+  if (platformShape() === 'windows') return windowsStateRoot();
   return DEFAULT_SYSTEM_ROOT;
 }
 
+/**
+ * The Windows state root, WHICH IS CONDITIONAL, and the condition is not fussiness.
+ *
+ * On Linux and macOS the system root is returned unconditionally and a daemon that has not
+ * been installed gets EACCES creating it — a loud, correct "run the installer". That does
+ * not work here, because `C:\ProgramData` grants Users the right to create subdirectories.
+ * An uninstalled Windows daemon would therefore SUCCEED in creating
+ * `%ProgramData%\wundervault\state`, inherit ProgramData's ACL, and store every
+ * credential on the machine in a directory the other accounts on that machine can read.
+ * Pre-split state in the owner's own profile is not a boundary either, but it is at least
+ * private to the owner — so the uninstalled case would be a REGRESSION dressed as progress.
+ *
+ * The rule: use the installed location only when it exists AND its ACL is actually
+ * private. A rogue process that pre-creates the directory to redirect the daemon gets
+ * inherited ACEs, fails the check, and the daemon quietly stays in the owner's profile and
+ * says it has no boundary — which is the truth in both cases.
+ *
+ * Cached, because it costs an `icacls` subprocess and the answer cannot change under a
+ * running daemon without the install changing under it too.
+ */
+let cachedWindowsRoot: string | null = null;
+
+function windowsStateRoot(): string {
+  if (cachedWindowsRoot) return cachedWindowsRoot;
+  const installed = WINDOWS_SYSTEM_ROOT();
+  let use = userRoot();
+  try {
+    if (fs.statSync(installed).isDirectory()) {
+      // WE ARE THE SERVICE ACCOUNT: this directory is ours, whatever its ACL says today.
+      //
+      // The first version fell back whenever the ACL was not private, and that is wrong
+      // for an INSTALLED machine. Widening the state ACL -- a bad group policy, a careless
+      // icacls, an attacker -- made the daemon quietly relocate to the service account's
+      // own profile, leave a stale discovery file pointing at a port it no longer held,
+      // and strand every credential in the store it had walked away from. Observed: after
+      // granting Users:(RX), every agent got "connection refused" and the broker was
+      // simply gone.
+      //
+      // Linux does not do that, and neither should this. A widened directory is a
+      // boundary that is GONE, not a store that is someone else's: boundaryIsReal() says
+      // so loudly, the startup warning prints, and the credentials keep working. Refusing
+      // to serve protects nothing and strands everything -- the same argument
+      // deriveMachineKey() makes about a store it cannot verify.
+      //
+      // The fallback still does its one job, which is the UNINSTALLED case: C:\ProgramData
+      // lets any account create a subdirectory, so a rogue could pre-create this path to
+      // capture credentials from a daemon that has never been installed. A rogue cannot be
+      // the service account -- that account exists only because the installer made it.
+      let ours = false;
+      try { ours = os.userInfo().username.toLowerCase() === expectedAccount().toLowerCase(); }
+      catch { ours = false; }
+
+      if (ours) {
+        use = installed;
+      } else {
+        const report = readAclReport(installed);
+        if (report !== null && windowsAclIsRestricted(report)) use = installed;
+      }
+    }
+  } catch { /* not installed, or unreadable: stay in the owner's profile */ }
+  cachedWindowsRoot = use;
+  return use;
+}
+
+/** Exported so a test can make the decision again after changing the world. */
+export function _resetWindowsRootCacheForTests(): void { cachedWindowsRoot = null; }
+
 /**
  * The agent's own directory: its token, and its view of things.
  *
@@ -167,6 +274,51 @@ export function systemRoot(): string {
  * anything into a user's home (see `dropToSudoUser` in log-viewer.ts). A root process must
  * not follow paths that an unprivileged account can rearrange under it.
  */
+/**
+ * WHO WE ARE, for the purposes of keying something that is machine-global.
+ *
+ * Every derivation in this codebase that needs "this account, not another one on the same
+ * box" was written as `process.getuid?.() ?? 0`. On Windows `getuid` is undefined, so the
+ * fallback fires and EVERY ACCOUNT ON THE MACHINE IS PRINCIPAL 0. `lock.ts` says in a
+ * comment that the uid is in its port digest so that "two OS accounts on one box [do not]
+ * exclude each other over credentials they do not share" — and on Windows that is precisely
+ * what happened: two users, same agent name, same derived port, and one of them told its
+ * credential was already in use.
+ *
+ * On POSIX this returns the uid as a string, so the derived values are bit-for-bit what
+ * they were. On Windows it returns the account SID, which is the uid's actual counterpart:
+ * unique per account, stable across renames, and machine-local.
+ *
+ * The SID costs a subprocess, so it is read once and cached. If it cannot be read we fall
+ * back to the lowercased username — weaker (a renamed account changes principal) but still
+ * per-account, which is the property that was missing.
+ */
+let cachedPrincipal: string | null = null;
+
+export function principalId(): string {
+  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
+  if (uid !== undefined) return String(uid);
+  if (cachedPrincipal) return cachedPrincipal;
+
+  const override = process.env.WUNDERVAULT_PRINCIPAL_ID;
+  if (override && override.trim()) { cachedPrincipal = override.trim(); return cachedPrincipal; }
+
+  try {
+    const out = execFileSync('whoami', ['/user', '/fo', 'csv', '/nh'], {
+      encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'],
+    });
+    const m = out.match(/"(S-1-[0-9-]+)"/);
+    if (m) { cachedPrincipal = m[1]; return cachedPrincipal; }
+  } catch { /* fall through to the username */ }
+
+  try { cachedPrincipal = os.userInfo().username.toLowerCase(); }
+  catch { cachedPrincipal = 'unknown-principal'; }
+  return cachedPrincipal;
+}
+
+/** Exported so a test can force the Windows path to be re-read. */
+export function _resetPrincipalCacheForTests(): void { cachedPrincipal = null; }
+
 export function userRoot(): string {
   return process.env.WUNDERVAULT_USER_ROOT || path.join(os.homedir(), '.wundervault');
 }
@@ -190,7 +342,13 @@ export function runtimeDir(): string {
   const run = `/run/${SYSTEM_ACCOUNT}`;
   let linuxRunExists = false;
   try { linuxRunExists = fs.existsSync(run); } catch { /* treat as absent */ }
-  return runtimeDirFor(platformShape(), systemRoot(), linuxRunExists);
+  const root = systemRoot();
+  // Is the state root a directory belonging to somebody the agent is not? That is the
+  // whole condition for putting the sockets beside it rather than inside it.
+  let rootIsSeparate = true;
+  try { rootIsSeparate = path.resolve(root) !== path.resolve(userRoot()); }
+  catch { rootIsSeparate = true; }
+  return runtimeDirFor(platformShape(), root, linuxRunExists, rootIsSeparate);
 }
 
 /**
@@ -210,10 +368,22 @@ export function runtimeDirFor(
   shape: PlatformShape,
   root: string,
   linuxRunExists: boolean,
+  rootIsSeparate = true,
 ): string {
-  // A SIBLING of the state directory, never a child. The state directory is 0700, which
-  // denies search permission to the agents that have to reach these sockets.
-  if (shape === 'darwin') return path.join(path.dirname(root), 'run');
+  // A SIBLING of the state directory, never a child. The state directory is 0700 on macOS
+  // and ACL'd to the account on Windows; either way the agents that have to reach these
+  // endpoints are shut out of it.
+  //
+  // ONLY WHEN THE STATE ROOT IS SOMEBODY ELSE'S, and that qualifier was missing for one
+  // run on Windows. Pre-split, the state root IS the agent's own `~/.wundervault`, so the
+  // sibling of it is `C:\Users\<you>\run` — a directory this daemon helpfully created in
+  // the root of the user's home profile, next to Documents. Observed on Windows 10.
+  //
+  // There is nothing to be outside of when there is no boundary: pre-split the run
+  // directory belongs INSIDE the root, exactly where the pre-split layout always put it.
+  if ((shape === 'darwin' || shape === 'windows') && rootIsSeparate) {
+    return path.join(path.dirname(root), 'run');
+  }
   if (linuxRunExists) return `/run/${SYSTEM_ACCOUNT}`;
   return path.join(root, 'run');
 }
@@ -238,11 +408,20 @@ export function systemdCredential(name = CREDENTIAL_NAME): Buffer | null {
   const dir = process.env.CREDENTIALS_DIRECTORY;
   if (dir) candidates.push(path.join(dir, name));
   candidates.push(path.join(runtimeDir(), 'store.key'));
-  // macOS has no systemd and nothing that unseals on our behalf, so the installer writes a
-  // RANDOM key into the state directory at 0600, owned by the daemon account. It is not
-  // sealed and the startup report must not say it is — but it is not DERIVED either, which
-  // is the difference that matters: nobody can recompute it from public inputs.
-  if (platformShape() === 'darwin') candidates.push(storeKeyPath());
+  // macOS and Windows have no systemd and nothing that unseals on our behalf, so the
+  // installer writes a RANDOM key into the state directory -- 0600 on macOS, and on Windows
+  // an ACL naming only the account, SYSTEM and Administrators. It is not sealed and the
+  // startup report must not say it is — but it is not DERIVED either, which is the
+  // difference that matters: nobody can recompute it from public inputs.
+  //
+  // WINDOWS WAS MISSING FROM THIS LIST for one run, and the symptom was quiet: the
+  // installer wrote a perfectly good random key, the daemon never looked at it, and
+  // reported key_mode=derived — a key recomputable by anyone who can read the directory —
+  // while a 32-byte secret sat unread beside the store. Caught by the verifier asking the
+  // daemon what key it was actually using, rather than by anyone reading this line.
+  if (platformShape() === 'darwin' || platformShape() === 'windows') {
+    candidates.push(storeKeyPath());
+  }
 
   for (const p of candidates) {
     try {
@@ -286,9 +465,14 @@ export type SealKind = 'tpm' | 'host' | 'local-file' | null;
 export function sealKind(): SealKind {
   const declared = process.env.WUNDERVAULT_SEAL_KIND;
   if (declared === 'tpm' || declared === 'host' || declared === 'local-file') return declared;
-  // Undeclared on darwin but the file is there: the installer wrote it and did not get to
-  // set the variable, or the daemon was started by hand. Report what is actually in use.
-  if (platformShape() === 'darwin') {
+  // Undeclared but the file is there: the installer wrote it and did not get to set the
+  // variable, or the daemon was started by hand. Report what is actually in use.
+  //
+  // This is the ONLY route on Windows, where a scheduled task carries no environment of
+  // its own the way a systemd unit or a launchd plist does -- so the file on disk is the
+  // whole of the evidence and there is nothing to declare it.
+  const shape = platformShape();
+  if (shape === 'darwin' || shape === 'windows') {
     try { if (fs.statSync(storeKeyPath()).size >= 32) return 'local-file'; } catch { /* none */ }
   }
   return null;
@@ -421,7 +605,9 @@ export function ensureSystemRoot(root = systemRoot()): void {
     if (code === 'EACCES' || code === 'EPERM') {
       const installer = process.platform === 'darwin'
         ? 'sudo sh packaging/install-daemon-macos.sh'
-        : 'sudo sh packaging/install-daemon.sh';
+        : process.platform === 'win32'
+          ? 'powershell -ExecutionPolicy Bypass -File packaging\\install-daemon-windows.ps1  (as Administrator)'
+          : 'sudo sh packaging/install-daemon.sh';
       throw new Error(
         `Cannot use ${root}: permission denied.\n` +
         `  The secret broker needs its own account, and the privileged install step has\n` +
@@ -432,11 +618,12 @@ export function ensureSystemRoot(root = systemRoot()): void {
     }
     throw err;
   }
-  // The mode check is the BOUNDARY on Linux and merely hygiene elsewhere, where the
-  // directory belongs to the same user the agents run as. Refusing to start over it off
-  // Linux would block a daemon on a platform that never claimed the boundary — Windows in
-  // particular reports modes that do not mean what they say.
-  if (!splitAvailable()) return;
+  // The mode check is the BOUNDARY on Linux and macOS. It is NOT one on Windows, and this
+  // guard is now load-bearing rather than cautious: measured on Windows 10, chmod(0o700)
+  // followed by stat() returns 666, every time, for every directory. Leaving the check in
+  // would refuse to start on a correctly installed Windows box. The Windows boundary is an
+  // ACL and is checked in boundaryIsReal(), against icacls, which reports what is real.
+  if (!splitAvailable() || platformShape() === 'windows') return;
   const mode = fs.statSync(root).mode & 0o777;
   if (mode !== 0o700) {
     throw new Error(
@@ -496,13 +683,202 @@ export function runningAsDaemonAccount(root = systemRoot()): boolean {
  * agent is not". When the state root IS the agent's own directory, there is nobody else.
  */
 export function expectedAccount(): string {
+  const shape = platformShape();
   return process.env.WUNDERVAULT_SYSTEM_ACCOUNT
-    || (platformShape() === 'darwin' ? DARWIN_ACCOUNT : SYSTEM_ACCOUNT);
+    || (shape === 'darwin' ? DARWIN_ACCOUNT : shape === 'windows' ? WINDOWS_ACCOUNT : SYSTEM_ACCOUNT);
+}
+
+/**
+ * The allowed holders of the Windows state directory.
+ *
+ * The service account, because it is the daemon. SYSTEM and Administrators, because they
+ * are outside every boundary on this operating system exactly as root is on Linux, and
+ * pretending otherwise would be the false claim this file exists to prevent.
+ * TrustedInstaller because Windows puts it on things and removing it fights the OS.
+ *
+ * `Users`, `Authenticated Users` and `Everyone` are the ones this is looking for. Any of
+ * them means the agents can read the store, which is the whole boundary gone.
+ */
+/**
+ * Well-known SIDs, because NAMES ARE LOCALISED AND SIDS ARE NOT.
+ *
+ * The first version of this read `icacls` output and compared the text against
+ * "administrators" and "system". On a German or Japanese Windows those strings are
+ * `Administratoren` and `SYSTEM`/`システム`, so the check would have failed closed on a
+ * perfectly installed machine and reported no boundary — or, with a looser comparison,
+ * failed OPEN. A security check that depends on the display language is not a check.
+ */
+const SID_SYSTEM = 'S-1-5-18';
+const SID_ADMINISTRATORS = 'S-1-5-32-544';
+const SID_TRUSTED_INSTALLER =
+  'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
+/** The ones this is actually looking for: anything that means "other people". */
+const SID_USERS = 'S-1-5-32-545';
+const SID_EVERYONE = 'S-1-1-0';
+const SID_AUTHENTICATED_USERS = 'S-1-5-11';
+const SID_INTERACTIVE = 'S-1-5-4';
+const BROAD_SIDS = new Set([
+  SID_USERS, SID_EVERYONE, SID_AUTHENTICATED_USERS, SID_INTERACTIVE,
+]);
+
+export interface AclEntry {
+  allow: boolean;
+  inherited: boolean;
+  sid: string;
+}
+
+/**
+ * Parse the ACL report the daemon asks PowerShell for.
+ *
+ * One entry per line, `Allow;False;S-1-5-32-544`. Generated rather than scraped: the
+ * report is produced by translating each IdentityReference to a SecurityIdentifier, so
+ * what arrives here is already language-independent.
+ *
+ * PURE. The thing that can silently return the wrong answer is the parsing, and the
+ * parsing has to be testable on a machine that is not Windows — phase 7 learned that twice
+ * and this file is where both lessons live.
+ */
+export function parseAclReport(report: string): AclEntry[] {
+  const out: AclEntry[] = [];
+  for (const raw of report.split(/\r?\n/)) {
+    const line = raw.trim();
+    if (!line) continue;
+    const parts = line.split(';');
+    if (parts.length < 3) continue;
+    const sid = parts[2].trim().toUpperCase();
+    if (!/^S-1-[0-9-]+$/.test(sid)) continue;
+    out.push({
+      allow: /^allow$/i.test(parts[0].trim()),
+      inherited: /^true$/i.test(parts[1].trim()),
+      sid,
+    });
+  }
+  return out;
+}
+
+/**
+ * Is this directory closed to the other accounts on the machine?
+ *
+ * The weaker of the two questions, and the one `windowsStateRoot()` asks before it agrees
+ * to store credentials somewhere. It does not care WHO owns the directory — only that
+ * `Users`, `Everyone` and friends are not on it, and that nothing is inherited.
+ *
+ * Inheritance is fatal on its own: an inherited ACE means access is whatever the parent
+ * says today and whatever it says tomorrow. `C:\ProgramData` grants Users the right to
+ * create subdirectories, so a directory created there and left with inherited permissions
+ * is readable by every account on the box.
+ */
+export function windowsAclIsRestricted(report: string): boolean {
+  const entries = parseAclReport(report);
+  if (entries.length === 0) return false;   // unparsed is never a boundary
+  for (const e of entries) {
+    if (e.inherited) return false;
+    if (e.allow && BROAD_SIDS.has(e.sid)) return false;
+  }
+  return true;
+}
+
+/**
+ * Is this directory private to the broker's own account?
+ *
+ * The strong question, and the one the startup report is allowed to answer `true` to.
+ * Every ALLOW entry must name the service account, SYSTEM, Administrators or
+ * TrustedInstaller. Deny entries are ignored: a deny only ever narrows.
+ *
+ * SYSTEM and Administrators are inside the wall, and saying so is the point rather than an
+ * embarrassment — they are outside every boundary on this operating system exactly as root
+ * is on Linux, and `/limitations` says the same thing about both.
+ */
+export function windowsAclIsPrivate(report: string, accountSid: string): boolean {
+  const allowed = new Set([
+    SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER, accountSid.toUpperCase(),
+  ]);
+  const entries = parseAclReport(report);
+  if (entries.length === 0) return false;
+  let sawAllow = false;
+  for (const e of entries) {
+    if (e.inherited) return false;
+    if (!e.allow) continue;
+    sawAllow = true;
+    if (!allowed.has(e.sid)) return false;
+  }
+  return sawAllow;
+}
+
+/**
+ * Ask Windows for the ACL, in SIDs.
+ *
+ * A PowerShell subprocess, once, at startup — and `-NonInteractive` and a timeout because
+ * a daemon must not be able to hang on a shell.
+ */
+export function readAclReport(target: string): string | null {
+  try {
+    // THE PATH TRAVELS IN THE ENVIRONMENT, and that is not a style choice.
+    //
+    // The first version passed it as a trailing argv element and read it as `$args[0]`.
+    // `powershell -Command` takes the REST OF THE LINE as the command, so the extra
+    // argument was never bound: `$args[0]` was empty, Get-Acl threw, the catch returned
+    // null, and every Windows daemon silently concluded it had no boundary and fell back
+    // to the pre-split layout. It failed identically on a perfectly installed machine and
+    // on one that had never run the installer, which is why it took running it to find.
+    //
+    // An environment variable also removes the quoting question entirely: nothing about
+    // the path is parsed by PowerShell, so a directory name containing a quote or a
+    // backtick is data rather than an injection site.
+    return execFileSync('powershell', [
+      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
+      "$ErrorActionPreference='Stop';" +
+      "(Get-Acl -LiteralPath $env:WV_ACL_TARGET).Access | ForEach-Object { " +
+      "$s = try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } " +
+      "catch { $_.IdentityReference.Value }; " +
+      '"$($_.AccessControlType);$($_.IsInherited);$s" }',
+    ], {
+      encoding: 'utf8', timeout: 20000, stdio: ['ignore', 'pipe', 'ignore'],
+      env: { ...process.env, WV_ACL_TARGET: target },
+    });
+  } catch { return null; }
+}
+
+/**
+ * The Windows half of boundaryIsReal(), separated because nothing it checks is a uid.
+ *
+ * There is no euid and no mode here — measured: chmod is a no-op and stat().uid is 0 for
+ * every file on the volume. What IS real is the ACL (a non-administrator was denied read
+ * and list on an ACL'd directory, observed on Windows 10 with two accounts), so the ACL is
+ * what gets checked.
+ */
+function windowsBoundaryIsReal(root: string): boolean {
+  // Same check as everywhere else, and the same reason: an owner who starts the daemon by
+  // hand gets a directory they own, and it is not a boundary against the agents they also
+  // run.
+  try {
+    if (os.userInfo().username.toLowerCase() !== expectedAccount().toLowerCase()) return false;
+  } catch { return false; }
+
+  // The pre-split location passes an ACL test trivially — it is the owner's own directory.
+  try {
+    if (fs.realpathSync(root) === fs.realpathSync(userRoot())) return false;
+  } catch {
+    if (path.resolve(root) === path.resolve(userRoot())) return false;
+  }
+
+  try { if (!fs.statSync(root).isDirectory()) return false; } catch { return false; }
+
+  // Our own SID. principalId() returns it on Windows; if it fell back to a username there
+  // is no SID to compare and we cannot vouch for the ACL.
+  const sid = principalId();
+  if (!/^S-1-[0-9-]+$/i.test(sid)) return false;
+
+  const report = readAclReport(root);
+  if (report === null) return false;   // cannot see the ACL, cannot promise it
+  return windowsAclIsPrivate(report, sid);
 }
 
 export function boundaryIsReal(root = systemRoot()): boolean {
+  if (platformShape() === 'windows') return windowsBoundaryIsReal(root);
+
   const geteuid = (process as unknown as { geteuid?: () => number }).geteuid;
-  if (typeof geteuid !== 'function') return false; // Windows: no uids, no boundary.
+  if (typeof geteuid !== 'function') return false; // no uids, no boundary.
   const euid = geteuid.call(process);
   if (euid === 0) return false;
 

```

## File: src/endpoint.ts

```
/**
 * WHERE THE BROKER LISTENS, AND HOW AN AGENT REACHES IT.
 *
 * On Linux and macOS this is a unix domain socket at a path, and nothing in this file
 * changes that — `endpointFor()` returns the same path the rest of the code always used
 * and `listenOn()` calls `server.listen(path)`. The Windows work below must not reach the
 * other two platforms, because a phase that was supposed to leave them alone has broken
 * them twice already.
 *
 * WHY WINDOWS CANNOT USE EITHER OF THE OBVIOUS ANSWERS
 *
 * A unix socket is not available: `listen()` on a filesystem path returns EACCES, measured
 * on Windows 10 22H2 with Node 22. libuv wants a named pipe.
 *
 * A NAMED PIPE IS WORSE, and the measurement that settled it is the one worth keeping.
 * libuv calls `CreateNamedPipeW` with a NULL security descriptor and Node exposes no way
 * to supply one, so the pipe gets the creating account's default DACL. With the server
 * running as a non-admin service account:
 *
 *   client as a local ADMINISTRATOR      connect OK, round trip OK
 *   client as a non-admin local account  EPERM: connect
 *
 * The first line is the trap. Every developer box runs its agents as an administrator, so
 * a pipe transport passes every test anyone would write and then fails for every customer
 * whose agents run unprivileged. "It works on my machine" would have been literally true.
 *
 * SO: LOOPBACK TCP, WITH A DAEMON-OWNED DISCOVERY FILE.
 *
 * The daemon binds 127.0.0.1:0 and writes the port it actually got into a file in the run
 * directory, which everyone can read and only the daemon can write. An OS-assigned port,
 * not a derived one — deriving the port is exactly how the single-instance lock shipped
 * broken on macOS (eight candidates inside the ephemeral range, two live holders of one
 * credential), and a derived port carries a birthday bound that an assigned one does not.
 *
 * This is the same exposure as the 0666 unix sockets: any local process can connect, and
 * the token decides what it gets. `paths.ts` argues that position at length and it is
 * unchanged here.
 *
 * THE ONE THING A PORT IS WEAKER AT, AND WHY IT IS CLOSED RATHER THAN DOCUMENTED
 *
 * A unix socket lives at a path inside a directory only the daemon can write, so nobody
 * else can put something there for an agent to find. A PORT is different: once the daemon
 * dies, its port is free, and any local process can bind it and answer as the broker while
 * the discovery file still points at it.
 *
 * So before an agent sends its token it sends a nonce, and the broker signs
 *
 *     wv-broker-hello-v1:<nonce>:<port>:<server_id>
 *
 * with the P-256 identity key phase 6 already gave it. The agent verifies against
 * `broker.pub`, published beside the discovery files. A squatter has no private key, so
 * the agent refuses and reports the broker as unavailable rather than handing a credential
 * to a stranger. The nonce is what stops a captured banner being replayed — `broker.pub`
 * and the port file are both world-readable, so a banner with nothing fresh in it would be
 * a replay waiting to happen.
 *
 * WHAT THE HANDSHAKE DOES NOT BUY. A rogue process running as the owner can already read
 * every agent's token out of `%USERPROFILE%\.wundervault\agents\*.token`, because all
 * agents run as the owner. This stops a stale port being answered by a stranger. It does
 * not make one agent safe from another — nothing local does, and phases 6 and 7 say so.
 */
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  platformShape, runtimeDir, mgmtSocketPath, agentSocketPath, mgmtDir, safeName,
} from './paths.js';

export const HELLO_VERSION = 'wv-broker-hello-v1';

/** How the broker is addressed on this platform. */
export type Endpoint =
  | { kind: 'path'; address: string }
  | { kind: 'port'; file: string };

/** True where the broker is reached by a port rather than a path. */
export function usesPortFiles(): boolean {
  return platformShape() === 'windows';
}

export function mgmtEndpoint(): Endpoint {
  return usesPortFiles()
    ? { kind: 'port', file: path.join(mgmtDir(), 'mgmt.port') }
    : { kind: 'path', address: mgmtSocketPath() };
}

export function agentEndpoint(name: string): Endpoint {
  return usesPortFiles()
    ? { kind: 'port', file: path.join(runtimeDir(), `${safeName(name)}.port`) }
    : { kind: 'path', address: agentSocketPath(name) };
}

/** Where the broker's public key is published for agents to verify against. */
export function brokerPubPath(): string {
  return path.join(runtimeDir(), 'broker.pub');
}

/** What a person should see in a message: a path, or an address they can check. */
export function endpointLabel(ep: Endpoint): string {
  if (ep.kind === 'path') return ep.address;
  const rec = readPortFile(ep.file);
  return rec ? `127.0.0.1:${rec.port} (${ep.file})` : ep.file;
}

export interface PortRecord {
  port: number;
  pid: number;
  server_id: string;
}

export function readPortFile(file: string): PortRecord | null {
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<PortRecord>;
    if (!Number.isInteger(raw.port) || raw.port! < 1 || raw.port! > 65535) return null;
    if (typeof raw.server_id !== 'string' || raw.server_id.length < 16) return null;
    return { port: raw.port!, pid: Number(raw.pid) || 0, server_id: raw.server_id };
  } catch { return null; }
}

// ── the daemon's side ─────────────────────────────────────────────────────────

/**
 * Everything the daemon needs to prove it is the daemon. Built once per process.
 *
 * `server_id` is fresh per start, so a discovery file left behind by a previous daemon
 * cannot be mistaken for this one's.
 */
export interface HelloSigner {
  serverId: string;
  sign(message: string): string;
}

export function helloSignerFrom(privateKeyPem: string): HelloSigner {
  const serverId = crypto.randomBytes(16).toString('hex');
  return {
    serverId,
    sign(message: string): string {
      return crypto.createSign('SHA256').update(message).sign(privateKeyPem).toString('base64');
    },
  };
}

/**
 * Bind, and record where we bound.
 *
 * REFUSES rather than retries. A daemon that cannot bind, or cannot write the file that
 * tells agents where it is, is a daemon nobody can reach — and the failure mode this
 * replaces (walk to another port, carry on) is the one that put two live holders on one
 * credential on macOS.
 */
export function listenOn(
  server: net.Server,
  ep: Endpoint,
  signer: HelloSigner | null,
  onReady: (label: string) => void,
  onError: (message: string) => void,
): void {
  if (ep.kind === 'path') {
    server.listen(ep.address, () => {
      // World-connectable BY DESIGN — see paths.ts. The daemon is a different uid from
      // every agent, so a mode that excluded others would exclude the agent too. The
      // token is the identity; this mode is not a control and must not be read as one.
      try { fs.chmodSync(ep.address, 0o666); } catch { /* best effort */ }
      onReady(ep.address);
    });
    return;
  }

  if (!signer) {
    onError(
      `Refusing to listen for ${path.basename(ep.file)}: the broker has no identity key, ` +
      `so it cannot prove to an agent that it is the broker. Run the installer.`,
    );
    return;
  }

  server.listen(0, '127.0.0.1', () => {
    const addr = server.address();
    if (!addr || typeof addr === 'string') {
      onError(`Bound ${ep.file} but the address is not a TCP address. Refusing to serve.`);
      try { server.close(); } catch { /* already gone */ }
      return;
    }
    const rec: PortRecord = { port: addr.port, pid: process.pid, server_id: signer.serverId };
    try {
      // Written whole and renamed into place. A half-written discovery file read by an
      // agent mid-write is a connection to a port that is not ours.
      const tmp = `${ep.file}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(rec), { mode: 0o644 });
      fs.renameSync(tmp, ep.file);
    } catch (e) {
      onError(
        `Bound 127.0.0.1:${addr.port} but could not write ${ep.file}: ` +
        `${(e as Error).message}. No agent could find this broker, so it is not serving.`,
      );
      try { server.close(); } catch { /* already gone */ }
      return;
    }
    onReady(`127.0.0.1:${addr.port}`);
  });
}

/** Remove a discovery file on a clean stop, so a stale one never points at a free port. */
export function releaseEndpoint(ep: Endpoint): void {
  const target = ep.kind === 'path' ? ep.address : ep.file;
  try { fs.unlinkSync(target); } catch { /* never existed, or already gone */ }
}

/**
 * Wrap a connection handler so it answers the hello first, on Windows only.
 *
 * On every other platform this returns the handler UNCHANGED — not a wrapper that happens
 * to pass through, the same function object — so there is no new code between a Linux
 * agent and the daemon it has been talking to since phase 4.
 *
 * A client that does NOT send a hello is served exactly as before: the buffered bytes are
 * handed straight to the real handler. The handshake protects the CLIENT, so making it
 * mandatory would only break old agents without protecting anyone.
 */
export function withHello(
  onConnection: (socket: net.Socket) => void,
  signer: HelloSigner | null,
  port: () => number,
): (socket: net.Socket) => void {
  if (!usesPortFiles()) return onConnection;

  return (socket: net.Socket) => {
    let buf = '';
    let settled = false;

    const handOff = (rest: string) => {
      if (settled) return;
      settled = true;
      socket.removeListener('data', onData);
      onConnection(socket);
      if (rest) socket.emit('data', Buffer.from(rest, 'utf8'));
    };

    const onData = (d: Buffer) => {
      buf += d.toString('utf8');
      // A hello is tiny. Anything larger than this before a newline is not one, and is
      // the real handler's business — including its own size ceilings.
      if (buf.length > 4096) { handOff(buf); return; }
      const nl = buf.indexOf('\n');
      if (nl === -1) return;

      const line = buf.slice(0, nl);
      const rest = buf.slice(nl + 1);
      let msg: { hello?: unknown; nonce?: unknown } | null = null;
      try {
        const parsed = JSON.parse(line) as unknown;
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          msg = parsed as { hello?: unknown; nonce?: unknown };
        }
      } catch { /* not JSON: the real handler says what it thinks of that */ }

      if (!msg || msg.hello !== HELLO_VERSION || typeof msg.nonce !== 'string') {
        handOff(buf);
        return;
      }

      // A nonce we are about to sign over. Bounded, because it is attacker-chosen and is
      // about to become part of a signed message.
      const nonce = msg.nonce.slice(0, 128);
      if (!signer) {
        try { socket.write(JSON.stringify({ error: 'no broker identity' }) + '\n'); } catch { /* gone */ }
        try { socket.end(); } catch { /* gone */ }
        return;
      }
      const p = port();
      const sig = signer.sign(`${HELLO_VERSION}:${nonce}:${p}:${signer.serverId}`);
      try {
        socket.write(JSON.stringify({
          hello: HELLO_VERSION, server_id: signer.serverId, port: p, sig,
        }) + '\n');
      } catch { /* the client hung up mid-handshake */ }

      // The connection continues. The agent sends its real request next, and the existing
      // handler owns the socket from here.
      settled = true;
      socket.removeListener('data', onData);
      onConnection(socket);
      if (rest) socket.emit('data', Buffer.from(rest, 'utf8'));
    };

    socket.on('data', onData);
  };
}

// ── the agent's side ──────────────────────────────────────────────────────────

export class EndpointUnreachable extends Error {}
export class BrokerNotAuthentic extends Error {}

/**
 * Connect, and on Windows do not say a word until the far end has proved who it is.
 *
 * The order matters and is the whole point: nonce out, signature in, verify, and only then
 * does the caller get a socket it may write a token to.
 */
export function connectToEndpoint(ep: Endpoint, timeoutMs: number): Promise<net.Socket> {
  if (ep.kind === 'path') {
    return Promise.resolve(net.createConnection(ep.address));
  }

  return new Promise((resolve, reject) => {
    const rec = readPortFile(ep.file);
    if (!rec) {
      reject(new EndpointUnreachable(
        `No broker is listening: ${ep.file} is missing or unreadable.`));
      return;
    }
    const pub = loadBrokerPublicKey();
    if (!pub) {
      reject(new BrokerNotAuthentic(
        `Cannot verify the broker: ${brokerPubPath()} is missing or unreadable, and this ` +
        `platform reaches the broker by a port, which anything local can bind.`));
      return;
    }

    const nonce = crypto.randomBytes(16).toString('hex');
    const socket = net.createConnection({ host: '127.0.0.1', port: rec.port });
    let buf = '';
    let done = false;
    const fail = (err: Error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* already gone */ }
      reject(err);
    };
    const timer = setTimeout(
      () => fail(new EndpointUnreachable(
        `The broker at 127.0.0.1:${rec.port} did not answer the handshake.`)),
      Math.min(timeoutMs, 15_000),
    );

    socket.on('error', (e) => fail(new EndpointUnreachable(
      `Could not reach the broker at 127.0.0.1:${rec.port}: ${e.message}`)));
    socket.on('connect', () => {
      socket.write(JSON.stringify({ hello: HELLO_VERSION, nonce }) + '\n');
    });
    socket.on('data', (d) => {
      if (done) return;
      buf += d.toString('utf8');
      if (buf.length > 8192) { fail(new BrokerNotAuthentic('Handshake reply was too large.')); return; }
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      const rest = buf.slice(nl + 1);

      let reply: { server_id?: unknown; port?: unknown; sig?: unknown } | null = null;
      try {
        const parsed = JSON.parse(line) as unknown;
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          reply = parsed as { server_id?: unknown; port?: unknown; sig?: unknown };
        }
      } catch { /* handled below */ }

      if (!reply || typeof reply.sig !== 'string' || typeof reply.server_id !== 'string') {
        fail(new BrokerNotAuthentic(
          `Whatever is listening on 127.0.0.1:${rec.port} did not answer as the broker. ` +
          `Refusing to send a credential to it.`));
        return;
      }
      // The port and server_id are checked against the DISCOVERY FILE, not taken from the
      // reply: a signature over values the far end chose proves only that it can sign.
      if (reply.server_id !== rec.server_id || Number(reply.port) !== rec.port) {
        fail(new BrokerNotAuthentic(
          `The broker on 127.0.0.1:${rec.port} identified itself as a different instance ` +
          `than ${path.basename(ep.file)} names. Refusing to send a credential to it.`));
        return;
      }
      const message = `${HELLO_VERSION}:${nonce}:${rec.port}:${rec.server_id}`;
      let ok = false;
      try {
        ok = crypto.createVerify('SHA256').update(message)
          .verify(pub, Buffer.from(reply.sig, 'base64'));
      } catch { ok = false; }
      if (!ok) {
        fail(new BrokerNotAuthentic(
          `The process on 127.0.0.1:${rec.port} could not prove it is the broker. ` +
          `Refusing to send a credential to it.`));
        return;
      }

      done = true;
      clearTimeout(timer);
      socket.removeAllListeners('data');
      resolve(socket);
      // Anything that arrived with the banner belongs to the caller's handler.
      if (rest) socket.emit('data', Buffer.from(rest, 'utf8'));
    });
  });
}

function loadBrokerPublicKey(): crypto.KeyObject | null {
  try {
    const b64 = fs.readFileSync(brokerPubPath(), 'utf8').trim();
    return crypto.createPublicKey({
      key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki',
    });
  } catch { return null; }
}

/** Publish the half agents verify against. Written by the daemon, read by everyone. */
export function publishBrokerPublicKey(publicKeyB64: string): void {
  const p = brokerPubPath();
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, publicKeyB64 + '\n', { mode: 0o644 });
  fs.renameSync(tmp, p);
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
