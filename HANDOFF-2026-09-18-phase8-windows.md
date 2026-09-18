# Handoff — phase 8: the secret broker on Windows

Written 2026-09-18, after `HANDOFF-2026-09-18-phase7-macos.md`. Spec is
`SPEC-phase8-windows.md`. Joins the same unshipped cutover as everything from 16–18
September → `project_wundervault_v2_cutover_plan`.

**NOTHING IS DEPLOYED.** But unlike phase 7, **all of this has run on the target
platform** — win199, Windows 10 22H2 build 19045.6466, Node v22.23.2 — and the box changed
the design twice and found seven bugs no amount of reading would have.

---

## 1. What this closes, and the part nobody knew was open

Phase 8 was supposed to be "give the broker its own account on Windows". The first hour on
a real Windows box established something else:

**The product did not work on Windows at all, and had not since the first public release.**

- **`npm install -g @wundervault/mcp-server` exited 1.** `postinstall` was
  `chmod +x dist/agent.js dist/index.js 2>/dev/null || true` — POSIX shell, run by npm
  through cmd.exe, where `2>/dev/null` is a path that does not exist and `true` is not a
  command. Verified against the **published 1.7.2**, not just the working tree. npm then
  rolled the package back **but left the `wundervault-mcp` and `wundervault-agent` shims on
  PATH**, so the documented next command failed with `MODULE_NOT_FOUND` rather than "not
  installed" — pointing every Windows customer at the wrong problem.
- **Past that, the daemon refused to start.** `machineIdentity()` read `/etc/machine-id` or
  ran `ioreg`, and had no Windows branch, so it returned null — and phase 7's `keyModeFor`
  turns a null identity with no existing store into `refuse`. The comment above it said
  that branch was "unreachable on any machine that has /etc/machine-id or ioreg, which is
  all of them". Windows is not.
- **Past that, the sockets could never have worked.** `net.Server.listen()` on a filesystem
  path returns **EACCES** on Windows. `server.ts` has no fallback: every tool call goes
  through `brokerClient()`.

So this phase is two things: make Windows work, then give the broker its own account there.

---

## 2. The measurement that changed the design

**A named pipe is the obvious transport, and it is wrong.** libuv calls
`CreateNamedPipeW` with a NULL security descriptor and Node exposes no way to supply one.
Measured with three accounts — pipe server as a non-admin service account, then:

| client | result |
|---|---|
| a local **administrator** | `connect=OK`, round trip `PONG` |
| a **non-admin** local account | **`EPERM: connect`** |

The first row is the trap. Every developer box runs its agents as an administrator, so a
pipe transport passes every test anyone would write and then fails for every customer whose
agents run unprivileged — and "it works on my machine" would have been literally true.

**So: loopback TCP, with a daemon-owned discovery file.** The daemon binds `127.0.0.1:0`
and writes the port it actually got into `run\<agent>.port`, which everyone can read and
only the daemon can write. An OS-assigned port, not a derived one — deriving the port is
precisely how the single-instance lock shipped broken to macOS.

That is the same exposure as the 0666 unix sockets: any local process can connect, and the
token decides what it gets. **The one thing a port is weaker at** is that a dead daemon
releases it, so a stranger can answer where the discovery file still points. Closed rather
than documented away: the agent sends a nonce and the broker signs
`wv-broker-hello-v1:<nonce>:<port>:<server_id>` with the P-256 identity key from phase 6.
A squatter has no private key, so the agent refuses and reports the broker unavailable
instead of handing over a credential. **Windows-only** — the unix-socket path is untouched,
and a test asserts `withHello` returns *the same function object* on POSIX.

---

## 3. The shape

```
%ProgramData%\wundervault           traversable; holds nothing readable
%ProgramData%\wundervault\state     THE BOUNDARY - an ACL, not a mode
%ProgramData%\wundervault\run       everyone reads; only the account writes
%USERPROFILE%\.wundervault          each agent's own: its token, and nothing that matters
```

- **A local account `wundervault`**, created with a random password that is used twice and
  never written down, denied interactive/network/remote logon, granted `SeBatchLogonRight`.
- **A scheduled task**, not a service. A real Windows service must answer the SCM within 30
  seconds; `node.exe` does not, so `sc create` gives error 1053, and every route to a real
  service goes through a third-party wrapper binary — against `/verify#installer`, where
  the trust story is one readable file you can diff. The task brings one thing launchd could
  not: **a restart count with a give-up limit.**
- **The boundary is an NTFS ACL**, because `chmod` on Windows is a no-op: ask for 0700 and
  `stat` reports 666, every time. `boundaryIsReal()` reads the ACL in **SIDs**, never names
  — names are localised, and a security check that depends on the display language is not a
  check.

---

## 4. Things that will bite you

- **`/inheritance:r` does not clear an ACL.** It removes only the *inherited* entries;
  explicit ones survive, and `/grant` adds without removing. So an explicit `Users:(RX)`
  someone had granted survived a reinstall and the installer printed "the boundary" over a
  directory every local account could read. The sequence is `/reset`, then
  `/inheritance:r`, then the grants. **An allowlist built by adding to whatever was there
  is not an allowlist.**
- **The OWNER is inside the wall whether the DACL mentions it or not.** A Windows owner
  always holds `READ_CONTROL` and `WRITE_DAC`, so a state directory owned by the agents'
  account is one they can unlock at will. The installer sets the owner explicitly; the
  daemon checks it.
- **`AreAccessRulesProtected` is the inheritance flag; per-entry `IsInherited` is only its
  visible consequence.** A directory can have inheritance *on* and show no inherited
  entries, because its parent has none inheritable yet — and the day the parent gains one,
  it flows in.
- **PowerShell 5.1 reads a `.ps1` as ANSI unless it has a UTF-8 BOM.** Em-dashes in the
  installer's comments produced a stray double quote that closed a string early and
  desynchronised the parser into nine cascading syntax errors *in valid code*. Both scripts
  are pure ASCII and a unit test enforces it.
- **`$ErrorActionPreference = 'Stop'` turns a native program's stderr into a terminating
  error.** `schtasks /delete` on a task that does not exist — the thing that makes the
  scripts idempotent — killed the installer four fifths of the way through, after it had
  created the account and the directories. Native programs go through a `Native` helper
  that decides on the **exit code**.
- **`schtasks` does not grant `SeBatchLogonRight`.** It registers the task, reports success,
  and the task silently never runs. `secedit` grants it.
- **A SID must be matched as a whole token.** `...-1001` matches *inside* `...-10010`, and
  the consequence is the worst available: the code concludes the right is already granted,
  omits our SID, and the task silently never runs.
- **`New-LocalUser -Description` is capped at 48 characters and refuses rather than
  truncating.** `Register-ScheduledTask` puts `-Password` in the `-User` parameter set, not
  with `-Principal`.
- **`wundervault-agent <unknown-flag>` used to start a broker.** `--ping` is not a flag; it
  fell through to "run the daemon in the foreground", so the verifier started a *second*
  broker as the wrong user and hung. On Windows the second broker overwrites the first's
  discovery files and takes every agent with it. Unknown options now exit 2 — **that was a
  bug on every platform since phase 4.**
- **Nothing else stops two brokers on a port.** `listen(0)` always succeeds, where two
  daemons cannot share a socket path. The daemon now probes the recorded port and requires
  the far end to *prove* it is a broker before standing down — an earlier version treated
  any open port as a live broker, which meant a crash plus a recycled port would refuse to
  start for ever.
- **Whatever the task runs is inside the boundary.** If `node.exe` or `dist/agent.js` sits
  where a non-administrator can write — and **nvm-windows installs node under `%APPDATA%`,
  which is exactly that** — then that person chooses what the broker executes, and the
  separate account protects their code instead of yours. The installer warns; the verifier
  **fails**. It fired truthfully on win199 the first time, and the box was locked down
  rather than the check softened.

---

## 5. What phase 8 does NOT close

- **No sandboxing.** The systemd unit's `ProtectSystem=strict`, `ProtectProc=invisible`,
  syscall filter and empty capability set have no Task Scheduler equivalent, exactly as on
  macOS. The account split is very nearly the whole defence.
- **The store key is not sealed to hardware.** No TPM use. BitLocker covers the stolen
  disk, and the installer reports `manage-bde` status rather than claiming it.
- **An administrator and SYSTEM are inside the wall**, as root is on Linux.
- **One account is one principal**: any agent can read any other agent's token.
- **The derived-key path is fragile if a machine-identity source goes missing** (round 24's
  B1). It fails safe — the daemon refuses to serve or overwrite and says the store is
  unreadable — and the supported install uses `store.key`, not a derived key. Open.
- **A per-agent endpoint that cannot be published** drops that agent and keeps the rest
  serving. Deliberate, but the failure is one line on stderr. Wants a degraded-state field
  in `ping`. Open.
- **The daemon's log has no rotation** — the same gap as macOS, still wanting one fix for
  both.
- **A real Windows service, under a signed binary** — phase 9, with macOS's Keychain ACL.

---

## 6. Deploy order

Unchanged from phase 7 for steps 1–4, plus:

5. **Windows, NEW:** `npm install -g @wundervault/mcp-server`, then in an **Administrator**
   prompt `powershell -ExecutionPolicy Bypass -File packaging\install-daemon-windows.ps1`,
   then **`packaging\verify-windows.ps1`** — and it must exit 0 with **0 not applicable**.
   Then `wundervault-agent --pair` once.
6. Migrate ONE agent, then stop and check the edge. Unchanged, and still the step most
   likely to bite.

---

## 7. Review log

Two rounds, both triaged in `.buildreview/`. Round 23 took the transport and the path
layer; round 24 took the daemon and the packaging.

| Round | Verdict | Outcome |
|---|---|---|
| 23 (transport + paths) | revise | 3 blockers, 1 major, 1 minor, 3 blind spots — 6 fixed, 1 partially accepted with the spec amended, 2 blind spots promoted to real bugs |
| 24 (daemon + packaging) | revise | 1 blocker, 7 majors, 3 minors, 6 blind spots — 11 fixed, 1 rejected with evidence, 1 fixed in the spec, 1 blind spot promoted to a verifier check, 3 deferred and named |

**What I rejected, and why:**

- *Round 23 F1 — "`splitAvailableFor('linux','windows')` returns true, contradicting
  acceptance check 26".* The contradiction is real and **the spec was the wrong half**.
  Making it false puts the Windows paths out of reach of CI on Linux, which is exactly how
  the port lock shipped broken to macOS and stayed broken for a release. Verified the
  safety property holds anyway: under the windows shape on Linux, `boundaryIsReal()` wants
  `icacls`, which Linux does not have, so it is false. Check 26 rewritten to assert that
  directly instead of by proxy.
- *Round 24 F8 — "a per-agent publication failure leaves a partially serving daemon".*
  Deliberate. Killing the broker because one agent's discovery file could not be written
  takes every other agent down with it. The reviewer had not been shown `listenOn` and
  flagged it as conditional, correctly. What is real and smaller is that the failure is one
  line on stderr — recorded as open, not fixed here.
- *Round 24 F9 — "`machineIdentityFromSources` does not implement the spec's derivation
  string".* Mismatch real, **spec wrong**. The code labels each source; unlabelled, a
  machine with only an SMBIOS UUID and one with only a MachineGuid of the same value hash
  the same input.

**The two most valuable findings were blind spots, not findings.** Round 23's B1 — the ACL
model checked the allow entries but not the directory's **owner** — was a hole straight
through the boundary. Round 24's B4 — nothing checked whether an ordinary user could
rewrite the thing being run *as* the broker's account — was the same shape one level out,
and it turned out to be **true of the test machine**.

---

## 8. Proof, on the actual platform

`packaging\verify-windows.ps1` on win199: **31 passed, 0 failed, 0 not applicable, exit 0.**
Including, from a throwaway non-administrator account the script creates and destroys:

- cannot list `%ProgramData%\wundervault\state`; cannot read `store.key`;
- **can** list the run directory, **cannot** write it;
- **can** reach the broker and gets an answer it can check.

**And, separately, against the verifying user's OWN account — which is the case that
matters and which the first version of this verifier did not cover.** Most people are
administrators of their own Windows machine, so their agents run as an account that IS in
the state directory's ACL; whether it can open the directory comes down to elevation.
Measured in all three cases:

| the agent's process | `store.key` | run directory |
|---|---|---|
| a non-administrator account | **denied** | readable |
| the owner's account, **unelevated** | **denied** | readable |
| the owner's account, **elevated** | **allowed** | readable |

The third row is by design and is the same as root on Linux. **It also includes anything
launched over SSH**, because Windows OpenSSH hands an administrator a full token rather
than the filtered one an interactive logon gets — so every command in this phase's own
testing ran *inside* the boundary. The verifier now measures the middle row with
`runas /trustlevel:0x20000` and fails if it cannot, rather than skipping.

And separately, by hand on the box:

- `npm install -g` exits **0** (it exited 1 on every Windows machine for the life of the
  product);
- granting `Users:(RX)` on the state directory flips the reported boundary to **false** at
  the next start **while the broker keeps serving**, and removing it flips it back —
  the Linux behaviour, after a first attempt that made the broker relocate and strand its
  own credentials;
- planting an explicit `Users:(RX)` and reinstalling **removes** it;
- a second broker refuses to start; an unknown flag exits 2 instead of starting one;
- 555 unit tests pass on Linux, and **seven guards were sabotage-tested** — each one broken
  deliberately, each one caught by the suite.

**Until `verify-windows.ps1` exits 0 on a customer's machine, Windows is not supported
there**, and no customer-facing copy should say otherwise.
