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

`identity = sha256("wv-win:" + <labelled, colon-joined sources>)`, e.g.
`wv-win:smbios=<uuid>:machineguid=<guid>`, where a source is dropped if it is absent or
degenerate (all-zero, all-FF, or a known placeholder).

**The labels are load-bearing** — an earlier draft of this spec wrote the unlabelled form
`"wv-win:" + a + ":" + b`, which review round 24 correctly noticed the code does not
implement. The code is right and the spec was wrong: unlabelled, a machine with only an
SMBIOS UUID and a machine with only a MachineGuid of the same value hash the same input.
Naming which source produced which value makes the dropped-source cases distinguishable.
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
11a. **[win199]** **THE CASE THAT ACTUALLY MATTERS, added 2026-09-18 after the owner asked.**
    An **unelevated process of the verifying user's own account** — an administrator, which
    is what most people are on their own machine — is denied read and list on the state
    directory, and **can still reach the run directory**. Check 11 proves the boundary
    against somebody else; this proves it against *you*, which is who the agents actually
    run as. Measured on the box in all three cases: a non-admin account DENIED, an
    unelevated administrator DENIED, an **elevated** administrator ALLOWED — the last by
    design, the same as root on Linux, and it includes anything launched over SSH, because
    Windows OpenSSH hands administrators a full token.
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

28. Non-ASCII characters do not appear in daemon console output on Windows — **any**
    non-ASCII, not merely the typographic punctuation we happen to write. Agent names,
    paths and upstream error text flow through the same writes. Anything left after
    transliteration is escaped as `\uXXXX`. **[win199]** *(Widened after review round 24,
    which pointed out that an agent named `José` went straight to the console.)*
35. The startup warning does not say the daemon runs as the agents' user when it does not.
    A weakened ACL on an installed machine is a different failure from an uninstalled one
    and gets a different sentence. *(Added after review round 24.)*
36. `Set-ExplicitAcl` produces an **allowlist**: an explicit ACE granted by someone else
    before a reinstall does not survive it. *(Added after review round 24 — `/inheritance:r`
    removes only inherited entries, so it did survive.)*
37. The installer **fails** when the task registers but the broker is not running.
    *(Added after review round 24.)*
38. A SID is matched as a whole token, never as a substring, wherever a rights list is
    read. *(Added after review round 24 — `...-1001` matches inside `...-10010`.)*
39. The verifier creates its probe account and task under a **random** name, refuses to
    adopt an existing one, and removes the probe's SID from local security policy when it
    is done. *(Added after review round 24.)*
40. Every verifier network call has a deadline; no required check can hang instead of
    failing. *(Added after review round 24.)*
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
