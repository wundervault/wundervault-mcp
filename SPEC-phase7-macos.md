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
shape and keeps warning. Its BEHAVIOUR is untouched — shape `none`, `splitAvailable()`
false, state in the user's own directory, a warning at every start.

> The warning's WORDING does change, and has to. It ended "The boundary is Linux-only for
> now", which this phase makes false. An earlier draft of this line said "byte for byte"
> and a reviewer correctly held me to it; keeping the bytes would have meant shipping a
> sentence the release contradicts.

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

**A3.** A new `boundaryIsReal()` reports on **observed facts**, not on the platform: we are
running as the expected service account BY NAME, the state root exists, is mode 0700, is
owned by our euid, our euid is neither 0 nor `SUDO_UID`, and the root is not the pre-split
location. `announceBoundary()` keys off this instead of off the platform.

> The account-name check is the one that does the work, and an earlier draft left it out.
> Without it an owner who starts the daemon by hand with `WUNDERVAULT_SYSTEM_ROOT` pointed
> at a scratch directory gets a 0700 directory owned by their own uid, outside their
> `~/.wundervault` — passing every other test, while the daemon runs as exactly the
> account its agents run as. `SUDO_UID` does not cover it; nobody used sudo.

> This closes a gap that predates macOS. On Linux today, a daemon started by hand with
> `WUNDERVAULT_SYSTEM_ROOT` pointed into the owner's home prints nothing at all, because
> the platform is Linux and the platform is all the check consults.

### Acceptance

1. With `WUNDERVAULT_PLATFORM_SHAPE=darwin` on Linux, `systemRoot()`, `runtimeDir()`,
   `mgmtSocketPath()` and `agentSocketPath()` return the macOS layout of §2.
2. With `WUNDERVAULT_PLATFORM_SHAPE=linux` and a stubbed real platform of `win32`,
   `splitAvailable()` is **false**. The override cannot manufacture a boundary.
3. `boundaryIsReal()` is true for a 0700 state root owned by the calling euid that is NOT
   the pre-split location, and false in each of: mode wider than 0700, root missing, root
   owned by another uid, euid 0, euid equal to `SUDO_UID`, and **root equal to the
   pre-split location**. That last case is the one that matters: pre-split, state lives in
   the owner's own `~/.wundervault`, which `ensureSystemRoot()` chmods to 0700 — so it
   passes every other test while the daemon and the agent are the same account.
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
10. On darwin the derivation uses `IOPlatformUUID`, and two different UUIDs yield two
    different keys — never the value the old code would have produced.

    With no machine identity available at all, the daemon reports a distinct
    `derived-shared` mode and **refuses enrolment**, but still starts and serves.

    > Amended from "refuses" during the build. Refusing to start would make an existing
    > install on a box with no machine identity — a container without `/etc/machine-id`
    > and no `systemd-creds` — permanently unrecoverable, which is the exact failure the
    > unit file already refuses elsewhere ("a cleared TPM must not mean a broker that
    > cannot start"). The point of the refusal is to stop a NEW secret being committed to
    > a key that is not one; that is `registerProfile`, not startup.
11. `parseIOPlatformUUID` is a pure function over real `ioreg` output, and returns null —
    never a constant — when the format does not match. Sabotage: making it return a fixed
    string fails check 10.

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


---

## 8. Amendments made during the build

Recorded here rather than silently, because a spec that quietly tracks the implementation
stops being able to judge it.

- **Acceptance 3** was written from the wrong side ("false for a root owned by the calling
  uid") — the daemon SHOULD own its own state root. Rewritten, and the account-name check
  added after round 21 found that ownership alone certifies an owner-run daemon.
- **Acceptance 10** softened from "refuses" to a split decision, then re-tightened after
  round 21: refuse to START when there is no store to lose, serve-and-warn when there is.
- **B2 changed shape entirely.** The runtime directory was specified as
  `/var/lib/wundervault/run`, inside the state root. That is fatal: the state root is 0700,
  which denies search permission to everyone but the daemon account, so an agent — which
  runs as the OWNER — could not traverse to its own socket and every connection would fail
  with EACCES on a perfect install. The layout is now three directories: a traversable
  0755 base holding nothing readable, `state/` at 0700, and `run/` at 0755 beside it.
  Found by reading the permissions through, not by any test, and it would otherwise have
  surfaced only on the Mac.
- **Windows warning**: "byte for byte" → behaviour unchanged. §0.
- **D1 gained a collision rule.** One derived port over a 12,768-wide range means the
  birthday bound bites at around a hundred agent names on one machine. A wundervault
  holder answering for a DIFFERENT agent is now reported as a collision naming
  `WUNDERVAULT_LOCK_PORT`, never as "your credential is in use" — which would be false,
  and would send someone hunting a duplicate agent that does not exist.
