# Review package — round 22
generated 2026-09-18T15:36:18+00:00

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


## What was built this round, and how it was tested

PHASE 7 ROUND 2. Round 21 reviewed the CODE and explicitly did not see the packaging; this round is the packaging, plus src/paths.ts whole so you can judge the installer against the contract the code expects. You are NOT shown src/agent.ts, src/lock.ts, src/migrate.ts or the test files — flag anything that depends on them and I will check it.

WHAT ROUND 21 FOUND AND WHAT I DID (its findings are NOT open; do not re-raise unless my fix is wrong)
F1 BLOCKER, fixed: no sealed key + no machine identity used the globally shared legacy key. Now a pure keyModeFor(sealed, kind, hasIdentity, storeExists): with NO store on disk it returns 'refuse' and the daemon throws (nothing is lost by stopping, and starting would write a NEW store under a key that is not a secret); with a store present it returns 'derived-shared', serves, warns at every start and refuses enrolment (refusing to open a store already encrypted under that key protects nothing and strands everything).
F2 BLOCKER, fixed: boundaryIsReal() certified an owner-run daemon. It now also requires os.userInfo().username === expectedAccount() (wundervault / _wundervault, WUNDERVAULT_SYSTEM_ACCOUNT overrides). See paths.ts, which you have.
F3 REJECTED: 'the legacy fallback cannot open a pre-phase-7 macOS store'. The arithmetic is right, the conclusion does not follow — nothing asks the daemon to open that store. Migration carries no credentials: --migrate runs as the OWNER and reads only agent NAMES; credentials are replaced by REPAIR in the dashboard. I corrected a comment of mine that implied otherwise.
F4 MAJOR, fixed: the migration guard checked platform capability, not an actual split, so a same-directory source and destination could reach destructive cleanup. It now refuses when systemRoot() and the legacy root resolve to the same place or one contains the other.
F5 MAJOR, fixed: isInside() mis-resolved a /var alias when the child does not exist yet — which is EVERY socket path. It now resolves the deepest existing ancestor and re-appends the remainder. In paths.ts, which you have.
F6 MAJOR, fixed: machineIdentity() consulted /etc/machine-id before ioreg. Darwin now prefers the hardware UUID, because a file travels with a disk image and a hardware UUID does not.
F7 REJECTED: the Windows warning text changed. It had to — the removed sentence was 'The boundary is Linux-only for now', which this phase makes false. Spec amended from 'byte for byte' to 'behaviour unchanged'.
Blind spot B2 turned out to be a real bug and is fixed: 12,768 possible lock ports means the birthday bound bites around a hundred agent names, and a wundervault holder answering for a DIFFERENT agent was being reported as 'your credential is in use'. That is false — a different credential is in use. It is now a collision message naming WUNDERVAULT_LOCK_PORT.

THE BIGGEST CHANGE THIS ROUND, WHICH I FOUND MYSELF AND WHICH RESHAPED THE LAYOUT
I originally specified the runtime directory as /var/lib/wundervault/run, INSIDE the 0700 state root. That is fatal and no test would have caught it: 0700 denies search permission to everyone but the daemon account, and the agents run as the OWNER — so every agent would get EACCES connecting to its own socket on a perfect install. The layout is now THREE directories: /var/lib/wundervault at 0755 holding nothing readable, state/ at 0700 (the boundary), run/ at 0755 beside it (sockets, which agents must reach). The plist's Umask 0077 then re-broke it a second way — the daemon mkdirs the mgmt socket dir at 0755 and umask masks it straight back to 0700 — so the daemon now chmods and VERIFIES the runtime directory is traversable, and throws naming EACCES if it is not.

HOW I TESTED IT
511 tests passing, up from 461 at the start of the phase. Everything in paths.ts is exercised from Linux through WUNDERVAULT_PLATFORM_SHAPE=darwin. Every fix checked by sabotage: reverting the account-name check, the realpath fix, the migration guard, the chmod, the port range, the single address, and the darwin runtime branch each fail at least one test. Two of my own tests initially passed under sabotage and I had to strengthen them (a pure runtimeDirFor so the DECISION is observable, not just its result, because the darwin and Linux branches return the same string on a box with no /run/wundervault). One test I could NOT make bite — that the post-bind close is awaited — and I labelled it as reasoned-not-demonstrated rather than let it look like coverage.
The packaging is UNRUN. No Mac available. sh -n and bash -n parse both scripts, plutil validates the plist, and I verified the awk ProgramArguments substitution on Linux against the real template. shellcheck is not installed here.

WHAT I WANT YOU TO ATTACK
1. The three-directory layout. Is 0755 on the base and run dir actually safe given what each holds, and is there any path by which an agent reaches something it should not? Is there a macOS-specific reason /var/lib is a bad choice?
2. The dscl account creation. Free uid scan 200-399, IsHidden, Password '*', UserShell /usr/bin/false. What is wrong or missing? Is the existing-account refusal sufficient?
3. launchctl bootout/bootstrap idempotency, and whether KeepAlive true is right for a daemon that can legitimately refuse to start (see F1 — it now throws on a machine with no identity and no store; will launchd spin on that?).
4. verify-macos.sh: does any check pass vacuously, or report PASS for having checked nothing? That failure mode has already bitten me twice this session.
5. Anything in the installer that would leave the machine half-changed if it failed partway.

## File: packaging/install-daemon-macos.sh

```
#!/bin/sh
# The one privileged step, on macOS. Install the secret broker. Run it once per machine.
#
# The broker is the process that holds your agents' credentials. It gets its own account
# so that the agents — which run as you — cannot read what it holds.
#
# It creates a hidden service account, a directory it owns, and a LaunchDaemon. It does not
# download anything, does not touch the network, and does not install the daemon itself —
# npm already did that, unprivileged, and you verified it then. Keeping the privileged part
# small enough to read in one sitting is the point: this is the script that asks for root,
# so it should be the script you can audit in a minute.
#
#   sudo sh install-daemon-macos.sh [--exec /path/to/wundervault-agent] [--uninstall]
#
# Re-runnable. Running it twice leaves the same machine as running it once.

set -eu

ACCOUNT=_wundervault
# THREE directories, and the split between them is not tidiness.
#
# On Linux systemd puts the sockets in /run/wundervault, at 0755, OUTSIDE the 0700 state
# directory. macOS has no /run and no RuntimeDirectory=, and putting the sockets inside the
# state directory is fatally wrong: 0700 denies search permission to everyone but this
# account, so an agent — which runs as the OWNER — cannot traverse in to reach its own
# socket, and every connection fails with EACCES on a perfect install.
#
#   BASE_DIR   0755  traversable, holds nothing readable
#   STATE_DIR  0700  the boundary: credentials, keys, the store
#   RUN_DIR    0755  sockets, which agents must be able to reach
BASE_DIR=/var/lib/wundervault
STATE_DIR="${BASE_DIR}/state"
RUN_DIR="${BASE_DIR}/run"
LABEL=com.wundervault.agent
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXEC=""
MODE=install

while [ $# -gt 0 ]; do
  case "$1" in
    --exec) EXEC="${2:?--exec needs a path}"; shift 2 ;;
    --uninstall) MODE=uninstall; shift ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "This step needs root. Re-run with sudo." >&2; exit 1; }
case "$(uname -s)" in
  Darwin) ;;
  Linux)
    echo "This is the macOS installer. On Linux use install-daemon.sh." >&2
    exit 1 ;;
  *)
    echo "The uid split is not available on $(uname -s). The daemon there runs as you," >&2
    echo "with the pre-split threat model. Nothing to install." >&2
    exit 1 ;;
esac

if [ "$MODE" = uninstall ]; then
  echo "Stopping and removing the secret broker (${LABEL})…"
  launchctl bootout "system/${LABEL}" 2>/dev/null || true
  rm -f "$PLIST_PATH"
  # The account and its state are LEFT BEHIND on purpose. They hold the credentials this
  # machine's agents use; deleting them here would turn "stop the service" into
  # "irreversibly destroy the vault contents" for anyone who typed --uninstall to debug a
  # startup problem. Removing them is a separate, deliberate act:
  echo "Removed the job. Credentials are left at ${STATE_DIR}."
  echo "To destroy them:"
  echo "  sudo rm -rf ${BASE_DIR}"
  echo "  sudo dscl . -delete /Users/${ACCOUNT} && sudo dscl . -delete /Groups/${ACCOUNT}"
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

# Resolve symlinks BEFORE the home-directory check. `npm install -g` into a user prefix
# leaves ~/.local/bin/wundervault-agent pointing at ~/.local/lib/node_modules/..., so a
# path that looks fine can still land the real file under /Users.
if command -v readlink >/dev/null 2>&1 && readlink -f / >/dev/null 2>&1; then
  REAL_EXEC=$(readlink -f "$EXEC")
else
  # macOS readlink has no -f before Ventura. Follow it by hand.
  REAL_EXEC="$EXEC"
  while [ -L "$REAL_EXEC" ]; do
    LINK=$(readlink "$REAL_EXEC")
    case "$LINK" in
      /*) REAL_EXEC="$LINK" ;;
      *)  REAL_EXEC="$(dirname -- "$REAL_EXEC")/$LINK" ;;
    esac
  done
  REAL_EXEC=$(CDPATH= cd -- "$(dirname -- "$REAL_EXEC")" && pwd)/$(basename -- "$REAL_EXEC")
fi

# On Linux the reason to refuse a home directory is ProtectHome=yes, which makes the path
# invisible to the service. launchd has no ProtectHome, so the job WOULD start — and that
# is worse, not better. A directory under /Users is writable by the account the agents run
# as, so the daemon would be executing code its own agents can replace: not just the
# credentials handed over, but the process that guards them.
for CANDIDATE in "$EXEC" "$REAL_EXEC"; do
  case "$CANDIDATE" in
    /Users/*|/private/var/root/*|/var/root/*)
      echo "ERROR: $CANDIDATE is inside a home directory." >&2
      if [ "$CANDIDATE" = "$REAL_EXEC" ] && [ "$EXEC" != "$REAL_EXEC" ]; then
        echo "       (reached via the symlink $EXEC)" >&2
      fi
      cat >&2 <<EOM

A home directory is writable by the account your agents run as. Installing from there
would have the broker execute code those agents can replace — which hands over not only
the credentials but the process that guards them. That is a worse hole than the one this
step exists to close.

Install the package somewhere the agent cannot write:

  sudo npm install -g --prefix /usr/local @wundervault/mcp-server
  sudo sh $0 --exec /usr/local/bin/wundervault-agent
EOM
      exit 1 ;;
  esac
done

PLIST_SRC="${HERE}/${LABEL}.plist"
[ -f "$PLIST_SRC" ] || { echo "Missing plist template: $PLIST_SRC" >&2; exit 1; }

echo "This will:"
echo "  1. create the hidden service account '${ACCOUNT}' for the secret broker"
echo "  2. create ${STATE_DIR} (0700) and ${RUN_DIR} (0755), owned by ${ACCOUNT}"
echo "  3. install ${PLIST_PATH}, which runs the broker: ${EXEC}"
echo "  4. start the broker"
echo

# ── 1. the account ───────────────────────────────────────────────────────────
if dscl . -read "/Users/${ACCOUNT}" >/dev/null 2>&1; then
  # An existing account is NOT automatically the right account.
  #
  # If a human logs in as this name — their own uid, the uid their agents run as — then
  # skipping creation here chowns the credential store to that uid and starts the daemon as
  # them. The agent can then read the store and attach to the daemon, while the install
  # prints that the directory is readable only by the broker. The boundary is gone and
  # every message says it is there, which is worse than not installing at all.
  EXISTING_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
  EXISTING_SHELL=$(dscl . -read "/Users/${ACCOUNT}" UserShell 2>/dev/null | awk '{print $2}')
  ACCOUNT_GID=$(dscl . -read "/Users/${ACCOUNT}" PrimaryGroupID 2>/dev/null | awk '{print $2}')

  if [ -n "${SUDO_UID:-}" ] && [ "$EXISTING_UID" = "$SUDO_UID" ]; then
    echo "ERROR: '${ACCOUNT}' is the account you are running as (uid ${EXISTING_UID})." >&2
    echo "       The broker must not run as the account its agents run as — that is the" >&2
    echo "       entire boundary." >&2
    exit 1
  fi

  case "$EXISTING_SHELL" in
    /usr/bin/false|/usr/bin/nologin|/sbin/nologin|/dev/null) ;;
    *)
      cat >&2 <<EOM
ERROR: an account named '${ACCOUNT}' already exists with uid ${EXISTING_UID} and login
shell ${EXISTING_SHELL:-<none>}.

The broker's account must not be able to log in. This one can, so a person can become it
and read every credential the broker holds — while the install reports that the directory
is readable only by ${ACCOUNT}. That is worse than not installing at all.

If this account is meant to be the daemon's:
  sudo dscl . -create /Users/${ACCOUNT} UserShell /usr/bin/false
If it belongs to a person or another service, the daemon needs a different name.
EOM
      exit 1 ;;
  esac
  echo "account ${ACCOUNT}: already exists (uid ${EXISTING_UID})"
else
  # A free id below 500, which is where macOS keeps service accounts. Both lists are
  # checked so the user and the group can share a number.
  ACCOUNT_UID=""
  TAKEN_UIDS=$(dscl . -list /Users UniqueID | awk '{print $2}')
  TAKEN_GIDS=$(dscl . -list /Groups PrimaryGroupID | awk '{print $2}')
  N=200
  while [ "$N" -lt 400 ]; do
    if ! printf '%s\n' "$TAKEN_UIDS" | grep -qx "$N" \
       && ! printf '%s\n' "$TAKEN_GIDS" | grep -qx "$N"; then
      ACCOUNT_UID="$N"; break
    fi
    N=$((N + 1))
  done
  [ -n "$ACCOUNT_UID" ] || {
    echo "ERROR: no free uid/gid between 200 and 399 for the service account." >&2
    exit 1
  }
  ACCOUNT_GID="$ACCOUNT_UID"

  dscl . -create "/Groups/${ACCOUNT}"
  dscl . -create "/Groups/${ACCOUNT}" PrimaryGroupID "$ACCOUNT_GID"
  dscl . -create "/Groups/${ACCOUNT}" RealName "Wundervault secret broker"
  dscl . -create "/Groups/${ACCOUNT}" Password '*'

  dscl . -create "/Users/${ACCOUNT}"
  dscl . -create "/Users/${ACCOUNT}" UniqueID "$ACCOUNT_UID"
  dscl . -create "/Users/${ACCOUNT}" PrimaryGroupID "$ACCOUNT_GID"
  dscl . -create "/Users/${ACCOUNT}" RealName "Wundervault secret broker"
  # No shell and no home. If a credential leak elsewhere ever reaches this name, it must
  # not also be a way to get a session.
  dscl . -create "/Users/${ACCOUNT}" UserShell /usr/bin/false
  dscl . -create "/Users/${ACCOUNT}" NFSHomeDirectory /var/empty
  dscl . -create "/Users/${ACCOUNT}" Password '*'
  # Keeps it off the login window and out of Users & Groups.
  dscl . -create "/Users/${ACCOUNT}" IsHidden 1
  echo "account ${ACCOUNT}: created (uid ${ACCOUNT_UID})"
fi

# ── 2. the directories ───────────────────────────────────────────────────────
mkdir -p "$STATE_DIR" "$RUN_DIR"
chown "${ACCOUNT}:${ACCOUNT}" "$BASE_DIR" "$STATE_DIR" "$RUN_DIR"
# Unconditional, because mkdir's mode is masked by umask and ignored outright when the
# directory already exists. A state directory left at 0755 by an earlier run would leave
# the boundary open while every other check here passed.
chmod 0755 "$BASE_DIR"
chmod 0700 "$STATE_DIR"
chmod 0755 "$RUN_DIR"
ACTUAL=$(stat -f '%Lp' "$STATE_DIR")
[ "$ACTUAL" = "700" ] || { echo "ERROR: ${STATE_DIR} is mode ${ACTUAL}, expected 700." >&2; exit 1; }
# And the other direction, which is just as fatal and fails far more quietly: a run
# directory the agents cannot traverse means every socket connection returns EACCES.
RUN_MODE=$(stat -f '%Lp' "$RUN_DIR")
case "$RUN_MODE" in
  755|775|777) ;;
  *) echo "ERROR: ${RUN_DIR} is mode ${RUN_MODE}; agents could not reach their sockets." >&2; exit 1 ;;
esac
BASE_MODE=$(stat -f '%Lp' "$BASE_DIR")
case "$BASE_MODE" in
  755|775|777) ;;
  *) echo "ERROR: ${BASE_DIR} is mode ${BASE_MODE}; agents could not traverse to ${RUN_DIR}." >&2; exit 1 ;;
esac
echo "state dir ${STATE_DIR}: 0700 ${ACCOUNT}"
echo "run dir   ${RUN_DIR}: 0755 ${ACCOUNT} — agents reach their sockets through here"

# ── 2b. the broker's own identity ────────────────────────────────────────────
#
# A P-256 keypair, generated HERE and never leaving this machine. Its public half is what
# an owner pairs with their account; after that, a repair seals the agent's credential to
# it and the thing the owner carries to this terminal is a claim code, which opens nothing.
#
# Generated with openssl rather than by the broker at first start, so that the key exists
# before anything can ask for it and so the mode is set by root while root is still here.
BROKER_KEY="${STATE_DIR}/broker-key.pem"
if [ -f "$BROKER_KEY" ]; then
  echo "broker key: already present at ${BROKER_KEY}"
else
  # umask before the write, not chmod after: openssl creates the file itself, and a chmod
  # that lands a moment later is a moment in which the key was world-readable.
  ( umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out "$BROKER_KEY" 2>/dev/null )
  if [ -s "$BROKER_KEY" ]; then
    chown "${ACCOUNT}:${ACCOUNT}" "$BROKER_KEY"
    chmod 0600 "$BROKER_KEY"
    BK_MODE=$(stat -f '%Lp' "$BROKER_KEY")
    [ "$BK_MODE" = "600" ] || { echo "ERROR: ${BROKER_KEY} is mode ${BK_MODE}, expected 600." >&2; exit 1; }
    echo "broker key: created, 0600 ${ACCOUNT}"
  else
    rm -f "$BROKER_KEY"
    echo "WARNING: could not generate the broker key with openssl." >&2
    echo "         The broker will create one at first --pair instead." >&2
  fi
fi

# ── 2c. the store key ────────────────────────────────────────────────────────
#
# What this replaces: a key DERIVED from a machine id and the account's uid. On macOS there
# is no /etc/machine-id, the read failed, and the code carried on with the literal string
# "unknown" — so every Mac running this daemon derived THE SAME store key. Anyone holding a
# copy of the ciphertext could open it without the machine.
#
# There is no macOS analogue of systemd-creds: no TPM sealing we can reach, and the System
# keychain is root-only, so a daemon that is deliberately not root cannot read it without a
# privileged unseal step — which lands on the same promise anyway, because the keychain's
# master key is on this same disk. So: a random key in a 0600 file owned by the account.
#
# NOT RECOMPUTABLE, which the derived key was. NOT SEALED, which the TPM tier is. A copy of
# this disk plus root opens it, and FileVault is what covers that. Say both.
STORE_KEY="${STATE_DIR}/store.key"
if [ -s "$STORE_KEY" ]; then
  echo "store key: already present at ${STORE_KEY}"
else
  ( umask 077 && dd if=/dev/urandom of="$STORE_KEY" bs=32 count=1 2>/dev/null )
  chown "${ACCOUNT}:${ACCOUNT}" "$STORE_KEY"
  chmod 0600 "$STORE_KEY"
  SK_MODE=$(stat -f '%Lp' "$STORE_KEY")
  [ "$SK_MODE" = "600" ] || { echo "ERROR: ${STORE_KEY} is mode ${SK_MODE}, expected 600." >&2; exit 1; }
  echo "store key: created, 0600 ${ACCOUNT} — random, so it cannot be recomputed"
fi
echo "           It is NOT sealed to hardware: a copy of this disk plus root opens it."
if fdesetup status 2>/dev/null | grep -qi 'FileVault is On'; then
  echo "           FileVault is ON, which is what covers that case."
else
  echo "           FileVault appears to be OFF. Turn it on: a stolen disk opens this store."
fi

echo ""
echo "  Next, ONCE per machine:  sudo wundervault-agent --pair"
echo "  That prints a code and a fingerprint. Type the code into the dashboard and check"
echo "  the fingerprint matches before you confirm. Neither value is a secret."
echo ""

# ── 3. the job ───────────────────────────────────────────────────────────────
# The template is shipped alongside this script and read from disk rather than written
# inline, so what lands in /Library/LaunchDaemons is the file you reviewed in the repo.
# Only the ProgramArguments path is substituted.
awk -v exec_path="$EXEC" '
  prev ~ /<key>ProgramArguments<\/key>/ && $0 ~ /<array>/ { print; inarr = 1; prev = $0; next }
  inarr && /<string>/ { sub(/<string>.*<\/string>/, "<string>" exec_path "</string>"); inarr = 0 }
  { print; prev = $0 }
' "$PLIST_SRC" > "$PLIST_PATH"

chown root:wheel "$PLIST_PATH"
chmod 0644 "$PLIST_PATH"

# launchd refuses a plist it considers insecure, and a job that runs as the wrong account
# is the one failure this whole script exists to prevent. Check both before loading.
grep -q "<string>${ACCOUNT}</string>" "$PLIST_PATH" || {
  echo "ERROR: the installed plist does not run as ${ACCOUNT}. Refusing to continue." >&2
  rm -f "$PLIST_PATH"; exit 1
}
grep -q "<string>${EXEC}</string>" "$PLIST_PATH" || {
  echo "ERROR: the installed plist does not point at ${EXEC}. Refusing to continue." >&2
  rm -f "$PLIST_PATH"; exit 1
}
plutil -lint "$PLIST_PATH" >/dev/null || {
  echo "ERROR: the installed plist is not valid. Refusing to continue." >&2
  rm -f "$PLIST_PATH"; exit 1
}
echo "job ${PLIST_PATH}: installed"

# ── 4. start ─────────────────────────────────────────────────────────────────
# bootout then bootstrap, not a bare bootstrap. Re-running the installer after an upgrade
# rewrote the plist must not leave the OLD process running under the OLD configuration,
# including a ProgramArguments pointing at the previous binary. `bootout` on a job that is
# not loaded is an error, so it is allowed to fail.
launchctl bootout "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH"
launchctl enable "system/${LABEL}"

sleep 2

# Did it actually come up, as the right account, on the right key?
#
# Ask the broker directly rather than reading a log: a log can be stale, truncated, or
# describe a previous run, and then a machine reports a clean install while running on the
# weaker key or as the wrong user.
PING='{"action":"ping"}'
SOCK="${RUN_DIR}/mgmt/agent.sock"
REPLY=""
if command -v socat >/dev/null 2>&1; then
  REPLY=$(printf '%s\n' "$PING" | socat - "UNIX-CONNECT:${SOCK}" 2>/dev/null || true)
elif command -v nc >/dev/null 2>&1; then
  # The daemon ends the socket after replying, so nc exits on its own. -w is a belt for
  # the case where the socket file exists and nothing is accepting on it.
  REPLY=$(printf '%s\n' "$PING" | nc -U -w 5 "$SOCK" 2>/dev/null || true)
fi

# args=, not comm=. The broker is a JavaScript file run by Node, so `ps -o comm=` reports
# the NODE binary and never the script path — a check written against comm= silently
# matches nothing and skips the one test that decides whether there is a boundary at all.
RUNNING_UID=$(ps -axo user=,args= | awk '/wundervault-agent/ && !/awk/ {print $1; exit}')

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  echo
  if [ -n "$REPLY" ]; then
    KEY_MODE=$(printf '%s' "$REPLY" | sed -n 's/.*"key_mode":"\([a-z-]*\)".*/\1/p')
    case "$KEY_MODE" in
      local-file)
        echo "The secret broker is running, on the random store key." ;;
      derived|derived-shared)
        echo "WARNING: the broker is running on a DERIVED store key, not the one this" >&2
        echo "         installer wrote. Check ${STORE_KEY} is readable by ${ACCOUNT}:" >&2
        echo "           sudo ls -l ${STORE_KEY}" >&2
        echo "           sudo tail -20 ${STATE_DIR}/agent.log" >&2
        echo "         Do not describe this machine as having a random store key." >&2 ;;
      *)
        echo "The secret broker is running. Store key mode: ${KEY_MODE:-unreported}." ;;
    esac
  else
    echo "The secret broker is loaded, but the management socket did not answer."
    echo "Neither socat nor nc could reach ${SOCK}; check it by hand:"
    echo "  sudo tail -20 ${STATE_DIR}/agent.log"
  fi

  if [ -n "$RUNNING_UID" ] && [ "$RUNNING_UID" != "$ACCOUNT" ]; then
    echo >&2
    echo "ERROR: the broker is running as '${RUNNING_UID}', not '${ACCOUNT}'." >&2
    echo "       There is no boundary in that state. Do not migrate agents to it." >&2
    exit 1
  fi

  echo
  echo "${STATE_DIR} is readable only by ${ACCOUNT}, which means your agents cannot"
  echo "read the credentials it holds."
  echo
  echo "Next, as your normal user (no sudo):"
  echo "  wundervault-agent --migrate     # hand existing agents over to the daemon"
else
  echo
  echo "The secret broker did not start. What it said:" >&2
  tail -20 "${STATE_DIR}/agent.log" 2>/dev/null >&2 || true
  launchctl print "system/${LABEL}" 2>&1 | head -20 >&2 || true
  exit 1
fi

```

## File: packaging/com.wundervault.agent.plist

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  The daemon, as its own user. The macOS half of phase 4.

  UserName is what does the work, exactly as User= does in the systemd unit. Everything the
  vault claims about a key "never reaching the agent" was, before this, true on a Mac only
  against an agent that did not try: same uid meant the agent could read the key files and
  attach to this process.

  WHAT LAUNCHD DOES NOT GIVE US, AND WE MUST NOT IMPLY IT DOES

  The systemd unit carries a second layer the boundary does not depend on but benefits
  from: ProtectSystem=strict, ProtectHome, PrivateTmp, ProtectProc=invisible,
  SystemCallFilter, an empty CapabilityBoundingSet. launchd has NO equivalent for any of
  them. A launchd job is an ordinary process owned by an ordinary account.

  So on macOS the uid split is not merely the boundary — it is very nearly the whole of the
  defence, and the daemon's filesystem reach is wider than on Linux. That is written into
  /limitations rather than left for someone to discover. What macOS does give us for free:
  System Integrity Protection keeps the account out of the system directories, and
  task_for_pid against another uid needs root just as ptrace does on Linux.

  Sandboxing this properly means a signed binary and an App Sandbox entitlement, which is
  phase 9. It is not a prerequisite for the uid split and must not be allowed to block it.
-->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.wundervault.agent</string>

  <!-- Rewritten by the installer to the resolved, verified path. -->
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/wundervault-agent</string>
  </array>

  <key>UserName</key>
  <string>_wundervault</string>
  <key>GroupName</key>
  <string>_wundervault</string>

  <key>RunAtLoad</key>
  <true/>

  <!--
    Restart on any exit, including a clean one. The daemon has no reason to exit while the
    machine is up, so an exit is a fault however tidy it looked, and a broker that quietly
    stays down is a machine whose agents cannot reach their credentials.
  -->
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>2</integer>

  <key>EnvironmentVariables</key>
  <dict>
    <!--
      One level down. /var/lib/wundervault itself is 0755 and holds nothing readable, so
      agents can traverse it to reach /var/lib/wundervault/run; the private state is here,
      at 0700. Putting the sockets inside a 0700 directory would deny every agent search
      permission on the path to its own socket.
    -->
    <key>WUNDERVAULT_SYSTEM_ROOT</key>
    <string>/var/lib/wundervault/state</string>
    <!--
      Which mechanism produced the store key, so the startup line makes the RIGHT promise.
      'local-file' is a random key in a 0600 file owned by this account: not recomputable,
      which the old derived key was, and not sealed to hardware, which the TPM tier is.
      A copy of the disk plus root opens it. FileVault is what covers that, and FileVault
      is not ours to claim.
    -->
    <key>WUNDERVAULT_SEAL_KIND</key>
    <string>local-file</string>
  </dict>

  <!-- 63 decimal is 0077. launchd reads this key as decimal, not octal. -->
  <key>Umask</key>
  <integer>63</integer>

  <!--
    Inside the STATE directory, which is 0700 and owned by this account — the log names
    agents and reports which store key is in use, so it does not belong in the traversable
    directory above it. /var/log would mean a file launchd creates as root that this
    account may not be able to append to, and a log nobody can write is a daemon that dies
    at boot for a reason nobody can read.
  -->
  <key>StandardOutPath</key>
  <string>/var/lib/wundervault/state/agent.log</string>
  <key>StandardErrorPath</key>
  <string>/var/lib/wundervault/state/agent.log</string>

  <!-- No core file. A crash must not spill credentials onto the disk. -->
  <key>SoftResourceLimits</key>
  <dict>
    <key>Core</key>
    <integer>0</integer>
  </dict>
  <key>HardResourceLimits</key>
  <dict>
    <key>Core</key>
    <integer>0</integer>
  </dict>
</dict>
</plist>

```

## File: packaging/verify-macos.sh

```
#!/bin/sh
# Phase 7 acceptance, run on the Mac.
#
# Everything in phase 7 except the installer itself was built and tested on Linux, through
# WUNDERVAULT_PLATFORM_SHAPE=darwin and WUNDERVAULT_LOCK_STRATEGY=port. That covers the
# paths and the lock semantics. It cannot cover dscl, launchctl, ioreg, or whether the
# account the job actually runs as is the account the plist names.
#
# This script covers those. Until it has been run and passed, phase 7 is BUILT and
# UNVERIFIED on its target platform, and the handoff says exactly that.
#
#   sh verify-macos.sh            # read-only: checks the install that is there
#   sh verify-macos.sh --full     # also exercises reinstall and uninstall (needs sudo)
#
# Read-only mode changes nothing. --full stops the broker and starts it again.

set -u

ACCOUNT=_wundervault
BASE_DIR=/var/lib/wundervault
STATE_DIR="${BASE_DIR}/state"
RUN_DIR="${BASE_DIR}/run"
LABEL=com.wundervault.agent
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FULL=0
[ "${1:-}" = "--full" ] && FULL=1

PASS=0
FAIL=0
SKIP=0

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }
skip() { SKIP=$((SKIP+1)); printf '  SKIP  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }

case "$(uname -s)" in
  Darwin) ;;
  *) echo "This script is for macOS. On Linux there is nothing here to verify." >&2; exit 1 ;;
esac

echo "Phase 7 acceptance — $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)"
echo

# ── the account (spec C1, C2) ────────────────────────────────────────────────
echo "The service account"
if dscl . -read "/Users/${ACCOUNT}" >/dev/null 2>&1; then
  ok "${ACCOUNT} exists"
  A_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
  A_SHELL=$(dscl . -read "/Users/${ACCOUNT}" UserShell 2>/dev/null | awk '{print $2}')
  case "$A_SHELL" in
    /usr/bin/false|/usr/bin/nologin|/sbin/nologin|/dev/null) ok "cannot log in (shell ${A_SHELL})" ;;
    *) bad "the account can log in" "UserShell is ${A_SHELL}; a person who becomes this account reads every credential" ;;
  esac
  if [ "$A_UID" -lt 500 ] 2>/dev/null; then
    ok "uid ${A_UID} is in the service range"
  else
    bad "uid ${A_UID} is in the login range" "a human account at this uid would dissolve the boundary"
  fi
  if [ "${SUDO_UID:-x}" = "$A_UID" ]; then
    bad "the broker account IS the invoking user" "there is no boundary between an account and itself"
  else
    ok "the broker account is not the invoking user"
  fi
  # Exactly one account, however many times the installer ran (spec check 14).
  N=$(dscl . -list /Users | grep -cx "${ACCOUNT}")
  [ "$N" = "1" ] && ok "exactly one ${ACCOUNT} account" || bad "${N} accounts named ${ACCOUNT}"
else
  bad "${ACCOUNT} does not exist" "run: sudo sh ${HERE}/install-daemon-macos.sh"
fi
echo

# ── the state directory (spec B1, check 6) ───────────────────────────────────
echo "Daemon state"
if [ -d "$STATE_DIR" ]; then
  MODE=$(stat -f '%Lp' "$STATE_DIR")
  OWNER=$(stat -f '%Su' "$STATE_DIR")
  [ "$MODE" = "700" ] && ok "${STATE_DIR} is 0700" || bad "${STATE_DIR} is ${MODE}, not 700" "the mode IS the boundary"
  [ "$OWNER" = "$ACCOUNT" ] && ok "owned by ${ACCOUNT}" || bad "owned by ${OWNER}, not ${ACCOUNT}"

  # The check that matters most, and the one only this machine can make: can the OWNER,
  # who is who the agents run as, read it? Run deliberately as the invoking user.
  if [ -n "${SUDO_USER:-}" ]; then
    if sudo -u "$SUDO_USER" test -r "$STATE_DIR" 2>/dev/null; then
      bad "the invoking user CAN read ${STATE_DIR}" "the agents run as that user; there is no boundary"
    else
      ok "the invoking user cannot read ${STATE_DIR}"
    fi
  elif [ "$(id -u)" != "0" ]; then
    if [ -r "$STATE_DIR" ]; then
      bad "this user CAN read ${STATE_DIR}" "the agents run as this user; there is no boundary"
    else
      ok "this user cannot read ${STATE_DIR}"
    fi
  else
    skip "reading ${STATE_DIR} as the owner" "run without sudo, or with sudo from a user shell"
  fi

  # The runtime directory is a SIBLING of the state directory, not a child (spec B2).
  # A child would be inside a 0700 directory and no agent could traverse to its socket.
  if [ -d "$RUN_DIR" ]; then
    ok "runtime directory is ${RUN_DIR}"
    R_MODE=$(stat -f '%Lp' "$RUN_DIR")
    case "$R_MODE" in
      755|775|777) ok "run dir is ${R_MODE} — agents can reach their sockets" ;;
      *) bad "run dir is ${R_MODE}" "agents cannot traverse it; every socket connect returns EACCES" ;;
    esac
    B_MODE=$(stat -f '%Lp' "$BASE_DIR")
    case "$B_MODE" in
      755|775|777) ok "base dir is ${B_MODE} — traversable" ;;
      *) bad "base dir is ${B_MODE}" "agents cannot traverse to ${RUN_DIR}" ;;
    esac
    # The decisive one: can the OWNER actually connect? Checked as the invoking user.
    if [ -n "${SUDO_USER:-}" ] && sudo -u "$SUDO_USER" test -x "$RUN_DIR" 2>/dev/null; then
      ok "the invoking user can traverse ${RUN_DIR}"
    elif [ -n "${SUDO_USER:-}" ]; then
      bad "the invoking user CANNOT traverse ${RUN_DIR}" "its agents cannot reach their sockets"
    elif [ -x "$RUN_DIR" ]; then
      ok "this user can traverse ${RUN_DIR}"
    else
      bad "this user CANNOT traverse ${RUN_DIR}" "its agents cannot reach their sockets"
    fi
  else
    bad "no ${RUN_DIR}" "the installer creates it; the daemon cannot, ${BASE_DIR} being root-made"
  fi
  [ -e /run/wundervault ] && bad "/run/wundervault exists" "the darwin shape must not use it" \
                          || ok "/run is not used"

  # Socket path length (spec check 7). 104 is the macOS sun_path limit.
  LONGEST="${RUN_DIR}/$(printf 'a%.0s' $(seq 1 64)).sock"
  if [ ${#LONGEST} -le 103 ]; then
    ok "longest possible socket path is ${#LONGEST} bytes (limit 104)"
  else
    bad "longest socket path is ${#LONGEST} bytes" "over the macOS sun_path limit; long agent names will fail to bind"
  fi
else
  bad "${STATE_DIR} does not exist" "run the installer"
fi
echo

# ── the store key (spec B3, check 9) ─────────────────────────────────────────
echo "The store key"
if sudo -n true 2>/dev/null || [ "$(id -u)" = "0" ]; then
  SK="${STATE_DIR}/store.key"
  if sudo test -s "$SK"; then
    SK_MODE=$(sudo stat -f '%Lp' "$SK")
    SK_SIZE=$(sudo stat -f '%z' "$SK")
    [ "$SK_MODE" = "600" ] && ok "store.key is 0600" || bad "store.key is ${SK_MODE}, not 600"
    [ "$SK_SIZE" -ge 32 ] && ok "store.key is ${SK_SIZE} bytes" || bad "store.key is only ${SK_SIZE} bytes"
  else
    bad "no store.key" "the broker is running on a derived key; the installer writes this one"
  fi
else
  skip "store.key mode and size" "needs sudo"
fi

# The hardware UUID is what the derived fallback uses if the store key is ever missing.
# Before phase 7 this was the string "unknown" on every Mac.
UUID=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | sed -n 's/.*"IOPlatformUUID" = "\([^"]*\)".*/\1/p')
if [ -n "$UUID" ]; then
  ok "IOPlatformUUID is readable (${UUID})"
else
  bad "cannot read IOPlatformUUID" "the derived fallback would have no machine identity here"
fi

if fdesetup status 2>/dev/null | grep -qi 'FileVault is On'; then
  ok "FileVault is on — a stolen disk does not open the store"
else
  bad "FileVault is off" "the store key is NOT sealed to hardware; FileVault is what covers a stolen disk"
fi
echo

# ── the job (spec C3, C4) ────────────────────────────────────────────────────
echo "The LaunchDaemon"
if [ -f "$PLIST_PATH" ]; then
  ok "${PLIST_PATH} installed"
  P_MODE=$(stat -f '%Lp' "$PLIST_PATH")
  P_OWNER=$(stat -f '%Su' "$PLIST_PATH")
  [ "$P_MODE" = "644" ] && ok "plist is 0644" || bad "plist is ${P_MODE}" "launchd refuses a writable plist"
  [ "$P_OWNER" = "root" ] && ok "plist owned by root" || bad "plist owned by ${P_OWNER}"
  plutil -lint "$PLIST_PATH" >/dev/null 2>&1 && ok "plist is valid" || bad "plist is not valid XML"
  grep -q "<string>${ACCOUNT}</string>" "$PLIST_PATH" && ok "plist names ${ACCOUNT}" \
    || bad "plist does not name ${ACCOUNT}" "the job would run as root or as you"
else
  bad "no ${PLIST_PATH}"
fi

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  ok "job is bootstrapped"
  # The decisive one. A plist that NAMES the account and a process RUNNING as it are two
  # different facts, and only the second is the boundary.
  RUNNING_AS=$(ps -axo user=,args= | awk '/wundervault-agent/ && !/awk/ {print $1; exit}')
  if [ -n "$RUNNING_AS" ]; then
    [ "$RUNNING_AS" = "$ACCOUNT" ] && ok "the broker process runs as ${ACCOUNT}" \
      || bad "the broker runs as ${RUNNING_AS}, not ${ACCOUNT}" "there is no boundary in this state"
  else
    bad "no broker process found" "the job is loaded but nothing is running"
  fi
else
  bad "job is not bootstrapped" "sudo launchctl bootstrap system ${PLIST_PATH}"
fi

# key_mode straight from the daemon, not from a log (spec C4).
SOCK="${RUN_DIR}/mgmt/agent.sock"
REPLY=""
if command -v nc >/dev/null 2>&1; then
  REPLY=$(printf '{"action":"ping"}\n' | sudo nc -U "$SOCK" 2>/dev/null)
fi
if [ -n "$REPLY" ]; then
  KM=$(printf '%s' "$REPLY" | sed -n 's/.*"key_mode":"\([a-z-]*\)".*/\1/p')
  case "$KM" in
    local-file) ok "daemon reports key_mode=local-file" ;;
    derived|derived-shared) bad "daemon reports key_mode=${KM}" "it is NOT using the key the installer wrote" ;;
    *) bad "daemon reported key_mode=${KM:-nothing}" ;;
  esac
else
  skip "key_mode from the daemon" "could not reach ${SOCK} with nc"
fi
echo

# ── the lock, on the real platform (spec checks 17-20) ───────────────────────
echo "The single-instance lock, on this machine"
if command -v node >/dev/null 2>&1 && [ -d "${HERE}/../dist" ]; then
  node -e '
    const lock = require("'"${HERE}"'/../dist/lock.js");
    process.env.WUNDERVAULT_AGENT_NAME = "VerifyMacOS_" + process.pid;
    (async () => {
      const first = await lock.acquireCredential("verify");
      if (!first.ok) { console.log("FAIL first claim refused: " + (first.reason || "")); process.exit(1); }
      const second = await lock.acquireCredential("verify");
      if (second.ok) { console.log("FAIL second claim SUCCEEDED — two holders of one credential"); process.exit(1); }
      if (!second.holder || second.holder.source !== "holder") {
        console.log("FAIL second claim refused but the holder was not identified: " + JSON.stringify(second.holder));
        process.exit(1);
      }
      const port = lock._addressPortForTests();
      if (port < 20000 || port > 32767) { console.log("FAIL derived port " + port + " is in the ephemeral range"); process.exit(1); }
      console.log("OK port=" + port);
      await lock.releaseCredential();
    })();
  ' > /tmp/wv-lock-verify.$$ 2>&1
  if grep -q '^OK' /tmp/wv-lock-verify.$$; then
    ok "a second claim is refused and names the holder ($(sed -n 's/^OK //p' /tmp/wv-lock-verify.$$))"
  else
    bad "the lock did not behave" "$(cat /tmp/wv-lock-verify.$$)"
  fi
  rm -f /tmp/wv-lock-verify.$$
else
  skip "the lock" "build first: npm run build"
fi
echo

# ── reinstall and uninstall (spec checks 12, 13, 14) ─────────────────────────
if [ "$FULL" = "1" ]; then
  echo "Reinstall and uninstall"
  if [ "$(id -u)" != "0" ]; then
    skip "--full checks" "re-run with sudo"
  else
    BEFORE_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
    sh "${HERE}/install-daemon-macos.sh" >/tmp/wv-reinstall.$$ 2>&1
    if [ $? -eq 0 ]; then ok "re-running the installer succeeds"; else bad "re-running the installer failed" "$(tail -5 /tmp/wv-reinstall.$$)"; fi
    AFTER_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
    [ "$BEFORE_UID" = "$AFTER_UID" ] && ok "the account uid did not move (${AFTER_UID})" \
      || bad "the uid changed from ${BEFORE_UID} to ${AFTER_UID}" "every file it owns is now orphaned"
    N=$(dscl . -list /Users | grep -cx "${ACCOUNT}")
    [ "$N" = "1" ] && ok "still exactly one account" || bad "${N} accounts after reinstall"
    rm -f /tmp/wv-reinstall.$$

    sh "${HERE}/install-daemon-macos.sh" --uninstall >/dev/null 2>&1
    [ -f "$PLIST_PATH" ] && bad "uninstall left the plist" || ok "uninstall removed the job"
    [ -d "$STATE_DIR" ] && ok "uninstall LEFT the credentials (${STATE_DIR})" \
      || bad "uninstall destroyed ${STATE_DIR}" "--uninstall must never be a way to lose the vault"
    dscl . -read "/Users/${ACCOUNT}" >/dev/null 2>&1 && ok "uninstall left the account" \
      || bad "uninstall deleted the account" "every file it owned is now orphaned"

    sh "${HERE}/install-daemon-macos.sh" >/dev/null 2>&1 \
      && ok "reinstalled after uninstall" || bad "could not reinstall after uninstall"
  fi
  echo
fi

echo "─────────────────────────────────────────"
printf '%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" = "0" ] || exit 1

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
# Unseal the store key into the runtime directory, and DO NOT DIE IF THAT FAILS.
#
# The obvious mechanism here is LoadCredentialEncrypted=, and it is the designed one — but a
# missing or undecryptable source is FATAL (243/CREDENTIALS), which turns a cleared or
# replaced TPM into a broker that cannot start at all. That is the worst version of this
# failure: the store has already been migrated to the sealed key, the old derived key is gone,
# and the fallback the code carries can never run because ExecStart is never reached. A
# machine in that state has no way back short of re-enrolling every agent, and the operator
# finds out at boot rather than at a moment of their choosing.
#
# ExecStartPre with a '-' prefix is non-fatal by construction, and '+' runs it as root, which
# is needed to reach the TPM or the host key. If unsealing works the broker finds the key and
# uses it; if it does not, the broker starts on the derived key and says so loudly at every
# start. Failing open is right here because the directory mode is still a real boundary — what
# is lost is defence in depth, not the boundary itself.
ExecStartPre=-+/bin/sh -c 'systemd-creds decrypt --name=wv-store-key /var/lib/wundervault/store.key.cred /run/wundervault/store.key && chown wundervault:wundervault /run/wundervault/store.key && chmod 0600 /run/wundervault/store.key'

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
 * account — `wundervault` under a systemd unit on Linux, `_wundervault` under a
 * LaunchDaemon on macOS. The mode is the control. The at-rest encryption beside it is
 * defence in depth and nothing more; calling it "encrypted at rest" as though it were the
 * boundary would repeat exactly the mistake this phase exists to correct.
 *
 * ON macOS THE BOUNDARY IS THE SAME AND THE DEFENCE AROUND IT IS THINNER. The systemd unit
 * carries ProtectSystem=strict, ProtectHome, ProtectProc=invisible, a system-call filter
 * and an empty capability set. launchd has no equivalent for any of them, so the uid split
 * there is very nearly the whole of it. Written down here and in /limitations rather than
 * left for someone to infer parity that does not exist.
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
 * macOS keeps its state one level down, and the reason is not tidiness.
 *
 * On Linux the sockets live in /run/wundervault, which systemd creates at 0755 OUTSIDE the
 * 0700 state directory. macOS has no /run and no RuntimeDirectory=, and the obvious answer
 * — put the sockets inside the state directory — is fatally wrong: 0700 means no search
 * permission for anyone but the daemon account, so an agent, which runs as the OWNER,
 * cannot traverse into it to reach its own socket. Every connection would fail with EACCES
 * on a machine where the install had gone perfectly.
 *
 * So the top directory is traversable and holds nothing readable, with the private state
 * one level down:
 *
 *   /var/lib/wundervault        0755  the account   — traversable, empty of secrets
 *   /var/lib/wundervault/state  0700  the account   — the boundary
 *   /var/lib/wundervault/run    0755  the account   — sockets, reachable by agents
 *
 * This is the same shape the module already argues for elsewhere: the sockets are
 * world-connectable and the TOKEN is the identity. Nothing is protected by being hard to
 * reach — so nothing legitimate may be made hard to reach either.
 */
export const DARWIN_BASE = '/var/lib/wundervault';
export const DARWIN_SYSTEM_ROOT = `${DARWIN_BASE}/state`;
export const DARWIN_ACCOUNT = '_wundervault';

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
 * Is the uid split actually available here, and which layout are we using?
 *
 * Phase 4 was Linux; phase 7 adds macOS; Windows (phase 8) is deliberately later. But OUT
 * OF SCOPE HAS TO MEAN UNCHANGED, not broken — and for two commits it meant broken. The
 * daemon's constructor calls ensureSystemRoot() unconditionally, so on macOS it tried to
 * mkdir /var/lib/wundervault as a normal user and died with EACCES where it had previously
 * used the home directory. On Windows it is quieter and worse: /var/lib/wundervault
 * resolves to C:\var\lib\wundervault, the mkdir SUCCEEDS, and the daemon then tries to
 * bind unix domain sockets there, which Windows does not have.
 *
 * Windows therefore keeps the pre-split layout exactly: state in the user's own directory,
 * daemon as the user. That is the old threat model, and the code says so out loud rather
 * than letting anyone infer a boundary that is not there.
 *
 * TWO QUESTIONS, NOT ONE — AND KEEPING THEM APART IS THE POINT
 *
 * `platformShape()` decides WHERE THINGS GO. It is overridable, because otherwise the
 * macOS layout is unreachable from CI on Linux and verifiable only by hand on one
 * machine — which is precisely how the port lock in lock.ts shipped broken and stayed
 * broken for a release.
 *
 * `splitAvailable()` decides WHETHER A BOUNDARY IS POSSIBLE. It consults the REAL
 * platform, so the override can make a Linux box exercise the darwin paths but can never
 * make a platform claim a separation it cannot perform.
 *
 * And neither of them is what we tell the user. That is `boundaryIsReal()`, below, which
 * looks at the directory rather than at the operating system.
 */
export type PlatformShape = 'linux' | 'darwin' | 'none';

/** Platforms on which a second uid is actually reachable. NOT overridable. */
const SPLIT_CAPABLE = new Set(['linux', 'darwin']);

function shapeFor(platform: string): PlatformShape {
  if (platform === 'linux') return 'linux';
  if (platform === 'darwin') return 'darwin';
  return 'none';
}

/**
 * Which layout to use. `WUNDERVAULT_PLATFORM_SHAPE` exists so a test on one platform can
 * exercise another's paths. An unrecognised value is a typo, not a request for the
 * pre-split layout, so it throws rather than silently dropping the boundary.
 */
export function platformShape(): PlatformShape {
  const override = process.env.WUNDERVAULT_PLATFORM_SHAPE;
  if (override) {
    if (override !== 'linux' && override !== 'darwin' && override !== 'none') {
      throw new Error(
        `WUNDERVAULT_PLATFORM_SHAPE=${JSON.stringify(override)} is not one of ` +
        `linux, darwin, none.`,
      );
    }
    return override;
  }
  return shapeFor(process.platform);
}

/**
 * Pure, so the combination can be asserted directly rather than by stubbing a global.
 *
 * The real platform is the veto. A shape of 'linux' on Windows yields FALSE: the override
 * relocates state, it does not conjure an account the operating system cannot give us.
 */
export function splitAvailableFor(realPlatform: string, shape: PlatformShape): boolean {
  return SPLIT_CAPABLE.has(realPlatform) && shape !== 'none';
}

/** True where the daemon CAN hold a real privilege boundary. Not that it does. */
export function splitAvailable(): boolean {
  return splitAvailableFor(process.platform, platformShape());
}

export function systemRoot(): string {
  if (process.env.WUNDERVAULT_SYSTEM_ROOT) return process.env.WUNDERVAULT_SYSTEM_ROOT;
  // Where there is no system account and no unit, the daemon is the user, as before.
  if (!splitAvailable()) return userRoot();
  if (platformShape() === 'darwin') return DARWIN_SYSTEM_ROOT;
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
  if (!splitAvailable()) return userRoot();
  const run = `/run/${SYSTEM_ACCOUNT}`;
  let linuxRunExists = false;
  try { linuxRunExists = fs.existsSync(run); } catch { /* treat as absent */ }
  return runtimeDirFor(platformShape(), systemRoot(), linuxRunExists);
}

/**
 * Pure, and pure for a reason that cost a round to learn.
 *
 * The darwin branch and the Linux fallback return THE SAME STRING on a box that has no
 * /run/wundervault — which is every development box. So a test asserting the returned path
 * passed whether the darwin branch was there or not: deleting it entirely left the suite
 * green. What distinguishes the two is the DECISION, not the result, and a decision is only
 * observable if the inputs can be supplied.
 *
 * macOS has no /run, and /var/run is cleared at boot and unwritable by the service account,
 * so there is no analogue of systemd's RuntimeDirectory=. The runtime directory lives inside
 * the state directory, which the account already owns.
 */
export function runtimeDirFor(
  shape: PlatformShape,
  root: string,
  linuxRunExists: boolean,
): string {
  // A SIBLING of the state directory, never a child. The state directory is 0700, which
  // denies search permission to the agents that have to reach these sockets.
  if (shape === 'darwin') return path.join(path.dirname(root), 'run');
  if (linuxRunExists) return `/run/${SYSTEM_ACCOUNT}`;
  return path.join(root, 'run');
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
  // Two places, because the unit unseals with ExecStartPre rather than
  // LoadCredentialEncrypted — that mechanism is fatal when the source cannot be decrypted,
  // which turns a cleared TPM into a broker that will not start. $CREDENTIALS_DIRECTORY is
  // still checked first so the unit can be switched back without touching this code.
  const candidates: string[] = [];
  const dir = process.env.CREDENTIALS_DIRECTORY;
  if (dir) candidates.push(path.join(dir, name));
  candidates.push(path.join(runtimeDir(), 'store.key'));
  // macOS has no systemd and nothing that unseals on our behalf, so the installer writes a
  // RANDOM key into the state directory at 0600, owned by the daemon account. It is not
  // sealed and the startup report must not say it is — but it is not DERIVED either, which
  // is the difference that matters: nobody can recompute it from public inputs.
  if (platformShape() === 'darwin') candidates.push(storeKeyPath());

  for (const p of candidates) {
    try {
      const buf = fs.readFileSync(p);
      if (buf.length >= 32) return buf;
    } catch { /* try the next */ }
  }
  return null;
}

/**
 * Was the key sealed to the TPM, or only to systemd's host key?
 *
 * The difference is the entire claim. A TPM-sealed key does not leave the machine: copy the
 * disk and it does not open. A HOST-KEY-sealed one is protected by a file at
 * /var/lib/systemd/credential.secret which lives ON THE SAME DISK, so a copy of that disk
 * plus root access opens it — verified by decrypting a sealed blob using nothing but files
 * from the same filesystem. It is still far better than a key derived from public inputs, but
 * saying "a copy of the disk does not open it" about it is simply false, and that sentence
 * was being printed.
 */
export function sealedWithTpm(): boolean {
  return sealKind() === 'tpm';
}

/**
 * Which mechanism produced the store key, so the startup report can make the RIGHT promise.
 *
 *   'tpm'        — sealed to this machine's TPM. A copy of the disk does not open it.
 *   'host'       — sealed to systemd's host key, which is on the same disk. Root plus a
 *                  disk copy does open it.
 *   'local-file' — macOS. A random key in a 0600 file owned by the daemon account. Same
 *                  promise as 'host': not recomputable, not sealed to hardware. FileVault
 *                  is what covers the stolen-disk case, and FileVault is not ours to claim.
 *
 * Three names because three different sentences are true, and the failure this codebase
 * keeps having is one sentence being reused for a weaker mechanism.
 */
export type SealKind = 'tpm' | 'host' | 'local-file' | null;

export function sealKind(): SealKind {
  const declared = process.env.WUNDERVAULT_SEAL_KIND;
  if (declared === 'tpm' || declared === 'host' || declared === 'local-file') return declared;
  // Undeclared on darwin but the file is there: the installer wrote it and did not get to
  // set the variable, or the daemon was started by hand. Report what is actually in use.
  if (platformShape() === 'darwin') {
    try { if (fs.statSync(storeKeyPath()).size >= 32) return 'local-file'; } catch { /* none */ }
  }
  return null;
}

/** The macOS store key: written by the installer, read by us, 0600 and never shared. */
export const storeKeyPath = () => path.join(systemRoot(), 'store.key');

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
  splitAvailable() ? path.join(runtimeDir(), 'mgmt') : runtimeDir();
export const mgmtSocketPath = () => path.join(mgmtDir(), 'agent.sock');
export const agentSocketPath = (name: string) =>
  splitAvailable()
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
  try {
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    fs.chmodSync(root, 0o700);
  } catch (err) {
    // The commonest first-run failure on a machine where the privileged step has not been
    // taken: the daemon is not the account that owns this directory, and cannot create it.
    // Raw EACCES on /var/lib/wundervault sends a person looking for a bug in the daemon
    // rather than telling them the one command that fixes it — and on macOS, where this
    // path is new in phase 7, an upgrade lands exactly here.
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EACCES' || code === 'EPERM') {
      const installer = process.platform === 'darwin'
        ? 'sudo sh packaging/install-daemon-macos.sh'
        : 'sudo sh packaging/install-daemon.sh';
      throw new Error(
        `Cannot use ${root}: permission denied.\n` +
        `  The secret broker needs its own account, and the privileged install step has\n` +
        `  not been run on this machine:\n` +
        `    ${installer}\n` +
        `  Then hand your existing agents over:  wundervault-agent --migrate`,
      );
    }
    throw err;
  }
  // The mode check is the BOUNDARY on Linux and merely hygiene elsewhere, where the
  // directory belongs to the same user the agents run as. Refusing to start over it off
  // Linux would block a daemon on a platform that never claimed the boundary — Windows in
  // particular reports modes that do not mean what they say.
  if (!splitAvailable()) return;
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

/**
 * Is there ACTUALLY a boundary here, right now?
 *
 * Every other function in this file answers a question about the operating system. This
 * one answers the question the user is actually asking, and it answers it by looking at
 * the directory rather than at `process.platform`.
 *
 * The distinction is not academic. Before this existed, the startup warning keyed off the
 * platform alone — so a daemon started by hand on Linux with WUNDERVAULT_SYSTEM_ROOT
 * pointed into the owner's home printed NOTHING, while running as the same uid as the
 * agents it served. The platform was Linux, and the platform was all the check consulted.
 * The same shape of mistake on macOS would be a broker that had never been installed
 * reporting a separation it did not have.
 *
 * Five things, all observed:
 *   - the state root exists and is a directory;
 *   - its mode is exactly 0700 — anything wider is not a boundary whatever owns it;
 *   - it is owned by OUR euid, so we are the daemon account rather than a visitor;
 *   - our euid is not 0, because root is not a boundary against anything, and is not the
 *     uid that invoked us under sudo, because that is the owner's own account;
 *   - the state root is NOT the pre-split location.
 *
 * That last one is not belt-and-braces, it is the check that makes the rest mean anything.
 * Pre-split, state lives in the owner's own `~/.wundervault`, which ensureSystemRoot()
 * chmods to 0700 — so it is a 0700 directory owned by the euid running the daemon, and the
 * first four tests all pass while the agent and the daemon are the same account. The
 * boundary is not "a private directory"; it is "a directory belonging to somebody the
 * agent is not". When the state root IS the agent's own directory, there is nobody else.
 */
export function expectedAccount(): string {
  return process.env.WUNDERVAULT_SYSTEM_ACCOUNT
    || (platformShape() === 'darwin' ? DARWIN_ACCOUNT : SYSTEM_ACCOUNT);
}

export function boundaryIsReal(root = systemRoot()): boolean {
  const geteuid = (process as unknown as { geteuid?: () => number }).geteuid;
  if (typeof geteuid !== 'function') return false; // Windows: no uids, no boundary.
  const euid = geteuid.call(process);
  if (euid === 0) return false;

  // WE MUST BE THE SERVICE ACCOUNT, BY NAME. This is the check that does the work, and
  // leaving it out was a hole big enough to drive the whole phase through: an owner who
  // starts the daemon by hand with WUNDERVAULT_SYSTEM_ROOT pointed at a scratch directory
  // gets a 0700 directory owned by their own uid, outside their ~/.wundervault — which
  // passes every test below it. The daemon would then report a boundary while running as
  // precisely the account its agents run as.
  //
  // SUDO_UID does not cover this; it is only set when someone used sudo. The account name
  // is the one signal that is present however the process was started.
  try {
    if (os.userInfo().username !== expectedAccount()) return false;
  } catch {
    return false; // Cannot identify ourselves: not a boundary we can vouch for.
  }

  // Running under `sudo` as the invoking user's own account is the one case that looks
  // right from the inside and is not: the agent runs as that uid too.
  const sudoUid = process.env.SUDO_UID ? Number(process.env.SUDO_UID) : NaN;
  if (Number.isInteger(sudoUid) && sudoUid === euid) return false;

  // The pre-split layout, which passes every other test here while being the exact thing
  // this function exists to deny. EQUALITY, not containment: pre-split, systemRoot()
  // literally returns userRoot(), so they are the same path and nothing weaker is needed.
  //
  // Containment was tried and is WRONG. The installer runs
  // `useradd --home-dir /var/lib/wundervault`, so inside the daemon os.homedir() is the
  // state directory and userRoot() is `<state dir>/.wundervault` — contained by the state
  // root on every correct install. A containment test therefore reports "no privilege
  // boundary" on precisely the configuration that has one.
  try {
    if (fs.realpathSync(root) === fs.realpathSync(userRoot())) return false;
  } catch {
    if (path.resolve(root) === path.resolve(userRoot())) return false;
  }

  try {
    const st = fs.statSync(root);
    if (!st.isDirectory()) return false;
    if ((st.mode & 0o777) !== 0o700) return false;
    return st.uid === euid;
  } catch {
    return false;
  }
}

/**
 * Does `child` live inside `parent`?
 *
 * Both sides are resolved before they are compared, because on macOS `/var` is a symlink
 * to `/private/var`. `/var/lib/wundervault` and `/private/var/lib/wundervault` are the
 * same directory, and a string prefix test says they are not — so a containment check
 * written the obvious way passes on Linux, fails on a Mac, and fails in the direction that
 * refuses legitimate paths rather than admitting illegitimate ones.
 *
 * Falls back to the unresolved path when a component does not exist yet: realpath throws
 * on a path that is about to be created, and refusing to answer would be worse than
 * answering about the lexical path.
 */
export function isInside(parent: string, child: string): boolean {
  // Resolving each side independently is NOT enough, and the asymmetry is the bug: on a
  // Mac an existing parent resolves to /private/var/... while a child that does not exist
  // yet falls back to its literal /var/... form, so a path genuinely inside the parent
  // reports false. Anything about to be created — every socket path — takes that branch.
  //
  // So: resolve the deepest ancestor that DOES exist, then re-append the rest.
  const resolve = (p: string): string => {
    const abs = path.resolve(p);
    let head = abs;
    const tail: string[] = [];
    for (;;) {
      try { return path.join(fs.realpathSync(head), ...tail); } catch { /* go up */ }
      const parentOfHead = path.dirname(head);
      if (parentOfHead === head) return abs;   // reached the root, nothing resolvable
      tail.unshift(path.basename(head));
      head = parentOfHead;
    }
  };
  const p = resolve(parent);
  const c = resolve(child);
  return c === p || c.startsWith(p.endsWith(path.sep) ? p : p + path.sep);
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
