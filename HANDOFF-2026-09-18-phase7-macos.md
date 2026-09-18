# Handoff — phase 7: the secret broker on macOS

Written 2026-09-18, after `HANDOFF-2026-09-17-phase6.md`. Spec is
`SPEC-phase7-macos.md`. Joins the same unshipped cutover as everything from 16–18
September → `project_wundervault_v2_cutover_plan`.

**NOTHING IS DEPLOYED.** And one thing more than usual: **nothing here has run on a Mac.**
There was no macOS machine available. Everything except the installer is exercised from
Linux through two new overrides, and `packaging/verify-macos.sh` exists precisely so that
the remaining gap can be closed in one command when a Mac appears.

---

## 1. What this closes

Phase 4 gave the broker its own uid on Linux and said so out loud:
`SPLIT_AVAILABLE = process.platform === 'linux'`. On macOS the daemon kept the pre-split
layout and printed, at every start, that its key material and memory were readable by
anything the owner ran. That warning was true. This phase makes it false.

The boundary is the same mechanism as Linux and makes the same claim: a second uid. A
LaunchDaemon running as `_wundervault`, a state directory at 0700 owned by that account,
agents that run as the owner and cannot open it.

**What it is NOT.** The plan's §B2 proposed trading the privileged install for code
signing — a Keychain ACL binds an item to a signed binary, so another program running as
the same user cannot read it. That mechanism is real and does not reach us: an ACL records
the designated requirement of the trusted executable, our daemon is a JavaScript file that
Node executes, so the identity recorded is **Node's** — and every agent on the machine can
also run Node. It separates programs; it cannot separate two invocations of one
interpreter. Making the ACL name *us* means a signed, notarised standalone binary, an
Apple Developer account, a signing pipeline, and a distribution channel that is not npm —
which also cuts against `/verify#installer`. **That is phase 9**, where it buys "which
program" rather than merely "which user", a stronger claim than Linux makes. It was not
allowed to block uid separation.

---

## 2. What was built

**The platform decision split in two, and became observable.** `platformShape()`
(`linux|darwin|none`, overridable by `WUNDERVAULT_PLATFORM_SHAPE`) decides WHERE THINGS
GO. `splitAvailableFor(realPlatform, shape)` — pure — decides WHETHER a boundary is
possible, and the real platform is a veto, so the override can make a Linux box exercise
the darwin layout but can never manufacture a boundary.

**`boundaryIsReal()` replaces the platform as the thing we tell the user.** It looks at
the directory, not the operating system: we are running as the expected service account
BY NAME, the state root exists at exactly 0700 owned by our euid, our euid is neither 0
nor `SUDO_UID`, and the root is not the pre-split location. This also closed a gap that
predates macOS — on Linux, a daemon started by hand with `WUNDERVAULT_SYSTEM_ROOT` pointed
into the owner's home printed nothing at all.

**Three directories on macOS, and the split between them is not tidiness.**

```
/var/lib/wundervault         0755  _wundervault   traversable, holds nothing readable
/var/lib/wundervault/state   0700  _wundervault   the boundary
/var/lib/wundervault/run     0755  _wundervault   sockets, which agents must reach
```

**The store key.** Linux seals with `systemd-creds`, to a TPM where there is one. macOS
has neither, so the installer writes a random 32-byte key at 0600 owned by the account,
and `key_mode` is `local-file` with its **own** startup sentence. Not recomputable, which
the old derived key was. Not sealed, which the TPM tier is: a copy of the disk plus root
opens it, FileVault is what covers that, and the installer reports `fdesetup status`
rather than claiming it.

**The single-instance lock, which was broken.** `HANDOFF-lock-on-non-linux.md` recorded
two assertions that failed on macOS CI and were gated off as unexplained. Cause found, and
it was not `askHolder`: the eight candidate ports were derived into **49152–65535, exactly
macOS's default ephemeral range**, so an unrelated outbound socket transiently owned a
candidate, the walk moved on, and a later claim bound the freed candidate and returned
`ok: true`. **Two live holders of one credential** — the control the module exists to
enforce. Now one port in 20000–32767, no walk, a stranger is a hard refusal naming the
port. That handoff is deleted rather than left to read as open.

---

## 3. The bug found on the way, which is the one to remember

`legacyDerivedKey()` read `/etc/machine-id`, swallowed the failure, and carried on with
the literal string `unknown`.

That file does not exist on macOS. So the derived store key on every Mac was HKDF over
`sha256("unknown:501")` — and 501 is the uid macOS gives the first account it creates. The
fallback was documented as "recomputable by anyone who can read the directory". On a Mac
it was computable by anyone who could read the repository, on any machine, without the
disk.

macOS now derives from `IOPlatformUUID`, **checked before** `/etc/machine-id`: a file
travels with a disk image and a hardware UUID does not. `legacyDerivedKey()` is kept
verbatim, for opening a store this account wrote under the old derivation — and with a
comment saying explicitly that it does NOT reach across to a pre-split store in the
owner's home, and must not be "fixed" to.

---

## 4. Deploy order — one step added

1. **Re-sign `onboard.py`.** Still step one. Key vaulted as `OnboardSigningKey`.
2. **Publish the npm package.** `packaging/` is in `files`, so the new installer, plist and
   verify script ship with it.
3. **Deploy burnbox**, running the four migrations from the phase-6 handoff. Not
   12:00–13:00 PT on a weekday.
4. **Linux, unchanged:** install the broker, `sudo wundervault-agent --pair` once.
5. **macOS, NEW:** `sudo sh packaging/install-daemon-macos.sh`, then
   **`sh packaging/verify-macos.sh`**, then `sudo wundervault-agent --pair` once.
6. **Migrate ONE agent, then STOP AND CHECK THE EDGE** — unchanged from phase 6, and still
   the step most likely to bite.
7. **Migrate the rest**, one at a time. Installing the broker migrates nothing by itself.
8. **Open WHAT TO ROTATE and work the list.**

---

## 5. What phase 7 does NOT close

- **launchd has no sandboxing.** The systemd unit carries `ProtectSystem=strict`,
  `ProtectHome`, `ProtectProc=invisible`, a syscall filter and an empty capability set.
  launchd has no equivalent for any of them, so on macOS the uid split is very nearly the
  whole of the defence and the daemon's filesystem reach is wider. In `/limitations`; do
  not let the copy imply parity.
- **The store key is not sealed to hardware.** §2.
- **A compromised broker**, unchanged from phase 6. It holds the private key.
- **One uid is one principal**, on both platforms.
- **Windows.** Phase 8, still pre-split, still warning at every start. Its behaviour is
  untouched; the warning's *wording* changed, because it ended "The boundary is Linux-only
  for now", which this phase makes false.

---

## 6. Things that will bite you

- **The runtime directory must stay OUTSIDE the 0700 state directory, and outside is not
  obvious.** I specified it as `/var/lib/wundervault/run` inside the state root and that is
  fatal: 0700 denies search permission to everyone but the daemon account, and the agents
  run as the OWNER — so every agent would get EACCES connecting to its own socket on a
  perfect install. Then the plist's `Umask 0077` re-broke it a second way, masking the
  daemon's `mkdir(0755)` of the `mgmt/` directory back down to 0700. The daemon now chmods
  **and verifies** that directory is traversable, and refuses with a message naming EACCES
  if it is not.
- **`KeepAlive` must be `{SuccessfulExit: false}`, not `true`.** launchd has no
  `Restart=on-failure` with a give-up count, so a job that exits non-zero comes back every
  `ThrottleInterval` for ever. A daemon correctly refusing to start would respawn every two
  seconds and append its reason to a log inside a 0700 directory nobody watches, until the
  disk filled. Refusals a restart cannot fix throw `ConfigurationRefusal` and exit **0**;
  everything else keeps its non-zero code. **The plist and that class have to stay in
  step** — a test pins both.
- **Two agents can derive the same lock port.** 12,768 addresses, so the birthday bound
  bites at around a hundred agent names on one machine. A wundervault holder answering for
  a *different* agent is reported as a collision naming `WUNDERVAULT_LOCK_PORT` — never as
  "your credential is in use", which would be false and would send someone hunting a
  duplicate agent that does not exist.
- **`/var` is a symlink to `/private/var`.** Every containment check resolves realpaths,
  and resolving each side independently is not enough: a child that does not exist yet —
  which is every socket path — fell back to its literal form while the parent resolved
  through the symlink.
- **The daemon's log has no size bound.** `StandardOutPath` points at a file in the state
  directory and nothing rotates it. The KeepAlive spin that would have filled it is fixed,
  but a chatty failure still grows unboundedly. It wants a `newsyslog.d` entry, and the
  same gap exists anywhere the Linux daemon runs without journald — worth doing once, for
  both, rather than here. **Open.**
- **`WUNDERVAULT_SYSTEM_ACCOUNT` exists for a non-standard install.** If you install the
  broker under a different account name, set it, or the daemon will correctly report that
  it cannot vouch for the boundary.

---

## 7. Review log

Two rounds, both triaged in `.buildreview/`.

| Round | Verdict | Outcome |
|---|---|---|
| 21 (code) | revise | 2 blockers, 4 majors, 1 minor, 3 blind spots — 5 fixed, 2 rejected with evidence, 1 blind spot promoted to a real bug and fixed |
| 22 (packaging) | revise | 2 blockers, 6 majors, 1 minor, 4 blind spots — 12 fixed, 1 rejected with evidence |

**What I rejected, with evidence:**

- *F3 — "the legacy fallback cannot open a pre-phase-7 macOS store after the uid split".*
  The arithmetic is right and the conclusion does not follow: nothing ever asks the daemon
  to open that store. Migration deliberately carries no credentials — `--migrate` runs as
  the OWNER, `legacyAgentNames()` derives with the owner's uid and reads only agent NAMES,
  and the credentials are replaced by REPAIR in the dashboard. The reviewer had not been
  shown `migrate.ts`. It did catch a comment of mine that implied otherwise, now corrected.
- *F7 — "the Windows warning changed, though the spec said byte for byte".* It did change
  and it had to; the removed sentence is now false. The spec said the wrong thing and was
  amended to "behaviour unchanged".
- *Round 22 F2 — "Umask 63 makes Node create the sockets at 0700, so agents get EACCES".*
  The code chmods every socket to 0666 in its listen callback (`agent.ts:941`, `:1215`) and
  chmod is absolute, so umask does not reach it. The reviewer had not been shown `agent.ts`
  that round — the case I had asked it to flag rather than assume. What is real and much
  smaller: a brief window between `listen()` and the chmod, which fails CLOSED. The same
  reflex found the genuine version of this bug in the DIRECTORIES, which is fixed.

**The most serious thing round 22 found was in its blind spots, not its findings.** The
installer writes `store.key` and `broker-key.pem` as **root**, into a directory the service
account owns. That account could place a dangling symlink at either path before a
reinstall; `openssl` or `dd` would follow it as root, create or clobber whatever it pointed
at, and the `chown` afterwards would hand that target to the service account. A root-write
primitive, in the one script that asks for root. Both paths are now refused if they are
symlinks — tested with `-h`, which asks about the link, not `-f`, which follows it and
answers about the target.

**Round 22's other theme was my verifier lying.** It exited zero with required checks
skipped (no passwordless sudo, no build → the store-key checks and the entire lock test
silently SKIPped), measured a socket path built from a possibly-empty `seq` expansion, and
in `--full` could uninstall and then fail to reinstall, leaving the machine with no broker
at all. `skip()` now means "does not apply"; `need()` records a required check that could
not run, prints NOT RUN, and fails the script.

**Three of my own tests initially passed under sabotage**, which is the part worth keeping:

1. Pinning `platformShape()` to `'linux'`, and deleting the darwin branch from
   `runtimeDir()`, both left the suite green — because on a box with no `/run/wundervault`
   the darwin branch and the Linux fallback **return the same string**. The test asserted
   the result, and the result could not tell them apart. Fixed by extracting a pure
   `runtimeDirFor(shape, root, linuxRunExists)` so the DECISION is observable.
2. Deleting `refuseWithoutSplit()` from `cleanup()` changed no behaviour at all, because
   `cleanup()` calls `status()`, which guards too. No behavioural test can catch that, so
   the redundant guard keeps a narrow source assertion, **labelled as the weaker check it
   is** rather than dressed up as coverage.
3. Un-awaiting the post-bind `close()` left its test green, because with no active
   connections the close callback wins the race on this machine every time. The await is
   **reasoned, not demonstrated**, and the test says so.

**Found by reading rather than by any test:** the runtime-directory permission bug in §6.
No test would have caught it and it would have surfaced only on the Mac.

---

## 8. What is still unverified, and exactly how to finish it

Parts A, B and D are exercised from Linux through `WUNDERVAULT_PLATFORM_SHAPE` and
`WUNDERVAULT_LOCK_STRATEGY`. **512 tests pass, up from 461.** CI already runs
`macos-latest`, so those three parts get a real Mac on the next push without anyone doing
anything.

**Part C — `dscl`, `launchctl`, `ioreg`, and whether the account the job runs as is the
account the plist names — has never executed.** `sh -n`, `bash -n`, `plutil -lint` and a
Linux run of the `awk` substitution are the whole of its verification. `shellcheck` is not
installed on this box and has not been run.

On the Mac, in order:

```sh
npm install -g --prefix /usr/local @wundervault/mcp-server
sudo sh packaging/install-daemon-macos.sh --exec /usr/local/bin/wundervault-agent
npm run build && sh packaging/verify-macos.sh          # read-only
sudo sh packaging/verify-macos.sh --full               # also exercises reinstall/uninstall
```

`verify-macos.sh` prints a PASS/FAIL line per check and exits non-zero if any failed. It
asserts the things only that machine can answer: that the invoking user **cannot** read the
state directory and **can** traverse the run directory, that the running process is owned by
`_wundervault` and not by root or by you, that `key_mode` is `local-file` straight from the
daemon rather than from a log, that the derived lock port is outside the ephemeral range,
and that a second claim is refused. The lock harness inside it was run against a real build
on Linux first — a verification script that cannot itself run reports nothing and looks
like a pass.

**Until that has been run, phase 7 is BUILT and UNVERIFIED on its target platform.** Do not
describe macOS as supported in any customer-facing copy before it passes.
