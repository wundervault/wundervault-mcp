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
