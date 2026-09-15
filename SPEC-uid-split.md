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
      `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `MemoryDenyWriteExecute=yes`,
      `LockPersonality=yes`, `ProtectProc=invisible`, `LimitCORE=0`.
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
