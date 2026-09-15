# PLAN — local network shape, then the uid split on three platforms

Review the PLAN, not an implementation. One module exists (`src/network-store.ts`);
everything else below is proposed.

## Context a reviewer needs

Wundervault is a secrets vault for AI agents. The server is genuinely blind to secret
contents — the browser generates a per-agent vault key and the server holds only
ciphertext and wrapped keys. Built so far, all local, none shipped:

- an **ssh-agent broker** — the key answers signature requests and never touches disk
- **`vault_call`** — the daemon performs a typed or agent-described HTTP request; the
  credential is attached by the daemon and never returned
- **`entry_mode`** — per-entry, non-null: `LEGACY_EXEC` | `BROKER_SSH_AGENT` | `BROKER_HTTP`
- **tiering**: Tier 1 brokers with no approval; Tier 2 refuses into an owner approval
  scoped to the exact origin, method and path

**The daemon currently runs as the SAME uid as the agent.** So none of this is a
confidentiality boundary yet: the agent can read the daemon's key files and memory. That
is stated in the code, not implied away.

---

# Part A — move the network shape off the server

## A1. What and why

Destinations are a behavioural profile: which services are called, how often, when, and
(for private origins) the customer's internal network addresses. None of it helps anyone
read a secret. All of it is competitive intelligence, and it is what a breach or a
subpoena reaches.

Proposal: **Tier 1 destinations never leave the customer's machine.** Tier 2 destinations
DO reach the server, because a human must review the request to approve it, and review
requires seeing it. That is consented disclosure of one call, not a standing profile.

## A2. What moves

| data | today | proposed |
|---|---|---|
| seen destinations (the "new destination" baseline) | server access log | local file |
| approved private origins | server, on the entry | **stays server-side** — see A5a |
| Tier 1 call destination | server access log | local only |
| Tier 1 fact-of-call (entry, agent, time) | server | **unchanged — stays server-side** |
| Tier 2 requested operation | server | unchanged — approval needs it |

Keeping the fact-of-call server-side preserves the tamper-evident, HMAC-chained audit
that already exists. Only the *where* becomes local.

## A5a. Why approvals did NOT move

An earlier draft moved them local with everything else. That was a regression: the file
is writable by the agent's uid, so a compromised agent could write its own approval and
walk through the SSRF filter it was meant to be constrained by.

An observation being forgeable costs a missed notice. A control being forgeable costs the
control. So the local store records what happened and never decides what is allowed, and
approvals stay where the owner authenticates — at the cost of the server learning the
internal addresses of entries you explicitly approve. That is a small consented
disclosure rather than a standing profile, and it becomes local once a daemon-owned path
exists.

## A3. The honest limit

The local file lives in the agent's home directory and is writable by the agent's uid, so
**a compromised agent can edit its own record of where it sent things.** The party being
audited controls the evidence. This is therefore a privacy improvement and NOT an
integrity control until Part B moves it to a daemon-owned path.

Stated plainly rather than papered over, because shipping it as "local audit log" would
claim something it does not do.

## A4. Alerting, and one unresolved choice

The daemon detects a first sighting locally. To email the owner, the server must be told.
Two options, and we have not chosen:

1. **Server relays, does not store.** The email names the destination; the server handles
   it transiently. Better UX, weaker claim ("we never store it" rather than "we never see
   it").
2. **Server knows only that something is new.** The email says a secret went somewhere
   new and to check locally (`wundervault destinations`). Purest, materially worse.

**Reviewer: which is defensible, and is option 1's distinction honest or a fig leaf?**

## A5. Also proposed

- shorter retention option (7 days) for the server-side log
- an explicit off switch for destination recording, accepting that it disables alerting —
  the metadata IS the control, so opting out of one opts out of both

---

# Part B — the uid split, three platforms

## B1. Linux (first)

- system account `wundervault`; key material in `/var/lib/wundervault`, mode 0700
- systemd **system** unit, hardened: `NoNewPrivileges`, empty `CapabilityBoundingSet`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `RestrictSUIDSGID`, `LimitCORE=0`,
  `ReadWritePaths=/var/lib/wundervault`, process non-dumpable
- the local network store moves here and becomes an integrity control
- **one privileged install per machine; enrolment stays unprivileged**
- distribution: signed `.deb`/`.rpm`, verified before install. **Not `curl | sudo sh`** —
  the product's differentiator is a verifiable installer, and piping unverified network
  content to root destroys that

### B1a. Peer identity — a constraint worth flagging

**Node has no `SO_PEERCRED`.** Verified: `net.Socket` exposes no peer credentials, and a
native addon would put a compiled dependency into an npm package whose selling point is
that you can read and verify it.

Proposal: authenticate with the **per-agent token that already exists**
(`~/.wundervault/agents/<name>.token`, mode 0600, 32 random bytes, written at enrolment).
After the split it lives in the agent's home, readable only by the agent's uid, so the
socket can be world-connectable and the token is the identity.

This gives **uid-level identity** — the same granularity `SO_PEERCRED` offers on Linux
anyway, since that only reports a uid. One uid is one security principal: two agents
under one uid cannot be told apart, by us or by the kernel.

**Reviewer: is token-in-file equivalent to `SO_PEERCRED` here, or is there a gap?**

## B2. macOS (second) — possibly without sudo

macOS offers what Linux does not:

- **Keychain ACLs** bind a secret to a specific *signed binary*. Another program running
  as the same user cannot read it.
- **Hardened runtime** blocks `task_for_pid` against signed processes, so reading the
  daemon's memory is genuinely hard rather than trivial.
- Over a Mach port, the daemon can obtain the caller's **audit token and verify its code
  signature** — "which program is this", not merely "which user".

So the strong claim may be reachable on macOS **without a privileged install**, trading
sudo for an Apple Developer account, notarisation and a signed release pipeline.

**Reviewer: is signing + Keychain ACL + hardened runtime genuinely comparable to uid
separation, or does it just raise the bar?**

## B3. Windows (last)

Service account via the SCM (requires administrator); named pipes with security
descriptors; **Authenticode verification of the connecting process**; DPAPI for binding
secrets to a user or machine.

## B4. The asymmetry

The platform where a privileged install is unavoidable (Linux) is the platform with the
weakest peer check. 1Password lands in the same place: their macOS and Windows checks
verify code signatures; their Linux check is group membership.

**Reviewer: is "macOS strong via signing, Linux strong via sudo" a coherent product
position, or does a split guarantee confuse customers into assuming the weaker one?**

---

# Sequencing

1. Part A local store + alerting + off switch  ← module written, rest proposed
2. Part B Linux
3. Migration: fresh key hierarchy, re-wrap to a device key, rotate exposed upstream
   credentials (breaking; affordable now at one active user)
4. macOS
5. Windows

# Specific questions

1. A4 — relay-but-not-store, or tell-them-nothing?
2. B1a — is the token equivalent to `SO_PEERCRED`, or is there a gap?
3. Does keeping fact-of-call server-side while destination goes local actually buy
   privacy, or is the correlation enough to reconstruct the profile anyway?
4. Is the A3 caveat (agent can edit its own local record pre-split) acceptable to ship,
   given it is documented?
5. B2 — is macOS signing genuinely comparable to uid separation?
6. What breaks first when a second customer arrives, given the local store is per-machine
   and one uid is one principal?
7. Anything in this plan that is the wrong shape, not merely incomplete.
