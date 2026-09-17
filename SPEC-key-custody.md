# SPEC — key custody: the broker stops handing out the vault key

Phase 4 gave the broker its own uid. It did not stop the broker handing the agent the
key. This spec closes that, and closes the two delivery holes that make the key reachable
before the broker ever holds it.

Spans two repos. `wundervault-mcp` (the broker and the MCP server) and `burnbox` (the
dashboard, the vault API, the setup flow). An acceptance check that says "anywhere" is
checked in BOTH.

---

## 0. The three defects

**D-A. Repair publishes the vault credential to the agent.**
`burnbox/app/static/js/dashboard.js:5137` — repair calls `_showAgentCreatedModal(data,
passphrase, {rekeyed:true})`, which renders "Send this message to the agent:" over
`_buildOnboardMsg()` (`:5221`). That message embeds the full setup URL — path token AND
`#passphrase` — twice, inside shell commands the agent is told to run. The link decrypts
to `encryption_key` (`:5097`), which unwraps `vault_key_for_agent` (`:5101`), which
decrypts every entry in that agent's vault.

This violates acceptance check 22 of `SPEC-uid-split.md` — "No instruction anywhere tells
a user to pass the setup link as an argument." Round 13 finding F2 fixed the CLI side; the
dashboard was in the other repo and was never checked.

Worse, the message orders the steps so the pre-split path is guaranteed: the agent runs
`onboard.py` at step 2, BEFORE step 3 installs the broker, so `/run/wundervault/mgmt/agent.sock`
does not exist, `onboard.py:452` takes the "No secret broker on this machine" branch, and
the agent decrypts the blob and files `api_key` + `encryption_key` in its own home as its
own uid. The link is then burned, so step 4's `--enrol` gets a spent token.

**D-B. The setup link is a bearer credential, so any courier sees it.**
Even with D-A fixed, the link has to travel browser → terminal. The owner accepts driving
that terminal themselves, which is enough IF the link is the only copy. It is not enough
as a design: `onboard.py:320` takes it from `sys.argv[1]`, and anything that ever puts it
in a command line, a chat log, or a shell history hands over the vault key.

**D-C. The broker hands `enc_key` to the agent on request.**
`src/agent.ts:449-456` — the per-agent socket, on a valid token, replies with
`{api_key, enc_key, vault_url}`. `src/server.ts:143` files it as `agent_encryption_key`;
`:469-470` builds `AgentVaultAPI(api_key, encKey, url)`; `src/api-client.ts:219` calls
`decryptVaultKey(encKey, vault_key_for_agent)`. The MCP server runs as the AGENT's uid, so
`vault_key` lives in the agent's memory, derived by the agent's own code.

The authorising token is `~/.wundervault/agents/<name>.token`, mode 0600, owned by the
agent's uid — it must be readable by the agent, that is how the MCP server authenticates.
The socket is 0666 (`agent.ts:475`), world-connectable by design. So obtaining the whole
vault needs no exploit: read your own token, connect, receive `enc_key`.

`entry_mode` does not stand in the way. `src/types.ts:49` says so — "set server-side,
**enforced client-side**" — and every check (`server.ts:497, 572, 625, 852, 974`) runs in
the agent's process. `SPEC-tiered-broker.md` claims for tier 1 that "the key never reaches
the agent"; `performOperation` is imported at `server.ts:23` and runs in the agent's
process, so that claim is false as built.

`PLAN-local-shape-and-uid-split.md` sequencing step 3 called for "fresh key hierarchy,
**re-wrap to a device key**, rotate exposed upstream credentials". Phase 5 built the first
and the third. `SPEC-phase5-rekey.md` never mentions a device key and has no out-of-scope
section recording the omission. Part 2 below is that missing piece.

---

## 1. Part 1 — repair and create stop addressing the agent

- 1.1 `_buildOnboardMsg` is **deleted**, not edited. There is no agent-addressed message
  for the Linux path.
- 1.2 The repair modal and the create modal render, for Linux: the broker delivery block
  (Part 2) when the account has at least one paired broker, otherwise the setup link as a
  bare copy field plus the instruction to run `wundervault-agent --enrol` and paste it at
  the prompt.
- 1.3 A setup link NEVER appears inside a shell command, in either repo, in any template,
  string, docs page or test fixture.
- 1.4 macOS and Windows keep an agent-addressed install message, because there is no
  broker on those platforms and the agent legitimately holds its own credentials. That
  message states plainly that the credentials are held by a process running as the same
  user as the agent. It still must not put the setup link in a command line: the link is
  a separate copy field and `onboard.py` reads it from stdin.
- 1.5 `onboard.py` stops accepting the setup URL as `sys.argv[1]`. It reads the link from
  stdin, exactly as `wundervault-agent --enrol` does. `--dry-run` needs no link at all.
  A link supplied in argv is refused with a message saying why.

## 2. Part 2 — the broker gets a keypair, and the credential travels wrapped to it

The bearer link stops being how the credential reaches a Linux broker.

- 2.1 `install-daemon.sh` generates a **P-256 ECDH** keypair in `/var/lib/wundervault`,
  mode 0600, owned by the `wundervault` account, sealed by the same `systemd-creds` path
  as the store key. P-256 because WebCrypto supports it everywhere; X25519 does not need
  vendoring but is not universal in browsers, and vendoring a curve into the page that
  handles passphrases is the thing `PROVENANCE.md` exists to avoid.
- 2.2 The private key never leaves the broker's uid and is never written anywhere else,
  never logged, and never returned by any socket operation.
- 2.3 `sudo wundervault-agent --pair` POSTs the PUBLIC key to `POST /api/broker/pair-request`
  (unauthenticated, rate-limited, no account context) and prints two things: a **pairing
  code** and a **fingerprint**.
- 2.4 The fingerprint is `SHA-256(SPKI public key)`, first 10 bytes, rendered as five
  hyphenated groups of Crockford base32. It is derived identically in the broker and in
  the browser, from the key bytes, never carried as a field.
- 2.5 In the dashboard the owner enters the pairing code, the page shows the fingerprint it
  computed from the fetched public key, and the owner confirms it matches the terminal.
  Only on confirm is the public key bound to the account, with a label the owner types.
- 2.6 Everything moved by hand in 2.3-2.5 is non-secret. A pairing code confers nothing
  but the right to read a public key. An attacker who reads the whole terminal and the
  whole screen learns a public key and a fingerprint.
- 2.7 Create-agent and repair-agent, when a broker is chosen, ALSO produce
  `broker_blob`: ephemeral-P-256-ECDH → HKDF-SHA256 → AES-256-GCM over the same
  `{api_key, api_key_hmac, encryption_key}` payload the passphrase blob carries. Layout:
  `ephemeral SPKI (DER, variable length) || nonce (12B) || ciphertext||tag`.

  **Corrected from "65B".** 65 bytes is the RAW P-256 point; `exportKey('spki', ...)`
  emits a DER SubjectPublicKeyInfo, which is 91 bytes for P-256 and is not fixed by the
  standard. A reader that split at a hardcoded offset would land inside the key, fail the
  GCM tag, and report a corrupt credential — so the length is read from the DER header at
  both ends, and a length form this build does not know is refused rather than guessed.

  The server stores it opaquely and can no more read it than it can read the passphrase
  blob.
- 2.8 The dashboard returns a **claim code** for a broker delivery, not a setup URL. The
  claim code is not a credential: `GET /api/setup/agent/{token}/broker-blob` returns a blob
  only the holder of that broker's private key can open.
- 2.9 `wundervault-agent --enrol` accepts EITHER a claim code (broker path) or a setup link
  (link path), both read from stdin. With a claim code it fetches the broker blob, decrypts
  with its private key, files the profile, and burns the token.
- 2.10 **On Linux, once a broker is paired, the link path for that account's agents is
  refused by the broker** — `enrol` with a setup link returns an error naming the paired
  broker. Otherwise the weaker path stays available as a downgrade.
- 2.11 A broker can be unpaired from the dashboard. Unpairing does not revoke any agent;
  it only stops new deliveries to that key.
- 2.12 Pairing is once per machine, not once per repair. A repair on a paired machine needs
  the owner to move a claim code, and nothing secret, from the browser to the terminal.

## 3. Part 3 — the socket serves operations, not credentials

- 3.1 The per-agent socket **no longer returns `api_key` or `enc_key`**, to anyone, ever.
  The credential-dispensing reply at `agent.ts:449-456` is removed. A request in the old
  shape gets `{"error":"unsupported","upgrade":true}` and a message naming the version to
  install. It is not deprecated, kept behind a flag, or available under any env var.
- 3.2 The socket speaks newline-delimited JSON as today. Every request carries `token` and
  `op`. The token check is unchanged, still constant-time, still first, still with the
  same penalty behaviour.
- 3.3 The request byte cap rises from 4096 to 1 MiB **measured in raw bytes**, to carry an
  HTTP body. The absolute connection deadline rises from 10s to **180s**.

  **Corrected from 120s.** A tier-2 call waits up to 90s for a human, then re-asks the
  server and performs a request with its own 30s timeout, so 120s would cut off the one
  path that exists to survive a person taking their time.

  Both timers remain, with different jobs: the inactivity timer bounds a caller who never
  finishes SENDING, and is **disarmed the moment a complete request has been read** —
  during an operation there is no traffic by design, so leaving it armed destroyed the
  socket mid-flight. The absolute deadline is what bounds the connection thereafter. No
  per-connection ceiling is introduced (see the `maxConnections` note).
- 3.4 Operations:
  - `list_entries` → entry ids, names, tiers. No key material.
  - `profile_flags` → account flags the agent needs (`allow_env_inject`). No key material,
    and no secret access, so it costs no access-log row.
  - `get_entry {entry_id, purpose}` → plaintext, name, exec config, and the directive
    integrity verdict computed IN THE BROKER. **Refused unless the entry's mode allows
    LEGACY_EXEC.** There is deliberately no separate metadata operation: each RPC performs
    exactly ONE `getSecret`, so the access log and the tier-2 gate see precisely what they
    see today. A metadata probe would add a row per call and could trip tier 2 twice.
  - `call {entry_id, purpose, request:{origin, method, path, body?, query?}}` → the broker
    performs the HTTP operation and returns the scrubbed response. The plaintext does not
    cross the socket.
  - `ssh_agent_open {entry_id, purpose}` → the broker loads the key and serves the
    ssh-agent protocol on a socket it owns; returns the path. `ssh_agent_close {session_id}`.
    The private key does not cross the socket.
  - `settings` → the account's MCP settings. No key material.
- 3.4a A reply the broker cannot serialise within a bound is refused rather than sent, and
  concurrent `ssh_agent_open` sessions per agent are capped. Neither is a confidentiality
  control; both stop an authenticated caller turning a legitimate operation into a
  resource it can accumulate.
- 3.5 `entry_mode` is enforced **in the broker**, which is the only process where
  enforcement means anything. The client-side checks may remain as a fast path for a
  better error message, but the broker's decision is the one that governs, and removing
  every client-side check must not change what an agent can obtain.
- 3.6 `performOperation` (`http-broker.ts`) and the ssh-agent protocol server
  (`ssh-agent.ts`) run in the broker process. The SSRF guards, the pinned lookup, the
  private-origin allowlist and the secret scrubbing move with them, unchanged in behaviour.
- 3.7 The broker NEVER spawns an agent-supplied command. `vault_exec`, `vault_rsync` and
  `vault_ssh_exec` continue to run in the agent's process, on plaintext obtained through
  `get_entry` — which is LEGACY_EXEC by definition — or on an ssh-agent socket. A design
  where the broker runs the agent's command would hand the agent code execution as the
  broker's uid, which is `/var/lib/wundervault`.
- 3.8 `recordDestination` runs in the broker. Today it is called at `server.ts:703` in the
  agent's process against `/var/lib/wundervault/network.json`, which that uid cannot write:
  the write either fails the call or fails silently, and either way D3 of `SPEC-uid-split.md`
  — "the party being audited owned the evidence" — is not satisfied as built. Moving
  `call` into the broker fixes it as a side effect. Verify which of the two it is today and
  state it.
- 3.9 The tier-2 wait, the unanswered-escalation report, and `checkOperation` run in the
  broker, because they are part of performing the operation.
- 3.10 `session_lock` / single-instance lock behaviour is unchanged in effect. If any part
  of it gates access to secrets, it moves to the broker; if it only guards the MCP
  process's own lifecycle, it stays.
- 3.11 Nothing in the MCP process imports `decryptVaultKey`, `decryptSecretContent`, or
  `loadEncryptionKey` after this change. Verified by grep, as a test.

## 4. Non-goals

- Server-side `entry_mode` enforcement (phase 6). Unchanged: the server will still serve
  `vault_key_for_agent` to a holder of the api_key. After this spec the broker is the only
  holder, which is why phase 6 is a backstop rather than the fix.
- macOS (phase 7) and Windows (phase 8). Both keep the pre-split shape and say so.
- Hands-off enrolment. The broker could poll for pending enrolments once paired, removing
  the claim-code step entirely. The owner has said driving the terminal is acceptable, so
  this is deliberately not built.
- Any change to what LEGACY_EXEC means. An entry in that mode still hands its plaintext to
  the agent; that is the mode's definition and the exposure report's subject.
- Retracting anything an agent has already read.

## 5. Honest limits this spec does NOT close, and must not claim to

- **One uid is one principal.** All seven agents share the owner's uid, so any agent can
  read any other agent's token file and impersonate it to the broker. `SO_PEERCRED` cannot
  separate them. This spec narrows what an impersonator gets — one entry at a time, mode-
  gated, logged — but it does not make agent A and agent B distinguishable.
- **The ssh-agent socket is world-connectable** for the same reason every broker socket is.
  A random path and a short lifetime bound the exposure; they do not eliminate it. It is
  still strictly better than today, where the agent holds the private key itself.
- **A LEGACY_EXEC entry is still handed over in full**, and anything an agent has read it
  keeps. The exposure report remains the only remedy.
- **Pairing trusts the terminal once.** An agent driving the terminal at pairing time could
  print a fingerprint for a key it controls. Pairing is the owner's job, in a session no
  agent is driving, once per machine. This is the same trust the `sudo` install already
  assumes, and it replaces a per-repair exposure with a per-machine one.
- **The pairing code is not a secret, so the ceremony needs TWO human checks.** Anyone who
  reads the code can look it up and confirm it under their own account — the key
  fingerprint cannot catch that, because the key really is this machine's, which is what
  makes the attack work. So `--pair` also prints which account confirmed and asks the
  person at the terminal whether it is theirs. Claiming the code for the first account
  that touches it makes an attacker have to be first; the account question is what makes
  being first useless.
- **A cloned machine clones its broker.** The private key and `paired.json` are files, so
  imaging a host duplicates the identity and both copies can open future claims sealed to
  that fingerprint. Binding to a TPM would close it and is the same unbuilt work the
  store key's sealing already tracks.

---

## 6. Acceptance checks

Numbered, each true or false, each checked in both repos where the wording says "anywhere".

**Part 1**
1. `_buildOnboardMsg` does not exist in `burnbox`.
2. No string in either repo places a setup link inside a shell command. Grep-enforced by a
   test that fails on a planted violation.
3. The repair modal contains no text addressed to an agent on the Linux path.
4. `onboard.py` refuses a setup URL passed in argv, with a message saying to pipe it or
   paste it at the prompt.
5. `onboard.py --dry-run` works with no link supplied at all.
6. The macOS and Windows message still exists, still states the same-uid limit, and still
   carries no link in a command.

**Part 2**
7. A fresh install produces a P-256 keypair with the private key mode 0600 owned by
   `wundervault`, and the file is absent from any tar, backup manifest or log this repo
   writes.
8. `--pair` prints a fingerprint that the browser independently recomputes to the same
   value from the fetched public key.
9. A pairing code is single-use and expires in 15 minutes.
10. A pairing code that is read by a third party yields only a public key: there is no
    endpoint where a pairing code returns anything secret.
11. A `broker_blob` produced in the browser decrypts in the broker to exactly the payload
    the passphrase blob carries, byte for byte.
12. A `broker_blob` cannot be decrypted with a different broker's private key, and a
    tampered blob fails the GCM tag rather than returning garbage.
13. The server stores `broker_blob` without being able to read it: no server-side code path
    decrypts it, and a test asserts the stored bytes are opaque.
14. With a broker paired, `enrol` fed a setup link for that account is refused and names
    the paired broker.
15. With no broker paired, the link path still works unchanged.
16. Unpairing a broker stops new deliveries and revokes no agent.

**Part 3**
17. The per-agent socket never emits `api_key` or `enc_key`. A test asserts the reply to
    every operation, and to a malformed one, contains neither field.
18. An old-shape `{token}` request returns an upgrade error, not credentials.
19. `get_entry` on a BROKER_SSH_AGENT or BROKER_HTTP entry is refused BY THE BROKER, with
    every client-side mode check deleted in the test build.
19a. Each RPC causes exactly one `getSecret` against the vault API — the access log and the
    tier-2 gate behave identically to today. Asserted against a recording fake.
20. `call` performs the HTTP operation with the plaintext never appearing in any socket
    reply, verified by asserting on the raw bytes written to the socket.
21. `ssh_agent_open` lets `ssh` authenticate without the private key crossing the socket,
    and the session is closed on `ssh_agent_close` and on a timeout.
22. No file under `src/` other than the broker's own modules imports `decryptVaultKey`,
    `decryptSecretContent` or `loadEncryptionKey`. Grep test.
23. The SSRF guard, the pinned lookup, the private-origin allowlist and the scrubbing
    behave identically after the move — the existing `http-broker` tests pass unchanged
    against the broker-hosted path.
24. `recordDestination` writes `/var/lib/wundervault/network.json` as the broker, and an
    agent cannot write that file.
25. A request larger than 1 MiB — measured in BYTES, not UTF-16 code units — is refused,
    and a connection held open past 180s is closed, while a legitimate 30s upstream call
    and a 90s tier-2 wait both complete. The inactivity timer must not fire during an
    operation.
26. A wrong token still costs the failing caller the exponential penalty, and a valid token
    is still served during another caller's flood.
27. The seven live agents' flow — repair, pair, claim, enrol, then every tool — works
    end to end in the rehearsal container.
28. `SPEC-tiered-broker.md`'s "the key never reaches the agent" is true for tier 1 after
    this change, or the sentence is corrected.
