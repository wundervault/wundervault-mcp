# Handoff — phase 6: the server stops taking the api_key's word for it

Written 2026-09-17, after `HANDOFF-2026-09-17-key-custody.md` the same day. Spec is
`SPEC-phase6-server-enforcement.md` (burnbox); the client half is in `wundervault-mcp`.

**NOTHING IS DEPLOYED.** Committed this time — `burnbox 65fcf40`, `wundervault-mcp
33fe853` — and joining the same cutover as everything from 16-17 September.

---

## 1. What this closes

Key custody made the broker the only holder of an agent's `api_key` and `enc_key`. The
server did not know that. It authenticated the bearer credential and served whatever the
holder asked for: `vault_key_for_agent` on `/agent/profile`, and the ciphertext of an
entry in a broker mode — precisely the ciphertext the mode exists to keep out of the
agent's process. `agent.py` said so plainly: "Server-side enforcement needs the daemon to
hold an identity of its own."

The key-custody build gave it one. Phase 6 makes the server use it.

**It is a backstop, not the fix.** The fix was moving the credential into the broker. This
stops a copy of that credential from being sufficient on its own — a restored backup, a
support copy, a future bug. It does nothing against a compromised broker, which holds the
private key by definition.

## 2. What was built

**Every request from a broker-held agent is signed.** Detached ECDSA P-256 over
`wv-broker-req-v1 \n METHOD \n raw path \n query \n timestamp \n nonce \n sha256(body)`,
in `X-Broker-Timestamp`, `X-Broker-Nonce`, `X-Broker-Signature`. Verified in
`app/broker_auth.py`, called from `_get_agent_from_request` — the one door every agent
endpoint goes through, so an endpoint added later inherits the check.

**Which key verifies is decided by the agent's row, not by anything the caller says.**
There is no fingerprint header. Every `BrokerKey` for the account whose fingerprint —
recomputed from the stored key bytes — matches `agent.broker_fingerprint` is tried.

**A broker-mode entry is served only to a caller that signed.** An agent with no paired
broker gets `403 broker_mode_entry`, because there is nothing on that machine that could
use such a secret without handing over the plaintext.

**Replays are refused.** `broker_request_nonces`, keyed `(agent_id, nonce)`, expiry keyed
to the SIGNED timestamp, swept on about one write in 32.

**The client half** signs through one function in `api-client.ts`, from the parsed URL so
both sides agree on the encoded form, with the signer injected into `BrokerOps` and read
from `/var/lib/wundervault/broker-key.pem`.

## 3. The hole found on the way, which had nothing to do with phase 6

`/agent/vault/secrets/{id}/request-access` and `.../access-status` authenticated on
`_get_agent_id`, which read the agent id out of the `Authorization` header and **verified
nothing** — no HMAC, no credential check at all. Any caller who knew an agent's id could
raise approval requests in its name (mailing and Telegramming the owner) and poll for the
ciphertext of an approved one.

Neither endpoint has a caller — not the MCP client, not the dashboard, not a test — which
is why it survived. Both are behind `_get_agent_from_request` now, and `_get_agent_id` is
deleted rather than left dormant: a helper whose name reads like authentication, sitting
next to one that is, is a trap for whoever wires up the next endpoint in a hurry.

**Worth a look before the cutover: are those two endpoints wanted at all?** The tier-2
flow superseded them.

## 4. Deploy order — one step added, and it is not optional

1. **Re-sign `onboard.py`.** Still step one. Key vaulted as `OnboardSigningKey`.
2. **Publish the npm package.**
3. **Deploy burnbox.** Run `migrations/add_escrow_kdf.py`, `add_rekeyed_at.py`,
   `add_broker_custody.py` and **`add_broker_nonces.py`**. Not 12:00-13:00 PT on a weekday.
4. **Install the broker**, then `sudo wundervault-agent --pair` ONCE.
5. **Migrate ONE agent, then STOP AND CHECK THE EDGE.** The signature covers the raw path
   from `scope["raw_path"]`. If Cloudflare normalises percent escapes, repeated slashes or
   dot segments before forwarding, the broker signs one string and the server verifies
   another, and every signed request fails. Nothing in use today needs encoding — entry
   ids are `token_urlsafe` — so this is untested rather than known-broken. **Confirm one
   signed request end to end through the edge before migrating the other six.**
6. **Migrate the remaining six**, one at a time.
7. **Open WHAT TO ROTATE and work the list.**

## 5. What this does NOT close

- **A compromised broker.** It holds the private key. This authenticates the machine, not
  the state of the software on it.
- **One uid is one principal.** Unchanged.
- **The unsigned path is still there, and it is where every agent starts.** Any agent whose
  `broker_fingerprint` is NULL authenticates exactly as before — every agent on macOS and
  Windows until phases 7 and 8, and every Linux agent until it is repaired. It cannot put
  itself back on that path (the column is written by the owner's repair), but the path is
  real and `/limitations` and `README-AGENTS.md` say so.
- **A malformed body is refused before authentication runs**, so no refusal is logged.
  FastAPI validates a declared body before it solves dependencies. It cannot return data
  and, at 422 time, no credential has been verified — so there is no actor to attribute.
  The refusal log is a record of authenticated probing, not of all probing.
- **A retry is indistinguishable from a replay.** An edge retrying a byte-identical signed
  POST after an upstream disconnect is refused, after the first attempt already had its
  effect. Idempotency keys are the answer and are not built.
- **Clock jumps and database restores** can both reopen a replay window. Bounded by 120
  seconds, written into the spec.
- **Denial rows have no volume control.** Every refusal writes a durable audit row. Not new
  with phase 6 — `tier2_blocked` and the rest do the same — and worth fixing across all of
  them at once rather than here.

## 6. Things that will bite you

- **`_may_carry_a_signature` decides which paths get their bodies hashed** — anything with
  an `/agent/` segment. An agent endpoint added on some other prefix fails CLOSED: the
  request is refused because the hash is absent. Loud, but you have to know why.
- **The MCP server and the broker ship together.** They already did; phase 6 does not
  change the socket protocol, but the client's signing and the server's verification are
  one mechanism.
- **A new broker against an OLD server still works** — the headers are ignored — so the two
  halves may be deployed in either order. An OLD broker against a NEW server is refused
  with a message naming the upgrade.
- **The nonce table grows if the sweep never runs.** It runs on about one write in 32; at
  any real traffic that is seconds. Skipping a sweep never skips a claim, and a test pins
  it.

## 7. Review log

Three rounds, every finding triaged in `.buildreview/round-2{5,6,7}-triage.json`.

| Round | Verdict | Outcome |
|---|---|---|
| 25 | revise | 6 findings, 3 blind spots — 8 fixed, 1 deferred with a reason |
| 26 | revise | 1 BLOCKER, 2 majors, 2 minors, 3 blind spots — 4 fixed, 1 rejected, 3 deferred |
| 27 | revise | 1 BLOCKER, 2 blind spots — all 3 fixed, 1 spec note deferred |

**The blocker in round 26 was a real replay hole.** The freshness window is symmetric, so a
signature is acceptable 120 seconds either side of its own timestamp — but the nonce
expired 120 seconds after WE received it. Submit a request signed 119 seconds in the
future, it is accepted, its nonce is swept 120 seconds later, and the byte-identical
request is then two seconds from its own timestamp: still fresh, no longer remembered,
served again. Expiry is now keyed to the signed timestamp.

**The blocker in round 27 is the one worth remembering.** Round 26 asked me to check the
body-size cap before appending the chunk rather than after. I moved the check — and left
the append. The join still allocated prefix+chunk, a second copy of a body it had just
decided was too big to hold. And the test I shipped with that fix asserted the resulting
hash and the downstream body length, **both of which are true either way**. It could not
fail. What distinguishes the two is the size of the first message handed to the
application, which is what the test asserts now.

**What I rejected, with evidence:**
- *Round 26, F2:* malformed bodies get a 422 before the broker check, so no refusal is
  logged. Real behaviour, not the defect described: no credential has been verified at
  that point, so logging it would invent an actor, and the path cannot return data.
  Written into the honest limits instead.
- *Round 25, F1:* the nonce is claimed after signature verification rather than before.
  The spec was wrong, not the code — claiming first would let anyone who can observe a
  nonce spend it on a forged request and have the real broker's retry refused as a replay.
  The spec now states the order as built.

**Every fix was checked by sabotage, not by a green suite.** Blanking `enforce()` fails 15
tests; disabling the `entry_mode` condition fails 2; reverting the nonce expiry fails 2;
restoring the round-26 append fails the one test that catches it.
