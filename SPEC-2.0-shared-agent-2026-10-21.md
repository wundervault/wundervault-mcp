# Copies of one agent share its connection (broker 2.0, 2026-10-21)

## Why

The owner's Telegram onboarding test: OpenClaw 2026.10.5 with an OpenAI model runs chats on the
Codex app-server, which starts its own `wundervault-mcp` beside the gateway's. Both started in
the same second for agent "Bearclaw"; the gateway's copy took the claim and the chat's copy was
refused ("held by another MCP instance"), so the chat had no vault tools. Claude Code subagents,
several chats, and any host that starts one MCP process per session hit the same wall.

Owner decision 2026-10-21: copies of the same agent, under the same account on the same computer,
share. A copy under a different agent name, or a holder that can't share, is still refused.

## Why sharing is safe in 2.0

The single-instance rule came from 1.x, where the MCP process held the agent's credential. In 2.0
`wundervault-mcp` holds nothing: BrokerClient opens one connection per tool call to the broker's
agent socket with the token from `~/.wundervault/agents/<name>.token` ("one request, one reply,
one connection. Deliberately not pooled"). The broker decrypts, decides and logs per call, by
agent name. A second copy under the same uid can already do everything a first copy can: read
the same token and talk to the socket directly, without `wundervault-mcp` at all (the skill says
as much: "Agents that run under the same user account can read each other's token files"). So
the lock is no longer a boundary between same-account copies of one agent. What it still does,
and must keep doing: stop a 1.x copy (which holds a real credential in-process) starting beside
a 2.0 one, via the compatibility file; and never let two DIFFERENT agents' claims collide.

## Requirements

- **S1** The holder's identity reply says it can share (`shares: 1`) and which account it runs
  under, as a 12-hex digest of the principal (`account`), so a same-name holder under another
  account is never shared with (round 1, B2). No secret and no command line is added to it.
- **S2** `acquireCredential(version, { share: true })` against a live holder of the SAME agent
  name that says it can share returns `{ ok: true, role: 'shared', holder }`. The sharing copy
  binds nothing, writes no compatibility file, and serves the vault tools normally.
- **S3** Refused exactly as today: a holder that does not say it can share (older 2.0 builds,
  frozen copies), a holder of a different agent name (collision), a non-wundervault occupant of
  the address, a live 1.x holder known only from the compatibility file, and any claim made
  without `share: true` (so the exclusive meaning of the function is unchanged for callers and
  tests that rely on it).
- **S4** A holder that bound its address but has not yet started answering (two copies started
  in the same second, as on the owner's Mac) is asked again within ONE deadline of about 1.5 s,
  answers and pauses included, before it is treated as a stranger, so a simultaneous start
  shares instead of refusing (round 1, F2). If the address frees up while it is being asked,
  the claim is retried as an ordinary claim, not refused (round 1, F1).
- **S5** While a sharing copy runs, it tries every 5 s to take the claim when the address is free,
  so after the holder exits a 2.0 copy soon holds the address and the compatibility file again
  (older copies keep standing down). Taking it over is the ordinary exclusive claim.
- **S6** `wundervault-mcp` uses `share: true`. A sharing copy logs one line to stderr naming the
  holder's PID. The held-notice for a refused copy says the holder can't share or is a different
  agent, and how to fix it.
- **S8** A sharing copy whose take-over is refused by something that can't share (a 1.x copy
  that started in the gap, an older 2.0 copy) keeps serving: in 2.0 the broker is the boundary,
  and a 1.x copy of this agent holds a credential the enrol that 2.0 requires already retired.
  It says so once on stderr and keeps trying (round 2, B1).
- **S9** A running vault tool whose broker answers 'unauthorized' re-reads the agent's token
  file once and retries if the token changed (a re-enrol after Repair); never re-sends an
  unchanged token, never overrides WUNDERVAULT_AGENT_TOKEN (round 2, B2).
- **S7** Unchanged: the per-uid, per-agent address derivation; release on exit; never removing a
  compatibility file another incarnation wrote; the port strategy's single address.

## Acceptance checks

1. Claim, then a `share: true` claim of the same agent: the second is ok, role 'shared', and
   names the first's PID; the first still holds the address and the file.
2. ...a claim WITHOUT `share: true` is still refused (the existing exclusion tests pass unchanged).
3. A holder whose banner lacks `shares` refuses a `share: true` claim.
4. A holder of a different agent name (banner with `shares`) refuses it, as a collision.
5. A holder that starts answering 400 ms late: a `share: true` claim shares, not "stranger".
6. A live 1.x holder known from the compatibility file: refused (the existing test).
7. The sharing copy takes over within one interval after the holder exits, and the compatibility
   file then names it.
8. Checks 1, 3, 4 and 7 also on the port strategy.
9. The banner still carries no secret: the holder keys are exactly agent, pid, since, source,
   shares; a same-name holder with another account digest is not shared with.
9a. A permanently silent occupant is refused in under 2.5 s; an occupant that leaves while being
   asked yields an ordinary claim (role 'holder').
9b. Two real processes: a sharing process exiting leaves the holder's file byte-for-byte; a
   sharing process takes over (file names it) after the holder is killed.
9c. An occupant leaving during the LAST identity attempt yields an ordinary claim.
9d. Real broker: after re-registering the agent with a new token and writing it to the file, an
   existing BrokerClient's next call succeeds; a wrong token still in the file stays refused.
10. Each of checks 1, 3, 4, 5, 7, 9a-9d fails when its guard is removed (mutation).
11. Full suite: no new failures.
12. On the owner's Mac, after the new tarball is installed and the OpenClaw runtime switch is put
    back to the Codex default, Bearclaw has vault tools in a fresh chat while the gateway's copy
    also runs (the real two-host check).
