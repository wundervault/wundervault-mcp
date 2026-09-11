# Open: the single-instance lock is only verified on Linux

**Opened 2026-09-11 while adding CI for 1.7.2. Pre-existing; not introduced by that
release.** The audited commit had no CI at all, so no platform but Linux was ever run.

## What the two implementations are

`src/lock.ts` picks by platform (`listenOptions`, line ~135):

- **Linux** — binds an abstract socket, `\0wundervault-mcp-<key>`. Atomic to claim,
  released by the kernel when the process dies, no filesystem entry to delete. This is
  what the daemon runs on and what four rounds of review in `.buildreview/` hardened.
- **Everything else** — binds `127.0.0.1` on one of `PORT_CANDIDATES = 8` ports derived
  from `sha256(uid + agent name)` (`addressPorts`, line ~121).

## The gap

`acquireCredential` walks the candidates. When a port is in use it calls `askHolder`,
and **if nobody answers our protocol it moves to the next candidate** (line ~332). The
reasoning is sound in isolation — a stranger on a loopback port is not our holder — but
it means the claim is spread across 8 addresses rather than being one address that is
either held or not.

macOS CI fails two assertions that pass on Linux:

- `acquiring the credential > refuses a second claim while the first is held` —
  the second in-process claim returns `ok: true`.
- `holder identity > falls back to the lock file when nobody answers` —
  `whoHolds().source` is `'holder'` where `'lock-file'` was expected.

Both point the same way: on the port path, a claim that should have been recognised as
ours was not, and the walk carried on to a free port. `procStart()` also returns `null`
off Linux (line ~209), so the PID-recycling check that backs the compat file is inert
there too.

The lock suite is therefore gated to Linux (`LINUX_ONLY` in `test/lock.test.ts`) rather
than asserting semantics the port path does not implement.

## Why it was not fixed in 1.7.2

No macOS machine to reproduce on. Guessing at a concurrency primitive from CI logs is
how the PID-file version of this lock got its bugs in the first place.

## What to do

1. Reproduce on a real macOS box — `npm test` with the gate removed.
2. Work out whether `askHolder` fails to recognise our own listener there (likely: check
   the connect/timeout path against a loopback listener in the same process) or whether
   the walk itself is wrong.
3. The likely correct answer is to stop walking. One derived port, held or not, matches
   the Linux semantics; a stranger occupying it should be a hard error the operator can
   see, not a silent move to another address that quietly permits a second instance.
4. Decide what `README.md` should claim. It currently says Linux and macOS are supported
   platforms — true for secret delivery, not currently true for single-instance locking.

## Impact today

Low for the shipped product: the daemon runs on Linux. It matters for a developer running
the MCP server on a Mac, where two agents could both believe they hold the credential.

Related: `feedback_wundervault_mcp_single_instance`, `reference_vault_agent_lock_is_per_name`.
