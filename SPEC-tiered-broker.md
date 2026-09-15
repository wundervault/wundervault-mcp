# SPEC — phase 3.5: tiered brokering

Replaces the "every secret needs a typed adapter" model, which taxed every future secret
and would have left most entries at `LEGACY_EXEC` forever.

## The correction this is built on

Operation definitions were treated as the mechanism for **safety**. They are the
mechanism for **review**. The agent already knows what to do — the secret's name and the
user's prompt tell it ("get my Cloudflare key and change setting X"). A definition adds
nothing to the agent's capability; it exists so a *human* can see what is about to happen
and consent. Requiring one everywhere taxes precisely the cases where nobody was going to
look.

So the effort goes where the value is, using the tier that already exists:

- **Tier 1** — brokered, no definition, no pre-approval. The key never reaches the agent;
  the log records where it went.
- **Tier 2** — brokered, and the first attempt is refused into the existing approval
  flow. The owner's approval *becomes* the definition.

There is no key-shape detection anywhere: the server cannot read plaintext, and doing it
in the browser would put "this is an OpenAI key" on the server as metadata for no gain.
The agent supplies the destination because it is the party that knows it.

## J. The call

    vault_call(entry_id, purpose, request: { origin, method, path, body?, query? })

`origin` is `{scheme, host, port}`. No URL string — the daemon builds the target from
typed parts so there is nothing to smuggle through parsing.

### J1. Tier 1 — proceed and record
- No definition needed, no approval.
- Perform the request, return the response, scrub the credential from it.
- Write a structured log row (§L).

### J2. Tier 2 — refuse, pend, approve, retry
- First attempt returns a pending request id, exactly as the Tier 2 secret gate does now.
- The pending record carries the **exact** origin, method, path and a body hash, so the
  owner approves a specific operation rather than a category.
- The owner's approval is stored as the definition for that (agent, entry, operation).
- Approvals are single-use or a bounded time window, as today; a window does NOT widen
  to other origins or paths.
- A later call that differs in origin, method or path pends again. It does not reuse an
  approval granted for something else.

## K. What still applies at both tiers

- **SSRF**: agent-chosen destinations go through the same filter. No loopback, RFC1918,
  link-local, CGNAT, ULA, multicast, cloud metadata, in any IPv6 spelling.
- **https only**, exact origin, real certificate validation, IP pinned after the check.
- **Redirects denied** — never followed with the credential attached, target not echoed.
- **Credential never returned**: scrubbed from the body, keys and values.
- **Size and time caps**, wire and decompressed.
- The credential binding (which header, what template) still comes from the entry, not
  from the agent — an agent may choose *where to send*, never *how the secret is framed*.

## L. The log becomes a control, not a record

At Tier 1 the log is the only thing telling the owner where a key went, so it stops being
free text:

    origin, method, path, response_status, bytes, agent_id, entry_id, at

`purpose` stays, but as agent-written prose beside the structured facts, never instead of
them.

## Acceptance checks

1. A Tier 1 entry with no definition brokers successfully; the credential never appears
   in the result.
2. That call writes a structured row carrying origin, method, path and status.
3. A Tier 2 entry's first call is refused with a pending request id, and no request is
   sent upstream.
4. The pending record shows the exact origin, method and path the agent asked for.
5. After approval, the identical call succeeds.
6. After approval, a call with a DIFFERENT path pends again rather than reusing it.
7. After approval, a call with a different origin pends again.
8. A single-use approval cannot be replayed.
9. An agent-chosen origin resolving to an internal address is refused at both tiers.
10. An agent cannot override the credential binding.
11. A redirect is not followed and its target is not echoed, at both tiers.
12. `LEGACY_EXEC` entries are unaffected: `vault_exec` still works, `vault_call` refuses.

## Out of scope
- Typed adapters with response allowlists. They remain available and are strictly
  stronger, but are now an optimisation for high-traffic operations rather than a
  prerequisite for using a secret at all.
- Path parameters, streaming, OAuth refresh, multipart.
