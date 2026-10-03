# SPEC — vault_call works with real APIs: replies, headers, bodies

**Written 2026-10-03.** Found while answering the owner's question "can the new update
handle API keys?". Ships in the one 1.0 / MCP 2.0 cutover.

## The defect

`performOperation` (src/http-broker.ts) parsed every reply as JSON and, when that failed,
returned `ok:false` with "Upstream returned a body this operation could not parse as JSON."
It did this **whatever the status**. Measured against a real https server:

- `DELETE` → 204, no body → `ok:false`
- `POST` → 200 `text/plain` "OK done" → `ok:false`
- `GET` → 200 `text/csv` → `ok:false`

The request had already been sent and had taken effect. An agent told a POST failed sends
it again: a second email, a second order, a second payment.

## Required behaviour

1. An empty reply body is a valid answer: `ok` follows the status, `body` is `null`.
2. A 2xx reply that is not JSON, on an **agent-described request** (no signed definition,
   `def.response === undefined`): returned as text when it is text, scrubbed of every form
   of the key exactly as JSON is.
3. "Is text": strict UTF-8 decode succeeds, no NUL byte, and the content-type is not
   `image/*`, `audio/*`, `video/*`, `font/*` or `application/octet-stream`. Anything else is
   **described, never returned**: `[N bytes of <content-type>, not text, so not shown]`.
4. A 2xx reply that is not JSON on a **signed definition** (`def.response` present): none of
   it is returned (its allowlist names JSON fields and cannot be applied). `ok:true` — the
   request went through — and the body is a description:
   `[N bytes of <type>, not JSON; this operation returns only named JSON fields, so none of
   the reply is shown]`. (Round 1, B1: `ok:false` here invites a retry of a side effect.)
5. A non-2xx reply is withheld, whatever its type, empty or not: `ok:false`, the status, and
   the existing "not repeated here" message, and **no `body` field at all** — enforced in
   `performOperation`, not left to the caller (round 1, F1; the caller already dropped it).
5a. A description never repeats the upstream's content-type verbatim: it is reduced to a bare
   `type/subtype` (or "unknown type") and scrubbed (round 1, F2).
6. Scrubbing gains encoded spellings of the key, when they differ from it: percent-encoded as
   sent, with lowercase escapes, and form-style (`+` for a space) (round 1, B2), because a
   query-parameter key echoed back in a request line travels encoded.
7. The MCP tool renders the reply for the agent: `null` → `(empty reply)`, a string as
   written (not JSON-escaped), anything else as indented JSON.
8. Nothing else changes: redirects, size caps (wire and decompressed), timeouts, SSRF pinning,
   the allowlist for JSON replies, and the 4xx withholding are untouched.

## B. Headers and bodies the agent writes

Found while answering the same question. An agent-described request (`request`) could carry
no headers and only a JSON body. Measured: GitHub answers **403 "Please make sure your
request has a User-Agent header"** to every such request (Node sends none). Per their docs,
Anthropic requires `anthropic-version`, and Stripe and Twilio take form-encoded bodies.

9. `request.headers` — an object of name → value (absent or `null` = none of the agent's own;
   any other non-object is refused). Checked **in the broker**, before the key is
   decrypted; any refused header refuses the whole call (`BAD_REQUEST`), never dropped:
   - name is an HTTP token, 1–64 chars, lowercased; a name given twice (any case) is refused;
   - refused: the framing set (`host, content-length, transfer-encoding, connection, upgrade,
     te, trailer, proxy-authorization, cookie, set-cookie`) plus `expect, keep-alive,
     accept-encoding, content-encoding`, any `proxy-*`, and **the header that carries this
     entry's key** (binding name, for a header binding);
   - value: a string, printable ASCII or tab, ≤ 1024 chars; at most 20 headers;
   - values are literal: `{secret}` in a value is sent as those characters.
10. The credential is written after the agent's headers, so even a header that escaped the
    check could not replace it.
11. A User-Agent `wundervault-broker/<version>` is sent when none is given (any request).
12. `request.body` as a **string** is sent as written, with the agent's content-type, or
    `text/plain; charset=utf-8` if none. An object/array is JSON as before; the agent may set a
    JSON media type. Signed operations are unchanged (typed args, JSON).
13. Tier 2 approval still matches origin + method + path; it covers whatever headers and body
    the call carries, as it already did for the body. The tool description says so.

## Acceptance checks

1. DELETE → 204 empty returns `{ok:true, status:204, body:null}`; the agent sees `(empty reply)`.
2. A 201 with `content-type: application/json` and an empty body returns `ok:true, body:null`.
3. 200 `text/plain` containing the key returns the text with the key replaced by `[REDACTED]`.
4. 200 `text/csv` returns the CSV unchanged, rendered with real newlines.
5. A query-bound key containing `& / + space`, echoed percent-encoded in an HTML reply, is
   scrubbed; neither the raw nor the encoded key appears.
6. `image/png` bytes, and invalid UTF-8 labelled `text/plain`, are described, not returned.
7. 400 `text/plain` containing the key returns `ok:false`, no body, the withholding message.
8. A signed definition (response allowlist) given 200 `text/plain`: exactly one request is
   sent, `ok:true`, `status:200`, the body is the description, and none of the reply text
   appears anywhere in the result.
9. Each of checks 1–8 fails against the previous code (verified by running the new tests
   with the old `http-broker.ts` and `delivery.ts`).
10. Full MCP suite passes; `tsc --noEmit` clean.
11. JSON 4xx and empty 404 return exactly `{ok:false, status, error}` — no body key.
12. A content-type carrying the key as a parameter, or as the subtype, never reaches the
    description in clear.
13. Through the broker socket: the key's header (any case), each framing header, `proxy-*`,
    a CR/LF value, a duplicate name, a non-object `headers` → `BAD_REQUEST`, no key in reply.
14. On the wire: default UA when none given; the agent's UA and `anthropic-version` arrive;
    the key's header still carries the key when an unchecked `authorization` is passed
    straight to `performOperation`; a form body arrives byte-for-byte with its content-type
    and length; a bare string body is `text/plain`; an object is JSON; `{secret}` in a header
    value arrives literally.
15. Mutation: removing each of — the credential-header check, the default UA, string bodies,
    credential-written-last, 4xx withholding, content-type scrubbing, the value check, and the
    broker's call to the header check — fails at least one test.

## C. Round 2 additions

14. The reply is decoded strictly (asText) BEFORE any JSON parse; bytes that fail the text rules
    are described, never parsed, for signed and agent requests alike.
15. A header named `__proto__` is kept as an own property and sent.
16. A request other than GET/HEAD that fails with no status after the TLS connection was up
    says it may already have taken effect and to check before resending. One that never
    connected does not say so; a GET does not say so.
17. A 2xx reply over the size cap is `ok:true` with a description and nothing of the reply;
    a non-2xx one over the cap is `ok:false`.

## Out of scope (owner decisions, listed in the report)

- A cap on how much of a (JSON or text) reply the agent is shown, below the 8 MiB transport cap.

- Returning the upstream's error detail on 4xx (scrubbed, as 2xx is). An agent cannot see
  why an API refused it (e.g. "max_tokens is required"); the 2xx path already returns scrubbed
  bodies, so withholding 4xx bodies is not a stronger guarantee — an owner decision.
- A key placed in the URL path (Telegram bot tokens, webhook URLs) or in the request body.
- Request-signing schemes (HMAC, SigV4), two-part credentials.
