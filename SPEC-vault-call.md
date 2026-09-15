# SPEC — vault_call: typed operations over a held credential

Phase 2. Builds on the ssh-agent broker (SPEC.md), same scope rules: **same-uid, not yet
a confidentiality boundary.** What this adds is that a bearer credential stops being
handed to a caller-chosen command and starts being used, by this server, for a named
operation whose shape the owner approved.

## Why not a generic HTTP tool

The obvious design — `vault_http(entry, method, url, headers, body)` with a host/path
allowlist — was written and rejected in review. It is an **egress rule, not an
authorization model**:

- a permitted endpoint may itself be a URL fetcher, webhook tester, GraphQL endpoint,
  batch API or credential-management endpoint;
- `X-HTTP-Method-Override`, `_method`, GraphQL mutations and RPC method fields change the
  effective action while passing a method check;
- the upstream **receives the credential** and can return it — encoded, split across
  fields, or by minting a fresh one and returning that instead.

So the unit is a typed operation with a fixed route and a **response schema**, not a URL.

## The signature problem, and the mechanism that already solves it

An operation definition says *where a credential gets sent*. If the server hands that
definition to the client unauthenticated, a compromised server could define an operation
that posts the secret to itself — a hole that does not exist today, because the server
cannot decrypt.

`verifyDirectiveSignature` already solves exactly this shape: it derives a key from the
**plaintext secret** with PBKDF2 and HMACs the directive. Only a party holding the
plaintext (the owner's browser, at send time) can produce it; the server never can.
Operation definitions reuse that construction.

    op_signature = HMAC-SHA256( PBKDF2(plaintext, salt, 600k, 32), canonical_json(definition) )

The definition travels as server-held data, so adding a provider needs no MCP release —
but the server cannot author or alter one.

## D. The operation definition

Stored on the entry, plaintext, alongside its signature.

    {
      "op": "anthropic.messages.create",
      "origin":  { "scheme": "https", "host": "api.anthropic.com", "port": 443 },
      "route":   { "method": "POST", "path": "/v1/messages" },
      "credential_binding": { "in": "header", "name": "x-api-key", "template": "{secret}" },
      "arguments_schema": { "model": "string", "max_tokens": "number", "messages": "array" },
      "static_headers": { "anthropic-version": "2023-06-01", "content-type": "application/json" },
      "response": { "allow": ["id", "model", "role", "content", "stop_reason", "usage"] },
      "limits": { "request_bytes": 1048576, "response_bytes": 8388608 },
      "redirects": "deny"
    }

### D1. Canonicalisation
- One canonical JSON form (sorted keys, no insignificant whitespace) is what gets signed
  and what gets verified. A definition that does not round-trip canonicalisation is
  rejected before any network call.

### D2. Verification
- A definition with a missing or invalid signature is **refused**, never "used anyway".
- The salt travels with the signature, as in the directive mechanism.
- PBKDF2 at 600k iterations is ~0.5s, so the derived key is cached per
  (entry, salt, secret-hash) — all three, because keying on entry and salt alone let a
  DIFFERENT secret reuse a cached key and verify successfully.
- The cache is **bounded** (64 entries, oldest evicted). An earlier draft said "for the
  life of the process", which is not compatible with a bound: past 64 distinct
  combinations, an evicted key is re-derived and that call pays ~0.5s again. Bounded is
  the right trade — an unbounded cache in a long-lived daemon grows with every secret it
  has ever seen — and the cost falls on a re-verification, not on every call.

## E. Request construction

### E1. The caller supplies typed arguments only
`vault_call(entry_id, operation_id, args, purpose)`. No URL, no headers, no raw body.
The engine builds the request from the definition.

### E2. Origin, not host
- Exact scheme + host + port. HTTPS only. Normal WebPKI validation.
- SNI and certificate verification against the original hostname even when dialling a
  pinned IP.
- No custom CA, no disabled verification, no userinfo, no fragments.

### E3. Redirects are denied
- A 3xx is returned to the caller as a result. It is never followed with the credential
  attached. Following a redirect off-origin is a one-request credential exfiltration.

### E4. SSRF
- Resolve the name once, pin the chosen IP for the connection, keep the original hostname
  for Host/SNI/validation, and ensure the HTTP client cannot perform a second lookup.
- Reject loopback, link-local, RFC1918, ULA, multicast, unspecified, CGNAT, benchmarking
  and cloud-metadata ranges — **including IPv4-mapped IPv6 forms**.

### E5. Headers
- Only `static_headers` from the definition plus the credential binding. Nothing
  caller-supplied.
- The credential header name is refused if it also appears in `static_headers`, in any
  case variant.

### E6. Limits
- Request and response byte caps, and a cap on the **decompressed** response.
- Connect, TLS, header, total and idle timeouts.

## F. Response handling

### F1. Field allowlist
- Only fields named in `response.allow` are returned to the caller. Everything else is
  dropped, including headers.
- An upstream that echoes the credential in an unlisted field therefore cannot reach the
  model. **This does not make disclosure impossible** — a listed field can still contain
  it — and that limitation is documented, not implied away.

### F2. Credential-management operations
- A definition whose route matches a known credential-management shape (paths containing
  `token`, `key`, `credential`, `secret`, `password`) must set
  `"allows_credential_management": true` explicitly, or be refused at verification time.

## Acceptance checks

1. A definition with a valid signature verifies; one with a tampered field does not.
2. A definition the server altered (any field) fails verification and the call is refused.
3. An unsigned definition is refused.
4. Canonicalisation is stable: key order and whitespace do not change the signature.
5. The derived key is cached per (entry, salt); a new salt forces re-derivation.
6. `vault_call` rejects arguments that do not match `arguments_schema`.
7. A caller cannot supply headers, a URL, or a raw body.
8. The credential never appears in the returned result for a well-formed response.
9. A 3xx is returned, not followed.
10. A definition naming an http:// origin is refused.
11. A hostname resolving to 127.0.0.1, 169.254.169.254, 10.x, or ::ffff:127.0.0.1 is refused.
12. The connection dials the pinned IP while presenting the original hostname for SNI.
13. A response field not in `response.allow` is absent from the result.
14. A response larger than the cap, or a decompression bomb, is truncated/refused rather
    than buffered.
15. A credential-management route without the explicit flag is refused at verification.
16. An entry in `BROKER_HTTP` mode is refused by `vault_exec`, `vault_entry_get` and
    `vault_entry_inject_env` (extends the existing mode gate).

## Out of scope

- The uid split, device identity, per-entry keys (phase 4/5).
- Streaming, SSE, WebSockets, multipart, OAuth refresh, request signing (HMAC) — each is
  its own adapter shape and would expand the engine's surface; noted for later.
- Authoring the definitions in the dashboard UI (this spec covers storage, signing
  verification and execution).
