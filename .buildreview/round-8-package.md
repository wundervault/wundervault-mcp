# Review package — round 8
generated 2026-09-15T01:15:01+00:00

## Spec — judge the build against THIS

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
- PBKDF2 at 600k iterations is ~0.5s, so the derived key is cached per (entry, salt) for
  the life of the process. The cache is keyed by salt so a re-signed definition does not
  verify against a stale key.

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


## What was built this round, and how it was tested

Phase 2 round 2. All seven round-1 findings accepted and fixed; triage in round-7-triage.json. F1 Location header no longer echoed (upstream holds the credential and can put it there). F2 operation_id now bound — verifyOperationDefinition takes expectedOperationId and requires it to equal the signed definition's own op. F3 limits validated as positive integers. F4 credential-management match is substring-based, catches /v1/apikeys and /oauth2/authorize. F5 addresses expanded to eight groups before the mapped check, so 0:0:0:0:0:ffff:127.0.0.1 is blocked; public v6 still permitted. F6 wire bytes capped alongside decompressed. F7 secret scrubbed from the response body and the success wording no longer claims non-disclosure. Also bounded the derived-key cache at 64 with oldest-first eviction. Tested: 233 pass, 10 new regression tests, each fix verified empirically before writing the test. SAME KNOWN GAP as round 1, still worth weighing: the live HTTP path in performOperation is not exercised against a server — redirect handling, the two size caps and header assembly are reasoned about and unit-tested at the edges only.

## Diff

```diff
diff --git a/src/http-broker.ts b/src/http-broker.ts
index 1638205..ca07c9f 100644
--- a/src/http-broker.ts
+++ b/src/http-broker.ts
@@ -26,6 +26,26 @@ export interface CallResult {
   redirectedTo?: string;
 }
 
+/**
+ * Remove the credential from anything on its way back to the caller.
+ *
+ * The field allowlist is not sufficient by itself: an upstream can echo the credential
+ * in a field the operation legitimately allows. This is exact-match scrubbing, so it is
+ * defence in depth and NOT a guarantee — an upstream that encodes the value still
+ * defeats it, which is why the tool no longer claims non-disclosure outright.
+ */
+export function scrubSecret(value: unknown, secret: string): unknown {
+  if (!secret) return value;
+  if (typeof value === 'string') return value.split(secret).join('[REDACTED]');
+  if (Array.isArray(value)) return value.map((v) => scrubSecret(v, secret));
+  if (value && typeof value === 'object') {
+    const out: Record<string, unknown> = {};
+    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = scrubSecret(v, secret);
+    return out;
+  }
+  return value;
+}
+
 const DEFAULT_RESPONSE_BYTES = 8 * 1024 * 1024;
 const DEFAULT_REQUEST_BYTES = 1024 * 1024;
 const CONNECT_TIMEOUT_MS = 10_000;
@@ -58,21 +78,49 @@ function isBlockedIPv4(ip: string): boolean {
   return false;
 }
 
+/** Expand any IPv6 spelling to eight 16-bit groups, or null if it is not one. */
+export function expandIPv6(ip: string): number[] | null {
+  let s = ip;
+  // A trailing dotted-quad (::ffff:127.0.0.1) becomes two hex groups first.
+  const dotted = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
+  if (dotted) {
+    const p = dotted[2].split('.').map(Number);
+    if (p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
+    s = dotted[1] + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
+  }
+  const halves = s.split('::');
+  if (halves.length > 2) return null;
+  const head = halves[0] ? halves[0].split(':') : [];
+  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
+  const fill = 8 - head.length - tail.length;
+  if (halves.length === 2 ? fill < 0 : fill !== 0) return null;
+  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail];
+  if (groups.length !== 8) return null;
+  const out = groups.map((g) => (g === '' ? 0 : parseInt(g, 16)));
+  if (out.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
+  return out;
+}
+
 export function isBlockedAddress(ip: string): boolean {
   const v = isIP(ip);
   if (v === 4) return isBlockedIPv4(ip);
   if (v !== 6) return true;                                  // not an address at all
 
   const lower = ip.toLowerCase();
-  // IPv4-mapped (::ffff:127.0.0.1) and IPv4-compatible forms smuggle a v4 address
-  // through a v6 check. Unwrap and apply the v4 rules rather than treating it as "some
-  // v6 address, looks fine".
-  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
-  if (mapped) return isBlockedIPv4(mapped[1]);
-  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
-  if (mappedHex) {
-    const hi = parseInt(mappedHex[1], 16), lo = parseInt(mappedHex[2], 16);
-    return isBlockedIPv4([hi >> 8, hi & 255, lo >> 8, lo & 255].join('.'));
+
+  // IPv4-mapped forms smuggle a v4 address through a v6 check, and they have MANY
+  // spellings: ::ffff:127.0.0.1, ::ffff:7f00:1, and the fully-expanded
+  // 0:0:0:0:0:ffff:127.0.0.1 — an earlier version matched only the compressed ones and
+  // let the expanded form through to loopback. Expand to eight groups first, then
+  // decide once.
+  const expanded = expandIPv6(lower);
+  if (expanded) {
+    const g = expanded;
+    const isMapped = g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0);
+    if (isMapped && !(g[5] === 0 && g[6] === 0 && g[7] <= 1)) {
+      const v4 = [g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.');
+      return isBlockedIPv4(v4);
+    }
   }
 
   if (lower === '::' || lower === '::1') return true;        // unspecified, loopback
@@ -184,9 +232,12 @@ export async function performOperation(
       // whatever host the upstream nominates, which is a one-request exfiltration.
       if (status >= 300 && status < 400) {
         res.resume();
+        // The Location header is NOT echoed. The upstream has already received the
+        // credential, so it can put it anywhere it likes — including Location — and
+        // returning that verbatim hands the secret straight back to the caller.
         return finish({
-          ok: false, status, redirectedTo: res.headers.location,
-          error: `Upstream redirected to ${res.headers.location ?? 'an unnamed location'}. Redirects are not followed, because the credential would travel with them. If this destination is legitimate, define an operation for it.`,
+          ok: false, status,
+          error: 'Upstream redirected. The redirect is not followed, because the credential would travel with it, and the target is not shown, because an upstream that holds the credential can put it in the Location header. If the destination is legitimate, define an operation for it.',
         });
       }
 
@@ -194,8 +245,17 @@ export async function performOperation(
       if (stream !== res) res.pipe(stream as NodeJS.WritableStream & NodeJS.ReadableStream);
 
       let size = 0;
+      let wire = 0;
       const chunks: Buffer[] = [];
       let over = false;
+
+      // Cap the WIRE bytes too. Counting only after decompression meant a 20 MiB
+      // compressed stream that expands to "{}" downloaded in full before anything
+      // noticed — the decompressed cap catches bombs, this one catches the download.
+      res.on('data', (c: Buffer) => {
+        wire += c.length;
+        if (wire > maxRes) { over = true; req.destroy(); }
+      });
       (stream as NodeJS.ReadableStream).on('data', (c: Buffer) => {
         // Counted AFTER decompression, so a small compressed bomb cannot expand past
         // the cap unnoticed.
@@ -211,8 +271,11 @@ export async function performOperation(
         if (parsed === undefined) {
           return finish({ ok: false, status, error: 'Upstream returned a body this operation could not parse as JSON.' });
         }
-        // Only the fields the definition allows reach the caller.
-        finish({ ok: status >= 200 && status < 300, status, body: filterResponse(def, parsed) });
+        // Only the fields the definition allows reach the caller — and even then the
+        // secret is scrubbed, because an upstream can echo it in an ALLOWED field and
+        // the allowlist alone would pass it through.
+        const filtered = filterResponse(def, parsed);
+        finish({ ok: status >= 200 && status < 300, status, body: scrubSecret(filtered, secret) });
       });
       (stream as NodeJS.ReadableStream).on('error', (e: Error) => finish({ ok: false, status, error: `Response error: ${e.message}` }));
     });
diff --git a/src/opdef.ts b/src/opdef.ts
index 460539b..c699da9 100644
--- a/src/opdef.ts
+++ b/src/opdef.ts
@@ -41,7 +41,10 @@ const HMAC_BYTES = 32;
  * refused unless the owner said so explicitly, because "fetch me a new API key" defeats
  * the entire point of never releasing the old one.
  */
-const CREDENTIAL_MANAGEMENT = /(^|[/_-])(tokens?|keys?|credentials?|secrets?|passwords?|oauth|authorize|sessions?)([/_-]|$)/i;
+// Substring, deliberately not boundary-anchored. An earlier version required a
+// separator and so missed "/v1/apikeys", where "keys" sits inside a longer segment.
+// False positives are the safe direction here — the explicit flag exists for them.
+const CREDENTIAL_MANAGEMENT = /(token|key|credential|secret|password|oauth|authoriz|session)/i;
 
 /**
  * Canonical JSON: keys sorted at every level, no insignificant whitespace.
@@ -69,6 +72,8 @@ export function canonicalJson(value: unknown): string {
  * plaintext is hashed rather than stored so the cache key is not itself key material.
  */
 const derivedKeys = new Map<string, Buffer>();
+/** Bounded so a long-lived process cannot accumulate one entry per secret seen. */
+const MAX_CACHED_KEYS = 64;
 
 function cacheKeyFor(entryId: string, salt: Buffer, plaintext: Uint8Array): string {
   const pt = createHash('sha256').update(Buffer.from(plaintext)).digest('base64');
@@ -80,6 +85,11 @@ export function deriveOpKey(entryId: string, plaintext: Uint8Array, salt: Buffer
   const hit = derivedKeys.get(k);
   if (hit) return hit;
   const derived = pbkdf2Sync(Buffer.from(plaintext), salt, PBKDF2_ITERATIONS, 32, 'sha256');
+  if (derivedKeys.size >= MAX_CACHED_KEYS) {
+    // Oldest-first eviction; Map preserves insertion order.
+    const oldest = derivedKeys.keys().next().value;
+    if (oldest !== undefined) derivedKeys.delete(oldest);
+  }
   derivedKeys.set(k, derived);
   return derived;
 }
@@ -105,6 +115,14 @@ export function verifyOperationDefinition(
   rawDefinition: unknown,
   signatureB64: string | undefined,
   plaintext: Uint8Array,
+  /**
+   * The catalogue key the caller asked for. The signature covers the definition but NOT
+   * where it was filed, so without this a server can move one legitimately signed
+   * definition into another's slot: the caller asks for health.check, verification
+   * passes against the jobs.trigger definition, and the credential goes somewhere it
+   * never asked to send it.
+   */
+  expectedOperationId?: string,
 ): VerifyResult {
   if (!signatureB64) {
     return { ok: false, reason: 'This operation has no signature. An unsigned definition is refused: without it, a definition the server wrote is indistinguishable from one you approved.' };
@@ -135,6 +153,10 @@ export function verifyOperationDefinition(
 
   const shaped = validateShape(rawDefinition);
   if (!shaped.ok) return shaped;
+
+  if (expectedOperationId !== undefined && shaped.definition!.op !== expectedOperationId) {
+    return { ok: false, reason: `Catalogue mismatch: the entry files this definition under "${expectedOperationId}", but the signed definition is for "${shaped.definition!.op}". Refusing — a definition moved into another slot is still validly signed.` };
+  }
   return { ok: true, definition: shaped.definition };
 }
 
@@ -184,6 +206,22 @@ export function validateShape(raw: unknown): VerifyResult {
     }
   }
 
+  // Limits are signed data but were never type-checked. A string sails through
+  // verification and then defeats every size comparison via NaN: `2 > "none"` is false,
+  // so no cap ever fires and an arbitrarily large response is buffered.
+  if (d.limits !== undefined) {
+    if (typeof d.limits !== 'object' || d.limits === null || Array.isArray(d.limits)) {
+      return { ok: false, reason: `Operation "${d.op}" has a malformed limits object.` };
+    }
+    for (const field of ['request_bytes', 'response_bytes'] as const) {
+      const v = (d.limits as Record<string, unknown>)[field];
+      if (v === undefined) continue;
+      if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) {
+        return { ok: false, reason: `Operation "${d.op}" limits.${field} must be a positive integer, got ${JSON.stringify(v)}.` };
+      }
+    }
+  }
+
   if (d.redirects && d.redirects !== 'deny') {
     return { ok: false, reason: `Operation "${d.op}" may not enable redirects; a redirect carries the credential off-origin.` };
   }
diff --git a/src/server.ts b/src/server.ts
index 768327a..b319525 100644
--- a/src/server.ts
+++ b/src/server.ts
@@ -602,7 +602,7 @@ export function createServer(args: { url?: string } = {}) {
         try {
           // Verified against the DECRYPTED SECRET, so a definition this server wrote or
           // altered cannot pass — the server has never seen the plaintext.
-          const verified = verifyOperationDefinition(entry_id, slot.definition, slot.signature, plaintextBytes);
+          const verified = verifyOperationDefinition(entry_id, slot.definition, slot.signature, plaintextBytes, operation_id);
           if (!verified.ok || !verified.definition) return fail(`Refused: ${verified.reason}`);
 
           const argCheck = validateArguments(verified.definition, callArgs);
@@ -615,7 +615,7 @@ export function createServer(args: { url?: string } = {}) {
           }
           return CallToolResultSchema.parse({
             content: [{ type: 'text', text:
-              `✅ ${operation_id} → HTTP ${result.status}. The credential was used, not disclosed.\n`
+              `✅ ${operation_id} → HTTP ${result.status}. The credential was used here, not returned to you; the response was filtered to this operation's allowed fields.\n`
               + `${JSON.stringify(result.body, null, 2)}` }],
           });
         } finally {
diff --git a/test/vault-call.test.ts b/test/vault-call.test.ts
index eae1826..0108b95 100644
--- a/test/vault-call.test.ts
+++ b/test/vault-call.test.ts
@@ -10,7 +10,7 @@ import {
   canonicalJson, verifyOperationDefinition, validateShape, validateArguments,
   filterResponse, _clearDerivedKeyCache, type OperationDefinition,
 } from '../src/opdef.js';
-import { isBlockedAddress, resolvePinned } from '../src/http-broker.js';
+import { isBlockedAddress, resolvePinned, expandIPv6, scrubSecret } from '../src/http-broker.js';
 import { modeAllowsHttpBroker, modeAllowsLegacyExec, wrongModeMessage } from '../src/ssh-agent.js';
 
 const SECRET = Buffer.from('sk-ant-api03-EXAMPLE-SECRET-VALUE');
@@ -229,3 +229,80 @@ describe('mode gating for BROKER_HTTP', () => {
     expect(wrongModeMessage('LEGACY_EXEC', 'http')).toContain('BROKER_HTTP');
   });
 });
+
+describe('round 1 regressions', () => {
+  const base = {
+    op: 'x', origin: { scheme: 'https', host: 'h.example', port: 443 },
+    credential_binding: { in: 'header' as const, name: 'a', template: '{secret}' },
+  };
+
+  it('binds the catalogue key, so a signed definition cannot be filed elsewhere', () => {
+    // Both definitions are legitimately signed; moving one into another's slot used to
+    // pass verification and send the credential to a route nobody asked for.
+    const def = { ...base, op: 'jobs.trigger', route: { method: 'POST', path: '/v1/jobs' } };
+    const sig = sign(def, SECRET);
+    expect(verifyOperationDefinition('e', def, sig, SECRET, 'jobs.trigger').ok).toBe(true);
+    const moved = verifyOperationDefinition('e', def, sig, SECRET, 'health.check');
+    expect(moved.ok).toBe(false);
+    expect(moved.reason).toMatch(/Catalogue mismatch/);
+  });
+
+  it('refuses a non-numeric byte limit', () => {
+    // `2 > "none"` is false, so a string limit silently disabled every size check.
+    const r = validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { response_bytes: 'none' } });
+    expect(r.ok).toBe(false);
+    expect(r.reason).toMatch(/positive integer/);
+  });
+
+  it('refuses a zero or negative byte limit', () => {
+    expect(validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { response_bytes: 0 } }).ok).toBe(false);
+    expect(validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { request_bytes: -1 } }).ok).toBe(false);
+  });
+
+  it('catches a credential-management path with no separator around the word', () => {
+    // "/v1/apikeys" — "keys" sits inside a longer segment, which a boundary-anchored
+    // pattern missed entirely.
+    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/apikeys' } }).ok).toBe(false);
+    expect(validateShape({ ...base, route: { method: 'GET', path: '/oauth2/authorize' } }).ok).toBe(false);
+  });
+
+  it('still allows ordinary routes', () => {
+    expect(validateShape({ ...base, route: { method: 'POST', path: '/v1/messages' } }).ok).toBe(true);
+    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/user' } }).ok).toBe(true);
+  });
+
+  it('blocks the fully-expanded IPv4-mapped loopback form', () => {
+    // Only the compressed spellings were matched before, so this reached 127.0.0.1.
+    expect(isBlockedAddress('0:0:0:0:0:ffff:127.0.0.1')).toBe(true);
+    expect(isBlockedAddress('0:0:0:0:0:ffff:169.254.169.254')).toBe(true);
+  });
+
+  it('still permits a genuine public IPv6 address', () => {
+    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false);
+  });
+
+  it('scrubs the credential from a response even in an allowed field', () => {
+    // The allowlist alone cannot help when the upstream echoes the secret into a field
+    // the operation legitimately permits.
+    const out = scrubSecret({ content: 'sk-live-123', nested: [{ x: 'pre sk-live-123 post' }] }, 'sk-live-123');
+    expect(JSON.stringify(out)).not.toContain('sk-live-123');
+    expect(JSON.stringify(out)).toContain('[REDACTED]');
+  });
+
+  it('leaves a response alone when it does not contain the secret', () => {
+    expect(scrubSecret({ a: 'ordinary' }, 'sk-live')).toEqual({ a: 'ordinary' });
+  });
+});
+
+describe('IPv6 expansion', () => {
+  it('expands compressed and dotted forms to eight groups', () => {
+    expect(expandIPv6('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
+    expect(expandIPv6('::ffff:127.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
+    expect(expandIPv6('0:0:0:0:0:ffff:127.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
+  });
+
+  it('returns null for things that are not addresses', () => {
+    expect(expandIPv6('nonsense')).toBeNull();
+    expect(expandIPv6('1::2::3')).toBeNull();
+  });
+});

```

## File: src/opdef.ts

```
/**
 * Operation definitions: what a held credential may be used for.
 *
 * A definition says where a credential gets sent, so it is security-critical data. It
 * travels as server-held plaintext — that is what lets a new provider be added without
 * an MCP release — but the server must not be able to author or alter one, or a
 * compromised server could define an operation that posts the secret to itself. That
 * would be a new hole: today the server genuinely cannot decrypt.
 *
 * The binding reuses the construction already used for directives: a key derived from
 * the PLAINTEXT SECRET via PBKDF2, then an HMAC over the canonical definition. Only a
 * party holding the plaintext — the owner's browser at send time — can produce it. The
 * server never can.
 */
import { pbkdf2Sync, createHmac, timingSafeEqual, createHash } from 'node:crypto';

export interface Origin { scheme: string; host: string; port: number; }
export interface Route { method: string; path: string; }
export interface CredentialBinding { in: 'header' | 'query'; name: string; template: string; }

export interface OperationDefinition {
  op: string;
  origin: Origin;
  route: Route;
  credential_binding: CredentialBinding;
  arguments_schema?: Record<string, string>;
  static_headers?: Record<string, string>;
  response?: { allow?: string[] };
  limits?: { request_bytes?: number; response_bytes?: number };
  redirects?: 'deny';
  allows_credential_management?: boolean;
}

/** PBKDF2 cost matches the directive mechanism; see cacheKeyFor for why it is cached. */
const PBKDF2_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const HMAC_BYTES = 32;

/**
 * Paths that hand out or rotate credentials. An operation pointed at one of these is
 * refused unless the owner said so explicitly, because "fetch me a new API key" defeats
 * the entire point of never releasing the old one.
 */
// Substring, deliberately not boundary-anchored. An earlier version required a
// separator and so missed "/v1/apikeys", where "keys" sits inside a longer segment.
// False positives are the safe direction here — the explicit flag exists for them.
const CREDENTIAL_MANAGEMENT = /(token|key|credential|secret|password|oauth|authoriz|session)/i;

/**
 * Canonical JSON: keys sorted at every level, no insignificant whitespace.
 *
 * Signing a canonical form is what stops a re-ordered or re-spaced definition being a
 * different message. Anything that does not round-trip through here is rejected before a
 * network call rather than signed in one shape and executed in another.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

/**
 * Derived keys are cached because 600k PBKDF2 rounds is roughly half a second —
 * acceptable once, not on every call.
 *
 * The cache key MUST include the plaintext. An earlier version keyed on (entry, salt)
 * only, which meant a second verification with a DIFFERENT secret reused the first
 * secret's key and verified successfully — two secrets colliding under one entry, and a
 * rotated secret still verifying against definitions signed for the old one. The
 * plaintext is hashed rather than stored so the cache key is not itself key material.
 */
const derivedKeys = new Map<string, Buffer>();
/** Bounded so a long-lived process cannot accumulate one entry per secret seen. */
const MAX_CACHED_KEYS = 64;

function cacheKeyFor(entryId: string, salt: Buffer, plaintext: Uint8Array): string {
  const pt = createHash('sha256').update(Buffer.from(plaintext)).digest('base64');
  return `${entryId}:${salt.toString('base64')}:${pt}`;
}

export function deriveOpKey(entryId: string, plaintext: Uint8Array, salt: Buffer): Buffer {
  const k = cacheKeyFor(entryId, salt, plaintext);
  const hit = derivedKeys.get(k);
  if (hit) return hit;
  const derived = pbkdf2Sync(Buffer.from(plaintext), salt, PBKDF2_ITERATIONS, 32, 'sha256');
  if (derivedKeys.size >= MAX_CACHED_KEYS) {
    // Oldest-first eviction; Map preserves insertion order.
    const oldest = derivedKeys.keys().next().value;
    if (oldest !== undefined) derivedKeys.delete(oldest);
  }
  derivedKeys.set(k, derived);
  return derived;
}

/** Test seam: the cache is process-global, which a test must be able to reset. */
export function _clearDerivedKeyCache(): void { derivedKeys.clear(); }

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  definition?: OperationDefinition;
}

/**
 * Verify a definition against its signature.
 *
 * Refuses rather than degrades: an unsigned or mis-signed definition is not "used
 * anyway with a warning", because the whole value of the signature is that an
 * unverified definition is indistinguishable from one the server wrote.
 */
export function verifyOperationDefinition(
  entryId: string,
  rawDefinition: unknown,
  signatureB64: string | undefined,
  plaintext: Uint8Array,
  /**
   * The catalogue key the caller asked for. The signature covers the definition but NOT
   * where it was filed, so without this a server can move one legitimately signed
   * definition into another's slot: the caller asks for health.check, verification
   * passes against the jobs.trigger definition, and the credential goes somewhere it
   * never asked to send it.
   */
  expectedOperationId?: string,
): VerifyResult {
  if (!signatureB64) {
    return { ok: false, reason: 'This operation has no signature. An unsigned definition is refused: without it, a definition the server wrote is indistinguishable from one you approved.' };
  }
  if (!plaintext || plaintext.length === 0) {
    return { ok: false, reason: 'Cannot verify the operation definition without the decrypted secret.' };
  }

  let raw: Buffer;
  try { raw = Buffer.from(signatureB64, 'base64'); } catch { return { ok: false, reason: 'Operation signature is not valid base64.' }; }
  if (raw.length !== SALT_BYTES + HMAC_BYTES) {
    return { ok: false, reason: `Operation signature is malformed (expected ${SALT_BYTES + HMAC_BYTES} bytes, got ${raw.length}).` };
  }

  const salt = raw.subarray(0, SALT_BYTES);
  const expected = raw.subarray(SALT_BYTES);

  let canonical: string;
  try { canonical = canonicalJson(rawDefinition); } catch { return { ok: false, reason: 'Operation definition is not serialisable.' }; }

  const key = deriveOpKey(entryId, plaintext, Buffer.from(salt));
  const actual = createHmac('sha256', key).update(canonical).digest();

  // timingSafeEqual needs equal lengths; both are 32 bytes by the check above.
  if (!timingSafeEqual(actual, expected)) {
    return { ok: false, reason: 'Operation definition does not match its signature. It has been altered since it was approved, or was signed for a different secret.' };
  }

  const shaped = validateShape(rawDefinition);
  if (!shaped.ok) return shaped;

  if (expectedOperationId !== undefined && shaped.definition!.op !== expectedOperationId) {
    return { ok: false, reason: `Catalogue mismatch: the entry files this definition under "${expectedOperationId}", but the signed definition is for "${shaped.definition!.op}". Refusing — a definition moved into another slot is still validly signed.` };
  }
  return { ok: true, definition: shaped.definition };
}

/**
 * Structural validation, run AFTER the signature so a malformed definition cannot be
 * used to probe verification. Everything here is a refusal the owner can act on.
 */
export function validateShape(raw: unknown): VerifyResult {
  const d = raw as OperationDefinition;
  if (!d || typeof d !== 'object') return { ok: false, reason: 'Operation definition is not an object.' };
  if (!d.op || typeof d.op !== 'string') return { ok: false, reason: 'Operation definition has no "op" name.' };

  const o = d.origin;
  if (!o || typeof o !== 'object') return { ok: false, reason: `Operation "${d.op}" has no origin.` };
  // https only. A definition naming http:// would send the credential in clear.
  if (o.scheme !== 'https') return { ok: false, reason: `Operation "${d.op}" names scheme "${o.scheme}"; only https is permitted.` };
  if (!o.host || typeof o.host !== 'string') return { ok: false, reason: `Operation "${d.op}" has no origin host.` };
  if (typeof o.port !== 'number' || o.port <= 0 || o.port > 65535) {
    return { ok: false, reason: `Operation "${d.op}" has an invalid origin port.` };
  }
  if (o.host.includes('@') || o.host.includes('/') || o.host.includes('#')) {
    return { ok: false, reason: `Operation "${d.op}" origin host must be a bare hostname — no userinfo, path or fragment.` };
  }

  const r = d.route;
  if (!r || typeof r.method !== 'string' || typeof r.path !== 'string') {
    return { ok: false, reason: `Operation "${d.op}" has no route.` };
  }
  if (!r.path.startsWith('/')) return { ok: false, reason: `Operation "${d.op}" route path must start with "/".` };

  const cb = d.credential_binding;
  if (!cb || (cb.in !== 'header' && cb.in !== 'query')) {
    return { ok: false, reason: `Operation "${d.op}" has no credential_binding.` };
  }
  if (!cb.name || !cb.template || !cb.template.includes('{secret}')) {
    return { ok: false, reason: `Operation "${d.op}" credential_binding must name a field and a template containing {secret}.` };
  }

  // The credential header must not also be a static header, in any case variant — the
  // later value would silently win and the binding would look applied while not being.
  if (cb.in === 'header' && d.static_headers) {
    const lower = cb.name.toLowerCase();
    for (const k of Object.keys(d.static_headers)) {
      if (k.toLowerCase() === lower) {
        return { ok: false, reason: `Operation "${d.op}" sets "${k}" as both the credential binding and a static header.` };
      }
    }
  }

  // Limits are signed data but were never type-checked. A string sails through
  // verification and then defeats every size comparison via NaN: `2 > "none"` is false,
  // so no cap ever fires and an arbitrarily large response is buffered.
  if (d.limits !== undefined) {
    if (typeof d.limits !== 'object' || d.limits === null || Array.isArray(d.limits)) {
      return { ok: false, reason: `Operation "${d.op}" has a malformed limits object.` };
    }
    for (const field of ['request_bytes', 'response_bytes'] as const) {
      const v = (d.limits as Record<string, unknown>)[field];
      if (v === undefined) continue;
      if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) {
        return { ok: false, reason: `Operation "${d.op}" limits.${field} must be a positive integer, got ${JSON.stringify(v)}.` };
      }
    }
  }

  if (d.redirects && d.redirects !== 'deny') {
    return { ok: false, reason: `Operation "${d.op}" may not enable redirects; a redirect carries the credential off-origin.` };
  }

  // An operation that mints or lists credentials defeats never releasing the original,
  // so it has to be an explicit decision rather than an accident of routing.
  if (CREDENTIAL_MANAGEMENT.test(r.path) && d.allows_credential_management !== true) {
    return { ok: false, reason: `Operation "${d.op}" targets a credential-management path ("${r.path}") without allows_credential_management. An operation that can mint or read credentials defeats the point of never releasing this one; set the flag deliberately if that is intended.` };
  }

  return { ok: true, definition: d };
}

/** Arguments the caller supplied, checked against the definition's declared shape. */
export function validateArguments(
  def: OperationDefinition,
  args: Record<string, unknown>,
): { ok: true } | { ok: false; reason: string } {
  const schema = def.arguments_schema ?? {};
  for (const [name, type] of Object.entries(schema)) {
    const v = (args ?? {})[name];
    if (v === undefined) return { ok: false, reason: `Missing argument "${name}" (${type}).` };
    const actual = Array.isArray(v) ? 'array' : typeof v;
    if (actual !== type) return { ok: false, reason: `Argument "${name}" should be ${type}, got ${actual}.` };
  }
  for (const name of Object.keys(args ?? {})) {
    if (!(name in schema)) {
      // Unknown arguments are refused, not ignored: silently dropping one means a caller
      // believes it constrained a request that actually went out without the constraint.
      return { ok: false, reason: `Unknown argument "${name}" for operation "${def.op}".` };
    }
  }
  return { ok: true };
}

/** Only the fields the definition allows reach the caller. */
export function filterResponse(def: OperationDefinition, body: unknown): unknown {
  const allow = def.response?.allow;
  if (!allow || !Array.isArray(allow) || allow.length === 0) return {};
  if (!body || typeof body !== 'object' || Array.isArray(body)) return {};
  const out: Record<string, unknown> = {};
  for (const k of allow) {
    if (Object.prototype.hasOwnProperty.call(body as object, k)) {
      out[k] = (body as Record<string, unknown>)[k];
    }
  }
  return out;
}

```

## File: src/http-broker.ts

```
/**
 * Perform one typed operation with a held credential.
 *
 * The caller never supplies a URL, headers or a body — only typed arguments against a
 * signed definition. Everything about where the request goes comes from the definition,
 * which the server cannot author (see opdef.ts).
 *
 * The hard parts here are all about a request going somewhere other than where the
 * definition says: DNS resolving to a private address, a second lookup between check and
 * connect, a redirect carrying the credential off-origin, or a header the caller slipped
 * in. Each is handled explicitly rather than by trusting the HTTP client's defaults.
 */
import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup } from 'node:dns';
import { isIP } from 'node:net';
import { createGunzip, createInflate, createBrotliDecompress } from 'node:zlib';
import type { OperationDefinition } from './opdef.js';
import { filterResponse } from './opdef.js';

export interface CallResult {
  ok: boolean;
  status?: number;
  body?: unknown;
  error?: string;
  /** Set when the upstream redirected. The redirect is NOT followed. */
  redirectedTo?: string;
}

/**
 * Remove the credential from anything on its way back to the caller.
 *
 * The field allowlist is not sufficient by itself: an upstream can echo the credential
 * in a field the operation legitimately allows. This is exact-match scrubbing, so it is
 * defence in depth and NOT a guarantee — an upstream that encodes the value still
 * defeats it, which is why the tool no longer claims non-disclosure outright.
 */
export function scrubSecret(value: unknown, secret: string): unknown {
  if (!secret) return value;
  if (typeof value === 'string') return value.split(secret).join('[REDACTED]');
  if (Array.isArray(value)) return value.map((v) => scrubSecret(v, secret));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = scrubSecret(v, secret);
    return out;
  }
  return value;
}

const DEFAULT_RESPONSE_BYTES = 8 * 1024 * 1024;
const DEFAULT_REQUEST_BYTES = 1024 * 1024;
const CONNECT_TIMEOUT_MS = 10_000;
const TOTAL_TIMEOUT_MS = 60_000;

/**
 * Address ranges a brokered request must never reach.
 *
 * The point is not tidiness: cloud metadata at 169.254.169.254 hands out instance
 * credentials, and loopback reaches whatever else is running on this machine. A hostname
 * the definition names could resolve to any of these, whether by misconfiguration or by
 * an attacker controlling the DNS record.
 */
function isBlockedIPv4(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  if (a === 0) return true;                                  // "this network"
  if (a === 10) return true;                                 // RFC1918
  if (a === 127) return true;                                // loopback
  if (a === 100 && b >= 64 && b <= 127) return true;         // CGNAT
  if (a === 169 && b === 254) return true;                   // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;          // RFC1918
  if (a === 192 && b === 168) return true;                   // RFC1918
  if (a === 192 && b === 0) return true;                     // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true;       // benchmarking
  if (a === 198 && b === 51) return true;                    // TEST-NET-2
  if (a === 203 && b === 0) return true;                     // TEST-NET-3
  if (a >= 224) return true;                                 // multicast + reserved
  return false;
}

/** Expand any IPv6 spelling to eight 16-bit groups, or null if it is not one. */
export function expandIPv6(ip: string): number[] | null {
  let s = ip;
  // A trailing dotted-quad (::ffff:127.0.0.1) becomes two hex groups first.
  const dotted = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (dotted) {
    const p = dotted[2].split('.').map(Number);
    if (p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
    s = dotted[1] + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 0 : fill !== 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  const out = groups.map((g) => (g === '' ? 0 : parseInt(g, 16)));
  if (out.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  return out;
}

export function isBlockedAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) return isBlockedIPv4(ip);
  if (v !== 6) return true;                                  // not an address at all

  const lower = ip.toLowerCase();

  // IPv4-mapped forms smuggle a v4 address through a v6 check, and they have MANY
  // spellings: ::ffff:127.0.0.1, ::ffff:7f00:1, and the fully-expanded
  // 0:0:0:0:0:ffff:127.0.0.1 — an earlier version matched only the compressed ones and
  // let the expanded form through to loopback. Expand to eight groups first, then
  // decide once.
  const expanded = expandIPv6(lower);
  if (expanded) {
    const g = expanded;
    const isMapped = g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0);
    if (isMapped && !(g[5] === 0 && g[6] === 0 && g[7] <= 1)) {
      const v4 = [g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.');
      return isBlockedIPv4(v4);
    }
  }

  if (lower === '::' || lower === '::1') return true;        // unspecified, loopback
  if (/^f[cd]/.test(lower)) return true;                     // unique local fc00::/7
  if (/^fe[89ab]/.test(lower)) return true;                  // link-local fe80::/10
  if (/^ff/.test(lower)) return true;                        // multicast
  return false;
}

/** Resolve once and choose an address, refusing anything internal. */
export function resolvePinned(host: string): Promise<{ address: string; family: number }> {
  return new Promise((resolve, reject) => {
    if (isIP(host)) {
      // A literal address in a definition still goes through the same filter.
      if (isBlockedAddress(host)) return reject(new Error(`refuses to connect to ${host}: internal or reserved address`));
      return resolve({ address: host, family: isIP(host) });
    }
    dnsLookup(host, { all: true }, (err, addrs) => {
      if (err) return reject(new Error(`could not resolve ${host}: ${err.message}`));
      const usable = addrs.filter((a) => !isBlockedAddress(a.address));
      if (usable.length === 0) {
        return reject(new Error(
          `${host} resolves only to internal or reserved addresses (${addrs.map((a) => a.address).join(', ')}); refusing to send the credential there`,
        ));
      }
      resolve({ address: usable[0].address, family: usable[0].family });
    });
  });
}

function decompressor(encoding: string | undefined) {
  switch ((encoding || '').toLowerCase()) {
    case 'gzip': return createGunzip();
    case 'deflate': return createInflate();
    case 'br': return createBrotliDecompress();
    default: return null;
  }
}

/**
 * Build and send the request described by a verified definition.
 *
 * `secret` is used here and nowhere else — it is not returned, not logged, and not
 * placed anywhere the caller can read.
 */
export async function performOperation(
  def: OperationDefinition,
  args: Record<string, unknown>,
  secret: string,
): Promise<CallResult> {
  const { scheme, host, port } = def.origin;
  if (scheme !== 'https') return { ok: false, error: 'Only https origins are permitted.' };

  let pinned: { address: string; family: number };
  try {
    pinned = await resolvePinned(host);
  } catch (e) {
    return { ok: false, error: `Refused: ${e instanceof Error ? e.message : String(e)}` };
  }

  const headers: Record<string, string> = { ...(def.static_headers ?? {}) };
  let body: string | undefined;
  if (def.route.method !== 'GET' && def.route.method !== 'HEAD') {
    body = JSON.stringify(args ?? {});
    const maxReq = def.limits?.request_bytes ?? DEFAULT_REQUEST_BYTES;
    if (Buffer.byteLength(body) > maxReq) {
      return { ok: false, error: `Request body exceeds this operation's limit of ${maxReq} bytes.` };
    }
    headers['content-length'] = String(Buffer.byteLength(body));
    if (!Object.keys(headers).some((k) => k.toLowerCase() === 'content-type')) {
      headers['content-type'] = 'application/json';
    }
  }

  // The credential goes in last, so nothing in the definition's static headers can
  // shadow it. validateShape already refuses a definition that names both.
  let path = def.route.path;
  if (def.credential_binding.in === 'header') {
    headers[def.credential_binding.name] = def.credential_binding.template.replace('{secret}', secret);
  } else {
    const sep = path.includes('?') ? '&' : '?';
    path += `${sep}${encodeURIComponent(def.credential_binding.name)}=${encodeURIComponent(def.credential_binding.template.replace('{secret}', secret))}`;
  }

  const maxRes = def.limits?.response_bytes ?? DEFAULT_RESPONSE_BYTES;

  return await new Promise<CallResult>((resolve) => {
    let settled = false;
    const finish = (r: CallResult) => { if (!settled) { settled = true; resolve(r); } };

    const req = httpsRequest({
      host,
      port,
      path,
      method: def.route.method,
      headers: { ...headers, host },
      // Pin the address we vetted. Without this the agent performs its own lookup at
      // connect time, and the record could differ from the one that passed the check.
      lookup: (_h, _o, cb) => (cb as (e: NodeJS.ErrnoException | null, a: string, f: number) => void)(null, pinned.address, pinned.family),
      // Certificate and SNI still use the ORIGINAL hostname, so pinning the IP does not
      // weaken TLS verification in the slightest.
      servername: host,
      rejectUnauthorized: true,
      timeout: CONNECT_TIMEOUT_MS,
    }, (res) => {
      const status = res.statusCode ?? 0;

      // A redirect is returned, never followed: following one sends the credential to
      // whatever host the upstream nominates, which is a one-request exfiltration.
      if (status >= 300 && status < 400) {
        res.resume();
        // The Location header is NOT echoed. The upstream has already received the
        // credential, so it can put it anywhere it likes — including Location — and
        // returning that verbatim hands the secret straight back to the caller.
        return finish({
          ok: false, status,
          error: 'Upstream redirected. The redirect is not followed, because the credential would travel with it, and the target is not shown, because an upstream that holds the credential can put it in the Location header. If the destination is legitimate, define an operation for it.',
        });
      }

      const stream = decompressor(res.headers['content-encoding']) ?? res;
      if (stream !== res) res.pipe(stream as NodeJS.WritableStream & NodeJS.ReadableStream);

      let size = 0;
      let wire = 0;
      const chunks: Buffer[] = [];
      let over = false;

      // Cap the WIRE bytes too. Counting only after decompression meant a 20 MiB
      // compressed stream that expands to "{}" downloaded in full before anything
      // noticed — the decompressed cap catches bombs, this one catches the download.
      res.on('data', (c: Buffer) => {
        wire += c.length;
        if (wire > maxRes) { over = true; req.destroy(); }
      });
      (stream as NodeJS.ReadableStream).on('data', (c: Buffer) => {
        // Counted AFTER decompression, so a small compressed bomb cannot expand past
        // the cap unnoticed.
        size += c.length;
        if (size > maxRes) { over = true; req.destroy(); return; }
        chunks.push(c);
      });
      (stream as NodeJS.ReadableStream).on('end', () => {
        if (over) return finish({ ok: false, status, error: `Response exceeded ${maxRes} bytes.` });
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed: unknown;
        try { parsed = JSON.parse(text); } catch { parsed = undefined; }
        if (parsed === undefined) {
          return finish({ ok: false, status, error: 'Upstream returned a body this operation could not parse as JSON.' });
        }
        // Only the fields the definition allows reach the caller — and even then the
        // secret is scrubbed, because an upstream can echo it in an ALLOWED field and
        // the allowlist alone would pass it through.
        const filtered = filterResponse(def, parsed);
        finish({ ok: status >= 200 && status < 300, status, body: scrubSecret(filtered, secret) });
      });
      (stream as NodeJS.ReadableStream).on('error', (e: Error) => finish({ ok: false, status, error: `Response error: ${e.message}` }));
    });

    const total = setTimeout(() => { req.destroy(); finish({ ok: false, error: `Operation timed out after ${TOTAL_TIMEOUT_MS / 1000}s.` }); }, TOTAL_TIMEOUT_MS);
    req.on('close', () => clearTimeout(total));
    req.on('timeout', () => { req.destroy(); finish({ ok: false, error: 'Connection timed out.' }); });
    req.on('error', (e) => finish({ ok: false, error: `Request failed: ${e.message}` }));

    if (body) req.write(body);
    req.end();
  });
}

```

## File: test/vault-call.test.ts

```
/**
 * Acceptance checks for vault_call (SPEC-vault-call.md).
 *
 * The signature tests sign definitions the way the owner's browser would, so what is
 * exercised is the real construction rather than a stub that agrees with itself.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { pbkdf2Sync, createHmac, randomBytes } from 'node:crypto';
import {
  canonicalJson, verifyOperationDefinition, validateShape, validateArguments,
  filterResponse, _clearDerivedKeyCache, type OperationDefinition,
} from '../src/opdef.js';
import { isBlockedAddress, resolvePinned, expandIPv6, scrubSecret } from '../src/http-broker.js';
import { modeAllowsHttpBroker, modeAllowsLegacyExec, wrongModeMessage } from '../src/ssh-agent.js';

const SECRET = Buffer.from('sk-ant-api03-EXAMPLE-SECRET-VALUE');

const DEF: OperationDefinition = {
  op: 'anthropic.messages.create',
  origin: { scheme: 'https', host: 'api.anthropic.com', port: 443 },
  route: { method: 'POST', path: '/v1/messages' },
  credential_binding: { in: 'header', name: 'x-api-key', template: '{secret}' },
  arguments_schema: { model: 'string', max_tokens: 'number', messages: 'array' },
  static_headers: { 'anthropic-version': '2023-06-01' },
  response: { allow: ['id', 'model', 'content', 'usage'] },
  redirects: 'deny',
};

/** Sign exactly as the owner's browser would: PBKDF2 over the plaintext, HMAC the canonical form. */
function sign(def: unknown, secret: Buffer, salt = randomBytes(16)): string {
  const key = pbkdf2Sync(secret, salt, 600_000, 32, 'sha256');
  const mac = createHmac('sha256', key).update(canonicalJson(def)).digest();
  return Buffer.concat([salt, mac]).toString('base64');
}

beforeEach(() => { _clearDerivedKeyCache(); });

describe('canonicalisation', () => {
  it('is stable under key order', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
  });

  it('is stable under nesting order', () => {
    expect(canonicalJson({ x: { q: 1, p: 2 } })).toBe(canonicalJson({ x: { p: 2, q: 1 } }));
  });

  it('keeps array order, which is meaningful', () => {
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });
});

describe('signature verification', () => {
  it('accepts a correctly signed definition', () => {
    expect(verifyOperationDefinition('e1', DEF, sign(DEF, SECRET), SECRET).ok).toBe(true);
  });

  it('accepts the same definition with its keys reordered', () => {
    const sig = sign(DEF, SECRET);
    const reordered = { route: DEF.route, op: DEF.op, origin: DEF.origin,
      credential_binding: DEF.credential_binding, arguments_schema: DEF.arguments_schema,
      static_headers: DEF.static_headers, response: DEF.response, redirects: DEF.redirects };
    expect(verifyOperationDefinition('e1', reordered, sig, SECRET).ok).toBe(true);
  });

  it('refuses a definition whose origin was changed', () => {
    // The attack this exists for: a compromised server redirecting the credential.
    const sig = sign(DEF, SECRET);
    const tampered = { ...DEF, origin: { ...DEF.origin, host: 'evil.example' } };
    const r = verifyOperationDefinition('e1', tampered, sig, SECRET);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not match its signature/);
  });

  it('refuses a definition whose credential binding was changed', () => {
    const sig = sign(DEF, SECRET);
    const tampered = { ...DEF, credential_binding: { in: 'query' as const, name: 'leak', template: '{secret}' } };
    expect(verifyOperationDefinition('e1', tampered, sig, SECRET).ok).toBe(false);
  });

  it('refuses an unsigned definition rather than using it anyway', () => {
    const r = verifyOperationDefinition('e1', DEF, undefined, SECRET);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no signature/);
  });

  it('refuses a signature of the wrong length', () => {
    expect(verifyOperationDefinition('e1', DEF, Buffer.alloc(10).toString('base64'), SECRET).ok).toBe(false);
  });

  it('refuses a definition signed for a DIFFERENT secret', () => {
    // Regression: the derived-key cache once keyed on (entry, salt) only, so a second
    // verification with another secret reused the first key and passed.
    const sig = sign(DEF, SECRET);
    expect(verifyOperationDefinition('e1', DEF, sig, Buffer.from('a-different-secret')).ok).toBe(false);
  });

  it('does not let a cached key leak across secrets under one entry', () => {
    const salt = randomBytes(16);
    const sigA = sign(DEF, SECRET, salt);
    expect(verifyOperationDefinition('e1', DEF, sigA, SECRET).ok).toBe(true);
    // same entry, same salt, different secret — must still fail
    expect(verifyOperationDefinition('e1', DEF, sigA, Buffer.from('other')).ok).toBe(false);
  });
});

describe('definition shape', () => {
  it('refuses an http origin', () => {
    const r = validateShape({ ...DEF, origin: { scheme: 'http', host: 'x.example', port: 80 } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/only https/);
  });

  it('refuses a host carrying userinfo or a path', () => {
    expect(validateShape({ ...DEF, origin: { ...DEF.origin, host: 'evil@api.anthropic.com' } }).ok).toBe(false);
    expect(validateShape({ ...DEF, origin: { ...DEF.origin, host: 'api.anthropic.com/x' } }).ok).toBe(false);
  });

  it('refuses a credential binding with no {secret} placeholder', () => {
    expect(validateShape({ ...DEF, credential_binding: { in: 'header' as const, name: 'a', template: 'constant' } }).ok).toBe(false);
  });

  it('refuses the credential header also appearing as a static header, in any case', () => {
    // The later value would silently win and the binding would look applied but not be.
    const r = validateShape({ ...DEF, static_headers: { 'X-API-KEY': 'oops' } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/both the credential binding and a static header/);
  });

  it('refuses enabling redirects', () => {
    expect(validateShape({ ...DEF, redirects: 'follow' as unknown as 'deny' }).ok).toBe(false);
  });

  it('refuses a credential-management route unless flagged deliberately', () => {
    const r = validateShape({ ...DEF, route: { method: 'GET', path: '/v1/api_keys' } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/credential-management/);
  });

  it('allows a credential-management route when flagged', () => {
    expect(validateShape({ ...DEF, route: { method: 'GET', path: '/v1/api_keys' }, allows_credential_management: true }).ok).toBe(true);
  });
});

describe('arguments', () => {
  it('accepts arguments matching the schema', () => {
    expect(validateArguments(DEF, { model: 'claude', max_tokens: 10, messages: [] }).ok).toBe(true);
  });

  it('rejects a wrong type', () => {
    const r = validateArguments(DEF, { model: 'claude', max_tokens: '10', messages: [] });
    expect(r.ok).toBe(false);
  });

  it('rejects a missing argument', () => {
    expect(validateArguments(DEF, { model: 'claude', messages: [] }).ok).toBe(false);
  });

  it('rejects an unknown argument rather than dropping it', () => {
    // Silently ignoring one means the caller believes it constrained a request that went
    // out without the constraint.
    const r = validateArguments(DEF, { model: 'c', max_tokens: 1, messages: [], stream: true });
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/Unknown argument "stream"/);
  });

  it('tells arrays from objects', () => {
    expect(validateArguments(DEF, { model: 'c', max_tokens: 1, messages: {} }).ok).toBe(false);
  });
});

describe('response filtering', () => {
  it('returns only allowed fields', () => {
    const out = filterResponse(DEF, { id: 'x', model: 'm', content: [], usage: {}, secret_echo: 'sk-leak' }) as Record<string, unknown>;
    expect(Object.keys(out).sort()).toEqual(['content', 'id', 'model', 'usage']);
    expect(JSON.stringify(out)).not.toContain('sk-leak');
  });

  it('returns nothing when the definition allows nothing', () => {
    expect(filterResponse({ ...DEF, response: { allow: [] } }, { a: 1 })).toEqual({});
  });

  it('does not pass an array body through', () => {
    expect(filterResponse(DEF, [1, 2, 3])).toEqual({});
  });
});

describe('SSRF address filtering', () => {
  const blocked = ['127.0.0.1', '10.0.0.5', '172.16.0.1', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '198.18.0.1', '::1', '::', 'fe80::1', 'fc00::1', 'ff02::1'];
  const mapped = ['::ffff:127.0.0.1', '::ffff:169.254.169.254', '::ffff:7f00:1'];
  const allowed = ['1.1.1.1', '8.8.8.8', '129.146.202.158', '2606:4700:4700::1111'];

  it.each(blocked)('blocks %s', (ip) => { expect(isBlockedAddress(ip)).toBe(true); });

  it.each(mapped)('blocks the IPv4-mapped form %s', (ip) => {
    // A v4 address wrapped in v6 notation smuggles past a naive v6 check.
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it.each(allowed)('permits %s', (ip) => { expect(isBlockedAddress(ip)).toBe(false); });

  it('blocks anything that is not an address', () => {
    expect(isBlockedAddress('not-an-ip')).toBe(true);
    expect(isBlockedAddress('')).toBe(true);
  });

  it('refuses to resolve a hostname that points at loopback', async () => {
    await expect(resolvePinned('localhost')).rejects.toThrow(/internal or reserved/);
  });

  it('refuses a literal metadata address', async () => {
    await expect(resolvePinned('169.254.169.254')).rejects.toThrow(/internal or reserved/);
  });
});

describe('mode gating for BROKER_HTTP', () => {
  it('keeps a BROKER_HTTP entry out of the plaintext paths', () => {
    expect(modeAllowsLegacyExec('BROKER_HTTP')).toBe(false);
  });

  it('allows vault_call only for BROKER_HTTP', () => {
    expect(modeAllowsHttpBroker('BROKER_HTTP')).toBe(true);
    expect(modeAllowsHttpBroker('LEGACY_EXEC')).toBe(false);
    expect(modeAllowsHttpBroker('BROKER_SSH_AGENT')).toBe(false);
    expect(modeAllowsHttpBroker(undefined)).toBe(false);
  });

  it('names the mode the caller needs', () => {
    expect(wrongModeMessage('LEGACY_EXEC', 'http')).toContain('BROKER_HTTP');
  });
});

describe('round 1 regressions', () => {
  const base = {
    op: 'x', origin: { scheme: 'https', host: 'h.example', port: 443 },
    credential_binding: { in: 'header' as const, name: 'a', template: '{secret}' },
  };

  it('binds the catalogue key, so a signed definition cannot be filed elsewhere', () => {
    // Both definitions are legitimately signed; moving one into another's slot used to
    // pass verification and send the credential to a route nobody asked for.
    const def = { ...base, op: 'jobs.trigger', route: { method: 'POST', path: '/v1/jobs' } };
    const sig = sign(def, SECRET);
    expect(verifyOperationDefinition('e', def, sig, SECRET, 'jobs.trigger').ok).toBe(true);
    const moved = verifyOperationDefinition('e', def, sig, SECRET, 'health.check');
    expect(moved.ok).toBe(false);
    expect(moved.reason).toMatch(/Catalogue mismatch/);
  });

  it('refuses a non-numeric byte limit', () => {
    // `2 > "none"` is false, so a string limit silently disabled every size check.
    const r = validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { response_bytes: 'none' } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/positive integer/);
  });

  it('refuses a zero or negative byte limit', () => {
    expect(validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { response_bytes: 0 } }).ok).toBe(false);
    expect(validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { request_bytes: -1 } }).ok).toBe(false);
  });

  it('catches a credential-management path with no separator around the word', () => {
    // "/v1/apikeys" — "keys" sits inside a longer segment, which a boundary-anchored
    // pattern missed entirely.
    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/apikeys' } }).ok).toBe(false);
    expect(validateShape({ ...base, route: { method: 'GET', path: '/oauth2/authorize' } }).ok).toBe(false);
  });

  it('still allows ordinary routes', () => {
    expect(validateShape({ ...base, route: { method: 'POST', path: '/v1/messages' } }).ok).toBe(true);
    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/user' } }).ok).toBe(true);
  });

  it('blocks the fully-expanded IPv4-mapped loopback form', () => {
    // Only the compressed spellings were matched before, so this reached 127.0.0.1.
    expect(isBlockedAddress('0:0:0:0:0:ffff:127.0.0.1')).toBe(true);
    expect(isBlockedAddress('0:0:0:0:0:ffff:169.254.169.254')).toBe(true);
  });

  it('still permits a genuine public IPv6 address', () => {
    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false);
  });

  it('scrubs the credential from a response even in an allowed field', () => {
    // The allowlist alone cannot help when the upstream echoes the secret into a field
    // the operation legitimately permits.
    const out = scrubSecret({ content: 'sk-live-123', nested: [{ x: 'pre sk-live-123 post' }] }, 'sk-live-123');
    expect(JSON.stringify(out)).not.toContain('sk-live-123');
    expect(JSON.stringify(out)).toContain('[REDACTED]');
  });

  it('leaves a response alone when it does not contain the secret', () => {
    expect(scrubSecret({ a: 'ordinary' }, 'sk-live')).toEqual({ a: 'ordinary' });
  });
});

describe('IPv6 expansion', () => {
  it('expands compressed and dotted forms to eight groups', () => {
    expect(expandIPv6('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(expandIPv6('::ffff:127.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
    expect(expandIPv6('0:0:0:0:0:ffff:127.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
  });

  it('returns null for things that are not addresses', () => {
    expect(expandIPv6('nonsense')).toBeNull();
    expect(expandIPv6('1::2::3')).toBeNull();
  });
});

```

## Already ruled on in earlier rounds

Do not raise these again unless you have new evidence, and name the evidence if you do.

- [round 1 F2] deferred: Delete the lock file, start a frozen OLDER copy of the package, and it starts alongside a live holder because it has no process scan.
  reason: True and unfixable from inside this repo — an old build cannot be taught to scan. Explicitly out of scope per the spec (frozen copies are not being rebuilt), but it means the invariant is only restored box-wide once Byte's copy in ~/.openclaw/workspace/node_modules is updated. Raised to the user as a real remaining gap, not closed.
- [round 1 B2] rejected: Agent names 'Team A' and 'Team?A' both slug to mcp-Team_A.lock and can clobber each other's lock.
  reason: Real but not fixable under this spec's compatibility constraint: changing the filename breaks every older copy on the box that reads mcp-<slug>.lock, which is a strictly worse failure. Impact is now small because arbitration is by process and the scan compares the RAW agent name from environ, not the slug. Documented, not changed.
- [round 1 B1] deferred: Containers with disjoint /proc views sharing one home directory cannot be disambiguated by a host-local (pid, start) pair.
  reason: Correct, and out of scope — no such deployment exists here. Worth recording as a known boundary of the design rather than pretending the lock is namespace-safe.
- [round 1 B3] deferred: On non-Linux there is no incarnation evidence, so a stale lock naming a reused PID refuses forever and points at the wrong process.
  reason: Accurate. Mitigated in practice by fix 2 of this build: the refusal is now legible and names the PID, so an operator can see it is wrong and delete the lock, instead of staring at CONNECTION_CLOSED. A real fix needs a non-/proc incarnation source; noted, not built.
- [round 2 F4] rejected: A reparented (PPID 1) holder yields no parent hint, so the blocked user gets no way to identify the owning session.
  reason: Accurate but not a defect. PID and connection time are still reported and are enough to find the process; naming init would identify nothing. Deliberately not falling back to the parent's argv, which is where a useful-looking hint would have to come from and which can contain tokens — that was blocker F4 in round 1.
- [round 3 B1] deferred: Any local process can bind the predictable address and impersonate occupancy without being an MCP server.
  reason: True and inherent to any same-UID lock — a process that can bind your address can also read your lock file, your socket and your home directory. It denies service rather than granting it, which is the safe direction, and the identity banner now makes an impostor visible (it cannot produce the protocol line, so the refusal reports the holder as unknown rather than pretending). Not fixable without an authenticated channel, which is out of proportion here.
- [round 3 B3] deferred: The suite covers the lock module and cross-process behaviour but not full MCP initialization, tool listing, tool rejection, or holder turnover.
  reason: Fair. Those paths ARE exercised, but by hand against the live daemon rather than in the suite — handshake, vault_status only, vault-tool rejection, and standing down for this machine's older-build holder. Worth turning into a spawned-server integration test; noted rather than done, and called out to the owner as the weakest part of the coverage.
- [round 4 F1] deferred: A rebuilt instance and a frozen pre-socket instance can both serve if they interleave around the old build's non-atomic pid-file check and write.
  reason: Confirmed, and NOT FIXABLE FROM THIS REPOSITORY. The race lives in code already installed elsewhere: an older build does existsSync, then readFile, then writeFile with no atomicity, and nothing a new build does can make another process's check-then-write atomic. Binding first and honouring the pid file narrows the window but cannot close it. The actual remedy is to stop having two versions — which is what publishing this and updating the frozen copies achieves. Raised to the owner explicitly rather than closed, because it means the invariant is not fully restored box-wide until every copy is updated.
- [round 6 F3] rejected: the tool API does not match the spec's vault_ssh_exec(entry_id, host, argv[], purpose)
  reason: the spec is stale, not the code. That exact signature IS round 1's F2 bug — an argv carrying its own destination alongside an advisory host field. Changing the API was the fix. Updating SPEC.md to match rather than reintroducing the vulnerability.
