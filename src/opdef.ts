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
const CREDENTIAL_MANAGEMENT = /(^|[/_-])(tokens?|keys?|credentials?|secrets?|passwords?|oauth|authorize|sessions?)([/_-]|$)/i;

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

function cacheKeyFor(entryId: string, salt: Buffer, plaintext: Uint8Array): string {
  const pt = createHash('sha256').update(Buffer.from(plaintext)).digest('base64');
  return `${entryId}:${salt.toString('base64')}:${pt}`;
}

export function deriveOpKey(entryId: string, plaintext: Uint8Array, salt: Buffer): Buffer {
  const k = cacheKeyFor(entryId, salt, plaintext);
  const hit = derivedKeys.get(k);
  if (hit) return hit;
  const derived = pbkdf2Sync(Buffer.from(plaintext), salt, PBKDF2_ITERATIONS, 32, 'sha256');
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
