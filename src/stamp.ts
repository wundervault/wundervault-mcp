/**
 * Stamped requests: the key never travels; each request carries a code computed from it.
 *
 * The agent describes HOW to stamp, per call, as a recipe built from fixed pieces — because
 * every service stamps differently and no table of services would keep up. What the agent
 * cannot do, whatever recipe it writes, is reach the key: the secret is accepted in exactly
 * one place, as the MAC key (or the root of AWS's signing-key chain), and there is no part,
 * placement or option that reads it as data. That is the whole safety argument, and
 * `computeStamp` is the only function in this file that is handed the secret.
 *
 * The owner approves each (recipe, address) pair once; that lives in the policy (wallet.ts).
 *
 * Two schemes are named built-ins instead, because no recipe can express them: AWS SigV4 (a
 * signing-key chain) and OAuth 1.0a (SHA-1, a fresh nonce and timestamp in every request, and
 * four stored values). The same rule holds for both: the secrets are MAC keys and nothing else.
 *
 * See SPEC-1.0-signing.md §F and SPEC-oauth1-2026-10-29.md.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { canonicalJson } from './opdef.js';

export type MacAlg = 'hmac-sha256' | 'hmac-sha384' | 'hmac-sha512';
type Var = 'method' | 'path' | 'query' | 'path_and_query' | 'body' | 'host' | 'key_id' | 'body_json';

export type Part =
  | { text: string }
  | { var: Var }
  | { header: string }
  | { body_field: string }
  | { sha256: Part[] }
  | { sha512: Part[] }
  | { sha256_hex: Part[] }
  | { json: Record<string, Part> };

export interface Placement { in: 'header' | 'query'; name: string; value: string }

export interface HmacRecipe {
  mac: MacAlg;
  key: 'utf8' | 'base64' | 'hex';
  message: Part[];
  encoding: 'hex' | 'base64' | 'base64url';
  place: Placement[];
}

export interface AwsRecipe {
  builtin: 'aws-sigv4';
  region: string;
  service: string;
  /** Add and sign x-amz-content-sha256. Default: on for s3, off otherwise. */
  content_sha256_header?: boolean;
}

/** OAuth 1.0a (RFC 5849), signed fresh for every request (SPEC-oauth1). */
export interface OAuth1Recipe {
  builtin: 'oauth1';
  /** Always present once checked, so the default and the explicit default hash the same. */
  signature_method: 'HMAC-SHA1' | 'HMAC-SHA256';
  realm?: string;
}

export type Recipe = HmacRecipe | AwsRecipe | OAuth1Recipe;

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;
const QUERY_NAME = /^[A-Za-z0-9_.\-[\]]{1,64}$/;
const VARS: ReadonlySet<string> = new Set(['method', 'path', 'query', 'path_and_query', 'body', 'host', 'key_id', 'body_json']);
/** Headers a stamp may never be placed in: framing, routing, and the broker's own. */
const NOT_PLACEABLE: ReadonlySet<string> = new Set([
  'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade', 'te', 'trailer',
  'proxy-authorization', 'cookie', 'set-cookie', 'expect', 'keep-alive', 'accept-encoding',
  'content-encoding', 'content-type', 'user-agent',
]);
const MAX_PARTS = 32;
const MAX_DEPTH = 3;

export type RecipeCheck = { ok: true; recipe: Recipe } | { ok: false; reason: string };

function printableText(s: string): boolean {
  return /^[\x20-\x7e\n]*$/.test(s);
}

/** Every key and value checked; nothing unknown passes, nothing is repaired. */
export function validateRecipe(raw: unknown): RecipeCheck {
  const bad = (reason: string): RecipeCheck => ({ ok: false, reason });
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return bad('stamp must be an object');
  const r = raw as Record<string, unknown>;
  if (r.builtin === 'oauth1') {
    const extra = Object.keys(r).filter((k) => !['builtin', 'signature_method', 'realm'].includes(k));
    if (extra.length) return bad(`unknown fields ${extra.join(', ')}`);
    // Only an ABSENT field takes the default: null is a value, and not one of the two (round 1, F1).
    const method = r.signature_method === undefined ? 'HMAC-SHA1' : r.signature_method;
    // PLAINTEXT sends the secret itself; RSA-SHA1 is not offered.
    if (method !== 'HMAC-SHA1' && method !== 'HMAC-SHA256') return bad('signature_method must be HMAC-SHA1 or HMAC-SHA256');
    if (r.realm !== undefined && (typeof r.realm !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(r.realm))) {
      return bad('realm must be letters, digits, _ . - (64 at most)');
    }
    return { ok: true, recipe: {
      builtin: 'oauth1', signature_method: method,
      ...(r.realm !== undefined ? { realm: r.realm as string } : {}),
    } };
  }
  if (r.builtin !== undefined) {
    if (r.builtin !== 'aws-sigv4') return bad(`unknown builtin ${String(r.builtin).slice(0, 32)} (known: aws-sigv4, oauth1)`);
    const extra = Object.keys(r).filter((k) => !['builtin', 'region', 'service', 'content_sha256_header'].includes(k));
    if (extra.length) return bad(`unknown fields ${extra.join(', ')}`);
    if (typeof r.region !== 'string' || !/^[a-z0-9-]{2,32}$/.test(r.region)) return bad('region must be an AWS region name');
    if (typeof r.service !== 'string' || !/^[a-z0-9-]{1,32}$/.test(r.service)) return bad('service must be an AWS service name');
    if (r.content_sha256_header !== undefined && typeof r.content_sha256_header !== 'boolean') {
      return bad('content_sha256_header must be true or false');
    }
    return { ok: true, recipe: {
      builtin: 'aws-sigv4', region: r.region, service: r.service,
      ...(r.content_sha256_header !== undefined ? { content_sha256_header: r.content_sha256_header as boolean } : {}),
    } };
  }
  const extra = Object.keys(r).filter((k) => !['mac', 'key', 'message', 'encoding', 'place'].includes(k));
  if (extra.length) return bad(`unknown fields ${extra.join(', ')}`);
  if (!['hmac-sha256', 'hmac-sha384', 'hmac-sha512'].includes(r.mac as string)) return bad('mac must be hmac-sha256, hmac-sha384 or hmac-sha512');
  if (!['utf8', 'base64', 'hex'].includes(r.key as string)) return bad('key must be utf8, base64 or hex');
  if (!['hex', 'base64', 'base64url'].includes(r.encoding as string)) return bad('encoding must be hex, base64 or base64url');
  if (!Array.isArray(r.message) || r.message.length === 0) return bad('message must be a non-empty list of parts');

  let count = 0;
  const headersRead = new Set<string>();
  const checkPart = (p: unknown, depth: number): string | null => {
    if (++count > MAX_PARTS) return `at most ${MAX_PARTS} parts`;
    if (depth > MAX_DEPTH) return `parts nest at most ${MAX_DEPTH} deep`;
    if (!p || typeof p !== 'object' || Array.isArray(p)) return 'a part must be an object';
    const keys = Object.keys(p);
    if (keys.length !== 1) return 'a part has exactly one kind';
    const k = keys[0];
    const v = (p as Record<string, unknown>)[k];
    switch (k) {
      case 'text':
        return typeof v === 'string' && v.length <= 256 && printableText(v) ? null : 'text must be printable, 256 characters at most';
      case 'var':
        return typeof v === 'string' && VARS.has(v) ? null : `var must be one of ${[...VARS].join(', ')}`;
      case 'header':
        if (typeof v !== 'string' || !HEADER_NAME.test(v)) return 'header must be a header name';
        headersRead.add(v.toLowerCase());
        return null;
      case 'body_field':
        return typeof v === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(v) ? null : 'body_field must be a field name';
      case 'sha256': case 'sha512': case 'sha256_hex':
        if (!Array.isArray(v) || v.length === 0) return `${k} takes a non-empty list of parts`;
        for (const q of v) { const e = checkPart(q, depth + 1); if (e) return e; }
        return null;
      case 'json': {
        if (!v || typeof v !== 'object' || Array.isArray(v)) return 'json takes an object of name: part';
        const entries = Object.entries(v as Record<string, unknown>);
        if (entries.length === 0 || entries.length > 16) return 'json takes 1 to 16 fields';
        for (const [name, q] of entries) {
          if (!/^[A-Za-z0-9_.-]{1,64}$/.test(name)) return 'json field names are letters, digits, _ . -';
          const e = checkPart(q, depth + 1);
          if (e) return e;
        }
        return null;
      }
      default:
        return `unknown part ${k.slice(0, 32)}`;
    }
  };
  for (const p of r.message) { const e = checkPart(p, 1); if (e) return bad(e); }

  if (!Array.isArray(r.place) || r.place.length === 0 || r.place.length > 3) return bad('place must list 1 to 3 placements');
  let stamped = false;
  const placed = new Set<string>();
  const place: Placement[] = [];
  for (const raw of r.place) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return bad('a placement must be an object');
    const pl = raw as Record<string, unknown>;
    if (Object.keys(pl).some((k) => !['in', 'name', 'value'].includes(k))) return bad('a placement has in, name and value only');
    if (pl.in !== 'header' && pl.in !== 'query') return bad("a placement goes in 'header' or 'query'");
    if (typeof pl.name !== 'string') return bad('a placement needs a name');
    if (pl.in === 'header') {
      if (!HEADER_NAME.test(pl.name)) return bad('not a valid header name');
      const lower = pl.name.toLowerCase();
      if (NOT_PLACEABLE.has(lower) || lower.startsWith('proxy-')) return bad(`a stamp cannot go in the ${lower} header`);
      // A stamp read from the header it is written into has no defined value.
      if (headersRead.has(lower)) return bad(`the recipe both reads and writes the ${lower} header`);
      if (placed.has(`h:${lower}`)) return bad(`${lower} is placed twice`);
      placed.add(`h:${lower}`);
    } else {
      if (!QUERY_NAME.test(pl.name)) return bad('not a valid query parameter name');
      if (placed.has(`q:${pl.name}`)) return bad(`${pl.name} is placed twice`);
      placed.add(`q:${pl.name}`);
    }
    if (typeof pl.value !== 'string' || pl.value.length > 256 || !/^[\x20-\x7e]*$/.test(pl.value)) {
      return bad('a placement value is printable text, 256 characters at most');
    }
    // Only these two placeholders exist. Anything else in braces is refused, so a later
    // edit that adds a third placeholder cannot quietly become a way to reach the key.
    const rest = pl.value.replace(/\{stamp\}|\{key_id\}/g, '');
    if (/[{}]/.test(rest)) return bad('a placement value may contain {stamp} and {key_id} only');
    if (pl.value.includes('{stamp}')) stamped = true;
    place.push({ in: pl.in, name: pl.in === 'header' ? pl.name.toLowerCase() : pl.name, value: pl.value });
  }
  if (!stamped) return bad('no placement contains {stamp}');
  return { ok: true, recipe: {
    mac: r.mac as MacAlg, key: r.key as HmacRecipe['key'], message: r.message as Part[],
    encoding: r.encoding as HmacRecipe['encoding'], place,
  } };
}

/** What the owner approves: sha256 of the recipe's canonical JSON. */
export function recipeSha256(recipe: Recipe): string {
  return createHash('sha256').update(canonicalJson(recipe)).digest('hex');
}

/** The recipe in words, for the approval card. Built from the checked recipe only. */
export function describeRecipe(recipe: Recipe): string {
  if ('builtin' in recipe && recipe.builtin === 'oauth1') {
    return `OAuth 1.0a (${recipe.signature_method}), signed fresh for every request, in the Authorization header`
      + (recipe.realm ? `, realm ${recipe.realm}` : '');
  }
  if ('builtin' in recipe) return `AWS Signature Version 4 (region ${recipe.region}, service ${recipe.service})`;
  const part = (p: Part): string => {
    if ('text' in p) return JSON.stringify(p.text);
    if ('var' in p) return p.var;
    if ('header' in p) return `header ${p.header}`;
    if ('body_field' in p) return `body field ${p.body_field}`;
    if ('sha256' in p) return `sha256(${p.sha256.map(part).join(' + ')})`;
    if ('sha512' in p) return `sha512(${p.sha512.map(part).join(' + ')})`;
    if ('sha256_hex' in p) return `sha256-hex(${p.sha256_hex.map(part).join(' + ')})`;
    return `json{${Object.entries(p.json).map(([k, q]) => `${k}: ${part(q)}`).join(', ')}}`;
  };
  const where = recipe.place.map((pl) => `${pl.in} ${pl.name}`).join(' and ');
  return `${recipe.mac.toUpperCase()} over ${recipe.message.map(part).join(' + ')}, ${recipe.encoding}, in ${where}`;
}

/** The request exactly as the broker will send it, before any placement. */
export interface RequestImage {
  method: string;
  host: string;
  /** Wire path, without the query. */
  path: string;
  /** Wire query, without the `?`; empty when there is none. */
  query: string;
  /** The body bytes as sent, or undefined for none. */
  body: string | undefined;
  /** Headers as sent, lowercased names. */
  headers: Record<string, string>;
  /** The port the request goes to; 443 when absent. OAuth 1.0a signs it when it is not 443. */
  port?: number;
}

export interface StampResult {
  headers: Record<string, string>;
  /** `name=value` pairs to append to the query, already encoded. */
  query: string[];
  /** The stamp itself, to scrub from the reply. */
  stamp: string;
  /** Further secrets to scrub from the reply, beyond the one the request was given (OAuth 1.0a). */
  scrub?: string[];
}

/** OAuth 1.0a's four stored values. */
export interface OAuth1Value {
  consumer_key: string;
  consumer_secret: string;
  token: string;
  token_secret: string;
}

/**
 * A stamped entry's value, parsed for the recipe that will use it. `secret` is what the
 * request scrubs; `oauth1` is set for the OAuth 1.0a built-in only.
 */
export interface StampedValue {
  id?: string;
  secret: string;
  oauth1?: OAuth1Value;
}

/** Each role, and the names it may be stored under: X's, the RFC's, and X's "API Key Secret". */
const OAUTH1_ROLES: ReadonlyArray<[keyof OAuth1Value, readonly string[]]> = [
  ['consumer_key', ['api_key', 'consumer_key']],
  ['consumer_secret', ['api_secret', 'api_key_secret', 'consumer_secret']],
  ['token', ['access_token', 'token']],
  ['token_secret', ['access_token_secret', 'token_secret']],
];
const OAUTH1_SHAPE = 'OAuth 1.0a needs the entry stored as {"api_key": "…", "api_secret": "…", "access_token": "…", '
  + '"access_token_secret": "…"} (X\'s names; consumer_key, consumer_secret, token and token_secret also work)';

/**
 * The four values, or a refusal that names the field names and never a value. Nothing is
 * repaired: an extra field, a missing role, two names for one role, a name given twice, or a
 * value with a space, a quote or a backslash is refused (SPEC-oauth1 §2).
 */
function parseOAuth1Value(value: string): OAuth1Value {
  const v = value.trim();
  // No escapes anywhere: the values may not hold a quote or a backslash, and the names never need
  // one. With none, every member name is spelled literally, so the count below sees them all —
  // "api_\u0073ecret" would otherwise be a second api_secret it missed (round 2, F1).
  if (v.includes('\\')) throw new Error(`${OAUTH1_SHAPE}; it contains a backslash, which none of these values has`);
  // JSON.parse keeps the LAST of two members with one name, so {"api_secret":"a",…,"api_secret":"b"}
  // would sign with b and say nothing (round 1, B3). Values cannot hold a quote, so a name
  // followed by a colon is a member wherever it appears.
  for (const [, names] of OAUTH1_ROLES) {
    for (const n of names) {
      if ((v.match(new RegExp(`"${n}"\\s*:`, 'g')) ?? []).length > 1) throw new Error(`${OAUTH1_SHAPE}; ${n} is given twice`);
    }
  }
  let o: unknown;
  try { o = v.startsWith('{') ? JSON.parse(v) : undefined; } catch { o = undefined; }
  const r = (o && typeof o === 'object' && !Array.isArray(o)) ? o as Record<string, unknown> : null;
  if (!r) throw new Error(`${OAUTH1_SHAPE}, and it is stored as something else`);
  const known = new Set(OAUTH1_ROLES.flatMap(([, names]) => names));
  const unknown = Object.keys(r).filter((k) => !known.has(k));
  // Counted, never named: a stray field name could itself be a secret pasted in the wrong place.
  if (unknown.length) throw new Error(`${OAUTH1_SHAPE}; it has ${unknown.length} field${unknown.length === 1 ? '' : 's'} that do${unknown.length === 1 ? 'es' : ''} not belong`);
  const out: Partial<OAuth1Value> = {};
  for (const [role, names] of OAUTH1_ROLES) {
    const present = names.filter((n) => n in r);
    if (present.length === 0) throw new Error(`${OAUTH1_SHAPE}; ${names[0]} is missing`);
    if (present.length > 1) throw new Error(`${OAUTH1_SHAPE}; ${present.join(' and ')} are the same value stored twice`);
    const val = r[present[0]];
    // No quote or backslash either: a reply that is not JSON could carry a secret in its escaped
    // spelling, which no scrub of the plain one would catch (round 1, B4). No service issues them.
    if (typeof val !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]{1,512}$/.test(val)) {
      throw new Error(`${OAUTH1_SHAPE}; ${present[0]} must be text with no spaces, quotes or backslashes`);
    }
    out[role] = val;
  }
  return out as OAuth1Value;
}

/**
 * A stamped entry's value: the secret alone, or {"id":…,"secret":…}.
 *
 * Something that is JSON-shaped but not exactly that shape is REFUSED, never used whole: a
 * key stored as {"id":…,"secret":…,"extra":1} signed with the entire JSON text as its MAC key
 * would send a stamp the service rejects, or worse, one it accepts for a key nobody meant
 * (round 1, F1).
 */
/**
 * Does this value look like OAuth 1.0a's keys — a consumer secret and a token secret, by any of
 * their names? Then it is not a bearer token: sent whole it is refused by every service, and it
 * sends both secrets (round 1, B1 — the X entry that 1.0's migration made a bearer key did exactly
 * that). Recognised, not validated: a bundle with one bad value is still a bundle, and must not
 * fall back to being sent whole because it would not sign (round 2, F2).
 */
export function looksLikeOAuth1Value(value: string): boolean {
  const has = (names: readonly string[]) => names.some((n) => value.includes(`"${n}"`));
  return has(OAUTH1_ROLES[1][1]) && has(OAUTH1_ROLES[3][1]);
}

export function parseStampedValue(value: string, recipe?: Recipe): StampedValue {
  if (recipe && 'builtin' in recipe && recipe.builtin === 'oauth1') {
    const o = parseOAuth1Value(value);
    return { secret: o.consumer_secret, oauth1: o };
  }
  const v = value.trim();
  if (!v.startsWith('{')) return { secret: value };
  let o: unknown;
  try { o = JSON.parse(v); } catch { throw new Error('this stamped key is stored as something that looks like {"id", "secret"} but is not valid JSON'); }
  const r = (o && typeof o === 'object' && !Array.isArray(o)) ? o as Record<string, unknown> : null;
  if (!r || !Object.keys(r).every((k) => k === 'id' || k === 'secret') || typeof r.secret !== 'string' || !r.secret
      || (r.id !== undefined && !(typeof r.id === 'string' && r.id.length <= 256 && /^[\x20-\x7e]*$/.test(r.id)))) {
    throw new Error('this stamped key must be stored as the secret alone, or exactly {"id": "…", "secret": "…"}');
  }
  return { secret: r.secret, ...(r.id ? { id: r.id } : {}) };
}

function bodyField(img: RequestImage, name: string): string {
  if (img.body === undefined) throw new Error(`body_field ${name}: the request has no body`);
  const ct = img.headers['content-type'] ?? '';
  if (/json/i.test(ct) || /^\s*[{[]/.test(img.body)) {
    let o: unknown;
    try { o = JSON.parse(img.body); } catch { throw new Error(`body_field ${name}: the body is not JSON`); }
    const v = (o as Record<string, unknown>)?.[name];
    if (v === undefined || v === null) throw new Error(`body_field ${name}: no such field in the body`);
    return typeof v === 'string' ? v : JSON.stringify(v);
  }
  const v = new URLSearchParams(img.body).get(name);
  if (v === null) throw new Error(`body_field ${name}: no such field in the body`);
  return v;
}

/** Python's json.dumps(sort_keys=True, separators=(',', ':')): non-ASCII escaped as \\uXXXX. */
function pyJson(value: unknown): string {
  return canonicalJson(value).replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/**
 * The body parsed as JSON, or null when there is none. `{}` stays `{}`: a recipe signs the
 * body that was sent (round 1, F2). A service that wants null for an empty body — SnapTrade's
 * SDK does — gets it by sending no body.
 */
function bodyJson(img: RequestImage): unknown {
  if (img.body === undefined || img.body.trim() === '') return null;
  try { return JSON.parse(img.body); } catch { throw new Error('body_json: the body is not JSON'); }
}

function evalPart(p: Part, img: RequestImage, keyId: string | undefined): Buffer {
  if ('text' in p) return Buffer.from(p.text, 'utf8');
  if ('var' in p) {
    switch (p.var) {
      case 'method': return Buffer.from(img.method);
      case 'path': return Buffer.from(img.path);
      case 'query': return Buffer.from(img.query);
      case 'path_and_query': return Buffer.from(img.query ? `${img.path}?${img.query}` : img.path);
      case 'body': return Buffer.from(img.body ?? '', 'utf8');
      case 'host': return Buffer.from(img.host);
      case 'key_id':
        if (keyId === undefined) throw new Error('the recipe reads key_id, but this entry stores no id');
        return Buffer.from(keyId);
      case 'body_json': return Buffer.from(pyJson(bodyJson(img)));
    }
  }
  if ('header' in p) {
    const v = img.headers[p.header.toLowerCase()];
    if (v === undefined) throw new Error(`the recipe reads header ${p.header}, which the request does not send`);
    return Buffer.from(v);
  }
  if ('body_field' in p) return Buffer.from(bodyField(img, p.body_field));
  if ('sha256' in p) return createHash('sha256').update(Buffer.concat(p.sha256.map((q) => evalPart(q, img, keyId)))).digest();
  if ('sha512' in p) return createHash('sha512').update(Buffer.concat(p.sha512.map((q) => evalPart(q, img, keyId)))).digest();
  if ('sha256_hex' in p) {
    return Buffer.from(createHash('sha256').update(Buffer.concat(p.sha256_hex.map((q) => evalPart(q, img, keyId)))).digest('hex'));
  }
  // json: values are strings, except body_json which is the parsed body (or null).
  const obj: Record<string, unknown> = {};
  for (const [name, q] of Object.entries(p.json)) {
    if ('var' in q && q.var === 'body_json') {
      obj[name] = bodyJson(img);
    } else {
      obj[name] = evalPart(q, img, keyId).toString('utf8');
    }
  }
  return Buffer.from(pyJson(obj));
}

function macKey(secret: string, how: HmacRecipe['key']): Buffer {
  if (how === 'utf8') return Buffer.from(secret, 'utf8');
  if (how === 'hex') {
    if (!/^([0-9a-fA-F]{2})+$/.test(secret.trim())) throw new Error('the recipe reads the key as hex, and it is not hex');
    return Buffer.from(secret.trim(), 'hex');
  }
  const b = secret.trim();
  // Checked by round-trip, not by character set alone: "Z" is all base64 characters and
  // decodes to nothing, which would have signed with an empty key (round 2, F2).
  const norm = b.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const out = Buffer.from(norm, 'base64');
  if (!/^[A-Za-z0-9+/]+$/.test(norm) || norm.length % 4 === 1 || out.length === 0
      || out.toString('base64').replace(/=+$/, '') !== norm) {
    throw new Error('the recipe reads the key as base64, and it is not base64');
  }
  return out;
}

function encode(b: Buffer, how: HmacRecipe['encoding']): string {
  if (how === 'hex') return b.toString('hex');
  if (how === 'base64') return b.toString('base64');
  return b.toString('base64url');
}

/** RFC 3986 encoding: everything but unreserved characters. */
function uriEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function safeDecode(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}

function sha256hex(s: string | Buffer): string {
  return createHash('sha256').update(s).digest('hex');
}

/** AWS SigV4 headers that are sent but never signed (matches AWS's own signers). */
const AWS_UNSIGNED = new Set(['user-agent', 'connection', 'expect', 'transfer-encoding', 'x-amzn-trace-id', 'authorization']);

function awsSign(recipe: AwsRecipe, img: RequestImage, keyId: string, secret: string, now: Date): StampResult {
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const day = amzDate.slice(0, 8);
  const payloadHash = sha256hex(img.body ?? '');
  const added: Record<string, string> = { 'x-amz-date': amzDate };
  const wantContentHeader = recipe.content_sha256_header ?? recipe.service === 's3';
  if (wantContentHeader) added['x-amz-content-sha256'] = payloadHash;
  const all: Record<string, string> = { ...img.headers, host: img.host, ...added };
  const signed = Object.keys(all).map((k) => k.toLowerCase()).filter((k) => !AWS_UNSIGNED.has(k)).sort();
  const canonicalHeaders = signed.map((k) => `${k}:${String(all[k]).trim().replace(/\s+/g, ' ')}\n`).join('');
  const segments = img.path.split('/').map((seg) => {
    const once = uriEncode(safeDecode(seg));
    return recipe.service === 's3' ? once : uriEncode(once);
  });
  const canonicalUri = segments.join('/') || '/';
  const pairs = img.query ? img.query.split('&').filter(Boolean).map((kv) => {
    const i = kv.indexOf('=');
    const k = i < 0 ? kv : kv.slice(0, i);
    const v = i < 0 ? '' : kv.slice(i + 1);
    return [uriEncode(safeDecode(k.replace(/\+/g, ' '))), uriEncode(safeDecode(v.replace(/\+/g, ' ')))];
  }) : [];
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  const canonicalQuery = pairs.map(([k, v]) => `${k}=${v}`).join('&');
  const canonicalRequest = [img.method, canonicalUri, canonicalQuery, canonicalHeaders, signed.join(';'), payloadHash].join('\n');
  const scope = `${day}/${recipe.region}/${recipe.service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  // The secret's only appearance: the root of the signing-key chain.
  let k: Buffer = createHmac('sha256', `AWS4${secret}`).update(day).digest();
  for (const piece of [recipe.region, recipe.service, 'aws4_request']) k = createHmac('sha256', k).update(piece).digest();
  const signature = createHmac('sha256', k).update(toSign).digest('hex');
  return {
    headers: {
      ...added,
      authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signed.join(';')}, Signature=${signature}`,
    },
    query: [],
    stamp: signature,
  };
}

/**
 * Form-style pairs (`+` is a space, `%XX` a UTF-8 byte), as OAuth 1.0a reads a query or a
 * form body. A malformed escape is refused: the broker and the service would disagree about
 * what was signed (SPEC-oauth1 §6).
 */
function formPairs(s: string, where: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const seg of s.split('&')) {
    if (!seg) continue;
    const i = seg.indexOf('=');
    const raw = i < 0 ? [seg, ''] : [seg.slice(0, i), seg.slice(i + 1)];
    const [k, v] = raw.map((x) => {
      try { return decodeURIComponent(x.replace(/\+/g, ' ')); } catch {
        throw new Error(`the ${where} has a malformed % escape, so it cannot be signed`);
      }
    });
    if (/^oauth_/i.test(k)) throw new Error(`the ${where} carries ${k.slice(0, 40)}; OAuth parameters go in the Authorization header, which the broker writes`);
    out.push([k, v]);
  }
  return out;
}

export interface OAuth1Input {
  method: string;
  scheme: 'https' | 'http';
  host: string;
  port: number;
  /** Wire path, without the query. */
  path: string;
  /** Wire query, without the `?`. */
  query: string;
  /** The body, when it is application/x-www-form-urlencoded; otherwise undefined. */
  form?: string;
  /** The oauth_* parameters, without oauth_signature. */
  oauth: Record<string, string>;
  consumerSecret: string;
  tokenSecret: string;
  alg: 'HMAC-SHA1' | 'HMAC-SHA256';
}

/** RFC 5849 §3.4: the signature base string and the signature over it. */
export function oauth1Sign(input: OAuth1Input): { base: string; signature: string } {
  const defaultPort = input.scheme === 'https' ? 443 : 80;
  const uri = `${input.scheme}://${input.host.toLowerCase()}${input.port === defaultPort ? '' : `:${input.port}`}${input.path || '/'}`;
  const pairs: Array<[string, string]> = [
    ...Object.entries(input.oauth),
    ...formPairs(input.query, 'query'),
    ...(input.form !== undefined ? formPairs(input.form, 'form body') : []),
  ].map(([k, v]) => [uriEncode(k), uriEncode(v)]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  const params = pairs.map(([k, v]) => `${k}=${v}`).join('&');
  const base = [input.method.toUpperCase(), uriEncode(uri), uriEncode(params)].join('&');
  // The two secrets' only appearance: the HMAC key.
  const key = `${uriEncode(input.consumerSecret)}&${uriEncode(input.tokenSecret)}`;
  const signature = createHmac(input.alg === 'HMAC-SHA1' ? 'sha1' : 'sha256', key).update(base).digest('base64');
  return { base, signature };
}

function oauth1Stamp(recipe: OAuth1Recipe, img: RequestImage, v: OAuth1Value, now: Date, nonce: () => string): StampResult {
  const ct = (img.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  const oauth: Record<string, string> = {
    oauth_consumer_key: v.consumer_key,
    oauth_nonce: nonce(),
    oauth_signature_method: recipe.signature_method,
    oauth_timestamp: String(Math.floor(now.getTime() / 1000)),
    oauth_token: v.token,
    oauth_version: '1.0',
  };
  const { signature } = oauth1Sign({
    method: img.method, scheme: 'https', host: img.host, port: img.port ?? 443, path: img.path, query: img.query,
    form: ct === 'application/x-www-form-urlencoded' && img.body !== undefined ? img.body : undefined,
    oauth, consumerSecret: v.consumer_secret, tokenSecret: v.token_secret, alg: recipe.signature_method,
  });
  const fields = { ...oauth, oauth_signature: signature };
  const header = 'OAuth ' + [
    ...(recipe.realm ? [`realm="${recipe.realm}"`] : []),
    ...Object.keys(fields).sort().map((k) => `${k}="${uriEncode(fields[k as keyof typeof fields])}"`),
  ].join(', ');
  return {
    headers: { authorization: header },
    query: [],
    stamp: signature,
    scrub: [v.consumer_secret, v.token_secret, `${uriEncode(v.consumer_secret)}&${uriEncode(v.token_secret)}`],
  };
}

/** 32 hex characters from the CSPRNG, new for every request. */
function freshNonce(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Compute the stamp for one request. The ONLY function here that receives the secret, and
 * it uses it as a MAC key and nothing else.
 */
export function computeStamp(recipe: Recipe, img: RequestImage, value: StampedValue, now = new Date(), nonce: () => string = freshNonce): StampResult {
  if ('builtin' in recipe && recipe.builtin === 'oauth1') {
    if (!value.oauth1) throw new Error(OAUTH1_SHAPE);
    return oauth1Stamp(recipe, img, value.oauth1, now, nonce);
  }
  if ('builtin' in recipe) {
    if (!value.id) throw new Error('AWS signing needs the access key id: store the entry as {"id": "AKIA…", "secret": "…"}');
    return awsSign(recipe, img, value.id, value.secret, now);
  }
  const message = Buffer.concat(recipe.message.map((p) => evalPart(p, img, value.id)));
  const alg = recipe.mac.slice(5); // sha256 | sha384 | sha512
  const stamp = encode(createHmac(alg, macKey(value.secret, recipe.key)).update(message).digest(), recipe.encoding);
  const fill = (v: string) => v.replace(/\{stamp\}|\{key_id\}/g, (m) => {
    if (m === '{stamp}') return stamp;
    if (value.id === undefined) throw new Error('the recipe places key_id, but this entry stores no id');
    return value.id;
  });
  const headers: Record<string, string> = {};
  const query: string[] = [];
  for (const pl of recipe.place) {
    const v = fill(pl.value);
    if (pl.in === 'header') headers[pl.name] = v;
    else query.push(`${encodeURIComponent(pl.name)}=${encodeURIComponent(v)}`);
  }
  return { headers, query, stamp };
}
