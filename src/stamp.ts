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
 * See SPEC-1.0-signing.md §F.
 */
import { createHash, createHmac } from 'node:crypto';
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

export type Recipe = HmacRecipe | AwsRecipe;

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
  if (r.builtin !== undefined) {
    if (r.builtin !== 'aws-sigv4') return bad(`unknown builtin ${String(r.builtin).slice(0, 32)} (known: aws-sigv4)`);
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
}

export interface StampResult {
  headers: Record<string, string>;
  /** `name=value` pairs to append to the query, already encoded. */
  query: string[];
  /** The stamp itself, to scrub from the reply. */
  stamp: string;
}

/**
 * A stamped entry's value: the secret alone, or {"id":…,"secret":…}.
 *
 * Something that is JSON-shaped but not exactly that shape is REFUSED, never used whole: a
 * key stored as {"id":…,"secret":…,"extra":1} signed with the entire JSON text as its MAC key
 * would send a stamp the service rejects, or worse, one it accepts for a key nobody meant
 * (round 1, F1).
 */
export function parseStampedValue(value: string): { id?: string; secret: string } {
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
 * Compute the stamp for one request. The ONLY function here that receives the secret, and
 * it uses it as a MAC key and nothing else.
 */
export function computeStamp(recipe: Recipe, img: RequestImage, value: { id?: string; secret: string }, now = new Date()): StampResult {
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
