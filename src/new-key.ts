/**
 * Keys a service hands back when you ask it to make one (SPEC-helper-fetch-and-save).
 *
 * A "make me a key" call is the one web call whose ANSWER is a secret. Passed through
 * `vault_call` the new key lands in the agent's transcript before it ever reaches the vault.
 * So the helper knows, per service, which address makes keys and where in the answer the key
 * sits. Those recipes are OURS: they ship in this file, an agent cannot name the field, and
 * nothing the server sends can add or change one.
 *
 *   vault_new_key  -> the address must match a recipe EXACTLY; the key goes to the vault,
 *                     the agent gets only the recipe's allow-listed fields.
 *   vault_call     -> an address that even LOOSELY matches a recipe is refused, so the old
 *                     leak is not one tool away.
 */
import fs from 'node:fs';
import path from 'node:path';

export interface NewKeyRecipe {
  /** Unique; shown in the activity log. */
  id: string;
  /** Catalogue service id (the vault page sets the new secret up from it). */
  service: string;
  /** What the owner reads: "Resend". */
  service_name: string;
  origin: { scheme: 'https'; host: string; port: number };
  method: 'POST' | 'PUT';
  /** The address replaces an existing key's value in place: the old value stops working at once. */
  rolls?: boolean;
  /** Path segments; '*' stands for exactly one id-like segment. */
  path: string[];
  /** Where the new key is in the JSON answer. */
  secret: string[];
  /** Fields that are safe to show the agent and the owner. Never the secret's own path. */
  info: Record<string, string[]>;
}

/**
 * Each checked against the service's own API reference (see RECIPES-new-key.md for the page
 * and the date). One we cannot confirm stays out.
 */
export const BUILTIN_RECIPES: readonly NewKeyRecipe[] = Object.freeze([
  {
    id: 'resend.api-key', service: 'resend', service_name: 'Resend',
    origin: { scheme: 'https', host: 'api.resend.com', port: 443 }, method: 'POST',
    path: ['api-keys'], secret: ['token'], info: { id: ['id'] },
  },
  {
    id: 'cloudflare.user-token', service: 'cloudflare', service_name: 'Cloudflare',
    origin: { scheme: 'https', host: 'api.cloudflare.com', port: 443 }, method: 'POST',
    path: ['client', 'v4', 'user', 'tokens'], secret: ['result', 'value'],
    info: { id: ['result', 'id'], name: ['result', 'name'], status: ['result', 'status'], expires_on: ['result', 'expires_on'] },
  },
  {
    id: 'cloudflare.account-token', service: 'cloudflare', service_name: 'Cloudflare',
    origin: { scheme: 'https', host: 'api.cloudflare.com', port: 443 }, method: 'POST',
    path: ['client', 'v4', 'accounts', '*', 'tokens'], secret: ['result', 'value'],
    info: { id: ['result', 'id'], name: ['result', 'name'], status: ['result', 'status'], expires_on: ['result', 'expires_on'] },
  },
  // Rolling a token in place: the answer is the new value itself (SPEC-key-rotation R6).
  {
    id: 'cloudflare.user-token-roll', service: 'cloudflare', service_name: 'Cloudflare', rolls: true,
    origin: { scheme: 'https', host: 'api.cloudflare.com', port: 443 }, method: 'PUT',
    path: ['client', 'v4', 'user', 'tokens', '*', 'value'], secret: ['result'], info: {},
  },
  {
    id: 'cloudflare.account-token-roll', service: 'cloudflare', service_name: 'Cloudflare', rolls: true,
    origin: { scheme: 'https', host: 'api.cloudflare.com', port: 443 }, method: 'PUT',
    path: ['client', 'v4', 'accounts', '*', 'tokens', '*', 'value'], secret: ['result'], info: {},
  },
  {
    id: 'sendgrid.api-key', service: 'sendgrid', service_name: 'SendGrid',
    origin: { scheme: 'https', host: 'api.sendgrid.com', port: 443 }, method: 'POST',
    path: ['v3', 'api_keys'], secret: ['api_key'], info: { id: ['api_key_id'], name: ['name'] },
  },
  {
    id: 'openai.admin-key', service: 'openai', service_name: 'OpenAI',
    origin: { scheme: 'https', host: 'api.openai.com', port: 443 }, method: 'POST',
    path: ['v1', 'organization', 'admin_api_keys'], secret: ['value'],
    info: { id: ['id'], name: ['name'], created_at: ['created_at'] },
  },
  {
    id: 'openai.service-account', service: 'openai', service_name: 'OpenAI',
    origin: { scheme: 'https', host: 'api.openai.com', port: 443 }, method: 'POST',
    path: ['v1', 'organization', 'projects', '*', 'service_accounts'], secret: ['api_key', 'value'],
    info: { id: ['id'], name: ['name'], key_id: ['api_key', 'id'], created_at: ['created_at'] },
  },
  {
    id: 'twilio.api-key', service: 'twilio', service_name: 'Twilio',
    origin: { scheme: 'https', host: 'api.twilio.com', port: 443 }, method: 'POST',
    path: ['2010-04-01', 'Accounts', '*', 'Keys.json'], secret: ['secret'],
    info: { id: ['sid'], name: ['friendly_name'], created: ['date_created'] },
  },
  {
    id: 'openrouter.key', service: 'openrouter', service_name: 'OpenRouter',
    origin: { scheme: 'https', host: 'openrouter.ai', port: 443 }, method: 'POST',
    path: ['api', 'v1', 'keys'], secret: ['key'],
    info: { id: ['data', 'hash'], name: ['data', 'name'], created_at: ['data', 'created_at'] },
  },
] as NewKeyRecipe[]);

const ID_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_SEGMENT = /^[A-Za-z0-9._-]{1,64}$/;
const NAME = /^[A-Za-z0-9_]{1,32}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Why a recipe is not acceptable, or null. Used on the built-in list by a test, and on any list a test injects. */
export function recipeProblem(r: NewKeyRecipe, allowLoopback = false): string | null {
  if (!r || typeof r !== 'object') return 'not an object';
  if (typeof r.id !== 'string' || !/^[a-z0-9.-]{1,64}$/.test(r.id)) return 'id';
  if (typeof r.service !== 'string' || !/^[a-z0-9-]{1,40}$/.test(r.service)) return 'service';
  if (typeof r.service_name !== 'string' || !r.service_name || r.service_name.length > 40) return 'service_name';
  const o = r.origin;
  if (!o || o.scheme !== 'https' || !Number.isInteger(o.port) || o.port < 1 || o.port > 65535) return 'origin';
  if (typeof o.host !== 'string' || o.host !== o.host.toLowerCase()) return 'host';
  const hostOk = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(o.host)
    || (allowLoopback && o.host === '127.0.0.1');
  if (!hostOk) return 'host';
  if (r.method !== 'POST' && r.method !== 'PUT') return 'method';
  if (r.rolls !== undefined && typeof r.rolls !== 'boolean') return 'rolls';
  if (!Array.isArray(r.path) || r.path.length < 1 || r.path.length > 8
      || !r.path.every((s) => s === '*' || SAFE_SEGMENT.test(s))) return 'path';
  const okPath = (p: unknown): p is string[] => Array.isArray(p) && p.length >= 1 && p.length <= 4
    && p.every((k) => typeof k === 'string' && NAME.test(k) && !FORBIDDEN_KEYS.has(k));
  if (!okPath(r.secret)) return 'secret';
  if (!r.info || typeof r.info !== 'object' || Object.keys(r.info).length > 8) return 'info';
  for (const [name, p] of Object.entries(r.info)) {
    if (!NAME.test(name) || FORBIDDEN_KEYS.has(name) || !okPath(p)) return `info.${name}`;
    // Not the secret, not a parent of it (which would hand back the object holding it), not under it.
    const n = Math.min(p.length, r.secret.length);
    if (p.slice(0, n).join('\u0000') === r.secret.slice(0, n).join('\u0000')) return `info.${name} overlaps the secret`;
  }
  return null;
}

function pathOnly(raw: string): string {
  const cut = raw.search(/[?#]/);
  return cut === -1 ? raw : raw.slice(0, cut);
}

/** The exact spelling a recipe is written in: /seg/seg, nothing encoded, nothing doubled. */
function strictSegments(raw: string): string[] | null {
  const p = pathOnly(raw);
  if (!p.startsWith('/') || p.length > 512) return null;
  const segs = p.slice(1).split('/');
  return segs.every((s) => SAFE_SEGMENT.test(s) && s !== '.' && s !== '..') ? segs : null;
}

/**
 * Every spelling a web server might read as the same path: decoded (twice, for a doubly
 * encoded one), backslashes as slashes, empty and dot segments dropped, lower case, and a
 * `;param` tail cut from each segment. Deliberately over-matches: it only ever REFUSES.
 */
function looseSegments(raw: string): string[] {
  let p = pathOnly(raw);
  for (let i = 0; i < 2; i++) {
    try { p = decodeURIComponent(p); } catch { p = p.replace(/%[0-9a-fA-F]{2}/g, (m) => { try { return decodeURIComponent(m); } catch { return m; } }); }
  }
  p = pathOnly(p).replace(/\\/g, '/');
  const out: string[] = [];
  for (const seg of p.split('/')) {
    const s = seg.split(';')[0].trim().toLowerCase();
    if (s === '' || s === '.') continue;
    if (s === '..') { out.pop(); continue; }
    out.push(s);
  }
  return out;
}

function sameOrigin(r: NewKeyRecipe, o: { scheme?: unknown; host?: unknown; port?: unknown }): boolean {
  const host = String(o?.host ?? '').toLowerCase().replace(/\.$/, '');
  return String(o?.scheme ?? '').toLowerCase() === 'https' && host === r.origin.host && Number(o?.port) === r.origin.port;
}

export class NewKeyRecipes {
  constructor(private readonly list: readonly NewKeyRecipe[] = BUILTIN_RECIPES, allowLoopback = false) {
    const seen = new Set<string>();
    for (const r of list) {
      const why = recipeProblem(r, allowLoopback);
      if (why) throw new Error(`new-key recipe ${String((r as { id?: unknown })?.id)}: ${why}`);
      const where = `${r.origin.host}:${r.origin.port}/${r.path.join('/').toLowerCase()}`;
      if (seen.has(r.id) || seen.has(where)) throw new Error(`new-key recipe ${r.id}: duplicate`);
      seen.add(r.id); seen.add(where);
    }
  }

  /** For vault_new_key: the request is spelled exactly as the recipe is. */
  exact(origin: { scheme?: unknown; host?: unknown; port?: unknown }, method: string, rawPath: string): NewKeyRecipe | null {
    const m = String(method).toUpperCase();
    if (String(origin?.host ?? '') !== String(origin?.host ?? '').toLowerCase()) return null;
    const segs = strictSegments(String(rawPath ?? ''));
    if (!segs) return null;
    for (const r of this.list) {
      if (r.method !== m || !sameOrigin(r, origin) || String(origin.host) !== r.origin.host) continue;
      if (r.path.length !== segs.length) continue;
      if (r.path.every((want, i) => (want === '*' ? ID_SEGMENT.test(segs[i]) : want === segs[i]))) return r;
    }
    return null;
  }

  /** For vault_call: anything a server could take for a key-making address. Any method that writes. */
  loose(origin: { scheme?: unknown; host?: unknown; port?: unknown }, method: string, rawPath: string): NewKeyRecipe | null {
    const m = String(method).toUpperCase();
    if (m === 'GET' || m === 'HEAD' || m === 'DELETE' || m === 'OPTIONS') return null;
    const segs = looseSegments(String(rawPath ?? ''));
    for (const r of this.list) {
      if (!sameOrigin(r, origin)) continue;
      if (r.path.length !== segs.length) continue;
      if (r.path.every((want, i) => want === '*' || want.toLowerCase() === segs[i])) return r;
    }
    return null;
  }
}

export const MAX_NEW_KEY_BYTES = 16 * 1024;

function dig(body: unknown, p: string[]): unknown {
  let at: unknown = body;
  for (const k of p) {
    if (!at || typeof at !== 'object' || Array.isArray(at) || !Object.hasOwn(at as object, k)) return undefined;
    at = (at as Record<string, unknown>)[k];
  }
  return at;
}

/** The spellings of the new key that must never reach the agent. Longest first. */
export function newKeyForms(value: string): string[] {
  const b = Buffer.from(value, 'utf8');
  const every = [...b].map((x) => `%${x.toString(16).padStart(2, '0').toUpperCase()}`).join('');
  const lowerEscapes = (s: string) => s.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());
  const forms = new Set<string>([
    value, JSON.stringify(value).slice(1, -1),
    // Percent-encoded: as a browser writes it, with lower-case escapes, and with every byte escaped.
    encodeURIComponent(value), lowerEscapes(encodeURIComponent(value)), every, every.toLowerCase(),
    b.toString('base64'), b.toString('base64').replace(/=+$/, ''), b.toString('base64url'),
    b.toString('hex'), b.toString('hex').toUpperCase(),
  ]);
  return [...forms].filter((f) => f.length >= 4).sort((a, c) => c.length - a.length);
}

/** Percent-decoding that never throws: what a reader could turn the text back into. */
function decoded(text: string): string {
  let out = text;
  for (let i = 0; i < 2; i++) {
    const next = out.replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => { try { return decodeURIComponent(m); } catch { return m; } });
    if (next === out) break;
    out = next;
  }
  return out;
}

/**
 * Does this text carry the key in any spelling we know? Checked as written, percent-decoded
 * (so a mixed-case or partly escaped copy is caught: review r1 F1), and without regard to case
 * for the hex and percent spellings.
 */
export function carriesKey(text: string, value: string, forms: readonly string[] = newKeyForms(value)): boolean {
  if (!text) return false;
  const lower = text.toLowerCase();
  if (decoded(text).includes(value) || decoded(text.replace(/\+/g, ' ')).includes(value)) return true;
  return forms.some((f) => text.includes(f) || (/^(?:%[0-9a-f]{2})+$|^[0-9a-f]+$/i.test(f) && lower.includes(f.toLowerCase())));
}

export function cutForms(text: string, forms: readonly string[]): string {
  let out = text;
  for (const f of forms) out = out.split(f).join('[REMOVED]');
  return out;
}

/**
 * Take the new key out of a service's answer. Returns the key and ONLY the allow-listed
 * fields (short text, numbers, true/false), each with the key's own text cut from it.
 */
export function readNewKey(recipe: NewKeyRecipe, body: unknown):
  { ok: true; value: string; info: Record<string, string | number | boolean> } | { ok: false } {
  const value = dig(body, recipe.secret);
  if (typeof value !== 'string' || value.length < 8 || Buffer.byteLength(value, 'utf8') > MAX_NEW_KEY_BYTES
      || value.trim() !== value) return { ok: false };
  const forms = newKeyForms(value);
  const info: Record<string, string | number | boolean> = {};
  for (const [name, p] of Object.entries(recipe.info)) {
    const v = dig(body, p);
    // A field that carries the key (in any spelling) is dropped whole, never patched: a number
    // too (a key made of digits could equal an id; review r1 F2).
    if (typeof v === 'number' && Number.isFinite(v)) { if (!carriesKey(String(v), value, forms)) info[name] = v; }
    else if (typeof v === 'boolean') info[name] = v;
    else if (typeof v === 'string' && v.length <= 200 && !carriesKey(v, value, forms)) info[name] = v;
  }
  return { ok: true, value, info };
}

// ── the outbox: a made key that could not be delivered yet ──────────────────────────────

export interface OutboxItem {
  id: string;
  agent_id: string;
  /** So the vault can take the key even after its slot lapsed. */
  name_mac?: string;
  /** Already locked with the agent's vault key: this file holds no readable secret. */
  ciphertext: string;
  nonce: string;
  made_at: string;
}

const ITEM_ID = /^[A-Za-z0-9_-]{22,64}$/;

/** One small file per undelivered key, in a folder only the helper's account can open. */
export class NewKeyOutbox {
  constructor(private readonly dir: string) {}

  private file(id: string): string {
    if (!ITEM_ID.test(id)) throw new Error('bad id');
    return path.join(this.dir, `${id}.json`);
  }

  put(item: OutboxItem): void {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const tmp = `${this.file(item.id)}.tmp`;
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.writeFileSync(fd, JSON.stringify(item));
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, this.file(item.id));
    // The folder too, so the name survives a power cut (review r2 B5). Not every system allows it.
    try { const d = fs.openSync(this.dir, 'r'); try { fs.fsyncSync(d); } finally { fs.closeSync(d); } } catch { /* best effort */ }
  }

  /** Anything at all waiting here? One directory read, for the common "nothing" case. */
  any(): boolean {
    try { return fs.readdirSync(this.dir).some((n) => n.endsWith('.json') || n.endsWith('.json.tmp')); } catch { return false; }
  }

  remove(id: string): void {
    try { fs.unlinkSync(this.file(id)); } catch { /* already gone */ }
  }

  list(agentId: string): OutboxItem[] {
    let names: string[];
    try { names = fs.readdirSync(this.dir); } catch { return []; }
    // A helper stopped between writing a file and giving it its name: a complete one is the only
    // copy of a made key, so it is taken up (review r1 B3); a half-written one cannot be read.
    for (const n of names) {
      if (!n.endsWith('.json.tmp') || !ITEM_ID.test(n.slice(0, -9)) || names.includes(n.slice(0, -4))) continue;
      try {
        const j = JSON.parse(fs.readFileSync(path.join(this.dir, n), 'utf8')) as OutboxItem;
        if (j && j.id === n.slice(0, -9) && typeof j.ciphertext === 'string') fs.renameSync(path.join(this.dir, n), path.join(this.dir, n.slice(0, -4)));
      } catch { /* half-written */ }
    }
    try { names = fs.readdirSync(this.dir); } catch { return []; }
    const out: OutboxItem[] = [];
    for (const n of names.sort()) {
      if (!n.endsWith('.json') || !ITEM_ID.test(n.slice(0, -5))) continue;
      try {
        const j = JSON.parse(fs.readFileSync(path.join(this.dir, n), 'utf8')) as OutboxItem;
        if (j && j.id === n.slice(0, -5) && j.agent_id === agentId
            && typeof j.ciphertext === 'string' && typeof j.nonce === 'string') out.push(j);
      } catch { /* unreadable: left for a person */ }
    }
    return out;
  }
}
