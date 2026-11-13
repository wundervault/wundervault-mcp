/**
 * vault_send_secret (SPEC-send-a-secret-to-a-service, revision 2): put vaulted secrets into
 * Cloudflare Worker secrets without the agent seeing them.
 *
 * The agent names a list of (value secret, Worker, NAME) in one Cloudflare account and the
 * key that signs the requests. The owner approves the list once; each item is then remembered
 * in the SIGNING KEY's sealed policy, so sending it again asks nothing. The value goes into
 * the request body only at the moment of sending; every hash, approval and log line sees a
 * placeholder instead.
 *
 * Everything here is pure: the checks and the approval shapes. BrokerOps.sendSecrets runs it.
 */
import { createHash } from 'node:crypto';
import { canonicalJson } from './opdef.js';

export const CLOUDFLARE_ORIGIN = 'https://api.cloudflare.com:443';
export const MAX_ITEMS = 20;
/** Cloudflare's limit for one Worker secret (Workers limits: environment variable size, 5 KB). */
export const MAX_VALUE_BYTES = 5 * 1024;

const ACCOUNT = /^[0-9a-f]{32}$/;
/** A Worker's name: letters, digits, - and _, not starting or ending with -, up to 63. */
const WORKER = /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/;
/** The name the Worker's code reads it by (env.NAME). */
const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const ENTRY = /^[A-Za-z0-9_-]{1,64}$/;

export interface SendItem { secret: string; worker: string; name: string }
export interface SendList { using: string; account: string; items: SendItem[] }

export type Checked = { ok: true; list: SendList } | { ok: false; reason: string };

/** The agent's arguments, checked before anything is fetched. Extra fields are refused, never ignored. */
export function checkSendArgs(raw: { using?: unknown; account?: unknown; items?: unknown }): Checked {
  const using = raw.using, account = raw.account, items = raw.items;
  if (typeof using !== 'string' || !ENTRY.test(using)) return { ok: false, reason: 'using must be the vault entry id of the Cloudflare key that signs the requests' };
  if (typeof account !== 'string' || !ACCOUNT.test(account)) return { ok: false, reason: 'account must be the Cloudflare account id: 32 characters, 0-9 and a-f' };
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_ITEMS) return { ok: false, reason: `items must be a list of 1 to ${MAX_ITEMS}` };
  const out: SendItem[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < items.length; i++) {
    const it = items[i] as Record<string, unknown>;
    if (!it || typeof it !== 'object' || Array.isArray(it)) return { ok: false, reason: `items[${i}] must be {secret, worker, name}` };
    const extra = Object.keys(it).filter((k) => k !== 'secret' && k !== 'worker' && k !== 'name');
    if (extra.length) return { ok: false, reason: `items[${i}] has ${extra.join(', ')}, which is not accepted` };
    if (typeof it.secret !== 'string' || !ENTRY.test(it.secret)) return { ok: false, reason: `items[${i}].secret must be a vault entry id` };
    if (typeof it.worker !== 'string' || !WORKER.test(it.worker)) return { ok: false, reason: `items[${i}].worker must be a Worker's name (letters, digits, - and _)` };
    if (typeof it.name !== 'string' || !NAME.test(it.name)) return { ok: false, reason: `items[${i}].name must be a name the Worker's code reads (letters, digits and _, not starting with a digit)` };
    if (it.secret === using) return { ok: false, reason: `items[${i}] would send the signing key itself, which is never sent` };
    const where = `${it.worker}\u0000${it.name}`;
    if (seen.has(where)) return { ok: false, reason: `items[${i}] sets ${it.name} in ${it.worker} a second time` };
    seen.add(where);
    out.push({ secret: it.secret, worker: it.worker, name: it.name });
  }
  return { ok: true, list: { using, account, items: out } };
}

/** What one item's approval commits to. The owner's page builds the same object to hash. */
export function itemRecipe(account: string, it: SendItem, origin = CLOUDFLARE_ORIGIN): Record<string, unknown> {
  return { type: 'worker_secret', v: 1, origin, account, worker: it.worker, name: it.name, entry_id: it.secret };
}

export function itemSha(account: string, it: SendItem, origin = CLOUDFLARE_ORIGIN): string {
  return createHash('sha256').update(canonicalJson(itemRecipe(account, it, origin))).digest('hex');
}

/**
 * "Ask me first" values on this card (R11): their entry ids, sorted, and a fresh `send` nonce so the
 * card is never one the owner already approved. Absent when every value runs without asking, so a
 * tier-1 card hashes exactly as it did before.
 */
export interface AskEachTime { ids: string[]; send: string }

/** The card: the items needing approval, in a fixed order so the same ask hashes the same. */
export function listRecipe(account: string, items: SendItem[], origin = CLOUDFLARE_ORIGIN, ask?: AskEachTime): Record<string, unknown> {
  const sorted = [...items].sort((a, b) => (a.worker + '\u0000' + a.name).localeCompare(b.worker + '\u0000' + b.name));
  return {
    type: 'worker_secrets', v: 1, origin, account,
    items: sorted.map((it) => ({ entry_id: it.secret, worker: it.worker, name: it.name })),
    ...(ask && ask.ids.length ? { ask_each_time: [...new Set(ask.ids)].sort(), send: ask.send } : {}),
  };
}

export function listSha(account: string, items: SendItem[], origin = CLOUDFLARE_ORIGIN, ask?: AskEachTime): string {
  return createHash('sha256').update(canonicalJson(listRecipe(account, items, origin, ask))).digest('hex');
}

/** Words for the card. Names come from the helper's own reads; the owner's page resolves them again itself. */
export function describeList(account: string, items: SendItem[], names: Map<string, string>, signer: string, askEach: Set<string> = new Set()): string {
  const lines = items.map((it) => `${names.get(it.secret) ?? 'a secret'} -> ${it.name} in Worker ${it.worker}${askEach.has(it.secret) ? ' (asks every time)' : ''}`);
  return `Put ${items.length === 1 ? 'a secret' : `${items.length} secrets`} into Cloudflare Worker settings `
    + `(account ${account}), as encrypted secrets, signed with "${signer}": ${lines.join('; ')}.`;
}

/** The PUT that sets one secret. The value is the placeholder here; it is put in only at sending. */
export function itemRequest(account: string, it: SendItem, placeholder: string, origin = CLOUDFLARE_ORIGIN): {
  origin: { scheme: 'https'; host: string; port: number }; method: 'PUT'; path: string;
  body: { name: string; text: string; type: 'secret_text' };
} {
  return {
    origin: { scheme: 'https', host: new URL(origin).hostname, port: Number(new URL(origin).port || 443) },
    method: 'PUT',
    path: `/client/v4/accounts/${account}/workers/scripts/${it.worker}/secrets`,
    body: { name: it.name, text: placeholder, type: 'secret_text' },
  };
}

/** Cloudflare's error codes and messages only, short. The caller cuts every form of both secrets first. */
export function cloudflareErrors(body: unknown): Array<{ code?: number; message: string }> {
  const errs = (body && typeof body === 'object' && Array.isArray((body as { errors?: unknown }).errors))
    ? (body as { errors: unknown[] }).errors : [];
  return errs.slice(0, 3).flatMap((e) => {
    if (!e || typeof e !== 'object') return [];
    const m = (e as { message?: unknown }).message;
    const c = (e as { code?: unknown }).code;
    if (typeof m !== 'string') return [];
    // Not cut short here: the caller removes every form of the secrets first, THEN shortens (review R11 r1 F3).
    return [{ ...(typeof c === 'number' && Number.isFinite(c) ? { code: c } : {}), message: m.slice(0, 20000) }];
  });
}
