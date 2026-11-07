/**
 * A first-use web approval locks both the address and the way the key is sent.
 * These objects are also hashed by the owner's page, so their shape is deliberate.
 */
import { createHash } from 'node:crypto';
import { canonicalJson } from './opdef.js';

export interface SendAs {
  in: 'header' | 'query';
  name: string;
  template: string;
}

const FORBIDDEN_HEADERS = new Set([
  'host', 'content-length', 'transfer-encoding', 'connection', 'cookie',
  'proxy-authorization', 'te', 'upgrade', 'trailer', 'keep-alive',
]);

/** One spelling for an https origin, without credentials, a path or an IPv6 literal. */
export function normalizeOrigin(o: { scheme: string; host: string; port?: number } | string): string | null {
  let scheme: string;
  let host: string;
  let port: number;
  if (typeof o === 'string') {
    const match = /^https:\/\/([a-z0-9.-]+)(?::([0-9]{1,5}))?$/i.exec(o);
    if (!match) return null;
    scheme = 'https';
    host = match[1].toLowerCase();
    port = match[2] === undefined ? 443 : Number(match[2]);
  } else {
    if (!o || typeof o !== 'object' || typeof o.scheme !== 'string' || typeof o.host !== 'string') return null;
    scheme = o.scheme.toLowerCase();
    host = o.host.toLowerCase();
    port = o.port === undefined ? 443 : o.port;
  }
  if (scheme !== 'https' || !Number.isInteger(port) || port < 1 || port > 65535
      || host.length < 1 || host.length > 253
      || !host.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return null;
  }
  // URL parsers expand alternative IPv4 spellings. Do not approve one host spelling
  // and then execute against another.
  try {
    if (new URL(`https://${host}:${port}`).hostname !== host) return null;
  } catch { return null; }
  return `https://${host}:${port}`;
}

export function validateSendAs(raw: unknown): { ok: true; sendAs: SendAs } | { ok: false; reason: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'use an object with in, name and template' };
  }
  const r = raw as Record<string, unknown>;
  if (Object.keys(r).some((key) => !['in', 'name', 'template'].includes(key))) {
    return { ok: false, reason: 'only in, name and template are allowed' };
  }
  if (r.in !== 'header' && r.in !== 'query') {
    return { ok: false, reason: 'in must be header or query' };
  }
  if (typeof r.name !== 'string' || /[\r\n]/.test(r.name)) {
    return { ok: false, reason: 'name must be text without line breaks' };
  }
  if (typeof r.template !== 'string' || r.template.length > 256 || /[\r\n]/.test(r.template)
      || r.template.split('{secret}').length !== 2) {
    return { ok: false, reason: 'template must contain {secret} exactly once, have no line breaks and be at most 256 characters' };
  }
  let name = r.name;
  if (r.in === 'header') {
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) {
      return { ok: false, reason: 'the header name must be an HTTP token' };
    }
    name = name.toLowerCase();
    if (FORBIDDEN_HEADERS.has(name)) {
      return { ok: false, reason: `the ${name} header cannot carry this key` };
    }
  } else if (!/^[A-Za-z0-9_.-]{1,64}$/.test(name)) {
    return { ok: false, reason: 'the query name must be 1–64 letters, digits, underscores, dots or hyphens' };
  }
  return { ok: true, sendAs: { in: r.in, name, template: r.template } };
}

export function placementRecipe(origin: string, sendAs: SendAs): {
  type: 'placement'; v: 1; origin: string; send_as: SendAs;
} {
  return { type: 'placement', v: 1, origin, send_as: sendAs };
}

export function placementSha(origin: string, sendAs: SendAs): string {
  return createHash('sha256').update(canonicalJson(placementRecipe(origin, sendAs))).digest('hex');
}

/** Plain words for the approval card; never includes a credential's value. */
export function describePlacement(origin: string, sendAs: SendAs): string {
  const address = new URL(origin);
  const host = address.hostname + (address.port && address.port !== '443' ? `:${address.port}` : '');
  // Text before AND after the secret, quoted exactly (spaces kept): two proposals that differ
  // only there must not read the same (review 13 r2 F2).
  const at = sendAs.template.indexOf('{secret}');
  const before = sendAs.template.slice(0, at);
  const after = sendAs.template.slice(at + '{secret}'.length);
  const around = (before ? `, after ${JSON.stringify(before)}` : '') + (after ? `, followed by ${JSON.stringify(after)}` : '');
  if (sendAs.in === 'query') {
    return `Send this secret to ${host} after ? in the address, as ?${sendAs.name}=…` + around;
  }
  if (sendAs.name.toLowerCase() === 'authorization' && sendAs.template === 'Bearer {secret}') {
    return `Send this secret to ${host} in the Authorization header (as a Bearer token)`;
  }
  const name = sendAs.name.split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('-');
  return `Send this secret to ${host} in a header named ${name}` + around;
}

export function isAskBinding(b: unknown): boolean {
  return !!b && typeof b === 'object' && !Array.isArray(b)
    && Object.keys(b).length === 1
    && Object.prototype.hasOwnProperty.call(b, 'ask')
    && (b as { ask?: unknown }).ask === true;
}
