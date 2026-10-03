/**
 * How a web-service key is framed on its way out: which header or query parameter carries
 * it, with what prefix, or a username and password composed into HTTP basic sign-in.
 *
 * The owner chooses this in the dashboard and the server stores it on the entry. The same
 * rules are checked there (burnbox `app/delivery.py`) so the owner gets a clear error when
 * they choose; they are checked again HERE because the broker must not trust the server
 * for what goes into a request. A server that rewrote a binding to `host`, or to a
 * template with the secret twice, or to something with a line break in it, gets a refused
 * call — never a repaired one, and never a quiet fall back to a bearer token, because
 * "the binding I was given is wrong" and "use the default" are different facts.
 *
 * See SPEC-1.0-brokered-only.md §A.
 */
import type { CredentialBinding } from './opdef.js';

export const BEARER: CredentialBinding = Object.freeze({
  in: 'header', name: 'authorization', template: 'Bearer {secret}',
}) as CredentialBinding;

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;
const QUERY_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
/** Headers that change how a request is framed or routed, or that are not the key's to set. */
export const FORBIDDEN_HEADERS: ReadonlySet<string> = new Set([
  'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade', 'te', 'trailer',
  'proxy-authorization', 'cookie', 'set-cookie',
]);

export type BindingCheck =
  | { ok: true; binding: CredentialBinding }
  | { ok: false; field: string; reason: string };

function printable(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c >= 0x7f) return false;
  }
  return true;
}

function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

/** A binding, checked and normalised. Never repaired: anything wrong is a refusal. */
export function validateBinding(raw: unknown): BindingCheck {
  const bad = (field: string, reason: string): BindingCheck => ({ ok: false, field, reason });
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return bad('binding', 'binding must be an object');
  const b = raw as Record<string, unknown>;
  const extra = Object.keys(b).filter((k) => !['in', 'name', 'template', 'username'].includes(k));
  if (extra.length) return bad('binding', `unknown binding fields: ${extra.sort().join(', ')}`);
  const where = b.in;
  if (where !== 'header' && where !== 'query') return bad('binding.in', "binding.in must be 'header' or 'query'");
  if (typeof b.name !== 'string') return bad('binding.name', 'binding.name is required');
  let name = b.name;
  if (where === 'header') {
    if (!HEADER_NAME.test(name)) return bad('binding.name', 'not a valid header name');
    name = name.toLowerCase();
    if (FORBIDDEN_HEADERS.has(name)) return bad('binding.name', `the ${name} header can't carry a key`);
  } else if (!QUERY_NAME.test(name)) {
    return bad('binding.name', 'not a valid query parameter name');
  }
  const template = b.template;
  if (typeof template !== 'string' || !template) return bad('binding.template', 'binding.template is required');
  if (template.length > 128 || !printable(template)) {
    return bad('binding.template', 'the template must be printable text, 128 characters at most');
  }
  if (count(template, '{secret}') + count(template, '{basic}') !== 1) {
    return bad('binding.template', 'the template must contain exactly one {secret} or {basic}');
  }
  const out: CredentialBinding = { in: where, name, template };
  if (template.includes('{basic}')) {
    if (where !== 'header') return bad('binding.template', 'username and password can only be sent in a header');
    const u = b.username;
    if (typeof u !== 'string' || !u) return bad('binding.username', 'a username is required for {basic}');
    if (u.length > 128 || u.includes(':') || !printable(u)) {
      return bad('binding.username', "the username must be printable, without ':', 128 characters at most");
    }
    out.username = u;
  } else if (b.username !== undefined && b.username !== null) {
    return bad('binding.username', 'a username only goes with {basic}');
  }
  return { ok: true, binding: out };
}

/**
 * The binding an entry's exec_config names.
 *
 * ABSENT means the bearer default — an entry made before bindings existed, or set to the
 * web mode without one. PRESENT BUT INVALID is a refusal, not the default: falling back
 * would send the key as a bearer token to a service that was configured to receive it
 * some other way, which is a decision nobody made.
 */
export function bindingFromExecConfig(cfg: Record<string, unknown>): BindingCheck {
  // ABSENT is the key not being there at all. An explicit `null` is a value somebody wrote,
  // and no path on the server writes one — so it is treated like any other invalid binding.
  if (!Object.prototype.hasOwnProperty.call(cfg, 'credential_binding')) {
    return { ok: true, binding: { ...BEARER } };
  }
  return validateBinding(cfg.credential_binding);
}

/** base64(username ":" secret) — HTTP basic sign-in (RFC 7617), composed in the broker. */
export function basicToken(username: string, secret: string): string {
  return Buffer.from(`${username}:${secret}`, 'utf8').toString('base64');
}

/**
 * The value that goes into the header or parameter.
 *
 * A FUNCTION replacement, deliberately. `String.prototype.replace` with a string second
 * argument expands `$&`, `$'`, `` $` `` and `$$` inside it — so a key containing `$'`
 * would have been sent with the template's tail spliced into the middle of it.
 */
export function renderCredential(binding: CredentialBinding, secret: string): string {
  if (binding.template.includes('{basic}')) {
    const token = basicToken(binding.username ?? '', secret);
    return binding.template.replace('{basic}', () => token);
  }
  return binding.template.replace('{secret}', () => secret);
}

/**
 * Every form of the key a response could echo back: the key itself, and for basic sign-in
 * the encoded pair, which is what the upstream actually received.
 */
export function secretForms(binding: CredentialBinding, secret: string): string[] {
  const forms = [secret];
  if (binding.template.includes('{basic}')) forms.push(basicToken(binding.username ?? '', secret));
  return forms.filter((f) => f.length > 0);
}

/**
 * Does this value look like a private key? Then it is not a web credential.
 *
 * 1.0 converted every hand-over entry to "web service, bearer token", because the server
 * cannot see a value to know better. An SSH key that was used through vault_exec is in that
 * set until its owner switches it to SSH — and until then a vault_call would send the
 * private key, as a bearer token or in an address, to whatever host the agent named. No
 * service takes a private key as a bearer token, so refusing costs nothing legitimate.
 */
export function looksLikePrivateKey(secret: string): boolean {
  return /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(secret);
}

