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
/** RFC 3986 path characters, without `%`: nothing in a key's address is pre-encoded. */
const PATH_CHARS = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/]*$/;
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
  if (where === 'path') return validatePathBinding(b);
  if (where === 'stamp') {
    // The key is never placed anywhere, so there is nothing to name or template. Anything
    // present is a binding this broker did not write, and is refused rather than ignored.
    for (const f of ['name', 'template', 'username'] as const) {
      if (b[f] !== undefined && b[f] !== null && b[f] !== '') return bad(`binding.${f}`, 'a stamped key has no ' + f);
    }
    return { ok: true, binding: { in: 'stamp', name: '', template: '' } };
  }
  if (where !== 'header' && where !== 'query') return bad('binding.in', "binding.in must be 'header', 'query', 'path' or 'stamp'");
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

/** Is any segment of this path `.` or `..`, in any spelling a server would decode? */
export function hasDotSegment(path: string): boolean {
  return path.split('/').some((seg) => /^(?:\.|%2e){1,2}$/i.test(seg));
}

/**
 * A key that goes in the web address: `{in:'path', template:'/bot{secret}'}`.
 *
 * The template is the address path up to and including the key; the agent's own path is
 * appended after it. Telegram is `/bot{secret}`, a Slack webhook `/services/{secret}`.
 */
function validatePathBinding(b: Record<string, unknown>): BindingCheck {
  const bad = (field: string, reason: string): BindingCheck => ({ ok: false, field, reason });
  if (b.name !== undefined && b.name !== null && b.name !== '') return bad('binding.name', 'a key in the web address has no name');
  if (b.username !== undefined && b.username !== null) return bad('binding.username', 'a username only goes with {basic}');
  const template = b.template;
  if (typeof template !== 'string' || !template) return bad('binding.template', 'binding.template is required');
  if (template.length > 128 || !printable(template)) {
    return bad('binding.template', 'the template must be printable text, 128 characters at most');
  }
  if (count(template, '{secret}') !== 1 || template.includes('{basic}')) {
    return bad('binding.template', 'the address must contain {secret} exactly once');
  }
  if (!template.startsWith('/')) return bad('binding.template', 'the address path must start with /');
  const rest = template.replace('{secret}', '');
  if (!PATH_CHARS.test(rest)) {
    return bad('binding.template', 'the address may use letters, digits and - . _ ~ ! $ & \' ( ) * + , ; = : @ / only');
  }
  if (hasDotSegment(template)) return bad('binding.template', 'the address may not contain a . or .. segment');
  return { ok: true, binding: { in: 'path', name: '', template } };
}

/**
 * Why a path-bound call cannot be sent, or null when it can.
 *
 * The KEY is checked here, at call time, because only the broker ever sees it. It goes into
 * the address as written — a Slack key's `/` has to stay a `/` — so anything that would
 * change the address's meaning (`?`, `#`, `%`, a space, a dot segment) refuses the call
 * rather than being encoded into something the owner never stored. The AGENT's path may
 * not walk out from under the key with a dot segment.
 */
export function pathBindingProblem(binding: CredentialBinding, secret: string, agentPath: string): string | null {
  if (binding.in !== 'path') return null;
  if (!secret || secret.length > 512 || !PATH_CHARS.test(secret) || hasDotSegment(secret)
      || secret.includes('//') || secret.startsWith('/') || secret.endsWith('/')) {
    return "this entry's key has characters that can't go in a web address, so it can't be sent that way. "
      + 'The owner can choose another way to send it in the dashboard.';
  }
  const pathOnly = agentPath.split('?')[0];
  if (hasDotSegment(pathOnly)) return 'with a key in the web address, the path may not contain a . or .. segment.';
  return null;
}

/** The wire path for a path-bound key: the stored address, then whatever the agent added. */
export function pathWithKey(binding: CredentialBinding, secret: string, agentPath: string): string {
  // `/` alone, or `/` before a query, means "the stored address as is": a Slack webhook does
  // not answer at `/services/T/B/X/`.
  const rest = agentPath === '/' ? '' : agentPath.startsWith('/?') ? agentPath.slice(1) : agentPath;
  return renderCredential(binding, secret) + rest;
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
  // Defence in depth: the executor never calls this for a stamp, and must not start to.
  if (binding.in === 'stamp') throw new Error('a stamped key is never rendered into a request');
  if (binding.template.includes('{basic}')) {
    const token = basicToken(binding.username ?? '', secret);
    return binding.template.replace('{basic}', () => token);
  }
  return binding.template.replace('{secret}', () => secret);
}

/**
 * Headers an agent may never set on a brokered request, whatever the entry's binding.
 *
 * The framing set above, plus the ones that would change how the broker reads the reply
 * (`accept-encoding`, `content-encoding`: the size caps and decompression assume they own
 * these) or that address a proxy. The credential's own header is added per call.
 */
const AGENT_FORBIDDEN_HEADERS: ReadonlySet<string> = new Set([
  ...FORBIDDEN_HEADERS, 'expect', 'keep-alive', 'accept-encoding', 'content-encoding',
]);
const MAX_AGENT_HEADERS = 20;
const MAX_AGENT_HEADER_VALUE = 1024;

export type HeaderCheck =
  | { ok: true; headers: Record<string, string> }
  | { ok: false; field: string; reason: string };

/**
 * The headers an agent asked to send, checked and lowercased — or why not.
 *
 * Without these, a brokered call could not reach GitHub at all (it refuses a request
 * with no User-Agent) or Anthropic (anthropic-version is required). What the agent still
 * cannot do is touch the key: the credential's header is refused by name, and the
 * credential is written after these in any case, so nothing here can shadow it. Values are
 * literal — nothing in them is a placeholder.
 */
export function validateAgentHeaders(raw: unknown, binding: CredentialBinding): HeaderCheck {
  const bad = (field: string, reason: string): HeaderCheck => ({ ok: false, field, reason });
  // Absent and null both mean "no headers of my own" — JSON has no other way to say it.
  if (raw === undefined || raw === null) return { ok: true, headers: {} };
  if (typeof raw !== 'object' || Array.isArray(raw)) return bad('request.headers', 'headers must be an object of name: value');
  const entries = Object.entries(raw as Record<string, unknown>);
  if (entries.length > MAX_AGENT_HEADERS) return bad('request.headers', `at most ${MAX_AGENT_HEADERS} headers`);
  const credentialHeader = binding.in === 'header' ? binding.name.toLowerCase() : '';
  // A Map, not an object literal: `out['__proto__'] = v` sets nothing on a plain object,
  // so a valid header would have been checked and then silently not sent (round 2, F3).
  const out = new Map<string, string>();
  for (const [name, value] of entries) {
    if (!HEADER_NAME.test(name)) return bad('request.headers', `"${name.slice(0, 64)}" is not a header name`);
    const lower = name.toLowerCase();
    if (AGENT_FORBIDDEN_HEADERS.has(lower) || lower.startsWith('proxy-')) {
      return bad('request.headers', `the ${lower} header is set by the broker, not the caller`);
    }
    if (lower === credentialHeader) {
      return bad('request.headers', `${lower} carries this entry's key; the entry sets it, not the caller`);
    }
    if (out.has(lower)) return bad('request.headers', `${lower} is given twice`);
    if (typeof value !== 'string') return bad('request.headers', `the value of ${lower} must be a string`);
    if (value.length > MAX_AGENT_HEADER_VALUE || !/^[\x20-\x7e\t]*$/.test(value)) {
      return bad('request.headers', `the value of ${lower} must be printable text, ${MAX_AGENT_HEADER_VALUE} characters at most`);
    }
    out.set(lower, value);
  }
  return { ok: true, headers: Object.fromEntries(out) };
}

/**
 * Every form of the key a response could echo back: the key itself, and for basic sign-in
 * the encoded pair, which is what the upstream actually received.
 */
export function secretForms(binding: CredentialBinding, secret: string): string[] {
  const forms = [secret];
  if (binding.in !== 'stamp' && binding.template.includes('{basic}')) forms.push(basicToken(binding.username ?? '', secret));
  // A query key travels percent-encoded, and an upstream that echoes the request line (an
  // error page, a debug field) echoes it in that form, which a verbatim scrub misses. Three
  // spellings, because servers normalise: as sent, with lowercase escapes, and form-style
  // (`+` for a space). Still exact matching — defence in depth, not a guarantee.
  const encoded = encodeURIComponent(secret);
  forms.push(encoded, encoded.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
  forms.push(new URLSearchParams([['k', secret]]).toString().slice(2));
  return [...new Set(forms)].filter((f) => f.length > 0);
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

