/**
 * Named credential parts and their placements. Values are never inspected to guess their
 * format: only the format in the sealed setup can turn a value into a parts envelope.
 *
 * v1 bindings retain delivery.ts's rendering, including the username stored beside a
 * basic-auth password. v2 bindings name every part they place.
 */
import {
  BEARER, basicToken, pathBindingProblem, pathWithKey, renderCredential, secretForms,
  validateAgentHeaders, validateBinding,
} from './delivery.js';
import type { BindingCheck, HeaderCheck } from './delivery.js';
import type { OAuth1Value } from './stamp.js';

export const SHAPES = {
  api_key: {
    parts: { key: 'Key' }, optionalParts: {}, delivery: 'http',
  },
  key_id: {
    parts: { id: 'ID', secret: 'Secret' }, optionalParts: {}, delivery: 'http',
  },
  signed_set: {
    parts: {
      consumer_key: 'Consumer key',
      consumer_secret: 'Consumer secret',
      token: 'Access token',
      token_secret: 'Access token secret',
    },
    optionalParts: {}, delivery: 'http',
  },
  password: {
    parts: { username: 'Username', password: 'Password' }, optionalParts: {}, delivery: 'http',
  },
  website_login: {
    parts: { username: 'Username', password: 'Password' },
    optionalParts: { totp: 'TOTP' }, delivery: null,
  },
  // An authenticator seed on its own. Stored only: the broker never sends it anywhere; it
  // turns it into the current 6-digit code for vault_2fa_code.
  two_factor: {
    parts: { seed: 'Seed' }, optionalParts: {}, delivery: null,
  },
  ssh_key: {
    parts: { private_key: 'Private key' }, optionalParts: {}, delivery: 'ssh',
  },
  wallet: {
    parts: { private_key: 'Private key' }, optionalParts: {}, delivery: 'wallet',
  },
  signing_key: {
    parts: { private_key: 'Private key' }, optionalParts: {}, delivery: 'sign',
  },
} as const;

export type Shape = keyof typeof SHAPES;
export type Delivery = 'http' | 'ssh' | 'wallet' | 'sign';

type CredentialBinding = Extract<BindingCheck, { ok: true }>['binding'];

export type BindingV1 = CredentialBinding & { v: 1 };

export interface Placement {
  in: 'header' | 'query' | 'path' | 'stamp';
  name: string;
  template: string;
}

export interface BindingV2 {
  v: 2;
  placements: Placement[];
}

export type PartsBinding = BindingV1 | BindingV2;

export type PartsBindingCheck =
  | { ok: true; binding: PartsBinding }
  | { ok: false; field: string; message: string };

export type ValueCheck =
  | { ok: true; shape: Shape; parts: Record<string, string> }
  | { ok: false; reason: string };

const PART_ID = /^[a-z][a-z0-9_]{0,31}$/;
const MAX_PART_BYTES = 16 * 1024;
const RAW_SHAPES: Record<Delivery, Shape> = {
  http: 'api_key', ssh: 'ssh_key', wallet: 'wallet', sign: 'signing_key',
};

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isShape(value: unknown): value is Shape {
  return typeof value === 'string' && Object.hasOwn(SHAPES, value);
}

function shapeMatchesDelivery(shape: Shape, delivery: Delivery): boolean {
  // A website login may be stored and listed alongside HTTP entries, but has no binding.
  return SHAPES[shape].delivery === delivery
    || ((shape === 'website_login' || shape === 'two_factor') && delivery === 'http');
}

/**
 * The vault page's save-time rules, checked again where the setup is USED (parent spec item 1:
 * a setup that fails them refuses use, never "unrestricted"). Returns why, or null.
 * `forUse` = the broker is about to send/sign with it (a stored-only key may still be listed).
 */
export function setupProblem(setup: {
  shape?: unknown; delivery?: unknown; value_format?: unknown; binding?: unknown;
  ssh_hosts?: unknown; chain?: unknown; ask?: unknown;
}, forUse: boolean): string | null {
  const { shape, delivery } = setup;
  if (!isShape(shape)) return 'unknown shape';
  if (delivery !== 'http' && delivery !== 'ssh' && delivery !== 'wallet' && delivery !== 'sign') {
    return 'unknown delivery';
  }
  if (!shapeMatchesDelivery(shape, delivery)) return 'shape does not allow this delivery';
  const format = setup.value_format ?? 'raw';
  if (format !== 'raw' && format !== 'parts-1') return 'unknown value format';
  if (format === 'raw' && shape !== RAW_SHAPES[delivery]) return 'raw values require a single-part shape';
  if (format === 'parts-1' && delivery !== 'http') return 'SSH, wallet and signing values must use the raw format';
  if (delivery === 'http') {
    const storedOnly = shape === 'website_login' || shape === 'two_factor'
      || (shape === 'password' && setup.binding == null);
    if (storedOnly) {
      if (setup.binding != null) return 'this shape has no web credential binding';
      // Fetchable, never SENT as it is: the operation decides (spec 1.2 B3). vault_2fa_code
      // turns a seed into a code; an approved request.sign_in sends the password only in the
      // login request. Plain vault_call refuses these entries itself (broker-ops STORED_ONLY).
      return null;
    }
    // Spec 1.3: a single key may wait for its first use; the broker then asks the owner once
    // how to send it (broker-ops, NEEDS_PLACEMENT / send_as). Exactly {ask:true}, nothing else.
    if (shape === 'api_key' && isObject(setup.binding) && Object.keys(setup.binding).length === 1
        && (setup.binding as Record<string, unknown>).ask === true) {
      return null;
    }
    if (setup.binding == null && shape !== 'api_key') return 'this shape needs a binding';
    if (setup.binding != null) {
      const checked = validateBindingV2(setup.binding, shape, 'http');
      if (!checked.ok) return `${checked.field}: ${checked.message}`;
    }
  } else if (setup.binding != null) {
    return 'this shape has no web credential binding';
  }
  if (setup.ask !== undefined && (setup.ask !== true || delivery !== 'ssh')) return 'ask is only for an SSH key, and only true';
  // Spec 1.3: with ask, the servers are approved on first use, so an empty list is allowed.
  if (delivery === 'ssh' && !(setup.ask === true && Array.isArray(setup.ssh_hosts) && setup.ssh_hosts.length === 0)
      && (!Array.isArray(setup.ssh_hosts) || setup.ssh_hosts.length === 0
      || setup.ssh_hosts.some((h) => typeof h !== 'string' || !h))) {
    return 'an SSH key needs at least one server';
  }
  if (delivery === 'wallet' && setup.chain !== 'evm' && setup.chain !== 'solana') {
    return 'a wallet is on evm or solana';
  }
  if (delivery !== 'wallet' && setup.chain != null) return 'a chain only applies to wallets';
  return null;
}

function allowedParts(shape: Shape): Set<string> {
  return new Set([
    ...Object.keys(SHAPES[shape].parts),
    ...Object.keys(SHAPES[shape].optionalParts),
  ]);
}

function partsProblem(raw: unknown, shape: Shape): string | null {
  if (!isObject(raw)) return 'parts must be an object';
  const ids = Object.keys(raw);
  if (ids.length > 4) return 'at most four parts are allowed';
  const allowed = allowedParts(shape);
  for (const id of ids) {
    if (!PART_ID.test(id)) return `invalid part id: ${id}`;
    if (!allowed.has(id)) return `unexpected part: ${id}`;
    const value = raw[id];
    if (typeof value !== 'string') return `part ${id} must be a string`;
    if (Buffer.byteLength(value, 'utf8') > MAX_PART_BYTES) {
      return `part ${id} exceeds 16 KiB`;
    }
  }
  for (const id of Object.keys(SHAPES[shape].parts)) {
    if (!Object.hasOwn(raw, id)) return `missing part: ${id}`;
  }
  return null;
}

/** A legacy value is opaque, even when its bytes happen to be a valid parts envelope. */
export function readValue(
  plain: string,
  valueFormat: 'raw' | 'parts-1' | undefined,
  delivery: Delivery,
  shape?: Shape,
): ValueCheck {
  const bad = (reason: string): ValueCheck => ({ ok: false, reason });
  if (!Object.hasOwn(RAW_SHAPES, delivery)) return bad('unknown delivery');
  if (shape !== undefined && !isShape(shape)) return bad('unknown shape');

  const resolvedShape = shape ?? RAW_SHAPES[delivery];
  if (!shapeMatchesDelivery(resolvedShape, delivery)) return bad('shape does not allow this delivery');

  if (valueFormat === undefined || valueFormat === 'raw') {
    // A multipart shape cannot describe an opaque, single-part legacy value.
    if (resolvedShape !== RAW_SHAPES[delivery]) return bad('raw values require a single-part shape');
    const id = delivery === 'http' ? 'key' : 'private_key';
    if (Buffer.byteLength(plain, 'utf8') > MAX_PART_BYTES) return bad(`part ${id} exceeds 16 KiB`);
    return { ok: true, shape: resolvedShape, parts: { [id]: plain } };
  }
  if (valueFormat !== 'parts-1') return bad('unknown value format');

  let envelope: unknown;
  try {
    envelope = JSON.parse(plain);
  } catch {
    return bad('parts-1 value must be JSON');
  }
  if (!isObject(envelope) || Object.keys(envelope).length !== 1 || !Object.hasOwn(envelope, 'parts')) {
    return bad('parts-1 value must contain exactly the parts field');
  }
  const problem = partsProblem(envelope.parts, resolvedShape);
  if (problem) return bad(problem);
  return {
    ok: true,
    shape: resolvedShape,
    parts: Object.fromEntries(Object.entries(envelope.parts as Record<string, string>)),
  };
}

interface Placeholder {
  token: string;
  ids: string[];
  basic: boolean;
}

function placeholder(template: string): Placeholder | null {
  const match = /\{(?:part:([a-z][a-z0-9_]{0,31})|basic:([a-z][a-z0-9_]{0,31}):([a-z][a-z0-9_]{0,31}))\}/.exec(template);
  if (!match) return null;
  const rest = template.slice(0, match.index) + template.slice(match.index + match[0].length);
  if (/[{}]/.test(rest)) return null;
  return match[1] !== undefined
    ? { token: match[0], ids: [match[1]], basic: false }
    : { token: match[0], ids: [match[2]!, match[3]!], basic: true };
}

function badBinding(field: string, message: string): PartsBindingCheck {
  return { ok: false, field, message };
}

/**
 * Reuse the v1 validator for header/query names and all static path rules. Replacing
 * only the placeholder keeps those rules identical without accepting v1 placeholders
 * in a v2 template.
 */
function legacyPlacement(p: Placement, token: Placeholder): CredentialBinding {
  return {
    in: p.in,
    name: p.name,
    template: p.template.replace(token.token, () => token.basic ? '{basic}' : '{secret}'),
    ...(token.basic ? { username: 'user' } : {}),
  };
}

export function validateBindingV2(
  raw: unknown,
  shape: Shape,
  delivery: Delivery,
): PartsBindingCheck {
  if (!isShape(shape)) return badBinding('shape', 'unknown shape');
  if (!Object.hasOwn(RAW_SHAPES, delivery) || !shapeMatchesDelivery(shape, delivery)) {
    return badBinding('delivery', 'shape does not allow this delivery');
  }
  if (delivery !== 'http' || shape === 'website_login' || shape === 'two_factor') {
    return badBinding('binding', 'this shape has no web credential binding');
  }
  if (!isObject(raw)) return badBinding('binding', 'binding must be an object');

  if (raw.v === undefined || raw.v === 1) {
    const legacy = { ...raw };
    delete legacy.v;
    const checked = validateBinding(legacy);
    if (!checked.ok) return badBinding(checked.field, checked.reason);
    const binding = checked.binding;
    if (shape === 'signed_set') {
      if (binding.in !== 'stamp') return badBinding('binding.in', 'a signed set requires a stamp');
    } else if (shape !== 'api_key') {
      return badBinding('binding', 'this shape requires named-part placements');
    }
    // A single key may stamp too: AWS SigV4 and HMAC recipes take one secret as the MAC key,
    // and a pre-release X entry holds its four values as one JSON value.
    return { ok: true, binding: { ...binding, v: 1 } };
  }

  if (raw.v !== 2) return badBinding('binding.v', 'unknown binding version');
  if (Object.keys(raw).some((key) => key !== 'v' && key !== 'placements')) {
    return badBinding('binding', 'unknown binding fields');
  }
  if (!Array.isArray(raw.placements) || raw.placements.length < 1 || raw.placements.length > 4) {
    return badBinding('binding.placements', 'one to four placements are required');
  }

  const placed = new Set<string>();
  const targets = new Set<string>();
  const allowed = allowedParts(shape);
  const placements: Placement[] = [];
  let pathCount = 0;
  for (let i = 0; i < raw.placements.length; i++) {
    const field = `binding.placements.${i}`;
    const p: unknown = raw.placements[i];
    if (!isObject(p)) return badBinding(field, 'placement must be an object');
    if (Object.keys(p).some((key) => !['in', 'name', 'template'].includes(key))) {
      return badBinding(field, 'unknown placement fields');
    }
    if (!['header', 'query', 'path', 'stamp'].includes(p.in as string)) {
      return badBinding(`${field}.in`, 'unknown placement location');
    }
    if (p.in === 'stamp') {
      if (!['signed_set', 'api_key', 'key_id'].includes(shape) || raw.placements.length !== 1) {
        return badBinding(`${field}.in`, 'a stamp must be alone, on a signed set, a single key, or an ID and secret');
      }
      if (p.name !== '' || p.template !== '') {
        return badBinding(field, 'a stamp has an empty name and template');
      }
      placements.push({ in: 'stamp', name: '', template: '' });
      continue;
    }
    if (shape === 'signed_set') return badBinding(`${field}.in`, 'a signed set requires a stamp');
    if (typeof p.template !== 'string' || !p.template || p.template.length > 128
        || /[^\x20-\x7e]/.test(p.template)) {
      return badBinding(`${field}.template`, 'the template must be printable text, 128 characters at most');
    }
    const token = placeholder(p.template);
    if (!token) {
      return badBinding(`${field}.template`, 'exactly one named part or basic placeholder is required');
    }
    if (token.basic && p.in !== 'header') {
      return badBinding(`${field}.template`, 'basic credentials can only be sent in a header');
    }
    if (shape === 'password'
        && (!token.basic || token.ids[0] !== 'username' || token.ids[1] !== 'password')) {
      return badBinding(`${field}.template`, 'a password requires {basic:username:password}');
    }
    for (const id of token.ids) {
      if (!allowed.has(id)) return badBinding(`${field}.template`, `unknown part: ${id}`);
      if (placed.has(id)) return badBinding(`${field}.template`, `part ${id} is placed twice`);
      placed.add(id);
    }

    const candidate = {
      in: p.in, name: p.name, template: p.template,
    } as Placement;
    const checked = validateBinding(legacyPlacement(candidate, token));
    if (!checked.ok) {
      return badBinding(checked.field.replace('binding', field), checked.reason);
    }
    const normalised: Placement = {
      in: checked.binding.in, name: checked.binding.name, template: p.template,
    };
    if (normalised.in === 'path' && ++pathCount > 1) {
      return badBinding(`${field}.in`, 'at most one path placement is allowed');
    }
    if (normalised.in === 'header' || normalised.in === 'query') {
      const target = `${normalised.in}:${normalised.name.toLowerCase()}`;
      if (targets.has(target)) return badBinding(`${field}.name`, 'the placement target is given twice');
      targets.add(target);
    }
    placements.push(normalised);
  }
  if (shape === 'api_key' && placements.length !== 1) {
    return badBinding('binding.placements', 'an API key requires one placement');
  }
  if (shape === 'key_id' && placements.length > 2) {
    return badBinding('binding.placements', 'a key and ID allow at most two placements');
  }
  return { ok: true, binding: { v: 2, placements } };
}

function part(parts: Record<string, string>, id: string): string {
  if (!Object.hasOwn(parts, id) || typeof parts[id] !== 'string') {
    throw new Error(`missing part: ${id}`);
  }
  return parts[id]!;
}

function singlePart(parts: Record<string, string>): string {
  const ids = Object.keys(parts);
  if (ids.length !== 1) throw new Error('a v1 binding requires a single part');
  return part(parts, ids[0]!);
}

function checkedBasicToken(username: string, password: string): string {
  // delivery.ts's helper composes bytes; named-part usernames need this value-time check.
  if (username.includes(':')) throw new Error("a basic username must not contain ':'");
  return basicToken(username, password);
}

export interface RenderedPlacements {
  headers: Record<string, string>;
  query: Array<[string, string]>;
  pathTemplate?: string;
}

export function renderPlacements(
  binding: PartsBinding,
  parts: Record<string, string>,
): RenderedPlacements {
  const headers = new Map<string, string>();
  const query: Array<[string, string]> = [];
  let pathTemplate: string | undefined;

  const put = (placement: CredentialBinding, secret: string): void => {
    if (placement.in === 'stamp') return;
    if (placement.in === 'path') {
      const problem = pathBindingProblem(placement, secret, '/');
      if (problem) throw new Error(problem);
      pathTemplate = pathWithKey(placement, secret, '/');
    } else {
      const value = renderCredential(placement, secret);
      if (placement.in === 'header') headers.set(placement.name.toLowerCase(), value);
      else query.push([placement.name, value]);
    }
  };

  if (binding.v === 1) {
    if (binding.in !== 'stamp') {
      const secret = singlePart(parts);
      if (binding.template.includes('{basic}')) checkedBasicToken(binding.username ?? '', secret);
      put(binding, secret);
    }
  } else {
    for (const p of binding.placements) {
      if (p.in === 'stamp') continue;
      const token = placeholder(p.template);
      if (!token) throw new Error('invalid placement template');
      if (token.basic) {
        const value = checkedBasicToken(part(parts, token.ids[0]!), part(parts, token.ids[1]!));
        headers.set(p.name.toLowerCase(), p.template.replace(token.token, () => value));
      } else {
        put(legacyPlacement(p, token), part(parts, token.ids[0]!));
      }
    }
  }
  return {
    headers: Object.fromEntries(headers),
    query,
    ...(pathTemplate === undefined ? {} : { pathTemplate }),
  };
}

/** Apply placements to the actual request path, including its existing query. */
export function applyPlacements(
  binding: BindingV2,
  parts: Record<string, string>,
  agentPath: string,
): { headers: Record<string, string>; path: string } {
  const headers: Record<string, string> = {};
  let path = agentPath;
  for (const p of binding.placements) {
    if (p.in === 'stamp') continue;
    const token = placeholder(p.template);
    if (!token) throw new Error('invalid placement template');
    const value = token.basic
      ? checkedBasicToken(part(parts, token.ids[0]!), part(parts, token.ids[1]!))
      : part(parts, token.ids[0]!);
    if (p.in === 'path') {
      const placement = legacyPlacement(p, token);
      const problem = pathBindingProblem(placement, value, path);
      if (problem) throw new Error(problem);
      path = pathWithKey(placement, value, path);
    } else {
      const rendered = p.template.replace(token.token, () => value);
      if (p.in === 'header') headers[p.name.toLowerCase()] = rendered;
      else {
        const sep = path.includes('?') ? '&' : '?';
        path += `${sep}${encodeURIComponent(p.name)}=${encodeURIComponent(rendered)}`;
      }
    }
  }
  return { headers, path };
}

/** Include URL spellings for every part, not only the ones placed in a query. */
export function secretFormsAll(binding: PartsBinding, parts: Record<string, string>): string[] {
  const forms: string[] = [];
  const add = (value: string): void => { forms.push(...secretForms(BEARER, value)); };
  const addBasicPart = (value: string): void => {
    add(value);
    add(Buffer.from(value, 'utf8').toString('base64'));
  };
  for (const value of Object.values(parts)) add(value);

  if (binding.v === 1 && binding.in !== 'stamp') {
    const secret = singlePart(parts);
    forms.push(...secretForms(binding, secret));
    if (binding.template.includes('{basic}')) {
      const username = binding.username ?? '';
      addBasicPart(username);
      addBasicPart(secret);
      add(checkedBasicToken(username, secret));
    }
  } else if (binding.v === 2) {
    for (const p of binding.placements) {
      if (p.in === 'stamp') continue;
      const token = placeholder(p.template);
      if (!token) throw new Error('invalid placement template');
      if (token.basic) {
        const username = part(parts, token.ids[0]!);
        const password = part(parts, token.ids[1]!);
        addBasicPart(username);
        addBasicPart(password);
        add(checkedBasicToken(username, password));
      }
    }
  }
  return [...new Set(forms)].filter((form) => form.length > 0).sort((a, b) => b.length - a.length);
}

/** One pass avoids matching a later secret inside an inserted redaction marker. */
export function scrub(text: string, forms: readonly string[]): string {
  const sorted = [...new Set(forms)].filter((form) => form.length > 0).sort((a, b) => b.length - a.length);
  if (!sorted.length) return text;
  const pattern = sorted.map((form) => form.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  return text.replace(new RegExp(pattern, 'g'), () => '[REDACTED]');
}

export function oauth1FromParts(parts: Record<string, string>): OAuth1Value {
  const problem = partsProblem(parts, 'signed_set');
  if (problem) return (() => { throw new Error(problem); })();
  return {
    consumer_key: part(parts, 'consumer_key'),
    consumer_secret: part(parts, 'consumer_secret'),
    token: part(parts, 'token'),
    token_secret: part(parts, 'token_secret'),
  };
}

export function checkAgentHeaders(agentHeaders: unknown, binding: PartsBinding): HeaderCheck {
  if (binding.v === 1) return validateAgentHeaders(agentHeaders, binding);

  // First apply every ordinary agent-header rule, without inventing a credential header.
  const checked = validateAgentHeaders(agentHeaders, { in: 'stamp', name: '', template: '' });
  if (!checked.ok) return checked;
  const credentialHeaders = new Set(
    binding.placements.filter((p) => p.in === 'header').map((p) => p.name.toLowerCase()),
  );
  for (const name of Object.keys(checked.headers)) {
    if (credentialHeaders.has(name)) {
      return {
        ok: false,
        field: 'request.headers',
        reason: `${name} carries this entry's secret; the entry sets it, not the caller`,
      };
    }
  }
  return checked;
}
