import { createHash } from 'node:crypto';
import { canonicalJson } from './opdef.js';
import { scrub } from './parts.js';
import { secretForms } from './delivery.js';

export type SignInRecipe = {
  login: {
    method: 'POST' | 'PUT';
    path: string;
    body_format: 'json' | 'form';
    body: unknown;
  };
  session_from: { cookie: string } | { json: string } | { header: string };
  send_session_as: { cookie: string } | { header: string; template: string };
  signed_out_when?: number[];
  expires_after_seconds?: number;
};

type Response = {
  headers: Record<string, string | string[] | undefined>;
  body: string;
};

const usernameSlot = '{{username}}';
const passwordSlot = '{{password}}';
const sessionSlot = '{{session}}';
const tokenPattern = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const forbiddenHeaders = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'cookie',
  'proxy-authorization',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function onlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Reflect.ownKeys(value).every(key => typeof key === 'string' && keys.includes(key));
}

function validName(value: unknown): value is string {
  return typeof value === 'string' && tokenPattern.test(value);
}

function validSlots(value: string, slots: readonly string[]): boolean {
  let position = 0;
  while ((position = value.indexOf('{{', position)) !== -1) {
    const slot = slots.find(candidate => value.startsWith(candidate, position));
    if (!slot) return false;
    position += slot.length;
  }
  return true;
}

function validSessionTemplate(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 256 || /[\r\n]/.test(value)) return false;
  const position = value.indexOf(sessionSlot);
  return position !== -1
    && value.indexOf(sessionSlot, position + sessionSlot.length) === -1
    && validSlots(value, [sessionSlot]);
}

export function validateSignInRecipe(
  raw: unknown,
): { ok: true; recipe: SignInRecipe } | { ok: false; reason: string } {
  const refuse = (reason: string): { ok: false; reason: string } => ({ ok: false, reason });

  if (!isRecord(raw) || !onlyKeys(raw, [
    'login', 'session_from', 'send_session_as', 'signed_out_when', 'expires_after_seconds',
  ])) {
    return refuse('invalid sign-in fields');
  }

  const login = raw.login;
  if (!isRecord(login) || !onlyKeys(login, ['method', 'path', 'body_format', 'body'])) {
    return refuse('invalid login fields');
  }
  if (login.method !== 'POST' && login.method !== 'PUT') {
    return refuse('login method must be POST or PUT');
  }
  if (typeof login.path !== 'string'
    || !login.path.startsWith('/')
    || login.path.includes('//')
    || login.path.split('?')[0].split('/').includes('..')
    || /[\s\u0000-\u001f\u007f-\u009f]/u.test(login.path)
    || login.path.length > 512
    || login.path.includes('#')) {
    return refuse('invalid login path');
  }
  if (login.body_format !== 'json' && login.body_format !== 'form') {
    return refuse('login body must be JSON or form data');
  }

  let hasPassword = false;
  const checkString = (value: string): boolean => {
    if (!validSlots(value, [usernameSlot, passwordSlot])) return false;
    if (value.includes(passwordSlot)) hasPassword = true;
    return true;
  };
  const checkJson = (value: unknown, depth: number): boolean => {
    if (depth > 6) return false;
    if (typeof value === 'string') return checkString(value);
    if (value === null || typeof value === 'boolean') return true;
    if (typeof value === 'number') return Number.isFinite(value);
    if (Array.isArray(value)) {
      for (const item of value) {
        if (!checkJson(item, depth + 1)) return false;
      }
      return true;
    }
    if (isRecord(value)) {
      if (Object.getOwnPropertySymbols(value).length !== 0) return false;
      return Object.values(value).every(item => checkJson(item, depth + 1));
    }
    return false;
  };

  if (login.body_format === 'json') {
    if (!checkJson(login.body, 0)) return refuse('invalid JSON login body');
  } else {
    if (!isRecord(login.body)
      || Object.getOwnPropertySymbols(login.body).length !== 0
      || !Object.values(login.body).every(value => typeof value === 'string' && checkString(value))) {
      return refuse('form login body must contain only string values');
    }
  }
  if (!hasPassword) return refuse('login body must include {{password}}');

  const source = raw.session_from;
  let sessionFrom: SignInRecipe['session_from'];
  if (!isRecord(source)) return refuse('invalid session source');
  if (onlyKeys(source, ['cookie']) && validName(source.cookie)) {
    sessionFrom = { cookie: source.cookie };
  } else if (onlyKeys(source, ['header']) && validName(source.header)) {
    sessionFrom = { header: source.header };
  } else if (onlyKeys(source, ['json']) && typeof source.json === 'string') {
    const segments = source.json.split('.');
    if (segments.length > 8 || !segments.every(segment => /^[A-Za-z0-9_-]{1,64}$/.test(segment))) {
      return refuse('invalid session response path');
    }
    sessionFrom = { json: source.json };
  } else {
    return refuse('invalid session source');
  }

  const destination = raw.send_session_as;
  let sendSessionAs: SignInRecipe['send_session_as'];
  if (!isRecord(destination)) return refuse('invalid session destination');
  if (onlyKeys(destination, ['cookie']) && validName(destination.cookie)) {
    sendSessionAs = { cookie: destination.cookie };
  } else if (onlyKeys(destination, ['header', 'template']) && validName(destination.header)) {
    if (forbiddenHeaders.has(destination.header.toLowerCase())) {
      return refuse('that session header is not allowed');
    }
    if (!validSessionTemplate(destination.template)) {
      return refuse('session header must include {{session}} exactly once and contain no line breaks');
    }
    sendSessionAs = { header: destination.header, template: destination.template };
  } else {
    return refuse('invalid session destination');
  }

  let signedOutWhen: number[] = [401];
  if ('signed_out_when' in raw) {
    if (!Array.isArray(raw.signed_out_when) || raw.signed_out_when.length === 0) {
      return refuse('invalid signed-out statuses');
    }
    signedOutWhen = [];
    for (const status of raw.signed_out_when) {
      if (typeof status !== 'number' || ![401, 403, 419, 440].includes(status)) {
        return refuse('invalid signed-out statuses');
      }
      signedOutWhen.push(status);
    }
  }

  const recipe: SignInRecipe = {
    login: {
      method: login.method,
      path: login.path,
      body_format: login.body_format,
      body: login.body,
    },
    session_from: sessionFrom,
    send_session_as: sendSessionAs,
    signed_out_when: signedOutWhen,
  };
  if ('expires_after_seconds' in raw) {
    const expires = raw.expires_after_seconds;
    if (typeof expires !== 'number' || !Number.isInteger(expires) || expires < 60 || expires > 86400) {
      return refuse('session lifetime must be an integer from 60 to 86400 seconds');
    }
    recipe.expires_after_seconds = expires;
  }

  try {
    if (Buffer.byteLength(canonicalJson(recipe), 'utf8') > 4096) {
      return refuse('sign-in instructions are too large');
    }
  } catch {
    return refuse('invalid sign-in data');
  }
  return { ok: true, recipe };
}

export function signInRecipeSha(recipe: SignInRecipe, origin: string): string {
  return createHash('sha256')
    .update(canonicalJson({ type: 'sign_in', v: 1, origin, recipe }))
    .digest('hex');
}

export function describeSignIn(recipe: SignInRecipe, origin: string, username: string): string {
  const destination = 'cookie' in recipe.send_session_as
    ? `the cookie ${recipe.send_session_as.cookie}`
    : `the ${recipe.send_session_as.header} header`;
  const account = username ? ` as ${username}` : '';
  return `Sign in to ${origin}${account} by sending your password to ${recipe.login.path}, then send the session as ${destination} on later calls to that address.`;
}

export function renderLoginBody(
  recipe: SignInRecipe,
  parts: { username?: string; password: string },
): { body: string; contentType: string } {
  const replace = (value: string): string => value.replace(
    /\{\{(username|password)\}\}/g,
    (_match, name: string) => {
      if (name === 'password') return parts.password;
      if (!parts.username) throw new Error('this login has no username');
      return parts.username;
    },
  );
  const render = (value: unknown): unknown => {
    if (typeof value === 'string') return replace(value);
    if (Array.isArray(value)) return value.map(render);
    if (isRecord(value)) {
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, render(item)]));
    }
    return value;
  };

  if (recipe.login.body_format === 'form') {
    const form = new URLSearchParams();
    for (const [key, value] of Object.entries(recipe.login.body as Record<string, string>)) {
      form.append(key, replace(value));
    }
    return { body: form.toString(), contentType: 'application/x-www-form-urlencoded' };
  }
  return { body: JSON.stringify(render(recipe.login.body)), contentType: 'application/json' };
}

function responseHeaderValues(res: Response, name: string): string[] {
  const values: string[] = [];
  for (const [key, value] of Object.entries(res.headers)) {
    if (key.toLowerCase() !== name.toLowerCase() || value === undefined) continue;
    if (Array.isArray(value)) values.push(...value);
    else values.push(value);
  }
  return values;
}

function sessionValue(value: unknown): string | null {
  if (typeof value === 'number' && Number.isFinite(value)) value = String(value);
  return typeof value === 'string' && value.length > 0 && value.length <= 8192 ? value : null;
}

export function extractSession(recipe: SignInRecipe, res: Response): string | null {
  const source = recipe.session_from;
  if ('cookie' in source) {
    for (const header of responseHeaderValues(res, 'set-cookie')) {
      // Also tolerate folded headers without splitting the comma in an Expires date.
      const cookies = header.split(/,(?=\s*[A-Za-z0-9!#$%&'*+.^_`|~-]+=)/);
      for (const cookie of cookies) {
        const pair = cookie.split(';', 1)[0];
        const equals = pair.indexOf('=');
        if (equals === -1 || pair.slice(0, equals).trim() !== source.cookie) continue;
        return sessionValue(pair.slice(equals + 1).trim());
      }
    }
    return null;
  }
  if ('header' in source) {
    return sessionValue(responseHeaderValues(res, source.header)[0]);
  }

  try {
    let value: unknown = JSON.parse(res.body);
    for (const segment of source.json.split('.')) {
      if (Array.isArray(value)) {
        if (!/^\d+$/.test(segment)) return null;
        const index = Number(segment);
        if (!Number.isSafeInteger(index) || !Object.prototype.hasOwnProperty.call(value, index)) {
          return null;
        }
        value = value[index];
      } else if (isRecord(value) && Object.prototype.hasOwnProperty.call(value, segment)) {
        value = value[segment];
      } else {
        return null;
      }
    }
    return sessionValue(value);
  } catch {
    return null;
  }
}

export function applySession(
  recipe: SignInRecipe,
  session: string,
  headers: Record<string, string>,
): { ok: true; headers: Record<string, string> } | { ok: false; reason: string } {
  if (/[\r\n]/.test(session)) return { ok: false, reason: 'invalid session value' };

  const destination = recipe.send_session_as;
  const result = { ...headers };
  if ('header' in destination) {
    if (Object.keys(headers).some(key => key.toLowerCase() === destination.header.toLowerCase())) {
      return { ok: false, reason: 'the request already contains the session header' };
    }
    result[destination.header] = destination.template.replace(sessionSlot, () => session);
  } else {
    if (session.includes(';')) return { ok: false, reason: 'invalid session cookie value' };
    const cookieKeys = Object.keys(headers).filter(key => key.toLowerCase() === 'cookie');
    for (const key of cookieKeys) {
      const conflict = headers[key].split(';').some(pair => {
        const equals = pair.indexOf('=');
        return equals !== -1 && pair.slice(0, equals).trim() === destination.cookie;
      });
      if (conflict) return { ok: false, reason: 'the request already contains the session cookie' };
    }
    const key = cookieKeys[0] ?? 'Cookie';
    const existing = cookieKeys.map(cookieKey => headers[cookieKey]).filter(Boolean).join('; ');
    for (const cookieKey of cookieKeys) delete result[cookieKey];
    result[key] = `${existing ? `${existing}; ` : ''}${destination.cookie}=${session}`;
  }
  return { ok: true, headers: result };
}

export function secretFormsFor(values: string[]): string[] {
  const forms = new Set<string>();
  for (const value of values) {
    if (!value) continue;
    forms.add(value);
    for (const form of secretForms(
      { in: 'header', name: 'Authorization', template: 'Bearer {key}' },
      value,
    )) {
      if (form) forms.add(form);
    }
    const escaped = JSON.stringify(value).slice(1, -1);
    forms.add(escaped);
    forms.add(escaped.replace(/\//g, '\\/'));
    forms.add(Buffer.from(value, 'utf8').toString('base64'));
    forms.add(Buffer.from(value, 'utf8').toString('base64url'));
  }
  return [...forms];
}

export function scrubResponse(
  res: Response,
  secrets: string[],
): { headers: Record<string, string | string[]>; body: string } {
  const forms = secretFormsFor(secrets);
  const headers: [string, string | string[]][] = [];
  for (const [name, value] of Object.entries(res.headers)) {
    if (name.toLowerCase() === 'set-cookie' || value === undefined) continue;
    headers.push([
      name,
      Array.isArray(value) ? value.map(item => scrub(item, forms)) : scrub(value, forms),
    ]);
  }
  return { headers: Object.fromEntries(headers), body: scrub(res.body, forms) };
}

export class SessionCache {
  private readonly sessions = new Map<string, { session: string; expiresAt?: number }>();
  private readonly flights = new Map<string, Promise<string>>();
  /** Every session seen per group (agent+entry+address), kept to scrub later replies (round 3, F1). */
  private readonly history = new Map<string, string[]>();
  /** One login at a time per group, whatever recipe or value is current (round 3, F2). */
  private readonly locks = new Map<string, Promise<unknown>>();
  static readonly MAX_SESSIONS = 256;
  static readonly MAX_HISTORY = 16;
  /** A session with no stated lifetime is still not kept for ever (round 3, B2). */
  static readonly DEFAULT_TTL_SECONDS = 12 * 3600;

  constructor(private readonly now: () => number = Date.now) {}

  remember(group: string, session: string): void {
    const list = (this.history.get(group) ?? []).filter((s) => s !== session);
    list.push(session);
    while (list.length > SessionCache.MAX_HISTORY) list.shift();
    this.history.delete(group);
    this.history.set(group, list);
    while (this.history.size > SessionCache.MAX_SESSIONS) {
      this.history.delete(this.history.keys().next().value as string);
    }
  }

  seen(group: string): string[] {
    return [...(this.history.get(group) ?? [])];
  }

  async exclusive<T>(group: string, fn: () => Promise<T>): Promise<T> {
    const before = this.locks.get(group) ?? Promise.resolve();
    const run = before.catch(() => undefined).then(fn);
    const tail = run.catch(() => undefined);
    this.locks.set(group, tail);
    try { return await run; } finally {
      if (this.locks.get(group) === tail) this.locks.delete(group);
    }
  }

  get(key: string): string | undefined {
    const cached = this.sessions.get(key);
    if (!cached) return undefined;
    if (cached.expiresAt !== undefined && this.now() >= cached.expiresAt) {
      this.sessions.delete(key);
      return undefined;
    }
    return cached.session;
  }

  set(key: string, session: string, expiresAfterSeconds?: number): void {
    const cached: { session: string; expiresAt?: number } = {
      session, expiresAt: this.now() + (expiresAfterSeconds ?? SessionCache.DEFAULT_TTL_SECONDS) * 1000,
    };
    this.sessions.delete(key);
    while (this.sessions.size >= SessionCache.MAX_SESSIONS) {
      this.sessions.delete(this.sessions.keys().next().value as string);
    }
    this.sessions.set(key, cached);
  }

  delete(key: string): void {
    this.sessions.delete(key);
    this.flights.delete(key);
  }

  /**
   * The service said `used` is signed out. Forget it only if it is still the cached one,
   * and never cancel a login already in flight: two calls that both got a 401 then share
   * ONE re-login instead of each starting their own (review round 1, F2).
   */
  expire(key: string, used: string): void {
    if (this.sessions.get(key)?.session === used) this.sessions.delete(key);
  }

  deleteWhere(pred: (key: string) => boolean): void {
    const keys = new Set([...this.sessions.keys(), ...this.flights.keys()]);
    for (const key of keys) {
      if (pred(key)) this.delete(key);
    }
  }

  async singleFlight(
    key: string,
    login: () => Promise<string>,
    expiresAfterSeconds?: number,
  ): Promise<string> {
    const cached = this.get(key);
    if (cached !== undefined) return cached;
    const existing = this.flights.get(key);
    if (existing) return existing;

    const pending = Promise.resolve().then(login).then(session => {
      // Invalidating a key during login must not repopulate the cache.
      if (this.flights.get(key) === pending) this.set(key, session, expiresAfterSeconds);
      return session;
    }).finally(() => {
      if (this.flights.get(key) === pending) this.flights.delete(key);
    });
    this.flights.set(key, pending);
    return pending;
  }
}

export function sessionKey(p: {
  entryId: string;
  origin: string;
  recipeSha: string;
  valueSha: string;
  pin?: string;
}): string {
  return [p.entryId, p.origin, p.recipeSha, p.valueSha, p.pin ?? ''].join('\0');
}
