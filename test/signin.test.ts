import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../src/opdef.js';
import {
  applySession,
  describeSignIn,
  extractSession,
  renderLoginBody,
  scrubResponse,
  secretFormsFor,
  SessionCache,
  sessionKey,
  signInRecipeSha,
  validateSignInRecipe,
  type SignInRecipe,
} from '../src/signin.js';

function rawRecipe() {
  return {
    login: {
      method: 'POST' as const,
      path: '/jrd/webapi',
      body_format: 'json' as const,
      body: { username: '{{username}}', password: '{{password}}' },
    },
    session_from: { cookie: 'qsessionid' },
    send_session_as: { cookie: 'qsessionid' },
  };
}

function recipe(): SignInRecipe {
  return { ...rawRecipe(), signed_out_when: [401] };
}

function nested(depth: number): unknown {
  let value: unknown = '{{password}}';
  for (let index = 0; index < depth; index++) value = { child: value };
  return value;
}

function deferred() {
  let resolve!: (value: string) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<string>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe('validateSignInRecipe', () => {
  it('accepts a login and fills the default without mutating the input', () => {
    const raw = rawRecipe();
    expect(validateSignInRecipe(raw)).toEqual({
      ok: true,
      recipe: { ...raw, signed_out_when: [401] },
    });
    expect(raw).not.toHaveProperty('signed_out_when');
  });

  it('accepts both methods, JSON values, and the maximum body depth', () => {
    const raw = rawRecipe();
    for (const method of ['POST', 'PUT']) {
      for (const body of [
        '{{password}}',
        ['{{password}}', null, false, true, 2.5],
        { arbitrary: { data: ['{{password}}', '{{username}}'] } },
        nested(6),
      ]) {
        expect(validateSignInRecipe({
          ...raw,
          login: { ...raw.login, method, body },
        }).ok).toBe(true);
      }
    }
  });

  it('accepts form data, all allowed statuses and lifetime boundaries', () => {
    const raw = rawRecipe();
    for (const expires of [60, 86400]) {
      expect(validateSignInRecipe({
        ...raw,
        login: {
          ...raw.login,
          method: 'PUT',
          body_format: 'form',
          body: { user: '{{username}}', pass: 'prefix:{{password}}', extra: '' },
        },
        signed_out_when: [401, 403, 419, 440],
        expires_after_seconds: expires,
      }).ok).toBe(true);
    }
  });

  it('accepts every allowed token character and 64-character names', () => {
    const raw = rawRecipe();
    for (const name of ["AZaz09!#$%&'*+.^_`|~-", 'x'.repeat(64)]) {
      for (const session_from of [{ cookie: name }, { header: name }]) {
        for (const send_session_as of [
          { cookie: name },
          { header: name, template: '{{session}}' },
        ]) {
          expect(validateSignInRecipe({ ...raw, session_from, send_session_as }).ok).toBe(true);
        }
      }
    }
  });

  it('accepts numeric path segments, eight segments and 64-character segments', () => {
    for (const path of ['data.0.sid', 'a.b.c.d.e.f.g.h', 'a'.repeat(64)]) {
      expect(validateSignInRecipe({
        ...rawRecipe(),
        session_from: { json: path },
      }).ok).toBe(true);
    }
  });

  it('accepts the path and session header length boundaries', () => {
    const raw = rawRecipe();
    expect(validateSignInRecipe({
      ...raw,
      login: { ...raw.login, path: `/${'a'.repeat(511)}` },
      send_session_as: {
        header: 'Authorization',
        template: `${'x'.repeat(256 - '{{session}}'.length)}{{session}}`,
      },
    }).ok).toBe(true);
    expect(validateSignInRecipe({
      ...raw,
      login: { ...raw.login, path: '/' },
    }).ok).toBe(true);
  });

  const base = rawRecipe();
  const invalid: { name: string; raw: unknown }[] = [
    { name: 'null', raw: null },
    { name: 'array', raw: [] },
    { name: 'unknown root field', raw: { ...base, extra: true } },
    { name: 'missing login', raw: { session_from: base.session_from, send_session_as: base.send_session_as } },
    { name: 'unknown login field', raw: { ...base, login: { ...base.login, extra: true } } },
    { name: 'unsupported method', raw: { ...base, login: { ...base.login, method: 'GET' } } },
    { name: 'unsupported body format', raw: { ...base, login: { ...base.login, body_format: 'text' } } },
    { name: 'missing body', raw: { ...base, login: { method: 'POST', path: '/', body_format: 'json' } } },
    { name: 'non-absolute path', raw: { ...base, login: { ...base.login, path: 'login' } } },
    { name: 'double slash', raw: { ...base, login: { ...base.login, path: '/api//login' } } },
    { name: 'parent path segment', raw: { ...base, login: { ...base.login, path: '/api/../login' } } },
    { name: 'parent segment before query', raw: { ...base, login: { ...base.login, path: '/..?x=1' } } },
    { name: 'fragment', raw: { ...base, login: { ...base.login, path: '/login#token' } } },
    { name: 'space in path', raw: { ...base, login: { ...base.login, path: '/log in' } } },
    { name: 'newline in path', raw: { ...base, login: { ...base.login, path: '/login\n' } } },
    { name: 'control in path', raw: { ...base, login: { ...base.login, path: '/login\u0000' } } },
    { name: 'DEL in path', raw: { ...base, login: { ...base.login, path: '/login\u007f' } } },
    { name: 'long path', raw: { ...base, login: { ...base.login, path: `/${'a'.repeat(512)}` } } },
    { name: 'no password', raw: { ...base, login: { ...base.login, body: { user: '{{username}}' } } } },
    { name: 'unknown body slot', raw: { ...base, login: { ...base.login, body: '{{password}} {{other}}' } } },
    { name: 'unfinished body slot', raw: { ...base, login: { ...base.login, body: '{{password}} {{username' } } },
    { name: 'depth seven', raw: { ...base, login: { ...base.login, body: nested(7) } } },
    { name: 'undefined JSON value', raw: { ...base, login: { ...base.login, body: ['{{password}}', undefined] } } },
    { name: 'non-finite JSON value', raw: { ...base, login: { ...base.login, body: ['{{password}}', Infinity] } } },
    { name: 'non-JSON object', raw: { ...base, login: { ...base.login, body: ['{{password}}', new Date(0)] } } },
    { name: 'non-object form', raw: { ...base, login: { ...base.login, body_format: 'form', body: '{{password}}' } } },
    { name: 'array form', raw: { ...base, login: { ...base.login, body_format: 'form', body: ['{{password}}'] } } },
    { name: 'nested form', raw: { ...base, login: { ...base.login, body_format: 'form', body: { pass: '{{password}}', extra: {} } } } },
    { name: 'numeric form value', raw: { ...base, login: { ...base.login, body_format: 'form', body: { pass: '{{password}}', extra: 1 } } } },
    { name: 'unknown form slot', raw: { ...base, login: { ...base.login, body_format: 'form', body: { pass: '{{password}} {{unknown}}' } } } },
    { name: 'form without password', raw: { ...base, login: { ...base.login, body_format: 'form', body: { user: '{{username}}' } } } },
    { name: 'empty source', raw: { ...base, session_from: {} } },
    { name: 'unknown source field', raw: { ...base, session_from: { cookie: 'sid', extra: true } } },
    { name: 'multiple sources', raw: { ...base, session_from: { cookie: 'sid', header: 'X-Session' } } },
    { name: 'empty destination', raw: { ...base, send_session_as: {} } },
    { name: 'unknown destination field', raw: { ...base, send_session_as: { cookie: 'sid', extra: true } } },
    { name: 'multiple destinations', raw: { ...base, send_session_as: { cookie: 'sid', header: 'X-Session', template: '{{session}}' } } },
    { name: 'missing session slot', raw: { ...base, send_session_as: { header: 'Authorization', template: 'Bearer token' } } },
    { name: 'repeated session slot', raw: { ...base, send_session_as: { header: 'Authorization', template: '{{session}}{{session}}' } } },
    { name: 'unknown session slot', raw: { ...base, send_session_as: { header: 'Authorization', template: '{{session}} {{password}}' } } },
    { name: 'unfinished session slot', raw: { ...base, send_session_as: { header: 'Authorization', template: '{{session}} {{' } } },
    { name: 'CR in session header', raw: { ...base, send_session_as: { header: 'Authorization', template: '{{session}}\r' } } },
    { name: 'LF in session header', raw: { ...base, send_session_as: { header: 'Authorization', template: '{{session}}\n' } } },
    { name: 'long session header', raw: { ...base, send_session_as: { header: 'Authorization', template: `${'x'.repeat(257 - '{{session}}'.length)}{{session}}` } } },
    { name: 'empty statuses', raw: { ...base, signed_out_when: [] } },
    { name: 'unsupported status', raw: { ...base, signed_out_when: [401, 500] } },
    { name: 'string status', raw: { ...base, signed_out_when: ['401'] } },
    { name: 'undefined statuses', raw: { ...base, signed_out_when: undefined } },
    { name: 'short lifetime', raw: { ...base, expires_after_seconds: 59 } },
    { name: 'long lifetime', raw: { ...base, expires_after_seconds: 86401 } },
    { name: 'fractional lifetime', raw: { ...base, expires_after_seconds: 60.5 } },
    { name: 'string lifetime', raw: { ...base, expires_after_seconds: '60' } },
    { name: 'undefined lifetime', raw: { ...base, expires_after_seconds: undefined } },
  ];

  it.each(invalid)('refuses $name', ({ raw }) => {
    expect(validateSignInRecipe(raw)).toMatchObject({ ok: false, reason: expect.any(String) });
  });

  it('refuses invalid names in every name position', () => {
    for (const name of ['', 'a b', 'a:b', 'a/b', 'a\n', 'é', 'a'.repeat(65)]) {
      for (const session_from of [{ cookie: name }, { header: name }]) {
        expect(validateSignInRecipe({ ...base, session_from }).ok).toBe(false);
      }
      for (const send_session_as of [
        { cookie: name },
        { header: name, template: '{{session}}' },
      ]) {
        expect(validateSignInRecipe({ ...base, send_session_as }).ok).toBe(false);
      }
    }
  });

  it('refuses all forbidden outbound headers case-insensitively', () => {
    for (const header of [
      'Host', 'CONTENT-LENGTH', 'Transfer-Encoding', 'Connection', 'Cookie', 'Proxy-Authorization',
    ]) {
      expect(validateSignInRecipe({
        ...base,
        send_session_as: { header, template: '{{session}}' },
      }).ok).toBe(false);
    }
  });

  it('refuses invalid response paths', () => {
    for (const json of [
      '', '.token', 'token.', 'data..sid', 'data[0].sid', 'a b', 'a/b',
      'a'.repeat(65), 'a.b.c.d.e.f.g.h.i',
    ]) {
      expect(validateSignInRecipe({ ...base, session_from: { json } }).ok).toBe(false);
    }
  });

  it('limits the normalized canonical recipe to 4096 UTF-8 bytes', () => {
    const raw = rawRecipe();
    const body = '{{password}}';
    const overhead = Buffer.byteLength(canonicalJson({
      ...raw,
      login: { ...raw.login, body },
      signed_out_when: [401],
    }), 'utf8');
    const padding = 'x'.repeat(4096 - overhead);
    expect(validateSignInRecipe({
      ...raw,
      login: { ...raw.login, body: body + padding },
    }).ok).toBe(true);
    expect(validateSignInRecipe({
      ...raw,
      login: { ...raw.login, body: body + padding + 'x' },
    }).ok).toBe(false);
    expect(validateSignInRecipe({
      ...raw,
      login: { ...raw.login, body: body + padding.replace(/x/g, 'é') },
    }).ok).toBe(false);
  });

  it('refuses cycles and does not include body data in errors', () => {
    const body: Record<string, unknown> = { password: '{{password}}', marker: 'private-marker' };
    body.self = body;
    const result = validateSignInRecipe({
      ...base,
      login: { ...base.login, body },
    });
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).not.toContain('private-marker');
  });
});

describe('sign-in approval', () => {
  it('hashes the versioned operation and origin, not just the recipe', () => {
    const value = recipe();
    const origin = 'https://192.168.1.1';
    const sha = signInRecipeSha(value, origin);
    expect(sha).toMatch(/^[a-f0-9]{64}$/);
    expect(sha).toBe(createHash('sha256').update(canonicalJson({
      type: 'sign_in', v: 1, origin, recipe: value,
    })).digest('hex'));
    expect(sha).not.toBe(signInRecipeSha(value, 'https://192.168.1.2'));
    expect(sha).not.toBe(createHash('sha256').update(canonicalJson(value)).digest('hex'));
    expect(sha).not.toBe(signInRecipeSha({
      ...value,
      login: { ...value.login, path: '/other' },
    }, origin));
  });

  it('is independent of object key insertion order', () => {
    const value = recipe();
    const reordered: SignInRecipe = {
      signed_out_when: [401],
      send_session_as: value.send_session_as,
      session_from: value.session_from,
      login: {
        body: value.login.body,
        body_format: value.login.body_format,
        path: value.login.path,
        method: value.login.method,
      },
    };
    expect(signInRecipeSha(value, 'https://example.com'))
      .toBe(signInRecipeSha(reordered, 'https://example.com'));
  });

  it('describes cookie delivery in plain English', () => {
    const text = describeSignIn(recipe(), 'https://192.168.1.1', 'admin');
    expect(text).toBe('Sign in to https://192.168.1.1 as admin by sending your password to /jrd/webapi, then send the session as the cookie qsessionid on later calls to that address.');
    expect(text).not.toMatch(/JSON-RPC|TOTP|template|recipe|placeholder/i);
  });

  it('describes header delivery without exposing its formatting', () => {
    const text = describeSignIn({
      ...recipe(),
      send_session_as: { header: 'Authorization', template: 'Bearer {{session}}' },
    }, 'https://example.com', '');
    expect(text).toContain('the Authorization header');
    expect(text).not.toContain('Bearer');
    expect(text).not.toMatch(/JSON-RPC|TOTP|template|recipe|placeholder/i);
  });
});

describe('renderLoginBody', () => {
  it('substitutes JSON string values before serialization', () => {
    const value = recipe();
    value.login.body = {
      user: '{{username}}',
      nested: ['{{password}}', { combined: 'prefix:{{password}}:suffix' }],
      untouched: [null, true, 12],
      '{{username}}': 'literal key',
    };
    const password = 'a"}雪/{{username}}/$&';
    const original = canonicalJson(value);
    const rendered = renderLoginBody(value, { username: 'admin', password });
    expect(rendered.contentType).toBe('application/json');
    expect(JSON.parse(rendered.body)).toEqual({
      user: 'admin',
      nested: [password, { combined: `prefix:${password}:suffix` }],
      untouched: [null, true, 12],
      '{{username}}': 'literal key',
    });
    expect(canonicalJson(value)).toBe(original);
  });

  it('supports a JSON string as the root body', () => {
    const value = recipe();
    value.login.body = '{{password}}';
    expect(JSON.parse(renderLoginBody(value, { password: '"}密' }).body)).toBe('"}密');
  });

  it('renders form fields with URLSearchParams', () => {
    const value = recipe();
    value.login = {
      ...value.login,
      body_format: 'form',
      body: { username: '{{username}}', password: '{{password}}', repeated: '{{password}}' },
    };
    const password = 'a&b=+ "}密';
    const rendered = renderLoginBody(value, { username: 'a b', password });
    expect(rendered.contentType).toBe('application/x-www-form-urlencoded');
    const fields = new URLSearchParams(rendered.body);
    expect(fields.get('username')).toBe('a b');
    expect(fields.get('password')).toBe(password);
    expect(fields.get('repeated')).toBe(password);
  });

  it('requires a non-empty username only when a string value uses it', () => {
    for (const username of [undefined, '']) {
      expect(() => renderLoginBody(recipe(), { username, password: 'password' }))
        .toThrow('this login has no username');
      const form = recipe();
      form.login = {
        ...form.login,
        body_format: 'form',
        body: { user: '{{username}}', pass: '{{password}}' },
      };
      expect(() => renderLoginBody(form, { username, password: 'password' }))
        .toThrow('this login has no username');
    }
    const value = recipe();
    value.login.body = { password: '{{password}}' };
    expect(JSON.parse(renderLoginBody(value, { password: 'password' }).body))
      .toEqual({ password: 'password' });
  });
});

describe('extractSession', () => {
  it('finds the named cookie among multiple Set-Cookie values', () => {
    expect(extractSession(recipe(), {
      headers: {
        'SeT-CoOkIe': ['other=one; Path=/', 'qsessionid=token==; HttpOnly; Path=/'],
      },
      body: '',
    })).toBe('token==');
    expect(extractSession(recipe(), {
      headers: { 'SET-COOKIE': 'qsessionid=single; Secure' },
      body: '',
    })).toBe('single');
  });

  it('handles separately cased keys and folded cookie headers with Expires', () => {
    expect(extractSession(recipe(), {
      headers: {
        'Set-Cookie': 'other=one',
        'set-cookie': 'another=two; Expires=Wed, 21 Oct 2030 07:28:00 GMT, qsessionid=found; Path=/',
      },
      body: '',
    })).toBe('found');
  });

  it('matches cookie names exactly', () => {
    expect(extractSession(recipe(), {
      headers: { 'set-cookie': ['QSESSIONID=wrong', 'prefixqsessionid=wrong'] },
      body: '',
    })).toBeNull();
  });

  it('reads response headers case-insensitively, using the first array value', () => {
    const value = { ...recipe(), session_from: { header: 'X-Session' } };
    expect(extractSession(value, {
      headers: { 'x-SESSION': 'token' }, body: '',
    })).toBe('token');
    expect(extractSession(value, {
      headers: { 'X-Session': ['first', 'second'] }, body: '',
    })).toBe('first');
    expect(extractSession(value, { headers: {}, body: '' })).toBeNull();
  });

  it('walks object and numeric array paths and stringifies numeric tokens', () => {
    expect(extractSession({
      ...recipe(), session_from: { json: 'result.token' },
    }, {
      headers: {}, body: '{"result":{"token":"abc"}}',
    })).toBe('abc');
    expect(extractSession({
      ...recipe(), session_from: { json: 'data.0.sid' },
    }, {
      headers: {}, body: '{"data":[{"sid":12345}]}',
    })).toBe('12345');
    expect(extractSession({
      ...recipe(), session_from: { json: 'result.token' },
    }, {
      headers: {}, body: '{"result":{"token":0}}',
    })).toBe('0');
  });

  it('refuses malformed, missing, empty and non-scalar JSON tokens', () => {
    const value = { ...recipe(), session_from: { json: 'result.token' } };
    for (const body of [
      'not JSON', '{}', '{"result":null}', '{"result":{}}',
      '{"result":{"token":""}}', '{"result":{"token":true}}',
      '{"result":{"token":null}}', '{"result":{"token":[]}}',
      '{"result":{"token":{}}}', '{"result":{"token":1e400}}',
    ]) {
      expect(extractSession(value, { headers: {}, body })).toBeNull();
    }
    expect(extractSession({
      ...recipe(), session_from: { json: 'data.length' },
    }, { headers: {}, body: '{"data":[]}' })).toBeNull();
    expect(extractSession({
      ...recipe(), session_from: { json: 'constructor.name' },
    }, { headers: {}, body: '{}' })).toBeNull();
  });

  it('enforces the session length limit for every source', () => {
    for (const length of [0, 8192, 8193]) {
      const token = 'x'.repeat(length);
      const expected = length === 8192 ? token : null;
      expect(extractSession(recipe(), {
        headers: { 'set-cookie': `qsessionid=${token}` }, body: '',
      })).toBe(expected);
      expect(extractSession({
        ...recipe(), session_from: { header: 'X-Session' },
      }, {
        headers: { 'X-Session': token }, body: '',
      })).toBe(expected);
      expect(extractSession({
        ...recipe(), session_from: { json: 'token' },
      }, {
        headers: {}, body: JSON.stringify({ token }),
      })).toBe(expected);
    }
  });
});

describe('applySession', () => {
  it('adds or appends a cookie without modifying caller headers', () => {
    const headers = { Accept: 'application/json', cOoKiE: 'other=one' };
    const result = applySession(recipe(), 'token', headers);
    expect(result).toEqual({
      ok: true,
      headers: { Accept: 'application/json', cOoKiE: 'other=one; qsessionid=token' },
    });
    expect(headers).toEqual({ Accept: 'application/json', cOoKiE: 'other=one' });
    if (result.ok) expect(result.headers).not.toBe(headers);
    expect(applySession(recipe(), 'token', {})).toEqual({
      ok: true, headers: { Cookie: 'qsessionid=token' },
    });
  });

  it('refuses an existing cookie with the same name', () => {
    for (const cookie of ['qsessionid=old', 'other=one; qsessionid = old']) {
      expect(applySession(recipe(), 'new', { COOKIE: cookie })).toMatchObject({ ok: false });
    }
    expect(applySession(recipe(), 'new', { Cookie: 'QSESSIONID=other' }).ok).toBe(true);
  });

  it('checks and consolidates all differently cased Cookie headers', () => {
    expect(applySession(recipe(), 'token', {
      Cookie: 'one=1', cookie: 'qsessionid=old',
    }).ok).toBe(false);
    expect(applySession(recipe(), 'token', {
      Cookie: 'one=1', cookie: 'two=2',
    })).toEqual({
      ok: true, headers: { Cookie: 'one=1; two=2; qsessionid=token' },
    });
  });

  it('adds a header with literal replacement and refuses case-insensitive conflicts', () => {
    const value = {
      ...recipe(),
      send_session_as: { header: 'Authorization', template: 'Bearer {{session}}' },
    };
    const headers = { Accept: 'application/json' };
    expect(applySession(value, '$&token', headers)).toEqual({
      ok: true,
      headers: { Accept: 'application/json', Authorization: 'Bearer $&token' },
    });
    expect(headers).toEqual({ Accept: 'application/json' });
    expect(applySession(value, 'token', { authorization: 'caller' }))
      .toMatchObject({ ok: false });
  });

  it('refuses session values that could inject headers or cookies', () => {
    expect(applySession(recipe(), 'token; other=bad', {})).toMatchObject({ ok: false });
    expect(applySession(recipe(), 'token\r\nX-Bad: yes', {})).toMatchObject({ ok: false });
    expect(applySession({
      ...recipe(),
      send_session_as: { header: 'Authorization', template: 'Bearer {{session}}' },
    }, 'token\nX-Bad: yes', {})).toMatchObject({ ok: false });
  });
});

describe('response scrubbing', () => {
  it('generates literal, URL, JSON, slash-escaped and both base64 spellings', () => {
    const value = 'a/b"雪';
    const forms = secretFormsFor(['', value, value]);
    const escaped = JSON.stringify(value).slice(1, -1);
    for (const form of [
      value,
      encodeURIComponent(value),
      escaped,
      escaped.replace(/\//g, '\\/'),
      Buffer.from(value).toString('base64'),
      Buffer.from(value).toString('base64url'),
    ]) {
      expect(forms).toContain(form);
    }
    expect(forms).not.toContain('');
    expect(new Set(forms).size).toBe(forms.length);
    expect(secretFormsFor(['', ''])).toEqual([]);
  });

  it('scrubs every ordinary header value and the body and drops every Set-Cookie', () => {
    const secrets = ['a/b', 'p"a}密'];
    const forms = secretFormsFor(secrets);
    expect(forms).toContain('a\\/b');
    const text = forms.join(' | ');
    const res = {
      headers: {
        'Set-Cookie': 'a/b',
        'sEt-CoOkIe': ['p"a}密'],
        'X-Echo': text,
        'X-Array': [text, `prefix ${text} suffix`],
        'X-Omitted': undefined,
        'Content-Type': 'text/plain',
      },
      body: text,
    };
    const result = scrubResponse(res, secrets);
    expect(Object.keys(result.headers).some(key => key.toLowerCase() === 'set-cookie')).toBe(false);
    expect(result.headers).not.toHaveProperty('X-Omitted');
    expect(result.headers['Content-Type']).toBe('text/plain');
    expect(result.body).toContain('[REDACTED]');
    expect(result.headers['X-Echo']).toBe(result.body);
    expect(result.headers['X-Array']).toEqual([result.body, `prefix ${result.body} suffix`]);
    for (const form of forms) {
      expect(result.body).not.toContain(form);
      expect(String(result.headers['X-Echo'])).not.toContain(form);
    }
    expect(res.body).toBe(text);
    expect(res.headers['Set-Cookie']).toBe('a/b');
    expect(res.headers['X-Array']).toEqual([text, `prefix ${text} suffix`]);
  });

  it('drops cookies even when there are no secrets', () => {
    expect(scrubResponse({
      headers: { 'SET-cookie': 'secret', Other: ['one', 'two'], Missing: undefined },
      body: 'unchanged',
    }, [])).toEqual({
      headers: { Other: ['one', 'two'] },
      body: 'unchanged',
    });
  });
});

describe('SessionCache', () => {
  it('shares one login across five concurrent calls and then uses the cache', async () => {
    const cache = new SessionCache();
    const gate = deferred();
    let calls = 0;
    const login = () => {
      calls++;
      return gate.promise;
    };
    const pending = Array.from({ length: 5 }, () => cache.singleFlight('key', login));
    await Promise.resolve();
    expect(calls).toBe(1);
    gate.resolve('session');
    expect(await Promise.all(pending)).toEqual(Array(5).fill('session'));
    expect(await cache.singleFlight('key', login)).toBe('session');
    expect(calls).toBe(1);
  });

  it('shares failures without caching them and retries on the next call', async () => {
    const cache = new SessionCache();
    const gate = deferred();
    let calls = 0;
    const login = () => {
      calls++;
      return calls === 1 ? gate.promise : Promise.resolve('recovered');
    };
    const first = cache.singleFlight('key', login);
    const second = cache.singleFlight('key', login);
    const firstFailure = expect(first).rejects.toThrow('login failed');
    const secondFailure = expect(second).rejects.toThrow('login failed');
    await Promise.resolve();
    expect(calls).toBe(1);
    gate.reject(new Error('login failed'));
    await Promise.all([firstFailure, secondFailure]);
    expect(cache.get('key')).toBeUndefined();
    expect(await cache.singleFlight('key', login)).toBe('recovered');
    expect(calls).toBe(2);
  });

  it('also permits retry after a synchronous login exception', async () => {
    const cache = new SessionCache();
    await expect(cache.singleFlight('key', () => {
      throw new Error('failed');
    })).rejects.toThrow('failed');
    expect(await cache.singleFlight('key', async () => 'next')).toBe('next');
  });

  it('honours expiry at the exact boundary using the injected millisecond clock', async () => {
    let now = 1000;
    const cache = new SessionCache(() => now);
    let calls = 0;
    const login = async () => `session-${++calls}`;
    expect(await cache.singleFlight('key', login, 60)).toBe('session-1');
    now = 60999;
    expect(cache.get('key')).toBe('session-1');
    expect(await cache.singleFlight('key', login, 60)).toBe('session-1');
    now = 61000;
    expect(cache.get('key')).toBeUndefined();
    expect(await cache.singleFlight('key', login, 60)).toBe('session-2');
    expect(calls).toBe(2);
  });

  it('starts expiry when login completes, not when it starts', async () => {
    let now = 0;
    const cache = new SessionCache(() => now);
    const gate = deferred();
    const pending = cache.singleFlight('key', () => gate.promise, 60);
    await Promise.resolve();
    now = 5000;
    gate.resolve('session');
    await pending;
    now = 64999;
    expect(cache.get('key')).toBe('session');
    now = 65000;
    expect(cache.get('key')).toBeUndefined();
  });

  it('supports direct set, overwrite, indefinite lifetime and deletion', () => {
    let now = 0;
    const cache = new SessionCache(() => now);
    cache.set('permanent', 'one');
    cache.set('expires', 'old', 60);
    cache.set('expires', 'new', 120);
    now = 60000;
    expect(cache.get('expires')).toBe('new');
    now = 120000;
    expect(cache.get('expires')).toBeUndefined();
    expect(cache.get('permanent')).toBe('one');
    cache.delete('permanent');
    expect(cache.get('permanent')).toBeUndefined();
    cache.delete('absent');
  });

  it('deletes matching keys without affecting other entries', () => {
    const cache = new SessionCache();
    cache.set('entry-a:one', 'one');
    cache.set('entry-a:two', 'two');
    cache.set('entry-b:one', 'three');
    cache.deleteWhere(key => key.startsWith('entry-a:'));
    expect(cache.get('entry-a:one')).toBeUndefined();
    expect(cache.get('entry-a:two')).toBeUndefined();
    expect(cache.get('entry-b:one')).toBe('three');
  });

  it('does not repopulate an invalidated key when an old login finishes', async () => {
    for (const matchingDelete of [false, true]) {
      const cache = new SessionCache();
      const old = deferred();
      const pending = cache.singleFlight('key', () => old.promise);
      await Promise.resolve();
      if (matchingDelete) cache.deleteWhere(key => key === 'key');
      else cache.delete('key');
      expect(await cache.singleFlight('key', async () => 'new')).toBe('new');
      old.resolve('old');
      expect(await pending).toBe('old');
      expect(cache.get('key')).toBe('new');
    }
  });

  it('does not share logins between different keys', async () => {
    const cache = new SessionCache();
    let calls = 0;
    const login = async () => `session-${++calls}`;
    expect(await Promise.all([
      cache.singleFlight('one', login),
      cache.singleFlight('two', login),
    ])).toEqual(['session-1', 'session-2']);
    expect(calls).toBe(2);
  });
});

describe('sessionKey', () => {
  it('joins all five fields with NUL and uses an empty field for an absent pin', () => {
    const parts = {
      entryId: 'entry',
      origin: 'https://example.com',
      recipeSha: 'recipe-hash',
      valueSha: 'value-hash',
    };
    expect(sessionKey(parts)).toBe('entry\0https://example.com\0recipe-hash\0value-hash\0');
    expect(sessionKey({ ...parts, pin: 'cert-hash' }))
      .toBe('entry\0https://example.com\0recipe-hash\0value-hash\0cert-hash');
    for (const changed of [
      { entryId: 'other' },
      { origin: 'https://other.example' },
      { recipeSha: 'other' },
      { valueSha: 'other' },
      { pin: 'other' },
    ]) {
      expect(sessionKey({ ...parts, ...changed })).not.toBe(sessionKey(parts));
    }
  });
});
