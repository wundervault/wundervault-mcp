import { describe, expect, it } from 'vitest';
import {
  BEARER, basicToken, pathWithKey, renderCredential, secretForms, validateBinding,
} from '../src/delivery.js';
import {
  SHAPES, checkAgentHeaders, oauth1FromParts, readValue, renderPlacements,
  scrub, secretFormsAll, validateBindingV2,
} from '../src/parts.js';
import type { Delivery, PartsBinding, Shape } from '../src/parts.js';

function checked(raw: unknown, shape: Shape = 'api_key', delivery: Delivery = 'http'): PartsBinding {
  const result = validateBindingV2(raw, shape, delivery);
  if (!result.ok) throw new Error(`${result.field}: ${result.message}`);
  return result.binding;
}

function v2(placements: unknown[]): unknown {
  return { v: 2, placements };
}

function header(name: string, template: string): unknown {
  return { in: 'header', name, template };
}

function refused(raw: unknown, shape: Shape = 'key_id', delivery: Delivery = 'http'): void {
  expect(validateBindingV2(raw, shape, delivery)).toEqual({
    ok: false, field: expect.any(String), message: expect.any(String),
  });
}

function valueRefused(plain: string, shape: Shape = 'key_id'): void {
  expect(readValue(plain, 'parts-1', 'http', shape)).toEqual({
    ok: false, reason: expect.any(String),
  });
}

const twoHeaders = v2([
  header('APCA-API-KEY-ID', '{part:id}'),
  header('APCA-API-SECRET-KEY', '{part:secret}'),
]);

describe('readValue', () => {
  it('keeps a legacy JSON object as one opaque part', () => {
    const plain = '{"token":"abc"}';
    expect(readValue(plain, 'raw', 'http')).toEqual({
      ok: true, shape: 'api_key', parts: { key: plain },
    });
  });

  it('keeps a legacy JSON array as one opaque part', () => {
    expect(readValue('[1,2]', 'raw', 'http')).toEqual({
      ok: true, shape: 'api_key', parts: { key: '[1,2]' },
    });
  });

  it('keeps a legacy JSON number as one opaque part', () => {
    expect(readValue('123', 'raw', 'http')).toEqual({
      ok: true, shape: 'api_key', parts: { key: '123' },
    });
  });

  it('keeps an envelope-looking legacy string as one opaque part', () => {
    const plain = '{"parts":{"key":"x"}}';
    expect(readValue(plain, 'raw', 'http')).toEqual({
      ok: true, shape: 'api_key', parts: { key: plain },
    });
  });

  it('treats an absent format as raw, even for an envelope', () => {
    const plain = '{"parts":{"key":"x"}}';
    expect(readValue(plain, undefined, 'http')).toEqual({
      ok: true, shape: 'api_key', parts: { key: plain },
    });
  });

  it('uses private_key for an opaque SSH value', () => {
    const plain = '{"parts":{"private_key":"not an envelope"}}';
    expect(readValue(plain, undefined, 'ssh')).toEqual({
      ok: true, shape: 'ssh_key', parts: { private_key: plain },
    });
  });

  it('uses private_key and the wallet shape for a raw wallet value', () => {
    expect(readValue('123', 'raw', 'wallet')).toEqual({
      ok: true, shape: 'wallet', parts: { private_key: '123' },
    });
  });

  it('uses private_key and the signing shape for a raw signing value', () => {
    expect(readValue('[1,2]', 'raw', 'sign')).toEqual({
      ok: true, shape: 'signing_key', parts: { private_key: '[1,2]' },
    });
  });

  it('reads a parts-1 key and ID with exactly the required parts', () => {
    expect(readValue('{"parts":{"id":"PK123","secret":"secret"}}', 'parts-1', 'http', 'key_id')).toEqual({
      ok: true, shape: 'key_id', parts: { id: 'PK123', secret: 'secret' },
    });
  });

  it('refuses a missing part', () => {
    valueRefused('{"parts":{"id":"PK123"}}');
  });

  it('refuses an extra part', () => {
    valueRefused('{"parts":{"id":"PK123","secret":"secret","other":"extra"}}');
  });

  it('refuses a part larger than 16 KiB in UTF-8 bytes', () => {
    valueRefused(JSON.stringify({ parts: { id: 'PK123', secret: 'é'.repeat(8193) } }));
  });

  it('accepts a part exactly 16 KiB in UTF-8 bytes', () => {
    expect(readValue(JSON.stringify({ parts: { key: 'é'.repeat(8192) } }), 'parts-1', 'http').ok).toBe(true);
  });

  it('refuses more than four parts', () => {
    valueRefused(JSON.stringify({
      parts: { consumer_key: 'a', consumer_secret: 'b', token: 'c', token_secret: 'd', fifth: 'e' },
    }), 'signed_set');
  });

  it('refuses a non-string part', () => {
    valueRefused('{"parts":{"id":"PK123","secret":123}}');
  });

  it('refuses an invalid part id', () => {
    valueRefused('{"parts":{"key":"x","Bad-ID":"y"}}', 'api_key');
  });

  it('refuses a parts array', () => {
    valueRefused('{"parts":["id","secret"]}');
  });

  it('refuses an envelope with an extra top-level field', () => {
    valueRefused('{"parts":{"id":"PK123","secret":"x"},"shape":"key_id"}');
  });

  it('refuses a parts-2 envelope instead of guessing its format', () => {
    valueRefused('{"wv":"parts-2","parts":{"key":"x"}}', 'api_key');
  });

  it('refuses invalid JSON when the external format says parts-1', () => {
    valueRefused('not JSON');
  });

  it('allows a website login without its optional totp part', () => {
    expect(readValue('{"parts":{"username":"u","password":"p"}}', 'parts-1', 'http', 'website_login').ok).toBe(true);
  });

  it('allows a website login with its optional totp part', () => {
    expect(readValue(
      '{"parts":{"username":"u","password":"p","totp":"seed"}}',
      'parts-1', 'http', 'website_login',
    ).ok).toBe(true);
  });

  it('refuses a shape with the wrong delivery', () => {
    expect(readValue('{"parts":{"private_key":"x"}}', 'parts-1', 'http', 'ssh_key').ok).toBe(false);
  });

  it('does not silently reinterpret a raw value as a multipart shape', () => {
    expect(readValue('opaque', 'raw', 'http', 'key_id').ok).toBe(false);
  });

  it('refuses an oversized raw part too', () => {
    expect(readValue('é'.repeat(8193), 'raw', 'http').ok).toBe(false);
  });
});

describe('validateBindingV2', () => {
  it('refuses a placement naming a part absent from the shape', () => {
    refused(v2([header('x-key', '{part:missing}')]));
  });

  it('refuses a part placed twice', () => {
    refused(v2([
      header('x-id', '{part:id}'),
      header('x-other-id', '{part:id}'),
    ]));
  });

  it('refuses two header targets differing only in case', () => {
    refused(v2([
      header('X-Credential', '{part:id}'),
      header('x-CREDENTIAL', '{part:secret}'),
    ]));
  });

  it('refuses a forbidden credential header', () => {
    refused(v2([header('HoSt', '{part:key}')]), 'api_key');
  });

  it('refuses a fifth placement', () => {
    const placements = Array.from({ length: 5 }, () => ({
      in: 'stamp', name: '', template: '',
    }));
    refused(v2(placements), 'signed_set');
  });

  it('refuses the legacy basic placeholder in a query', () => {
    refused(v2([{ in: 'query', name: 'credential', template: '{basic}' }]));
  });

  it('refuses a named basic placeholder in a query', () => {
    refused(v2([{ in: 'query', name: 'credential', template: '{basic:id:secret}' }]));
  });

  it('refuses an unknown placement location', () => {
    refused(v2([{ in: 'body', name: 'credential', template: '{part:key}' }]), 'api_key');
  });

  it('refuses case-insensitive duplicate query targets', () => {
    refused(v2([
      { in: 'query', name: 'Key', template: '{part:id}' },
      { in: 'query', name: 'KEY', template: '{part:secret}' },
    ]));
  });

  it('refuses two path placements using different parts', () => {
    refused(v2([
      { in: 'path', name: '', template: '/id/{part:id}' },
      { in: 'path', name: '', template: '/secret/{part:secret}' },
    ]));
  });

  it('refuses a dot segment in a path template', () => {
    refused(v2([{ in: 'path', name: '', template: '/../{part:key}' }]), 'api_key');
  });

  it('refuses a path without a leading slash', () => {
    refused(v2([{ in: 'path', name: '', template: 'bot{part:key}' }]), 'api_key');
  });

  it('refuses pre-encoded characters in a path template', () => {
    refused(v2([{ in: 'path', name: '', template: '/%2e/{part:key}' }]), 'api_key');
  });

  it('refuses a template with two placeholders', () => {
    refused(v2([header('x-key', '{part:id}:{part:secret}')]));
  });

  it('refuses an unknown placeholder alongside a valid one', () => {
    refused(v2([header('x-key', '{part:key}{unknown}')]), 'api_key');
  });

  it('refuses a template containing a line break', () => {
    refused(v2([header('x-key', '{part:key}\r\nx-injected: yes')]), 'api_key');
  });

  it('refuses a template over 128 characters', () => {
    refused(v2([header('x-key', 'a'.repeat(119) + '{part:key}')]), 'api_key');
  });

  it('refuses an empty placements list', () => {
    refused(v2([]), 'api_key');
  });

  it('refuses unknown binding fields', () => {
    refused({ v: 2, placements: [header('x-key', '{part:key}')], ignored: true }, 'api_key');
  });

  it('refuses unknown placement fields', () => {
    refused(v2([{
      in: 'header', name: 'x-key', template: '{part:key}', username: 'ignored',
    }]), 'api_key');
  });

  it('normalises every credential header name', () => {
    expect(checked(twoHeaders, 'key_id')).toEqual(v2([
      header('apca-api-key-id', '{part:id}'),
      header('apca-api-secret-key', '{part:secret}'),
    ]));
  });

  it('allows a single key_id part to be placed', () => {
    expect(checked(v2([header('x-secret', '{part:secret}')]), 'key_id').v).toBe(2);
  });

  it('requires password parts in their basic-auth roles', () => {
    refused(v2([header('authorization', 'Basic {basic:password:username}')]), 'password');
  });

  it('refuses a plain password placement', () => {
    refused(v2([header('x-password', '{part:password}')]), 'password');
  });

  it('accepts a password basic-auth placement', () => {
    expect(checked(v2([
      header('authorization', 'Basic {basic:username:password}'),
    ]), 'password').v).toBe(2);
  });

  it('refuses a website login binding', () => {
    refused(v2([header('authorization', 'Basic {basic:username:password}')]), 'website_login');
  });

  it('refuses HTTP delivery for an SSH shape', () => {
    refused(v2([header('x-key', '{part:private_key}')]), 'ssh_key');
  });

  it('refuses web placements even with an SSH delivery', () => {
    refused(v2([header('x-key', '{part:private_key}')]), 'ssh_key', 'ssh');
  });

  it('accepts a signed set only as a lone stamp', () => {
    expect(checked(v2([{ in: 'stamp', name: '', template: '' }]), 'signed_set')).toEqual(
      v2([{ in: 'stamp', name: '', template: '' }]),
    );
  });

  it('refuses a signed-set part placed directly', () => {
    refused(v2([header('x-key', '{part:consumer_key}')]), 'signed_set');
  });

  it('refuses a stamp accompanied by another placement', () => {
    refused(v2([
      { in: 'stamp', name: '', template: '' },
      header('x-key', '{part:consumer_key}'),
    ]), 'signed_set');
  });

  it('refuses a stamp with a nonempty template', () => {
    refused(v2([{ in: 'stamp', name: '', template: '{part:consumer_key}' }]), 'signed_set');
  });

  it('refuses a stamp for a password, and accepts one for a single key', () => {
    refused(v2([{ in: 'stamp', name: '', template: '' }]), 'password');
    expect(checked(v2([{ in: 'stamp', name: '', template: '' }]), 'api_key').placements[0]!.in).toBe('stamp');
  });

  it('keeps a v1 basic username rather than converting it', () => {
    expect(checked({
      in: 'header', name: 'Authorization', template: 'Basic {basic}', username: 'legacy-user',
    })).toEqual({
      v: 1, in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'legacy-user',
    });
  });
});

describe('renderPlacements', () => {
  it('renders both key+ID headers', () => {
    expect(renderPlacements(checked(twoHeaders, 'key_id'), {
      id: 'PK$&123', secret: "secret$'456",
    })).toEqual({
      headers: { 'apca-api-key-id': 'PK$&123', 'apca-api-secret-key': "secret$'456" },
      query: [],
    });
  });

  it('renders named basic-auth parts', () => {
    const binding = checked(v2([header('Authorization', 'Basic {basic:id:secret}')]), 'key_id');
    expect(renderPlacements(binding, { id: 'account', secret: 'pass:word' })).toEqual({
      headers: { authorization: `Basic ${basicToken('account', 'pass:word')}` }, query: [],
    });
  });

  it('refuses a colon in a basic username at value time', () => {
    const binding = checked(v2([header('authorization', 'Basic {basic:id:secret}')]), 'key_id');
    expect(() => renderPlacements(binding, { id: 'account:admin', secret: 'password' })).toThrow(
      "a basic username must not contain ':'",
    );
  });

  it('refuses a missing value rather than rendering undefined', () => {
    expect(() => renderPlacements(checked(twoHeaders, 'key_id'), { id: 'PK123' })).toThrow('missing part: secret');
  });

  it('renders v1 bearer exactly as delivery.ts', () => {
    const secret = "key$&$'";
    expect(renderPlacements(checked(BEARER), { key: secret })).toEqual({
      headers: { authorization: renderCredential(BEARER, secret) }, query: [],
    });
  });

  it('renders v1 query exactly as delivery.ts without pre-encoding', () => {
    const raw = { in: 'query', name: 'api_key', template: '{secret}' };
    const legacy = validateBinding(raw);
    if (!legacy.ok) throw new Error(legacy.reason);
    const secret = 'key +/$&';
    expect(renderPlacements(checked(raw), { key: secret })).toEqual({
      headers: {}, query: [['api_key', renderCredential(legacy.binding, secret)]],
    });
  });

  it('renders v1 path exactly as delivery.ts for the stored path alone', () => {
    const raw = { in: 'path', name: '', template: '/services/{secret}' };
    const legacy = validateBinding(raw);
    if (!legacy.ok) throw new Error(legacy.reason);
    const secret = 'T/B/X';
    expect(renderPlacements(checked(raw), { key: secret })).toEqual({
      headers: {}, query: [], pathTemplate: pathWithKey(legacy.binding, secret, '/'),
    });
  });

  it('renders v1 basic with its original username exactly as delivery.ts', () => {
    const raw = {
      in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'legacy-user',
    };
    const legacy = validateBinding(raw);
    if (!legacy.ok) throw new Error(legacy.reason);
    const secret = "pass:$&$'";
    expect(renderPlacements(checked(raw), { key: secret })).toEqual({
      headers: { authorization: renderCredential(legacy.binding, secret) }, query: [],
    });
  });

  it('renders v2 path parts with the existing path semantics', () => {
    const binding = checked(v2([{ in: 'path', name: '', template: '/services/{part:key}' }]));
    expect(renderPlacements(binding, { key: 'T/B/X' })).toEqual({
      headers: {}, query: [], pathTemplate: '/services/T/B/X',
    });
  });

  it('refuses unsafe path part bytes instead of encoding them', () => {
    const binding = checked(v2([{ in: 'path', name: '', template: '/bot{part:key}' }]));
    expect(() => renderPlacements(binding, { key: 'token?redirect=elsewhere' })).toThrow();
  });

  it('does not render stamped parts into a request', () => {
    const binding = checked(v2([{ in: 'stamp', name: '', template: '' }]), 'signed_set');
    expect(renderPlacements(binding, {
      consumer_key: 'a', consumer_secret: 'b', token: 'c', token_secret: 'd',
    })).toEqual({ headers: {}, query: [] });
  });

  it('preserves a credential header named __proto__', () => {
    const binding = checked(v2([header('__proto__', '{part:key}')]));
    const result = renderPlacements(binding, { key: 'secret' });
    expect(Object.hasOwn(result.headers, '__proto__')).toBe(true);
    expect(Object.entries(result.headers)).toEqual([['__proto__', 'secret']]);
  });
});

describe('redaction', () => {
  const binding = checked(v2([header('authorization', 'Basic {basic:id:secret}')]), 'key_id');
  const parts = { id: 'owner+42', secret: 'long/password&value' };

  it('scrubs an echoed ID part', () => {
    expect(scrub(`id=${parts.id}; again=${parts.id}`, secretFormsAll(binding, parts))).toBe(
      'id=[REDACTED]; again=[REDACTED]',
    );
  });

  it('scrubs an echoed secret part', () => {
    expect(scrub(`secret=${parts.secret}`, secretFormsAll(binding, parts))).toBe('secret=[REDACTED]');
  });

  it('scrubs the composed basic token', () => {
    const token = basicToken(parts.id, parts.secret);
    expect(scrub(`Authorization: Basic ${token}`, secretFormsAll(binding, parts))).toBe(
      'Authorization: Basic [REDACTED]',
    );
  });

  it('scrubs the longer part completely when another part is its substring', () => {
    const overlapping = { id: 'abc', secret: 'abc-long-credential' };
    expect(scrub('abc-long-credential abc', secretFormsAll(binding, overlapping))).toBe(
      '[REDACTED] [REDACTED]',
    );
  });

  it('sorts forms longest first, deduplicates, and drops empty strings', () => {
    const forms = secretFormsAll(binding, { id: 'same', secret: 'same' });
    expect(forms).toEqual([...new Set(forms)]);
    expect(forms).not.toContain('');
    expect(forms.map((form) => form.length)).toEqual(
      forms.map((form) => form.length).sort((a, b) => b - a),
    );
    expect(secretFormsAll(checked(BEARER), { key: '' })).toEqual([]);
  });

  it('includes URL-encoded parts and base64-encoded basic parts', () => {
    const forms = secretFormsAll(binding, parts);
    expect(forms).toContain(encodeURIComponent(parts.secret));
    expect(forms).toContain(Buffer.from(parts.id, 'utf8').toString('base64'));
    expect(forms).toContain(Buffer.from(parts.secret, 'utf8').toString('base64'));
  });

  it('includes every spelling delivery.ts supplies for a v1 basic value', () => {
    const legacy = checked({
      in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'legacy-user',
    });
    if (legacy.v !== 1) throw new Error('expected v1');
    const forms = secretFormsAll(legacy, { key: parts.secret });
    for (const form of secretForms(legacy, parts.secret)) expect(forms).toContain(form);
  });

  it('scrubs URL spellings of unplaced parts as well', () => {
    const onePlacement = checked(v2([header('x-id', '{part:id}')]), 'key_id');
    const forms = secretFormsAll(onePlacement, parts);
    expect(scrub(encodeURIComponent(parts.secret), forms)).toBe('[REDACTED]');
    expect(scrub(encodeURIComponent(parts.secret).toLowerCase(), forms)).toBe('[REDACTED]');
  });

  it('sorts supplied forms itself before matching', () => {
    expect(scrub('abcdef abc', ['abc', 'abcdef'])).toBe('[REDACTED] [REDACTED]');
  });

  it('treats regex metacharacters as literal secret bytes', () => {
    expect(scrub('x .*+$& x', ['.*+$&'])).toBe('x [REDACTED] x');
  });

  it('does not scrub inside a marker it just inserted', () => {
    expect(scrub('secret RED', ['secret', 'RED'])).toBe('[REDACTED] [REDACTED]');
  });
});

describe('checkAgentHeaders', () => {
  it('refuses an agent collision with the second placement, ignoring case', () => {
    expect(checkAgentHeaders(
      { 'APCA-API-SECRET-KEY': 'attacker' }, checked(twoHeaders, 'key_id'),
    ).ok).toBe(false);
  });

  it('refuses forbidden agent headers independently of placements', () => {
    expect(checkAgentHeaders({ 'Accept-Encoding': 'gzip' }, checked(twoHeaders, 'key_id')).ok).toBe(false);
  });

  it('refuses proxy headers independently of placements', () => {
    expect(checkAgentHeaders({ 'Proxy-Anything': 'value' }, checked(twoHeaders, 'key_id')).ok).toBe(false);
  });

  it('allows and normalises an unrelated agent header', () => {
    expect(checkAgentHeaders({ 'User-Agent': 'test-broker' }, checked(twoHeaders, 'key_id'))).toEqual({
      ok: true, headers: { 'user-agent': 'test-broker' },
    });
  });

  it('uses the existing collision check for v1 bindings', () => {
    expect(checkAgentHeaders({ Authorization: 'attacker' }, checked(BEARER)).ok).toBe(false);
  });
});

describe('signed sets', () => {
  it('maps the four OAuth1 parts to the stamp value', () => {
    expect(oauth1FromParts({
      consumer_key: 'consumer', consumer_secret: 'consumer-secret',
      token: 'access', token_secret: 'access-secret',
    })).toEqual({
      consumer_key: 'consumer', consumer_secret: 'consumer-secret',
      token: 'access', token_secret: 'access-secret',
    });
  });

  it('refuses an incomplete OAuth1 set', () => {
    expect(() => oauth1FromParts({
      consumer_key: 'consumer', consumer_secret: 'consumer-secret', token: 'access',
    })).toThrow('missing part: token_secret');
  });

  it('defines all eight shapes and the optional website-login part', () => {
    expect(Object.keys(SHAPES)).toEqual([
      'api_key', 'key_id', 'signed_set', 'password', 'website_login',
      'ssh_key', 'wallet', 'signing_key',
    ]);
    expect(SHAPES.website_login.optionalParts).toEqual({ totp: 'TOTP' });
  });
});
