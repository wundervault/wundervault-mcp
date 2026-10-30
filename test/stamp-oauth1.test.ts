/**
 * SPEC-oauth1-2026-10-29: OAuth 1.0a as a built-in stamp (X, Tumblr, Flickr, NetSuite).
 *
 * The signatures are checked against two published examples and against Python's oauthlib
 * (test/fixtures/oauth1_fixtures.py → oauth1.json), an implementation that shares no code
 * with ours. The wire half runs against a REAL https server that echoes everything back.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import tls from 'node:tls';
import type http from 'node:http';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { performOperation, definitionFromAgentRequest } from '../src/http-broker.js';
import {
  validateRecipe, computeStamp, recipeSha256, describeRecipe, parseStampedValue, oauth1Sign, looksLikeOAuth1Value,
  type Recipe, type RequestImage, type StampedValue,
} from '../src/stamp.js';

interface Case {
  name: string; method: string; url: string; body?: string; ct?: string; realm?: string;
  ck: string; cs: string; tk: string; ts_: string; nonce: string; timestamp: string;
  alg: 'HMAC-SHA1' | 'HMAC-SHA256'; signature: string; authorization: string;
}
const FIXTURES: { oauthlib: string; cases: Case[] } = JSON.parse(fs.readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'oauth1.json'), 'utf8'));
const byName = (n: string) => FIXTURES.cases.find((c) => c.name === n)!;

function recipe(raw: unknown): Recipe {
  const r = validateRecipe(raw);
  if (!r.ok) throw new Error(r.reason);
  return r.recipe;
}

/** The request image the broker would build for a fixture's URL. */
function imageOf(c: Case): RequestImage {
  const u = new URL(c.url);
  const q = c.url.indexOf('?');
  return {
    method: c.method, host: c.url.split('/')[2].split(':')[0], port: u.port ? Number(u.port) : 443,
    path: u.pathname, query: q < 0 ? '' : c.url.slice(q + 1), body: c.body,
    headers: c.ct ? { 'content-type': c.ct } : {},
  };
}
const valueOf = (c: Case): StampedValue => parseStampedValue(JSON.stringify({
  api_key: c.ck, api_secret: c.cs, access_token: c.tk, access_token_secret: c.ts_,
}), recipe({ builtin: 'oauth1' }));

function stampFixture(c: Case) {
  const r = recipe({ builtin: 'oauth1', signature_method: c.alg, ...(c.realm ? { realm: c.realm } : {}) });
  return computeStamp(r, imageOf(c), valueOf(c), new Date(Number(c.timestamp) * 1000), () => c.nonce);
}

/** The Authorization header's fields, decoded. */
function fieldsOf(header: string): Record<string, string> {
  expect(header.startsWith('OAuth ')).toBe(true);
  const out: Record<string, string> = {};
  for (const m of header.slice(6).matchAll(/([a-z_]+)="([^"]*)"/g)) out[m[1]] = decodeURIComponent(m[2]);
  return out;
}

describe('oauth1: published examples (checks 1, 2)', () => {
  it('OAuth Core 1.0 Appendix A.5 (photos.example.net)', () => {
    const c = byName('core10_appendix');
    const { signature } = oauth1Sign({
      method: 'GET', scheme: 'http', host: 'photos.example.net', port: 80, path: '/photos',
      query: 'file=vacation.jpg&size=original',
      oauth: { oauth_consumer_key: c.ck, oauth_token: c.tk, oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: c.timestamp, oauth_nonce: c.nonce, oauth_version: '1.0' },
      consumerSecret: c.cs, tokenSecret: c.ts_, alg: 'HMAC-SHA1',
    });
    expect(signature).toBe('tR3+Ty81lMeYAr/Fid0kMTYa/WM=');
  });
  it("X's creating-a-signature example, through computeStamp", () => {
    const st = stampFixture(byName('x_doc'));
    expect(st.stamp).toBe('hCtSmYh+iHYCEqBWrE7C7hYmtUk=');
    expect(st.headers.authorization).toContain('oauth_signature="hCtSmYh%2BiHYCEqBWrE7C7hYmtUk%3D"');
    expect(st.query).toEqual([]);
  });
});

describe(`oauth1: agrees with oauthlib ${FIXTURES.oauthlib} (check 3)`, () => {
  it.each(FIXTURES.cases.filter((c) => c.url.startsWith('https:')).map((c) => [c.name, c] as const))('%s', (_n, c) => {
    const st = stampFixture(c);
    expect(st.stamp).toBe(c.signature);
    const ours = fieldsOf(st.headers.authorization);
    const theirs = fieldsOf(c.authorization);
    expect(ours).toEqual(theirs);
  });
  it('a form body with "; charset=utf-8" is still a form body', () => {
    const c = byName('form_body');
    expect(stampFixture({ ...c, ct: 'Application/X-WWW-Form-Urlencoded; charset=utf-8' }).stamp).toBe(c.signature);
  });
  it('a body that is not form-encoded is not signed (changing it leaves the signature alone)', () => {
    const c = byName('json_tweet');
    expect(stampFixture({ ...c, body: '{"text":"something else entirely"}' }).stamp).toBe(c.signature);
    // ...while a form body IS signed: change one byte, the signature changes.
    const f = byName('form_body');
    expect(stampFixture({ ...f, body: 'a=1+3&b=%E2%9C%93&c=' }).stamp).not.toBe(f.signature);
  });
  it('the realm goes in the header and not in the signature', () => {
    const c = byName('sha256_realm');
    const st = stampFixture(c);
    expect(st.headers.authorization.startsWith('OAuth realm="1234567_SB1", ')).toBe(true);
    expect(st.stamp).toBe(c.signature);
  });
});

const X_VALUE = { api_key: 'ck-AAAA', api_secret: 'cs-SECRET-1', access_token: '99-TOKEN', access_token_secret: 'ts-SECRET-2' };
const OAUTH = recipe({ builtin: 'oauth1' });

describe('oauth1: stored values (checks 4, 5)', () => {
  it('X names, RFC names, and "api_key_secret" are accepted', () => {
    expect(parseStampedValue(JSON.stringify(X_VALUE), OAUTH).oauth1).toEqual({
      consumer_key: 'ck-AAAA', consumer_secret: 'cs-SECRET-1', token: '99-TOKEN', token_secret: 'ts-SECRET-2' });
    const rfc = { consumer_key: 'a', consumer_secret: 'b', token: 'c', token_secret: 'd' };
    expect(parseStampedValue(JSON.stringify(rfc), OAUTH).oauth1?.token).toBe('c');
    const mixed = { api_key: 'a', api_key_secret: 'b', token: 'c', access_token_secret: 'd' };
    expect(parseStampedValue(`\n ${JSON.stringify(mixed)} \n`, OAUTH).oauth1?.consumer_secret).toBe('b');
    // what the request scrubs as "the secret" is the consumer secret
    expect(parseStampedValue(JSON.stringify(X_VALUE), OAUTH).secret).toBe('cs-SECRET-1');
  });
  const bad: Array<[string, string]> = [
    ['an extra field', JSON.stringify({ ...X_VALUE, bearer_token: 'BEARER-VALUE-9' })],
    ['a missing role', JSON.stringify({ api_key: 'ck-AAAA', api_secret: 'cs-SECRET-1', access_token: '99-TOKEN' })],
    ['two names for one role', JSON.stringify({ ...X_VALUE, consumer_secret: 'cs-SECRET-1' })],
    ['an empty value', JSON.stringify({ ...X_VALUE, access_token: '' })],
    ['a value with a space', JSON.stringify({ ...X_VALUE, access_token_secret: 'ts SECRET-2' })],
    ['a number', JSON.stringify({ ...X_VALUE, api_key: 12345 })],
    ['invalid JSON', '{"api_key": "ck-AAAA", "api_secret": "cs-SECRET-1",'],
    ['a plain secret', 'cs-SECRET-1'],
    ['{id, secret}', JSON.stringify({ id: 'ck-AAAA', secret: 'cs-SECRET-1' })],
    ['an array', JSON.stringify(['ck-AAAA', 'cs-SECRET-1', '99-TOKEN', 'ts-SECRET-2'])],
    // round 1, B3: JSON.parse would keep the second api_secret and say nothing
    ['a name given twice', '{"api_key":"ck-AAAA","api_secret":"cs-SECRET-1","access_token":"99-TOKEN","access_token_secret":"ts-SECRET-2","api_secret" : "BEARER-VALUE-9"}'],
    // round 1, B4: no quote or backslash, whose escaped spelling a text reply could carry
    ['a value with a quote', JSON.stringify({ ...X_VALUE, access_token_secret: 'ts"SECRET-2' })],
    ['a value with a backslash', JSON.stringify({ ...X_VALUE, api_secret: 'cs\\SECRET-1' })],
    // round 2, F1: an escaped spelling of a name is the same name to JSON.parse
    ['a name given twice, once escaped', '{"api_key":"ck-AAAA","api_secret":"cs-SECRET-1","api_\\u0073ecret":"BEARER-VALUE-9","access_token":"99-TOKEN","access_token_secret":"ts-SECRET-2"}'],
    ['a value ending in U+2028', JSON.stringify({ ...X_VALUE, api_secret: 'cs-SECRET-1\u2028' })],
    ['a value ending in a newline', JSON.stringify({ ...X_VALUE, access_token: '99-TOKEN\n' })],
    ['an escaped value', '{"api_key":"ck-AAAA","api_secret":"cs-\\u0053ECRET-1","access_token":"99-TOKEN","access_token_secret":"ts-SECRET-2"}'],
  ];
  it.each(bad)('refused: %s, and the message carries no value', (_what, value) => {
    let msg = '';
    try { parseStampedValue(value, OAUTH); } catch (e) { msg = (e as Error).message; }
    expect(msg).toMatch(/OAuth 1\.0a needs the entry stored as/);
    for (const v of ['ck-AAAA', 'cs-SECRET-1', '99-TOKEN', 'ts-SECRET-2', 'BEARER-VALUE-9', '12345', 'ts SECRET', 'ts"SECRET', 'SECRET-2']) {
      expect(msg).not.toContain(v);
    }
  });
  it('an unknown field is counted, never named', () => {
    let msg = '';
    try { parseStampedValue(JSON.stringify({ ...X_VALUE, 'sk-live-PASTED': 'x' }), OAUTH); } catch (e) { msg = (e as Error).message; }
    expect(msg).toMatch(/1 field that does not belong/);
    expect(msg).not.toContain('sk-live');
  });
  it('the duplicate check reads member names, not text inside other names', () => {
    // "token" inside "access_token", "api_key" inside "api_key_secret": neither is a second member.
    const v = JSON.stringify({ api_key: 'a', api_key_secret: 'b', access_token: 'c', token_secret: 'd' });
    expect(parseStampedValue(v, OAUTH).oauth1).toEqual({ consumer_key: 'a', consumer_secret: 'b', token: 'c', token_secret: 'd' });
  });
  it('the four-field value with any other recipe is refused, never signed whole', () => {
    expect(() => parseStampedValue(JSON.stringify(X_VALUE))).toThrow(/exactly \{"id"/);
    const hmac = recipe({ mac: 'hmac-sha256', key: 'utf8', message: [{ var: 'path' }], encoding: 'hex',
      place: [{ in: 'header', name: 'x-sig', value: '{stamp}' }] });
    expect(() => parseStampedValue(JSON.stringify(X_VALUE), hmac)).toThrow(/exactly \{"id"/);
  });
  it('computeStamp refuses an oauth1 recipe given a value that was not parsed for it', () => {
    expect(() => computeStamp(OAUTH, { method: 'GET', host: 'api.x.com', path: '/', query: '', body: undefined, headers: {} },
      { secret: 'cs-SECRET-1' })).toThrow(/OAuth 1\.0a needs/);
  });
});

describe('oauth1: recipes (check 6)', () => {
  it.each([
    [{ builtin: 'oauth1', extra: 1 }, /unknown fields extra/],
    [{ builtin: 'oauth1', signature_method: 'PLAINTEXT' }, /HMAC-SHA1 or HMAC-SHA256/],
    [{ builtin: 'oauth1', signature_method: 'RSA-SHA1' }, /HMAC-SHA1 or HMAC-SHA256/],
    // round 1, F1: an explicit null is a value, not "absent"
    [{ builtin: 'oauth1', signature_method: null }, /HMAC-SHA1 or HMAC-SHA256/],
    [{ builtin: 'oauth1', realm: 'has space' }, /realm/],
    [{ builtin: 'oauth1', realm: 'a"b' }, /realm/],
    [{ builtin: 'oauth1', realm: '' }, /realm/],
    // round 3, F1 (rejected, pinned): JS's $ is the end of the input, so a trailing newline fails
    [{ builtin: 'oauth1', realm: '1234567_SB1\n' }, /realm/],
    [{ builtin: 'oauth2' }, /known: aws-sigv4, oauth1/],
  ])('refused: %j', (raw, why) => {
    const r = validateRecipe(raw);
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(why);
  });
  it('the default and the explicit default are one recipe; SHA-256 and a realm are others', () => {
    const a = recipeSha256(recipe({ builtin: 'oauth1' }));
    expect(recipeSha256(recipe({ builtin: 'oauth1', signature_method: 'HMAC-SHA1' }))).toBe(a);
    expect(recipeSha256(recipe({ builtin: 'oauth1', signature_method: 'HMAC-SHA256' }))).not.toBe(a);
    expect(recipeSha256(recipe({ builtin: 'oauth1', realm: 'X1' }))).not.toBe(a);
  });
  it('the approval card says what it is', () => {
    expect(describeRecipe(OAUTH)).toBe('OAuth 1.0a (HMAC-SHA1), signed fresh for every request, in the Authorization header');
    expect(describeRecipe(recipe({ builtin: 'oauth1', signature_method: 'HMAC-SHA256', realm: 'R_1' })))
      .toBe('OAuth 1.0a (HMAC-SHA256), signed fresh for every request, in the Authorization header, realm R_1');
  });
});

describe('oauth1: fresh every request (check 7)', () => {
  it('two calls carry different nonces and their own timestamps', () => {
    const img: RequestImage = { method: 'POST', host: 'api.x.com', path: '/2/tweets', query: '', body: '{}', headers: { 'content-type': 'application/json' } };
    const v = parseStampedValue(JSON.stringify(X_VALUE), OAUTH);
    const a = fieldsOf(computeStamp(OAUTH, img, v, new Date(1761782400_000)).headers.authorization);
    const b = fieldsOf(computeStamp(OAUTH, img, v, new Date(1761782401_000)).headers.authorization);
    expect(a.oauth_nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(b.oauth_nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(a.oauth_nonce).not.toBe(b.oauth_nonce);
    expect([a.oauth_timestamp, b.oauth_timestamp]).toEqual(['1761782400', '1761782401']);
    expect(a.oauth_signature).not.toBe(b.oauth_signature);
    // the same instant twice still gets two nonces
    const c = fieldsOf(computeStamp(OAUTH, img, v, new Date(1761782400_000)).headers.authorization);
    expect(c.oauth_nonce).not.toBe(a.oauth_nonce);
  });
});

describe('oauth1: refused before anything is built (check 9)', () => {
  const v = parseStampedValue(JSON.stringify(X_VALUE), OAUTH);
  const img = (o: Partial<RequestImage>): RequestImage => ({ method: 'GET', host: 'api.x.com', path: '/', query: '', body: undefined, headers: {}, ...o });
  it.each([
    ['an oauth_ query parameter', img({ query: 'a=1&oauth_token=other' }), /carries oauth_token/],
    ['an OAUTH_ query parameter', img({ query: 'OAuth_Nonce=1' }), /carries OAuth_Nonce/],
    ['an oauth_ form field', img({ method: 'POST', body: 'oauth_callback=x', headers: { 'content-type': 'application/x-www-form-urlencoded' } }), /form body carries oauth_callback/],
    ['a malformed % in the query', img({ query: 'q=100%' }), /query has a malformed % escape/],
    ['invalid UTF-8 in the query', img({ query: 'q=%C3' }), /query has a malformed % escape/],
    ['a malformed % in a form body', img({ method: 'POST', body: 'a=%zz', headers: { 'content-type': 'application/x-www-form-urlencoded' } }), /form body has a malformed/],
  ])('%s', (_what, image, why) => {
    expect(() => computeStamp(OAUTH, image, v)).toThrow(why);
  });
  it('a JSON body that happens to say oauth_ is not form data, and is signed fine', () => {
    expect(() => computeStamp(OAUTH, img({ method: 'POST', body: 'oauth_x=1', headers: { 'content-type': 'application/json' } }), v)).not.toThrow();
  });
});

// ── the wire (check 8) ───────────────────────────────────────────────────────

let dir = '';
let server: https.Server;
let port = 0;
let saved: string[] = [];
let wire: Array<{ method: string; url: string; headers: http.IncomingHttpHeaders; raw: string[]; body: string }> = [];
beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-oauth1-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  const cert = fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8');
  saved = tls.getCACertificates('default');
  tls.setDefaultCACertificates([...saved, cert]);
  server = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      wire.push({ method: req.method!, url: req.url!, headers: req.headers, raw: req.rawHeaders, body });
      res.writeHead(200, { 'content-type': 'text/plain' });
      // The hostile service: echoes the request, and the two secrets in their usual spellings.
      res.end(`you sent:\n${req.method} ${req.url}\n${JSON.stringify(req.headers)}\n${body}\n`
        + `cs-SECRET-1 ts-SECRET-2 cs-SECRET-1&ts-SECRET-2 ${encodeURIComponent('cs-SECRET-1&ts-SECRET-2')}`);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as net.AddressInfo).port;
});
afterAll(() => {
  server?.close();
  tls.setDefaultCACertificates(saved);
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('oauth1: on the wire (check 8)', () => {
  it('one Authorization header the server can verify; no secret goes out or comes back', async () => {
    wire = [];
    const def = definitionFromAgentRequest({
      origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'POST', path: '/2/tweets',
      query: { note: 'a b+c' }, headers: { 'content-type': 'application/json' },
    }, { in: 'stamp', name: '', template: '' });
    const v = parseStampedValue(JSON.stringify(X_VALUE), OAUTH);
    let sig = '';
    const r = await performOperation(def, { text: 'hello' }, v.secret, [`https://127.0.0.1:${port}`],
      (img) => { const st = computeStamp(OAUTH, img, v); sig = st.stamp; return st; });
    expect(r.ok, r.error).toBe(true);
    expect(wire.length).toBe(1);
    const got = wire[0];
    // exactly one Authorization header, in the §5 form
    expect(got.raw.filter((h, i) => i % 2 === 0 && h.toLowerCase() === 'authorization').length).toBe(1);
    const f = fieldsOf(String(got.headers.authorization));
    expect(Object.keys(f).sort()).toEqual(['oauth_consumer_key', 'oauth_nonce', 'oauth_signature',
      'oauth_signature_method', 'oauth_timestamp', 'oauth_token', 'oauth_version']);
    expect(f.oauth_consumer_key).toBe('ck-AAAA');
    expect(f.oauth_token).toBe('99-TOKEN');
    // the server recomputes the signature from what it received, and it matches
    const [p, q] = got.url.split('?');
    const { signature } = oauth1Sign({
      method: got.method, scheme: 'https', host: '127.0.0.1', port, path: p, query: q ?? '',
      oauth: Object.fromEntries(Object.entries(f).filter(([k]) => k !== 'oauth_signature')),
      consumerSecret: 'cs-SECRET-1', tokenSecret: 'ts-SECRET-2', alg: 'HMAC-SHA1',
    });
    expect(f.oauth_signature).toBe(signature);
    expect(f.oauth_signature).toBe(sig);
    // no secret on the wire, in any spelling
    const all = JSON.stringify(got);
    for (const s of ['cs-SECRET-1', 'ts-SECRET-2', 'cs-SECRET-1&ts-SECRET-2', encodeURIComponent('cs-SECRET-1&ts-SECRET-2')]) {
      expect(all).not.toContain(s);
    }
    // ...and none comes back, nor the signature
    const back = JSON.stringify(r.body);
    for (const s of ['cs-SECRET-1', 'ts-SECRET-2', encodeURIComponent('cs-SECRET-1&ts-SECRET-2'), sig, encodeURIComponent(sig)]) {
      expect(back).not.toContain(s);
    }
    expect(back).toContain('ck-AAAA'); // the public ids travel by design
  });

  it('a request that already sends Authorization is refused, nothing sent', async () => {
    wire = [];
    const def = definitionFromAgentRequest({ origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'GET', path: '/',
      headers: { authorization: 'Bearer mine' } }, { in: 'stamp', name: '', template: '' });
    const v = parseStampedValue(JSON.stringify(X_VALUE), OAUTH);
    const r = await performOperation(def, {}, v.secret, [`https://127.0.0.1:${port}`], (img) => computeStamp(OAUTH, img, v));
    expect(r.ok).toBe(false);
    expect(wire.length).toBe(0);
  });

  it('an oauth_ query parameter is refused, nothing sent', async () => {
    wire = [];
    const def = definitionFromAgentRequest({ origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'GET', path: '/',
      query: { oauth_token: 'other' } }, { in: 'stamp', name: '', template: '' });
    const v = parseStampedValue(JSON.stringify(X_VALUE), OAUTH);
    const r = await performOperation(def, {}, v.secret, [`https://127.0.0.1:${port}`], (img) => computeStamp(OAUTH, img, v));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/Authorization header, which the broker writes/);
    expect(wire.length).toBe(0);
  });
});

describe('oauth1: a bundle is recognised even when it would not sign (round 2, F2)', () => {
  it.each([
    ['valid', JSON.stringify(X_VALUE)],
    ['a value with a trailing space', JSON.stringify({ ...X_VALUE, api_secret: 'cs-SECRET-1 ' })],
    ['an extra field', JSON.stringify({ ...X_VALUE, bearer: 'b' })],
    ['RFC names, one missing', JSON.stringify({ consumer_secret: 'a', token_secret: 'b' })],
    ['not even valid JSON', '{"api_secret": "cs-SECRET-1", "access_token_secret": "ts-SECRET-2",'],
  ])('%s', (_what, v) => { expect(looksLikeOAuth1Value(v)).toBe(true); });
  it.each([
    ['a plain token', 'ghp_abcdef'],
    ['{id, secret}', JSON.stringify({ id: 'AKIA', secret: 's' })],
    ['only a consumer secret', JSON.stringify({ api_key: 'k', api_secret: 's' })],
  ])('not a bundle: %s', (_what, v) => { expect(looksLikeOAuth1Value(v)).toBe(false); });
});
