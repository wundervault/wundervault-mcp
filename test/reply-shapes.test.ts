/**
 * Replies that are not a JSON object — an empty 204, plain text, CSV, bytes.
 *
 * Before this, every one of them came back as "could not parse as JSON" with ok:false,
 * including a DELETE that had worked and a POST whose effect had already happened. A
 * caller told its request failed sends it again. Each case below fails on that code.
 *
 * A REAL https server, as in binding.test.ts, so the reply asserted is the one the
 * broker actually read off the wire.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import https from 'node:https';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import { performOperation, definitionFromAgentRequest, asText, mediaType } from '../src/http-broker.js';
import { VERSION } from '../src/version.js';
import { BEARER, secretForms, validateAgentHeaders } from '../src/delivery.js';
import { renderBody } from '../src/server.js';
import type { CredentialBinding, OperationDefinition } from '../src/opdef.js';

const KEY = 'k&y/z+1 secret';
const ENCODED = encodeURIComponent(KEY);

let dir = '';
let server: https.Server;
let port = 0;
let savedCAs: string[] = [];
let hits = 0;
let seen: { headers: import('node:http').IncomingHttpHeaders; raw: string[]; body: string }[] = [];

const routes: Record<string, (res: import('node:http').ServerResponse, url: string) => void> = {
  '/204': (res) => { res.writeHead(204); res.end(); },
  '/201-empty': (res) => { res.writeHead(201, { 'content-type': 'application/json' }); res.end(); },
  '/text': (res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(`queued; key was ${KEY}`); },
  '/csv': (res) => { res.writeHead(200, { 'content-type': 'text/csv' }); res.end('a,b\n1,2\n'); },
  '/echo-url': (res, url) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(`<p>GET ${url}</p>`); },
  '/png': (res) => { res.writeHead(200, { 'content-type': 'image/png' }); res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1, 2])); },
  '/latin1': (res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(Buffer.from([0x63, 0x61, 0x66, 0xe9])); },
  '/400-text': (res) => { res.writeHead(400, { 'content-type': 'text/plain' }); res.end(`bad key ${KEY}`); },
  '/400-json': (res) => { res.writeHead(400, { 'content-type': 'application/json' }); res.end(JSON.stringify({ detail: `bad key ${KEY}` })); },
  '/404-empty': (res) => { res.writeHead(404); res.end(); },
  '/400-bytes': (res) => { res.writeHead(400, { 'content-type': 'image/png' }); res.end(Buffer.from([1, 0, 2])); },
  '/png-keyed-param': (res) => { res.writeHead(200, { 'content-type': `image/png; note=${encodeURIComponent(KEY)}` }); res.end(Buffer.from([1, 0, 2])); },
  '/png-keyed-type': (res) => { res.writeHead(200, { 'content-type': 'image/plain123' }); res.end(Buffer.from([1, 0, 2])); },
  '/record': (res) => { res.writeHead(204); res.end(); },
  '/bad-utf8-json': (res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(Buffer.from([0x22, 0xff, 0x22])); },
  '/json-as-png': (res) => { res.writeHead(200, { 'content-type': 'image/png' }); res.end('{"a":1}'); },
  '/big': (res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('x'.repeat(5000)); },
  '/big-404': (res) => { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('x'.repeat(5000)); },
  '/hang-up': (res) => { res.socket?.destroy(); },
};

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-reply-'));
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
  ], { stdio: 'ignore' });
  const cert = fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8');
  savedCAs = tls.getCACertificates('default');
  tls.setDefaultCACertificates([...savedCAs, cert]);
  server = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert }, (req, res) => {
    hits++;
    const url = req.url ?? '';
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      seen.push({ headers: req.headers, raw: req.rawHeaders, body: Buffer.concat(chunks).toString('utf8') });
      routes[url.split('?')[0]](res, url);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});

afterAll(() => {
  server?.close();
  tls.setDefaultCACertificates(savedCAs);
  fs.rmSync(dir, { recursive: true, force: true });
});

function def(method: string, p: string, binding: CredentialBinding = BEARER): OperationDefinition {
  return definitionFromAgentRequest({ origin: { scheme: 'https', host: '127.0.0.1', port }, method, path: p }, binding);
}
const call = (d: OperationDefinition, key = KEY, body: Record<string, unknown> | string = {}) =>
  performOperation(d, body, key, [`https://127.0.0.1:${port}`]);

describe('a reply that is not a JSON object', () => {
  it('a 204 with no body is a success, and says it was empty', async () => {
    const r = await call(def('DELETE', '/204'));
    expect(r).toMatchObject({ ok: true, status: 204, body: null });
    expect(renderBody(r.body)).toBe('(empty reply)');
  });

  it('a 201 that claims JSON but sends nothing is a success too', async () => {
    expect(await call(def('POST', '/201-empty'))).toMatchObject({ ok: true, status: 201, body: null });
  });

  it('plain text comes back as text, with the key scrubbed out of it', async () => {
    const r = await call(def('POST', '/text'));
    expect(r.ok).toBe(true);
    expect(r.body).toBe('queued; key was [REDACTED]');
    expect(renderBody(r.body)).toBe('queued; key was [REDACTED]');
  });

  it('CSV comes back as written, not as a JSON-escaped string', async () => {
    const r = await call(def('GET', '/csv'));
    expect(r).toMatchObject({ ok: true, body: 'a,b\n1,2\n' });
    expect(renderBody(r.body)).toBe('a,b\n1,2\n');
  });

  it('a query key echoed back percent-encoded is scrubbed in that form too', async () => {
    const r = await call(def('GET', '/echo-url', { in: 'query', name: 'api_key', template: '{secret}' }));
    expect(r.ok).toBe(true);
    expect(String(r.body)).toContain('api_key=[REDACTED]');
    expect(String(r.body)).not.toContain(ENCODED);
    expect(String(r.body)).not.toContain(KEY);
  });

  it('bytes are described, never returned', async () => {
    const png = await call(def('GET', '/png'));
    expect(png.ok).toBe(true);
    expect(png.body).toBe('[7 bytes of image/png, not text, so not shown]');
    const latin1 = await call(def('GET', '/latin1'));
    expect(latin1.body).toBe('[4 bytes of text/plain, not text, so not shown]');
  });

  it("an error reply in text is returned as the service's explanation, scrubbed", async () => {
    // SPEC-1.0-api-keys §A: the agent sees why it was refused, never the key.
    const r = await call(def('POST', '/400-text'));
    expect(r).toEqual({ ok: false, status: 400, body: 'bad key [REDACTED]', error: 'Upstream returned HTTP 400.' });
  });

  it('a signed operation still withholds the explanation, and says why', async () => {
    const signed = { ...def('POST', '/400-json'), response: { allow: ['id'] } } as OperationDefinition;
    const r = await call(signed);
    expect(r.body).toBeUndefined();
    expect(r.error).toMatch(/HTTP 400\. This operation returns only the fields its owner named/);
    expect(JSON.stringify(r)).not.toContain('bad key');
  });

  it('an error reply in bytes is described, not returned', async () => {
    const r = await call(def('GET', '/400-bytes'));
    expect(r).toMatchObject({ ok: false, status: 400, body: '[3 bytes of image/png, not text, so not shown]' });
  });

  it('a SIGNED definition never returns text it cannot filter, and still reports success', async () => {
    // ok:true, because the request went through: a caller told a payment failed pays again.
    const signed = { ...def('POST', '/text'), response: { allow: ['id'] } } as OperationDefinition;
    const before = hits;
    const r = await call(signed);
    expect(hits).toBe(before + 1);
    expect(r.ok).toBe(true);
    expect(r.status).toBe(200);
    expect(r.body).toMatch(/^\[\d+ bytes of text\/plain, not JSON; this operation returns only named JSON fields/);
    expect(JSON.stringify(r)).not.toContain('queued');
  });

  it('a JSON error reply comes back as JSON, scrubbed', async () => {
    const r = await call(def('POST', '/400-json'));
    expect(r).toEqual({ ok: false, status: 400, body: { detail: 'bad key [REDACTED]' }, error: 'Upstream returned HTTP 400.' });
  });

  it('an empty error reply is not mistaken for an empty success', async () => {
    const r = await call(def('DELETE', '/404-empty'));
    expect(r).toEqual({ ok: false, status: 404, error: expect.stringMatching(/HTTP 404/) });
  });

  it('a content-type the upstream wrote is reduced and scrubbed before it is described', async () => {
    // Round 1, F2: the upstream holds the key and chooses this header.
    const withParam = await call(def('GET', '/png-keyed-param'));
    expect(withParam.body).toBe('[3 bytes of image/png, not text, so not shown]');
    const asType = await call(def('GET', '/png-keyed-type'), 'plain123');
    expect(String(asType.body)).not.toContain('plain123');
    expect(String(asType.body)).toBe('[3 bytes of image/[REDACTED], not text, so not shown]');
  });
});

describe('round 2 regressions', () => {
  it('bytes that are not valid UTF-8 are described even when they would parse as JSON', async () => {
    // A lenient decode turned 0xff into U+FFFD and JSON.parse accepted '"\uFFFD"'.
    expect((await call(def('GET', '/bad-utf8-json'))).body).toBe('[3 bytes of text/plain, not text, so not shown]');
    expect((await call(def('GET', '/json-as-png'))).body).toBe('[7 bytes of image/png, not text, so not shown]');
  });

  it('a 2xx reply over the size cap is a success with nothing shown; a 4xx one is a failure', async () => {
    const lim = { response_bytes: 100 };
    const mk = (p: string) => definitionFromAgentRequest(
      { origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'POST', path: p }, BEARER, lim);
    const ok = await call(mk('/big'));
    expect(ok.ok).toBe(true);
    expect(ok.status).toBe(200);
    expect(String(ok.body)).toMatch(/exceeded 100 bytes.*the request itself succeeded/);
    const notOk = await call(mk('/big-404'));
    expect(notOk).toMatchObject({ ok: false, status: 404 });
    expect(notOk.body).toBeUndefined();
  });

  it('a POST that loses its connection says it may have run; a GET does not', async () => {
    const post = await call(def('POST', '/hang-up'));
    expect(post.ok).toBe(false);
    expect(post.error).toMatch(/may already have reached the service and taken effect/);
    const get = await call(def('GET', '/hang-up'));
    expect(get.ok).toBe(false);
    expect(get.error).not.toMatch(/may already have reached/);
  });

  it('a POST that loses a REUSED (kept-alive) connection still says it may have run (2.0.2)', async () => {
    // The second request rides the socket the first left open; a reused socket fires no new
    // secureConnect, and the warning used to be lost exactly there (seen first on Node.js 24).
    const warm = await call(def('GET', '/record'));
    expect(warm.ok).toBe(true);
    const post = await call(def('POST', '/hang-up'));
    expect(post.ok).toBe(false);
    expect(post.error).toMatch(/may already have reached the service and taken effect/);
  });

  it('a POST that never connected does not claim it may have run', async () => {
    const closed = https.createServer();
    await new Promise<void>((r) => closed.listen(0, '127.0.0.1', () => r()));
    const deadPort = (closed.address() as AddressInfo).port;
    await new Promise<void>((r) => closed.close(() => r()));
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: '127.0.0.1', port: deadPort }, method: 'POST', path: '/' }, BEARER);
    const r = await performOperation(d, {}, KEY, [`https://127.0.0.1:${deadPort}`]);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/ECONNREFUSED/);
    expect(r.error).not.toMatch(/may already have reached/);
  });

  it('a header named __proto__ is kept and sent, not checked and then dropped', async () => {
    const checked = validateAgentHeaders(JSON.parse('{"__proto__":"kept","x-a":"1"}'), BEARER);
    expect(checked.ok).toBe(true);
    if (!checked.ok) return;
    expect(Object.keys(checked.headers).sort()).toEqual(['__proto__', 'x-a']);
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'GET', path: '/record', headers: checked.headers }, BEARER);
    await call(d);
    // rawHeaders, because the receiving side's own headers object reads __proto__ as its prototype.
    const raw = seen[seen.length - 1].raw;
    expect(raw[raw.findIndex((h, i) => i % 2 === 0 && h.toLowerCase() === '__proto__') + 1]).toBe('kept');
  });

  it('null headers mean none of the agent\'s own', () => {
    expect(validateAgentHeaders(null, BEARER)).toEqual({ ok: true, headers: {} });
  });
});

describe("the agent's headers and body, on the wire", () => {
  const withHeaders = (method: string, headers?: Record<string, string>) =>
    definitionFromAgentRequest({ origin: { scheme: 'https', host: '127.0.0.1', port }, method, path: '/record', headers }, BEARER);
  const last = () => seen[seen.length - 1];

  it('sends a User-Agent when the agent gives none, because GitHub refuses a request without one', async () => {
    await call(withHeaders('GET'));
    expect(last().headers['user-agent']).toBe(`wundervault-broker/${VERSION}`);
  });

  it("sends the agent's own headers, and its User-Agent instead of the default", async () => {
    await call(withHeaders('GET', { 'user-agent': 'my-agent/1.0', 'anthropic-version': '2023-06-01' }));
    expect(last().headers['user-agent']).toBe('my-agent/1.0');
    expect(last().headers['anthropic-version']).toBe('2023-06-01');
    expect(last().headers.authorization).toBe(`Bearer ${KEY}`);
  });

  it('sends a string body as written, with the content-type the agent chose', async () => {
    const form = 'name=Ada+Lovelace&email=ada%40example.com';
    await call(withHeaders('POST', { 'content-type': 'application/x-www-form-urlencoded' }), KEY, form);
    expect(last().body).toBe(form);
    expect(last().headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(last().headers['content-length']).toBe(String(Buffer.byteLength(form)));
  });

  it('a string body with no content-type goes as text, not as a JSON-quoted string', async () => {
    await call(withHeaders('POST'), KEY, 'hello');
    expect(last().body).toBe('hello');
    expect(last().headers['content-type']).toBe('text/plain; charset=utf-8');
  });

  it('an object body is still JSON, and the agent may name a JSON media type', async () => {
    await call(withHeaders('POST', { 'content-type': 'application/vnd.api+json' }), KEY, { a: 1 });
    expect(last().body).toBe('{"a":1}');
    expect(last().headers['content-type']).toBe('application/vnd.api+json');
  });

  it("the key is written last: even an unchecked authorization header cannot replace it", async () => {
    // The broker refuses this header before it gets here (validateAgentHeaders). This is
    // the second layer: if that check were ever lost, the upstream still gets the key's
    // header from the entry, not the agent's.
    await call(withHeaders('GET', { authorization: 'Bearer agent-chosen' }));
    expect(last().headers.authorization).toBe(`Bearer ${KEY}`);
  });

  it('a placeholder in a header value is sent literally, never filled with the key', async () => {
    await call(withHeaders('GET', { 'x-note': '{secret} {basic}' }));
    expect(last().headers['x-note']).toBe('{secret} {basic}');
  });
});

describe('validateAgentHeaders', () => {
  it("refuses the credential's header for a named-header binding, and allows authorization for a query one", () => {
    const named = { in: 'header', name: 'x-api-key', template: '{secret}' } as const;
    expect(validateAgentHeaders({ 'X-Api-Key': 'mine' }, named).ok).toBe(false);
    expect(validateAgentHeaders({ authorization: 'Bearer other' }, named).ok).toBe(true);
    const query = { in: 'query', name: 'api_key', template: '{secret}' } as const;
    expect(validateAgentHeaders({ authorization: 'Bearer other' }, query).ok).toBe(true);
  });

  it('lowercases names, allows a tab inside a value, and caps the count and the length', () => {
    expect(validateAgentHeaders({ 'User-Agent': 'a\tb' }, BEARER)).toEqual({ ok: true, headers: { 'user-agent': 'a\tb' } });
    const many = Object.fromEntries(Array.from({ length: 21 }, (_, i) => [`x-h${i}`, 'v']));
    expect(validateAgentHeaders(many, BEARER).ok).toBe(false);
    expect(validateAgentHeaders({ 'x-big': 'v'.repeat(1025) }, BEARER).ok).toBe(false);
    expect(validateAgentHeaders({ 'x-n': 5 }, BEARER).ok).toBe(false);
    expect(validateAgentHeaders({ 'x-u': 'é' }, BEARER).ok).toBe(false);
    expect(validateAgentHeaders(undefined, BEARER)).toEqual({ ok: true, headers: {} });
  });
});

describe('the pieces', () => {
  it('mediaType keeps type/subtype and nothing else', () => {
    expect(mediaType('Text/CSV; charset=utf-8')).toBe('text/csv');
    expect(mediaType(undefined)).toBe('unknown type');
    expect(mediaType('not a type')).toBe('unknown type');
    expect(mediaType('a/b\r\nx')).toBe('unknown type');
  });

  it('asText refuses bytes whatever the label says, and accepts unlabelled UTF-8', () => {
    expect(asText(Buffer.from('héllo'), undefined)).toBe('héllo');
    expect(asText(Buffer.from('a\0b'), 'text/plain')).toBeNull();
    expect(asText(Buffer.from('fine'), 'application/octet-stream')).toBeNull();
    expect(asText(Buffer.from('fine'), 'IMAGE/SVG+XML')).toBeNull();
  });

  it('secretForms adds encoded spellings only when they differ', () => {
    expect(secretForms(BEARER, 'plain123')).toEqual(['plain123']);
    // As sent, form-style (+ for a space), and lowercase escapes.
    expect(secretForms(BEARER, 'a b/c')).toEqual(['a b/c', 'a%20b%2Fc', 'a%20b%2fc', 'a+b%2Fc']);
  });

  it('renderBody keeps JSON as indented JSON', () => {
    expect(renderBody({ a: 1 })).toBe('{\n  "a": 1\n}');
    expect(renderBody(undefined)).toBe('(empty reply)');
  });
});
