/**
 * How a web-service key is framed on its way out — SPEC-1.0-brokered-only §A, checks 9.
 *
 * Three layers, because each one has a different way of being wrong:
 *
 *   1. the rules (validateBinding): every value the server refuses, the broker refuses
 *      too, because the broker must not trust the server for what goes into a request;
 *   2. the wire: a REAL https request to a local server, so the header or parameter the
 *      upstream receives is asserted — not the object the broker meant to send;
 *   3. the broker: an entry whose stored binding is invalid is refused with nothing sent,
 *      and never quietly downgraded to a bearer token.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import https from 'node:https';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import {
  validateBinding, bindingFromExecConfig, renderCredential, basicToken, BEARER, FORBIDDEN_HEADERS,
  looksLikePrivateKey,
} from '../src/delivery.js';
import { performOperation, definitionFromAgentRequest } from '../src/http-broker.js';
import type { CredentialBinding } from '../src/opdef.js';

const SECRET = 'sk-live-abc123';

describe('validateBinding — what the broker accepts', () => {
  const ok = (raw: unknown) => {
    const r = validateBinding(raw);
    if (!r.ok) throw new Error(`refused: ${r.field}: ${r.reason}`);
    return r.binding;
  };
  const refused = (raw: unknown) => {
    const r = validateBinding(raw);
    expect(r.ok, JSON.stringify(raw)).toBe(false);
    return r.ok ? '' : r.field;
  };

  it('accepts each of the four kinds', () => {
    expect(ok({ in: 'header', name: 'authorization', template: 'Bearer {secret}' })).toEqual(BEARER);
    expect(ok({ in: 'header', name: 'X-Api-Key', template: '{secret}' }))
      .toEqual({ in: 'header', name: 'x-api-key', template: '{secret}' });
    expect(ok({ in: 'header', name: 'authorization', template: 'Token {secret}' }).template).toBe('Token {secret}');
    expect(ok({ in: 'query', name: 'api_key', template: '{secret}' }))
      .toEqual({ in: 'query', name: 'api_key', template: '{secret}' });
    expect(ok({ in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'deploy' }))
      .toEqual({ in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'deploy' });
  });

  it('refuses every header that frames or routes the request, in any case', () => {
    for (const h of FORBIDDEN_HEADERS) {
      expect(refused({ in: 'header', name: h, template: '{secret}' })).toBe('binding.name');
      expect(refused({ in: 'header', name: h.toUpperCase(), template: '{secret}' })).toBe('binding.name');
    }
  });

  it('refuses names that are not names', () => {
    for (const name of ['', 'x key', 'x:key', 'x-key\n', 'x-key\r\nhost: evil', 'é', 'a'.repeat(65)]) {
      expect(refused({ in: 'header', name, template: '{secret}' })).toBe('binding.name');
    }
    for (const name of ['', 'a b', 'a&b', 'a=b', 'a\n', 'a'.repeat(65)]) {
      expect(refused({ in: 'query', name, template: '{secret}' })).toBe('binding.name');
    }
  });

  it('refuses a template that is not exactly one placeholder of printable text', () => {
    for (const template of [
      '', 'no placeholder', '{secret}{secret}', '{secret} {basic}', 'Bearer {secret}\r\nX: y',
      'Bearer\t{secret}', 'é {secret}', `${'x'.repeat(121)}{secret}`,
    ]) {
      expect(refused({ in: 'header', name: 'x-key', template })).toBe('binding.template');
    }
  });

  it('keeps username and password to a header, with a clean username', () => {
    expect(refused({ in: 'query', name: 'auth', template: '{basic}', username: 'u' })).toBe('binding.template');
    expect(refused({ in: 'header', name: 'authorization', template: 'Basic {basic}' })).toBe('binding.username');
    expect(refused({ in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'a:b' })).toBe('binding.username');
    expect(refused({ in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'a\nb' })).toBe('binding.username');
    expect(refused({ in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'u'.repeat(129) })).toBe('binding.username');
    expect(refused({ in: 'header', name: 'x-key', template: '{secret}', username: 'stray' })).toBe('binding.username');
  });

  it('refuses unknown fields and shapes', () => {
    expect(refused({ in: 'header', name: 'x', template: '{secret}', inject_as: 'env' })).toBe('binding');
    expect(refused({ in: 'body', name: 'x', template: '{secret}' })).toBe('binding.in');
    expect(refused(null)).toBe('binding');
    expect(refused(['header'])).toBe('binding');
    expect(refused('Bearer {secret}')).toBe('binding');
  });
});

describe('bindingFromExecConfig — absent is bearer, invalid is a refusal', () => {
  it('defaults an entry with no binding to a bearer token', () => {
    const r = bindingFromExecConfig({ delivery: 'http' });
    expect(r.ok && r.binding).toEqual(BEARER);
  });

  it('refuses an explicit null rather than reading it as "no binding"', () => {
    // Round 1, F2. Only an ABSENT key means bearer; nothing on the server writes a null.
    expect(bindingFromExecConfig({ credential_binding: null }).ok).toBe(false);
    expect(bindingFromExecConfig({ delivery: 'http', credential_binding: undefined }).ok).toBe(false);
  });

  it('does not repair a binding the server changed into something invalid', () => {
    const r = bindingFromExecConfig({ credential_binding: { in: 'header', name: 'host', template: '{secret}' } });
    expect(r.ok).toBe(false);
  });
});

describe('looksLikePrivateKey', () => {
  it('knows the private-key armours and nothing else', () => {
    for (const k of ['OPENSSH PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'PRIVATE KEY', 'ENCRYPTED PRIVATE KEY']) {
      expect(looksLikePrivateKey(`-----BEGIN ${k}-----\nAAAA\n-----END ${k}-----`), k).toBe(true);
    }
    for (const v of ['sk-live-abc', 'ghp_xxx', '-----BEGIN PUBLIC KEY-----\nAAAA', '-----BEGIN CERTIFICATE-----']) {
      expect(looksLikePrivateKey(v), v).toBe(false);
    }
  });
});

describe('renderCredential', () => {
  it('composes basic sign-in as base64(user:secret)', () => {
    const b = { in: 'header' as const, name: 'authorization', template: 'Basic {basic}', username: 'deploy' };
    expect(renderCredential(b, 'p@ss')).toBe(`Basic ${Buffer.from('deploy:p@ss').toString('base64')}`);
    expect(basicToken('deploy', 'p@ss')).toBe('ZGVwbG95OnBAc3M=');
  });

  it("sends a key containing $' or $& exactly as stored", () => {
    // String.replace with a string argument expands these; the old code did exactly that.
    for (const key of ["ab$'cd", 'ab$&cd', 'ab$`cd', 'ab$$cd']) {
      expect(renderCredential(BEARER, key)).toBe(`Bearer ${key}`);
    }
  });
});

// ── The wire ─────────────────────────────────────────────────────────────────────────

let dir = '';
let server: https.Server;
let port = 0;
let seen: { url: string; headers: Record<string, string | string[] | undefined> }[] = [];
let echo: unknown = { fine: true };
let savedCAs: string[] = [];

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-binding-'));
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'), '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
  ], { stdio: 'ignore' });
  const cert = fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8');
  // Trust this one certificate for the duration of the file, so the broker's real
  // `rejectUnauthorized: true` path is the one under test — no hook in production code.
  savedCAs = tls.getCACertificates('default');
  tls.setDefaultCACertificates([...savedCAs, cert]);
  server = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert }, (req, res) => {
    seen.push({ url: req.url ?? '', headers: req.headers });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(echo));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  port = (server.address() as AddressInfo).port;
});

afterAll(() => {
  server?.close();
  tls.setDefaultCACertificates(savedCAs);
  fs.rmSync(dir, { recursive: true, force: true });
});

async function send(binding: CredentialBinding, secret = SECRET, reqPath = '/v1/thing') {
  seen = [];
  const origin = { scheme: 'https', host: '127.0.0.1', port };
  const def = definitionFromAgentRequest({ origin, method: 'GET', path: reqPath }, binding);
  const r = await performOperation(def, {}, secret, [`https://127.0.0.1:${port}`]);
  expect(r.ok, r.error).toBe(true);
  expect(seen).toHaveLength(1);
  return { req: seen[0], result: r };
}

describe('the request the upstream actually receives', () => {
  it('bearer token', async () => {
    const { req } = await send(BEARER);
    expect(req.headers.authorization).toBe(`Bearer ${SECRET}`);
  });

  it('named header with a prefix, and nothing in authorization', async () => {
    const { req } = await send({ in: 'header', name: 'x-api-key', template: 'Key {secret}' });
    expect(req.headers['x-api-key']).toBe(`Key ${SECRET}`);
    expect(req.headers.authorization).toBeUndefined();
  });

  it('query parameter, encoded, beside the existing query', async () => {
    const key = 'a&b=c d';
    const { req } = await send({ in: 'query', name: 'api_key', template: '{secret}' }, key, '/v1/thing?x=1');
    const u = new URL(req.url, 'https://h');
    expect(u.searchParams.get('x')).toBe('1');
    expect(u.searchParams.get('api_key')).toBe(key);
    expect(req.headers.authorization).toBeUndefined();
  });

  it('username and password as HTTP basic sign-in', async () => {
    const { req } = await send(
      { in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'deploy' }, 'hunter2');
    expect(req.headers.authorization).toBe(`Basic ${Buffer.from('deploy:hunter2').toString('base64')}`);
  });

  it('scrubs the encoded pair, not only the password, from what comes back', async () => {
    const token = basicToken('deploy', 'hunter2');
    echo = { echoed: `Basic ${token}`, raw: 'hunter2' };
    try {
      const { result } = await send(
        { in: 'header', name: 'authorization', template: 'Basic {basic}', username: 'deploy' }, 'hunter2');
      const text = JSON.stringify(result.body);
      expect(text).not.toContain(token);
      expect(text).not.toContain('hunter2');
    } finally {
      echo = { fine: true };
    }
  });
});
