/**
 * SPEC-1.0-signing §F27, acceptance check 10: whatever recipe an agent writes, the secret
 * never reaches the wire, and neither the secret nor the stamp comes back in the reply.
 *
 * Driven through performOperation against a REAL https server that records every byte it
 * received and echoes the request back — the echo is the hostile service.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { performOperation, definitionFromAgentRequest } from '../src/http-broker.js';
import { validateRecipe, computeStamp, type Recipe } from '../src/stamp.js';

const SECRET = 'S3cr3t+/=Key_value-0042';
const KEY_ID = 'AKIDPUBLICID';
let dir = '';
let server: https.Server;
let port = 0;
let saved: string[] = [];
let wire: string[] = [];

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-stampwire-'));
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
      const all = `${req.method} ${req.url}\n${JSON.stringify(req.headers)}\n${Buffer.concat(chunks).toString('utf8')}`;
      wire.push(all);
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`you sent:\n${all}`);
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

/** Every spelling of the secret an encoder in this file could produce. */
const SECRET_FORMS = [
  SECRET, encodeURIComponent(SECRET), Buffer.from(SECRET).toString('base64'), Buffer.from(SECRET).toString('base64url'),
  Buffer.from(SECRET).toString('hex'), Buffer.from(SECRET, 'base64').toString('hex'),
];

const PARTS = [
  { text: 'fixed' }, { var: 'method' }, { var: 'path' }, { var: 'query' }, { var: 'path_and_query' }, { var: 'body' },
  { var: 'host' }, { var: 'key_id' }, { var: 'body_json' }, { header: 'x-ts' }, { body_field: 'n' },
  { sha256: [{ var: 'body' }] }, { sha512: [{ var: 'path' }, { text: 'x' }] }, { sha256_hex: [{ var: 'query' }] },
  { json: { a: { var: 'path' }, b: { var: 'body_json' } } },
];

function recipes(): Recipe[] {
  const out: Recipe[] = [];
  const macs = ['hmac-sha256', 'hmac-sha384', 'hmac-sha512'];
  const encs = ['hex', 'base64', 'base64url'];
  const places = [
    [{ in: 'header', name: 'x-sig', value: '{stamp}' }],
    [{ in: 'query', name: 'signature', value: '{stamp}' }, { in: 'header', name: 'x-key', value: '{key_id}' }],
    [{ in: 'header', name: 'authorization', value: 'HMAC {key_id}:{stamp}' }],
  ];
  PARTS.forEach((p, i) => {
    const raw = { mac: macs[i % 3], key: 'utf8', message: [p, { text: '\n' }, PARTS[(i + 5) % PARTS.length]],
      encoding: encs[i % 3], place: places[i % 3] };
    const r = validateRecipe(raw);
    if (!r.ok) throw new Error(`${JSON.stringify(raw)}: ${r.reason}`);
    out.push(r.recipe);
  });
  for (const service of ['s3', 'execute-api']) {
    const r = validateRecipe({ builtin: 'aws-sigv4', region: 'us-east-1', service });
    if (r.ok) out.push(r.recipe);
  }
  return out;
}

describe('no recipe puts the secret on the wire', () => {
  it.each(recipes().map((r, i) => [i, r] as const))('recipe %i', async (_i, recipe) => {
    wire = [];
    const def = definitionFromAgentRequest({
      origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'POST', path: '/v1/orders',
      query: { a: '1', b: 'two' }, headers: { 'x-ts': '1700000000', 'content-type': 'application/json' },
    }, { in: 'stamp', name: '', template: '' });
    let stampSeen = '';
    const r = await performOperation(def, JSON.stringify({ n: 7, item: 'x' }), SECRET, [`https://127.0.0.1:${port}`],
      (img) => { const st = computeStamp(recipe, img, { id: KEY_ID, secret: SECRET }); stampSeen = st.stamp; return st; });
    expect(r.ok, r.error).toBe(true);
    expect(wire.length).toBe(1);
    for (const f of SECRET_FORMS) expect(wire[0]).not.toContain(f);
    // the stamp did go (percent-encoded when it went in the query)
    expect(wire[0].includes(stampSeen) || wire[0].includes(encodeURIComponent(stampSeen))).toBe(true);
    const back = JSON.stringify(r.body);
    expect(back).not.toContain(stampSeen);                  // ...and is scrubbed on the way back,
    expect(back).not.toContain(encodeURIComponent(stampSeen)); // in the spelling the URL carried it too
    for (const f of SECRET_FORMS) expect(back).not.toContain(f);
  });

  it('a stamped binding with no stamper sends nothing', async () => {
    wire = [];
    const def = definitionFromAgentRequest({ origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'GET', path: '/' },
      { in: 'stamp', name: '', template: '' });
    const r = await performOperation(def, {}, SECRET, [`https://127.0.0.1:${port}`]);
    expect(r.ok).toBe(false);
    expect(wire.length).toBe(0);
  });

  it('a stamp that lands on a header the agent already sends is refused, nothing sent', async () => {
    wire = [];
    const def = definitionFromAgentRequest({ origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'GET', path: '/',
      headers: { 'x-sig': 'mine' } }, { in: 'stamp', name: '', template: '' });
    const rc = validateRecipe({ mac: 'hmac-sha256', key: 'utf8', message: [{ var: 'path' }], encoding: 'hex',
      place: [{ in: 'header', name: 'X-Sig', value: '{stamp}' }] });
    if (!rc.ok) throw new Error(rc.reason);
    const r = await performOperation(def, {}, SECRET, [`https://127.0.0.1:${port}`],
      (img) => computeStamp(rc.recipe, img, { secret: SECRET }));
    expect(r.ok).toBe(false);
    expect(wire.length).toBe(0);
  });

  it('the stamp is computed over the request exactly as received (the server can verify it)', async () => {
    wire = [];
    const rc = validateRecipe({ mac: 'hmac-sha256', key: 'utf8', encoding: 'hex',
      message: [{ var: 'method' }, { text: '\n' }, { var: 'path_and_query' }, { text: '\n' }, { var: 'body' }],
      place: [{ in: 'query', name: 'signature', value: '{stamp}' }] });
    if (!rc.ok) throw new Error(rc.reason);
    const def = definitionFromAgentRequest({ origin: { scheme: 'https', host: '127.0.0.1', port }, method: 'POST',
      path: '/v1/x', query: { z: '1', a: 'b c' } }, { in: 'stamp', name: '', template: '' });
    const body = 'k=v&n=1';
    const r = await performOperation(def, body, SECRET, [`https://127.0.0.1:${port}`],
      (img) => computeStamp(rc.recipe, img, { secret: SECRET }));
    expect(r.ok).toBe(true);
    const [line] = wire[0].split('\n');
    const url = line.split(' ')[1];
    const [p, q] = url.split('?');
    const sig = new URLSearchParams(q).get('signature');
    const signedQuery = q.replace(/&?signature=[^&]*$/, '');
    const expected = crypto.createHmac('sha256', SECRET).update(`POST\n${p}?${signedQuery}\n${body}`).digest('hex');
    expect(sig).toBe(expected);
  });
});
