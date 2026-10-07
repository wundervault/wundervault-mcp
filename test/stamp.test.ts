import { describe, it, expect } from 'vitest';
import { validateRecipe, computeStamp, recipeSha256, type RequestImage, type Recipe } from '../src/stamp.js';

function recipe(raw: unknown): Recipe {
  const r = validateRecipe(raw);
  if (!r.ok) throw new Error(r.reason);
  return r.recipe;
}
const img = (o: Partial<RequestImage>): RequestImage => ({
  method: 'GET', host: 'example.com', path: '/', query: '', body: undefined, headers: {}, ...o,
});
const AWS = { id: 'AKIDEXAMPLE', secret: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' };
const AWS_TIME = new Date('2015-08-30T12:36:00Z');

describe('stamp: published vectors', () => {
  it('AWS SigV4 get-vanilla (aws-c-auth test suite)', () => {
    const r = computeStamp(recipe({ builtin: 'aws-sigv4', region: 'us-east-1', service: 'service' }),
      img({ host: 'example.amazonaws.com' }), AWS, AWS_TIME);
    expect(r.stamp).toBe('5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
    expect(r.headers.authorization).toBe('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, '
      + 'SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
  });
  it('AWS SigV4 post-x-www-form-urlencoded with the body hash header', () => {
    const r = computeStamp(recipe({ builtin: 'aws-sigv4', region: 'us-east-1', service: 'service', content_sha256_header: true }),
      img({ method: 'POST', host: 'example.amazonaws.com', body: 'Param1=value1',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': '13', 'user-agent': 'x' } }), AWS, AWS_TIME);
    expect(r.stamp).toBe('d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b');
  });
  it('Binance HMAC-SHA256 over the query (Binance API docs example)', () => {
    const q = 'symbol=LTCBTC&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&price=0.1&recvWindow=5000&timestamp=1499827319559';
    const r = computeStamp(recipe({ mac: 'hmac-sha256', key: 'utf8', message: [{ var: 'query' }], encoding: 'hex',
      place: [{ in: 'query', name: 'signature', value: '{stamp}' }, { in: 'header', name: 'X-MBX-APIKEY', value: '{key_id}' }] }),
      img({ query: q }), { id: 'vmPUZE6mv9SD5VNHk4HlWFsOr6aKE2zvsw0MuIgwCIPy6utIco14y7Ju91duEh8A', secret: 'NhqPtmdSJYdKjVHjA7PZj4Mge3R5YNiP1e3UZjInClVN65XAbvqqM6A7H5fATj0j' });
    expect(r.stamp).toBe('c8db56825ae71d6d79447849e617115f4a920fa2acdcab2b053c4b2838bd6b71');
    expect(r.query).toEqual(['signature=c8db56825ae71d6d79447849e617115f4a920fa2acdcab2b053c4b2838bd6b71']);
    expect(r.headers['x-mbx-apikey']).toBe('vmPUZE6mv9SD5VNHk4HlWFsOr6aKE2zvsw0MuIgwCIPy6utIco14y7Ju91duEh8A');
  });
  it('Kraken HMAC-SHA512(base64 key, path + sha256(nonce + body)) (Kraken API docs example)', () => {
    const r = computeStamp(recipe({ mac: 'hmac-sha512', key: 'base64',
      message: [{ var: 'path' }, { sha256: [{ body_field: 'nonce' }, { var: 'body' }] }], encoding: 'base64',
      place: [{ in: 'header', name: 'API-Sign', value: '{stamp}' }] }),
      img({ method: 'POST', path: '/0/private/AddOrder', body: 'nonce=1616492376594&ordertype=limit&pair=XBTUSD&price=37500&type=buy&volume=1.25',
        headers: { 'content-type': 'application/x-www-form-urlencoded' } }),
      { secret: 'kQH5HW/8p1uGOVjbgWA7FunAmGO8lsSUXNsu3eow76sz84Q18fWxnyRzBHCd3pd5nE9qa99HAZtuZuj6F1huXg==' });
    expect(r.stamp).toBe('4/dpxb3iT4tp/ZCVEwSnEsLxx0bqyhLpdfOpc6fn7OR8+UClSV5n9E6aSS8MPtnRfp32bAb0nmbRn6H8ndwLUQ==');
  });
  // Reference values computed independently with Python, exactly as SnapTrade's Python SDK
  // does it (json.dumps(sort_keys=True, separators=(',', ':')), HMAC-SHA256, base64).
  const SNAP = { mac: 'hmac-sha256', key: 'utf8', encoding: 'base64',
    message: [{ json: { content: { var: 'body_json' }, path: { var: 'path' }, query: { var: 'query' } } }],
    place: [{ in: 'header', name: 'Signature', value: '{stamp}' }] };
  it('SnapTrade JSON signature, POST with a non-ASCII body', () => {
    const r = computeStamp(recipe(SNAP), img({ method: 'POST', path: '/api/v1/snapTrade/login',
      query: 'clientId=WV&timestamp=1700000000&userId=u1&userSecret=s1', body: '{"note":"café","brokerage":"ALPACA"}' }),
      { secret: 'CONSUMERKEYexample123' });
    expect(r.stamp).toBe('lqB+owbU21Bq/OUjG0/LexqgxGlYg4sLW4Tw2Tw8EL0=');
  });
  it('SnapTrade JSON signature, GET with no body', () => {
    const r = computeStamp(recipe(SNAP), img({ path: '/api/v1/accounts', query: 'clientId=WV&timestamp=1700000000&userId=u1&userSecret=s1' }),
      { secret: 'CONSUMERKEYexample123' });
    expect(r.stamp).toBe('nq5JKsvZ2QrXmrGZ3neNjOFH/MZTaoHzMSlIhzHFfWQ=');
  });
});

describe('stamp: stored values and bodies (round 1)', () => {
  it('a JSON-shaped value that is not exactly {id, secret} is refused, not used whole', async () => {
    const { parseStampedValue } = await import('../src/stamp.js');
    expect(parseStampedValue('plainsecret')).toEqual({ secret: 'plainsecret' });
    expect(parseStampedValue('{"id":"A","secret":"s"}')).toEqual({ id: 'A', secret: 's' });
    for (const bad of ['{"id":"A","secret":"s","extra":1}', '{"secret":""}', '{"id":1,"secret":"s"}', '{not json', '[1]'.replace('[', '{')]) {
      expect(() => parseStampedValue(bad), bad).toThrow();
    }
  });
  it('a key read as base64 must really be base64 (round 2, F2)', () => {
    const r = recipe({ mac: 'hmac-sha256', key: 'base64', encoding: 'hex', message: [{ var: 'path' }],
      place: [{ in: 'header', name: 'x-sig', value: '{stamp}' }] });
    for (const bad of ['Z', 'abd', '!!!!', 'QUJD=X']) expect(() => computeStamp(r, img({}), { secret: bad }), bad).toThrow(/base64/);
    expect(() => computeStamp(r, img({}), { secret: 'QUJD' })).not.toThrow();
    expect(() => computeStamp(r, img({}), { secret: 'QUI=' })).not.toThrow();
    expect(() => computeStamp(r, img({}), { secret: 'QUI' })).not.toThrow();
  });
  it('body_json signs {} as {}, and no body as null', () => {
    const r = recipe({ mac: 'hmac-sha256', key: 'utf8', encoding: 'hex', message: [{ var: 'body_json' }],
      place: [{ in: 'header', name: 'x-sig', value: '{stamp}' }] });
    const crypto = require('node:crypto');
    expect(computeStamp(r, img({ method: 'POST', body: '{}' }), { secret: 'k' }).stamp)
      .toBe(crypto.createHmac('sha256', 'k').update('{}').digest('hex'));
    expect(computeStamp(r, img({}), { secret: 'k' }).stamp)
      .toBe(crypto.createHmac('sha256', 'k').update('null').digest('hex'));
  });
});

describe('stamp: recipes are refused, never repaired', () => {
  const ok = { mac: 'hmac-sha256', key: 'utf8', message: [{ var: 'body' }], encoding: 'hex', place: [{ in: 'header', name: 'X-Sig', value: '{stamp}' }] };
  it.each([
    ['unknown field', { ...ok, secret: true }],
    ['a var that names the key', { ...ok, message: [{ var: 'secret' }] }],
    ['an unknown part', { ...ok, message: [{ key: 'x' }] }],
    ['a placeholder other than stamp/key_id', { ...ok, place: [{ in: 'header', name: 'X-Sig', value: '{secret}{stamp}' }] }],
    ['no {stamp} placed', { ...ok, place: [{ in: 'header', name: 'X-Sig', value: '{key_id}' }] }],
    ['the host header', { ...ok, place: [{ in: 'header', name: 'Host', value: '{stamp}' }] }],
    ['reading the header it writes', { ...ok, message: [{ header: 'X-Sig' }], place: [{ in: 'header', name: 'X-Sig', value: '{stamp}' }] }],
    ['md5', { ...ok, mac: 'hmac-md5' }],
    ['deep nesting', { ...ok, message: [{ sha256: [{ sha256: [{ sha256: [{ sha256: [{ var: 'body' }] }] }] }] }] }],
    ['a part with two kinds', { ...ok, message: [{ var: 'body', text: 'x' }] }],
    ['an unknown builtin', { builtin: 'gcp' }],
  ])('%s', (_name, raw) => {
    expect(validateRecipe(raw).ok).toBe(false);
  });
  it('the hash changes with one byte of the recipe', () => {
    const a = recipeSha256(recipe(ok));
    const b = recipeSha256(recipe({ ...ok, place: [{ in: 'header', name: 'X-Sih', value: '{stamp}' }] }));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(b);
    // Key order does not matter: canonical JSON.
    expect(recipeSha256(recipe({ place: ok.place, encoding: 'hex', message: ok.message, key: 'utf8', mac: 'hmac-sha256' }))).toBe(a);
  });
});
