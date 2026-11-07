import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'vitest';
import { canonicalJson } from '../src/opdef.js';
import {
  normalizeOrigin, validateSendAs, placementRecipe, placementSha,
  describePlacement, isAskBinding, type SendAs,
} from '../src/placement.js';

test('normalizeOrigin uses one https spelling with an explicit port', () => {
  assert.equal(normalizeOrigin('https://API.Example.com'), 'https://api.example.com:443');
  assert.equal(normalizeOrigin('https://API.Example.com:443'), 'https://api.example.com:443');
  assert.equal(normalizeOrigin('https://api.example.com:8443'), 'https://api.example.com:8443');
  assert.equal(normalizeOrigin('https://127.0.0.1:9443'), 'https://127.0.0.1:9443');
  assert.equal(normalizeOrigin({ scheme: 'https', host: 'API.Example.com' }), 'https://api.example.com:443');
  assert.equal(normalizeOrigin({ scheme: 'https', host: 'api.example.com', port: 8443 }), 'https://api.example.com:8443');
});

test('normalizeOrigin refuses anything other than an unambiguous https origin', () => {
  for (const origin of [
    '', 'http://api.example.com', 'https://user@api.example.com',
    'https://user:password@api.example.com', 'https://api.example.com/',
    'https://api.example.com/path', 'https://api.example.com?x=1',
    'https://api.example.com#fragment', 'https://[::1]:443',
    'https://api.example.com:0', 'https://api.example.com:65536',
    'https://api.example.com:-1', 'https://api.example.com:1.5',
    'https://api.example.com:', ' https://api.example.com',
    'https://api.example.com\n', 'https://api_example.com',
    'https://-api.example.com', 'https://api..example.com',
    'https://127.1', 'https://2130706433',
  ]) assert.equal(normalizeOrigin(origin), null, origin);
  for (const origin of [
    { scheme: 'http', host: 'api.example.com', port: 443 },
    { scheme: 'https', host: 'api.example.com/path', port: 443 },
    { scheme: 'https', host: 'user@api.example.com', port: 443 },
    { scheme: 'https', host: '::1', port: 443 },
    { scheme: 'https', host: 'api.example.com', port: 0 },
    { scheme: 'https', host: 'api.example.com', port: 65536 },
    { scheme: 'https', host: 'api.example.com', port: 443.5 },
    { scheme: 'https', host: 'api.example.com', port: NaN },
  ]) assert.equal(normalizeOrigin(origin), null, JSON.stringify(origin));
});

test('validateSendAs accepts headers and query names and lower-cases only header names', () => {
  assert.deepEqual(validateSendAs({ in: 'header', name: 'X-Api-Key', template: '{secret}' }), {
    ok: true, sendAs: { in: 'header', name: 'x-api-key', template: '{secret}' },
  });
  assert.deepEqual(validateSendAs({ in: 'header', name: 'Authorization', template: 'Bearer {secret}' }), {
    ok: true, sendAs: { in: 'header', name: 'authorization', template: 'Bearer {secret}' },
  });
  assert.deepEqual(validateSendAs({ in: 'query', name: 'Api_Key.v1-2', template: 'before{secret}after' }), {
    ok: true, sendAs: { in: 'query', name: 'Api_Key.v1-2', template: 'before{secret}after' },
  });
  assert.equal(validateSendAs({ in: 'header', name: "!#$%&'*+-.^_`|~AZ09", template: '{secret}' }).ok, true);
  assert.equal(validateSendAs({ in: 'query', name: 'x'.repeat(64), template: '{secret}' }).ok, true);
  assert.equal(validateSendAs({ in: 'header', name: 'x-key', template: 'x'.repeat(248) + '{secret}' }).ok, true);
});

test('validateSendAs refuses every forbidden header regardless of case', () => {
  for (const name of [
    'host', 'content-length', 'transfer-encoding', 'connection', 'cookie',
    'proxy-authorization', 'te', 'upgrade', 'trailer', 'keep-alive',
  ]) {
    for (const spelling of [name, name.toUpperCase()]) {
      assert.equal(validateSendAs({ in: 'header', name: spelling, template: '{secret}' }).ok, false, spelling);
    }
  }
});

test('validateSendAs refuses line breaks, invalid names and invalid secret markers', () => {
  for (const raw of [
    null, [], true, 'header',
    { in: 'path', name: 'key', template: '{secret}' },
    { in: 'header', name: '', template: '{secret}' },
    { in: 'header', name: 'X Key', template: '{secret}' },
    { in: 'header', name: 'X:Key', template: '{secret}' },
    { in: 'header', name: 'X-Key\r\nOther', template: '{secret}' },
    { in: 'query', name: 'api_key\n', template: '{secret}' },
    { in: 'query', name: 'api&key', template: '{secret}' },
    { in: 'query', name: 'x'.repeat(65), template: '{secret}' },
    { in: 'header', name: 'X-Key', template: 'Token\r{secret}' },
    { in: 'header', name: 'X-Key', template: '{secret}\n' },
    { in: 'header', name: 'X-Key', template: '{secret}{secret}' },
    { in: 'header', name: 'X-Key', template: 'no secret marker' },
    { in: 'header', name: 'X-Key', template: 'x'.repeat(249) + '{secret}' },
    { in: 'header', name: 'X-Key', template: '{secret}', extra: true },
  ]) assert.equal(validateSendAs(raw).ok, false, JSON.stringify(raw));
});

test('placement recipe is exactly the object the page hashes', () => {
  const origin = 'https://api.example.com:443';
  const sendAs: SendAs = { in: 'header', name: 'x-api-key', template: '{secret}' };
  assert.deepEqual(placementRecipe(origin, sendAs), {
    type: 'placement', v: 1, origin, send_as: sendAs,
  });
  const sha = createHash('sha256').update(canonicalJson({
    send_as: { template: '{secret}', name: 'x-api-key', in: 'header' },
    origin, v: 1, type: 'placement',
  })).digest('hex');
  assert.equal(placementSha(origin, sendAs), sha);
  assert.equal(placementSha(origin, { template: '{secret}', in: 'header', name: 'x-api-key' }), sha);
  assert.match(sha, /^[a-f0-9]{64}$/);
  for (const different of [
    placementSha('https://other.example.com:443', sendAs),
    placementSha('https://api.example.com:8443', sendAs),
    placementSha(origin, { ...sendAs, name: 'x-other-key' }),
    placementSha(origin, { ...sendAs, template: 'Token {secret}' }),
    placementSha(origin, { ...sendAs, in: 'query' }),
  ]) assert.notEqual(different, sha);
});

test('describePlacement uses plain words for each supported form', () => {
  const origin = 'https://api.example.com:443';
  const descriptions = [
    describePlacement(origin, { in: 'header', name: 'authorization', template: 'Bearer {secret}' }),
    describePlacement(origin, { in: 'header', name: 'x-api-key', template: '{secret}' }),
    describePlacement(origin, { in: 'header', name: 'x-api-key', template: 'Token {secret}' }),
    describePlacement(origin, { in: 'query', name: 'api_key', template: '{secret}' }),
  ];
  assert.deepEqual(descriptions, [
    'Send this key to api.example.com in the Authorization header (as a Bearer token)',
    'Send this key to api.example.com in a header named X-Api-Key',
    'Send this key to api.example.com in a header named X-Api-Key, after "Token "',
    'Send this key to api.example.com after ? in the address, as ?api_key=…',
  ]);
  for (const description of descriptions) {
    assert.doesNotMatch(description, /template|binding|placement/i);
    assert.doesNotMatch(description, /:443/);
  }
  assert.equal(
    describePlacement('https://api.example.com:8443', { in: 'header', name: 'x-api-key', template: '{secret}' }),
    'Send this key to api.example.com:8443 in a header named X-Api-Key',
  );
});

test('isAskBinding recognises only exactly {ask:true}', () => {
  assert.equal(isAskBinding({ ask: true }), true);
  for (const value of [
    null, undefined, [], true, 'ask', {}, { ask: false }, { ask: 1 },
    { ask: 'true' }, { ask: true, in: 'header' }, { ask: true, extra: undefined },
    { in: 'header', name: 'authorization', template: 'Bearer {secret}' },
    Object.create({ ask: true }),
  ]) assert.equal(isAskBinding(value), false);
});
