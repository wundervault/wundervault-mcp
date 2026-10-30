import { beforeEach, describe, expect, it, vi } from 'vitest';
import { request as httpsRequest } from 'node:https';
import type { RequestOptions } from 'node:https';
import type { ClientRequest, IncomingMessage } from 'node:http';
import { PassThrough } from 'node:stream';
import { applyPlacements } from '../src/parts.js';
import type { BindingV2 } from '../src/parts.js';
import { definitionFromAgentRequest, performOperation } from '../src/http-broker.js';

vi.mock('node:https', () => ({ request: vi.fn() }));

const twoHeaders: BindingV2 = {
  v: 2,
  placements: [
    { in: 'header', name: 'APCA-API-KEY-ID', template: '{part:id}' },
    { in: 'header', name: 'APCA-API-SECRET-KEY', template: '{part:secret}' },
  ],
};

const basic: BindingV2 = {
  v: 2,
  placements: [
    { in: 'header', name: 'Authorization', template: 'Basic {basic:id:secret}' },
  ],
};

const telegram: BindingV2 = {
  v: 2,
  placements: [
    { in: 'path', name: '', template: '/bot{part:key}' },
  ],
};

describe('applyPlacements', () => {
  it('places a key and ID in two lowercase headers', () => {
    expect(applyPlacements(twoHeaders, { id: 'public-id', secret: 'private-key' }, '/v2/account')).toEqual({
      headers: {
        'apca-api-key-id': 'public-id',
        'apca-api-secret-key': 'private-key',
      },
      path: '/v2/account',
    });
  });

  it('composes Twilio-style basic authentication from two parts', () => {
    const parts = { id: 'AC12345678', secret: 'twilio-password' };
    expect(applyPlacements(basic, parts, '/Accounts.json')).toEqual({
      headers: {
        authorization: `Basic ${Buffer.from(`${parts.id}:${parts.secret}`, 'utf8').toString('base64')}`,
      },
      path: '/Accounts.json',
    });
  });

  it('refuses a colon in a basic username', () => {
    expect(() => applyPlacements(basic, { id: 'bad:user', secret: 'password' }, '/'))
      .toThrow("a basic username must not contain ':'");
  });

  it('appends an encoded query placement to an existing query', () => {
    const binding: BindingV2 = {
      v: 2,
      placements: [
        { in: 'query', name: 'api_key', template: 'prefix {part:key}' },
      ],
    };
    expect(applyPlacements(binding, { key: 'a+b/&=' }, '/search?a=1')).toEqual({
      headers: {},
      path: `/search?a=1&${encodeURIComponent('api_key')}=${encodeURIComponent('prefix a+b/&=')}`,
    });
  });

  it('starts a query when the agent path has none', () => {
    const binding: BindingV2 = {
      v: 2,
      placements: [
        { in: 'query', name: 'api_key', template: '{part:key}' },
      ],
    };
    expect(applyPlacements(binding, { key: 'a+b' }, '/search')).toEqual({
      headers: {},
      path: '/search?api_key=a%2Bb',
    });
  });

  it('uses the real agent path for a Telegram-style path placement', () => {
    expect(applyPlacements(telegram, { key: '123456:ABCdef' }, '/getMe')).toEqual({
      headers: {},
      path: '/bot123456:ABCdef/getMe',
    });
  });

  it('throws when a placed part is missing', () => {
    expect(() => applyPlacements(twoHeaders, { id: 'public-id' }, '/'))
      .toThrow('missing part: secret');
    expect(() => applyPlacements(basic, { id: 'public-id' }, '/'))
      .toThrow('missing part: secret');
  });

  it('throws on a path binding problem', () => {
    expect(() => applyPlacements(telegram, { key: '/../../escape' }, '/getMe/../admin'))
      .toThrow();
  });

  it('skips a stamp placement', () => {
    expect(applyPlacements({
      v: 2,
      placements: [{ in: 'stamp', name: '', template: '' }],
    }, {}, '/unchanged?a=1')).toEqual({
      headers: {},
      path: '/unchanged?a=1',
    });
  });

  it('does not interpret replacement metacharacters in a part', () => {
    const binding: BindingV2 = {
      v: 2,
      placements: [{ in: 'header', name: 'x-key', template: 'prefix {part:key}' }],
    };
    expect(applyPlacements(binding, { key: '$&$`' }, '/').headers)
      .toEqual({ 'x-key': 'prefix $&$`' });
  });
});

describe('performOperation placements', () => {
  const approved = ['https://127.0.0.1:443'];
  let receivedHeaders: Record<string, string>;
  let receivedPath: string | undefined;
  let reply: unknown;
  let status: number;
  let contentType: string;
  let requestError: string | undefined;

  function definition(headers?: Record<string, string>, path = '/echo') {
    return definitionFromAgentRequest({
      origin: { scheme: 'https', host: '127.0.0.1', port: 443 },
      method: 'GET',
      path,
      headers,
    }, { in: 'header', name: 'x-legacy-key', template: '{secret}' });
  }

  beforeEach(() => {
    vi.mocked(httpsRequest).mockReset();
    receivedHeaders = {};
    receivedPath = undefined;
    reply = undefined;
    status = 200;
    contentType = 'application/json';
    requestError = undefined;

    // Stub only the HTTPS transport: the executor still builds the request and consumes
    // a streamed echo response, without a certificate fixture or an external service.
    vi.mocked(httpsRequest).mockImplementation((options, callback) => {
      const opts = options as RequestOptions;
      if (typeof callback !== 'function') throw new Error('expected a response callback');
      receivedHeaders = { ...(opts.headers as Record<string, string>) };
      receivedPath = opts.path;
      const request = new PassThrough();
      request.on('finish', () => {
        if (requestError !== undefined) {
          request.emit('error', new Error(requestError));
          request.emit('close');
          return;
        }
        const response = new PassThrough();
        const incoming = response as unknown as IncomingMessage;
        incoming.statusCode = status;
        incoming.headers = { 'content-type': contentType };
        callback(incoming);
        const body = reply === undefined
          ? { headers: receivedHeaders, path: receivedPath }
          : reply;
        response.end(Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8'));
        request.emit('close');
      });
      return request as unknown as ClientRequest;
    });
  });

  it('sends both headers, keeps ordinary headers, and scrubs either echoed part', async () => {
    const parts = { id: 'public-id-123', secret: 'private-key-456' };
    const result = await performOperation(
      definition({ 'x-api-version': '2024-01' }),
      {},
      '',
      approved,
      undefined,
      { binding: twoHeaders, parts },
    );

    expect(receivedHeaders).toMatchObject({
      'apca-api-key-id': parts.id,
      'apca-api-secret-key': parts.secret,
      'x-api-version': '2024-01',
    });
    expect(receivedHeaders).not.toHaveProperty('x-legacy-key');
    expect(result).toMatchObject({
      ok: true,
      status: 200,
      body: {
        headers: {
          'apca-api-key-id': '[REDACTED]',
          'apca-api-secret-key': '[REDACTED]',
          'x-api-version': '2024-01',
        },
        path: '/echo',
      },
    });
  });

  it('scrubs the composed basic token as well as both parts and their URL forms', async () => {
    const parts = { id: 'AC12345678', secret: 'twilio+/password=' };
    const token = Buffer.from(`${parts.id}:${parts.secret}`, 'utf8').toString('base64');
    reply = {
      token,
      authorization: `Basic ${token}`,
      id: parts.id,
      password: parts.secret,
      encodedPassword: encodeURIComponent(parts.secret),
      encodedToken: encodeURIComponent(token),
    };

    const result = await performOperation(
      definition(), {}, '', approved, undefined, { binding: basic, parts },
    );

    expect(receivedHeaders.authorization).toBe(`Basic ${token}`);
    expect(result).toEqual({
      ok: true,
      status: 200,
      body: {
        token: '[REDACTED]',
        authorization: 'Basic [REDACTED]',
        id: '[REDACTED]',
        password: '[REDACTED]',
        encodedPassword: '[REDACTED]',
        encodedToken: '[REDACTED]',
      },
    });
  });

  it('refuses a pre-existing credential header case-insensitively without sending', async () => {
    const result = await performOperation(
      definition({ 'ApCa-ApI-SeCrEt-KeY': 'agent-supplied' }),
      {},
      '',
      approved,
      undefined,
      { binding: twoHeaders, parts: { id: 'public-id', secret: 'private-key' } },
    );

    expect(result).toEqual({
      ok: false,
      error: 'Refused: the request already sends apca-api-secret-key, and the key goes there too. Nothing was sent.',
    });
    expect(httpsRequest).not.toHaveBeenCalled();
  });

  it('sends a query placement on the existing agent query and scrubs the echo', async () => {
    const binding: BindingV2 = {
      v: 2,
      placements: [{ in: 'query', name: 'api_key', template: '{part:key}' }],
    };
    const result = await performOperation(
      definition(undefined, '/echo?a=1'),
      {},
      '',
      approved,
      undefined,
      { binding, parts: { key: 'credential+/=' } },
    );

    expect(receivedPath).toBe('/echo?a=1&api_key=credential%2B%2F%3D');
    expect(result).toMatchObject({
      ok: true,
      body: { path: '/echo?a=1&api_key=[REDACTED]' },
    });
  });

  it('sends the real agent path after a path placement and leaves the definition unchanged', async () => {
    const def = definition(undefined, '/getMe');
    const result = await performOperation(
      def, {}, '', approved, undefined,
      { binding: telegram, parts: { key: '123456:ABCdef' } },
    );

    expect(receivedPath).toBe('/bot123456:ABCdef/getMe');
    expect(def.route.path).toBe('/getMe');
    expect(result).toMatchObject({
      ok: true,
      body: { path: '/bot[REDACTED]/getMe' },
    });
  });

  it('scrubs longest first in one pass, including object keys and nested arrays', async () => {
    reply = {
      'RED-long': ['RED-long RED', { nested: 'RED' }],
    };
    const result = await performOperation(
      definition(), {}, '', approved, undefined,
      { binding: twoHeaders, parts: { id: 'RED', secret: 'RED-long' } },
    );

    expect(result).toEqual({
      ok: true,
      status: 200,
      body: {
        '[REDACTED]': ['[REDACTED] [REDACTED]', { nested: '[REDACTED]' }],
      },
    });
  });

  it('scrubs plaintext error replies with all parts', async () => {
    status = 400;
    contentType = 'text/plain';
    reply = 'invalid public-id-123 or private-key-456';
    const result = await performOperation(
      definition(), {}, '', approved, undefined,
      { binding: twoHeaders, parts: { id: 'public-id-123', secret: 'private-key-456' } },
    );

    expect(result).toEqual({
      ok: false,
      status: 400,
      body: 'invalid [REDACTED] or [REDACTED]',
      error: 'Upstream returned HTTP 400.',
    });
  });

  it('scrubs transport errors with all parts', async () => {
    requestError = 'could not send public-id-123 or private-key-456';
    const result = await performOperation(
      definition(), {}, '', approved, undefined,
      { binding: twoHeaders, parts: { id: 'public-id-123', secret: 'private-key-456' } },
    );

    expect(result).toEqual({
      ok: false,
      error: 'Request failed: could not send [REDACTED] or [REDACTED]',
    });
  });

  it('scrubs an upstream media type before describing a non-text reply', async () => {
    contentType = 'application/private-key-456';
    reply = Buffer.from([0]).toString('utf8');
    const result = await performOperation(
      definition(), {}, '', approved, undefined,
      { binding: twoHeaders, parts: { id: 'public-id-123', secret: 'private-key-456' } },
    );

    expect(result).toEqual({
      ok: true,
      status: 200,
      body: '[1 bytes of application/[REDACTED], not text, so not shown]',
    });
  });

  it('ignores the legacy secret argument when parts are supplied', async () => {
    reply = { ordinary: 'legacy-value' };
    const result = await performOperation(
      definition(), {}, 'legacy-value', approved, undefined,
      { binding: twoHeaders, parts: { id: 'public-id-123', secret: 'private-key-456' } },
    );

    expect(result).toEqual({
      ok: true,
      status: 200,
      body: { ordinary: 'legacy-value' },
    });
  });

  it('refuses missing parts without sending', async () => {
    const result = await performOperation(
      definition(), {}, '', approved, undefined,
      { binding: twoHeaders, parts: { id: 'public-id-123' } },
    );

    expect(result.ok).toBe(false);
    expect(result.error).toContain('missing part: secret');
    expect(httpsRequest).not.toHaveBeenCalled();
  });

  it('refuses parts combined with a stamper without calling it or sending', async () => {
    const stamper = vi.fn(() => ({ headers: {}, query: [], stamp: 'stamp-value' }));
    const result = await performOperation(
      definition(), {}, '', approved, stamper,
      { binding: twoHeaders, parts: { id: 'public-id-123', secret: 'private-key-456' } },
    );

    expect(result).toEqual({
      ok: false,
      error: 'Refused: a stamp cannot be combined with parts. Nothing was sent.',
    });
    expect(stamper).not.toHaveBeenCalled();
    expect(httpsRequest).not.toHaveBeenCalled();
  });

  it('refuses a stamp placement in the supplied parts binding', async () => {
    const result = await performOperation(
      definition(), {}, '', approved, undefined,
      {
        binding: { v: 2, placements: [{ in: 'stamp', name: '', template: '' }] },
        parts: {},
      },
    );

    expect(result.ok).toBe(false);
    expect(httpsRequest).not.toHaveBeenCalled();
  });

  it('retains legacy placement and redaction when parts are absent', async () => {
    const result = await performOperation(
      definition(), {}, 'legacy-value', approved,
    );

    expect(receivedHeaders['x-legacy-key']).toBe('legacy-value');
    expect(result).toMatchObject({
      ok: true,
      body: { headers: { 'x-legacy-key': '[REDACTED]' }, path: '/echo' },
    });
  });
});
