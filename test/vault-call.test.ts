/**
 * Acceptance checks for vault_call (SPEC-vault-call.md).
 *
 * The signature tests sign definitions the way the owner's browser would, so what is
 * exercised is the real construction rather than a stub that agrees with itself.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { pbkdf2Sync, createHmac, randomBytes } from 'node:crypto';
import {
  canonicalJson, verifyOperationDefinition, validateShape, validateArguments,
  filterResponse, _clearDerivedKeyCache, type OperationDefinition,
} from '../src/opdef.js';
import { isBlockedAddress, resolvePinned, expandIPv6, scrubSecret, pinnedLookup,
  definitionFromAgentRequest, originString, isApprovedPrivateOrigin } from '../src/http-broker.js';
import { modeAllowsHttpBroker, wrongModeMessage } from '../src/ssh-agent.js';

const SECRET = Buffer.from('sk-ant-api03-EXAMPLE-SECRET-VALUE');

const DEF: OperationDefinition = {
  op: 'anthropic.messages.create',
  origin: { scheme: 'https', host: 'api.anthropic.com', port: 443 },
  route: { method: 'POST', path: '/v1/messages' },
  credential_binding: { in: 'header', name: 'x-api-key', template: '{secret}' },
  arguments_schema: { model: 'string', max_tokens: 'number', messages: 'array' },
  static_headers: { 'anthropic-version': '2023-06-01' },
  response: { allow: ['id', 'model', 'content', 'usage'] },
  redirects: 'deny',
};

/** Sign exactly as the owner's browser would: PBKDF2 over the plaintext, HMAC the canonical form. */
function sign(def: unknown, secret: Buffer, salt = randomBytes(16)): string {
  const key = pbkdf2Sync(secret, salt, 600_000, 32, 'sha256');
  const mac = createHmac('sha256', key).update(canonicalJson(def)).digest();
  return Buffer.concat([salt, mac]).toString('base64');
}

beforeEach(() => { _clearDerivedKeyCache(); });

describe('canonicalisation', () => {
  it('is stable under key order', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
  });

  it('is stable under nesting order', () => {
    expect(canonicalJson({ x: { q: 1, p: 2 } })).toBe(canonicalJson({ x: { p: 2, q: 1 } }));
  });

  it('keeps array order, which is meaningful', () => {
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });
});

describe('signature verification', () => {
  it('accepts a correctly signed definition', () => {
    expect(verifyOperationDefinition('e1', DEF, sign(DEF, SECRET), SECRET).ok).toBe(true);
  });

  it('accepts the same definition with its keys reordered', () => {
    const sig = sign(DEF, SECRET);
    const reordered = { route: DEF.route, op: DEF.op, origin: DEF.origin,
      credential_binding: DEF.credential_binding, arguments_schema: DEF.arguments_schema,
      static_headers: DEF.static_headers, response: DEF.response, redirects: DEF.redirects };
    expect(verifyOperationDefinition('e1', reordered, sig, SECRET).ok).toBe(true);
  });

  it('refuses a definition whose origin was changed', () => {
    // The attack this exists for: a compromised server redirecting the credential.
    const sig = sign(DEF, SECRET);
    const tampered = { ...DEF, origin: { ...DEF.origin, host: 'evil.example' } };
    const r = verifyOperationDefinition('e1', tampered, sig, SECRET);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not match its signature/);
  });

  it('refuses a definition whose credential binding was changed', () => {
    const sig = sign(DEF, SECRET);
    const tampered = { ...DEF, credential_binding: { in: 'query' as const, name: 'leak', template: '{secret}' } };
    expect(verifyOperationDefinition('e1', tampered, sig, SECRET).ok).toBe(false);
  });

  it('refuses an unsigned definition rather than using it anyway', () => {
    const r = verifyOperationDefinition('e1', DEF, undefined, SECRET);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/no signature/);
  });

  it('refuses a signature of the wrong length', () => {
    expect(verifyOperationDefinition('e1', DEF, Buffer.alloc(10).toString('base64'), SECRET).ok).toBe(false);
  });

  it('refuses a definition signed for a DIFFERENT secret', () => {
    // Regression: the derived-key cache once keyed on (entry, salt) only, so a second
    // verification with another secret reused the first key and passed.
    const sig = sign(DEF, SECRET);
    expect(verifyOperationDefinition('e1', DEF, sig, Buffer.from('a-different-secret')).ok).toBe(false);
  });

  it('does not let a cached key leak across secrets under one entry', () => {
    const salt = randomBytes(16);
    const sigA = sign(DEF, SECRET, salt);
    expect(verifyOperationDefinition('e1', DEF, sigA, SECRET).ok).toBe(true);
    // same entry, same salt, different secret — must still fail
    expect(verifyOperationDefinition('e1', DEF, sigA, Buffer.from('other')).ok).toBe(false);
  });
});

describe('definition shape', () => {
  it('refuses an http origin', () => {
    const r = validateShape({ ...DEF, origin: { scheme: 'http', host: 'x.example', port: 80 } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/only https/);
  });

  it('refuses a host carrying userinfo or a path', () => {
    expect(validateShape({ ...DEF, origin: { ...DEF.origin, host: 'evil@api.anthropic.com' } }).ok).toBe(false);
    expect(validateShape({ ...DEF, origin: { ...DEF.origin, host: 'api.anthropic.com/x' } }).ok).toBe(false);
  });

  it('refuses a credential binding with no {secret} placeholder', () => {
    expect(validateShape({ ...DEF, credential_binding: { in: 'header' as const, name: 'a', template: 'constant' } }).ok).toBe(false);
  });

  it('refuses the credential header also appearing as a static header, in any case', () => {
    // The later value would silently win and the binding would look applied but not be.
    const r = validateShape({ ...DEF, static_headers: { 'X-API-KEY': 'oops' } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/both the credential binding and a static header/);
  });

  it('refuses enabling redirects', () => {
    expect(validateShape({ ...DEF, redirects: 'follow' as unknown as 'deny' }).ok).toBe(false);
  });

  it('refuses a credential-management route unless flagged deliberately', () => {
    const r = validateShape({ ...DEF, route: { method: 'GET', path: '/v1/api_keys' } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/credential-management/);
  });

  it('allows a credential-management route when flagged', () => {
    expect(validateShape({ ...DEF, route: { method: 'GET', path: '/v1/api_keys' }, allows_credential_management: true }).ok).toBe(true);
  });
});

describe('arguments', () => {
  it('accepts arguments matching the schema', () => {
    expect(validateArguments(DEF, { model: 'claude', max_tokens: 10, messages: [] }).ok).toBe(true);
  });

  it('rejects a wrong type', () => {
    const r = validateArguments(DEF, { model: 'claude', max_tokens: '10', messages: [] });
    expect(r.ok).toBe(false);
  });

  it('rejects a missing argument', () => {
    expect(validateArguments(DEF, { model: 'claude', messages: [] }).ok).toBe(false);
  });

  it('rejects an unknown argument rather than dropping it', () => {
    // Silently ignoring one means the caller believes it constrained a request that went
    // out without the constraint.
    const r = validateArguments(DEF, { model: 'c', max_tokens: 1, messages: [], stream: true });
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/Unknown argument "stream"/);
  });

  it('tells arrays from objects', () => {
    expect(validateArguments(DEF, { model: 'c', max_tokens: 1, messages: {} }).ok).toBe(false);
  });
});

describe('response filtering', () => {
  it('returns only allowed fields', () => {
    const out = filterResponse(DEF, { id: 'x', model: 'm', content: [], usage: {}, secret_echo: 'sk-leak' }) as Record<string, unknown>;
    expect(Object.keys(out).sort()).toEqual(['content', 'id', 'model', 'usage']);
    expect(JSON.stringify(out)).not.toContain('sk-leak');
  });

  it('returns nothing when the definition allows nothing', () => {
    expect(filterResponse({ ...DEF, response: { allow: [] } }, { a: 1 })).toEqual({});
  });

  it('does not pass an array body through', () => {
    expect(filterResponse(DEF, [1, 2, 3])).toEqual({});
  });
});

describe('SSRF address filtering', () => {
  const blocked = ['127.0.0.1', '10.0.0.5', '172.16.0.1', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '198.18.0.1', '::1', '::', 'fe80::1', 'fc00::1', 'ff02::1'];
  const mapped = ['::ffff:127.0.0.1', '::ffff:169.254.169.254', '::ffff:7f00:1'];
  const allowed = ['1.1.1.1', '8.8.8.8', '129.146.202.158', '2606:4700:4700::1111'];

  it.each(blocked)('blocks %s', (ip) => { expect(isBlockedAddress(ip)).toBe(true); });

  it.each(mapped)('blocks the IPv4-mapped form %s', (ip) => {
    // A v4 address wrapped in v6 notation smuggles past a naive v6 check.
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it.each(allowed)('permits %s', (ip) => { expect(isBlockedAddress(ip)).toBe(false); });

  it('blocks anything that is not an address', () => {
    expect(isBlockedAddress('not-an-ip')).toBe(true);
    expect(isBlockedAddress('')).toBe(true);
  });

  it('refuses to resolve a hostname that points at loopback', async () => {
    await expect(resolvePinned('localhost')).rejects.toThrow(/internal or reserved/);
  });

  it('refuses a literal metadata address', async () => {
    await expect(resolvePinned('169.254.169.254')).rejects.toThrow(/internal or reserved/);
  });
});

describe('mode gating for BROKER_HTTP', () => {
  it('allows vault_call only for BROKER_HTTP', () => {
    expect(modeAllowsHttpBroker('BROKER_HTTP')).toBe(true);
    expect(modeAllowsHttpBroker('LEGACY_EXEC')).toBe(false);
    expect(modeAllowsHttpBroker('BROKER_SSH_AGENT')).toBe(false);
    expect(modeAllowsHttpBroker(undefined)).toBe(false);
  });

  it('names the tool the caller needs', () => {
    expect(wrongModeMessage('BROKER_SSH_AGENT', 'http')).toContain('vault_ssh_exec');
  });
});

describe('round 1 regressions', () => {
  const base = {
    op: 'x', origin: { scheme: 'https', host: 'h.example', port: 443 },
    credential_binding: { in: 'header' as const, name: 'a', template: '{secret}' },
  };

  it('binds the catalogue key, so a signed definition cannot be filed elsewhere', () => {
    // Both definitions are legitimately signed; moving one into another's slot used to
    // pass verification and send the credential to a route nobody asked for.
    const def = { ...base, op: 'jobs.trigger', route: { method: 'POST', path: '/v1/jobs' } };
    const sig = sign(def, SECRET);
    expect(verifyOperationDefinition('e', def, sig, SECRET, 'jobs.trigger').ok).toBe(true);
    const moved = verifyOperationDefinition('e', def, sig, SECRET, 'health.check');
    expect(moved.ok).toBe(false);
    expect(moved.reason).toMatch(/Catalogue mismatch/);
  });

  it('refuses a non-numeric byte limit', () => {
    // `2 > "none"` is false, so a string limit silently disabled every size check.
    const r = validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { response_bytes: 'none' } });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/positive integer/);
  });

  it('refuses a zero or negative byte limit', () => {
    expect(validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { response_bytes: 0 } }).ok).toBe(false);
    expect(validateShape({ ...base, route: { method: 'GET', path: '/x' }, limits: { request_bytes: -1 } }).ok).toBe(false);
  });

  it('catches a credential-management path with no separator around the word', () => {
    // "/v1/apikeys" — "keys" sits inside a longer segment, which a boundary-anchored
    // pattern missed entirely.
    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/apikeys' } }).ok).toBe(false);
    expect(validateShape({ ...base, route: { method: 'GET', path: '/oauth2/authorize' } }).ok).toBe(false);
  });

  it('still allows ordinary routes', () => {
    expect(validateShape({ ...base, route: { method: 'POST', path: '/v1/messages' } }).ok).toBe(true);
    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/user' } }).ok).toBe(true);
  });

  it('blocks the fully-expanded IPv4-mapped loopback form', () => {
    // Only the compressed spellings were matched before, so this reached 127.0.0.1.
    expect(isBlockedAddress('0:0:0:0:0:ffff:127.0.0.1')).toBe(true);
    expect(isBlockedAddress('0:0:0:0:0:ffff:169.254.169.254')).toBe(true);
  });

  it('still permits a genuine public IPv6 address', () => {
    expect(isBlockedAddress('2606:4700:4700::1111')).toBe(false);
  });

  it('scrubs the credential from a response even in an allowed field', () => {
    // The allowlist alone cannot help when the upstream echoes the secret into a field
    // the operation legitimately permits.
    const out = scrubSecret({ content: 'sk-live-123', nested: [{ x: 'pre sk-live-123 post' }] }, 'sk-live-123');
    expect(JSON.stringify(out)).not.toContain('sk-live-123');
    expect(JSON.stringify(out)).toContain('[REDACTED]');
  });

  it('leaves a response alone when it does not contain the secret', () => {
    expect(scrubSecret({ a: 'ordinary' }, 'sk-live')).toEqual({ a: 'ordinary' });
  });
});

describe('IPv6 expansion', () => {
  it('expands compressed and dotted forms to eight groups', () => {
    expect(expandIPv6('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(expandIPv6('::ffff:127.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
    expect(expandIPv6('0:0:0:0:0:ffff:127.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
  });

  it('returns null for things that are not addresses', () => {
    expect(expandIPv6('nonsense')).toBeNull();
    expect(expandIPv6('1::2::3')).toBeNull();
  });
});

describe('round 2 regressions', () => {
  const base = {
    op: 'x', origin: { scheme: 'https', host: 'h.example', port: 443 },
    credential_binding: { in: 'header' as const, name: 'a', template: '{secret}' },
  };

  // Round 1 fixed the mapped form and left the plain expanded one. Decide on groups,
  // never on the spelling.
  it.each(['0:0:0:0:0:0:0:1', '0:0:0:0:0:0:0:0', '::1', '::'])('blocks loopback written as %s', (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it.each(['fe80:0:0:0:0:0:0:1', 'fc00:0:0:0:0:0:0:1', 'ff02:0:0:0:0:0:0:1'])('blocks expanded %s', (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it('still permits a real public IPv6 address in expanded form', () => {
    expect(isBlockedAddress('2606:4700:4700:0:0:0:0:1111')).toBe(false);
  });

  it('scrubs the secret out of object KEYS, not only values', () => {
    // {"content":{"sk-live":"echo"}} put the secret in the key, and value-only scrubbing
    // left it in the stringified output.
    const out = scrubSecret({ content: { 'sk-live-123': 'echo' } }, 'sk-live-123');
    expect(JSON.stringify(out)).not.toContain('sk-live-123');
  });

  it('refuses a percent-encoded credential-management path', () => {
    // "/v1/%74oken" is "/v1/token" to any normal router; a raw substring test never sees it.
    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/%74oken' } }).ok).toBe(false);
  });

  it('refuses a double-encoded one too', () => {
    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/%2574oken' } }).ok).toBe(false);
  });

  it('refuses a path that is not valid percent-encoding rather than guessing', () => {
    expect(validateShape({ ...base, route: { method: 'GET', path: '/v1/%zz' } }).ok).toBe(false);
  });

  it('leaves an ordinary path alone after decoding', () => {
    expect(validateShape({ ...base, route: { method: 'POST', path: '/v1/mess%61ges' } }).ok).toBe(true);
  });
});

describe('pinned lookup shim', () => {
  it('answers the array shape when Node asks for all', async () => {
    // Getting this wrong is invisible to every unit test and fatal in production: the
    // broker returned "Invalid IP address: undefined" and no request could complete.
    const fn = pinnedLookup('93.184.216.34', 4);
    const got = await new Promise((r) => fn('example.com', { all: true }, (_e, v) => r(v)));
    expect(got).toEqual([{ address: '93.184.216.34', family: 4 }]);
  });

  it('answers the (address, family) shape otherwise', async () => {
    const fn = pinnedLookup('93.184.216.34', 4);
    const got = await new Promise((r) => fn('example.com', {}, (_e, a, f) => r([a, f])));
    expect(got).toEqual(['93.184.216.34', 4]);
  });

  it('handles a missing options object', async () => {
    const fn = pinnedLookup('::1', 6);
    const got = await new Promise((r) => fn('h', undefined, (_e, a, f) => r([a, f])));
    expect(got).toEqual(['::1', 6]);
  });
});

describe('tiered brokering — agent-described requests', () => {
  const BINDING = { in: 'header' as const, name: 'authorization', template: 'Bearer {secret}' };

  it('builds a route from typed parts, never from a URL string', () => {
    // No URL is parsed anywhere, so there is nothing to smuggle through parsing.
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: 'api.cloudflare.com', port: 443 }, method: 'get', path: '/client/v4/zones' },
      BINDING);
    expect(d.route.method).toBe('GET');
    expect(d.route.path).toBe('/client/v4/zones');
    expect(d.origin.host).toBe('api.cloudflare.com');
  });

  it('encodes query parameters rather than trusting a caller-built string', () => {
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: 'h.example', port: 443 }, method: 'GET', path: '/x',
        query: { q: 'a b&c', page: '2' } }, BINDING);
    expect(d.route.path).toBe('/x?q=a%20b%26c&page=2');
  });

  it('takes the credential binding from the entry, never from the agent', () => {
    // An agent may choose where to send a request; it never chooses how the secret is
    // framed on the way out.
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: 'h.example', port: 443 }, method: 'GET', path: '/' },
      { in: 'header', name: 'x-api-key', template: '{secret}' });
    expect(d.credential_binding.name).toBe('x-api-key');
    expect(d.credential_binding.template).toBe('{secret}');
  });

  it('denies redirects on an agent-described request too', () => {
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: 'h.example', port: 443 }, method: 'GET', path: '/' }, BINDING);
    expect(d.redirects).toBe('deny');
  });

  it('returns the whole body when no allowlist was declared', () => {
    // An unsigned request has no response section, and returning {} would make every
    // tier-1 call useless. Absent means everything; empty means nothing.
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: 'h.example', port: 443 }, method: 'GET', path: '/' }, BINDING);
    expect(filterResponse(d, { a: 1, b: 2 })).toEqual({ a: 1, b: 2 });
  });

  it('still returns nothing when a signed definition allows nothing', () => {
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: 'h.example', port: 443 }, method: 'GET', path: '/' }, BINDING);
    expect(filterResponse({ ...d, response: { allow: [] } }, { a: 1 })).toEqual({});
  });

  it('renders a canonical origin for the approval record and the audit row', () => {
    expect(originString({ scheme: 'https', host: 'api.openai.com', port: 443 }))
      .toBe('https://api.openai.com:443');
  });

  it('an agent-described request is still subject to the address filter', () => {
    // Tier 1 removes the approval, not the SSRF protection.
    const d = definitionFromAgentRequest(
      { origin: { scheme: 'https', host: '169.254.169.254', port: 443 }, method: 'GET', path: '/' }, BINDING);
    expect(isBlockedAddress(d.origin.host)).toBe(true);
  });
});

describe('owner-approved private origins', () => {
  const o = (host: string, port: number) => ({ scheme: 'https', host, port });

  it('matches only the exact scheme, host and port', () => {
    // A prefix or subnet match would let 10.0.0.5:9000 cover 10.0.0.50:9000 or port 22,
    // and a range is a decision an owner cannot realistically evaluate.
    const approved = ['https://10.0.0.5:9000'];
    expect(isApprovedPrivateOrigin(o('10.0.0.5', 9000), approved)).toBe(true);
    expect(isApprovedPrivateOrigin(o('10.0.0.5', 22), approved)).toBe(false);
    expect(isApprovedPrivateOrigin(o('10.0.0.50', 9000), approved)).toBe(false);
    expect(isApprovedPrivateOrigin({ ...o('10.0.0.5', 9000), scheme: 'http' }, approved)).toBe(false);
  });

  it('is case-insensitive on the host but still exact', () => {
    expect(isApprovedPrivateOrigin(o('NAS.local', 9000), ['https://nas.local:9000'])).toBe(true);
  });

  it('approves nothing when the entry has no approvals', () => {
    expect(isApprovedPrivateOrigin(o('10.0.0.5', 9000), [])).toBe(false);
    expect(isApprovedPrivateOrigin(o('10.0.0.5', 9000), undefined)).toBe(false);
  });

  it('refuses cloud metadata even when it appears in the approval list', () => {
    // These hand out instance credentials; it is not a decision an owner gets to make.
    expect(isApprovedPrivateOrigin(o('169.254.169.254', 80), ['https://169.254.169.254:80'])).toBe(false);
    expect(isApprovedPrivateOrigin(o('100.100.100.200', 80), ['https://100.100.100.200:80'])).toBe(false);
  });

  it('lets an approved internal address resolve, and still blocks an unapproved one', async () => {
    await expect(resolvePinned('10.0.0.5', true)).resolves.toMatchObject({ address: '10.0.0.5' });
    await expect(resolvePinned('10.0.0.5', false)).rejects.toThrow(/internal or reserved/);
  });

  it('blocks metadata even when internal access was granted', async () => {
    await expect(resolvePinned('169.254.169.254', true)).rejects.toThrow(/metadata/);
  });
});
