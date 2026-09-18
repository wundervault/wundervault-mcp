/**
 * Phase 6 — the broker signs, and nothing else can.
 *
 * `burnbox/SPEC-phase6-server-enforcement.md`. The server half is tested over there; what
 * these tests defend is that the client actually puts a signature on the wire, over the
 * bytes it actually sends, and that the private key stays on the one code path that is
 * allowed to touch it.
 *
 * The signature is checked by VERIFYING it against the public half, not by asserting that
 * a header is non-empty. A test that only checks presence would pass against a client
 * that signed the wrong string, which is precisely the bug that matters.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { describe, it, expect, vi, afterEach } from 'vitest';

import { AgentVaultAPI } from '../src/api-client.js';
import { BrokerSigner, canonicalString, sha256Hex, signerFromIdentity } from '../src/broker-sign.js';

const KEY = 'wv_agent_test|secret';
const ENC = new Uint8Array(32).fill(7);

function keypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey,
  };
}

type Seen = { url: string; method: string; headers: Record<string, string>; body?: string };

function stubFetch(response: unknown): Seen[] {
  const seen: Seen[] = [];
  vi.stubGlobal('fetch', async (url: string, init?: any) => {
    seen.push({
      url: String(url),
      method: init?.method ?? 'GET',
      headers: init?.headers ?? {},
      body: init?.body,
    });
    return {
      ok: true,
      status: 200,
      json: async () => response,
      text: async () => JSON.stringify(response),
    };
  });
  return seen;
}

/** Re-derive what the server would check, and verify the signature against it. */
function verifyAsServerWould(seen: Seen, publicKey: crypto.KeyObject): boolean {
  const u = new URL(seen.url);
  const message = canonicalString(
    seen.method,
    u.pathname,
    u.search.replace(/^\?/, ''),
    seen.headers['X-Broker-Timestamp'],
    seen.headers['X-Broker-Nonce'],
    sha256Hex(seen.body),
  );
  return crypto.verify(
    'sha256', message, publicKey,
    Buffer.from(seen.headers['X-Broker-Signature'], 'base64'),
  );
}

afterEach(() => { vi.unstubAllGlobals(); });

describe('every call the broker makes is signed', () => {
  it('signs a GET over the path and the query it actually sent', async () => {
    const { privateKeyPem, publicKey } = keypair();
    const api = new AgentVaultAPI(KEY, ENC, 'https://wundervault.com',
                                  new BrokerSigner(privateKeyPem));
    const seen = stubFetch({ name: 'X', encrypted_content: 'c', content_nonce: 'n' });

    await api.getSecret('entry-1', 'deploy the site');

    expect(seen).toHaveLength(1);
    expect(seen[0].url).toContain('purpose=');
    expect(verifyAsServerWould(seen[0], publicKey)).toBe(true);
  });

  it('signs a POST over the exact body bytes', async () => {
    const { privateKeyPem, publicKey } = keypair();
    const api = new AgentVaultAPI(KEY, ENC, 'https://wundervault.com',
                                  new BrokerSigner(privateKeyPem));
    const seen = stubFetch({ allowed: true, tier: '1' });

    await api.checkOperation({ entry_id: 'e1', purpose: 'send the mail' });

    expect(seen[0].method).toBe('POST');
    expect(seen[0].body).toBeTruthy();
    expect(verifyAsServerWould(seen[0], publicKey)).toBe(true);
  });

  it('signs the profile call, which is the one that carries the wrapped vault key', async () => {
    const { privateKeyPem, publicKey } = keypair();
    const api = new AgentVaultAPI(KEY, ENC, 'https://wundervault.com',
                                  new BrokerSigner(privateKeyPem));
    const seen = stubFetch({ agent_id: 'a', name: 'X', status: 'active',
                             vault_key_for_agent: null, allow_env_inject: false });

    await api.getProfile();
    expect(verifyAsServerWould(seen[0], publicKey)).toBe(true);
  });

  it('keeps the credential headers — the signature is added, never substituted', async () => {
    const { privateKeyPem } = keypair();
    const api = new AgentVaultAPI(KEY, ENC, 'https://wundervault.com',
                                  new BrokerSigner(privateKeyPem));
    const seen = stubFetch({ entries: [] });

    await api.listSecrets();

    expect(seen[0].headers['Authorization']).toBe(`Bearer ${KEY}`);
    expect(seen[0].headers['X-Api-Key-Hmac']).toBeTruthy();
    expect(seen[0].headers['X-Broker-Signature']).toBeTruthy();
  });

  it('signs the path in the form it is actually sent, not the form it was written', async () => {
    // The server verifies against the RAW path it received. `new URL()` applies the same
    // encoding fetch will, so an id needing encoding is signed encoded. Nothing in use
    // today needs it, which is exactly why this would have broken silently the first
    // time something did.
    const { privateKeyPem, publicKey } = keypair();
    const api = new AgentVaultAPI(KEY, ENC, 'https://wundervault.com',
                                  new BrokerSigner(privateKeyPem));
    const seen = stubFetch({ name: 'X', encrypted_content: 'c', content_nonce: 'n' });

    await api.getSecret('a b', 'deploy');

    // What the server will see is the ENCODED path: fetch normalises the URL on the way
    // out, and `new URL()` here applies the same rules. The signature must match that,
    // and must NOT match the string the code was written with.
    const encoded = new URL(seen[0].url);
    expect(encoded.pathname).toContain('%20');
    expect(verifyAsServerWould(seen[0], publicKey)).toBe(true);

    const asWritten = canonicalString(
      'GET', decodeURIComponent(encoded.pathname), encoded.search.replace(/^\?/, ''),
      seen[0].headers['X-Broker-Timestamp'], seen[0].headers['X-Broker-Nonce'],
      sha256Hex(undefined));
    expect(crypto.verify('sha256', asWritten, publicKey,
                         Buffer.from(seen[0].headers['X-Broker-Signature'], 'base64')))
      .toBe(false);
  });

  it('uses a fresh nonce for every request, so the server can refuse a replay', async () => {
    const { privateKeyPem } = keypair();
    const api = new AgentVaultAPI(KEY, ENC, 'https://wundervault.com',
                                  new BrokerSigner(privateKeyPem));
    const seen = stubFetch({ entries: [] });

    await api.listSecrets();
    await api.listSecrets();

    expect(seen[0].headers['X-Broker-Nonce'])
      .not.toBe(seen[1].headers['X-Broker-Nonce']);
  });

  it('sends nothing extra when there is no signer, which is the pre-split shape', async () => {
    const api = new AgentVaultAPI(KEY, ENC, 'https://wundervault.com', null);
    const seen = stubFetch({ entries: [] });

    await api.listSecrets();

    expect(seen[0].headers['X-Broker-Signature']).toBeUndefined();
    expect(seen[0].headers['Authorization']).toBe(`Bearer ${KEY}`);
  });
});

describe('the signature covers what it claims to cover', () => {
  it('does not verify against a different path', () => {
    const { privateKeyPem, publicKey } = keypair();
    const signed = new BrokerSigner(privateKeyPem).sign('GET', '/agent/profile', '');
    const wrong = canonicalString(
      'GET', '/agent/vault/secrets', '',
      signed['X-Broker-Timestamp'], signed['X-Broker-Nonce'], sha256Hex(''));
    expect(crypto.verify('sha256', wrong, publicKey,
                         Buffer.from(signed['X-Broker-Signature'], 'base64'))).toBe(false);
  });

  it('does not verify against a different body', () => {
    const { privateKeyPem, publicKey } = keypair();
    const signed = new BrokerSigner(privateKeyPem)
      .sign('POST', '/agent/vault/operation-check', '', '{"purpose":"deploy"}');
    const wrong = canonicalString(
      'POST', '/agent/vault/operation-check', '',
      signed['X-Broker-Timestamp'], signed['X-Broker-Nonce'],
      sha256Hex('{"purpose":"something else"}'));
    expect(crypto.verify('sha256', wrong, publicKey,
                         Buffer.from(signed['X-Broker-Signature'], 'base64'))).toBe(false);
  });

  it('begins every signed message with the version line, so the two uses of the key '
     + 'cannot be confused for one another', () => {
    const message = canonicalString('GET', '/agent/profile', '', '1', 'n', 'h');
    expect(message.toString('utf8').startsWith('wv-broker-req-v1\n')).toBe(true);
  });
});

describe('where the private key may be read', () => {
  it('returns no signer on a machine with no broker identity', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-nosign-'));
    const previous = process.env.WUNDERVAULT_BROKER_KEY;
    process.env.WUNDERVAULT_BROKER_KEY = path.join(dir, 'absent.pem');
    try {
      expect(signerFromIdentity()).toBeNull();
    } finally {
      if (previous === undefined) delete process.env.WUNDERVAULT_BROKER_KEY;
      else process.env.WUNDERVAULT_BROKER_KEY = previous;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses loudly when the key exists but cannot be trusted', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-badkey-'));
    const keyPath = path.join(dir, 'broker-key.pem');
    fs.writeFileSync(keyPath, keypair().privateKeyPem, { mode: 0o644 });
    fs.chmodSync(keyPath, 0o644);
    const previous = process.env.WUNDERVAULT_BROKER_KEY;
    process.env.WUNDERVAULT_BROKER_KEY = keyPath;
    try {
      // A key readable beyond its owner must not degrade to "unsigned is fine" — that
      // would turn a broken boundary into a silent downgrade.
      expect(() => signerFromIdentity()).toThrow(/cannot be used/);
    } finally {
      if (previous === undefined) delete process.env.WUNDERVAULT_BROKER_KEY;
      else process.env.WUNDERVAULT_BROKER_KEY = previous;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('is imported only by the broker path, never by the MCP server', () => {
    // Grep rather than trust. The private key opens every credential on the machine, and
    // the property being defended is about which PROCESS can read it — something no unit
    // test of a function can observe.
    const src = path.join(__dirname, '..', 'src');
    const offenders: string[] = [];
    for (const file of fs.readdirSync(src)) {
      if (!file.endsWith('.ts')) continue;
      if (['broker-sign.ts', 'broker-ops.ts', 'broker-key.ts', 'pair.ts',
           'agent.ts', 'api-client.ts'].includes(file)) continue;
      const text = fs.readFileSync(path.join(src, file), 'utf8');
      if (text.includes('broker-sign') || text.includes('broker-key')) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });
});
