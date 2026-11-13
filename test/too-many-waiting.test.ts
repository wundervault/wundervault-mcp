import { describe, it, expect, vi, afterEach } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { AgentVaultAPI } from '../src/api-client.js';
import { BrokerSigner } from '../src/broker-sign.js';

// Owner 2026-11-13: the site refuses an 11th waiting approval request from one agent. The agent is told the
// server's plain sentence, not a raw "HTTP 429: {json}".
afterEach(() => { vi.unstubAllGlobals(); });

function api() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return new AgentVaultAPI('wv_agent_test|secret', new Uint8Array(32).fill(7) as any, 'https://wundervault.com',
    new BrokerSigner(privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()));
}

function refuse(status: number, body: unknown) {
  vi.stubGlobal('fetch', async () => ({ ok: false, status, json: async () => body, text: async () => JSON.stringify(body) }));
}

describe('too many approval requests waiting', () => {
  it('says the server\'s sentence, with a code', async () => {
    const msg = '10 requests from this agent are already waiting for the owner. Wait for the owner to answer them.';
    refuse(429, { detail: { error: 'too_many_waiting', message: msg } });
    const e: any = await api().checkOperation({ entry_id: 'e1', purpose: 'x' }).catch((x) => x);
    expect(e.message).toBe(`Refused: ${msg}`);
    expect(e.code).toBe('TOO_MANY_WAITING');
    expect(e.status).toBe(429);
  });

  it('any other refusal keeps the full text as before', async () => {
    refuse(429, { error: 'Rate limit exceeded: 120 per 1 minute' });
    const e: any = await api().checkOperation({ entry_id: 'e1', purpose: 'x' }).catch((x) => x);
    expect(e.message).toMatch(/^HTTP 429: /);
    expect(e.code).toBeUndefined();
  });
});
