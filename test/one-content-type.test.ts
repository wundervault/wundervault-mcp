/**
 * Every request carries ONE content-type (burnbox/SPEC-1.0-key-page-2026-10-20.md, part H).
 *
 * Found in the 1.0 rehearsal on a copy of production: `headers()` set `Content-Type` and the
 * two POST paths added `content-type` again, so Node's fetch sent
 * `content-type: application/json, application/json`. FastAPI does not treat that as JSON and
 * answered 422 to every operation check and activity anchor, so `vault_call`, `vault_pay` and
 * `vault_sign` all failed against the real server.
 *
 * The other tests stub `fetch` and read `init.headers` back as a plain object, where the two
 * spellings sit side by side as separate keys and nothing joins them. That is why they agreed
 * with the bug. These tests use the real `fetch` against a real socket and read the header
 * lines exactly as they arrived.
 */
import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it, expect, afterEach } from 'vitest';

import { AgentVaultAPI } from '../src/api-client.js';
import { BrokerSigner } from '../src/broker-sign.js';

const KEY = 'wv_agent_test|secret';
const ENC = new Uint8Array(32).fill(7);

type Arrival = { method: string; url: string; contentTypes: string[] };

let server: http.Server | null = null;
afterEach(async () => {
  if (server) await new Promise<void>((r) => server!.close(() => r()));
  server = null;
});

/** A server that records each request's content-type header LINES and answers `reply`. */
async function recorder(reply: unknown): Promise<{ base: string; seen: Arrival[] }> {
  const seen: Arrival[] = [];
  server = http.createServer((req, res) => {
    const contentTypes: string[] = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (req.rawHeaders[i].toLowerCase() === 'content-type') contentTypes.push(req.rawHeaders[i + 1]);
    }
    seen.push({ method: req.method ?? '', url: req.url ?? '', contentTypes });
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(reply));
    });
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as AddressInfo;
  return { base: `http://127.0.0.1:${port}`, seen };
}

function signer(): BrokerSigner {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return new BrokerSigner(privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
}

describe('one content-type on the wire', () => {
  for (const signed of [true, false]) {
    const label = signed ? 'signed (a paired broker)' : 'unsigned';

    it(`checkOperation sends exactly one content-type, application/json — ${label}`, async () => {
      const { base, seen } = await recorder({ allowed: true, tier: '1' });
      const api = new AgentVaultAPI(KEY, ENC, base, signed ? signer() : null);

      await api.checkOperation({ entry_id: 'e1', purpose: '', first_sighting: true });

      expect(seen).toHaveLength(1);
      expect(seen[0].method).toBe('POST');
      expect(seen[0].url).toBe('/agent/vault/operation-check');
      expect(seen[0].contentTypes).toEqual(['application/json']);
    });

    it(`a postJson caller (the activity anchor) sends exactly one content-type — ${label}`, async () => {
      const { base, seen } = await recorder({ seq: 1, head: 'h', updated_at: null });
      const api = new AgentVaultAPI(KEY, ENC, base, signed ? signer() : null);

      await api.postActivityAnchor({ from_seq: 0, digests: ['d'] });

      expect(seen).toHaveLength(1);
      expect(seen[0].method).toBe('POST');
      expect(seen[0].contentTypes).toEqual(['application/json']);
    });
  }

  it('a GET carries at most one content-type', async () => {
    const { base, seen } = await recorder({ seq: null, head: null, updated_at: null });
    const api = new AgentVaultAPI(KEY, ENC, base, signer());

    await api.getActivityAnchor();

    expect(seen).toHaveLength(1);
    expect(seen[0].contentTypes.length).toBeLessThanOrEqual(1);
  });
});
