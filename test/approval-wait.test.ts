/**
 * What an agent is told when the owner's approval does not come (2.0.1, B4).
 *
 * On cutover day a tier-2 SSH call came back as the server's raw refusal — "HTTP 403: … Poll
 * /agent/vault/tier2-requests/… or retry after approval" — ninety seconds after the owner was
 * asked, and the owner read it as the call failing at once. The agent cannot call that endpoint
 * (its credentials are the broker's), and "retry after approval" did not say the request was
 * still waiting in the vault. Every tool now ends a wait with the same plain words.
 *
 * getSecret is driven against a stubbed fetch on a virtual clock (as unanswered.test.ts does), so
 * the full ninety-second wait runs in milliseconds with the real deadline and interval.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { AgentVaultAPI, ApprovalNotGiven, approvalNotGivenMessage, APPROVAL_WAIT_MS } from '../src/api-client.js';

const KEY = 'wv_test_key';
const ENC = new Uint8Array(32).fill(7);
const GATE = JSON.stringify({ detail: 'This secret requires Tier 2 approval. The vault owner has been notified '
  + '(request r1). Poll /agent/vault/tier2-requests/r1 or retry after approval.' });

function virtualClock(): void {
  let now = Date.now();
  vi.spyOn(Date, 'now').mockImplementation(() => now);
  vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
    now += ms ?? 0;
    queueMicrotask(fn);
    return 0 as unknown as NodeJS.Timeout;
  }) as unknown as typeof setTimeout);
}

/** The fetch gate refuses once; the request's status then reads `status` for as long as asked. */
function stubGate(status: string, listOk = true): string[] {
  const seen: string[] = [];
  let fetched = 0;
  vi.stubGlobal('fetch', async (url: string, init?: { method?: string }) => {
    const u = String(url);
    seen.push(`${init?.method ?? 'GET'} ${new URL(u).pathname}`);
    const json = (code: number, body: string) => new Response(body, { status: code, headers: { 'content-type': 'application/json' } });
    if (new URL(u).pathname === '/agent/vault/secrets') {
      return listOk ? json(200, JSON.stringify({ entries: [{ id: 'e1', secret_name: 'Synology Admin', access_tier: '2' }] }))
        : json(500, '{"detail":"down"}');
    }
    if (u.includes('/agent/vault/secrets/')) {
      return fetched++ === 0 ? json(403, GATE) : json(200, JSON.stringify({ name: 'Synology Admin', entry_mode: 'BROKER_SSH_AGENT' }));
    }
    if (u.endsWith('/unanswered')) return json(200, JSON.stringify({ request_id: 'r1', escalated: true, status: 'pending' }));
    return json(200, JSON.stringify({ status }));
  });
  virtualClock();
  return seen;
}

const api = () => new AgentVaultAPI(KEY, ENC, 'https://wundervault.test');

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('the words', () => {
  it('never names a server path, and always says nothing was sent', () => {
    for (const o of ['declined', 'expired', 'unanswered'] as const) {
      const m = approvalNotGivenMessage(o, '"x"');
      expect(m).toContain('Nothing was sent.');
      expect(m).not.toMatch(/\/agent\/|HTTP|403|poll/i);
    }
  });

  it('tells an unanswered wait from a refusal', () => {
    expect(approvalNotGivenMessage('unanswered')).toBe(`Waited ${APPROVAL_WAIT_MS / 1000} seconds for the vault owner to `
      + 'approve using this secret; no answer yet. Nothing was sent. The request stays open in their vault for a '
      + 'day: when they approve it, make the same call again.');
    expect(approvalNotGivenMessage('declined')).toBe('The vault owner declined this use of this secret. Nothing was sent.');
  });
});

describe('a fetch that waits for the owner (vault_ssh_exec, vault_call)', () => {
  it('ends an unanswered wait with the plain message, not the server\'s 403', async () => {
    const seen = stubGate('pending');
    const e = await api().getSecret('e1').catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApprovalNotGiven);
    expect((e as ApprovalNotGiven).outcome).toBe('unanswered');
    expect((e as Error).message).toMatch(/^Waited 90 seconds for the vault owner to approve using "Synology Admin"; no answer yet\./);
    expect((e as Error).message).not.toMatch(/HTTP 403|tier2-requests|retry after approval/);
    // It did wait, and it reported the silence once, as before.
    expect(seen.filter(s => s.startsWith('GET /agent/vault/tier2-requests/')).length).toBeGreaterThan(10);
    expect(seen.filter(s => s.endsWith('/unanswered'))).toHaveLength(1);
  });

  it('says declined when the owner said no', async () => {
    stubGate('denied');
    const e = await api().getSecret('e1').catch((x: unknown) => x);
    expect((e as ApprovalNotGiven).outcome).toBe('declined');
    expect((e as Error).message).toBe('The vault owner declined this use of "Synology Admin". Nothing was sent.');
  });

  it('still says it plainly when the name can\'t be looked up', async () => {
    stubGate('denied', false);
    const e = await api().getSecret('e1').catch((x: unknown) => x);
    expect((e as Error).message).toBe('The vault owner declined this use of this secret. Nothing was sent.');
  });

  it('says expired when the request had died', async () => {
    stubGate('expired');
    const e = await api().getSecret('e1').catch((x: unknown) => x);
    expect((e as ApprovalNotGiven).outcome).toBe('expired');
  });

  it('still goes through when the owner approves in time', async () => {
    stubGate('approved');
    const s = await api().getSecret('e1');
    expect(s.name).toBe('Synology Admin');
  });

  it('keeps the boolean wait for its older callers', async () => {
    stubGate('denied');
    expect(await api().waitForTier2Approval('r1')).toBe(false);
  });
});
