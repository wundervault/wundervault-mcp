/**
 * A wait that expires is the only evidence this system ever gets that nobody was there.
 *
 * Every other channel is written blind. stderr and the tool result are sent and then
 * hoped about; the first approval email is sent and then hoped about. None of them can
 * distinguish "the owner read it and is thinking" from "the terminal has been empty since
 * Tuesday". An approval that never arrives inside the agent's entire patience is the one
 * observation that separates those, and it costs nothing to collect.
 *
 * So the rule these tests defend is narrow: report ONLY the expiry. A denial means a
 * human looked. An explicit expired status means the request was already dead. Mailing
 * about either would make the second notice routine, and a routine alert is one that
 * stops being read — which is the entire failure mode for a channel whose only job is to
 * work when nobody is watching.
 *
 * The client is exercised against a stubbed fetch rather than a mocked AgentVaultAPI:
 * what is being claimed is which HTTP calls happen and in what order, and a mock of the
 * class under test would only agree with itself.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { AgentVaultAPI } from '../src/api-client.js';

const KEY = 'wv_test_key';
const ENC = new Uint8Array(32).fill(7);

type Call = { url: string; method: string };

/**
 * Stub fetch with a scripted tier-2 status sequence.
 *
 * Returns the calls it saw so a test can assert on the POST that matters, and puts the
 * loop on a virtual clock — otherwise a test of the 90-second deadline takes 90 seconds.
 */
function stubPolling(statuses: string[]): Call[] {
  const calls: Call[] = [];
  let i = 0;
  vi.stubGlobal('fetch', async (url: string, init?: { method?: string }) => {
    const method = init?.method ?? 'GET';
    calls.push({ url: String(url), method });
    if (String(url).endsWith('/unanswered')) {
      return new Response(JSON.stringify({ request_id: 'r1', escalated: true, status: 'pending' }),
        { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const status = statuses[Math.min(i++, statuses.length - 1)];
    return new Response(JSON.stringify({ status }),
      { status: 200, headers: { 'content-type': 'application/json' } });
  });
  virtualClock();
  return calls;
}

/**
 * Run the poll loop on a virtual clock.
 *
 * Collapsing setTimeout alone is not enough and fails in the worst way: the loop's exit
 * condition is Date.now() against a deadline, so a setTimeout that fires instantly
 * without advancing the clock spins at microtask speed and never terminates. The first
 * version of this file did exactly that and hung the runner. Advancing a fake `now` by
 * the delay each timer asks for keeps the real logic — same deadline, same interval,
 * same number of polls — and reaches ninety seconds in milliseconds.
 */
function virtualClock(): void {
  let now = Date.now();
  vi.spyOn(Date, 'now').mockImplementation(() => now);
  vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
    now += ms ?? 0;
    queueMicrotask(fn);
    return 0 as unknown as NodeJS.Timeout;
  }) as unknown as typeof setTimeout);
}

function api(): AgentVaultAPI {
  return new AgentVaultAPI(KEY, ENC, 'https://wundervault.test');
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('reporting an unanswered approval', () => {
  it('reports the expiry once the deadline passes', async () => {
    // Always pending: the owner never answered, which is the 3am case.
    const calls = stubPolling(['pending']);
    const ok = await api().waitForTier2Approval('r1');
    expect(ok).toBe(false);
    const posts = calls.filter(c => c.url.endsWith('/unanswered'));
    expect(posts).toHaveLength(1);
    expect(posts[0].method).toBe('POST');
  });

  it('does not report when the owner approved', async () => {
    const calls = stubPolling(['pending', 'approved']);
    const ok = await api().waitForTier2Approval('r1');
    expect(ok).toBe(true);
    expect(calls.some(c => c.url.endsWith('/unanswered'))).toBe(false);
  });

  it('does not report when the owner denied', async () => {
    // Somebody looked and said no. That is an answer, and mailing about it would teach
    // the reader that the second notice means nothing in particular.
    const calls = stubPolling(['denied']);
    const ok = await api().waitForTier2Approval('r1');
    expect(ok).toBe(false);
    expect(calls.some(c => c.url.endsWith('/unanswered'))).toBe(false);
  });

  it('does not report when the request had already expired server-side', async () => {
    const calls = stubPolling(['expired']);
    expect(await api().waitForTier2Approval('r1')).toBe(false);
    expect(calls.some(c => c.url.endsWith('/unanswered'))).toBe(false);
  });

  it('reports exactly once even though the poll ran many times', async () => {
    const calls = stubPolling(['pending']);
    await api().waitForTier2Approval('r1');
    expect(calls.filter(c => c.url.endsWith('/unanswered'))).toHaveLength(1);
    // And it polled more than once, or the test above proves nothing about "once".
    expect(calls.filter(c => c.method === 'GET').length).toBeGreaterThan(1);
  });

  it('carries the agent credentials, so only the owning agent can report', async () => {
    const seen: Record<string, string>[] = [];
    vi.stubGlobal('fetch', async (url: string, init?: { headers?: Record<string, string> }) => {
      seen.push(init?.headers ?? {});
      if (String(url).endsWith('/unanswered')) return new Response('{}', { status: 200 });
      return new Response(JSON.stringify({ status: 'pending' }),
        { status: 200, headers: { 'content-type': 'application/json' } });
    });
    virtualClock();
    await api().waitForTier2Approval('r1');
    expect(seen.at(-1)?.['Authorization']).toBe(`Bearer ${KEY}`);
  });

  it('swallows a failed report rather than changing the error the caller reports', async () => {
    // This runs at the end of a call that has already failed. Turning a broken
    // notification into a thrown error would replace an accurate message ("approval never
    // came") with a misleading one ("could not reach Wundervault").
    vi.stubGlobal('fetch', async (url: string) => {
      if (String(url).endsWith('/unanswered')) throw new Error('network down');
      return new Response(JSON.stringify({ status: 'pending' }),
        { status: 200, headers: { 'content-type': 'application/json' } });
    });
    virtualClock();
    await expect(api().waitForTier2Approval('r1')).resolves.toBe(false);
  });

  it('keeps waiting through a transient poll failure', async () => {
    // A blip must not read as "nobody answered" — that would mail the owner about an
    // approval they were about to give.
    let n = 0;
    vi.stubGlobal('fetch', async (url: string) => {
      if (String(url).endsWith('/unanswered')) {
        return new Response('{}', { status: 200 });
      }
      if (n++ < 2) return new Response('boom', { status: 500 });
      return new Response(JSON.stringify({ status: 'approved' }),
        { status: 200, headers: { 'content-type': 'application/json' } });
    });
    virtualClock();
    expect(await api().waitForTier2Approval('r1')).toBe(true);
  });
});
