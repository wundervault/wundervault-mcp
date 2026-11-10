import { describe, it, expect } from 'vitest';
import { BrokerOps } from '../src/broker-ops.js';

/** Whole-build review r2 F3: an early end that fails once is tried again, and stops at the certificate's end. */
describe('early server-side end is retried', () => {
  const ENC = Buffer.alloc(32, 7).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  function withSession(ops: BrokerOps, endRemote: () => Promise<number>, untilMs: number) {
    (ops as unknown as { ssh: Map<string, unknown> }).ssh.set('s1', {
      handle: { signCount: () => 0, close() {} }, timer: setTimeout(() => {}, 0), entryId: 'e', key: 'k', host: 'h',
      reason: 'r', tier: '2', adminUntil: new Date(untilMs).toISOString(), endRemote,
    });
  }
  it('fails twice, then succeeds', async () => {
    const saved = BrokerOps.END_RETRY_MS;
    BrokerOps.END_RETRY_MS = [20, 20, 20];
    try {
      const ops = new BrokerOps('T', 'k', ENC, 'http://127.0.0.1:1', null);
      let calls = 0;
      withSession(ops, async () => (++calls < 3 ? 255 : 0), Date.now() + 60_000);
      ops.closeSsh('s1', 'admin_access_ended');
      await new Promise((r) => setTimeout(r, 300));
      expect(calls).toBe(3);
    } finally { BrokerOps.END_RETRY_MS = saved; }
  });
  it('a thrown attempt counts as a failure and stops before the certificate ends', async () => {
    const saved = BrokerOps.END_RETRY_MS;
    BrokerOps.END_RETRY_MS = [5_000];   // the next try would land after the certificate's end
    try {
      const ops = new BrokerOps('T', 'k', ENC, 'http://127.0.0.1:1', null);
      let calls = 0;
      withSession(ops, async () => { calls++; throw new Error('refused'); }, Date.now() + 2_100);
      ops.closeSsh('s1', 'done');
      await new Promise((r) => setTimeout(r, 400));
      expect(calls).toBe(1);   // given up: the server's own timer ends it at the certificate's end
    } finally { BrokerOps.END_RETRY_MS = saved; }
  });
  it('a normal close (no reason) does not touch the server', async () => {
    const ops = new BrokerOps('T', 'k', ENC, 'http://127.0.0.1:1', null);
    let calls = 0;
    withSession(ops, async () => { calls++; return 0; }, Date.now() + 60_000);
    ops.closeSsh('s1');
    await new Promise((r) => setTimeout(r, 50));
    expect(calls).toBe(0);
  });
});
