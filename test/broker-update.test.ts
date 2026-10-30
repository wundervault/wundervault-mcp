import { createCipheriv, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  openOrder, pollOnce, startPolling,
  type BrokerUpdateDeps, type OrderClient,
} from '../src/broker-update.js';

const now = Date.parse('2026-10-30T12:00:00.000Z');
const key = randomBytes(32);

function plaintext(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    type: 'update',
    broker: 'broker-a',
    version: '2.2.0',
    order_id: 'sealed-id',
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 10 * 60_000).toISOString(),
    ...overrides,
  };
}

function seal(value = plaintext(), aad = 'broker-a'): { ciphertext: string; nonce: string } {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(`wv-broker-order-v1|${aad}`));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value)), cipher.final(), cipher.getAuthTag(),
  ]);
  return { ciphertext: ciphertext.toString('base64'), nonce: nonce.toString('base64') };
}

describe('openOrder', () => {
  function open(value: Record<string, unknown>, aad = 'broker-a') {
    const sealed = seal(value, aad);
    return openOrder(sealed.ciphertext, sealed.nonce, key, 'broker-a', now, '2.1.0');
  }

  it('opens the WebCrypto ciphertext and tag layout', () => {
    expect(open(plaintext())).toEqual({
      ok: true, order: { version: '2.2.0', order_id: 'sealed-id' },
    });
  });

  it.each([
    ['wrong broker', { broker: 'broker-b' }, 'wrong broker'],
    ['expired', {
      issued_at: new Date(now - 10 * 60_000).toISOString(),
      expires_at: new Date(now - 3 * 60_000).toISOString(),
    }, 'expired'],
    ['too-long life', { expires_at: new Date(now + 16 * 60_000).toISOString() }, 'malformed'],
    ['future issue', {
      issued_at: new Date(now + 3 * 60_000).toISOString(),
      expires_at: new Date(now + 10 * 60_000).toISOString(),
    }, 'expired'],
    ['equal version', { version: '2.1.0' }, 'not newer'],
    ['older version', { version: '2.0.99' }, 'not newer'],
    ['extra key', { extra: true }, 'malformed'],
    ['invalid version', { version: '02.2.0' }, 'malformed'],
    ['invalid date', { issued_at: '2026-02-30T12:00:00Z' }, 'malformed'],
    ['negative life', { expires_at: new Date(now - 1).toISOString() }, 'malformed'],
  ])('rejects %s', (_name, overrides, reason) => {
    expect(open(plaintext(overrides))).toEqual({ ok: false, reason });
  });

  it('compares version components numerically', () => {
    expect(open(plaintext({ version: '2.10.0' })).ok).toBe(true);
  });

  it('rejects a changed ciphertext byte', () => {
    const sealed = seal();
    const bytes = Buffer.from(sealed.ciphertext, 'base64');
    bytes[0] = bytes[0]! ^ 1;
    expect(openOrder(bytes.toString('base64'), sealed.nonce, key, 'broker-a', now, '2.1.0'))
      .toEqual({ ok: false, reason: 'bad seal' });
  });

  it('rejects the wrong AAD', () => {
    expect(open(plaintext(), 'broker-b')).toEqual({ ok: false, reason: 'bad seal' });
  });

  it('rejects invalid base64 and nonce lengths', () => {
    expect(openOrder('???', '', key, 'broker-a', now, '2.1.0'))
      .toEqual({ ok: false, reason: 'bad seal' });
    expect(openOrder(seal().ciphertext, randomBytes(8).toString('base64'), key, 'broker-a', now, '2.1.0'))
      .toEqual({ ok: false, reason: 'bad seal' });
  });
});

describe('broker update polling', () => {
  let directory: string;
  let d: BrokerUpdateDeps;
  let orders: Awaited<ReturnType<OrderClient['getOrders']>>['orders'];
  let postState: ReturnType<typeof vi.fn<OrderClient['postState']>>;
  let getOrders: ReturnType<typeof vi.fn<OrderClient['getOrders']>>;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'wv-broker-update-'));
    orders = [{ id: 'server-id', agent_id: 'agent-a', ...seal() }];
    postState = vi.fn<OrderClient['postState']>().mockResolvedValue(undefined);
    getOrders = vi.fn<OrderClient['getOrders']>().mockImplementation(async () => ({ orders }));
    d = {
      fingerprint: 'broker-a',
      version: '2.1.0',
      client: { getOrders, postState },
      vaultKeyFor: async agent => agent === 'agent-a' ? key : null,
      seenPath: join(directory, 'seen.json'),
      requestPath: join(directory, 'request.json'),
      statusPath: join(directory, 'status.json'),
      now: () => now,
      log: vi.fn(),
    };
    await writeFile(d.requestPath, 'old contents');
  });

  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    await rm(directory, { recursive: true, force: true });
  });

  it('writes exactly the request and reports receipt', async () => {
    await pollOnce(d);
    expect(getOrders).toHaveBeenCalledWith('2.1.0');
    expect(await readFile(d.requestPath, 'utf8'))
      .toBe('{"version":"2.2.0","order_id":"sealed-id"}');
    expect(postState).toHaveBeenCalledWith('server-id', 'received', '');
    expect(JSON.parse(await readFile(d.seenPath, 'utf8'))).toEqual(['server-id', 'sealed-id']);
  });

  it('refuses an order sealed for another broker without touching the spool', async () => {
    orders = [{ id: 'other', agent_id: 'agent-a', ...seal(plaintext({ broker: 'broker-b' })) }];
    await pollOnce(d);
    expect(postState).toHaveBeenCalledWith('other', 'refused', 'wrong broker');
    expect(await readFile(d.requestPath, 'utf8')).toBe('old contents');
  });

  it('refuses an unknown agent and persists the refusal', async () => {
    orders[0]!.agent_id = 'unknown';
    await pollOnce(d);
    await pollOnce(d);
    expect(postState).toHaveBeenCalledTimes(1);
    expect(postState).toHaveBeenCalledWith('server-id', 'refused', 'no key');
    expect(JSON.parse(await readFile(d.seenPath, 'utf8'))).toEqual(['server-id']);
  });

  it('rejects a replay under a new server id, including after restart', async () => {
    await pollOnce(d);
    orders = [{ id: 'new-server-id', agent_id: 'agent-a', ...seal() }];
    await pollOnce({ ...d });
    expect(postState).toHaveBeenLastCalledWith('new-server-id', 'refused', 'replay');
  });

  it('does not create a missing spool', async () => {
    await unlink(d.requestPath);
    await pollOnce(d);
    expect(postState).toHaveBeenCalledWith('server-id', 'failed', 'no spool');
    await expect(readFile(d.requestPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it.skipIf(process.platform === 'win32')('does not follow a spool symlink', async () => {
    const target = join(directory, 'target');
    await writeFile(target, 'sentinel');
    await unlink(d.requestPath);
    await symlink(target, d.requestPath);
    await pollOnce(d);
    expect(postState).toHaveBeenCalledWith('server-id', 'failed', 'no spool');
    expect(await readFile(target, 'utf8')).toBe('sentinel');
  });

  it('caps the persisted seen list at 100', async () => {
    orders = Array.from({ length: 105 }, (_, i) => ({
      id: `server-${i}`, agent_id: 'unknown', ...seal(),
    }));
    await pollOnce(d);
    const seen = JSON.parse(await readFile(d.seenPath, 'utf8')) as string[];
    expect(seen).toHaveLength(100);
    expect(seen[0]).toBe('server-5');
    expect(seen[99]).toBe('server-104');
    orders = [orders[104]!];
    postState.mockClear();
    await pollOnce({ ...d });
    expect(postState).not.toHaveBeenCalled();
  });

  it('relays status once per change with the server id and bounded detail', async () => {
    await pollOnce(d);
    postState.mockClear();
    const status = { order_id: 'sealed-id', state: 'working', detail: 'downloading' };
    await writeFile(d.statusPath, JSON.stringify(status));
    await pollOnce(d);
    await pollOnce(d);
    expect(postState).toHaveBeenCalledTimes(1);
    expect(postState).toHaveBeenCalledWith('server-id', 'working', 'downloading');
    await writeFile(d.statusPath, JSON.stringify({
      ...status, state: 'installed', detail: 'a'.repeat(250),
    }));
    await pollOnce(d);
    expect(postState).toHaveBeenLastCalledWith('server-id', 'installed', 'a'.repeat(200));
  });

  it('ignores missing, garbled, oversized, unmapped, and invalid statuses', async () => {
    await pollOnce(d);
    postState.mockClear();
    const statuses = [
      '{',
      ' '.repeat(4097),
      JSON.stringify({ order_id: 'unknown', state: 'working', detail: '' }),
      JSON.stringify({ order_id: 'sealed-id', state: 'received', detail: '' }),
      JSON.stringify({ order_id: 'sealed-id', state: 'arbitrary', detail: '' }),
      JSON.stringify({ order_id: 'sealed-id', state: 'working', detail: 123 }),
    ];
    for (const status of statuses) {
      await writeFile(d.statusPath, status);
      await pollOnce(d);
    }
    expect(postState).not.toHaveBeenCalled();
  });

  it('swallows network errors and still relays status after a failed poll', async () => {
    await pollOnce(d);
    await writeFile(d.statusPath, JSON.stringify({
      order_id: 'sealed-id', state: 'installed', detail: '',
    }));
    getOrders.mockRejectedValue(new Error('offline'));
    postState.mockRejectedValueOnce(new Error('offline'));
    await expect(pollOnce(d)).resolves.toBeUndefined();
    await expect(pollOnce(d)).resolves.toBeUndefined();
    expect(d.log).toHaveBeenCalled();
    expect(postState).toHaveBeenLastCalledWith('server-id', 'installed', '');
  });

  it('swallows receipt network failures without writing an order twice', async () => {
    postState.mockRejectedValue(new Error('offline'));
    await expect(pollOnce(d)).resolves.toBeUndefined();
    await pollOnce(d);
    expect(postState).toHaveBeenCalledTimes(1);
  });

  it('unrefs both timers, prevents overlapping polls, and stops scheduling', async () => {
    // WHY: hold the network call open so timer ticks cannot finish the first poll.
    await pollOnce(d);
    orders = [];
    getOrders.mockClear();
    let release!: (value: { orders: typeof orders }) => void;
    getOrders.mockImplementation(() => new Promise(resolve => { release = resolve; }));
    // Only the timers are fake: a poll finishes with real file reads, and those must be able to
    // complete for `running` to clear before the next tick.
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] });
    const settle = async () => { for (let i = 0; i < 20; i++) await new Promise(r => setImmediate(r)); };
    const timeoutSpy = vi.spyOn(globalThis, 'setTimeout');
    const intervalSpy = vi.spyOn(globalThis, 'setInterval');
    const polling = startPolling(d, 100, 30);
    const first = timeoutSpy.mock.results[0]!.value as ReturnType<typeof setTimeout>;
    expect(first.hasRef()).toBe(false);
    await vi.advanceTimersByTimeAsync(30);
    const interval = intervalSpy.mock.results[0]!.value as ReturnType<typeof setInterval>;
    expect(interval.hasRef()).toBe(false);
    expect(getOrders).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(500);
    expect(getOrders).toHaveBeenCalledTimes(1);
    release({ orders: [] });
    // Under a loaded machine the first poll's real file reads can take many turns to finish; keep
    // ticking until the next poll has started (or give up), rather than guessing a fixed count.
    for (let i = 0; i < 200 && getOrders.mock.calls.length < 2; i++) {
      await settle();
      await vi.advanceTimersByTimeAsync(100);
    }
    expect(getOrders).toHaveBeenCalledTimes(2);
    polling.stop();
    release({ orders: [] });
    await vi.advanceTimersByTimeAsync(1000);
    expect(getOrders).toHaveBeenCalledTimes(2);
  });

  it('can stop before the first poll', async () => {
    vi.useFakeTimers();
    const polling = startPolling(d);
    polling.stop();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(getOrders).not.toHaveBeenCalled();
  });
});
