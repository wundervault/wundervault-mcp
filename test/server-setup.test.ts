import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { validateServerOrder, runSetup, parseReport, sealForOwner, resultAad, type ServerRunner } from '../src/server-setup.js';
import { openServerOrder, openOrder, pollOnce, type BrokerUpdateDeps } from '../src/broker-update.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const FP = 'SHA256:broker-a';
const PUB = (n: number) => `ssh-ed25519 ${Buffer.concat([Buffer.from('AAAAC3NzaC1lZDI1NTE5AAAAI', 'utf8')]).toString()}${String.fromCharCode(65 + n).repeat(43)}`;
const KEY = Buffer.alloc(32, 5);

function setup(over: Record<string, unknown> = {}) {
  const now = Date.now();
  return {
    v: 1, type: 'setup', broker: FP, order_id: 'order-0123456789', issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 15 * 60_000).toISOString(), entry_id: 'entry-admin-1', destination: 'opc@203.0.113.7',
    everyday_user: 'wv-agent', everyday_entry_id: 'entry-daily-1', everyday_pub: PUB(1), emergency_pub: PUB(2), logs: true,
    ...over,
  } as Record<string, unknown>;
}

function seal(value: unknown, fp = FP) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, nonce);
  c.setAAD(Buffer.from(`wv-broker-order-v1|${fp}`));
  const ct = Buffer.concat([c.update(JSON.stringify(value)), c.final(), c.getAuthTag()]);
  return { ciphertext: ct.toString('base64'), nonce: nonce.toString('base64') };
}

describe('setup orders are checked before anything runs (check 24)', () => {
  it('accepts a well-formed setup order', () => {
    expect(PUB(1)).toMatch(/^ssh-ed25519 [A-Za-z0-9+/]{68}$/);
    const r = validateServerOrder(setup(), FP, Date.now());
    expect(r.ok).toBe(true);
  });
  it.each([
    ['another broker', { broker: 'SHA256:other' }, 'wrong broker'],
    ['an extra field', { extra: 1 }, 'malformed'],
    ['a name with shell in it', { everyday_user: 'a;rm -rf /' }, 'malformed'],
    ['the admin account as everyday', { everyday_user: 'opc' }, 'malformed'],
    ['a key with a comment', { everyday_pub: PUB(1) + ' x' }, 'malformed'],
    ['the same key twice', { emergency_pub: PUB(1) }, 'malformed'],
    ['a destination with options', { destination: '-oProxyCommand=x@h' }, 'bad destination'],
    ['logs as text', { logs: 'yes' }, 'malformed'],
    ['expired', { expires_at: new Date(Date.now() - 1000).toISOString(), issued_at: new Date(Date.now() - 60_000).toISOString() }, 'expired'],
    ['too long', { expires_at: new Date(Date.now() + 31 * 60_000).toISOString() }, 'malformed'],
  ])('refuses %s', (_n, over, reason) => {
    const r = validateServerOrder(setup(over as Record<string, unknown>), FP, Date.now());
    expect(r).toEqual({ ok: false, reason });
  });
  it('a setup order sealed for broker A does not open on broker B, and kinds must match', () => {
    const s = seal(setup());
    expect(openServerOrder(s.ciphertext, s.nonce, KEY, 'SHA256:other', Date.now(), 'setup')).toEqual({ ok: false, reason: 'bad seal' });
    expect(openServerOrder(s.ciphertext, s.nonce, KEY, FP, Date.now(), 'accept')).toEqual({ ok: false, reason: 'kind mismatch' });
    expect(openServerOrder(s.ciphertext, s.nonce, KEY, FP, Date.now(), 'setup').ok).toBe(true);
    // ...and an update reader never takes it for an update.
    expect(openOrder(s.ciphertext, s.nonce, KEY, FP, Date.now(), '2.4.0')).toEqual({ ok: false, reason: 'malformed' });
  });
});

function fakeRunner(script: (call: { argv: string[]; offer?: string; entryId: string; input?: string }) => { exitCode: number; stdout: string } ) {
  const calls: { argv: string[]; offer?: string; entryId: string; destination: string; input?: string }[] = [];
  const ops: ServerRunner = {
    async serverRun(a) {
      const argv = a.argv(PUB(9));
      const call = { argv, offer: a.offer, entryId: a.entryId, destination: a.destination, input: a.input };
      calls.push(call);
      const r = script(call);
      return { ...r, stderr: '' };
    },
  };
  return { ops, calls };
}

describe('setup runs in the order that cannot lock the owner out (check 25)', () => {
  const order = validateServerOrder(setup(), FP, Date.now());
  if (!order.ok || order.order.type !== 'setup') throw new Error('fixture');
  const o = order.order;

  it('all steps, in order, with the fixed script on stdin', async () => {
    const { ops, calls } = fakeRunner((c) => {
      if (c.argv[0] === 'echo') return { exitCode: 0, stdout: 'wv-cert-ok\n' };
      if (c.offer === 'plain') return { exitCode: 255, stdout: '' };
      if (c.argv[0] === 'sh' && c.argv[1] === '-c') return { exitCode: 0, stdout: 'PASS everyday key signs in\nPASS x\n' };
      return { exitCode: 0, stdout: 'PASS step\n' };
    });
    const r = await runSetup(ops, o, 'SCRIPT');
    expect(r.ok).toBe(true);
    const steps = calls.map((c) => ['prepare', 'finalize', 'status'].includes(c.argv[5] ?? '') ? c.argv[5] : c.argv[0]);
    expect(steps).toEqual(['prepare', 'echo', 'finalize', 'status', 'true', 'sh']);
    expect(calls[0]!.argv).toEqual(['sudo', '-n', 'sh', '-s', '--', 'prepare', 'opc', 'wv-agent', PUB(9), PUB(1), PUB(2), 'logs']);
    expect(calls[0]!.input).toBe('SCRIPT');
    expect(calls[1]!.offer).toBe('cert');
    expect(calls[2]!.argv.slice(5)).toEqual(['finalize', 'opc', PUB(9)]);
    expect(calls[4]!.offer).toBe('plain');
    expect(calls[5]!.entryId).toBe('entry-daily-1');
    expect(calls[5]!.destination).toBe('wv-agent@203.0.113.7');
  });

  it('a failed certificate sign-in stops before finalize', async () => {
    const { ops, calls } = fakeRunner((c) => c.argv[0] === 'echo' ? { exitCode: 255, stdout: '' } : { exitCode: 0, stdout: 'PASS prepared\n' });
    const r = await runSetup(ops, o, 'SCRIPT');
    expect(r.ok).toBe(false);
    expect(calls.map((c) => c.argv[0] === 'sudo' ? c.argv[5] : c.argv[0])).toEqual(['prepare', 'echo']);
    expect(r.lines.join('\n')).toMatch(/nothing was removed/);
  });

  it('a failed prepare stops at once', async () => {
    const { ops, calls } = fakeRunner(() => ({ exitCode: 2, stdout: 'FAIL wv-agent is in group docker; remove it and run setup again\n' }));
    const r = await runSetup(ops, o, 'SCRIPT');
    expect(r.ok).toBe(false);
    expect(calls).toHaveLength(1);
    expect(r.lines[0]).toMatch(/group docker/);
  });

  it('root needs no sudo', async () => {
    const root = validateServerOrder(setup({ destination: 'root@203.0.113.7:2222' }), FP, Date.now());
    if (!root.ok || root.order.type !== 'setup') throw new Error('fixture');
    const { ops, calls } = fakeRunner((c) => c.argv[0] === 'echo' ? { exitCode: 0, stdout: 'wv-cert-ok' } : c.offer === 'plain' ? { exitCode: 255, stdout: '' } : { exitCode: 0, stdout: 'PASS a\n' });
    await runSetup(ops, root.order, 'S');
    expect(calls[0]!.argv.slice(0, 2)).toEqual(['sh', '-s']);
    expect(calls[5]!.destination).toBe('wv-agent@203.0.113.7:2222');
  });
});

describe('change check report', () => {
  it('needs END; NEW and GONE lines only', () => {
    expect(parseReport('NEW\tkey\topc\tabc\tx\n')).toBeNull();
    expect(parseReport('END\n')).toEqual([]);
    expect(parseReport('NEW\tkey\topc\t0123456789abcdef\tsneaky\nGONE\tgroup\tsudo\tbob\nEND\n')).toHaveLength(2);
  });
  it('sealed results open with the agent key and the right AAD only', () => {
    const s = sealForOwner(KEY, resultAad(FP, 'o1'), { lines: ['PASS a'] });
    const raw = Buffer.from(s.ciphertext, 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(s.nonce, 'base64'));
    d.setAAD(Buffer.from(resultAad(FP, 'o1')));
    d.setAuthTag(raw.subarray(-16));
    expect(JSON.parse(Buffer.concat([d.update(raw.subarray(0, -16)), d.final()]).toString())).toEqual({ lines: ['PASS a'] });
    const e = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(s.nonce, 'base64'));
    e.setAAD(Buffer.from(resultAad(FP, 'o2')));
    e.setAuthTag(raw.subarray(-16));
    e.update(raw.subarray(0, -16));
    expect(() => e.final()).toThrow();
  });
});

describe('poll hands setup orders over once', () => {
  it('received + handed over; replay and kind mismatch refused', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-so-'));
    const posted: [string, string, string][] = [];
    const handed: string[] = [];
    const s = seal(setup());
    const bad = seal(setup({ order_id: 'order-other-12345' }));
    let orders = [
      { id: 'order-0123456789', agent_id: 'a1', kind: 'setup', ...s },
      { id: 'order-other-12345', agent_id: 'a1', kind: 'accept', ...bad },
    ];
    const d: BrokerUpdateDeps = {
      fingerprint: FP, version: '2.4.0',
      client: { getOrders: async () => ({ orders }), postState: async (id, st, det) => { posted.push([id, st, det]); } },
      vaultKeyFor: async () => KEY, seenPath: path.join(dir, 'seen.json'),
      requestPath: path.join(dir, 'nope', 'request.json'), statusPath: path.join(dir, 'nope', 'status.json'),
      now: () => Date.now(), log: () => {},
      serverOrder: (_a, o) => { handed.push(o.order_id); },
    };
    await pollOnce(d);
    expect(handed).toEqual(['order-0123456789']);
    expect(posted).toContainEqual(['order-0123456789', 'received', '']);
    expect(posted).toContainEqual(['order-other-12345', 'refused', 'kind mismatch']);
    await pollOnce(d);
    expect(handed).toEqual(['order-0123456789']);
    orders = [{ id: 'order-x-123456789', agent_id: 'a1', kind: 'setup', ...seal(setup({ order_id: 'order-x-123456789' })) }];
    const noRunner = { ...d, serverOrder: undefined };
    await pollOnce(noRunner);
    expect(posted).toContainEqual(['order-x-123456789', 'refused', 'not supported']);
  });
});
