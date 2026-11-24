import { createDecipheriv, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { newRequestId, sealProposal, validateJobProposal } from '../src/job-request.js';
import { validateJobOrder } from '../src/jobs.js';
import { canonicalDestination } from '../src/server-setup.js';

function proposal(): Record<string, unknown> {
  return {
    name: 'Nightly backup',
    entry_id: 'entry_12345678',
    destination: 'backup@example.com',
    argv: ['/usr/local/bin/backup', '--daily'],
    schedule: { kind: 'daily', time: '03:15', tz: 'UTC' },
    timeout_s: 300,
    grace_minutes: 30,
    why: 'Keep a daily backup while the owner is away.',
  };
}

function open(key: Uint8Array, requestId: string, sealed: { ciphertext: string; nonce: string }): unknown {
  const body = Buffer.from(sealed.ciphertext, 'base64');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.nonce, 'base64'));
  d.setAAD(Buffer.from(`wv-job-request-v1|${requestId}`, 'utf8'));
  d.setAuthTag(body.subarray(body.length - 16));
  return JSON.parse(Buffer.concat([d.update(body.subarray(0, -16)), d.final()]).toString('utf8'));
}

describe('validateJobProposal', () => {
  it('accepts a daily proposal and normalizes the destination with the order rules', () => {
    const input = proposal();
    const checked = validateJobProposal(input);
    expect(checked.ok).toBe(true);
    if (!checked.ok) throw new Error(checked.reason);
    expect(checked.proposal).toEqual({
      ...input,
      destination: canonicalDestination(input.destination)!.text,
    });
  });

  it('accepts every-N-hours schedules and the timeout and grace boundaries', () => {
    for (const hours of [1, 24]) {
      for (const timeout_s of [10, 600]) {
        for (const grace_minutes of [5, 1440]) {
          expect(validateJobProposal({
            ...proposal(),
            schedule: { kind: 'every', hours, tz: 'America/New_York' },
            timeout_s,
            grace_minutes,
          }).ok).toBe(true);
        }
      }
    }
  });

  it('defaults grace to 30 minutes and timeout to five minutes', () => {
    const input = proposal();
    delete input.grace_minutes;
    delete input.timeout_s;
    const checked = validateJobProposal(input);
    expect(checked.ok).toBe(true);
    if (!checked.ok) throw new Error(checked.reason);
    expect(checked.proposal.grace_minutes).toBe(30);
    expect(checked.proposal.timeout_s).toBe(300);
  });

  it('rejects malformed inputs and unknown fields', () => {
    for (const input of [null, undefined, [], 'job', 1, true]) {
      expect(validateJobProposal(input).ok).toBe(false);
    }
    expect(validateJobProposal({ ...proposal(), command: 'backup' }).ok).toBe(false);
    expect(validateJobProposal({ ...proposal(), v: 1 }).ok).toBe(false);
    expect(validateJobProposal({ ...proposal(), type: 'job-set' }).ok).toBe(false);
  });

  it('requires each non-defaulted field', () => {
    for (const field of ['name', 'entry_id', 'destination', 'argv', 'schedule', 'why']) {
      const input = proposal();
      delete input[field];
      expect(validateJobProposal(input).ok, field).toBe(false);
    }
  });

  it.each([
    ['', false],
    [' Backup', false],
    ['Backup ', false],
    ['Backup\n', false],
    ['Backup\u0000', false],
    ['a'.repeat(81), false],
    [123, false],
    ['a'.repeat(80), true],
  ])('validates name %j', (name, ok) => {
    expect(validateJobProposal({ ...proposal(), name }).ok).toBe(ok);
  });

  it.each([
    ['', false],
    ['short', false],
    ['entry with spaces', false],
    ['a'.repeat(65), false],
    [123, false],
    ['a'.repeat(8), true],
    ['a'.repeat(64), true],
  ])('validates entry_id %j', (entry_id, ok) => {
    expect(validateJobProposal({ ...proposal(), entry_id }).ok).toBe(ok);
  });

  it.each([
    '',
    null,
    42,
    'ssh://backup@example.com',
    'backup@example.com;echo bad',
    'backup@example.com\n',
    'backup@example.com:70000',
  ])('rejects bad destination %j', destination => {
    expect(validateJobProposal({ ...proposal(), destination }).ok).toBe(false);
  });

  it('validates every argv limit without interpreting shell syntax', () => {
    const invalid = [
      [],
      'backup',
      [1],
      [''],
      ['backup', 'bad\u0000arg'],
      ['a'.repeat(4097)],
      Array.from({ length: 65 }, () => 'a'),
      Array.from({ length: 5 }, () => 'a'.repeat(4096)),
    ];
    for (const argv of invalid) {
      expect(validateJobProposal({ ...proposal(), argv }).ok).toBe(false);
    }
    expect(validateJobProposal({
      ...proposal(), argv: ['backup', '; echo this is one argument', '$HOME'],
    }).ok).toBe(true);
    expect(validateJobProposal({
      ...proposal(), argv: Array.from({ length: 64 }, () => 'a'),
    }).ok).toBe(true);
    expect(validateJobProposal({
      ...proposal(), argv: Array.from({ length: 4 }, () => 'a'.repeat(4096)),
    }).ok).toBe(true);
    expect(validateJobProposal({
      ...proposal(), argv: Array.from({ length: 3 }, () => 'é'.repeat(4096)),
    }).ok).toBe(false);
  });

  it.each([
    null,
    [],
    {},
    { kind: 'daily', time: '24:00', tz: 'UTC' },
    { kind: 'daily', time: '03:60', tz: 'UTC' },
    { kind: 'daily', time: '3:15', tz: 'UTC' },
    { kind: 'daily', time: '03:15' },
    { kind: 'daily', time: '03:15', tz: 'UTC', hours: 1 },
    { kind: 'every', hours: 0, tz: 'UTC' },
    { kind: 'every', hours: 25, tz: 'UTC' },
    { kind: 'every', hours: 1.5, tz: 'UTC' },
    { kind: 'every', hours: '2', tz: 'UTC' },
    { kind: 'every', hours: 2, tz: 'UTC', time: '03:15' },
    { kind: 'weekly', hours: 2, tz: 'UTC' },
    { kind: 'every', hours: 2, tz: '' },
    { kind: 'every', hours: 2, tz: 123 },
    { kind: 'every', hours: 2, tz: 'not/a/timezone' },
    { kind: 'every', hours: 2, tz: 'a'.repeat(65) },
  ])('rejects bad schedule %j', schedule => {
    expect(validateJobProposal({ ...proposal(), schedule }).ok).toBe(false);
  });

  it.each([null, '300', 9, 601, 10.5, NaN, Infinity])('rejects bad timeout %j', timeout_s => {
    expect(validateJobProposal({ ...proposal(), timeout_s }).ok).toBe(false);
  });

  it.each([null, '30', 4, 1441, 30.5, NaN, Infinity])('rejects bad grace %j', grace_minutes => {
    expect(validateJobProposal({ ...proposal(), grace_minutes }).ok).toBe(false);
  });

  it.each(['', '   ', 'a'.repeat(301), 'why\nnow', 'why\rnow', 'why\t now', 'why\u0000', 'why\u007f', 'why\u0085', 42, null])(
    'rejects bad why %j',
    why => {
      expect(validateJobProposal({ ...proposal(), why }).ok).toBe(false);
    },
  );

  it('accepts why at both length boundaries', () => {
    for (const why of ['x', 'x'.repeat(300)]) {
      const checked = validateJobProposal({ ...proposal(), why });
      expect(checked.ok).toBe(true);
      if (!checked.ok) throw new Error(checked.reason);
      expect(checked.proposal.why).toBe(why);
    }
  });

  it('uses exactly the job-order validation rules for shared fields', () => {
    const variants = [
      proposal(),
      { ...proposal(), name: ' bad' },
      { ...proposal(), entry_id: 'bad' },
      { ...proposal(), destination: '--help' },
      { ...proposal(), argv: ['bad\u0000arg'] },
      { ...proposal(), schedule: { kind: 'every', hours: 25, tz: 'UTC' } },
      { ...proposal(), timeout_s: 601 },
    ];
    for (const input of variants) {
      const order = validateJobOrder({
        v: 1, type: 'job-set', broker: 'proposal',
        order_id: 'proposal', job_id: 'proposal', version: 1,
        issued_at: '1970-01-01T00:00:00.000Z',
        expires_at: '1970-01-01T00:01:00.000Z',
        name: input.name, entry_id: input.entry_id, destination: input.destination,
        argv: input.argv, schedule: input.schedule, timeout_s: input.timeout_s,
      }, 'proposal', 0);
      const checked = validateJobProposal(input);
      expect(checked.ok).toBe(order.ok);
      if (!checked.ok && !order.ok) expect(checked.reason).toBe(order.reason);
    }
  });

  it('copies argv and schedule rather than retaining caller-owned containers', () => {
    const input = proposal();
    const checked = validateJobProposal(input);
    if (!checked.ok) throw new Error(checked.reason);
    (input.argv as string[]).push('--changed');
    (input.schedule as Record<string, unknown>).time = '04:00';
    expect(checked.proposal.argv).toEqual(['/usr/local/bin/backup', '--daily']);
    expect(checked.proposal.schedule).toEqual({ kind: 'daily', time: '03:15', tz: 'UTC' });
  });
});

describe('sealed job proposals', () => {
  it('opens with the vault key and request AAD, with exactly the proposal fields and envelope', () => {
    const checked = validateJobProposal(proposal());
    if (!checked.ok) throw new Error(checked.reason);
    const key = randomBytes(32);
    const requestId = newRequestId();
    const now = '2026-11-23T03:15:00.000Z';
    const sealed = sealProposal(key, requestId, checked.proposal, 'Backup agent', now);
    expect(Object.keys(sealed).sort()).toEqual(['ciphertext', 'nonce']);
    expect(Buffer.from(sealed.nonce, 'base64')).toHaveLength(12);
    expect(open(key, requestId, sealed)).toEqual({
      v: 1,
      type: 'job-request',
      request_id: requestId,
      agent_name: 'Backup agent',
      created_at: now,
      ...checked.proposal,
    });
    expect(() => open(key, newRequestId(), sealed)).toThrow();
    expect(() => open(randomBytes(32), requestId, sealed)).toThrow();
  });

  it('uses a fresh nonce for each sealing', () => {
    const checked = validateJobProposal(proposal());
    if (!checked.ok) throw new Error(checked.reason);
    const key = randomBytes(32);
    const id = newRequestId();
    const now = '2026-11-23T03:15:00.000Z';
    const a = sealProposal(key, id, checked.proposal, 'Backup agent', now);
    const b = sealProposal(key, id, checked.proposal, 'Backup agent', now);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });
});

describe('newRequestId', () => {
  it('returns 18 random bytes as unpadded base64url', () => {
    const ids = Array.from({ length: 32 }, () => newRequestId());
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^[A-Za-z0-9_-]{24}$/);
      expect(Buffer.from(id, 'base64url')).toHaveLength(18);
      expect(Buffer.from(id, 'base64url').toString('base64url')).toBe(id);
    }
  });
});
