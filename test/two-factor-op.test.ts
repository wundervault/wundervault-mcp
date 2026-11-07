/**
 * vault_2fa_code (spec 1.2, section 1): the agent gets the code, never the seed.
 */
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { twoFactorCode, type Deps } from '../src/signing-ops.js';
import { SigningState } from '../src/wallet.js';
import { totpAt, parseSeed } from '../src/totp.js';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const VAULT_KEY = Buffer.alloc(32, 9);
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

function gcm(plaintext: string) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, nonce);
  const body = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { ciphertext: body.toString('base64'), nonce: nonce.toString('base64') };
}

function deps(shape: string, parts: Record<string, string>, opts: { nowMs: number; mode?: string; sleeps?: number[] }): Deps & { sleep: (ms: number) => Promise<void> } {
  const enc = gcm(JSON.stringify({ parts }));
  let now = opts.nowMs;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv2fa-'));
  return {
    api: {
      getSecret: async () => ({
        id: 'e1', name: 'GITHUB_LOGIN', entry_mode: opts.mode ?? 'BROKER_HTTP', access_tier: '1',
        encrypted_content: enc.ciphertext, content_nonce: enc.nonce,
        setup: { v: 1, rev: 1, value_sha256: 'x', shape, delivery: 'http', value_format: 'parts-1' },
      }),
      ensureVaultKey: async () => VAULT_KEY,
    } as never,
    state: new SigningState(path.join(dir, 'state.json')) as never,
    now: () => now,
    sleep: async (ms: number) => { opts.sleeps?.push(ms); now += ms; },
  };
}

const parsed = parseSeed(SEED);
if (!parsed.ok) throw new Error('fixture seed');
const expectAt = (ms: number) => totpAt(parsed.seed, Math.floor(ms / 1000), parsed);

describe('vault_2fa_code', () => {
  it('returns the current code for a 2FA secret, and nothing that contains the seed', async () => {
    const t = 1_700_000_020_000; // 10 s into a 30 s window
    const r = await twoFactorCode(deps('two_factor', { seed: SEED }, { nowMs: t }), { entryId: 'e1', purpose: 'sign in to GitHub' });
    expect(r).toEqual({ code: expectAt(t), expires_in_seconds: 20 });
    expect(JSON.stringify(r)).not.toContain(SEED.slice(0, 8));
  });

  it("reads a website login's 2FA field", async () => {
    const t = 1_700_000_020_000;
    const r = await twoFactorCode(deps('website_login', { username: 'u', password: 'p', totp: SEED }, { nowMs: t }), { entryId: 'e1', purpose: 'x' });
    expect(r).toEqual({ code: expectAt(t), expires_in_seconds: 20 });
  });

  it('waits for the next window when under 5 seconds remain (check 3)', async () => {
    const t = 1_700_000_037_500; // 2.5 s left
    const sleeps: number[] = [];
    const r = await twoFactorCode(deps('two_factor', { seed: SEED }, { nowMs: t, sleeps }), { entryId: 'e1', purpose: 'x' });
    expect(sleeps).toEqual([2500]);
    expect(r).toEqual({ code: expectAt(1_700_000_040_000), expires_in_seconds: 30 });
  });

  it('refuses a website login with no 2FA seed (check 4)', async () => {
    const r = await twoFactorCode(deps('website_login', { username: 'u', password: 'p', totp: '' }, { nowMs: 1 }), { entryId: 'e1', purpose: 'x' });
    expect(r).toMatchObject({ error: expect.stringContaining('this login has no authenticator setup key') });
  });

  it('refuses a secret that is not a login or 2FA secret, without reading it', async () => {
    const r = await twoFactorCode(deps('password', { username: 'u', password: 'p' }, { nowMs: 1 }), { entryId: 'e1', purpose: 'x' });
    expect(r).toMatchObject({ error: expect.stringContaining('holds no authenticator setup key') });
  });

  it('a bad stored seed is refused without echoing it (check 2)', async () => {
    const bad = 'NOTAVALIDSEED1!';
    const r = await twoFactorCode(deps('two_factor', { seed: bad }, { nowMs: 1 }), { entryId: 'e1', purpose: 'x' });
    expect(JSON.stringify(r)).toContain('not usable');
    expect(JSON.stringify(r)).not.toContain('NOTAVALID');
  });

  it('refuses an entry in another mode', async () => {
    const r = await twoFactorCode(deps('two_factor', { seed: SEED }, { nowMs: 1, mode: 'BROKER_SIGN' }), { entryId: 'e1', purpose: 'x' });
    expect(r).toMatchObject({ code: 'WRONG_MODE' });
  });
});
