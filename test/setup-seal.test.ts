import { createCipheriv, createHash, createHmac, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, open, readFile, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  checkValueCommitment, hkdfKey, newRequestId, openSetup, openT2Detail, pad,
  sealSetup, sealT2Detail, SetupPins, t2MatchMac,
} from '../src/setup-seal.js';
import type {
  SealResult, Setup, SetupPinsFs, T2Detail, T2MatchFields,
} from '../src/setup-seal.js';

interface SetupVector {
  vault_key_hex: string;
  agent_id: string;
  entry_id: string;
  rev: number;
  nonce_hex: string;
  setup: Setup;
  plaintext_padded_len: number;
  ciphertext_b64: string;
}

interface MatchVector {
  vault_key_hex: string;
  fields: T2MatchFields;
  mac_hex: string;
}

interface DetailVector {
  vault_key_hex: string;
  agent_id: string;
  request_id: string;
  nonce_hex: string;
  detail: T2Detail;
  plaintext_padded_len: number;
  ciphertext_b64: string;
}

const vectors = JSON.parse(readFileSync(
  new URL('./vectors/setup-v1.json', import.meta.url), 'utf8',
)) as { setups: SetupVector[]; t2_matches: MatchVector[]; t2_details: DetailVector[] };

/**
 * Independent reference: do not use the production HKDF, padding, or sealing helpers here.
 * These bytes are also the values to freeze into the shared browser/broker vector file.
 */
function referenceSeal(
  key: Buffer, info: string, aad: string, value: unknown, nonce: Buffer,
): { ciphertext: string; plaintextLength: number } {
  const json = Buffer.from(JSON.stringify(value), 'utf8');
  const sizes = [256, 1024, 4096, 16384, 65536, 131072, 262144, 524288];
  const size = sizes.find(candidate => candidate >= json.length);
  if (size === undefined) throw new Error('Reference plaintext too large');
  const plaintext = Buffer.concat([json, Buffer.alloc(size - json.length, 32)]);
  const derived = Buffer.from(hkdfSync('sha256', key, Buffer.alloc(32), info, 32));
  const cipher = createCipheriv('aes-256-gcm', derived, nonce);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext), cipher.final(), cipher.getAuthTag(),
  ]);
  return { ciphertext: ciphertext.toString('base64'), plaintextLength: size };
}

function referenceMatch(key: Buffer, fields: T2MatchFields): string {
  const derived = Buffer.from(hkdfSync(
    'sha256', key, Buffer.alloc(32), 'wv-t2-match-1', 32,
  ));
  const message = `${fields.kind}\n${fields.origin}\n${fields.method}\n${fields.path}\n${fields.entry_id}`;
  return createHmac('sha256', derived).update(message, 'utf8').digest('hex');
}

function requireSeal(result: SealResult): { ciphertext: string; nonce: string } {
  if (!result.ok) throw new Error(result.reason);
  return result;
}

const first = vectors.setups[0]!;
const key = Buffer.from(first.vault_key_hex, 'hex');
const nonce = Buffer.from(first.nonce_hex, 'hex');

function sealedSetup(setup: object = first.setup): { ciphertext: string; nonce: string } {
  return requireSeal(sealSetup(key, first.agent_id, first.entry_id, first.rev, setup, nonce));
}

function openFirst(ciphertext: string, nonceB64 = nonce.toString('base64')) {
  return openSetup(key, first.agent_id, first.entry_id, first.rev, ciphertext, nonceB64);
}

function referenceSetup(value: unknown): string {
  return referenceSeal(
    key, 'wv-setup-1', `wv-setup-1|${first.agent_id}|${first.entry_id}|${first.rev}`,
    value, nonce,
  ).ciphertext;
}

describe('shared sealing vectors', () => {
  it('has the required vector coverage', () => {
    expect(vectors.setups.length).toBeGreaterThanOrEqual(3);
    expect(vectors.t2_matches.length).toBeGreaterThanOrEqual(2);
    expect(vectors.t2_details.length).toBeGreaterThanOrEqual(1);
  });

  for (const [index, vector] of vectors.setups.entries()) {
    it(`matches the independent setup reference and frozen vector ${index + 1}`, () => {
      const vectorKey = Buffer.from(vector.vault_key_hex, 'hex');
      const vectorNonce = Buffer.from(vector.nonce_hex, 'hex');
      const reference = referenceSeal(
        vectorKey, 'wv-setup-1',
        `wv-setup-1|${vector.agent_id}|${vector.entry_id}|${vector.rev}`,
        vector.setup, vectorNonce,
      );
      const sealed = requireSeal(sealSetup(
        vectorKey, vector.agent_id, vector.entry_id, vector.rev, vector.setup, vectorNonce,
      ));
      expect(sealed.ciphertext).toBe(reference.ciphertext);
      expect(sealed.nonce).toBe(vectorNonce.toString('base64'));
      expect(reference.plaintextLength).toBe(vector.plaintext_padded_len);
      expect(openSetup(
        vectorKey, vector.agent_id, vector.entry_id, vector.rev, sealed.ciphertext, sealed.nonce,
      )).toEqual({ ok: true, setup: vector.setup });
      expect(reference.ciphertext).toBe(vector.ciphertext_b64);
    });
  }

  for (const [index, vector] of vectors.t2_matches.entries()) {
    it(`matches the independent tier-2 MAC reference and frozen vector ${index + 1}`, () => {
      const vectorKey = Buffer.from(vector.vault_key_hex, 'hex');
      const reference = referenceMatch(vectorKey, vector.fields);
      expect(t2MatchMac(vectorKey, vector.fields)).toBe(reference);
      expect(reference).toBe(vector.mac_hex);
    });
  }

  for (const [index, vector] of vectors.t2_details.entries()) {
    it(`matches the independent tier-2 detail reference and frozen vector ${index + 1}`, () => {
      const vectorKey = Buffer.from(vector.vault_key_hex, 'hex');
      const vectorNonce = Buffer.from(vector.nonce_hex, 'hex');
      const reference = referenceSeal(
        vectorKey, 'wv-t2-1', `wv-t2-1|${vector.agent_id}|${vector.request_id}`,
        { v: 1, ...vector.detail }, vectorNonce,
      );
      const sealed = requireSeal(sealT2Detail(
        vectorKey, vector.agent_id, vector.request_id, vector.detail, vectorNonce,
      ));
      expect(sealed.ciphertext).toBe(reference.ciphertext);
      expect(reference.plaintextLength).toBe(vector.plaintext_padded_len);
      expect(openT2Detail(
        vectorKey, vector.agent_id, vector.request_id, sealed.ciphertext, sealed.nonce,
      )).toEqual({ ok: true, detail: { v: 1, ...vector.detail } });
      expect(reference.ciphertext).toBe(vector.ciphertext_b64);
    });
  }
});

describe('setup envelopes', () => {
  it('derives a 32-byte HKDF-SHA256 subkey with the supplied salt and info', () => {
    const salt = Buffer.alloc(16, 19);
    const expected = Buffer.from(hkdfSync('sha256', key, salt, 'wundervault-v1-meta', 32));
    expect(hkdfKey(key, salt, 'wundervault-v1-meta')).toEqual(expected);
    expect(hkdfKey(key, salt, 'wundervault-v1-label')).not.toEqual(expected);
  });

  it('uses byte lengths, pads with spaces, and refuses values above the last bucket', () => {
    for (const size of [256, 1024, 4096, 16384, 65536, 131072, 262144, 524288]) {
      expect(pad('x'.repeat(size)).length).toBe(size);
    }
    expect(pad('x'.repeat(257)).length).toBe(1024);
    expect(pad('é'.repeat(128)).length).toBe(256);
    expect(pad('é'.repeat(129)).length).toBe(1024);
    expect(pad('😀'.repeat(64)).length).toBe(256);
    expect(pad('{}').subarray(2).every(byte => byte === 0x20)).toBe(true);
    expect(pad('x'.repeat(131073)).length).toBe(262144);
    expect(() => pad('x'.repeat(524289))).toThrow();
    expect(() => pad('é'.repeat(262145))).toThrow();
  });

  it('makes different setups within one bucket the same ciphertext length', () => {
    const a = sealedSetup({ ...first.setup, name: 'A' });
    const b = sealedSetup({ ...first.setup, name: 'A slightly longer name' });
    expect(Buffer.from(a.ciphertext, 'base64').length).toBe(
      Buffer.from(b.ciphertext, 'base64').length,
    );
  });

  it('binds a setup to its agent, entry, revision, and vault key', () => {
    const sealed = sealedSetup();
    const args = [sealed.ciphertext, sealed.nonce] as const;
    expect(openSetup(key, 'another-agent', first.entry_id, first.rev, ...args))
      .toEqual({ ok: false, reason: 'bad seal' });
    expect(openSetup(key, first.agent_id, 'another-entry', first.rev, ...args))
      .toEqual({ ok: false, reason: 'bad seal' });
    expect(openSetup(key, first.agent_id, first.entry_id, first.rev + 1, ...args))
      .toEqual({ ok: false, reason: 'bad seal' });
    expect(openSetup(Buffer.alloc(32, 99), first.agent_id, first.entry_id, first.rev, ...args))
      .toEqual({ ok: false, reason: 'bad seal' });
  });

  it('refuses tampered ciphertext, truncated tags, malformed base64, and invalid nonces', () => {
    const sealed = sealedSetup();
    const changed = Buffer.from(sealed.ciphertext, 'base64');
    changed[0] = changed[0]! ^ 1;
    for (const ciphertext of [
      changed.toString('base64'), Buffer.alloc(15).toString('base64'),
      `${sealed.ciphertext}\n`, '%%%%',
    ]) {
      expect(openFirst(ciphertext)).toEqual({ ok: false, reason: 'bad seal' });
    }
    expect(openFirst(sealed.ciphertext, Buffer.alloc(11).toString('base64')))
      .toEqual({ ok: false, reason: 'bad seal' });
    expect(openSetup(
      Buffer.alloc(31), first.agent_id, first.entry_id, first.rev, sealed.ciphertext, sealed.nonce,
    )).toEqual({ ok: false, reason: 'bad seal' });
  });

  it('rejects authenticated malformed setups on open as well as on seal', () => {
    const malformed: object[] = [
      { ...first.setup, unexpected: true },
      { ...first.setup, v: 2 },
      { ...first.setup, rev: first.rev + 1 },
      { ...first.setup, rev: 1.5 },
      { ...first.setup, value_sha256: 'A'.repeat(64) },
      { ...first.setup, value_sha256: '0'.repeat(63) },
      { ...first.setup, value_sha256: undefined },
      { ...first.setup, value_format: 'parts-2' },
      { ...first.setup, value_format: null },
      { ...first.setup, delivery: 'exec' },
      { ...first.setup, delivery: undefined },
      [],
    ];
    for (const setup of malformed) {
      expect(sealSetup(key, first.agent_id, first.entry_id, first.rev, setup, nonce))
        .toEqual({ ok: false, reason: 'malformed' });
      expect(openFirst(referenceSetup(setup))).toEqual({ ok: false, reason: 'malformed' });
    }
  });

  it('allows absent value_format for legacy raw values without inspecting their contents', () => {
    const setup = { ...first.setup };
    delete setup.value_format;
    const sealed = sealedSetup(setup);
    expect(openFirst(sealed.ciphertext)).toEqual({ ok: true, setup });
  });

  it('returns failures rather than throwing for invalid sealing inputs', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(sealSetup(key, first.agent_id, first.entry_id, first.rev, circular))
      .toEqual({ ok: false, reason: 'malformed' });
    expect(sealSetup(key, 'agent|injection', first.entry_id, first.rev, first.setup))
      .toEqual({ ok: false, reason: 'malformed' });
    expect(sealSetup(key, first.agent_id, first.entry_id, -1, first.setup))
      .toEqual({ ok: false, reason: 'malformed' });
    expect(sealSetup(key, first.agent_id, first.entry_id, first.rev, first.setup, Buffer.alloc(11)))
      .toEqual({ ok: false, reason: 'bad seal' });
    expect(sealSetup(key, first.agent_id, first.entry_id, first.rev, {
      ...first.setup, name: 'é'.repeat(262145),
    })).toEqual({ ok: false, reason: 'malformed' });
  });

  it('generates a fresh 12-byte nonce when one is not supplied', () => {
    const a = requireSeal(sealSetup(key, first.agent_id, first.entry_id, first.rev, first.setup));
    const b = requireSeal(sealSetup(key, first.agent_id, first.entry_id, first.rev, first.setup));
    expect(Buffer.from(a.nonce, 'base64').length).toBe(12);
    expect(a.nonce).not.toBe(b.nonce);
    expect(openFirst(a.ciphertext, a.nonce)).toEqual({ ok: true, setup: first.setup });
  });

  it('commits to decoded ciphertext bytes, not the base64 text', () => {
    const ciphertext = Buffer.from('exact ciphertext bytes plus tag', 'utf8');
    const setup: Setup = {
      ...first.setup,
      value_sha256: createHash('sha256').update(ciphertext).digest('hex'),
    };
    expect(checkValueCommitment(setup, ciphertext.toString('base64'))).toBe(true);
    expect(checkValueCommitment(setup, Buffer.concat([ciphertext, Buffer.from([0])]).toString('base64')))
      .toBe(false);
    expect(checkValueCommitment({
      ...setup, value_sha256: createHash('sha256').update(ciphertext.toString('base64')).digest('hex'),
    }, ciphertext.toString('base64'))).toBe(false);
    expect(checkValueCommitment({ ...setup, value_sha256: 'wrong' }, ciphertext.toString('base64')))
      .toBe(false);
    expect(checkValueCommitment(setup, '%%%%')).toBe(false);
  });
});

describe('tier-2 envelopes and matching', () => {
  const vector = vectors.t2_details[0]!;
  const vectorKey = Buffer.from(vector.vault_key_hex, 'hex');

  it('binds detail to its agent and request and rejects unknown fields', () => {
    const sealed = requireSeal(sealT2Detail(
      vectorKey, vector.agent_id, vector.request_id, vector.detail,
    ));
    expect(openT2Detail(
      vectorKey, 'another-agent', vector.request_id, sealed.ciphertext, sealed.nonce,
    )).toEqual({ ok: false, reason: 'bad seal' });
    expect(openT2Detail(
      vectorKey, vector.agent_id, 'f'.repeat(32), sealed.ciphertext, sealed.nonce,
    )).toEqual({ ok: false, reason: 'bad seal' });
    const ciphertext = referenceSeal(
      vectorKey, 'wv-t2-1', `wv-t2-1|${vector.agent_id}|${vector.request_id}`,
      { v: 1, ...vector.detail, extra: true }, nonce,
    ).ciphertext;
    expect(openT2Detail(
      vectorKey, vector.agent_id, vector.request_id, ciphertext, nonce.toString('base64'),
    )).toEqual({ ok: false, reason: 'malformed' });
    expect(sealT2Detail(vectorKey, vector.agent_id, vector.request_id, {
      ...vector.detail, extra: true,
    } as T2Detail)).toEqual({ ok: false, reason: 'malformed' });
  });

  it('distinguishes every match field, including GET /status from POST /transfer', () => {
    const fields = vectors.t2_matches[0]!.fields;
    const original = t2MatchMac(key, fields);
    for (const field of ['kind', 'origin', 'method', 'path', 'entry_id'] as const) {
      expect(t2MatchMac(key, { ...fields, [field]: `${fields[field]}x` })).not.toBe(original);
      expect(() => t2MatchMac(key, { ...fields, [field]: `${fields[field]}\ninjected` })).toThrow();
    }
    expect(t2MatchMac(key, { ...fields, method: 'GET', path: '/status' })).not.toBe(
      t2MatchMac(key, { ...fields, method: 'POST', path: '/transfer' }),
    );
    expect(original).toMatch(/^[0-9a-f]{64}$/);
  });

  it('generates 32-character lowercase hex request ids', () => {
    const ids = Array.from({ length: 100 }, () => newRequestId());
    expect(ids.every(id => /^[0-9a-f]{32}$/.test(id))).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

const temporaryDirectories: string[] = [];

async function pinPath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'wv-setup-pins-'));
  temporaryDirectories.push(directory);
  return join(directory, 'setup-pins.json');
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(directory => rm(directory, {
    recursive: true, force: true,
  })));
});

describe('setup pins', () => {
  it('requires loading and treats a missing file as empty', async () => {
    const pins = new SetupPins(await pinPath());
    expect(pins.decide('account', 'entry', false, undefined)).toBe('refuse: pins unreadable');
    await pins.load();
    expect(pins.decide('account', 'entry', false, undefined)).toBe('ok');
    expect(pins.decide('account', 'entry', true, 0)).toBe('ok');
    expect(pins.decide('account', 'entry', true, undefined)).toBe('refuse: older revision');
  });

  it('pins an account and highest entry revision, persists mode 0600, and survives reload', async () => {
    const path = await pinPath();
    const pins = new SetupPins(path);
    await pins.record('account', 'entry', 7);
    expect(pins.decide('account', 'other-entry', false, undefined))
      .toBe('refuse: plaintext after sealed');
    expect(pins.decide('other-account', 'other-entry', false, undefined)).toBe('ok');
    expect(pins.decide('account', 'entry', true, 6)).toBe('refuse: older revision');
    expect(pins.decide('account', 'entry', true, 7)).toBe('ok');
    expect(pins.decide('account', 'entry', true, 8)).toBe('ok');
    await pins.record('account', 'entry', 3);
    expect(pins.decide('account', 'entry', true, 6)).toBe('refuse: older revision');
    await pins.record('account', 'entry', 8);
    expect(JSON.parse(await readFile(path, 'utf8'))).toEqual({
      v: 1, accounts: { account: { sealed_seen: true } }, entries: { entry: 8 },
    });
    if (process.platform !== 'win32') expect((await stat(path)).mode & 0o777).toBe(0o600);
    const reloaded = new SetupPins(path);
    await reloaded.load();
    expect(reloaded.decide('account', 'entry', true, 7)).toBe('refuse: older revision');
    expect(reloaded.decide('account', 'entry', true, 8)).toBe('ok');
    expect(reloaded.decide('account', 'entry', false, 8)).toBe('refuse: plaintext after sealed');
  });

  it('serializes concurrent records without losing or lowering pins', async () => {
    const path = await pinPath();
    const pins = new SetupPins(path);
    await Promise.all([
      pins.record('account', 'entry', 10),
      pins.record('account', 'entry', 2),
      pins.record('account', 'other', 4),
    ]);
    const reloaded = new SetupPins(path);
    await reloaded.load();
    expect(reloaded.decide('account', 'entry', true, 9)).toBe('refuse: older revision');
    expect(reloaded.decide('account', 'other', true, 3)).toBe('refuse: older revision');
  });

  it('refuses everything for corrupt files instead of resetting them', async () => {
    const corrupt = [
      '{broken',
      '{"v":2,"accounts":{},"entries":{}}',
      '{"v":1,"accounts":{"a":{"sealed_seen":false}},"entries":{}}',
      '{"v":1,"accounts":{},"entries":{"e":-1}}',
      '{"v":1,"accounts":{},"entries":{"e":1.5}}',
      '{"v":1,"accounts":{},"entries":{},"extra":true}',
    ];
    for (const text of corrupt) {
      const path = await pinPath();
      await writeFile(path, text);
      const pins = new SetupPins(path);
      await pins.load();
      expect(pins.decide('any', 'entry', false, undefined)).toBe('refuse: pins unreadable');
      expect(pins.decide('any', 'entry', true, 999)).toBe('refuse: pins unreadable');
      await expect(pins.record('any', 'entry', 1)).rejects.toThrow('pins unreadable');
      expect(await readFile(path, 'utf8')).toBe(text);
    }
  });

  it('uses an exclusive same-directory temporary file, fsyncs, closes, then renames', async () => {
    const path = await pinPath();
    const events: string[] = [];
    const fs: SetupPinsFs = {
      readFile,
      unlink,
      async open(temporary, flags, mode) {
        expect(temporary.startsWith(`${path}.`)).toBe(true);
        expect(flags).toBe('wx');
        expect(mode).toBe(0o600);
        events.push('open');
        const handle = await open(temporary, flags, mode);
        return {
          async chmod(value) { events.push('chmod'); await handle.chmod(value); },
          async writeFile(data) { events.push('write'); await handle.writeFile(data); },
          async sync() { events.push('sync'); await handle.sync(); },
          async close() { events.push('close'); await handle.close(); },
        };
      },
      async rename(from, to) {
        expect(to).toBe(path);
        events.push('rename');
        await rename(from, to);
      },
    };
    await new SetupPins(path, fs).record('account', 'entry', 1);
    expect(events).toEqual(['open', 'chmod', 'write', 'sync', 'close', 'rename']);
  });

  it('fails closed on read and persistence errors', async () => {
    const path = await pinPath();
    const denied = new SetupPins(path, {
      readFile: async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); },
      open, rename, unlink,
    });
    await denied.load();
    expect(denied.decide('account', 'entry', true, 1)).toBe('refuse: pins unreadable');

    const failedWrite = new SetupPins(path, {
      readFile, open, unlink,
      rename: async () => { throw new Error('rename failed'); },
    });
    await expect(failedWrite.record('account', 'entry', 1)).rejects.toThrow('rename failed');
    expect(failedWrite.decide('account', 'entry', true, 1)).toBe('refuse: pins unreadable');
  });
});
