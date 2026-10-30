import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AgentVaultAPI } from '../src/api-client.js';
import { pinAccountFor, resolveEntry, resolveList } from '../src/entry-view.js';
import type { EntryContext } from '../src/entry-view.js';
import { sealSetup, SetupPins } from '../src/setup-seal.js';
import type { Setup } from '../src/setup-seal.js';
import type { SecretResponse, VaultEntry } from '../src/types.js';

const vaultKey = Buffer.alloc(32, 7);
const agentId = 'a'.repeat(32);
const entryId = 'b'.repeat(32);
const apiKey = 'test-api-key';
const account = pinAccountFor(apiKey);
const value = Buffer.alloc(48, 9).toString('base64');
const bindingV1 = {
  in: 'header',
  name: 'Authorization',
  template: '{basic}',
  username: 'owner',
};
const bindingV2 = {
  v: 2,
  placements: [
    { in: 'header', name: 'X-Key-ID', template: '{part:id}' },
    { in: 'header', name: 'X-Key-Secret', template: '{part:secret}' },
  ],
};

function setup(overrides: Partial<Setup> = {}): Setup {
  return {
    v: 1,
    rev: 3,
    value_sha256: createHash('sha256').update(Buffer.from(value, 'base64')).digest('hex'),
    value_format: 'raw',
    name: 'Owner name',
    shape: 'api_key',
    delivery: 'http',
    binding: bindingV1,
    ...overrides,
  };
}

function sealed(
  policy = setup(), id = entryId, agent = agentId,
): SecretResponse & { secret_name: string; extra: string } {
  const result = sealSetup(vaultKey, agent, id, policy.rev, policy);
  if (!result.ok) throw new Error(`Fixture seal failed: ${result.reason}`);
  return {
    id,
    agent_id: agent,
    rev: policy.rev,
    setup_ciphertext: result.ciphertext,
    setup_nonce: result.nonce,
    encrypted_content: value,
    content_nonce: Buffer.alloc(12, 2).toString('base64'),
    access_tier: 'tier1',
    alert_email: 'off',
    directive: 'directive',
    directive_signature: 'signature',
    name: 'evil',
    secret_name: 'evil',
    entry_mode: 'LEGACY_EXEC',
    exec_config: JSON.stringify({
      delivery: 'http',
      credential_binding: { in: 'header', name: 'X-Evil', template: '{secret}' },
    }),
    operations: '{"evil":{"definition":{"op":"evil"}}}',
    allowed_private_origins: '["https://evil.example"]',
    policy_ciphertext: 'server-policy',
    policy_nonce: 'server-policy-nonce',
    extra: 'must not survive',
  };
}

function listed(resp: SecretResponse): VaultEntry {
  return {
    ...resp,
    id: resp.id!,
    secret_name: 'evil',
    access_tier: resp.access_tier ?? 'tier1',
  };
}

describe('entry views', () => {
  let directory: string;
  let path: string;
  let pins: SetupPins;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'wv-entry-view-'));
    path = join(directory, 'setup-pins.json');
    pins = new SetupPins(path);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    await rm(directory, { recursive: true, force: true });
  });

  function context(overrides: Partial<EntryContext> = {}): EntryContext {
    return {
      requestedId: entryId,
      vaultKey: async () => vaultKey,
      pins,
      account,
      withValue: true,
      ...overrides,
    };
  }

  async function expectRefusal(
    resp: SecretResponse,
    code = 'SETUP_REFUSED',
    overrides: Partial<EntryContext> = {},
  ) {
    const activePins = overrides.pins ?? pins;
    const record = vi.spyOn(activePins, 'record');
    record.mockClear();
    const result = await resolveEntry(resp, context(overrides));
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('Expected refusal');
    expect(result.code).toBe(code);
    expect(result.message).toContain('Nothing was sent.');
    expect(record).not.toHaveBeenCalled();
    return result;
  }

  it('keys account pins by the UTF-8 API key hash', () => {
    expect(pinAccountFor('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(pinAccountFor('clé')).toBe(
      createHash('sha256').update(Buffer.from('clé', 'utf8')).digest('hex'),
    );
    expect(pinAccountFor('abc')).not.toBe(pinAccountFor('abcd'));
  });

  it('passes legacy unlocked responses through unchanged without opening or recording', async () => {
    const resp: SecretResponse = {
      encrypted_content: value,
      content_nonce: 'legacy-nonce',
      name: 'Legacy',
      exec_config: '{"delivery":"http"}',
    };
    const key = vi.fn(async () => vaultKey);
    const record = vi.spyOn(pins, 'record');
    const result = await resolveEntry(resp, context({ vaultKey: key }));
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('Expected legacy entry');
    expect(result.entry).toBe(resp);
    expect(key).not.toHaveBeenCalled();
    expect(record).not.toHaveBeenCalled();
  });

  it('refuses a locked account without a blob even before a sealed sighting', async () => {
    const result = await expectRefusal({
      encrypted_content: value,
      content_nonce: 'nonce',
      vault_locked: true,
    });
    expect(result.message).toContain('this account is locked but the server sent no sealed setup');
  });

  it('persists sealed sightings and refuses plaintext after a restart', async () => {
    const resp = sealed();
    expect((await resolveEntry(resp, context())).ok).toBe(true);
    const stored = JSON.parse(await readFile(path, 'utf8'));
    expect(stored.accounts[account]).toEqual({ sealed_seen: true });
    expect(stored.entries[entryId]).toBe(3);
    expect((await stat(path)).mode & 0o777).toBe(0o600);

    const legacy: SecretResponse = {
      id: 'c'.repeat(32),
      encrypted_content: value,
      content_nonce: 'nonce',
      name: 'plaintext fallback',
    };
    const first = await expectRefusal(legacy, 'SETUP_REFUSED', { requestedId: legacy.id! });
    expect(first.message).toContain('plaintext after sealed');
    const restarted = new SetupPins(path);
    const second = await expectRefusal(legacy, 'SETUP_REFUSED', {
      requestedId: legacy.id!,
      pins: restarted,
    });
    expect(second.message).toContain('plaintext after sealed');
  });

  it('refuses a genuinely sealed lower revision after a restart', async () => {
    expect((await resolveEntry(sealed(setup({ rev: 8 })), context())).ok).toBe(true);
    const result = await expectRefusal(sealed(setup({ rev: 7 })), 'SETUP_REFUSED', {
      pins: new SetupPins(path),
    });
    expect(result.message).toContain('older revision');
  });

  it('allows the same revision again and advances the persisted high-water mark', async () => {
    expect((await resolveEntry(sealed(), context())).ok).toBe(true);
    expect((await resolveEntry(sealed(), context())).ok).toBe(true);
    expect((await resolveEntry(sealed(setup({ rev: 4 })), context())).ok).toBe(true);
    expect(JSON.parse(await readFile(path, 'utf8')).entries[entryId]).toBe(4);
  });

  it('refuses a wrong agent id in the AAD', async () => {
    await expectRefusal({ ...sealed(), agent_id: 'd'.repeat(32) });
  });

  it('uses the requested entry id for AAD even when the response omits its id', async () => {
    const resp = sealed(setup(), 'c'.repeat(32));
    delete resp.id;
    await expectRefusal(resp);
  });

  it('refuses a wrong response revision in the AAD', async () => {
    await expectRefusal({ ...sealed(), rev: 4 });
  });

  it('refuses an id mismatch before loading pins or opening anything', async () => {
    const load = vi.spyOn(pins, 'load');
    const key = vi.fn(async () => vaultKey);
    await expectRefusal({ ...sealed(), id: 'c'.repeat(32) }, 'WRONG_ENTRY', { vaultKey: key });
    expect(load).not.toHaveBeenCalled();
    expect(key).not.toHaveBeenCalled();
  });

  it('uses the response id for list AAD, not an id from another entry', async () => {
    await expectRefusal({ ...sealed(), id: 'c'.repeat(32) }, 'SETUP_REFUSED', {
      requestedId: null,
      withValue: false,
    });
  });

  it.each([undefined, '', 'bad|id'])('refuses an unusable list id: %s', async id => {
    await expectRefusal({ ...sealed(), id }, 'MALFORMED', {
      requestedId: null,
      withValue: false,
    });
  });

  it('accepts a requested id when the response has no id', async () => {
    const resp = sealed();
    delete resp.id;
    const result = await resolveEntry(resp, context());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('Expected opened setup');
    expect(result.entry.name).toBe('Owner name');
    expect(result.entry.id).toBeUndefined();
    expect(JSON.parse(await readFile(path, 'utf8')).entries[entryId]).toBe(3);
  });

  it('refuses a mismatched value commitment on a value fetch', async () => {
    const result = await expectRefusal({
      ...sealed(),
      encrypted_content: Buffer.alloc(48, 5).toString('base64'),
    });
    expect(result.message).toContain("the key and its setup don't match");
  });

  it('ignores a mismatched or missing value for list views', async () => {
    const resp = sealed();
    const mismatched = {
      ...resp,
      encrypted_content: Buffer.alloc(48, 5).toString('base64'),
    };
    expect((await resolveEntry(mismatched, context({ withValue: false }))).ok).toBe(true);
    const { encrypted_content, content_nonce, ...withoutValue } = resp;
    const result = await resolveEntry(withoutValue, context({
      requestedId: null,
      withValue: false,
    }));
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('Expected list entry');
    expect(result.entry).not.toHaveProperty('encrypted_content');
    expect(result.entry).not.toHaveProperty('content_nonce');
  });

  it('builds only from the sealed setup and the explicit response allowlist', async () => {
    const operations = {
      status: { definition: { op: 'status' }, signature: 'owner-signature' },
    };
    const origins = ['https://internal.example'];
    const policy = setup({ operations, private_origins: origins });
    const resp = sealed(policy);
    const record = vi.spyOn(pins, 'record');
    const result = await resolveEntry(resp, context());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('Expected opened setup');
    expect(result.entry).toEqual({
      encrypted_content: resp.encrypted_content,
      content_nonce: resp.content_nonce,
      access_tier: resp.access_tier,
      alert_email: resp.alert_email,
      directive: resp.directive,
      directive_signature: resp.directive_signature,
      id: resp.id,
      agent_id: resp.agent_id,
      rev: resp.rev,
      name: policy.name,
      secret_name: policy.name,
      entry_mode: 'BROKER_HTTP',
      exec_config: JSON.stringify({ delivery: 'http', credential_binding: bindingV1 }),
      operations: JSON.stringify(operations),
      allowed_private_origins: JSON.stringify(origins),
      setup: policy,
    });
    expect(record).toHaveBeenCalledTimes(1);
    expect(record).toHaveBeenCalledWith(account, entryId, 3);
  });

  it.each([
    {
      label: 'http v1',
      policy: setup(),
      mode: 'BROKER_HTTP',
      config: { delivery: 'http', credential_binding: bindingV1 },
    },
    {
      label: 'http v2',
      policy: setup({ shape: 'key_id', value_format: 'parts-1', binding: bindingV2 }),
      mode: 'BROKER_HTTP',
      config: { delivery: 'http', credential_binding: bindingV2 },
    },
    {
      label: 'ssh',
      policy: setup({
        shape: 'ssh_key', delivery: 'ssh', binding: null, ssh_hosts: ['host.example'],
      }),
      mode: 'BROKER_SSH_AGENT',
      config: { delivery: 'ssh', ssh_hosts: ['host.example'] },
    },
    {
      label: 'wallet',
      policy: setup({
        shape: 'wallet', delivery: 'wallet', binding: null, chain: 'ethereum',
      }),
      mode: 'BROKER_WALLET',
      config: { delivery: 'wallet', chain: 'ethereum' },
    },
    {
      label: 'sign',
      policy: setup({ shape: 'signing_key', delivery: 'sign', binding: null }),
      mode: 'BROKER_SIGN',
      config: { delivery: 'sign' },
    },
  ])('maps $label without leaking server policy fields', async ({ policy, mode, config }) => {
    const result = await resolveEntry(sealed(policy), context());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('Expected opened setup');
    expect(result.entry.entry_mode).toBe(mode);
    expect(JSON.parse(result.entry.exec_config as string)).toEqual(config);
    expect(result.entry).not.toHaveProperty('operations');
    expect(result.entry).not.toHaveProperty('allowed_private_origins');
    expect(result.entry).not.toHaveProperty('policy_ciphertext');
    expect(result.entry).not.toHaveProperty('policy_nonce');
    expect(result.entry).not.toHaveProperty('setup_ciphertext');
    expect(result.entry).not.toHaveProperty('extra');
  });

  it('omits empty operations and private origins rather than retaining plaintext ones', async () => {
    const result = await resolveEntry(
      sealed(setup({ operations: {}, private_origins: [], ssh_hosts: null, chain: null })),
      context(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('Expected opened setup');
    expect(result.entry).not.toHaveProperty('operations');
    expect(result.entry).not.toHaveProperty('allowed_private_origins');
    expect(JSON.parse(result.entry.exec_config as string)).toEqual({
      delivery: 'http',
      credential_binding: bindingV1,
    });
  });

  it('leaves absent value_format absent, rather than inferring a parts envelope', async () => {
    const policy = setup();
    delete policy.value_format;
    const result = await resolveEntry(sealed(policy), context());
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('Expected opened setup');
    expect(result.entry.setup).not.toHaveProperty('value_format');
  });

  it.each(['ssh', 'wallet', 'sign'] as const)('refuses parts-1 for %s', async delivery => {
    await expectRefusal(sealed(setup({ delivery, value_format: 'parts-1' })));
  });

  it('leaves refused entries out of a list and counts them without requiring values', async () => {
    const good = listed(sealed());
    const bad = listed(sealed(setup(), 'c'.repeat(32)));
    bad.setup_nonce = Buffer.alloc(12, 99).toString('base64');
    const result = await resolveList({ entries: [bad, good] }, context());
    expect(result.refused).toBe(1);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].id).toBe(entryId);
    expect(result.entries[0].secret_name).toBe('Owner name');
    expect(result.entries[0].entry_mode).toBe('BROKER_HTTP');
  });

  it('a listed entry keeps the pre-L list shape: operations are ids, and no setup or config', async () => {
    const ops = {
      ping: { definition: { op: 'ping' }, signature: 's' },
      quote: { definition: { op: 'quote' }, signature: 's' },
    };
    const result = await resolveList({ entries: [listed(sealed(setup({ operations: ops })))] }, context());
    expect(result.entries).toHaveLength(1);
    const entry = result.entries[0] as unknown as Record<string, unknown>;
    // An older agent app renders `operations.join(', ')`; a JSON string would throw there.
    expect(entry.operations).toEqual(['ping', 'quote']);
    expect(Object.keys(entry).sort()).toEqual(['access_tier', 'entry_mode', 'id', 'operations', 'secret_name']);
  });

  it('a list sighting also establishes the account downgrade pin', async () => {
    const result = await resolveList({ entries: [listed(sealed())] }, context());
    expect(result.refused).toBe(0);
    expect(result.entries).toHaveLength(1);
    await expectRefusal({
      encrypted_content: value,
      content_nonce: 'nonce',
      name: 'fallback',
    });
  });

  it.each([
    { setup_ciphertext: '' },
    { setup_nonce: '' },
    { agent_id: undefined },
    { rev: undefined },
    { rev: -1 },
  ])('does not record a failed seal: %j', async changes => {
    await expectRefusal({ ...sealed(), ...changes });
  });

  it('does not record when the vault key cannot be obtained', async () => {
    await expectRefusal(sealed(), 'SETUP_REFUSED', {
      vaultKey: async () => { throw new Error('private error detail'); },
    });
  });

  it('does not record when pins refuse the entry', async () => {
    await pins.load();
    vi.spyOn(pins, 'decide').mockReturnValue('refuse: pins unreadable');
    const result = await expectRefusal(sealed());
    expect(result.message).toContain('pins unreadable');
  });

  it('does not open or record when pins cannot be loaded', async () => {
    vi.spyOn(pins, 'load').mockRejectedValue(new Error('private filesystem path'));
    const key = vi.fn(async () => vaultKey);
    const result = await expectRefusal(sealed(), 'SETUP_REFUSED', { vaultKey: key });
    expect(result.message).not.toContain('private filesystem path');
    expect(key).not.toHaveBeenCalled();
  });

  it('refuses rather than returning a view when recording fails', async () => {
    const record = vi.spyOn(pins, 'record').mockRejectedValue(new Error('private path'));
    const result = await resolveEntry(sealed(), context());
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('Expected persistence refusal');
    expect(result.code).toBe('SETUP_REFUSED');
    expect(result.message).toContain('Nothing was sent.');
    expect(result.message).not.toContain('private path');
    expect(record).toHaveBeenCalledTimes(1);
    expect(record).toHaveBeenCalledWith(account, entryId, 3);
  });

  it('resolves the first API fetch and exposes refusal codes on errors', async () => {
    const api = new AgentVaultAPI(apiKey, vaultKey, 'https://vault.example', null, pins);
    vi.spyOn(api, 'ensureVaultKey').mockResolvedValue(vaultKey);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(sealed()), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        ...sealed(),
        encrypted_content: Buffer.alloc(48, 6).toString('base64'),
      }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    expect((await api.getSecret(entryId)).name).toBe('Owner name');
    await expect(api.getSecret(entryId)).rejects.toMatchObject({
      code: 'SETUP_REFUSED',
      message: expect.stringContaining("the key and its setup don't match"),
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('resolves the post-approval API re-fetch too', async () => {
    const api = new AgentVaultAPI(apiKey, vaultKey, 'https://vault.example', null, pins);
    vi.spyOn(api, 'ensureVaultKey').mockResolvedValue(vaultKey);
    const wait = vi.spyOn(api, 'waitForTier2Outcome').mockResolvedValue('approved');
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('/tier2-requests/request-1', { status: 403 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        ...sealed(),
        encrypted_content: Buffer.alloc(48, 6).toString('base64'),
      }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(api.getSecret(entryId)).rejects.toMatchObject({
      code: 'SETUP_REFUSED',
      message: expect.stringContaining("the key and its setup don't match"),
    });
    expect(wait).toHaveBeenCalledWith('request-1');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('returns only resolved API list entries and does not fetch values', async () => {
    const api = new AgentVaultAPI(apiKey, vaultKey, 'https://vault.example', null, pins);
    vi.spyOn(api, 'ensureVaultKey').mockResolvedValue(vaultKey);
    const good = listed(sealed());
    const bad = { ...listed(sealed(setup(), 'c'.repeat(32))), setup_ciphertext: '' };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ entries: [good, bad] }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const result = await api.listSecrets();
    expect(Object.keys(result)).toEqual(['entries']);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].secret_name).toBe('Owner name');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('https://vault.example/agent/vault/secrets');
  });

  it('keeps API responses unchanged when pins are null', async () => {
    const api = new AgentVaultAPI(apiKey, vaultKey, 'https://vault.example');
    const key = vi.spyOn(api, 'ensureVaultKey');
    const resp = { ...sealed(), setup_ciphertext: '', vault_locked: true };
    const list = { entries: [listed(resp)] };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(resp), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(list), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    expect(await api.getSecret(entryId)).toEqual(resp);
    expect(await api.listSecrets()).toEqual(list);
    expect(key).not.toHaveBeenCalled();
  });
});
