import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BrokerOps } from '../src/broker-ops.js';
import { canonicalJson } from '../src/opdef.js';
import { approveStamp } from '../src/signing-ops.js';
import { hardenedSshOptions, type BrokeredOp } from '../src/ssh-agent.js';
import { pinnedSshOptions } from '../src/ssh-options.js';
import {
  normalizeSshTarget, sshHostRecipe, sshHostSha, describeSshHost,
  fingerprint, knownHostsLine, scanHostKey,
} from '../src/ssh-pin.js';
import { readPolicy, SigningState } from '../src/wallet.js';

// Exercise the broker's approval boundary without depending on the approval transport.
// Real policy decryption, rollback checks, key loading and signing sockets remain in use.
vi.mock('../src/signing-ops.js', async (importOriginal) => ({
  ...await importOriginal<typeof import('../src/signing-ops.js')>(),
  approveStamp: vi.fn(),
}));

const VAULT_KEY = Buffer.alloc(32, 9);
const ENC_KEY_B64 = Buffer.alloc(32, 7).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const TARGET = { user: 'debian', host: 'example.com', port: 22 };
const DENIED = { error: 'The owner did not approve this sign-in.', code: 'DENIED' };

function hostKey(fill: number, type = 'ssh-ed25519'): string {
  const name = Buffer.from(type);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(name.length);
  const keyLength = Buffer.alloc(4);
  keyLength.writeUInt32BE(32);
  return `${type} ${Buffer.concat([length, name, keyLength, Buffer.alloc(32, fill)]).toString('base64')}`;
}

const HOST_KEY = hostKey(1);
const OTHER_KEY = hostKey(2);

let base: string;
let run: string;
let encryptedKey: { ct: string; nonce: string };
let brokers: BrokerOps[];
const saved: Record<string, string | undefined> = {};

function setEnv(k: string, v: string) {
  if (!(k in saved)) saved[k] = process.env[k];
  process.env[k] = v;
}

function gcm(plaintext: Buffer): { ct: string; nonce: string } {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, nonce);
  const body = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { ct: body.toString('base64'), nonce: nonce.toString('base64') };
}

function sha(value: unknown): string {
  return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function approval(key: string | undefined = HOST_KEY) {
  return {
    recipe_sha256: key === undefined
      ? sha({ type: 'ssh_host', v: 1, ...TARGET, host_key: '' })
      : sshHostSha(TARGET, key),
    ssh: { ...TARGET, ...(key === undefined ? {} : { host_key: key }) },
  };
}

function unpinnedApproval() {
  return {
    recipe_sha256: sha({ type: 'ssh_host', v: 1, ...TARGET, host_key: '' }),
    ssh: { ...TARGET },
  };
}

function sealPolicy(approved: unknown[], version = 1) {
  const sealed = gcm(Buffer.from(JSON.stringify({
    v: 1, entry_id: 'ssh1', version, kind: 'stamped', stamped: { approved },
  })));
  return { policy_ciphertext: sealed.ct, policy_nonce: sealed.nonce };
}

function broker(approved?: unknown[], legacy = false, scanned: string | null = HOST_KEY) {
  const keyscan = vi.fn(async () => scanned);
  const entry: Record<string, unknown> = {
    name: 'ssh1', entry_mode: 'BROKER_SSH_AGENT', access_tier: '1',
    encrypted_content: encryptedKey.ct, content_nonce: encryptedKey.nonce,
    exec_config: JSON.stringify({ delivery: 'ssh', ssh_hosts: legacy ? [TARGET.host] : [] }),
    ...(legacy ? {} : { setup: { delivery: 'ssh', ask: true, ssh_hosts: [] } }),
    ...(approved === undefined ? {} : sealPolicy(approved)),
  };
  const state = new SigningState(path.join(base, `ledger-${brokers.length}.json`));
  const ops = new BrokerOps('Tester', 'k', ENC_KEY_B64, 'http://127.0.0.1:1', null, state, {}, {
    pinsPath: path.join(base, 'pins.json'), keyscan,
  });
  const api = {
    getSecret: vi.fn(async () => entry),
    ensureVaultKey: vi.fn(async () => VAULT_KEY),
  };
  (ops as unknown as { api: unknown }).api = api;
  brokers.push(ops);
  return { ops, api, entry, keyscan };
}

function open(ops: BrokerOps, destination = 'debian@example.com') {
  return ops.sshAgentOpen({
    entryId: 'ssh1', purpose: 'test sign-in',
    op: { kind: 'ssh', destination, remoteArgv: ['true'] },
  });
}

function expectNoSession() {
  const root = path.join(run, 'ssh');
  expect(fs.existsSync(root) ? fs.readdirSync(root) : []).toEqual([]);
}

beforeEach(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-sshask-'));
  run = path.join(base, 'run');
  fs.mkdirSync(run, { recursive: true });
  brokers = [];
  setEnv('WUNDERVAULT_RUNTIME_DIR', run);
  setEnv('WUNDERVAULT_SYSTEM_ROOT', path.join(base, 'state'));
  setEnv('WUNDERVAULT_USER_ROOT', path.join(base, 'home', '.wundervault'));
  const keyFile = path.join(base, 'k');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', keyFile]);
  encryptedKey = gcm(fs.readFileSync(keyFile));
  vi.mocked(approveStamp).mockReset();
  vi.mocked(approveStamp).mockResolvedValue(DENIED);
});

afterEach(() => {
  for (const ops of brokers) ops.reset();
  vi.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
  fs.rmSync(base, { recursive: true, force: true });
});

describe('SSH ask on first use', () => {
  it('asks with the exact hashed recipe and creates no session when denied', async () => {
    const { ops, api, keyscan } = broker();
    expect(await open(ops)).toEqual(DENIED);
    expect(api.getSecret).toHaveBeenCalledTimes(1);
    expect(keyscan).toHaveBeenCalledWith(TARGET);
    expect(approveStamp).toHaveBeenCalledTimes(1);
    const shown = vi.mocked(approveStamp).mock.calls[0][1];
    expect(shown.origin).toBe('ssh://debian@example.com:22');
    expect(shown.recipe).toEqual(sshHostRecipe(TARGET, HOST_KEY));
    expect(sha(shown.recipe)).toBe(sshHostSha(TARGET, HOST_KEY));
    expect(shown.recipeSha).toBe(sshHostSha(TARGET, HOST_KEY));
    expect(shown.summary).toContain(fingerprint(HOST_KEY));
    expect(shown.purpose).toBe('test sign-in');
    expectNoSession();
  });

  it('opens a pre-approved pinned session with exactly the broker-written identity', async () => {
    const { ops, keyscan } = broker([approval()]);
    const r = await open(ops);
    if ('error' in r) throw new Error(JSON.stringify(r));
    expect(keyscan).toHaveBeenCalledWith(TARGET);
    expect(approveStamp).not.toHaveBeenCalled();
    expect(r.pinned_host_key).toBe(HOST_KEY);
    expect(r.audited_host).toBe('debian@example.com:22');
    expect(r.known_hosts_path).toBe(path.join(path.dirname(r.socket_path), 'known_hosts'));
    expect(fs.readFileSync(r.known_hosts_path!, 'utf8')).toBe(knownHostsLine(TARGET, HOST_KEY));
    expect(fs.statSync(r.known_hosts_path!).mode & 0o777).toBe(0o644);
  });

  it('pins the scanned identity after a first-use approval succeeds', async () => {
    vi.mocked(approveStamp).mockResolvedValue(null);
    const { ops } = broker();
    const r = await open(ops);
    if ('error' in r) throw new Error(JSON.stringify(r));
    expect(approveStamp).toHaveBeenCalledTimes(1);
    expect(r.pinned_host_key).toBe(HOST_KEY);
    expect(fs.readFileSync(r.known_hosts_path!, 'utf8')).toBe(knownHostsLine(TARGET, HOST_KEY));
  });

  it('refuses a changed identity and shows both fingerprints without asking', async () => {
    const { ops } = broker([approval(OTHER_KEY)]);
    const r = await open(ops);
    if (!('error' in r)) throw new Error('A changed server identity was accepted');
    expect(r.code).toBe('HOST_KEY_CHANGED');
    expect(r.error).toContain(fingerprint(OTHER_KEY));
    expect(r.error).toContain(fingerprint(HOST_KEY));
    expect(r.error).toContain('Replace on the key page');
    expect(approveStamp).not.toHaveBeenCalled();
    expectNoSession();
  });

  it('asks to pin an owner-added address that has no identity yet', async () => {
    const { ops } = broker([unpinnedApproval()]);
    expect(await open(ops)).toEqual(DENIED);
    expect(approveStamp).toHaveBeenCalledTimes(1);
    const shown = vi.mocked(approveStamp).mock.calls[0][1];
    expect(shown.summary).toContain(fingerprint(HOST_KEY));
    expect(shown.recipe).toEqual(sshHostRecipe(TARGET, HOST_KEY));
    expectNoSession();
  });

  it.each(['opc@example.com', 'debian@example.com:2222', 'debian@other.example'])(
    'asks again for a different target: %s',
    async (destination) => {
      const { ops, keyscan } = broker([approval()]);
      expect(await open(ops, destination)).toEqual(DENIED);
      const target = normalizeSshTarget(destination)!;
      expect(keyscan).toHaveBeenCalledWith(target);
      expect(vi.mocked(approveStamp).mock.calls[0][1].recipeSha).toBe(sshHostSha(target, HOST_KEY));
      expectNoSession();
    },
  );

  it('does not scan or pin legacy allowlisted entries', async () => {
    const { ops, keyscan } = broker(undefined, true);
    const r = await open(ops);
    if ('error' in r) throw new Error(JSON.stringify(r));
    expect(keyscan).not.toHaveBeenCalled();
    expect(approveStamp).not.toHaveBeenCalled();
    expect(r.known_hosts_path).toBeUndefined();
    expect(r.pinned_host_key).toBeUndefined();
  });

  it('refuses when the broker cannot read the server identity', async () => {
    const { ops } = broker(undefined, false, null);
    const r = await open(ops);
    if (!('error' in r)) throw new Error('An unreadable identity was accepted');
    expect(r.error).toContain('could not read this server\'s identity');
    expect(approveStamp).not.toHaveBeenCalled();
    expectNoSession();
  });

  it('refuses malformed or rolled-back sealed policy before scanning', async () => {
    const { ops, entry, keyscan } = broker([approval()]);
    const r = await open(ops);
    if ('error' in r) throw new Error(JSON.stringify(r));
    ops.closeSsh(r.session_id);
    Object.assign(entry, sealPolicy([], 2));
    expect(await open(ops)).toEqual(DENIED);
    keyscan.mockClear();
    vi.mocked(approveStamp).mockClear();
    Object.assign(entry, sealPolicy([approval()], 1));
    const refused = await open(ops);
    expect('error' in refused && refused.code).toBe('BAD_POLICY');
    expect(keyscan).not.toHaveBeenCalled();
    expect(approveStamp).not.toHaveBeenCalled();
  });

  it('refuses rsync and mixed git targets before scanning or asking', async () => {
    const { ops, keyscan } = broker();
    const operations = [
      { kind: 'rsync', destination: 'debian@example.com' },
      {
        kind: 'git', destination: 'debian@example.com', subcommand: 'fetch',
        urls: ['debian@example.com:repo.git', 'opc@example.com:repo.git'],
      },
      {
        kind: 'git', destination: 'debian@example.com', subcommand: 'fetch',
        urls: ['ssh://debian@example.com:2222/repo.git'],
      },
    ];
    for (const op of operations) {
      const r = await ops.sshAgentOpen({
        entryId: 'ssh1', purpose: 'test', op: op as unknown as BrokeredOp,
      });
      expect('error' in r).toBe(true);
    }
    expect(keyscan).not.toHaveBeenCalled();
    expect(approveStamp).not.toHaveBeenCalled();
    expectNoSession();
  });

  it('uses strict isolated host checking without changing the legacy options', () => {
    const options = pinnedSshOptions('/session/agent.sock', '/session/id.pub', '/session/known_hosts');
    expect(options).toEqual([
      '-F', '/dev/null',
      '-o', 'IdentityFile=/session/id.pub',
      '-o', 'IdentitiesOnly=yes',
      '-o', 'IdentityAgent=/session/agent.sock',
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=yes',
      '-o', 'UserKnownHostsFile=/session/known_hosts',
      '-o', 'GlobalKnownHostsFile=/dev/null',
    ]);
    expect(options).not.toContain('StrictHostKeyChecking=accept-new');
    expect(hardenedSshOptions('/sock', '/pub')).toContain('StrictHostKeyChecking=accept-new');
  });
});

describe('sealed SSH approvals', () => {
  function check(items: unknown[]) {
    const sealed = sealPolicy(items);
    return readPolicy({
      ciphertext: sealed.policy_ciphertext, nonce: sealed.policy_nonce,
      vaultKey: VAULT_KEY, entryId: 'ssh1', kind: 'stamped',
    });
  }

  it('accepts pinned and address-only approvals', () => {
    for (const item of [approval(), unpinnedApproval()]) {
      const result = check([item]);
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.policy?.stamped?.approved).toEqual([item]);
    }
  });

  it('rejects unknown fields, ambiguous destinations, invalid targets and wrong hashes', () => {
    const good = approval();
    const bad = [
      { ...good, origin: 'https://example.com:443' },
      { recipe_sha256: good.recipe_sha256 },
      { ...good, extra: true },
      { ...good, ssh: { ...good.ssh, extra: true } },
      { ...good, ssh: { ...good.ssh, port: 0 } },
      { ...good, ssh: { ...good.ssh, host: '::1' } },
      { ...good, ssh: { ...good.ssh, host_key: 'ssh-ed25519 not-a-key' } },
      { ...good, recipe_sha256: '0'.repeat(64) },
      { ...unpinnedApproval(), recipe_sha256: good.recipe_sha256 },
      { ...good, placement: { in: 'header', name: 'Authorization', template: 'Bearer {secret}' } },
    ];
    for (const item of bad) expect(check([item]).ok).toBe(false);
  });
});

describe('SSH pin helpers', () => {
  it('normalizes targets and refuses ambiguous or unsafe destinations', () => {
    expect(normalizeSshTarget('debian@EXAMPLE.com.')).toEqual(TARGET);
    expect(normalizeSshTarget('debian@example.com:2222')).toEqual({ ...TARGET, port: 2222 });
    expect(normalizeSshTarget('debian@example.com', 2222)).toEqual({ ...TARGET, port: 2222 });
    for (const destination of [
      'example.com', 'debian@::1', 'debian@[::1]', 'debian@-bad.example',
      'debian@example.com:0', 'debian@example.com:65536', 'debian@example.com\n',
    ]) {
      expect(normalizeSshTarget(destination)).toBeNull();
    }
    expect(normalizeSshTarget('debian@example.com:22', 2222)).toBeNull();
  });

  it('hashes exactly the canonical recipe, independent of base64 padding', () => {
    const recipe = sshHostRecipe(TARGET, HOST_KEY);
    expect(sshHostSha(TARGET, HOST_KEY)).toBe(sha(recipe));
    expect(sshHostSha(TARGET, HOST_KEY.replace(/=+$/, ''))).toBe(sha(recipe));
    expect(sshHostSha({ ...TARGET, port: 2222 }, HOST_KEY)).not.toBe(sha(recipe));
    expect(sshHostSha(TARGET, OTHER_KEY)).not.toBe(sha(recipe));
  });

  it('describes the sign-in and renders known_hosts with the correct port syntax', () => {
    expect(describeSshHost(TARGET, HOST_KEY)).toBe(
      `Let agents use this key to sign in to debian@example.com? Server identity ${fingerprint(HOST_KEY)}`,
    );
    expect(describeSshHost({ ...TARGET, port: 2222 }, HOST_KEY)).toContain('debian@example.com (port 2222)');
    expect(knownHostsLine(TARGET, HOST_KEY)).toBe(`example.com ${HOST_KEY}`);
    expect(knownHostsLine({ ...TARGET, port: 2222 }, HOST_KEY)).toBe(`[example.com]:2222 ${HOST_KEY}`);
  });

  it('scans from a fixed broker command and prefers ed25519, then ECDSA, then RSA', async () => {
    const rsa = hostKey(3, 'ssh-rsa');
    const ecdsa = hostKey(4, 'ecdsa-sha2-nistp256');
    const runner = vi.fn(async () => ({
      code: 0,
      stdout: `# comment\nexample.com ${rsa}\nexample.com ${ecdsa}\nexample.com ${HOST_KEY}\n`,
    }));
    expect(await scanHostKey(TARGET, runner)).toBe(HOST_KEY);
    expect(runner).toHaveBeenCalledWith('ssh-keyscan', [
      '-T', '5', '-p', '22', '-t', 'ed25519,ecdsa,rsa', 'example.com',
    ]);
    runner.mockResolvedValue({ code: 0, stdout: `example.com ${rsa}\nexample.com ${ecdsa}\n` });
    expect(await scanHostKey(TARGET, runner)).toBe(ecdsa);
    runner.mockResolvedValue({ code: 0, stdout: `example.com ${rsa}\n` });
    expect(await scanHostKey(TARGET, runner)).toBe(rsa);
    runner.mockResolvedValue({ code: 1, stdout: `example.com ${HOST_KEY}\n` });
    expect(await scanHostKey(TARGET, runner)).toBeNull();
    runner.mockResolvedValue({ code: 0, stdout: '# no identity\nexample.com ssh-ed25519 invalid\n' });
    expect(await scanHostKey(TARGET, runner)).toBeNull();
  });
});
