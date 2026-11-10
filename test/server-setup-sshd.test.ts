import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BrokerOps } from '../src/broker-ops.js';
import { SigningState } from '../src/wallet.js';
import { sshHostSha } from '../src/ssh-pin.js';
import { runSetup, runChangeCheck, runRemoveOrAccept, bundledScript, SetupRecords, validateServerOrder } from '../src/server-setup.js';

/**
 * Site SPEC-admin-access checks 9, 25, 27 against a REAL sshd: the helper's own setup runner,
 * through BrokerOps.serverRun (host pin, admin gate, certificate), on a FRESH throwaway
 * container (image from packaging/server/test-setup.sh). Never a real server.
 *   WV_SSHD_SETUP_TEST=1 npx vitest run test/server-setup-sshd.test.ts
 */
const runIt = process.env.WV_SSHD_SETUP_TEST ? describe : describe.skip;
const NAME = 'wv-setup-test';
const PORT = 2298;
const VAULT_KEY = Buffer.alloc(32, 9);
const ENC_KEY_B64 = Buffer.alloc(32, 7).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function sh(cmd: string, args: string[], input?: string): string {
  return execFileSync(cmd, args, { encoding: 'utf8', ...(input !== undefined ? { input } : {}) });
}
function gcm(plaintext: Buffer) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, nonce);
  const body = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { ct: body.toString('base64'), nonce: nonce.toString('base64') };
}

runIt('guided setup against a real sshd', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-setup-'));
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(base, 'run');
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(base, 'state');
  process.env.WUNDERVAULT_USER_ROOT = path.join(base, 'home', '.wundervault');
  fs.mkdirSync(process.env.WUNDERVAULT_RUNTIME_DIR, { recursive: true });
  fs.mkdirSync(process.env.WUNDERVAULT_SYSTEM_ROOT, { recursive: true });
  for (const k of ['admin', 'daily', 'emerg', 'sneaky']) sh('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', k, '-f', path.join(base, k)]);
  const pub = (k: string) => fs.readFileSync(path.join(base, `${k}.pub`), 'utf8').trim().split(' ').slice(0, 2).join(' ');

  sh('podman', ['rm', '-f', NAME]);
  sh('podman', ['run', '-d', '--name', NAME, '-p', `127.0.0.1:${PORT}:22`, 'localhost/wv-admin-test:1']);
  afterAll(() => { if (!process.env.WV_KEEP) try { sh('podman', ['rm', '-f', NAME]); } catch { /* gone */ } });
  sh('sleep', ['1']);
  sh('podman', ['exec', '-i', NAME, 'sh', '-c',
    'install -d -o opc -g opc -m 700 /home/opc/.ssh; cat > /home/opc/.ssh/authorized_keys; chown opc:opc /home/opc/.ssh/authorized_keys; chmod 600 /home/opc/.ssh/authorized_keys; echo secret=1 > /home/opc/.env; chmod 755 /home/opc'],
  pub('admin') + ' admin\n');
  const hostKey = sh('ssh-keyscan', ['-p', String(PORT), '-t', 'ed25519', '127.0.0.1']).split('\n')
    .find((l) => l.includes('ssh-ed25519'))!.split(' ').slice(1, 3).join(' ');

  function entry(id: string, user: string, keyFile: string, admin: boolean) {
    const enc = gcm(fs.readFileSync(path.join(base, keyFile)));
    const target = { user, host: '127.0.0.1', port: PORT };
    const policy = gcm(Buffer.from(JSON.stringify({ v: 1, entry_id: id, version: 1, kind: 'stamped',
      stamped: { approved: [{ recipe_sha256: sshHostSha(target, hostKey), ssh: { ...target, host_key: hostKey } }] } })));
    return {
      name: id, entry_mode: 'BROKER_SSH_AGENT', access_tier: admin ? '2' : '1',
      ...(admin ? { admin_access: true, admin_until: new Date(Date.now() + 10 * 60_000).toISOString() } : {}),
      encrypted_content: enc.ct, content_nonce: enc.nonce,
      exec_config: JSON.stringify({ delivery: 'ssh', ssh_hosts: [] }),
      setup: { delivery: 'ssh', ask: true, ssh_hosts: [] },
      policy_ciphertext: policy.ct, policy_nonce: policy.nonce,
    };
  }
  const entries: Record<string, unknown> = {
    'entry-admin-1': entry('entry-admin-1', 'opc', 'admin', true),
    'entry-daily-1': entry('entry-daily-1', 'wv-agent', 'daily', false),
  };
  const ops = new BrokerOps('Tester', 'k', ENC_KEY_B64, 'http://127.0.0.1:1', null,
    new SigningState(path.join(base, 'ledger.json')), {}, { pinsPath: path.join(base, 'pins.json') });
  (ops as unknown as { api: unknown }).api = {
    getSecret: async (id: string) => entries[id],
    adminAccessStatus: async () => ({ admin: true, open: true, until: null }),
    ensureVaultKey: async () => VAULT_KEY,
  };
  const records = new SetupRecords(path.join(base, 'state', 'server-setups.json'));
  const now = Date.now();
  const v = validateServerOrder({ v: 1, type: 'setup', broker: 'fp', order_id: 'order-real-0001', issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 15 * 60_000).toISOString(), entry_id: 'entry-admin-1', destination: `opc@127.0.0.1:${PORT}`,
    everyday_user: 'wv-agent', everyday_entry_id: 'entry-daily-1', everyday_pub: pub('daily'), emergency_pub: pub('emerg'), logs: true }, 'fp', now);
  if (!v.ok || v.order.type !== 'setup') throw new Error(JSON.stringify(v));
  const order = v.order;
  const plainSsh = (user: string, key: string) => {
    try {
      sh('ssh', ['-F', '/dev/null', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=ERROR',
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'CertificateFile=/dev/null', '-i', path.join(base, key),
        '-p', String(PORT), `${user}@127.0.0.1`, 'echo in']);
      return true;
    } catch { return false; }
  };

  it.runIf(!!process.env.WV_DEBUG)('debug cert', async () => {
    sh('podman', ['exec', '-i', NAME, 'sh', '-c', 'cat >> /home/opc/.ssh/authorized_keys'], `cert-authority,principals="wv-admin" ${pub('admin')} ca\n`);
    for (const offer of [undefined, 'cert'] as const) {
      const o = await ops.sshAgentOpen({ entryId: 'entry-admin-1', purpose: 'dbg', op: { kind: 'ssh', destination: `opc@127.0.0.1:${PORT}`, remoteArgv: ['true'] } as never, ...(offer ? { offer } : {}) });
      if ('error' in o) throw new Error(o.error);
      const out: string = await new Promise((res) => {
        const c = spawn('ssh', ['-vvv', '-F', '/dev/null', '-o', `IdentityFile=${o.public_key_path}`, '-o', 'IdentitiesOnly=yes', '-o', `IdentityAgent=${o.socket_path}`, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${o.known_hosts_path}`, '-p', String(PORT), 'opc@127.0.0.1', 'echo hi'], { stdio: ['ignore', 'pipe', 'pipe'] });
        let b = ''; c.stdout.on('data', (d) => { b += d; }); c.stderr.on('data', (d) => { b += d; });
        c.on('close', () => res(b));
      });
      console.log(String(offer), out.split('\n').filter((l) => /Offering|Server accepts|agent|sign|Authenticated|denied|cert|Will attempt/i.test(l)).join('\n'));
      ops.closeSsh(o.session_id);
    }
  }, 60_000);

  it('every self-test line passes; the plain admin key is then refused; the emergency key works', async () => {
    const r = await runSetup(ops, order, bundledScript(), records);
    expect(r.lines.filter((l) => l.startsWith('FAIL'))).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.lines.filter((l) => l.startsWith('PASS')).length).toBeGreaterThanOrEqual(12);
    expect(plainSsh('opc', 'admin')).toBe(false);
    expect(plainSsh('opc', 'emerg')).toBe(true);
    expect(records.get('entry-admin-1')?.everyday_destination).toBe(`wv-agent@127.0.0.1:${PORT}`);
  }, 120_000);

  it('running setup again is safe (check 9)', async () => {
    const r = await runSetup(ops, order, bundledScript(), records);
    expect(r.lines.filter((l) => l.startsWith('FAIL'))).toEqual([]);
    expect(plainSsh('opc', 'emerg')).toBe(true);
  }, 120_000);

  it('change check: nothing, then a sneaky key, then Remove takes exactly it out (check 27)', async () => {
    const rec = records.get('entry-admin-1')!;
    const quiet = await runChangeCheck(ops, rec);
    expect(quiet).toEqual({ ok: true, changed: false, lines: [] });
    sh('podman', ['exec', '-i', NAME, 'sh', '-c', 'cat >> /home/opc/.ssh/authorized_keys'], pub('sneaky') + ' sneaky\n');
    const found = await runChangeCheck(ops, rec);
    if (!found.ok) throw new Error(found.error);
    expect(found.changed).toBe(true);
    const line = found.lines.find((l) => l.startsWith('NEW\tkey\topc\t'))!;
    expect(line).toMatch(/sneaky$/);
    expect(found.lines.join('\n')).not.toMatch(/AAAA/);         // no key material in the report
    const fp = line.split('\t')[3]!;
    expect(plainSsh('opc', 'sneaky')).toBe(true);
    const rm = await runRemoveOrAccept(ops, { type: 'remove-key', order_id: 'order-real-0002', entry_id: 'entry-admin-1',
      destination: `opc@127.0.0.1:${PORT}`, user: 'opc', fp }, bundledScript());
    expect(rm.ok).toBe(true);
    expect(plainSsh('opc', 'sneaky')).toBe(false);
    expect(plainSsh('opc', 'emerg')).toBe(true);
    expect(await runChangeCheck(ops, rec)).toEqual({ ok: true, changed: false, lines: [] });
  }, 120_000);

  it('Remove refuses the emergency and certificate lines', async () => {
    const ak = sh('podman', ['exec', NAME, 'cat', '/home/opc/.ssh/authorized_keys']).split('\n').filter(Boolean);
    for (const l of ak) {
      const fp = crypto.createHash('sha256').update(l).digest('hex').slice(0, 16);
      const r = await runRemoveOrAccept(ops, { type: 'remove-key', order_id: 'order-real-0003', entry_id: 'entry-admin-1',
        destination: `opc@127.0.0.1:${PORT}`, user: 'opc', fp }, bundledScript());
      expect(r.ok).toBe(false);
    }
    expect(plainSsh('opc', 'emerg')).toBe(true);
  }, 120_000);
});
