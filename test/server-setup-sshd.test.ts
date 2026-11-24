import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BrokerOps } from '../src/broker-ops.js';
import { SigningState } from '../src/wallet.js';
import { sshHostSha } from '../src/ssh-pin.js';
import { runSetup, runChangeCheck, runRemoveOrAccept, runListKeys, adminDestination, bundledScript, SetupRecords, validateServerOrder } from '../src/server-setup.js';
import { JobStore, runJob, runDue, type JobDefinition, type JobRoute } from '../src/jobs.js';

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
  // describe.skip still runs this body while collecting: without the switch, start nothing.
  if (!process.env.WV_SSHD_SETUP_TEST) { it('needs WV_SSHD_SETUP_TEST=1', () => {}); return; }
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
  function unapproved(id: string, user: string, keyFile: string) {
    const e = entry(id, user, keyFile, false) as Record<string, unknown>;
    const policy = gcm(Buffer.from(JSON.stringify({ v: 1, entry_id: id, version: 1, kind: 'stamped', stamped: { approved: [] } })));
    return { ...e, policy_ciphertext: policy.ct, policy_nonce: policy.nonce };
  }
  const entries: Record<string, unknown> = {
    'entry-admin-1': entry('entry-admin-1', 'opc', 'admin', true),
    'entry-daily-1': entry('entry-daily-1', 'wv-agent', 'daily', false),
  };
  const ops = new BrokerOps('Tester', 'k', ENC_KEY_B64, 'http://127.0.0.1:1', null,
    new SigningState(path.join(base, 'ledger.json')), {}, { pinsPath: path.join(base, 'pins.json') });
  (ops as unknown as { api: unknown }).api = {
    getSecret: async (id: string) => entries[id],
    getSecretMeta: async (id: string) => entries[id],
    adminAccessStatus: async () => ({ admin: true, open: adminOpen, until: null }),
    ensureVaultKey: async () => VAULT_KEY,
  };
  let adminOpen = true;
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

  it('End now ends the agent\'s OWN ssh session on the server within seconds (whole-build F1)', async () => {
    adminOpen = true;
    const o = await ops.sshAgentOpen({ entryId: 'entry-admin-1', purpose: 'agent work',
      op: { kind: 'ssh', destination: `opc@127.0.0.1:${PORT}`, remoteArgv: ['true'] } as never });
    if ('error' in o) throw new Error(o.error);
    // Two of the agent's own connections on the signing socket, and one other session (another
    // agent) whose tag differs: only this session's are ended.
    const own = (cmd: string, sock: string, pubp: string, kh: string) => new Promise<{ out: string; at: number }>((res) => {
      const c = spawn('ssh', ['-F', '/dev/null', '-o', `IdentityFile=${pubp}`, '-o', 'IdentitiesOnly=yes', '-o', `IdentityAgent=${sock}`,
        '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${kh}`, '-p', String(PORT), 'opc@127.0.0.1', cmd],
      { stdio: ['ignore', 'pipe', 'pipe'] });
      let b = ''; c.stdout.on('data', (d) => { b += d; }); c.stderr.on('data', (d) => { b += d; });
      const t = setTimeout(() => c.kill('SIGKILL'), 60_000);
      c.on('close', () => { clearTimeout(t); res({ out: b, at: Date.now() }); });
    });
    const other = await ops.sshAgentOpen({ entryId: 'entry-admin-1', purpose: 'other agent',
      op: { kind: 'ssh', destination: `opc@127.0.0.1:${PORT}`, remoteArgv: ['true'] } as never });
    if ('error' in other) throw new Error(other.error);
    // A connection held open with no command yet (ControlMaster), to start commands after End now.
    const cp = path.join(base, 'cm-end');
    const sshBase = ['-F', '/dev/null', '-o', `IdentityFile=${o.public_key_path}`, '-o', 'IdentitiesOnly=yes', '-o', `IdentityAgent=${o.socket_path}`,
      '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${o.known_hosts_path}`, '-p', String(PORT)];
    await new Promise<void>((resolve, reject) => {
      const c = spawn('ssh', [...sshBase, '-o', 'ControlMaster=yes', '-o', `ControlPath=${cp}`, '-o', 'ControlPersist=60', '-fN', 'opc@127.0.0.1'], { stdio: 'ignore' });
      c.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`master exit ${code}`))));
    });
    const viaMaster = (cmd: string) => new Promise<string>((res) => {
      const c = spawn('ssh', [...sshBase, '-o', `ControlPath=${cp}`, 'opc@127.0.0.1', cmd], { stdio: ['ignore', 'pipe', 'pipe'] });
      let b = ''; c.stdout.on('data', (d) => { b += d; }); c.stderr.on('data', (d) => { b += d; });
      c.on('close', () => res(b));
    });
    expect(await viaMaster('echo master-ok')).toContain('master-ok');
    const a = own('echo in-$(id -un); sleep 120', o.socket_path, o.public_key_path, o.known_hosts_path!);
    const b = own('echo in2; sleep 120', o.socket_path, o.public_key_path, o.known_hosts_path!);
    const keep = own('echo kept; sleep 25; echo still-here', other.socket_path, other.public_key_path, other.known_hosts_path!);
    await new Promise((r) => setTimeout(r, 4_000));
    // End now for THIS session only (the poll answers closed for it).
    const flip = Date.now();
    ops.closeSsh(o.session_id, 'admin_access_ended');
    const [ra, rb] = await Promise.all([a, b]);
    expect(ra.out).toContain('in-opc');
    expect(rb.out).toContain('in2');
    expect(ra.at - flip).toBeLessThan(8_000);
    expect(rb.at - flip).toBeLessThan(8_000);
    // r2 F1: the held-open connection cannot start a command after End now.
    const after = await viaMaster('echo SHOULD-NOT-RUN');
    expect(after).not.toContain('SHOULD-NOT-RUN');
    expect(after).toContain('admin access was ended');
    try { execFileSync('ssh', [...sshBase, '-o', `ControlPath=${cp}`, '-O', 'exit', 'opc@127.0.0.1'], { stdio: 'ignore' }); } catch { /* gone */ }
    const rk = await keep;
    expect(rk.out).toContain('still-here');           // the other session was not touched
    ops.closeSsh(other.session_id);
  }, 90_000);

  // ── Vault jobs (phases 1 + 2) against the same real sshd ──────────────────
  it('phase 1: the key list runs with the everyday key and fingerprints match removal', async () => {
    const rec = records.get('entry-admin-1')!;
    const r = await runListKeys(ops, rec, adminDestination(rec));
    expect(r.ok).toBe(true);
    expect(r.lines[0]).toMatch(/^PASS listed \d+ sign-in keys$/);
    expect(r.lines.some((l) => /^KEY\twv-agent\t[0-9a-f]{16}\twundervault-everyday\tno$/.test(l))).toBe(true);
    expect(r.lines.filter((l) => l.endsWith('\tyes')).length).toBe(2);
    expect(r.lines.join('\n')).not.toMatch(/AAAA/);
    expect((await runListKeys(ops, rec, 'opc@198.51.100.7')).ok).toBe(false);   // another server: refused, nothing run
  }, 60_000);

  const job = (patch: Partial<JobDefinition> = {}): JobDefinition => ({
    v: 1, type: 'job-set', broker: 'fp', order_id: 'order-job-0001', issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 10 * 60_000).toISOString(), job_id: 'job-real-0001', version: 1,
    name: 'Nightly report', entry_id: 'entry-daily-1', destination: `wv-agent@127.0.0.1:${PORT}`,
    argv: ['sh', '-c', 'echo backup-ok; id -un'], schedule: { kind: 'every', hours: 1, tz: 'UTC' }, timeout_s: 60, ...patch,
  });

  it('phase 2: a job runs on the real server with the everyday key, output kept privately', async () => {
    const out = path.join(base, 'job-output');
    const run = await runJob(ops, { def: job(), agent_id: 'a'.repeat(32), state: 'active', applied_at: new Date().toISOString() }, 'schedule', out);
    expect(run).toMatchObject({ ok: true, exit_code: 0 });
    const file = path.join(out, 'job-real-0001', `${run.run_id}.out`);
    expect(fs.readFileSync(file, 'utf8')).toBe('backup-ok\nwv-agent\n');
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  }, 60_000);

  it('phase 2: a nonzero exit is a failed run, not an error', async () => {
    const run = await runJob(ops, { def: job({ argv: ['sh', '-c', 'echo half; exit 3'] }), agent_id: 'a'.repeat(32), state: 'active', applied_at: new Date().toISOString() }, 'schedule', path.join(base, 'job-output'));
    expect(run).toMatchObject({ ok: false, exit_code: 3 });
    expect(run.error).toBeUndefined();
  }, 60_000);

  it('phase 2: the key check takes everyday keys only; an admin key is refused', async () => {
    expect(await ops.jobKeyCheck('entry-daily-1')).toEqual({ ok: true });
    expect(await ops.jobKeyCheck('entry-admin-1')).toMatchObject({ ok: false });
  }, 30_000);

  it('phase 2: a server not yet approved for the key refuses AT ONCE (never waits for the owner)', async () => {
    entries['entry-new-1'] = unapproved('entry-new-1', 'wv-agent', 'daily');
    const t0 = Date.now();
    const run = await runJob(ops, { def: job({ entry_id: 'entry-new-1' }), agent_id: 'a'.repeat(32), state: 'active', applied_at: new Date().toISOString() }, 'schedule', path.join(base, 'job-output'));
    expect(Date.now() - t0).toBeLessThan(15_000);
    expect(run).toMatchObject({ ok: false, exit_code: -1 });
    expect(run.error).toMatch(/not approved for this key yet/);
  }, 60_000);

  it('phase 2: the scheduler runs a due job once through the real ops, then not again in the same slot', async () => {
    const store = new JobStore(path.join(base, 'state', 'jobs.json'));
    const agentKey = 'b'.repeat(32);
    const applied = new Date(Date.now() - 61 * 60_000);
    expect(store.apply(job({ job_id: 'job-real-0002', order_id: 'order-job-0002', issued_at: applied.toISOString(),
      expires_at: new Date(applied.getTime() + 10 * 60_000).toISOString() }), agentKey, applied)).toEqual({ ok: true });
    const posted: unknown[] = []; const recorded: unknown[] = [];
    const route: JobRoute = {
      agent_id: agentKey, ops, outputDir: path.join(base, 'job-output'),
      getJobs: async () => ({ jobs: [{ id: 'job-real-0002', version: 1, state: 'active', run_now: false }] }),
      postJobRun: async (_id, body) => { posted.push(body); },
      authorize: (def) => ops.jobKeyCheck(def.entry_id),
      recordRun: async (_j, run) => { recorded.push(run); },
    };
    await runDue({ store, routes: [route], now: new Date(), running: new Set() });
    await runDue({ store, routes: [route], now: new Date(), running: new Set() });
    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({ ok: true, exit_code: 0, trigger: 'schedule' });
    expect(JSON.stringify(posted[0])).not.toMatch(/backup-ok|wv-agent|127\.0\.0\.1/);   // the site never gets output or server
    expect(recorded).toHaveLength(1);
  }, 90_000);
});
