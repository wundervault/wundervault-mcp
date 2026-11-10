import { describe, it, expect } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BrokerOps } from '../src/broker-ops.js';
import { loadOpenSshEd25519 } from '../src/ssh-agent.js';
import { adminCertificate } from '../src/ssh-cert.js';

/**
 * Site SPEC-admin-access D13 / check 19, against a REAL sshd: the server ends an admin
 * session when admin access ends, including a connection the agent opened with its OWN ssh
 * client on the helper's signing socket.
 *
 * Needs a test server whose admin account trusts the key only as a certificate authority
 * and has /usr/local/lib/wundervault/wv-admin-session installed:
 *   WV_SSHD_TEST=127.0.0.1:2299 WV_SSHD_USER=opc WV_SSHD_KEY=/path/to/admin_key npx vitest run test/admin-cert-sshd.test.ts
 * Skipped otherwise.
 */
const target = process.env.WV_SSHD_TEST;
const user = process.env.WV_SSHD_USER ?? 'opc';
const keyFile = process.env.WV_SSHD_KEY;
const run = target && keyFile ? describe : describe.skip;

const VAULT_KEY = Buffer.alloc(32, 9);
const ENC_KEY_B64 = Buffer.alloc(32, 7).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function gcm(plaintext: Buffer) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, nonce);
  const body = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { ct: body.toString('base64'), nonce: nonce.toString('base64') };
}

function sshArgs(socket: string, pub: string, extra: string[] = []): string[] {
  const [host, port] = target!.split(':');
  return ['-F', '/dev/null', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=ERROR',
    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', `IdentityFile=${pub}`, '-o', `IdentityAgent=${socket}`,
    '-p', port ?? '22', ...extra, `${user}@${host}`];
}

function sshRun(args: string[], cmd: string, timeoutMs = 60_000): Promise<{ code: number; out: string; ms: number }> {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const c = spawn('ssh', [...args, cmd], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    c.stdout.on('data', (d) => { out += d; });
    c.stderr.on('data', (d) => { out += d; });
    const t = setTimeout(() => c.kill('SIGKILL'), timeoutMs);
    c.on('close', (code) => { clearTimeout(t); resolve({ code: code ?? -1, out, ms: Date.now() - t0 }); });
  });
}

run('admin access is cut off by the server (real sshd)', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-cert-'));
  const run = path.join(base, 'run');
  fs.mkdirSync(run, { recursive: true });
  process.env.WUNDERVAULT_RUNTIME_DIR = run;
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(base, 'state');
  process.env.WUNDERVAULT_USER_ROOT = path.join(base, 'home', '.wundervault');

  function broker(untilMs: number): BrokerOps {
    const enc = gcm(fs.readFileSync(keyFile!));
    const ops = new BrokerOps('Tester', 'k', ENC_KEY_B64, 'http://127.0.0.1:1', null);
    (ops as unknown as { api: unknown }).api = {
      getSecret: async () => ({
        name: 'server admin', entry_mode: 'BROKER_SSH_AGENT', access_tier: '2', admin_access: true,
        admin_until: new Date(untilMs).toISOString(), encrypted_content: enc.ct, content_nonce: enc.nonce,
        exec_config: JSON.stringify({ delivery: 'ssh', ssh_hosts: [target!.split(':')[0]] }),
      }),
      adminAccessStatus: async () => ({ admin: true, open: true, until: new Date(untilMs).toISOString() }),
      ensureVaultKey: async () => VAULT_KEY,
    };
    return ops;
  }

  it('the agent\'s own ssh, opened inside admin access, is closed by the server at the end', async () => {
    const until = Date.now() + 12_000;
    const ops = broker(until);
    const r = await ops.sshAgentOpen({
      entryId: 'e', purpose: 'test', ttlSeconds: 300,
      op: { kind: 'ssh', destination: `${user}@${target!.split(':')[0]}`, remoteArgv: ['true'] },
    });
    if ('error' in r) throw new Error(JSON.stringify(r));
    // The agent's own ssh client: a long command on the helper's socket.
    const long = await sshRun(sshArgs(r.socket_path, r.public_key_path), 'echo in-$(id -un); sleep 120', 40_000);
    const endedLate = Date.now() - until;
    expect(long.out).toContain(`in-${user}`);
    // Closed by the server at the end (not by our 40 s kill): within a couple of seconds.
    expect(Math.abs(endedLate)).toBeLessThan(3_000);
    expect(long.code).not.toBe(0);
    ops.reset();
  }, 60_000);

  it('after the end the same certificate is refused, even with a fresh socket', async () => {
    const id = loadOpenSshEd25519(fs.readFileSync(keyFile!, 'utf8'));
    const cert = adminCertificate(id, { end: Math.floor(Date.now() / 1000) - 1, start: Math.floor(Date.now() / 1000) - 120 });
    expect(cert.length).toBeGreaterThan(100);
    const ops = broker(Date.now() + 8_000);
    const r = await ops.sshAgentOpen({
      entryId: 'e', purpose: 'test', ttlSeconds: 300,
      op: { kind: 'ssh', destination: `${user}@${target!.split(':')[0]}`, remoteArgv: ['true'] },
    });
    if ('error' in r) throw new Error(JSON.stringify(r));
    // A multiplexed master the agent keeps open past the end.
    const cp = path.join(base, 'cm');
    // Not execFileSync: the signing socket is served by this same process, and a blocking call
    // would stop it answering the signature ssh asks for.
    await new Promise<void>((resolve, reject) => {
      const c = spawn('ssh', sshArgs(r.socket_path, r.public_key_path, ['-o', 'ControlMaster=yes', '-o', `ControlPath=${cp}`,
        '-o', 'ControlPersist=60', '-fN']), { stdio: 'ignore' });
      c.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`master exit ${code}`))));
    });
    const inside = await sshRun(sshArgs(r.socket_path, r.public_key_path, ['-o', `ControlPath=${cp}`]), 'echo inside');
    expect(inside.out).toContain('inside');
    await new Promise((res) => setTimeout(res, 9_000));
    const after = await sshRun(sshArgs(r.socket_path, r.public_key_path, ['-o', `ControlPath=${cp}`]), 'echo SHOULD-NOT-RUN');
    expect(after.out).not.toContain('SHOULD-NOT-RUN');
    expect(after.out).toContain('admin access has ended');
    try { execFileSync('ssh', [...sshArgs(r.socket_path, r.public_key_path, ['-o', `ControlPath=${cp}`, '-O', 'exit'])], { stdio: 'ignore' }); } catch { /* gone */ }
    ops.reset();
  }, 60_000);
});
