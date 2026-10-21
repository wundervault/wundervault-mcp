import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BrokerOps } from '../src/broker-ops.js';

/**
 * An SSH session's files stay reachable by the agent under the macOS LaunchDaemon's umask.
 *
 * The broker opens each session in <runtime>/ssh/<id>/ (a socket and id.pub). Only the
 * leaf was chmodded, so the recursive mkdir made `ssh/` with its mode masked by the
 * daemon's Umask 0077: 0700, owned by the broker's account, and every vault_ssh_exec on a
 * Mac failed with "couldn't read the broker's id.pub file: Permission denied" (the owner's
 * Mac, 2026-10-21). Linux never showed it: its unit has no UMask, so `ssh/` came out 0755.
 *
 * process.umask() can't be set in vitest's worker threads, so the first test applies the
 * Mac's umask to every directory mkdirSync creates, the way the kernel would; the second
 * needs no umask at all: it starts from the 0700 `ssh/` the owner's Mac really had.
 */

const VAULT_KEY = Buffer.alloc(32, 9);
const ENC_KEY_B64 = Buffer.alloc(32, 7).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const HOST = 'host.example';

let base: string;
let run: string;
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

/** A broker whose vault serves one real, unencrypted ed25519 key for HOST. */
function brokerWithSshKey(): BrokerOps {
  const keyFile = path.join(base, 'k');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', keyFile]);
  const enc = gcm(fs.readFileSync(keyFile));
  const ops = new BrokerOps('Tester', 'k', ENC_KEY_B64, 'http://127.0.0.1:1', null);
  (ops as unknown as { api: unknown }).api = {
    getSecret: async () => ({
      name: 'ssh1', entry_mode: 'BROKER_SSH_AGENT', access_tier: '1',
      encrypted_content: enc.ct, content_nonce: enc.nonce,
      exec_config: JSON.stringify({ delivery: 'ssh', ssh_hosts: [HOST] }),
    }),
    ensureVaultKey: async () => VAULT_KEY,
  };
  return ops;
}

async function open(ops: BrokerOps) {
  const r = await ops.sshAgentOpen({
    entryId: 'ssh1', purpose: 'test',
    op: { kind: 'ssh', destination: `debian@${HOST}`, remoteArgv: ['true'] },
  });
  if ('error' in r) throw new Error(`open refused: ${JSON.stringify(r)}`);
  return r;
}

const mode = (p: string) => fs.statSync(p).mode & 0o777;

beforeEach(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-sshdir-'));
  run = path.join(base, 'run');
  fs.mkdirSync(run, { recursive: true });
  fs.chmodSync(run, 0o755);
  setEnv('WUNDERVAULT_RUNTIME_DIR', run);
  setEnv('WUNDERVAULT_SYSTEM_ROOT', path.join(base, 'state'));
  setEnv('WUNDERVAULT_USER_ROOT', path.join(base, 'home', '.wundervault'));
});

/** mkdirSync as it behaves under umask 0077 (the LaunchDaemon's Umask 63). */
function macUmask() {
  const real = fs.mkdirSync.bind(fs);
  return vi.spyOn(fs, 'mkdirSync').mockImplementation(((p: fs.PathLike, o?: fs.MakeDirectoryOptions) => {
    const made: string[] = [];
    for (let d = path.resolve(String(p)); !fs.existsSync(d); d = path.dirname(d)) made.push(d);
    const r = real(p, o);
    const want = (typeof o === 'object' && o?.mode !== undefined ? Number(o.mode) : 0o777) & ~0o077;
    for (const d of made) fs.chmodSync(d, want);
    return r;
  }) as typeof fs.mkdirSync);
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
  fs.rmSync(base, { recursive: true, force: true });
});

describe('an SSH session under umask 0077', () => {
  it('leaves every directory on the way to id.pub and the socket traversable', async () => {
    macUmask();
    const ops = brokerWithSshKey();
    const r = await open(ops);
    try {
      // Passable, not listable: the live session ids stay private (round 1, B1).
      expect(mode(path.join(run, 'ssh'))).toBe(0o711);
      expect(mode(path.dirname(r.public_key_path)) & 0o005).toBe(0o005);
      expect(mode(r.public_key_path) & 0o004).toBe(0o004);
      expect(path.dirname(r.socket_path)).toBe(path.dirname(r.public_key_path));
    } finally {
      ops.closeSsh(r.session_id);
    }
  });

  it('repairs an ssh/ directory a broken version already left at 0700', async () => {
    fs.mkdirSync(path.join(run, 'ssh'));
    fs.chmodSync(path.join(run, 'ssh'), 0o700);  // the owner's Mac, as found
    const ops = brokerWithSshKey();
    const r = await open(ops);
    try {
      expect(mode(path.join(run, 'ssh'))).toBe(0o711);
    } finally {
      ops.closeSsh(r.session_id);
    }
  });
});
