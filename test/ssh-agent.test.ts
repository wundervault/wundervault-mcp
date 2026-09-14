/**
 * Acceptance checks for the ssh-agent broker (SPEC.md §A).
 *
 * Keys are generated with real `ssh-keygen` rather than hand-built fixtures: the whole
 * point of this module is to interoperate with OpenSSH, so a fixture that only matches
 * my own parser would prove nothing.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { verify as cryptoVerify, createHash } from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  loadOpenSshEd25519, handleAgentMessage, startAgent, runSshBrokered, type LoadedIdentity,
} from '../src/ssh-agent.js';

let dir: string;
let ed25519Pem: string;
let identity: LoadedIdentity;

function keygen(d: string, name: string, args: string[]): void {
  execFileSync('ssh-keygen', ['-q', '-N', '', '-f', path.join(d, name), ...args]);
}

/** SSH length-prefixed string, for building request frames by hand. */
function s(v: Buffer | string): Buffer {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length, 0);
  return Buffer.concat([len, b]);
}

beforeAll(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), 'wv-test-keys-'));
  keygen(dir, 'ed', ['-t', 'ed25519', '-C', 'broker@test']);
  ed25519Pem = readFileSync(path.join(dir, 'ed'), 'utf8');
  identity = loadOpenSshEd25519(ed25519Pem);
});

afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

describe('A1 — key loading', () => {
  it('parses an unencrypted ed25519 key to a 32-byte public key', () => {
    expect(identity.keyBlob.length).toBe(51);           // 4+11 + 4+32
    expect(identity.comment).toBe('broker@test');
  });

  it('derives the same fingerprint ssh-keygen does', () => {
    // The real cross-check: agreement with OpenSSH, not with my own code.
    const out = execFileSync('ssh-keygen', ['-lf', path.join(dir, 'ed.pub')]).toString();
    expect(identity.fingerprint).toBe(out.split(/\s+/)[1]);
  });

  it('refuses an encrypted key by naming the passphrase recipe', () => {
    keygen(dir, 'enc_tmp', ['-t', 'ed25519']);
    // -N '' then re-encrypt, because ssh-keygen wants a passphrase interactively otherwise
    execFileSync('ssh-keygen', ['-q', '-p', '-P', '', '-N', 'hunter2', '-f', path.join(dir, 'enc_tmp')]);
    expect(() => loadOpenSshEd25519(readFileSync(path.join(dir, 'enc_tmp'), 'utf8')))
      .toThrow(/passphrase-encrypted|ssh-passphrase/i);
  });

  it('refuses a non-ed25519 key by naming the supported type', () => {
    keygen(dir, 'rsa', ['-t', 'rsa', '-b', '2048']);
    expect(() => loadOpenSshEd25519(readFileSync(path.join(dir, 'rsa'), 'utf8')))
      .toThrow(/ssh-ed25519/);
  });

  it('refuses input that is not an OpenSSH key at all', () => {
    expect(() => loadOpenSshEd25519('not a key')).toThrow(/OpenSSH private key/);
  });

  it('refuses a truncated key body without a raw parse error', () => {
    const broken = ed25519Pem.replace(/\n[A-Za-z0-9+/=]{20}/, '\nAAAA');
    expect(() => loadOpenSshEd25519(broken)).toThrow();
  });
});

describe('A2 — agent protocol', () => {
  it('answers REQUEST_IDENTITIES with exactly one identity', () => {
    const r = handleAgentMessage(Buffer.from([11]), identity);
    expect(r[0]).toBe(12);
    expect(r.readUInt32BE(1)).toBe(1);
    const blobLen = r.readUInt32BE(5);
    expect(r.subarray(9, 9 + blobLen).equals(identity.keyBlob)).toBe(true);
  });

  it('signs for the loaded identity, and the signature verifies', () => {
    const data = Buffer.from('the data ssh would sign');
    const req = Buffer.concat([Buffer.from([13]), s(identity.keyBlob), s(data), Buffer.alloc(4)]);
    const r = handleAgentMessage(req, identity);
    expect(r[0]).toBe(14);

    const blob = r.subarray(5, 5 + r.readUInt32BE(1));
    const algLen = blob.readUInt32BE(0);
    expect(blob.subarray(4, 4 + algLen).toString()).toBe('ssh-ed25519');
    const sig = blob.subarray(8 + algLen, 8 + algLen + blob.readUInt32BE(4 + algLen));
    expect(sig.length).toBe(64);
    expect(cryptoVerify(null, data, identity.publicKey, sig)).toBe(true);
  });

  it('refuses to sign for a key it does not hold', () => {
    // Otherwise the agent would sign anything with whatever key it happens to have.
    const req = Buffer.concat([Buffer.from([13]), s(Buffer.alloc(51)), s(Buffer.from('x')), Buffer.alloc(4)]);
    expect(handleAgentMessage(req, identity)[0]).toBe(5);
  });

  it('fails unknown message types rather than throwing', () => {
    expect(handleAgentMessage(Buffer.from([99]), identity)[0]).toBe(5);
    expect(handleAgentMessage(Buffer.from([27]), identity)[0]).toBe(5);  // EXTENSION
    expect(handleAgentMessage(Buffer.alloc(0), identity)[0]).toBe(5);
  });

  it('fails a truncated sign request rather than throwing', () => {
    const req = Buffer.concat([Buffer.from([13]), Buffer.from([0, 0, 255, 255])]);
    expect(handleAgentMessage(req, identity)[0]).toBe(5);
  });

  it('fails a sign request whose declared string runs past the buffer', () => {
    const len = Buffer.alloc(4); len.writeUInt32BE(0x7fffffff, 0);
    expect(handleAgentMessage(Buffer.concat([Buffer.from([13]), len]), identity)[0]).toBe(5);
  });
});

describe('A2/A5 — real OpenSSH interoperability', () => {
  it('ssh-add lists the identity and can sign through the socket', async () => {
    const signs: unknown[] = [];
    const agent = startAgent(identity, (e) => signs.push(e), 'host.example');
    try {
      await new Promise((r) => setTimeout(r, 200));
      const env = { ...process.env, SSH_AUTH_SOCK: agent.socketPath };

      // execFile, NOT execFileSync: the agent's listener runs on THIS process's event
      // loop, so a synchronous child would block the very loop that has to answer it.
      // That deadlock is exactly what forced runSshBrokered to be async too.
      const { stdout: listed } = await execFileAsync('ssh-add', ['-l'], { env, timeout: 10_000 });
      expect(listed).toContain(identity.fingerprint);

      // -T makes the real ssh client request a signature AND verify it. If our wire
      // format were subtly wrong, this is what would catch it.
      await execFileAsync('ssh-add', ['-T', path.join(dir, 'ed.pub')], { env, timeout: 10_000 });
      expect(agent.signCount()).toBeGreaterThan(0);
      expect(signs.length).toBeGreaterThan(0);
      expect(JSON.stringify(signs[0])).toContain('host.example');
      expect(JSON.stringify(signs[0])).not.toContain('PRIVATE');
    } finally {
      agent.close();
    }
  }, 30_000);
});

describe('A3 — socket lifetime and permissions', () => {
  it('uses a 0700 directory and a 0600 socket', async () => {
    const agent = startAgent(identity, undefined, 'h');
    try {
      await new Promise((r) => setTimeout(r, 200));
      expect(statSync(path.dirname(agent.socketPath)).mode & 0o777).toBe(0o700);
      expect(statSync(agent.socketPath).mode & 0o777).toBe(0o600);
    } finally { agent.close(); }
  });

  it('removes the socket and its directory on close, and close is idempotent', () => {
    const agent = startAgent(identity, undefined, 'h');
    const d = path.dirname(agent.socketPath);
    agent.close();
    expect(existsSync(agent.socketPath)).toBe(false);
    expect(existsSync(d)).toBe(false);
    expect(() => agent.close()).not.toThrow();
  });

  it('never writes key material into the socket directory', async () => {
    const agent = startAgent(identity, undefined, 'h');
    try {
      await new Promise((r) => setTimeout(r, 200));
      const d = path.dirname(agent.socketPath);
      for (const f of readdirSync(d)) {
        const p = path.join(d, f);
        if (statSync(p).isFile()) {
          expect(readFileSync(p).includes('PRIVATE KEY')).toBe(false);
        }
      }
    } finally { agent.close(); }
  });
});

describe('A4 — brokered execution', () => {
  const ALLOW = ['129.146.202.158'];

  it('runs the command with the agent reachable, without deadlocking', async () => {
    // Regression guard: a synchronous spawn here blocks the event loop that has to
    // answer the child's signature request, and the command hangs until timeout.
    const r = await runSshBrokered({
      identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['ssh-add', '-l'], timeoutMs: 15_000,
    });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain(identity.fingerprint);
  }, 30_000);

  it('refuses a host outside the allowlist', async () => {
    const r = await runSshBrokered({
      identity, host: 'evil.example', allowedHosts: ALLOW, argv: ['ssh-add', '-l'],
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/not in this entry's permitted hosts/);
  });

  it('fails closed when the entry lists no hosts', async () => {
    // "unset" must not mean "anywhere" — that is how an allowlist becomes decoration.
    const r = await runSshBrokered({
      identity, host: 'anything', allowedHosts: [], argv: ['ssh-add', '-l'],
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/authorises nothing/);
  });

  it('rejects an empty argv', async () => {
    const r = await runSshBrokered({ identity, host: ALLOW[0], allowedHosts: ALLOW, argv: [] });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/non-empty array/);
  });

  it('passes argv without a shell', async () => {
    const r = await runSshBrokered({
      identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['printf', '%s', 'a;b|c$(id)'], timeoutMs: 10_000,
    });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe('a;b|c$(id)');     // literal, not interpreted
  }, 20_000);

  it('times out a hanging command and reports 124', async () => {
    const r = await runSshBrokered({
      identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['sleep', '30'], timeoutMs: 1500,
    });
    expect(r.exitCode).toBe(124);
    expect(r.stderr).toMatch(/timed out/);
  }, 20_000);

  it('reports a missing binary instead of throwing', async () => {
    const r = await runSshBrokered({
      identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['wv-no-such-binary-xyz'], timeoutMs: 5000,
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/Failed to run/);
  }, 20_000);

  it('leaves no agent directory behind, on success or timeout', async () => {
    const before = readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length;
    await runSshBrokered({ identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['true'], timeoutMs: 10_000 });
    await runSshBrokered({ identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['sleep', '30'], timeoutMs: 1200 });
    const after = readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length;
    expect(after).toBe(before);
  }, 30_000);
});
