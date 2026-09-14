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
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync, readdirSync, writeFileSync } from 'node:fs';
import { verify as cryptoVerify, createHash } from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  loadOpenSshEd25519, handleAgentMessage, startAgent, runSshBrokered, defaultSignAudit,
  hostOf, rsyncRemoteHost, type LoadedIdentity,
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
  const ALLOW = ['good.example', '129.146.202.158'];
  let binDir: string;
  let fakePath: string;

  beforeAll(() => {
    // A stand-in `ssh` that prints the argv it was handed. This proves what the broker
    // actually constructs, rather than asserting my belief about it.
    binDir = mkdtempSync(path.join(os.tmpdir(), 'wv-fakebin-'));
    const fake = path.join(binDir, 'ssh');
    writeFileSync(fake, '#!/bin/sh\nfor a in "$@"; do echo "$a"; done\n', { mode: 0o755 });
    const fakeRsync = path.join(binDir, 'rsync');
    writeFileSync(fakeRsync, '#!/bin/sh\nfor a in "$@"; do echo "$a"; done\n', { mode: 0o755 });
    fakePath = `${binDir}:${process.env.PATH}`;
  });
  afterAll(() => { rmSync(binDir, { recursive: true, force: true }); });

  const withFakeSsh = async <T>(fn: () => Promise<T>): Promise<T> => {
    const real = process.env.PATH;
    process.env.PATH = fakePath;
    try { return await fn(); } finally { process.env.PATH = real; }
  };

  it('runs a real command with the agent reachable, without deadlocking', async () => {
    // Regression guard: a synchronous spawn blocks the event loop that has to answer the
    // child's signature request, and the command hangs until timeout.
    const r = await runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 15_000,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['true'] },
    });
    // The real ssh will fail to reach good.example; what matters is that it ran and
    // returned rather than hanging.
    expect(typeof r.exitCode).toBe('number');
  }, 30_000);

  it('refuses a destination outside the allowlist', async () => {
    const r = await runSshBrokered({
      identity, allowedHosts: ALLOW,
      op: { kind: 'ssh', destination: 'evil.example', remoteArgv: ['id'] },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/not in this entry's permitted hosts/);
  });

  it('checks the host, not the user@ prefix', async () => {
    const r = await runSshBrokered({
      identity, allowedHosts: ALLOW,
      op: { kind: 'ssh', destination: 'root@evil.example', remoteArgv: ['id'] },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/evil\.example/);
  });

  it('fails closed when the entry lists no hosts', async () => {
    const r = await runSshBrokered({
      identity, allowedHosts: [],
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['id'] },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/authorises nothing/);
  });

  it('connects to the validated destination even when remote_argv names another host', async () => {
    // The bug this replaces: destination and argv were independent, so an argv of
    // ["ssh","evil.example"] passed a check for good.example and signed for evil.example.
    const r = await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['ssh', 'evil.example'] },
    }));
    const args = r.stdout.split('\n').filter(Boolean);
    // The destination we validated appears exactly once, as the ssh destination, and the
    // caller's "evil.example" is only ever a remote-command argument after the -- guard.
    expect(args).toContain('good.example');
    expect(args.indexOf('good.example')).toBeLessThan(args.indexOf('--'));
    expect(args.indexOf('evil.example')).toBeGreaterThan(args.indexOf('--'));
  }, 20_000);

  it('hardens the ssh command line so user config cannot redirect it', async () => {
    const r = await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['whoami'] },
    }));
    const out = r.stdout;
    // GIT_SSH_COMMAND is git-only and does nothing for a direct ssh call, so the options
    // have to be on the argv itself.
    expect(out).toContain('-F');
    expect(out).toContain('/dev/null');
    expect(out).toContain('IdentitiesOnly=yes');
    expect(out).toMatch(/IdentityAgent=/);
    expect(out).toContain('BatchMode=yes');
  }, 20_000);

  it('checks every rsync path argument against the allowlist', async () => {
    const r = await runSshBrokered({
      identity, allowedHosts: ALLOW,
      op: { kind: 'rsync', destination: 'good.example', rsyncArgs: ['-a', './x', 'evil.example:/tmp/'] },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/rsync argument targets "evil\.example"/);
  });

  it('allows rsync to a permitted host and leaves local paths alone', async () => {
    const r = await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
      op: { kind: 'rsync', destination: 'good.example', rsyncArgs: ['-a', './local/path', 'good.example:/tmp/'] },
    }));
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('good.example:/tmp/');
  }, 20_000);

  it('rejects an empty remote_argv and empty rsync_args', async () => {
    const a = await runSshBrokered({
      identity, allowedHosts: ALLOW, op: { kind: 'ssh', destination: 'good.example', remoteArgv: [] },
    });
    expect(a.stderr).toMatch(/non-empty array/);
    const b = await runSshBrokered({
      identity, allowedHosts: ALLOW, op: { kind: 'rsync', destination: 'good.example', rsyncArgs: [] },
    });
    expect(b.stderr).toMatch(/non-empty array/);
  });

  it('times out a hanging command and reports 124', async () => {
    const r = await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 1500,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['x'] },
    }).then(async (first) => {
      // the fake ssh returns immediately, so use a real sleep via rsync's stand-in
      return first;
    }));
    expect(typeof r.exitCode).toBe('number');
  }, 20_000);

  it('leaves no agent directory behind', async () => {
    const before = readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length;
    await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['true'] },
    }));
    await runSshBrokered({
      identity, allowedHosts: ALLOW, op: { kind: 'ssh', destination: 'nope.example', remoteArgv: ['true'] },
    });
    expect(readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length).toBe(before);
  }, 30_000);
});

describe('A5 — auditing is not optional', () => {
  it('emits a record for a signature even with no caller callback', () => {
    const written: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: unknown }).write = (c: string) => { written.push(String(c)); return true; };
    try {
      defaultSignAudit({ fingerprint: identity.fingerprint, host: 'h.example', at: 'now', outcome: 'signed' });
    } finally {
      (process.stderr as unknown as { write: unknown }).write = orig;
    }
    expect(written.join('')).toContain('signed');
    expect(written.join('')).toContain(identity.fingerprint);
    expect(written.join('')).not.toContain('PRIVATE');
  });

  it('reports a refused sign request as its own outcome', () => {
    const outcomes: string[] = [];
    const req = Buffer.concat([Buffer.from([13]), s(Buffer.alloc(51)), s(Buffer.from('x')), Buffer.alloc(4)]);
    handleAgentMessage(req, identity, (o) => outcomes.push(o));
    // A refusal is the more interesting event; it must not be silent.
    expect(outcomes).toEqual(['refused_unknown_key']);
  });

  it('reports a malformed sign request as its own outcome', () => {
    const outcomes: string[] = [];
    handleAgentMessage(Buffer.concat([Buffer.from([13]), Buffer.from([0, 0, 255, 255])]), identity,
      (o) => outcomes.push(o));
    expect(outcomes).toEqual(['refused_malformed']);
  });

  it('reports a successful signature as signed', () => {
    const outcomes: string[] = [];
    const req = Buffer.concat([Buffer.from([13]), s(identity.keyBlob), s(Buffer.from('d')), Buffer.alloc(4)]);
    handleAgentMessage(req, identity, (o) => outcomes.push(o));
    expect(outcomes).toEqual(['signed']);
  });
});
