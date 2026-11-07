import { describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const script = resolve('packaging/admin-key.sh');

function onPath(command: string): boolean {
  return spawnSync(
    'sh',
    ['-c', 'command -v "$1" >/dev/null 2>&1', 'sh', command],
    { stdio: 'ignore' },
  ).status === 0;
}

const supported = process.platform !== 'win32' && onPath('ssh-keygen');
const hasShellcheck = process.platform !== 'win32' && onPath('shellcheck');
const isRoot = typeof process.getuid !== 'function' || process.getuid() === 0;

type Fixture = {
  dir: string;
  sshDir: string;
  keysFile: string;
  tempDir: string;
  env: NodeJS.ProcessEnv;
};

function withFixture(run: (fixture: Fixture) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'wv-admin-key-test-'));
  const sshDir = join(dir, 'root-ssh');
  const tempDir = join(dir, 'tmp');
  mkdirSync(tempDir);
  try {
    run({
      dir,
      sshDir,
      keysFile: join(sshDir, 'authorized_keys'),
      tempDir,
      env: {
        ...process.env,
        WV_ADMIN_ROOT_SSH_DIR: sshDir,
        WV_ADMIN_NO_WAIT: '1',
        TMPDIR: tempDir,
      },
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function run(fixture: Fixture, args: string[] = []): string {
  return execFileSync('sh', [script, ...args], {
    env: fixture.env,
    encoding: 'utf8',
  });
}

function unrelatedKey(): string {
  return `ssh-ed25519 AAAA${randomBytes(32).toString('base64')} existing-owner-key\n`;
}

describe.skipIf(!supported)('admin-key.sh', () => {
  it('adds exactly one restricted admin key with private directory and file modes', () => {
    withFixture((fixture) => {
      expect(existsSync(fixture.sshDir)).toBe(false);

      run(fixture);

      expect(statSync(fixture.sshDir).mode & 0o777).toBe(0o700);
      expect(statSync(fixture.keysFile).mode & 0o777).toBe(0o600);
      const contents = readFileSync(fixture.keysFile, 'utf8');
      const lines = contents.trimEnd().split('\n');
      expect(lines).toHaveLength(1);
      expect(lines[0].startsWith(
        'from="127.0.0.1,::1",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc ssh-ed25519 ',
      )).toBe(true);
      expect(lines[0]).toContain(' wundervault-admin ');
      expect(contents.endsWith('\n')).toBe(true);
    });
  });

  it('prints the private key once and it matches the installed public key', () => {
    withFixture((fixture) => {
      const output = run(fixture);
      const match = output.match(
        /-----BEGIN OPENSSH PRIVATE KEY-----\r?\n[\s\S]*?-----END OPENSSH PRIVATE KEY-----/,
      );
      expect(match).not.toBeNull();
      expect(output.match(/-----BEGIN OPENSSH PRIVATE KEY-----/g)).toHaveLength(1);
      expect(output).toContain('Add a secret > SSH key');
      expect(output).toContain('For its server, type localhost');

      const privateKeyFile = join(fixture.dir, 'printed-key');
      writeFileSync(privateKeyFile, `${match![0]}\n`, { mode: 0o600 });
      const publicKey = execFileSync('ssh-keygen', ['-y', '-f', privateKeyFile], {
        env: fixture.env,
        encoding: 'utf8',
      });
      const installed = readFileSync(fixture.keysFile, 'utf8').trim().split(/\s+/);
      expect(publicKey.trim().split(/\s+/)[1]).toBe(installed[2]);
    });
  });

  it('leaves no private key directory or file in TMPDIR after adding', () => {
    withFixture((fixture) => {
      run(fixture);

      expect(readdirSync(fixture.tempDir)).toEqual([]);
      expect(readdirSync(fixture.sshDir)).toEqual(['authorized_keys']);
    });
  });

  it('preserves an unrelated key byte-for-byte and appends a fresh key each time', () => {
    withFixture((fixture) => {
      const unrelated = unrelatedKey();
      mkdirSync(fixture.sshDir);
      writeFileSync(fixture.keysFile, unrelated);

      run(fixture);
      const first = readFileSync(fixture.keysFile, 'utf8');
      expect(first.startsWith(unrelated)).toBe(true);

      run(fixture);
      const second = readFileSync(fixture.keysFile, 'utf8');
      expect(second.startsWith(first)).toBe(true);
      const lines = second.trimEnd().split('\n');
      expect(lines).toHaveLength(3);
      expect(lines[0] + '\n').toBe(unrelated);
      expect(lines.filter((line) => line.includes(' wundervault-admin '))).toHaveLength(2);
      expect(lines[1]).not.toBe(lines[2]);
    });
  });

  it('accepts a custom address list and rejects unsafe lists without changes', () => {
    withFixture((fixture) => {
      run(fixture, ['--from', '192.168.1.10,10.0.0.5']);
      const before = readFileSync(fixture.keysFile, 'utf8');
      expect(before.startsWith('from="192.168.1.10,10.0.0.5",')).toBe(true);

      for (const value of ['a b', 'x;rm', '"', '', 'host,', ',host', 'a'.repeat(254)]) {
        const result = spawnSync('sh', [script, '--from', value], {
          env: fixture.env,
          encoding: 'utf8',
        });
        expect(result.error).toBeUndefined();
        expect(result.status).not.toBe(0);
        expect(readFileSync(fixture.keysFile, 'utf8')).toBe(before);
        expect(readdirSync(fixture.tempDir)).toEqual([]);
        expect(readdirSync(fixture.sshDir)).toEqual(['authorized_keys']);
      }
    });
  });

  it('removes only admin keys and reports how many were removed', () => {
    withFixture((fixture) => {
      const unrelated = unrelatedKey();
      mkdirSync(fixture.sshDir);
      writeFileSync(fixture.keysFile, unrelated);
      run(fixture);
      run(fixture);

      const output = run(fixture, ['--remove']);

      expect(output).toContain('Removed 2 admin keys.');
      expect(readFileSync(fixture.keysFile, 'utf8')).toBe(unrelated);
      expect(statSync(fixture.sshDir).mode & 0o777).toBe(0o700);
      expect(statSync(fixture.keysFile).mode & 0o777).toBe(0o600);
      expect(readdirSync(fixture.tempDir)).toEqual([]);
      expect(readdirSync(fixture.sshDir)).toEqual(['authorized_keys']);
      expect(run(fixture, ['--remove'])).toContain('Removed 0 admin keys.');
      expect(readFileSync(fixture.keysFile, 'utf8')).toBe(unrelated);
    });
  });

  it('lists comments and allowed addresses without displaying key material', () => {
    withFixture((fixture) => {
      const unrelated = unrelatedKey();
      mkdirSync(fixture.sshDir);
      writeFileSync(fixture.keysFile, unrelated);
      run(fixture);
      const before = readFileSync(fixture.keysFile, 'utf8');
      const adminLine = before.split('\n').find((line) => line.includes(' wundervault-admin '));
      expect(adminLine).toBeDefined();
      const comment = adminLine!.slice(adminLine!.indexOf(' wundervault-admin ') + 1);

      const output = run(fixture, ['--list']);

      expect(output).toContain(comment);
      expect(output).toContain('from="127.0.0.1,::1"');
      expect(output).not.toContain('AAAA');
      expect(output).not.toContain('ssh-ed25519');
      expect(output).not.toContain('PRIVATE KEY');
      expect(output).not.toContain('existing-owner-key');
      expect(readFileSync(fixture.keysFile, 'utf8')).toBe(before);
    });
  });

  it('refuses linked key folders and files without touching their targets', () => {
    withFixture((fixture) => {
      const targetDir = join(fixture.dir, 'target');
      const targetFile = join(targetDir, 'authorized_keys');
      const unrelated = unrelatedKey();
      mkdirSync(targetDir, { mode: 0o755 });
      writeFileSync(targetFile, unrelated, { mode: 0o644 });
      const directoryMode = statSync(targetDir).mode;
      const fileMode = statSync(targetFile).mode;
      symlinkSync(targetDir, fixture.sshDir, 'dir');

      for (const args of [[], ['--remove'], ['--list']]) {
        const result = spawnSync('sh', [script, ...args], {
          env: fixture.env,
          encoding: 'utf8',
        });
        expect(result.error).toBeUndefined();
        expect(result.status).not.toBe(0);
        expect(readFileSync(targetFile, 'utf8')).toBe(unrelated);
        expect(statSync(targetDir).mode).toBe(directoryMode);
        expect(statSync(targetFile).mode).toBe(fileMode);
        expect(readdirSync(targetDir)).toEqual(['authorized_keys']);
      }

      rmSync(fixture.sshDir);
      mkdirSync(fixture.sshDir);
      symlinkSync(targetFile, fixture.keysFile);

      for (const args of [[], ['--remove'], ['--list']]) {
        const result = spawnSync('sh', [script, ...args], {
          env: fixture.env,
          encoding: 'utf8',
        });
        expect(result.error).toBeUndefined();
        expect(result.status).not.toBe(0);
        expect(readFileSync(targetFile, 'utf8')).toBe(unrelated);
        expect(statSync(targetFile).mode).toBe(fileMode);
        expect(readdirSync(fixture.sshDir)).toEqual(['authorized_keys']);
        expect(readdirSync(fixture.tempDir)).toEqual([]);
      }
    });
  });

  it.skipIf(isRoot)('requires sudo without the test folder override', () => {
    withFixture((fixture) => {
      const env = { ...fixture.env };
      delete env.WV_ADMIN_ROOT_SSH_DIR;

      const result = spawnSync('sh', [script], {
        env,
        encoding: 'utf8',
      });

      expect(result.error).toBeUndefined();
      expect(result.status).not.toBe(0);
      expect(`${result.stdout}${result.stderr}`).toContain('sudo');
      expect(existsSync(fixture.sshDir)).toBe(false);
      expect(readdirSync(fixture.tempDir)).toEqual([]);
      expect(readdirSync(fixture.dir)).toEqual(['tmp']);
    });
  });

  it.skipIf(!hasShellcheck)('passes shellcheck without warnings', () => {
    withFixture((fixture) => {
      const output = execFileSync('shellcheck', [script], {
        env: fixture.env,
        encoding: 'utf8',
      });

      expect(output).toBe('');
      expect(existsSync(fixture.sshDir)).toBe(false);
      expect(readdirSync(fixture.tempDir)).toEqual([]);
    });
  });
});

// Round 1 (F1/F2/F3): the SSH settings check itself, through a fake sshd (WV_ADMIN_SSHD).
describe.skipIf(!supported)('admin-key.sh SSH settings check', () => {
  function fakeSshd(fixture: Fixture, body: string): string {
    const path = join(fixture.dir, 'fake-sshd');
    writeFileSync(path, `#!/bin/sh\nprintf '%s\\n' "$*" > "${join(fixture.dir, 'sshd-args')}"\n${body}\n`, { mode: 0o755 });
    return path;
  }
  function runWith(fixture: Fixture, sshd: string, args: string[] = []) {
    return spawnSync('sh', [script, ...args], {
      env: { ...fixture.env, WV_ADMIN_SSHD: sshd }, encoding: 'utf8',
    });
  }

  it('asks sshd about THIS connection (root, from the allowed address), so Match rules count', () => {
    withFixture((fixture) => {
      const sshd = fakeSshd(fixture, "printf 'permitrootlogin prohibit-password\\npubkeyauthentication yes\\n'");
      const r = runWith(fixture, sshd);
      expect(r.status).toBe(0);
      expect(readFileSync(join(fixture.dir, 'sshd-args'), 'utf8')).toContain('-C user=root,host=localhost,addr=127.0.0.1');
    });
  });

  for (const [label, settings] of [
    ['root login off', 'permitrootlogin no\npubkeyauthentication yes'],
    ['forced commands only', 'permitrootlogin forced-commands-only\npubkeyauthentication yes'],
    ['key sign-in off', 'permitrootlogin prohibit-password\npubkeyauthentication no'],
  ] as const) {
    it(`refuses and changes nothing when ${label}`, () => {
      withFixture((fixture) => {
        const sshd = fakeSshd(fixture, `printf '${settings.replace(/\n/g, '\\n')}\\n'`);
        const r = runWith(fixture, sshd);
        expect(r.status).not.toBe(0);
        expect(existsSync(fixture.keysFile)).toBe(false);
        expect(readdirSync(fixture.tempDir)).toEqual([]);
      });
    });
  }

  it('refuses when the settings cannot be read, unless --skip-checks', () => {
    withFixture((fixture) => {
      const sshd = fakeSshd(fixture, 'exit 1');
      const r = runWith(fixture, sshd);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain('--skip-checks');
      expect(existsSync(fixture.keysFile)).toBe(false);
      const r2 = runWith(fixture, sshd, ['--skip-checks']);
      expect(r2.status).toBe(0);
      expect(readFileSync(fixture.keysFile, 'utf8')).toContain(' wundervault-admin ');
    });
  });

  it('leaves no lock behind, and a held lock stops a second change', () => {
    withFixture((fixture) => {
      run(fixture);
      expect(existsSync(join(fixture.sshDir, '.wundervault-admin.lock'))).toBe(false);
    });
  });
});
