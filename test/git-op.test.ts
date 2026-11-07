import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { appendFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import type { Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildGitArgv,
  gitBaseArgs,
  gitEnv,
  parseGitSshUrl,
  resolveGitUrls,
  runGit,
  sshCommandFor,
  validateGitRequest,
} from '../src/git-op.js';
import type { GitRequest } from '../src/git-op.js';

const unixIt = process.platform === 'win32' ? it.skip : it;
const windowsIt = process.platform === 'win32' ? it : it.skip;

type Repository = {
  repo: string;
  env: NodeJS.ProcessEnv;
  git: (args: string[]) => string;
};

async function withRepository(
  test: (repository: Repository) => Promise<void>,
): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), 'vault-git-op-'));
  const repo = join(root, 'repo');
  const home = join(root, 'home');
  mkdirSync(repo);
  mkdirSync(home);

  const env = gitEnv({
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
  }, 'ssh');
  const git = (args: string[]): string => execFileSync('git', args, {
    cwd: repo,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    git(['init']);
    await test({ repo, env, git });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe('validateGitRequest', () => {
  it('accepts each supported subcommand', () => {
    const requests: GitRequest[] = [
      { subcommand: 'push', remote: 'origin', refspecs: ['HEAD:refs/heads/main'] },
      { subcommand: 'pull', remote: 'upstream', refspecs: ['main'] },
      { subcommand: 'fetch', remote: 'origin', refspecs: ['+refs/heads/*:refs/remotes/origin/*'] },
      { subcommand: 'clone', url: 'git@good.example:a/b.git', target_dir: 'checkout' },
      { subcommand: 'ls-remote', remote: 'origin' },
    ];

    for (const req of requests) {
      expect(validateGitRequest(req)).toEqual({ ok: true, req });
    }
  });

  it('accepts the exact flags allowed for each subcommand', () => {
    const requests: GitRequest[] = [
      {
        subcommand: 'push',
        remote: 'origin',
        flags: [
          '--force-with-lease',
          '--tags',
          '--set-upstream',
          '--dry-run',
          '--delete',
          '--follow-tags',
        ],
      },
      {
        subcommand: 'pull',
        remote: 'origin',
        flags: ['--ff-only', '--rebase', '--no-rebase'],
      },
      {
        subcommand: 'fetch',
        remote: 'origin',
        flags: ['--tags', '--prune', '--dry-run', '--depth=1', '--depth=1000000'],
      },
      {
        subcommand: 'clone',
        url: 'ssh://git@good.example/a/b.git',
        flags: [
          '--depth=30',
          '--branch=release/v1.2-rc_1',
          '--single-branch',
          '--no-checkout',
        ],
      },
      {
        subcommand: 'ls-remote',
        remote: 'origin',
        flags: ['--heads', '--tags'],
      },
    ];

    for (const req of requests) {
      expect(validateGitRequest(req)).toEqual({ ok: true, req });
    }
  });

  it.each([
    '--force',
    '-f',
    '--recurse-submodules',
    '--recurse-submodules=yes',
    '--recursive',
    '-j',
    '-j4',
    '--jobs',
    '--jobs=4',
    '--upload-pack',
    '--upload-pack=x',
    '--receive-pack',
    '--receive-pack=x',
    '--exec',
    '--exec=x',
    '-c',
    '--config',
    '--config=core.sshCommand=x',
    '--template',
    '--template=/tmp/template',
    '-u',
  ])('refuses the flag %s for every subcommand', (flag) => {
    const subcommands: GitRequest['subcommand'][] = [
      'push', 'pull', 'fetch', 'clone', 'ls-remote',
    ];
    for (const subcommand of subcommands) {
      const req: GitRequest = subcommand === 'clone'
        ? { subcommand, url: 'git@good.example:a/b.git', flags: [flag] }
        : { subcommand, remote: 'origin', flags: [flag] };
      expect(validateGitRequest(req).ok).toBe(false);
    }
  });

  it.each([
    '--depth=0',
    '--depth=1000001',
    '--depth=-1',
    '--depth=1.5',
    '--depth=',
    '--depth=1\n',
    '--branch=-bad',
    '--branch=',
    '--branch=two words',
    '--branch=main\n',
    '--branch=$(id)',
  ])('refuses invalid parameterised flags: %s', (flag) => {
    expect(validateGitRequest({
      subcommand: 'clone',
      url: 'git@good.example:a/b.git',
      flags: [flag],
    }).ok).toBe(false);
  });

  it('does not accept flags belonging to another subcommand', () => {
    for (const [subcommand, flag] of [
      ['push', '--depth=1'],
      ['pull', '--tags'],
      ['fetch', '--branch=main'],
      ['ls-remote', '--dry-run'],
    ] as const) {
      expect(validateGitRequest({
        subcommand,
        remote: 'origin',
        flags: [flag],
      }).ok).toBe(false);
    }
  });

  it.each([
    '',
    '-origin',
    '--upload-pack=x',
    'two words',
    'origin\n',
    'git@good.example:a/b.git',
    'ssh://good.example/a/b.git',
    'origin/main',
    'origin;id',
  ])('refuses the remote name %s', (remote) => {
    expect(validateGitRequest({ subcommand: 'fetch', remote }).ok).toBe(false);
  });

  it.each([
    '',
    '--upload-pack=x',
    'git@evil:x',
    'ext::sh',
    'https://evil.example/repo',
    'two refs',
    'main\nother',
    'main\0other',
    'x'.repeat(257),
  ])('refuses the refspec %s', (refspec) => {
    expect(validateGitRequest({
      subcommand: 'push',
      remote: 'origin',
      refspecs: [refspec],
    }).ok).toBe(false);
  });

  it.each([
    '',
    '/absolute',
    '../outside',
    'inside/../outside',
    '..',
    '-option',
    'C:/outside',
    'inside\\..\\outside',
    'inside\0outside',
  ])('refuses the clone target %s', (target_dir) => {
    expect(validateGitRequest({
      subcommand: 'clone',
      url: 'git@good.example:a/b.git',
      target_dir,
    }).ok).toBe(false);
  });

  it('accepts relative clone directories, including spaces', () => {
    for (const target_dir of ['checkout', './checkout', 'parent/checkout', 'my checkout']) {
      expect(validateGitRequest({
        subcommand: 'clone',
        url: 'git@good.example:a/b.git',
        target_dir,
      }).ok).toBe(true);
    }
  });

  it('refuses malformed requests and fields not applicable to the operation', () => {
    const requests: unknown[] = [
      null,
      [],
      'push',
      {},
      { subcommand: 'status', remote: 'origin' },
      { subcommand: 'push' },
      { subcommand: 'push', remote: 123 },
      { subcommand: 'push', remote: 'origin', git_args: ['--force'] },
      { subcommand: 'push', remote: 'origin', flags: '--tags' },
      { subcommand: 'push', remote: 'origin', flags: [123] },
      { subcommand: 'push', remote: 'origin', flags: new Array(1) },
      { subcommand: 'push', remote: 'origin', refspecs: 'main' },
      { subcommand: 'push', remote: 'origin', refspecs: [123] },
      { subcommand: 'push', remote: 'origin', refspecs: new Array(1) },
      { subcommand: 'fetch', remote: 'origin', url: 'git@good.example:a/b.git' },
      { subcommand: 'fetch', remote: 'origin', target_dir: 'checkout' },
      { subcommand: 'clone' },
      { subcommand: 'clone', url: 'https://good.example/a/b.git' },
      { subcommand: 'clone', url: 'git@good.example:a/b.git', remote: 'origin' },
      { subcommand: 'clone', url: 'git@good.example:a/b.git', refspecs: [] },
      { subcommand: 'clone', url: 'git@good.example:a/b.git', target_dir: 123 },
      { subcommand: 'ls-remote', remote: 'origin', refspecs: [] },
    ];

    for (const req of requests) {
      expect(validateGitRequest(req).ok).toBe(false);
    }
  });

  it('returns independent arrays rather than retaining caller-owned arrays', () => {
    const req: GitRequest = {
      subcommand: 'push',
      remote: 'origin',
      flags: ['--tags'],
      refspecs: ['main'],
    };
    const result = validateGitRequest(req);
    expect(result.ok).toBe(true);
    if (result.ok) {
      req.flags!.push('--force');
      req.refspecs!.push('--upload-pack=x');
      expect(result.req.flags).toEqual(['--tags']);
      expect(result.req.refspecs).toEqual(['main']);
    }
  });
});

describe('parseGitSshUrl', () => {
  it.each([
    ['git@good.example:a/b.git', 'good.example', 'git', undefined],
    ['good.example:a/b.git', 'good.example', undefined, undefined],
    ['ssh://git@good.example/a/b.git', 'good.example', 'git', undefined],
    ['ssh://good.example:2222/a/b.git', 'good.example', undefined, 2222],
    ['ssh://git@GOOD.example:22/a/b.git', 'good.example', 'git', undefined],
    ['ssh://git@[2001:db8::1]:2222/a/b.git', '2001:db8::1', 'git', 2222],
    ['ssh://[::1]/a/b.git', '::1', undefined, undefined],
  ])('parses %s', (url, host, user, port) => {
    expect(parseGitSshUrl(url)).toEqual({
      ok: true, host, ...(port !== undefined ? { port } : {}), ...(user !== undefined ? { user } : {}),
    });
  });

  it.each([
    '',
    'https://good.example/repo',
    'http://good.example/repo',
    'git://good.example/repo',
    'file://good.example/repo',
    'ext::sh',
    'custom::address',
    '/repo',
    './repo',
    '../repo',
    'C:',
    'C:/repo',
    'C:\\repo',
    'repo',
    'git@good.example:',
    'ssh://good.example',
    'ssh://good.example/',
    'ssh://good.example:0/repo',
    'ssh://good.example:65536/repo',
    'ssh://good.example:notaport/repo',
    'ssh://[not-ipv6]/repo',
    'ssh://[127.0.0.1]/repo',
    '[::1]:repo',
    'git@-oProxyCommand=x:repo',
    '-oProxyCommand=x:repo',
    'ssh://git@-evil.example/repo',
    'ssh://git@%2devil.example/repo',
    'ssh://git:password@good.example/repo',
    'git@good.example:repo\n',
  ])('refuses %s', (url) => {
    expect(parseGitSshUrl(url).ok).toBe(false);
  });
});

describe('git process arguments and environment', () => {
  it('returns the forced configuration in the required order', () => {
    expect(gitBaseArgs()).toEqual([
      '-c', 'protocol.allow=never',
      '-c', 'protocol.ssh.allow=always',
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      '-c', 'submodule.recurse=false',
      '-c', 'fetch.recurseSubmodules=false',
      '-c', 'push.recurseSubmodules=no',
      '-c', 'core.sshCommand=',
    ]);

    const args = gitBaseArgs();
    args.push('changed');
    expect(gitBaseArgs()).not.toContain('changed');
  });

  it('removes inherited git controls and the ambient agent socket', () => {
    const base: NodeJS.ProcessEnv = {
      PATH: '/usr/bin',
      HOME: '/home/test',
      KEEP_ME: 'yes',
      GIT_CONFIG_PARAMETERS: "'core.sshCommand=evil'",
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'core.sshCommand',
      GIT_CONFIG_VALUE_0: 'evil',
      GIT_CONFIG_GLOBAL: '/tmp/evil',
      GIT_CONFIG_SYSTEM: '/tmp/evil',
      GIT_SSH: 'evil',
      GIT_SSH_COMMAND: 'evil',
      GIT_SSH_VARIANT: 'plink',
      GIT_EXEC_PATH: '/tmp/evil',
      GIT_DIR: '/tmp/evil',
      GIT_WORK_TREE: '/tmp/evil',
      GIT_FUTURE_CONTROL: 'evil',
      GIT_TERMINAL_PROMPT: '1',
      SSH_AUTH_SOCK: '/tmp/ambient-agent',
    };
    const original = { ...base };
    const env = gitEnv(base, "'ssh' '-F' '/dev/null'");

    expect(env).toEqual({
      PATH: '/usr/bin',
      HOME: '/home/test',
      KEEP_ME: 'yes',
      GIT_SSH_COMMAND: "'ssh' '-F' '/dev/null'",
      GIT_SSH_VARIANT: 'ssh',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_TERMINAL_PROMPT: '0',
    });
    expect(base).toEqual(original);
  });

  it('shell-quotes hardened SSH arguments, including embedded quotes', () => {
    const command = sshCommandFor(
      "/tmp/socket'dir/agent socket",
      "/tmp/key'dir/public key",
    );

    expect(command).toMatch(/^'ssh' /);
    expect(command).toContain("'-F' '/dev/null'");
    expect(command).toContain("socket'\\''dir/agent socket");
    expect(command).toContain("key'\\''dir/public key");
    expect(command).toContain('IdentityAgent=');
    expect(command).toContain('IdentitiesOnly=yes');
    expect(command).toContain('BatchMode=yes');
    expect(command).toContain('StrictHostKeyChecking=accept-new');
  });

  it('places the end-of-options marker before the remote and refspecs', () => {
    expect(buildGitArgv({
      subcommand: 'push',
      remote: 'origin',
      flags: ['--dry-run', '--tags'],
      refspecs: ['HEAD:refs/heads/main'],
    })).toEqual([
      ...gitBaseArgs(),
      'push',
      '--dry-run',
      '--tags',
      '--end-of-options',
      'origin',
      'HEAD:refs/heads/main',
    ]);
  });

  it('builds clone arguments without inventing flags or a target directory', () => {
    expect(buildGitArgv({
      subcommand: 'clone',
      url: 'git@good.example:a/b.git',
    })).toEqual([
      ...gitBaseArgs(),
      'clone',
      '--end-of-options',
      'git@good.example:a/b.git',
    ]);

    expect(buildGitArgv({
      subcommand: 'clone',
      url: 'git@good.example:a/b.git',
      flags: ['--no-checkout'],
      target_dir: 'my checkout',
    })).toEqual([
      ...gitBaseArgs(),
      'clone',
      '--no-checkout',
      '--end-of-options',
      'git@good.example:a/b.git',
      'my checkout',
    ]);
  });

  it('revalidates requests before building executable arguments', () => {
    expect(() => buildGitArgv({
      subcommand: 'push',
      remote: 'origin',
      flags: ['--force'],
    })).toThrow('unsupported git flag');
  });
});

describe('resolveGitUrls with a fake runner', () => {
  unixIt('uses the required lookup for each operation and forwards cwd and env', async () => {
    const env = { HOME: '/test/home' };
    const cases: Array<{ req: GitRequest; args: string[] }> = [
      {
        req: { subcommand: 'push', remote: 'origin' },
        args: ['remote', 'get-url', '--push', '--all', '--end-of-options', 'origin'],
      },
      ...(['pull', 'fetch', 'ls-remote'] as const).map((subcommand) => ({
        req: { subcommand, remote: 'origin' },
        args: ['remote', 'get-url', '--all', '--end-of-options', 'origin'],
      })),
      {
        req: { subcommand: 'clone', url: 'git@good.example:a/b.git' },
        args: ['ls-remote', '--get-url', '--end-of-options', 'git@good.example:a/b.git'],
      },
    ];

    for (const test of cases) {
      let calls = 0;
      const result = await resolveGitUrls(test.req, '/test/repo', async (args, cwd, receivedEnv) => {
        calls += 1;
        expect(args).toEqual(test.args);
        if (test.req.subcommand === 'clone') {
          // A clone resolves in an empty folder outside any repository (round 2, F1).
          expect(cwd).not.toBe('/test/repo');
          expect(receivedEnv.HOME).toBe(env.HOME);
          expect(receivedEnv.GIT_CEILING_DIRECTORIES).toBeTruthy();
        } else {
          expect(cwd).toBe('/test/repo');
          expect(receivedEnv).toBe(env);
        }
        return { code: 0, stdout: 'git@good.example:a/b.git\n', stderr: '' };
      }, env);

      expect(calls).toBe(1);
      expect(result).toEqual({ ok: true, urls: ['git@good.example:a/b.git'] });
    }
  });

  unixIt('preserves every resolved URL for the broker to check', async () => {
    const result = await resolveGitUrls(
      { subcommand: 'push', remote: 'origin' },
      '/repo',
      async () => ({
        code: 0,
        stdout: 'git@good.example:a.git\r\ngit@evil.example:b.git\r\n',
        stderr: '',
      }),
      {},
    );

    expect(result).toEqual({
      ok: true,
      urls: ['git@good.example:a.git', 'git@evil.example:b.git'],
    });
  });

  unixIt('refuses the whole resolution if any URL is not SSH', async () => {
    const result = await resolveGitUrls(
      { subcommand: 'push', remote: 'origin' },
      '/repo',
      async () => ({
        code: 0,
        stdout: 'git@good.example:a.git\nhttps://evil.example/b.git\n',
        stderr: '',
      }),
      {},
    );

    expect(result).toEqual({
      ok: false,
      reason: 'git remote resolves to a non-SSH address',
    });
  });

  unixIt('refuses empty results and failed lookups without exposing stderr', async () => {
    for (const stdout of ['', '\n', '\r\n']) {
      expect((await resolveGitUrls(
        { subcommand: 'fetch', remote: 'origin' },
        '/repo',
        async () => ({ code: 0, stdout, stderr: '' }),
        {},
      )).ok).toBe(false);
    }

    expect(await resolveGitUrls(
      { subcommand: 'fetch', remote: 'missing' },
      '/repo',
      async () => ({ code: 2, stdout: '', stderr: 'private diagnostic' }),
      {},
    )).toEqual({ ok: false, reason: 'no such remote' });

    expect(await resolveGitUrls(
      { subcommand: 'fetch', remote: 'missing' },
      '/repo',
      async () => { throw new Error('private diagnostic'); },
      {},
    )).toEqual({ ok: false, reason: 'no such remote' });
  });

  unixIt('rejects invalid requests before invoking git', async () => {
    let called = false;
    const result = await resolveGitUrls(
      { subcommand: 'push', remote: 'origin', flags: ['--force'] },
      '/repo',
      async () => {
        called = true;
        return { code: 0, stdout: 'git@good.example:a.git\n', stderr: '' };
      },
      {},
    );

    expect(result.ok).toBe(false);
    expect(called).toBe(false);
  });

  windowsIt('refuses Windows before invoking the runner', async () => {
    let called = false;
    const result = await resolveGitUrls(
      { subcommand: 'fetch', remote: 'origin' },
      '/repo',
      async () => {
        called = true;
        return { code: 0, stdout: '', stderr: '' };
      },
      {},
    );

    expect(result).toEqual({
      ok: false,
      reason: 'git through the vault needs Linux or macOS; Windows is not supported yet',
    });
    expect(called).toBe(false);
  });
});

describe('resolveGitUrls with real repository configuration', () => {
  unixIt('uses pushurl for push, but the ordinary URL for fetch', async () => {
    await withRepository(async ({ repo, env, git }) => {
      git(['remote', 'add', 'origin', 'git@good.example:a/b.git']);
      git(['config', 'remote.origin.pushurl', 'git@evil.example:x.git']);

      expect(await resolveGitUrls(
        { subcommand: 'push', remote: 'origin' }, repo, runGit, env,
      )).toEqual({ ok: true, urls: ['git@evil.example:x.git'] });

      expect(await resolveGitUrls(
        { subcommand: 'fetch', remote: 'origin' }, repo, runGit, env,
      )).toEqual({ ok: true, urls: ['git@good.example:a/b.git'] });
    });
  });

  unixIt('applies insteadOf rewrites before returning hosts to the broker', async () => {
    await withRepository(async ({ repo, env, git }) => {
      git(['remote', 'add', 'origin', 'git@good.example:a/b.git']);
      git(['config', 'url.git@evil.example:.insteadOf', 'git@good.example:']);

      for (const subcommand of ['push', 'pull', 'fetch', 'ls-remote'] as const) {
        expect(await resolveGitUrls(
          { subcommand, remote: 'origin' }, repo, runGit, env,
        )).toEqual({ ok: true, urls: ['git@evil.example:a/b.git'] });
      }

      // A clone does NOT read the folder's own config, so the folder's rewrite must not be
      // what the broker checks: the clone will contact good.example (round 2, F1). This test
      // used to expect evil.example — it agreed with the bug.
      expect(await resolveGitUrls(
        { subcommand: 'clone', url: 'git@good.example:a/b.git' },
        repo,
        runGit,
        env,
      )).toEqual({ ok: true, urls: ['git@good.example:a/b.git'] });
    });
  });

  unixIt('a clone resolves with the configuration the clone itself uses (global rewrites apply)', async () => {
    await withRepository(async ({ repo, env }) => {
      execFileSync('git', ['config', '--global', 'url.git@evil.example:.insteadOf', 'git@good.example:'], { env, cwd: repo });
      expect(await resolveGitUrls(
        { subcommand: 'clone', url: 'git@good.example:a/b.git' }, repo, runGit, env,
      )).toEqual({ ok: true, urls: ['git@evil.example:a/b.git'] });
    });
  });

  unixIt('returns both push URLs, including a second disallowed host', async () => {
    await withRepository(async ({ repo, env, git }) => {
      git(['remote', 'add', 'origin', 'git@good.example:a/b.git']);
      git(['remote', 'set-url', '--add', '--push', 'origin', 'git@good.example:a/b.git']);
      git(['remote', 'set-url', '--add', '--push', 'origin', 'git@evil.example:x.git']);

      expect(await resolveGitUrls(
        { subcommand: 'push', remote: 'origin' }, repo, runGit, env,
      )).toEqual({
        ok: true,
        urls: ['git@good.example:a/b.git', 'git@evil.example:x.git'],
      });
    });
  });

  unixIt('refuses HTTPS, ext transport, and an option-like SSH host', async () => {
    await withRepository(async ({ repo, env, git }) => {
      for (const url of [
        'https://good.example/a/b.git',
        'ext::sh',
        'git@-oProxyCommand=x:repo',
      ]) {
        git(['config', 'remote.origin.url', url]);
        expect(await resolveGitUrls(
          { subcommand: 'fetch', remote: 'origin' }, repo, runGit, env,
        )).toEqual({
          ok: false,
          reason: 'git remote resolves to a non-SSH address',
        });
      }
    });
  });

  unixIt('refuses an insteadOf rewrite from SSH to a non-SSH address', async () => {
    await withRepository(async ({ repo, env, git }) => {
      git(['remote', 'add', 'origin', 'git@good.example:a/b.git']);
      git(['config', 'url.https://evil.example/.insteadOf', 'git@good.example:']);

      expect(await resolveGitUrls(
        { subcommand: 'fetch', remote: 'origin' }, repo, runGit, env,
      )).toEqual({
        ok: false,
        reason: 'git remote resolves to a non-SSH address',
      });
    });
  });

  unixIt('reports a missing remote without git diagnostics', async () => {
    await withRepository(async ({ repo, env }) => {
      expect(await resolveGitUrls(
        { subcommand: 'push', remote: 'missing' }, repo, runGit, env,
      )).toEqual({ ok: false, reason: 'no such remote' });
    });
  });
});

describe('runGit', () => {
  unixIt('captures output and exit status from git', async () => {
    await withRepository(async ({ repo, env }) => {
      const success = await runGit(['--version'], repo, env);
      expect(success.code).toBe(0);
      expect(success.stdout).toMatch(/^git version /);
      expect(success.stderr).toBe('');

      const failure = await runGit(['not-a-vault-git-command'], repo, env);
      expect(failure.code).not.toBe(0);
      expect(failure.stderr.length).toBeGreaterThan(0);
    });
  });

  unixIt('caps output at one MiB and includes a visible truncation note', async () => {
    await withRepository(async ({ repo, env }) => {
      appendFileSync(
        join(repo, '.git', 'config'),
        '\n[vault]\n' + `output = ${'x'.repeat(1024)}\n`.repeat(1100),
      );

      const result = await runGit(['config', '--get-all', 'vault.output'], repo, env);
      expect(result.code).toBe(0);
      expect(result.stdout).toContain('[output truncated]');
      expect(Buffer.byteLength(result.stdout)).toBeLessThanOrEqual(1024 * 1024);
      expect(result.stdout.length).toBeGreaterThan(1000000);
    });
  });

  unixIt('returns a safe error when git cannot be started', async () => {
    await withRepository(async ({ repo, env }) => {
      const result = await runGit(['--version'], join(repo, 'missing'), env);
      expect(result.code).toBe(127);
      expect(result.stderr).toContain('[could not start git]');
    });
  });

  unixIt('kills a stalled git process at the timeout and returns 124', async () => {
    await withRepository(async ({ repo, env }) => {
      const sockets = new Set<Socket>();
      const server = createServer((socket) => {
        sockets.add(socket);
        socket.on('error', () => {});
        socket.on('close', () => sockets.delete(socket));
        socket.on('data', () => {
          // Accept the git protocol request without answering it.
        });
      });

      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      try {
        const address = server.address();
        if (address === null || typeof address === 'string') {
          throw new Error('expected a TCP server address');
        }

        const result = await runGit(
          ['ls-remote', `git://127.0.0.1:${address.port}/repo`],
          repo,
          env,
          300,
        );

        expect(result.code).toBe(124);
        expect(result.stderr).toContain('[git timed out]');
      } finally {
        for (const socket of sockets) {
          socket.destroy();
        }
        await new Promise<void>((resolve, reject) => {
          server.close((error) => error ? reject(error) : resolve());
        });
      }
    });
  });

  it('rejects invalid timeout values', async () => {
    for (const timeout of [0, -1, NaN, Infinity, 1.5, 2147483648]) {
      await expect(runGit([], '.', {}, timeout)).rejects.toThrow('invalid git timeout');
    }
  });
});
