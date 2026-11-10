import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { isIP } from 'node:net';
import { hardenedSshOptions } from './ssh-agent.js';
import { pinnedSshOptions } from './ssh-options.js';

export type GitRequest = {
  subcommand: 'push' | 'pull' | 'fetch' | 'clone' | 'ls-remote';
  remote?: string;
  url?: string;
  refspecs?: string[];
  flags?: string[];
  target_dir?: string;
};

type ValidationResult = {
  ok: true;
  req: GitRequest;
} | {
  ok: false;
  reason: string;
};

type UrlResult = {
  ok: true;
  host: string;
  user?: string;
  /** ssh:// URLs may name one; scp-like ones are always 22. */
  port?: number;
} | {
  ok: false;
  reason: string;
};

type GitResult = {
  code: number;
  stdout: string;
  stderr: string;
};

type GitRunner = (
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
) => Promise<GitResult>;

type ResolutionResult = {
  ok: true;
  urls: string[];
} | {
  ok: false;
  reason: string;
};

const ALLOWED_FLAGS: Record<GitRequest['subcommand'], readonly string[]> = {
  push: [
    '--force-with-lease',
    '--tags',
    '--set-upstream',
    '--dry-run',
    '--delete',
    '--follow-tags',
  ],
  pull: ['--ff-only', '--rebase', '--no-rebase'],
  fetch: ['--tags', '--prune', '--dry-run'],
  clone: ['--single-branch', '--no-checkout'],
  'ls-remote': ['--heads', '--tags'],
};

const REQUEST_FIELDS = new Set([
  'subcommand',
  'remote',
  'url',
  'refspecs',
  'flags',
  'target_dir',
]);

const WHITESPACE_OR_CONTROL = /[\s\x00-\x1f\x7f-\x9f]/;
const OUTPUT_LIMIT = 1024 * 1024;

function allowedFlag(subcommand: GitRequest['subcommand'], flag: string): boolean {
  if (WHITESPACE_OR_CONTROL.test(flag)) {
    return false;
  }
  if (ALLOWED_FLAGS[subcommand].includes(flag)) {
    return true;
  }

  if (subcommand === 'fetch' || subcommand === 'clone') {
    const depth = /^--depth=([0-9]+)$/.exec(flag);
    if (depth !== null) {
      const value = Number(depth[1]);
      return Number.isInteger(value) && value >= 1 && value <= 1000000;
    }
  }

  if (subcommand === 'clone' && flag.startsWith('--branch=')) {
    const branch = flag.slice('--branch='.length);
    return /^[A-Za-z0-9._/-]+$/.test(branch) && !branch.startsWith('-');
  }

  return false;
}

export function validateGitRequest(req: unknown): ValidationResult {
  if (req === null || typeof req !== 'object' || Array.isArray(req)) {
    return { ok: false, reason: 'git request must be an object' };
  }

  const input = req as Record<string, unknown>;
  if (Object.keys(input).some((key) => !REQUEST_FIELDS.has(key))) {
    return { ok: false, reason: 'unsupported git request field' };
  }

  const subcommand = input.subcommand;
  if (
    subcommand !== 'push' &&
    subcommand !== 'pull' &&
    subcommand !== 'fetch' &&
    subcommand !== 'clone' &&
    subcommand !== 'ls-remote'
  ) {
    return { ok: false, reason: 'unsupported git subcommand' };
  }

  const validated: GitRequest = { subcommand };

  if (subcommand === 'clone') {
    if (input.remote !== undefined) {
      return { ok: false, reason: 'clone takes a URL, not a named remote' };
    }
    if (typeof input.url !== 'string') {
      return { ok: false, reason: 'clone requires an SSH URL' };
    }
    const parsed = parseGitSshUrl(input.url);
    if (!parsed.ok) {
      return { ok: false, reason: parsed.reason };
    }
    validated.url = input.url;
  } else {
    if (input.url !== undefined || input.target_dir !== undefined) {
      return { ok: false, reason: 'URL and target directory are only allowed for clone' };
    }
    if (
      typeof input.remote !== 'string' ||
      !/^[A-Za-z0-9._-]+$/.test(input.remote) ||
      input.remote.startsWith('-') ||
      WHITESPACE_OR_CONTROL.test(input.remote)
    ) {
      return { ok: false, reason: 'git requires a valid named remote' };
    }
    validated.remote = input.remote;
  }

  if (input.flags !== undefined) {
    if (!Array.isArray(input.flags)) {
      return { ok: false, reason: 'git flags must be an array' };
    }
    const flags: string[] = [];
    for (const flag of input.flags) {
      if (typeof flag !== 'string' || !allowedFlag(subcommand, flag)) {
        return { ok: false, reason: 'unsupported git flag' };
      }
      flags.push(flag);
    }
    validated.flags = flags;
  }

  if (input.refspecs !== undefined) {
    if (subcommand === 'clone' || subcommand === 'ls-remote') {
      return { ok: false, reason: 'refspecs are not allowed for this git subcommand' };
    }
    if (!Array.isArray(input.refspecs)) {
      return { ok: false, reason: 'git refspecs must be an array' };
    }

    const refspecs: string[] = [];
    for (const refspec of input.refspecs) {
      if (
        typeof refspec !== 'string' ||
        refspec.length === 0 ||
        refspec.length > 256 ||
        refspec.startsWith('-') ||
        WHITESPACE_OR_CONTROL.test(refspec) ||
        refspec.includes('://') ||
        refspec.includes('::') ||
        /@.*:/.test(refspec)
      ) {
        return { ok: false, reason: 'invalid git refspec' };
      }
      refspecs.push(refspec);
    }
    validated.refspecs = refspecs;
  }

  if (input.target_dir !== undefined) {
    if (
      typeof input.target_dir !== 'string' ||
      input.target_dir.length === 0 ||
      input.target_dir.startsWith('/') ||
      input.target_dir.startsWith('-') ||
      /^[A-Za-z]:/.test(input.target_dir) ||
      input.target_dir.includes('\\') ||
      input.target_dir.split('/').includes('..') ||
      /[\x00-\x1f\x7f-\x9f]/.test(input.target_dir)
    ) {
      return { ok: false, reason: 'clone target must be a relative directory without parent traversal' };
    }
    validated.target_dir = input.target_dir;
  }

  return { ok: true, req: validated };
}

export function parseGitSshUrl(url: string): UrlResult {
  if (
    typeof url !== 'string' ||
    url.length === 0 ||
    WHITESPACE_OR_CONTROL.test(url) ||
    url.includes('\\') ||
    /^(?:\/|\.\.?\/|[A-Za-z]:)/.test(url)
  ) {
    return { ok: false, reason: 'git requires an SSH address' };
  }

  let user: string | undefined;
  let host: string;
  let port: number | undefined;

  if (url.startsWith('ssh://')) {
    const match = /^ssh:\/\/(?:([^@/:]+)@)?(\[[^\]]+\]|[^/:@]+)(?::([0-9]+))?\/(.+)$/.exec(url);
    if (match === null) {
      return { ok: false, reason: 'invalid SSH address' };
    }

    user = match[1];
    host = match[2];
    if (match[3] !== undefined) {
      port = Number(match[3]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return { ok: false, reason: 'invalid SSH port' };
      }
    }

    if (host.startsWith('[')) {
      host = host.slice(1, -1);
      if (isIP(host) !== 6) {
        return { ok: false, reason: 'invalid SSH host' };
      }
    } else if (!/^[A-Za-z0-9.-]+$/.test(host) || host.startsWith('-')) {
      return { ok: false, reason: 'invalid SSH host' };
    }
  } else {
    if (url.includes('://') || /^[^/:]+::/.test(url)) {
      return { ok: false, reason: 'git requires an SSH address' };
    }

    const match = /^(?:([^@/:]+)@)?([^/:@]+):(.+)$/.exec(url);
    if (match === null) {
      return { ok: false, reason: 'git requires an SSH address' };
    }

    user = match[1];
    host = match[2];
    if (!/^[A-Za-z0-9.-]+$/.test(host) || host.startsWith('-')) {
      return { ok: false, reason: 'invalid SSH host' };
    }
  }

  if (user !== undefined && !/^[A-Za-z0-9._+-]+$/.test(user)) {
    return { ok: false, reason: 'invalid SSH user' };
  }

  const base = { ok: true as const, host: host.toLowerCase(), ...(port !== undefined && port !== 22 ? { port } : {}) };
  return user === undefined ? base : { ...base, user };
}

export function gitBaseArgs(): string[] {
  return [
    '-c', 'protocol.allow=never',
    '-c', 'protocol.ssh.allow=always',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.fsmonitor=false',
    '-c', 'submodule.recurse=false',
    '-c', 'fetch.recurseSubmodules=false',
    '-c', 'push.recurseSubmodules=no',
    '-c', 'core.sshCommand=',
  ];
}

export function gitEnv(
  base: NodeJS.ProcessEnv,
  sshCommand: string,
): NodeJS.ProcessEnv {
  const env = { ...base };
  for (const key of Object.keys(env)) {
    if (key.startsWith('GIT_') || key === 'SSH_AUTH_SOCK') {
      delete env[key];
    }
  }

  env.GIT_SSH_COMMAND = sshCommand;
  env.GIT_SSH_VARIANT = 'ssh';
  env.GIT_CONFIG_NOSYSTEM = '1';
  env.GIT_TERMINAL_PROMPT = '0';
  return env;
}

export function sshCommandFor(socketPath: string, publicKeyPath: string, knownHostsPath?: string): string {
  return ['ssh', ...(knownHostsPath ? pinnedSshOptions(socketPath, publicKeyPath, knownHostsPath) : hardenedSshOptions(socketPath, publicKeyPath))]
    .map((arg) => `'${arg.replace(/'/g, "'\\''")}'`)
    .join(' ');
}

export function buildGitArgv(req: GitRequest): string[] {
  const result = validateGitRequest(req);
  if (!result.ok) {
    throw new Error(result.reason);
  }

  const validated = result.req;
  const args = [
    ...gitBaseArgs(),
    validated.subcommand,
    ...(validated.flags ?? []),
    '--end-of-options',
  ];

  if (validated.subcommand === 'clone') {
    args.push(validated.url!);
    if (validated.target_dir !== undefined) {
      args.push(validated.target_dir);
    }
  } else {
    args.push(validated.remote!);
  }

  args.push(...(validated.refspecs ?? []));
  return args;
}

export async function resolveGitUrls(
  req: GitRequest,
  repoDir: string,
  runGit: GitRunner,
  env: NodeJS.ProcessEnv,
): Promise<ResolutionResult> {
  if (process.platform === 'win32') {
    return {
      ok: false,
      reason: 'git through the vault needs Linux or macOS; Windows is not supported yet',
    };
  }

  const validated = validateGitRequest(req);
  if (!validated.ok) {
    return { ok: false, reason: validated.reason };
  }

  const request = validated.req;
  let args: string[];
  if (request.subcommand === 'clone') {
    args = ['ls-remote', '--get-url', '--end-of-options', request.url!];
  } else if (request.subcommand === 'push') {
    args = ['remote', 'get-url', '--push', '--all', '--end-of-options', request.remote!];
  } else {
    args = ['remote', 'get-url', '--all', '--end-of-options', request.remote!];
  }

  let result: GitResult;
  // A clone does not read the configuration of the folder it runs in; resolving its URL
  // there would apply that folder's url.*.insteadOf rewrites, which the clone itself then
  // ignores — checking one host and connecting to another (round 2, F1). Resolve it in an
  // empty folder outside any repository, which is what the clone sees.
  const scratch = request.subcommand === 'clone' ? mkdtempSync(join(tmpdir(), 'wv-git-')) : null;
  try {
    result = await runGit(args, scratch ?? repoDir,
      scratch ? { ...env, GIT_CEILING_DIRECTORIES: dirname(scratch) } : env);
  } catch {
    return { ok: false, reason: 'no such remote' };
  } finally {
    if (scratch) rmSync(scratch, { recursive: true, force: true });
  }
  if (result.code !== 0) {
    return { ok: false, reason: 'no such remote' };
  }

  const urls = result.stdout.split(/\r?\n/).filter((url) => url.length > 0);
  if (urls.length === 0) {
    return { ok: false, reason: 'remote has no URLs' };
  }

  for (const url of urls) {
    if (!parseGitSshUrl(url).ok) {
      return { ok: false, reason: 'git remote resolves to a non-SSH address' };
    }
  }

  return { ok: true, urls };
}

function outputCollector(): {
  append: (chunk: Buffer) => void;
  text: (note?: string) => string;
} {
  const chunks: Buffer[] = [];
  let length = 0;
  let truncated = false;

  return {
    append(chunk) {
      const remaining = OUTPUT_LIMIT - length;
      if (chunk.length > remaining) {
        truncated = true;
      }
      if (remaining > 0) {
        const part = chunk.subarray(0, remaining);
        chunks.push(part);
        length += part.length;
      }
    },
    text(note = '') {
      let suffix = note;
      if (truncated || length + Buffer.byteLength(suffix) > OUTPUT_LIMIT) {
        suffix = '\n[output truncated]\n' + suffix;
      }

      const budget = OUTPUT_LIMIT - Buffer.byteLength(suffix);
      let text = Buffer.concat(chunks, length).subarray(0, budget).toString('utf8');
      // A cut through a UTF-8 character can introduce a larger replacement character.
      while (Buffer.byteLength(text) > budget) {
        text = text.slice(0, -1);
      }
      return text + suffix;
    },
  };
}

export async function runGit(
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  timeoutMs = 120000,
  signal?: AbortSignal,
): Promise<GitResult> {
  if (
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 2147483647
  ) {
    throw new RangeError('invalid git timeout');
  }

  return new Promise((resolve) => {
    // Its own process group, so a timeout kills git AND everything it started (ssh, helpers)
    // before the signing session closes (round 2, B3).
    const child = spawn('git', args, { cwd, env, stdio: 'pipe', detached: process.platform !== 'win32' });
    const stdout = outputCollector();
    const stderr = outputCollector();
    let finished = false;

    const timer = setTimeout(() => {
      finish(124, '\n[git timed out]\n');
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch { child.kill('SIGKILL'); }
      child.stdout.destroy();
      child.stderr.destroy();
      child.stdin.destroy();
    }, timeoutMs);

    const kill = (code: number, note: string) => {
      finish(code, note);
      try {
        if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch { child.kill('SIGKILL'); }
    };
    // Admin access ended (site SPEC-admin-access D7): the whole group, ssh included.
    if (signal?.aborted) kill(125, `\n[${String(signal.reason ?? 'stopped')}]\n`);
    else signal?.addEventListener('abort', () => kill(125, `\n[${String(signal.reason ?? 'stopped')}]\n`), { once: true });

    function finish(code: number, note = ''): void {
      if (finished) {
        return;
      }
      finished = true;
      clearTimeout(timer);
      resolve({
        code,
        stdout: stdout.text(),
        stderr: stderr.text(note),
      });
    }

    child.stdout.on('data', (chunk: Buffer) => {
      if (!finished) {
        stdout.append(chunk);
      }
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (!finished) {
        stderr.append(chunk);
      }
    });
    child.stdin.on('error', () => {
      // Git may exit before its input pipe closes.
    });
    child.stdin.end();

    child.on('error', () => finish(127, '\n[could not start git]\n'));
    child.on('close', (code) => finish(code ?? 1));
  });
}
