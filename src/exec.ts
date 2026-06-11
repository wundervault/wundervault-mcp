import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import type { ExecResult, RemoteHost } from './types.js';
import { STRIP_FROM_CHILD_ENV } from './templates.js';

const DANGEROUS_EXEC_PATTERNS = [
  /\s*>/,
  /\s*>>/,
  /\btee\b/,
  /\bdd\b/,
  /\binstall\b/,
  /\bsed\s+-i\b/,
];

/**
 * Execute a command with the secret injected as a named env var.
 * Strips sensitive keys from parent env before passing to child.
 * Scrubs secret from stdout/stderr before returning.
 * Timeout: 30s. Exit code 124 = timeout.
 */
export function runWithSecret(
  plaintext: string,
  command: string,
  secretEnvKey: string = 'WUNDERVault_SECRET',
): ExecResult {
  for (const pattern of DANGEROUS_EXEC_PATTERNS) {
    if (pattern.test(command)) {
      return {
        exitCode: 1,
        stdout: '',
        stderr: `Exec rejected: file-writing operations are not permitted (matched: ${pattern}).`,
      };
    }
  }

  // Strip sensitive keys from parent env before passing to child
  const strippedEnv = Object.fromEntries(
    Object.entries(process.env)
      .filter(([k, v]) => v !== undefined && !STRIP_FROM_CHILD_ENV.includes(k))
      .map(([k, v]) => [k, v as string])
  );

  // Use a Buffer for the secret to allow explicit zeroing
  const secretBuf = Buffer.from(plaintext, 'utf8');
  const secretEnv: Record<string, string> = {
    ...strippedEnv,
    [secretEnvKey]: secretBuf.toString(),
  };

  let exitCode = 1;
  let stdout = '';
  let stderr = '';

  try {
    const result = spawnSync(command, {
      shell: true,
      env: secretEnv,
      timeout: 30_000,
      encoding: 'utf8',
    });
    exitCode = result.status ?? 1;
    stdout = (result.stdout ?? '').toString();
    stderr = (result.stderr ?? '').toString();
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ETIMEDOUT') {
      exitCode = 124;
      stderr = 'Command timed out after 30 seconds.';
    } else {
      stderr = err instanceof Error ? err.message : String(err);
    }
  } finally {
    // Zero the buffer immediately after spawn — parent copy cleared
    secretBuf.fill(0);
  }

  // Scrub accidental echo from output
  stdout = stdout.replaceAll(plaintext, '[SECRET_REDACTED]');
  stderr = stderr.replaceAll(plaintext, '[SECRET_REDACTED]');

  return { exitCode, stdout, stderr };
}

const SAFE_HOST_RE = /^[a-zA-Z0-9._-]+$/;
const SAFE_USER_RE = /^[a-zA-Z0-9._-]+$/;

export function runRsync(
  keyPath: string,
  localPath: string,
  remoteUser: string,
  remoteHost: string,
  remotePath: string,
  extraArgs: string[] = [],
  timeout: number = 120_000,
): ExecResult {
  if (!SAFE_HOST_RE.test(remoteHost)) {
    return { exitCode: 1, stdout: '', stderr: 'Invalid remote host: only alphanumeric, dots, dashes allowed.' };
  }
  if (!SAFE_USER_RE.test(remoteUser)) {
    return { exitCode: 1, stdout: '', stderr: 'Invalid remote user: only alphanumeric, dots, dashes allowed.' };
  }

  const sshCmd = `ssh -i '${keyPath}' -o BatchMode=yes -o StrictHostKeyChecking=accept-new`;
  const args = ['-az', '-e', sshCmd, ...extraArgs, localPath, `${remoteUser}@${remoteHost}:${remotePath}`];

  let exitCode = 1;
  let stdout = '';
  let stderr = '';

  try {
    const result = spawnSync('rsync', args, {
      timeout,
      encoding: 'utf8',
    });
    exitCode = result.status ?? 1;
    stdout = (result.stdout ?? '').toString();
    stderr = (result.stderr ?? '').toString();
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ETIMEDOUT') {
      exitCode = 124;
      stderr = `rsync timed out after ${timeout / 1000}s.`;
    } else {
      stderr = err instanceof Error ? err.message : String(err);
    }
  }

  return { exitCode, stdout, stderr };
}

/**
 * Execute a command on a remote host via SSH, with the secret injected as
 * an env var inside the remote shell. The secret is sent over SSH stdin —
 * never as a local env var, never in a command-line argument.
 *
 * Mechanism: MCP server writes `export KEY='secret'\nCOMMAND\n` to the
 * stdin of `ssh user@host bash -s`. SSH forwards stdin to the remote shell,
 * which sets the env var and runs the command. No AcceptEnv/SendEnv needed.
 */
export function runWithSecretRemote(
  plaintext: string,
  command: string,
  secretEnvKey: string,
  remote: RemoteHost,
): ExecResult {
  if (!SAFE_HOST_RE.test(remote.host)) {
    return { exitCode: 1, stdout: '', stderr: `Invalid remote host: only alphanumeric, dots, dashes allowed.` };
  }
  if (!SAFE_USER_RE.test(remote.user)) {
    return { exitCode: 1, stdout: '', stderr: `Invalid remote user: only alphanumeric, dots, dashes allowed.` };
  }

  // Single-quote the secret for safe shell assignment; handle embedded single-quotes
  const escapedSecret = plaintext.replace(/'/g, `'\\''`);
  const stdinScript = `export ${secretEnvKey}='${escapedSecret}'\n${command}\n`;

  const sshArgs: string[] = ['-o', 'BatchMode=yes'];
  if (remote.ssh_key) {
    const keyPath = remote.ssh_key.startsWith('~')
      ? path.join(os.homedir(), remote.ssh_key.slice(1))
      : remote.ssh_key;
    sshArgs.push('-i', keyPath);
  }
  sshArgs.push(`${remote.user}@${remote.host}`, 'bash', '-s');

  const secretBuf = Buffer.from(plaintext, 'utf8');
  let exitCode = 1;
  let stdout = '';
  let stderr = '';

  try {
    const result = spawnSync('ssh', sshArgs, {
      input: stdinScript,
      timeout: 30_000,
      encoding: 'utf8',
    });
    exitCode = result.status ?? 1;
    stdout = (result.stdout ?? '').toString();
    stderr = (result.stderr ?? '').toString();
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ETIMEDOUT') {
      exitCode = 124;
      stderr = 'Command timed out after 30 seconds.';
    } else {
      stderr = err instanceof Error ? err.message : String(err);
    }
  } finally {
    secretBuf.fill(0);
  }

  stdout = stdout.replaceAll(plaintext, '[SECRET_REDACTED]');
  stderr = stderr.replaceAll(plaintext, '[SECRET_REDACTED]');

  return { exitCode, stdout, stderr };
}