import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, openSync, writeSync, closeSync, rmSync } from 'node:fs';
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

/** Reject commands that could exfiltrate a secret to disk. Returns an error message, or null if safe. */
function rejectDangerous(command: string): string | null {
  for (const pattern of DANGEROUS_EXEC_PATTERNS) {
    if (pattern.test(command)) {
      return `Exec rejected: redirecting/writing a secret to a file is not permitted (matched: ${pattern}). `
        + `This guards against exfiltrating a secret to disk. To deliver a secret into a config file, `
        + `use the vault_entry_inject_env tool (writes one named entry, scrubbed) instead of a shell redirect. `
        + `For setup/teardown that needs the secret (e.g. 'npm config set …'), set pre_command/post_command in the entry's exec_config.`;
    }
  }
  return null;
}

/** Parent env with sensitive keys stripped, for handing to a child process. */
function strippedParentEnv(): Record<string, string> {
  return Object.fromEntries(
    Object.entries(process.env)
      .filter(([k, v]) => v !== undefined && !STRIP_FROM_CHILD_ENV.includes(k))
      .map(([k, v]) => [k, v as string])
  );
}

/** Redact any literal occurrence of the secret from captured output (never redact '' — it would corrupt output). */
function scrub(text: string, plaintext: string): string {
  return plaintext ? text.replaceAll(plaintext, '[SECRET_REDACTED]') : text;
}

function isTimeout(err: unknown): boolean {
  return !!err && typeof err === 'object' && 'code' in err && (err as { code?: string }).code === 'ETIMEDOUT';
}

/**
 * Execute a command with the secret injected as a named ENV VAR (the `generic`
 * recipe / default). Strips sensitive keys from parent env, scrubs the secret
 * from output, zeroes the buffer. Timeout: 30s. Exit code 124 = timeout.
 */
export function runWithSecret(
  plaintext: string,
  command: string,
  secretEnvKey: string = 'WUNDERVault_SECRET',
): ExecResult {
  const rejection = rejectDangerous(command);
  if (rejection) return { exitCode: 1, stdout: '', stderr: rejection };

  // Use a Buffer for the secret to allow explicit zeroing
  const secretBuf = Buffer.from(plaintext, 'utf8');
  const secretEnv: Record<string, string> = {
    ...strippedParentEnv(),
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
    if (isTimeout(result.error)) { exitCode = 124; stderr = 'Command timed out after 30 seconds.'; }
  } catch (err: unknown) {
    if (isTimeout(err)) { exitCode = 124; stderr = 'Command timed out after 30 seconds.'; }
    else { stderr = err instanceof Error ? err.message : String(err); }
  } finally {
    // Zero the buffer immediately after spawn — parent copy cleared
    secretBuf.fill(0);
  }

  return { exitCode, stdout: scrub(stdout, plaintext), stderr: scrub(stderr, plaintext) };
}

/**
 * Deliver the secret on the child's STDIN — never in the environment (`sudo`
 * recipe: `sudo -S` reads the password from stdin). Line-terminated by default.
 */
export function runWithSecretStdin(
  plaintext: string,
  command: string,
  opts: { appendNewline?: boolean } = {},
): ExecResult {
  const rejection = rejectDangerous(command);
  if (rejection) return { exitCode: 1, stdout: '', stderr: rejection };

  const payload = opts.appendNewline === false ? plaintext : `${plaintext}\n`;
  const inputBuf = Buffer.from(payload, 'utf8');
  let exitCode = 1;
  let stdout = '';
  let stderr = '';

  try {
    const result = spawnSync(command, {
      shell: true,
      env: strippedParentEnv(), // secret is NOT in the environment
      input: inputBuf,
      timeout: 30_000,
      encoding: 'utf8',
    });
    exitCode = result.status ?? 1;
    stdout = (result.stdout ?? '').toString();
    stderr = (result.stderr ?? '').toString();
    if (isTimeout(result.error)) { exitCode = 124; stderr = 'Command timed out after 30 seconds.'; }
  } catch (err: unknown) {
    if (isTimeout(err)) { exitCode = 124; stderr = 'Command timed out after 30 seconds.'; }
    else { stderr = err instanceof Error ? err.message : String(err); }
  } finally {
    inputBuf.fill(0);
  }

  return { exitCode, stdout: scrub(stdout, plaintext), stderr: scrub(stderr, plaintext) };
}

/**
 * Deliver the secret through an askpass helper that reads a PRIVATE PIPE
 * (`git` / `ssh-passphrase` recipes). The secret never touches the environment,
 * argv, or a file at rest — only a FIFO (which carries no data at rest) and a
 * helper script that holds just the (non-secret) FIFO path.
 *
 * A FIFO opened O_RDWR ('r+') does not block and keeps the pipe alive; we
 * pre-load one line, the tool's askpass helper reads it, then everything is
 * unlinked and the buffer zeroed.
 */
export function runWithSecretAskpass(
  plaintext: string,
  command: string,
  opts: { askpassVar: string; wrap?: 'setsid' },
): ExecResult {
  const rejection = rejectDangerous(command);
  if (rejection) return { exitCode: 1, stdout: '', stderr: rejection };

  const dir = mkdtempSync(path.join(os.tmpdir(), 'wv-ap-'));
  const fifo = path.join(dir, 'p');
  const helper = path.join(dir, 'ap');
  const secretBuf = Buffer.from(`${plaintext}\n`, 'utf8');
  let fifoFd: number | null = null;
  let exitCode = 1;
  let stdout = '';
  let stderr = '';

  try {
    const mk = spawnSync('mkfifo', ['-m', '600', fifo], { encoding: 'utf8' });
    if (mk.status !== 0) {
      return { exitCode: 1, stdout: '', stderr: `askpass: mkfifo failed: ${(mk.stderr ?? '').toString().trim() || mk.error?.message || 'unknown'}` };
    }

    // Helper prints ONE line read from the FIFO. The FIFO path is embedded as a
    // literal (not secret), so the helper depends on nothing in its environment.
    writeFileSync(helper, `#!/bin/sh\nIFS= read -r __wv < '${fifo}'\nprintf '%s\\n' "$__wv"\n`, { mode: 0o700 });

    // Pre-load the secret into the pipe buffer. 'r+' (O_RDWR) does not block and
    // keeps the pipe alive until the helper's read consumes the line.
    fifoFd = openSync(fifo, 'r+');
    writeSync(fifoFd, secretBuf);

    const env = strippedParentEnv();
    env[opts.askpassVar] = helper;
    if (opts.askpassVar === 'SSH_ASKPASS') {
      env.SSH_ASKPASS_REQUIRE = 'force';    // OpenSSH ≥ 8.4 uses askpass without a tty
      if (!env.DISPLAY) env.DISPLAY = ':0'; // older OpenSSH still checks DISPLAY
    }
    const finalCommand = opts.wrap === 'setsid' ? `setsid -w ${command}` : command;

    const result = spawnSync(finalCommand, { shell: true, env, timeout: 30_000, encoding: 'utf8' });
    exitCode = result.status ?? 1;
    stdout = (result.stdout ?? '').toString();
    stderr = (result.stderr ?? '').toString();
    if (isTimeout(result.error)) { exitCode = 124; stderr = 'Command timed out after 30 seconds.'; }
  } catch (err: unknown) {
    if (isTimeout(err)) { exitCode = 124; stderr = 'Command timed out after 30 seconds.'; }
    else { stderr = err instanceof Error ? err.message : String(err); }
  } finally {
    secretBuf.fill(0);
    if (fifoFd !== null) { try { closeSync(fifoFd); } catch { /* ignore */ } }
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }

  return { exitCode, stdout: scrub(stdout, plaintext), stderr: scrub(stderr, plaintext) };
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

  // Single-quote the secret for safe shell assignment; handle embedded single-quotes.
  // When no env var is being injected (SSH-only remote exec, e.g. running a command
  // with just a vaulted SSH key), omit the export line entirely.
  const escapedSecret = plaintext.replace(/'/g, `'\\''`);
  const stdinScript = secretEnvKey
    ? `export ${secretEnvKey}='${escapedSecret}'\n${command}\n`
    : `${command}\n`;

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

  // Only redact when a secret was actually injected (replaceAll('') would corrupt output).
  if (plaintext) {
    stdout = stdout.replaceAll(plaintext, '[SECRET_REDACTED]');
    stderr = stderr.replaceAll(plaintext, '[SECRET_REDACTED]');
  }

  return { exitCode, stdout, stderr };
}