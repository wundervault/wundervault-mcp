import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, openSync, writeSync, closeSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { ExecConfig, ExecResult, RemoteHost } from './types.js';
import { STRIP_FROM_CHILD_ENV } from './templates.js';

/**
 * The backend stores exec_config as an opaque JSON STRING and forwards it
 * as-is. Coerce it to an object before use — tolerating an already-parsed
 * object, a JSON string, or absent/garbage (→ undefined). Without this the
 * dashboard's credential_type/env_key never reach the delivery dispatch.
 */
export function coerceExecConfig(raw: unknown): ExecConfig | undefined {
  if (!raw) return undefined;
  if (typeof raw === 'object') return raw as ExecConfig;
  if (typeof raw === 'string') {
    const s = raw.trim();
    if (!s) return undefined;
    try {
      const parsed = JSON.parse(s);
      return parsed && typeof parsed === 'object' ? (parsed as ExecConfig) : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/**
 * Decide the delivery config for one exec, given the entry's owner-set exec_config
 * and the calling agent's requested inject_as.
 *
 * The owner's channel is a CEILING, not a default. An agent that can name its own
 * delivery can pull a stdin-only secret into the process environment, where
 * /proc/<pid>/environ and every child process can read it — which would make the
 * owner's choice advisory. Two fields can name a channel (credential_type, and the
 * lower-level mechanism escape hatch); pinning both from the server config is what
 * stops an agent from dodging the first by using the second.
 *
 * Non-delivery fields (env_key, pre/post commands) stay negotiable, with the
 * owner's value preferred where it is set.
 */
/**
 * An env var name reaches us from the calling agent (inject_as.env_key) or from the
 * entry's exec_config, and it is INTERPOLATED, not passed as data:
 *   - runWithSecretRemote builds `export ${key}='<secret>'` and pipes it to a remote
 *     shell, so a key containing `;` is remote command execution. The shell-escape
 *     screen upstream only ever inspected `command`, never this,
 *   - writeInjectedLine builds `${key}=<secret>` as a config line, so a key containing
 *     a newline writes additional lines of attacker-chosen configuration.
 * Neither needs a clever payload — a semicolon or a newline is enough. Hold every key
 * to what a shell environment variable may actually be called.
 */
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function isValidEnvKey(k: unknown): k is string {
  return typeof k === 'string' && k.length <= 128 && ENV_KEY_RE.test(k);
}

export const VALID_MECHANISMS = ['env', 'stdin', 'askpass'] as const;

/** A mechanism arrives as opaque JSON from the backend or as an agent argument.
 *  Anything that is not one of the three real channels is rejected rather than
 *  allowed to fall through the dispatch — the bottom of that chain is `env`, so an
 *  unrecognised value would fail open into the least confidential delivery. */
export function isValidMechanism(m: unknown): m is 'env' | 'stdin' | 'askpass' {
  return typeof m === 'string' && (VALID_MECHANISMS as readonly string[]).includes(m);
}

/** Treat blank strings as absent: a dashboard that serialises an unselected recipe
 *  as "" must not read as "this entry names a channel" — nor, via ??, as a reason to
 *  discard an owner mechanism sitting right beside it. */
function present(v: string | undefined): string | undefined {
  const t = typeof v === 'string' ? v.trim() : undefined;
  return t ? t : undefined;
}

export function resolveDeliveryConfig(
  serverCfg: ExecConfig | undefined,
  injectAs: ExecConfig | undefined,
):
  | { ok: true; cfg: ExecConfig | undefined; ignoredOverride?: { asked: string; enforced: string } }
  | { ok: false; error: string } {
  const serverType = present(serverCfg?.credential_type);
  const serverMech = present(serverCfg?.mechanism);
  const clientType = present(injectAs?.credential_type);
  const clientMech = present(injectAs?.mechanism);

  if (serverMech !== undefined && !isValidMechanism(serverMech)) {
    return { ok: false, error: `This entry's exec_config names an unknown delivery mechanism '${serverMech}'. Valid: ${VALID_MECHANISMS.join(', ')}. Fix it in the dashboard.` };
  }
  if (clientMech !== undefined && !isValidMechanism(clientMech)) {
    return { ok: false, error: `Unknown delivery mechanism '${clientMech}' in inject_as. Valid: ${VALID_MECHANISMS.join(', ')}.` };
  }

  const serverChannel = serverType ?? serverMech;
  if (!serverChannel) {
    // No owner-set channel. The agent may choose, but the owner's other fields still
    // stand where the agent did not supply its own. Hand back a NORMALISED config
    // either way: returning serverCfg raw would let a whitespace-only credential_type
    // that present() just declared absent come back to life as an unknown recipe.
    if (!serverCfg && !injectAs) return { ok: true, cfg: undefined };
    return {
      ok: true,
      cfg: {
        ...(injectAs ?? {}),
        env_key: injectAs?.env_key ?? serverCfg?.env_key,
        pre_command: injectAs?.pre_command ?? serverCfg?.pre_command,
        post_command: injectAs?.post_command ?? serverCfg?.post_command,
        askpass_var: injectAs?.askpass_var ?? serverCfg?.askpass_var,
        credential_type: undefined,
        mechanism: clientMech as ExecConfig['mechanism'],
      },
    };
  }

  const cfg: ExecConfig = {
    ...(injectAs ?? {}),
    env_key: serverCfg?.env_key ?? injectAs?.env_key,
    pre_command: serverCfg?.pre_command ?? injectAs?.pre_command,
    post_command: serverCfg?.post_command ?? injectAs?.post_command,
    credential_type: serverType,
    mechanism: serverMech as ExecConfig['mechanism'],
    askpass_var: serverCfg?.askpass_var ?? injectAs?.askpass_var,
  };

  // Report on EITHER channel field the agent tried, not just the first one present:
  // {credential_type: 'sudo', mechanism: 'env'} silently lost its `env` before.
  const conflicting = [clientType, clientMech].find((a) => a && a !== serverChannel);
  return conflicting
    ? { ok: true, cfg, ignoredOverride: { asked: conflicting, enforced: serverChannel } }
    : { ok: true, cfg };
}

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
  opts: { cwd?: string } = {},
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
      cwd: opts.cwd,
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
  opts: { appendNewline?: boolean; cwd?: string } = {},
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
      cwd: opts.cwd,
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
  opts: { askpassVar: string; wrap?: 'setsid'; cwd?: string },
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

    const result = spawnSync(finalCommand, { shell: true, env, cwd: opts.cwd, timeout: 30_000, encoding: 'utf8' });
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
  if (secretEnvKey && !isValidEnvKey(secretEnvKey)) {
    return { exitCode: 1, stdout: '', stderr: `Refusing to build a remote script with an invalid env var name '${secretEnvKey}'.` };
  }
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