/**
 * CIP-016: Approved command templates for vault_exec.
 * Agents select templates by name — arbitrary shell strings are rejected.
 * Parameters are validated before substitution.
 */

import { realpathSync, lstatSync, statSync, fstatSync, fchmodSync, openSync, closeSync, readFileSync, writeFileSync, fsyncSync, renameSync, unlinkSync, constants as fsConstants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

export interface CommandTemplate {
  /** Command string. Use {param} for validated substitutions. */
  command: string;
  /** Env var name the secret is injected as */
  secretEnvKey: string;
  /** Allowed parameter names and their validators */
  params?: Record<string, (val: string) => boolean>;
  /** Human description shown in tool listing */
  description: string;
  /** If true, requires human approval gate before execution */
  highImpact: boolean;
}

// NPM auth helper: sets registry token, runs command, removes token on exit.
// NODE_AUTH_TOKEN alone is not read by npm without .npmrc wiring — this handles
// the full setup/teardown so agents need zero npm configuration beyond vault access.
const NPM_AUTH_WRAP = (cmd: string) =>
  `npm config set //registry.npmjs.org/:_authToken $NODE_AUTH_TOKEN && ${cmd}; npm config delete //registry.npmjs.org/:_authToken`;

export const TEMPLATES: Record<string, CommandTemplate> = {
  npm_publish: {
    command: NPM_AUTH_WRAP('npm publish --access public'),
    secretEnvKey: 'NODE_AUTH_TOKEN',
    description: 'Publish npm package to registry from current directory',
    highImpact: true,
  },
  npm_whoami: {
    command: NPM_AUTH_WRAP('npm whoami'),
    secretEnvKey: 'NODE_AUTH_TOKEN',
    description: 'Verify npm authentication token',
    highImpact: false,
  },
  npm_publish_scoped: {
    command: NPM_AUTH_WRAP('npm publish --access public --tag {tag}'),
    secretEnvKey: 'NODE_AUTH_TOKEN',
    params: {
      tag: (v) => /^[a-z0-9-]+$/.test(v) && v.length <= 32,
    },
    description: 'Publish npm package with a specific dist-tag',
    highImpact: true,
  },
  restic_backup: {
    command: 'restic backup {path}',
    secretEnvKey: 'RESTIC_PASSWORD',
    params: {
      path: (v) => !v.includes('..') && v.startsWith('/'),
    },
    description: 'Run restic backup on a given path',
    highImpact: false,
  },
  restic_check: {
    command: 'restic check',
    secretEnvKey: 'RESTIC_PASSWORD',
    description: 'Check restic repository integrity',
    highImpact: false,
  },
  git_push: {
    command: 'git push',
    secretEnvKey: 'GIT_ASKPASS_TOKEN',
    description: 'Git push using token credential',
    highImpact: true,
  },
};

/** Keys stripped from child process environment before injection */
export const STRIP_FROM_CHILD_ENV = [
  'WUNDERVAULT_AGENT_VAULT_API_KEY',
  'WUNDERVAULT_AGENT_ENCRYPTION_KEY',
  'WUNDERVAULT_AGENT_VAULT_URL',
  'WUNDERVault_AGENT_KEY',
  'WUNDERVault_AGENT_VAULT_API_KEY',
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'NODE_AUTH_TOKEN',
  'NPM_TOKEN',
  'RESTIC_PASSWORD',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'GITHUB_TOKEN',
  'GH_TOKEN',
];

/**
 * Directories a config file has no business being in. Not a substitute for a real
 * project-root allowlist (we have no concept of one) — a floor, so an agent cannot
 * name /etc/.env and have a basename rule wave it through.
 */
const FORBIDDEN_ROOTS = [
  '/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot',
  '/sys', '/proc', '/dev', '/run', '/var/lib', '/var/run', '/root',
  // macOS reaches several of these through /private; realpath() hands back that
  // spelling, so the list has to know both.
  '/private/etc', '/private/var/lib', '/private/var/run',
];

/** The account home, canonicalised once. os.homedir() honours $HOME on POSIX and may
 *  itself be a symlink; both sides of an equality test have to agree on spelling. */
function realHome(): string {
  try {
    return realpathSync(os.homedir());
  } catch {
    return os.homedir();
  }
}

/**
 * Allowed paths for vault_entry_inject_env.
 *
 * These run against a FULLY RESOLVED path — see resolveInjectTarget, which is the
 * only thing the server should call. A suffix match on an unresolved path is not a
 * policy: a symlink named `.env` satisfies `endsWith('/.env')` while pointing at any
 * file on the box, which would turn the "safe" injection tool into an arbitrary
 * file write. Resolve first, then ask these.
 */
/** Rules naming ONE exact destination. Safe to reach through a symlinked parent. */
const HOME_ANCHORED = [
  (p: string) => p === path.join(realHome(), '.npmrc'),
];

export const ALLOWED_INJECT_PATHS = [
  ...HOME_ANCHORED,
  (p: string) => path.basename(p) === '.env',
  (p: string) => path.basename(p) === '.env.local',
  (p: string) => path.basename(p) === '.env.production',
];

/**
 * Files this tool used to accept and cannot actually write. writeInjectedLine emits a
 * `KEY=value` line: appending one to .docker/config.json produces invalid JSON, and
 * .netrc is not key=value at all. Both were being corrupted rather than injected, so
 * they are refused by name with an explanation instead of silently mangled.
 */
const UNSUPPORTED_FORMATS: Array<[string, string]> = [
  [path.join(realHome(), '.netrc'), '.netrc uses its own machine/login/password grammar, not KEY=value'],
  [path.join(realHome(), '.docker', 'config.json'), 'a JSON file cannot take a KEY=value line'],
];

export function isAllowedInjectPath(filePath: string): boolean {
  return ALLOWED_INJECT_PATHS.some((fn) => fn(filePath));
}

export interface InjectTarget {
  /** The resolved path to write. */
  path: string;
  /** Identity of the verified parent directory, re-checked immediately before the
   *  write so a directory swapped underneath us is caught rather than followed. */
  parentDev: number;
  parentIno: number;
  /** Mode of the existing file, so a rewrite does not silently widen permissions. */
  existingMode?: number;
}

/**
 * Resolve an injection target and prove it is safe to write, or say why not.
 *
 * The allowlist only decides WHICH file is acceptable. It cannot decide WHERE that
 * file really lives, and every interesting attack is about where. So before the name
 * is judged:
 *   - the path must be absolute (a relative one silently resolves against whatever
 *     directory the daemon happens to be in),
 *   - the parent must already exist and contain no symlinked ancestor — honouring a
 *     redirect defeats the owner's "write to my project's .env",
 *   - the target, if it exists, must be a REGULAR FILE and not a symlink. A FIFO here
 *     is not hypothetical: opening one blocks forever, and every filesystem call on
 *     this path is synchronous, so a named pipe called `.env` hangs the whole daemon,
 *   - neither may sit in the temp tree or a system directory.
 *
 * What this deliberately does NOT try to do is win the race against a parent renamed
 * between here and the open. Node has no openat/RESOLVE_BENEATH, so that window is
 * closed by re-checking the parent's identity at write time (see InjectTarget) and by
 * writing through a temp file and rename rather than truncating in place.
 */
export function resolveInjectTarget(
  filePath: string,
): { ok: true; target: InjectTarget } | { ok: false; error: string } {
  if (typeof filePath !== 'string' || !filePath.trim()) {
    return { ok: false, error: 'No file_path given.' };
  }
  if (!path.isAbsolute(filePath)) {
    return { ok: false, error: `file_path must be absolute; got '${filePath}'.` };
  }

  const requested = path.resolve(filePath);
  const parent = path.dirname(requested);

  // Refuse a forbidden destination on the spelling we were handed, before asking the
  // filesystem anything. Otherwise a box without /root reports "does not exist" for
  // /root/.env — true, unhelpful, and the wrong reason.
  for (const root of FORBIDDEN_ROOTS) {
    if (requested === root || requested.startsWith(root + path.sep)) {
      return { ok: false, error: `Refusing to write a secret into a system directory ('${requested}').` };
    }
  }

  let realParent: string;
  try {
    realParent = realpathSync(parent);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    return code === 'ENOENT'
      ? { ok: false, error: `Directory '${parent}' does not exist. Create it first; injection will not create directories.` }
      : { ok: false, error: `Cannot resolve directory '${parent}' (${code ?? 'unknown error'}).` };
  }
  const target = path.join(realParent, path.basename(requested));

  // Judge location BEFORE the symlink rule, and judge BOTH spellings. macOS reaches
  // /etc through a symlink to /private/etc and /tmp through /private/tmp, so checking
  // only the resolved path would miss the denylist and checking only the lexical one
  // would miss the real destination. Either spelling landing somewhere forbidden is
  // enough, and asking here means the refusal names the actual reason.
  const spellings = [requested, target];

  let realTmp: string;
  try { realTmp = realpathSync(os.tmpdir()); } catch { realTmp = os.tmpdir(); }
  for (const p of spellings) {
    if (p === realTmp || p.startsWith(realTmp + path.sep) || p === os.tmpdir() || p.startsWith(os.tmpdir() + path.sep)) {
      return { ok: false, error: `Refusing to write a secret into the temp directory ('${p}').` };
    }
  }
  for (const root of FORBIDDEN_ROOTS) {
    for (const p of spellings) {
      if (p === root || p.startsWith(root + path.sep)) {
        return { ok: false, error: `Refusing to write a secret into a system directory ('${p}').` };
      }
    }
  }

  // A symlinked parent is refused for the basename rules (.env and friends), because
  // those accept ANY directory: honouring a redirect there would quietly relocate the
  // owner's "write my project's .env" to wherever the link points. The home-anchored
  // files name one exact destination, so resolving them is safe — and required, or a
  // user whose home is itself a symlink could not use the natural spelling at all.
  if (realParent !== parent && !HOME_ANCHORED.some((fn) => fn(target))) {
    return { ok: false, error: `Refusing to write through a symlinked directory: '${parent}' really resolves to '${realParent}'.` };
  }

  let existingMode: number | undefined;
  try {
    const st = lstatSync(target);
    if (st.isSymbolicLink()) {
      return { ok: false, error: `Refusing to write through a symlink: '${target}'.` };
    }
    if (!st.isFile()) {
      return { ok: false, error: `'${target}' exists and is not a regular file. Refusing to write a secret to it.` };
    }
    existingMode = st.mode & 0o777;
  } catch (err) {
    // Only "not there" is fine — injection creates the file. Anything else (EACCES,
    // EIO, ELOOP) means we could not establish what we are about to overwrite.
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      return { ok: false, error: `Cannot inspect '${target}': ${(err as NodeJS.ErrnoException)?.code ?? 'unknown error'}.` };
    }
  }

  for (const [p, why] of UNSUPPORTED_FORMATS) {
    if (target === p) {
      return { ok: false, error: `'${target}' is not supported by this tool: ${why}. Use vault_exec with the right tool for that file (e.g. 'npm config set', 'docker login').` };
    }
  }

  if (!isAllowedInjectPath(target)) {
    return { ok: false, error: `'${target}' is not an allowed config file path. Allowed: ~/.npmrc, ~/.netrc, ~/.docker/config.json, and project .env / .env.local / .env.production files.` };
  }

  // Inside the result union: this function promises an error, never a throw.
  try {
    const pst = statSync(realParent);
    return { ok: true, target: { path: target, parentDev: pst.dev, parentIno: pst.ino, existingMode } };
  } catch (err) {
    return { ok: false, error: `Cannot stat '${realParent}' (${(err as NodeJS.ErrnoException)?.code ?? 'unknown error'}).` };
  }
}

/**
 * Write `env_key=value` into a resolved target, replacing any existing line for that key.
 *
 * This is the other half of the path policy. resolveInjectTarget decides a NAME is
 * acceptable; this decides the bytes go to a file that still looks like what was
 * approved. Both halves are needed because every check made against a path is stale
 * the instant it returns.
 *
 * The write goes to a fresh 0600 file in the same directory, which is then renamed over
 * the target. That buys three things a truncating write cannot:
 *   - a hardlinked target is REPLACED rather than written through, so a `.env` that is
 *     a second name for ~/.bashrc leaves ~/.bashrc alone. Neither lstat nor O_NOFOLLOW
 *     can see a hardlink coming,
 *   - a failed or partial write cannot leave the real config truncated,
 *   - readers see the old file or the new one, never a half-written one.
 *
 * WHAT THIS DOES NOT DO: it does not win a race against another process mutating this
 * directory concurrently. Node exposes no openat/RESOLVE_BENEATH, so every operation
 * re-resolves the path from the root and the parent could be swapped between any two of
 * them. The parent identity re-check and the fstat below narrow those windows and turn
 * the common case into a clean abort; they do not close them. That is an accepted limit,
 * not an oversight: an attacker able to win this race is already running code as this
 * user, and can read the agent token and ask the vault for the secret directly. This
 * layer defends against a hostile PATH and planted files, not against a local attacker
 * who already has the credentials.
 */
export function writeInjectedLine(
  target: InjectTarget,
  envKey: string,
  value: string,
): { ok: true } | { ok: false; error: string } {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envKey)) {
    return { ok: false, error: `'${envKey}' is not a valid environment variable name.` };
  }

  const parentDir = path.dirname(target.path);
  let tmpPath: string | undefined;

  try {
    const pNow = statSync(parentDir);
    if (pNow.dev !== target.parentDev || pNow.ino !== target.parentIno) {
      return { ok: false, error: `'${parentDir}' changed identity after it was checked. Aborting rather than writing a secret into a directory swapped underneath us.` };
    }

    let lines: string[];
    let mode = target.existingMode ?? 0o600;
    try {
      // O_NONBLOCK so a FIFO swapped in after resolution cannot park this call — and
      // with it the whole daemon — waiting for a writer that never arrives.
      const fd = openSync(target.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
      try {
        // Re-establish on the OPEN FILE what was checked on the path. A regular file
        // with one link is the only thing safe to replace: more links means replacing
        // this name would also read out a file someone else still refers to.
        const st = fstatSync(fd);
        if (!st.isFile()) {
          return { ok: false, error: `'${target.path}' is not a regular file. Refusing to write a secret to it.` };
        }
        if (st.nlink !== 1) {
          return { ok: false, error: `'${target.path}' has ${st.nlink} hard links. Refusing to touch a file that is also known by another name.` };
        }
        mode = st.mode & 0o777;
        lines = readFileSync(fd, 'utf8').split('\n');
      } finally {
        closeSync(fd);
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      // Only "not there" may become an empty document. Anything else means we could not
      // establish what we are about to replace, and replacing it blind is data loss.
      if (code !== 'ENOENT') {
        return { ok: false, error: `Cannot read '${target.path}' (${code ?? 'unknown error'}). Refusing to overwrite a file whose contents could not be established.` };
      }
      lines = [];
      mode = 0o600;
    }

    const newLine = `${envKey}=${value}`;
    let replaced = false;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].split('=')[0].trim() === envKey) {
        lines[i] = newLine;
        replaced = true;
      }
    }
    if (!replaced) lines.push(newLine);

    tmpPath = path.join(parentDir, `.wv-inject-${randomBytes(8).toString('hex')}`);
    // Always 0600 while it holds a secret, whatever the destination's mode turns out
    // to be; the real mode is applied at the last moment, after the bytes are down.
    const fd = openSync(tmpPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    try {
      writeFileSync(fd, lines.join('\n'), 'utf8');
      fsyncSync(fd);
      fchmodSync(fd, mode);
    } finally {
      closeSync(fd);
    }
    renameSync(tmpPath, target.path);
    tmpPath = undefined;
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Write failed: ${(err as Error)?.message ?? 'unknown error'}` };
  } finally {
    // A temp still named here means we did not get as far as the rename. It holds the
    // secret, so it does not get to outlive the call.
    if (tmpPath) { try { unlinkSync(tmpPath); } catch { /* already gone */ } }
  }
}

export function buildCommand(
  template: CommandTemplate,
  params: Record<string, string> = {},
): { ok: true; command: string } | { ok: false; error: string } {
  let cmd = template.command;
  const placeholders = Array.from(cmd.matchAll(/\{(\w+)\}/g)).map((m) => m[1]);

  for (const key of placeholders) {
    const val = params[key];
    if (!val) return { ok: false, error: `Missing required param: ${key}` };
    const validator = template.params?.[key];
    if (validator && !validator(val)) {
      return { ok: false, error: `Invalid value for param '${key}': ${val}` };
    }
    // Reject shell metacharacters
    if (/[;&|`$<>\n\\]/.test(val)) {
      return { ok: false, error: `Param '${key}' contains disallowed characters` };
    }
    cmd = cmd.replace(`{${key}}`, val);
  }

  return { ok: true, command: cmd };
}