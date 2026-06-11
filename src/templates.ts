/**
 * CIP-016: Approved command templates for vault_exec.
 * Agents select templates by name — arbitrary shell strings are rejected.
 * Parameters are validated before substitution.
 */

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

/** Allowed paths for vault_entry_inject_env */
export const ALLOWED_INJECT_PATHS = [
  (p: string) => p === `${process.env.HOME}/.npmrc`,
  (p: string) => p === `${process.env.HOME}/.netrc`,
  (p: string) => p === `${process.env.HOME}/.docker/config.json`,
  (p: string) => p.endsWith('/.env') && !p.includes('/tmp/'),
  (p: string) => p.endsWith('/.env.local') && !p.includes('/tmp/'),
  (p: string) => p.endsWith('/.env.production') && !p.includes('/tmp/'),
];

export function isAllowedInjectPath(filePath: string): boolean {
  return ALLOWED_INJECT_PATHS.some((fn) => fn(filePath));
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