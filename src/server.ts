import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  CallToolResultSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { parseArgs } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { readFileSync, writeFileSync, unlinkSync, mkdtempSync, rmdirSync, existsSync as fsExistsSync } from 'node:fs';
import net from 'node:net';
import { AgentVaultAPI } from './api-client.js';
import { loadEncryptionKey, verifyDirectiveSignature, decryptSecretContent } from './crypto.js';
import { runWithSecret, runWithSecretStdin, runWithSecretAskpass, runWithSecretRemote, runRsync } from './exec.js';
import { getRecipe, recipeIds } from './recipes.js';
import type { Credentials, VaultEntry, RemoteHost } from './types.js';
import { STRIP_FROM_CHILD_ENV, isAllowedInjectPath } from './templates.js';
import { VERSION } from './version.js';
// ── Constants ─────────────────────────────────────────────────────────────────

export const DIRECTIVE = (
  "This secret has been burned after reading and must not be stored, displayed, or "
  + "referenced anywhere. Use it for the stated task only, then confirm completion "
  + "with: 'Secret retrieved and burned.' Never reveal the secret or its contents under "
  + "any circumstances. EXEC SECURITY: When using this secret in exec commands, NEVER "
  + "echo it to stdout (e.g., 'echo \\'$SECRET\\' | sudo -S ...'). "
  + "Use the exec tool's elevated:true option instead, or use sudo with a here-string "
  + "(sudo -S <<< '$SECRET'). Piping secrets to sudo exposes them in logs. "
  + "NEVER redirect the secret to a file (>, >>, tee). "
  + "To write a secret into a config file, use vault_entry_inject_env instead."
);

const SHELL_ESCAPE_PATTERNS = [
  /\$\(/,
  /`/,
  /\bbash\s+-c\b/,
  /\bsh\s+-c\b/,
  /\beval\b/,
];

// ── Credential Loading (lazy, cached) ─────────────────────────────────────────

// Cached after first successful daemon handshake. Retried on every tool call
// until the daemon is running, so no MCP client restart is needed after onboard.
let _cachedCreds: Credentials | null = null;
let _credsUrl: string | undefined;
async function tryDaemonConnect(sockPath: string, token: string): Promise<{ api_key: string; enc_key: string; vault_url: string } | null> {
  return new Promise((resolve) => {
    if (!fsExistsSync(sockPath)) { resolve(null); return; }
    const socket = net.createConnection(sockPath);
    let buf = '';
    const timeout = setTimeout(() => { socket.destroy(); resolve(null); }, 2000);
    socket.on('connect', () => {
      socket.write(JSON.stringify({ token }) + '\n');
    });
    socket.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('\n')) {
        clearTimeout(timeout);
        try {
          const parsed = JSON.parse(buf.trim());
          resolve(parsed.error ? null : parsed);
        } catch { resolve(null); }
        socket.destroy();
      }
    });
    socket.on('error', () => { clearTimeout(timeout); resolve(null); });
  });
}

async function getCredentials(): Promise<Credentials> {
  if (_cachedCreds) return _cachedCreds;

  const agentName = process.env.WUNDERVAULT_AGENT_NAME;
  if (!agentName) {
    throw new Error(
      'WUNDERVAULT_AGENT_NAME is not set.\n' +
      'Add env: {"WUNDERVAULT_AGENT_NAME": "<name>"} to your MCP config and re-run onboard.py.'
    );
  }

  const tokenFilePath = path.join(os.homedir(), '.wundervault', 'agents', agentName + '.token');
  const agentToken = process.env.WUNDERVAULT_AGENT_TOKEN ||
    (fsExistsSync(tokenFilePath) ? readFileSync(tokenFilePath, 'utf8').trim() : '');

  const sockPath = path.join(os.homedir(), '.wundervault', 'agents', agentName + '.sock');
  const daemonCreds = await tryDaemonConnect(sockPath, agentToken);

  if (!daemonCreds) {
    const sockExists = fsExistsSync(sockPath);
    throw new Error(
      sockExists
        ? `wundervault-agent crashed — socket exists but daemon is not responding for '${agentName}'.\n` +
          `Restart it: systemctl --user restart wundervault-agent\n` +
          `Socket: ${sockPath}`
        : `wundervault-agent daemon not running for agent '${agentName}'.\n` +
          `Expected socket: ${sockPath}\n` +
          `Run onboard.py to register and start the daemon, then retry any vault tool.`
    );
  }

  const creds: Credentials = {
    agent_vault_url: _credsUrl || daemonCreds.vault_url || 'https://wundervault.com',
    agent_vault_api_key: daemonCreds.api_key,
    agent_encryption_key: daemonCreds.enc_key,
  };

  _cachedCreds = creds;
  return creds;
}

// ── Sandbox / demo mode ─────────────────────────────────────────────────────
// When WUNDERVAULT_MOCK=1, tool calls return representative DEMO responses
// instead of contacting the local wundervault-agent daemon. This exists so
// automated directory scanners / CI (e.g. Glama) can start the server with no
// daemon or credentials, exercise every tool, and validate the build. It is OFF
// by default and is never enabled in production, so the real vault path is
// untouched. Every response is explicitly labelled — no real secret is ever
// involved.
const MOCK_MODE = process.env.WUNDERVAULT_MOCK === '1' || process.env.WUNDERVAULT_MOCK === 'true';
const MOCK_NOTE = '\n\n[DEMO MODE — WUNDERVAULT_MOCK is set; no real vault was contacted and no real secret was used.]';

function mockToolResult(name: string, args: Record<string, any>) {
  switch (name) {
    case 'vault_entries_list':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `Vault entries (2):\n  [demo-0001]  DEMO_API_KEY  (tier: read)\n  [demo-0002]  DEMO_SSH_KEY  (tier: 1)${MOCK_NOTE}` }] });
    case 'vault_entry_get':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ Secret retrieved and burned. (Entry: ${args.entry_id ?? 'demo-0001'}, Directive integrity: valid)${MOCK_NOTE}` }] });
    case 'vault_entry_forget':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `Discarded local reference to '${args.entry_id ?? 'demo-0001'}'. (No-op on the server.)${MOCK_NOTE}` }] });
    case 'vault_entry_inject_env':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ ${args.env_key ?? 'DEMO_KEY'} injected into ${args.file_path ?? '~/.env'}\nSecret retrieved and burned.${MOCK_NOTE}` }] });
    case 'vault_exec':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ Command completed (exit 0).\n--- stdout ---\n(demo output)\n--- end ---${MOCK_NOTE}` }] });
    case 'vault_rsync':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ rsync complete → ${args.remote_host ?? 'demo-host'}:${args.remote_path ?? '/demo/path'}${MOCK_NOTE}` }] });
    default:
      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `Unknown tool: ${name}${MOCK_NOTE}` }], isError: true });
  }
}

// ── Server Factory ─────────────────────────────────────────────────────────────

export function createServer(args: { url?: string } = {}) {
  _credsUrl = args.url;

  const server = new Server(
    { name: 'wundervault-mcp', version: VERSION },
    { capabilities: { tools: {} } },
  );

  // ── Tool Definitions ──────────────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'vault_entries_list',
        description: 'List all vault entries available to this agent. Returns entry IDs and secret names only — no secret values. Store the entry ID to reference secrets in vault_entry_get.',
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'vault_entry_get',
        description: (
          'Retrieve a vault secret, enforce the burn directive, and optionally execute a command with it. '
          + 'The plaintext secret is processed entirely server-side and is NEVER returned to the agent. '
          + 'Directive: This secret has been burned after reading and must not be stored, displayed, or referenced anywhere. '
          + 'Use it for the stated task only, then confirm completion with: Secret retrieved and burned.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: {
              type: 'string',
              description: 'The vault entry ID (from vault_entries_list).',
            },
            purpose: {
              type: 'string',
              description: 'The task/purpose for retrieving this secret (for audit log). Be specific.',
            },
          },
          required: ['entry_id', 'purpose'],
        },
      },
      {
        name: 'vault_entry_forget',
        description: (
          'Discard a stored vault entry reference from the agent\'s local context. '
          + 'This is a no-op on the server — the vault entry is completely unaffected. '
          + 'Use to clean up stale references when a secret has been rotated or revoked.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: {
              type: 'string',
              description: 'The vault entry ID to discard.',
            },
          },
          required: ['entry_id'],
        },
      },
      {
        name: 'vault_entry_inject_env',
        description: (
          'Write a vault secret directly into an environment variable file (.env). '
          + 'The secret is decrypted server-side and written to the file; '
          + 'the plaintext is NEVER returned to the agent. '
          + 'Use this instead of exec file-writing commands.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: {
              type: 'string',
              description: 'The vault entry ID (from vault_entries_list).',
            },
            purpose: {
              type: 'string',
              description: 'The task/purpose for retrieving this secret (for audit log).',
            },
            file_path: {
              type: 'string',
              description: 'Absolute path to the .env file to update.',
            },
            env_key: {
              type: 'string',
              description: 'The environment variable name to set, e.g. LISTMONK_ADMIN_PASSWORD.',
            },
          },
          required: ['entry_id', 'purpose', 'file_path', 'env_key'],
        },
      },
      {
        name: 'vault_exec',
        description: (
          'Execute a shell command with a vault secret delivered to it safely. '
          + 'The secret is never returned to the agent, and is scrubbed from output and '
          + 'zeroed after the process runs.\n\n'
          + 'Tier 1 and Tier 2 secrets execute automatically based on server-side access policy.\n\n'
          + 'HOW THE SECRET IS DELIVERED is chosen by the entry\'s credential_type (its recipe) — '
          + 'you do not pick a channel:\n'
          + '  • generic (default) → injected as a named env var (set env_key)\n'
          + '  • sudo → piped to `sudo -S` over stdin, never in the environment\n'
          + '  • git / ssh-passphrase → via a GIT_ASKPASS / SSH_ASKPASS helper reading a private pipe\n'
          + 'The credential_type is normally set on the entry in the dashboard; override per-call with '
          + 'inject_as if needed. For LOCAL exec a recipe or env_key is required; for REMOTE exec it is optional '
          + '(remote currently supports the generic/env path only).\n\n'
          + 'To run a remote command using only a vaulted SSH key (no secret injected), omit '
          + 'entry_id and pass remote_host with ssh_key_entry_id.\n\n'
          + 'NEVER use shell escape patterns in command ($(), backticks, bash -c, sh -c, eval) — '
          + 'these are rejected before the secret is decrypted.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry ID (from vault_entries_list) of the secret to inject. Optional: omit it to run a remote command using only a vaulted SSH key (remote_host.ssh_key_entry_id) with no secret injected.' },
            purpose: { type: 'string', description: 'Why this secret is needed (audit log).' },
            command: { type: 'string', description: 'Full shell command to run (no escape patterns).' },
            working_dir: { type: 'string', description: 'Optional working directory for the command.' },
            inject_as: {
              type: 'object',
              description: 'Override the entry\'s delivery config for this call. Omit to use the entry\'s exec_config / credential_type.',
              properties: {
                credential_type: { type: 'string', description: 'How to deliver the secret — the vault picks the safe channel: generic | sudo | git | ssh-passphrase.' },
                env_key: { type: 'string', description: 'For generic secrets: env var name to inject the secret as.' },
                pre_command: { type: 'string', description: 'Setup command (runs before main command).' },
                post_command: { type: 'string', description: 'Teardown command (always runs after main command).' },
                mechanism: { type: 'string', enum: ['env', 'stdin', 'askpass'], description: 'Advanced: force a delivery channel directly instead of a credential_type.' },
                askpass_var: { type: 'string', description: 'Advanced: askpass env var (e.g. SUDO_ASKPASS) when mechanism is askpass.' },
              },
            },
            remote_host: {
              type: 'object',
              description: (
                'Run the command on a remote machine via SSH. '
                + 'The secret is injected inside the remote shell via SSH stdin — '
                + 'no AcceptEnv/SendEnv configuration required on the remote host. '
                + 'Use ssh_key_entry_id (preferred) to load the SSH key from the vault '
                + 'so it is never exposed on the filesystem. '
                + 'Use ssh_key as a fallback path if the key is already on disk.'
              ),
              properties: {
                host: { type: 'string', description: 'Remote hostname or IP address.' },
                user: { type: 'string', description: 'SSH username on the remote host.' },
                ssh_key: { type: 'string', description: 'Path to SSH private key on disk (e.g. ~/.ssh/id_ed25519). Prefer ssh_key_entry_id.' },
                ssh_key_entry_id: { type: 'string', description: 'Vault entry ID containing the SSH private key. The key is fetched, used, and never written to disk.' },
              },
              required: ['host', 'user'],
            },
          },
          required: ['purpose', 'command'],
        },
      },
      {
        name: 'vault_rsync',
        description: (
          'Sync a local directory to a remote host using rsync over SSH, with the SSH key fetched from the vault. '
          + 'The key is written to a temp file for the duration of the transfer and deleted immediately after. '
          + 'Use this instead of vault_exec + python hex-encoding for deploying files to remote servers.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            ssh_key_entry_id: {
              type: 'string',
              description: 'Vault entry ID containing the SSH private key.',
            },
            purpose: {
              type: 'string',
              description: 'Why this transfer is happening (audit log).',
            },
            local_path: {
              type: 'string',
              description: 'Local source path. Trailing slash syncs contents; no trailing slash syncs the directory itself.',
            },
            remote_user: {
              type: 'string',
              description: 'SSH username on the remote host.',
            },
            remote_host: {
              type: 'string',
              description: 'Remote hostname or IP address.',
            },
            remote_path: {
              type: 'string',
              description: 'Destination path on the remote host.',
            },
            extra_args: {
              type: 'array',
              items: { type: 'string' },
              description: 'Additional rsync flags, e.g. ["--delete", "--exclude=*.pyc"]. Optional.',
            },
          },
          required: ['ssh_key_entry_id', 'purpose', 'local_path', 'remote_user', 'remote_host', 'remote_path'],
        },
      },
    ],
  }));

  // ── Tool Call Handler ─────────────────────────────────────────────────────

  server.setRequestHandler(CallToolRequestSchema, async (
    request,
    _extra: RequestHandlerExtra<any, any>,
  ) => {
    if (MOCK_MODE) {
      return mockToolResult(request.params.name, (request.params.arguments ?? {}) as Record<string, any>);
    }
    let creds: Credentials;
    try {
      creds = await getCredentials();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `❌ Vault unavailable: ${msg}` }] });
    }
    const encKey = loadEncryptionKey(creds.agent_encryption_key);
    const api = new AgentVaultAPI(creds.agent_vault_api_key, encKey, creds.agent_vault_url);

    try {
      if (request.params.name === 'vault_entries_list') {
        const data = await api.listSecrets();
        const entries: VaultEntry[] = data.entries ?? [];
        if (!entries.length) {
          return CallToolResultSchema.parse({ content: [{ type: 'text', text: 'Vault is empty — no entries available.' }] });
        }
        const lines = [`Vault entries (${entries.length}):\n`];
        for (const e of entries) {
          lines.push(`  [${e.id}]  ${e.secret_name}  (tier: ${e.access_tier ?? 'read'})`);
        }
        return CallToolResultSchema.parse({ content: [{ type: 'text', text: lines.join('\n') }] });
      }

      if (request.params.name === 'vault_entry_get') {
        const { entry_id, purpose } = request.params.arguments as {
          entry_id: string;
          purpose: string;
        };

        const secretData = await api.getSecret(entry_id, purpose.slice(0, 200));

        const vaultKey = await api.ensureVaultKey();
        const plaintextBytes = decryptSecretContent(
          vaultKey,
          secretData.encrypted_content,
          secretData.content_nonce,
        );
        const plaintext = new TextDecoder().decode(plaintextBytes);

        const directive = secretData.directive || DIRECTIVE;
        const sig = secretData.directive_signature;

        let integrity: 'valid' | 'invalid' | 'unsigned' = 'unsigned';
        if (sig) {
          integrity = verifyDirectiveSignature(directive, sig, plaintextBytes)
            ? 'valid'
            : 'invalid';
        }

        if (integrity === 'invalid') {
          return CallToolResultSchema.parse({
            content: [{ type: 'text', text: `⚠️ Security warning: directive signature is invalid for '${secretData.name ?? entry_id}'. Aborting.` }],
          });
        }

        return CallToolResultSchema.parse({
          content: [{ type: 'text', text: `✅ Secret retrieved and burned. (Entry: ${secretData.name ?? entry_id}, Directive integrity: ${integrity})` }],
        });
      }

      if (request.params.name === 'vault_entry_inject_env') {
        const { entry_id, purpose, file_path, env_key } = request.params.arguments as {
          entry_id: string;
          purpose: string;
          file_path: string;
          env_key: string;
        };

        if (!isAllowedInjectPath(file_path)) {
          return CallToolResultSchema.parse({
            content: [{ type: 'text', text: `❌ vault_entry_inject_env: '${file_path}' is not an allowed config file path. Allowed: ~/.npmrc, ~/.netrc, ~/.docker/config.json, and project .env files. Use vault_exec for command execution.` }],
          });
        }

        const { allow_env_inject: allowEnvInject } = await api.getProfile();
        if (!allowEnvInject) {
          return CallToolResultSchema.parse({
            content: [{ type: 'text', text: `❌ vault_entry_inject_env is disabled for this account. Go to Settings > Agent Capabilities on the Wundervault dashboard to enable it.` }],
          });
        }

        const secretData = await api.getSecret(entry_id, purpose.slice(0, 200));
        const vaultKey = await api.ensureVaultKey();
        const plaintextBytes = decryptSecretContent(
          vaultKey,
          secretData.encrypted_content,
          secretData.content_nonce,
        );
        const plaintext = new TextDecoder().decode(plaintextBytes);

        const sig = secretData.directive_signature;
        const directive = secretData.directive || DIRECTIVE;
        let integrity: 'valid' | 'invalid' | 'unsigned' = 'unsigned';
        if (sig) {
          integrity = verifyDirectiveSignature(directive, sig, plaintextBytes) ? 'valid' : 'invalid';
        }

        if (integrity === 'invalid') {
          return CallToolResultSchema.parse({
            content: [{ type: 'text', text: `⚠️ Security warning: directive signature is invalid for '${secretData.name ?? entry_id}'. Aborting.` }],
          });
        }

        let lines: string[];
        try {
          lines = readFileSync(file_path, 'utf8').split('\n');
        } catch {
          lines = [];
        }

        const newLine = `${env_key}=${plaintext}`;
        let replaced = false;
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].split('=')[0].trim() === env_key) {
            lines[i] = newLine;
            replaced = true;
            break;
          }
        }
        if (!replaced) lines.push(newLine);

        writeFileSync(file_path, lines.join('\n'), 'utf8');

        return CallToolResultSchema.parse({
          content: [{ type: 'text', text: `✅ ${env_key} injected into ${file_path}\nSecret retrieved and burned.` }],
        });
      }

      if (request.params.name === 'vault_exec') {
        const { entry_id, purpose, command, working_dir, inject_as, remote_host } = request.params.arguments as {
          entry_id?: string;
          purpose: string;
          command: string;
          working_dir?: string;
          inject_as?: { credential_type?: string; env_key?: string; pre_command?: string; post_command?: string; mechanism?: 'env' | 'stdin' | 'askpass'; askpass_var?: string };
          remote_host?: RemoteHost;
        };

        // Safety check BEFORE fetching entry or decrypting
        for (const pat of SHELL_ESCAPE_PATTERNS) {
          if (pat.test(command)) {
            return CallToolResultSchema.parse({
              content: [{ type: 'text', text: `❌ vault_exec rejected: command contains a disallowed shell escape pattern. Remove $(), backticks, bash -c, sh -c, or eval.` }],
            });
          }
        }

        // entry_id is optional: omit it to run a remote command using only a vaulted
        // SSH key (no secret injected). Require at least a secret to inject OR an SSH key.
        const hasSshKey = !!(remote_host && (remote_host.ssh_key_entry_id || remote_host.ssh_key));
        if (!entry_id && !hasSshKey) {
          return CallToolResultSchema.parse({
            content: [{ type: 'text', text: `❌ Provide entry_id (a secret to inject) and/or a remote_host with ssh_key_entry_id (to run remotely with a vaulted SSH key).` }],
          });
        }

        let plaintext = '';
        let tier = '-';
        let entryName: string | undefined;
        let cfg: { credential_type?: string; env_key?: string; pre_command?: string; post_command?: string; mechanism?: 'env' | 'stdin' | 'askpass'; askpass_var?: string } | undefined = inject_as;

        if (entry_id) {
          // Fetch entry to get tier and exec_config
          const secretData = await api.getSecret(entry_id, purpose.slice(0, 200));
          tier = secretData.access_tier ?? '1';
          entryName = secretData.name ?? entry_id;

          // Decrypt secret
          const vaultKey = await api.ensureVaultKey();
          const plaintextBytes = decryptSecretContent(
            vaultKey,
            secretData.encrypted_content,
            secretData.content_nonce,
          );
          plaintext = new TextDecoder().decode(plaintextBytes);

          // Verify directive
          const sig = secretData.directive_signature;
          const directive = secretData.directive || DIRECTIVE;
          if (sig && !verifyDirectiveSignature(directive, sig, plaintextBytes)) {
            return CallToolResultSchema.parse({
              content: [{ type: 'text', text: `⚠️ Directive signature invalid for '${secretData.name ?? entry_id}'. Aborting.` }],
            });
          }

          // Resolve injection config: prefer inject_as, fall back to the entry's exec_config.
          // Required for LOCAL exec (the point is to inject a secret); OPTIONAL for REMOTE
          // exec, where entry_id may be supplied only to use it as the SSH key without
          // injecting it as an env var.
          cfg = inject_as ?? secretData.exec_config;
          if (!cfg && !remote_host) {
            return CallToolResultSchema.parse({
              content: [{ type: 'text', text: `❌ No injection config. Set exec_config on the vault entry in the dashboard, or provide inject_as in the call.` }],
            });
          }
        }

        const envKey = cfg?.env_key ?? '';

        // Resolve the delivery mechanism from the recipe (credential_type), an
        // advanced override, or the legacy env_key (generic). Callers pick intent,
        // not a channel.
        let mechanism: 'env' | 'stdin' | 'askpass' = 'env';
        let askpassVar: string | undefined;
        let wrap: 'setsid' | undefined;
        let appendNewline: boolean | undefined;
        let deliveryNote = '';

        if (cfg?.credential_type) {
          const recipe = getRecipe(cfg.credential_type);
          if (!recipe) {
            return CallToolResultSchema.parse({
              content: [{ type: 'text', text: `❌ Unknown credential_type '${cfg.credential_type}'. Known types: ${recipeIds().join(', ')}.` }],
            });
          }
          mechanism = recipe.mechanism;
          askpassVar = recipe.askpassVar;
          wrap = recipe.wrap;
          appendNewline = recipe.appendNewline;
          deliveryNote = recipe.delivery;
        } else if (cfg?.mechanism) {
          // Advanced escape hatch: force a channel directly.
          mechanism = cfg.mechanism;
          askpassVar = cfg.askpass_var;
        }

        // Validate the mechanism has what it needs (SSH-only no-secret remote runs skip this).
        if (mechanism === 'env' && !envKey && !remote_host && (entry_id || cfg)) {
          return CallToolResultSchema.parse({
            content: [{ type: 'text', text: `❌ No delivery config. Set a credential_type (${recipeIds().join(', ')}) on the entry, or pass env_key for a generic secret.` }],
          });
        }
        if (mechanism === 'askpass' && !askpassVar) {
          return CallToolResultSchema.parse({
            content: [{ type: 'text', text: `❌ askpass delivery needs an askpass_var — use a credential_type (git, ssh-passphrase) instead of a bare mechanism.` }],
          });
        }

        // Build full command: pre_command && main_command; post_command
        let fullCommand = command;
        if (cfg?.pre_command) {
          fullCommand = `${cfg.pre_command} && ${command}`;
        }
        if (cfg?.post_command) {
          fullCommand = `${fullCommand}; ${cfg.post_command}`;
        }

        let execResult: ReturnType<typeof runWithSecret>;
        let keyFingerprint: string | null = null;
        if (remote_host) {
          if (mechanism !== 'env') {
            return CallToolResultSchema.parse({
              content: [{ type: 'text', text: `❌ credential_type '${cfg?.credential_type ?? mechanism}' is not supported for remote exec yet — remote delivery is env-only. Run it locally, or use a generic secret for the remote host.` }],
            });
          }
          // Resolve ssh_key_entry_id: fetch SSH key from vault, write to a temp file,
          // use for the connection, then delete immediately after.
          let resolvedRemote = { ...remote_host };
          let tempKeyPath: string | null = null;
          try {
            if (remote_host.ssh_key_entry_id) {
              const sshKeyData = await api.getSecret(remote_host.ssh_key_entry_id, `ssh key for vault_exec to ${remote_host.host}`);
              const sshVaultKey = await api.ensureVaultKey();
              const sshKeyBytes = decryptSecretContent(sshVaultKey, sshKeyData.encrypted_content, sshKeyData.content_nonce);
              let sshKeyPlaintext = new TextDecoder().decode(sshKeyBytes);
              // Normalize line endings (web UIs often introduce CRLF)
              sshKeyPlaintext = sshKeyPlaintext.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
              // If the dashboard stripped newlines + PEM headers, reconstruct proper OpenSSH PEM format.
              // This happens because some UIs collapse multi-line secrets into a single line.
              if (!sshKeyPlaintext.startsWith('-----') && /^[A-Za-z0-9+/]+=*$/.test(sshKeyPlaintext)) {
                const chunks = sshKeyPlaintext.match(/.{1,70}/g) ?? [];
                sshKeyPlaintext = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + chunks.join('\n') + '\n-----END OPENSSH PRIVATE KEY-----\n';
              } else {
                if (!sshKeyPlaintext.endsWith('\n')) sshKeyPlaintext += '\n';
              }
              const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'wv-ssh-'));
              tempKeyPath = path.join(tmpDir, 'key');
              writeFileSync(tempKeyPath, sshKeyPlaintext, { mode: 0o600 });
              // Validate key is parseable and capture fingerprint before attempting SSH connection
              const { spawnSync: spawnSyncVal } = await import('node:child_process');
              const keyCheck = spawnSyncVal('ssh-keygen', ['-l', '-f', tempKeyPath], { encoding: 'utf8' });
              const lineCount = sshKeyPlaintext.split('\n').length;
              const hasHeader = sshKeyPlaintext.includes('-----BEGIN');
              if (keyCheck.status !== 0) {
                return CallToolResultSchema.parse({ content: [{ type: 'text', text: `❌ SSH key validation failed (ssh-keygen exit ${keyCheck.status}): ${(keyCheck.stderr || keyCheck.stdout || '').trim()}\nKey diagnostic: lines=${lineCount}, hasHeader=${hasHeader}` }] });
              }
              keyFingerprint = (keyCheck.stdout || '').trim();
              resolvedRemote = { ...remote_host, ssh_key: tempKeyPath, ssh_key_entry_id: undefined };
            }
            // pre_command/post_command are local hooks — not forwarded to remote execution.
            execResult = runWithSecretRemote(plaintext, fullCommand, envKey, resolvedRemote);
          } finally {
            if (tempKeyPath) {
              try { unlinkSync(tempKeyPath); } catch { /* ignore */ }
              try { rmdirSync(path.dirname(tempKeyPath)); } catch { /* ignore */ }
            }
          }
        } else {
          const prevDir = process.cwd();
          if (working_dir) { try { process.chdir(working_dir); } catch { /* ignore */ } }
          if (mechanism === 'stdin') {
            execResult = runWithSecretStdin(plaintext, fullCommand, { appendNewline });
          } else if (mechanism === 'askpass') {
            execResult = runWithSecretAskpass(plaintext, fullCommand, { askpassVar: askpassVar as string, wrap });
          } else {
            execResult = runWithSecret(plaintext, fullCommand, envKey);
          }
          if (working_dir) { try { process.chdir(prevDir); } catch { /* ignore */ } }
        }
        const { exitCode, stdout, stderr } = execResult;

        const resultLines = [
          `✅ vault_exec complete.`,
          ``,
          `  Entry:   ${entryName ?? '(none — SSH-only, no secret injected)'}`,
          `  Tier:    ${tier}`,
          `  Command: ${command}`,
          ...(deliveryNote ? [`  Delivery: ${deliveryNote}`] : []),
          ...(remote_host ? [`  Remote:  ${remote_host.user}@${remote_host.host}${remote_host.ssh_key_entry_id ? ' (vaulted key)' : ''}`] : []),
          ...(keyFingerprint ? [`  Key:     ${keyFingerprint}`] : []),
          `  Exit:    ${exitCode}`,
          `  stdout:  ${(stdout || '(empty)').trim()}`,
        ];
        if (stderr) resultLines.push(`  stderr:  ${stderr.trim()}`);
        resultLines.push(`\nSecret injected and buffer zeroed. Not returned to agent.`);

        return CallToolResultSchema.parse({ content: [{ type: 'text', text: resultLines.join('\n') }] });
      }

      if (request.params.name === 'vault_rsync') {
        const { ssh_key_entry_id, purpose, local_path, remote_user, remote_host, remote_path, extra_args } = request.params.arguments as {
          ssh_key_entry_id: string;
          purpose: string;
          local_path: string;
          remote_user: string;
          remote_host: string;
          remote_path: string;
          extra_args?: string[];
        };

        const sshKeyData = await api.getSecret(ssh_key_entry_id, purpose.slice(0, 200));
        const vaultKey = await api.ensureVaultKey();
        const sshKeyBytes = decryptSecretContent(vaultKey, sshKeyData.encrypted_content, sshKeyData.content_nonce);
        let sshKeyPlaintext = new TextDecoder().decode(sshKeyBytes);
        sshKeyPlaintext = sshKeyPlaintext.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
        if (!sshKeyPlaintext.startsWith('-----') && /^[A-Za-z0-9+/]+=*$/.test(sshKeyPlaintext)) {
          const chunks = sshKeyPlaintext.match(/.{1,70}/g) ?? [];
          sshKeyPlaintext = '-----BEGIN OPENSSH PRIVATE KEY-----\n' + chunks.join('\n') + '\n-----END OPENSSH PRIVATE KEY-----\n';
        } else {
          if (!sshKeyPlaintext.endsWith('\n')) sshKeyPlaintext += '\n';
        }

        const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'wv-ssh-'));
        const tempKeyPath = path.join(tmpDir, 'key');
        let rsyncResult: ReturnType<typeof runRsync>;
        try {
          writeFileSync(tempKeyPath, sshKeyPlaintext, { mode: 0o600 });
          const { spawnSync: spawnSyncVal } = await import('node:child_process');
          const keyCheck = spawnSyncVal('ssh-keygen', ['-l', '-f', tempKeyPath], { encoding: 'utf8' });
          if (keyCheck.status !== 0) {
            return CallToolResultSchema.parse({ content: [{ type: 'text', text: `❌ SSH key validation failed: ${(keyCheck.stderr || keyCheck.stdout || '').trim()}` }] });
          }
          rsyncResult = runRsync(tempKeyPath, local_path, remote_user, remote_host, remote_path, extra_args ?? []);
        } finally {
          try { unlinkSync(tempKeyPath); } catch {}
          try { rmdirSync(path.dirname(tempKeyPath)); } catch {}
        }

        const lines = [
          `${rsyncResult.exitCode === 0 ? '✅' : '❌'} vault_rsync ${rsyncResult.exitCode === 0 ? 'complete' : 'failed'}.`,
          ``,
          `  From: ${local_path}`,
          `  To:   ${remote_user}@${remote_host}:${remote_path}`,
          `  Exit: ${rsyncResult.exitCode}`,
        ];
        if (rsyncResult.stdout) lines.push(`  Output:\n${rsyncResult.stdout.trim()}`);
        if (rsyncResult.stderr) lines.push(`  Stderr:\n${rsyncResult.stderr.trim()}`);

        return CallToolResultSchema.parse({ content: [{ type: 'text', text: lines.join('\n') }] });
      }

      if (request.params.name === 'vault_entry_forget') {
        const { entry_id } = request.params.arguments as { entry_id: string };
        return CallToolResultSchema.parse({
          content: [{ type: 'text', text: `✔️ Reference [${entry_id}] discarded from local context. Vault entry unchanged.` }],
        });
      }

      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `Unknown tool: ${request.params.name}` }] });

    } catch (err: unknown) {
      const status = (err as any)?.status;
      if (status === 401) {
        return CallToolResultSchema.parse({ content: [{ type: 'text', text: '❌ Unauthorized — agent credentials invalid or revoked.' }] });
      }
      if (status === 404) {
        return CallToolResultSchema.parse({ content: [{ type: 'text', text: '❌ Vault entry not found or not accessible.' }] });
      }
      const msg = err instanceof Error ? err.message : String(err);
      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `❌ Error: ${msg}` }] });
    }
  });

  return server;
}
