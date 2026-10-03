import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  CallToolResultSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { BrokerClient, brokerClient } from './broker-client.js';
import { runSshWithAgent, type BrokeredOp } from './ssh-agent.js';
import type { AgentRequest } from './http-broker.js';
import type { VaultEntry } from './types.js';
import { VERSION } from './version.js';

export { DIRECTIVE } from './directive.js';

// ── Three tools, and none of them returns a key ──────────────────────────────
//
// 1.0 is brokered only. vault_exec, vault_entry_get, vault_entry_inject_env, vault_rsync
// and vault_entry_forget handed the agent a key's value — in a command's environment, a
// file, or the tool result — and are retired with the hand-over mode on the server. What
// is left: list the entries, make a web call with a key (vault_call), or run ssh/rsync
// with a key the broker signs for (vault_ssh_exec). A removed name is "Unknown tool".

// ── Talking to the broker ─────────────────────────────────────────────────────
//
// There is no credential loading here any more, and that is the point of the phase.
//
// This process runs as the AGENT's uid. It used to open the per-agent socket, receive
// `{api_key, enc_key, vault_url}`, and derive `vault_key` in its own memory — so the uid
// split protected the store on disk and the broker's memory while the socket handed the
// key straight back. Every `entry_mode` check in this file ran here too, in the agent's
// own process, which is why `types.ts` described them as "enforced client-side".
//
// Now the socket serves operations. The checks that matter run in the broker; the ones
// left here are a faster, friendlier error and nothing more. Deleting every one of them
// must not change what an agent can obtain — that is acceptance check 3.5, and there is
// a test for it.

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
    case 'vault_ssh_exec':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ Ran on ${args.destination ?? 'demo-host'} (exit 0). 1 signature, key never left the server.${MOCK_NOTE}` }] });
    case 'vault_call':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ ${args.operation_id ?? 'demo.op'} returned 200. Credential was used, not disclosed.${MOCK_NOTE}` }] });
    default:
      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `Unknown tool: ${name}${MOCK_NOTE}` }], isError: true });
  }
}

// ── Server Factory ─────────────────────────────────────────────────────────────

export function createServer(args: { url?: string } = {}) {
  // `--url` no longer decides where the vault is, and that is deliberate rather than an
  // oversight. The vault URL is part of the credential the broker holds; letting this
  // process override it would let an agent point its own broker-fetched identity at a
  // server the agent chose — which is the same attack the enrolment origin allowlist
  // exists to stop, one layer down. It is ignored loudly rather than silently, because a
  // flag that appears to work and does nothing is worse than one that is refused.
  if (args.url) {
    process.stderr.write(
      `[wundervault] --url is ignored: the vault URL comes from the broker, with the\n`
      + `[wundervault] credential it belongs to. Set WUNDERVAULT_SETUP_ORIGIN on the broker\n`
      + `[wundervault] for a self-hosted install.\n`);
  }

  const server = new Server(
    { name: 'wundervault-mcp', version: VERSION },
    { capabilities: { tools: {} } },
  );

  // ── Tool Definitions ──────────────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'vault_entries_list',
        description: (
          'List the vault entries this agent may use. For each: its ID, name, tier, whether it '
          + 'is a web-service key (use vault_call) or an SSH key (use vault_ssh_exec), and any '
          + 'signed operations it offers. Never a key\'s value — no tool returns one.'
        ),
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'vault_call',
        description: (
          'Perform a named operation using a vaulted credential that is never returned '
          + 'to you.\n\n'
          + 'You supply typed arguments; this server builds the request, attaches the '
          + 'credential, sends it, and returns only the response fields the operation '
          + 'permits. You cannot supply a URL, headers or a raw body — the operation '
          + 'definition fixes the origin and route, and it is signed with a key derived '
          + 'from the secret itself, so a definition altered anywhere in transit is '
          + 'refused.\n\n'
          + 'vault_entries_list shows which operations an entry offers. Or describe the request '
          + 'yourself with `request`; the entry decides how the key is attached (header, query '
          + 'parameter or username and password) — you never choose that, and never see the key.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the credential.' },
            operation_id: { type: 'string', description: 'A signed operation on the entry. Use this OR request, not both.' },
            args: { type: 'object', description: 'Typed arguments for operation_id, checked against its schema.' },
            request: {
              type: 'object',
              description: 'Describe the call yourself: {origin:{scheme,host,port}, method, path, body?, query?}. '
                + 'Tier 1 secrets proceed and are logged. Tier 2 secrets are refused until the owner approves '
                + 'this exact origin, method and path.',
            },
            purpose: { type: 'string', description: 'Why this is needed (audit log).' },
          },
          required: ['entry_id', 'purpose'],
        },
      },
      {
        name: 'vault_ssh_exec',
        description: (
          'Run a command on a remote host, or rsync files to it, using a vaulted SSH key '
          + 'that is never written to disk and never returned to you.\n\n'
          + 'The key stays inside this server and answers signature requests over a private '
          + 'ssh-agent socket that exists only for the duration of this call. You choose the '
          + 'remote command; you do not get the key.\n\n'
          + 'The destination is checked against the ssh_hosts allowlist on the entry, and the '
          + 'ssh command line is constructed here — naming a different host inside remote_argv '
          + 'does not change where it connects. An entry with no ssh_hosts authorises nothing.\n\n'
          + 'Every signature is audited with the key fingerprint and the authorised host.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the SSH private key (ed25519, unencrypted).' },
            destination: { type: 'string', description: 'Remote destination, [user@]host. The host part must be in the entry\'s ssh_hosts.' },
            purpose: { type: 'string', description: 'Why this is needed (audit log).' },
            remote_argv: {
              type: 'array', items: { type: 'string' },
              description: 'Command and arguments to run on the remote host. An array, run without a shell. Omit when using rsync_args.',
            },
            rsync_args: {
              type: 'array', items: { type: 'string' },
              description: 'rsync arguments instead of a remote command. Every [user@]host:path argument is checked against the same allowlist.',
            },
            timeout_seconds: { type: 'number', description: 'Default 120.' },
            working_dir: { type: 'string', description: 'Local working directory for rsync source paths.' },
          },
          required: ['entry_id', 'destination', 'purpose'],
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
    let broker: BrokerClient;
    try {
      broker = brokerClient();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `❌ Vault unavailable: ${msg}` }] });
    }

    try {
      if (request.params.name === 'vault_entries_list') {
        const data = await broker.sendOrThrow('list_entries');
        const entries: VaultEntry[] = (data.entries as VaultEntry[]) ?? [];
        if (!entries.length) {
          return CallToolResultSchema.parse({ content: [{ type: 'text', text: 'Vault is empty — no entries available.' }] });
        }
        const lines = [`Vault entries (${entries.length}):\n`];
        for (const e of entries) {
          const use = e.entry_mode === 'BROKER_SSH_AGENT' ? 'SSH key → vault_ssh_exec'
            : e.entry_mode === 'BROKER_HTTP' ? 'web key → vault_call'
            : 'not usable until the owner sets how it is used';
          const ops = e.operations?.length ? `; operations: ${e.operations.join(', ')}` : '';
          lines.push(`  [${e.id}]  ${e.secret_name}  (tier: ${e.access_tier ?? 'read'}; ${use}${ops})`);
        }
        return CallToolResultSchema.parse({ content: [{ type: 'text', text: lines.join('\n') }] });
      }

      if (request.params.name === 'vault_call') {
        const a = request.params.arguments as Record<string, unknown>;
        const entry_id = String(a?.entry_id ?? '');
        const operation_id = String(a?.operation_id ?? '');
        const purpose = String(a?.purpose ?? '');
        const callArgs = (a?.args ?? {}) as Record<string, unknown>;
        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
        const agentReq = a?.request as AgentRequest | undefined;
        if (!entry_id || !purpose) return fail('vault_call needs entry_id and purpose.');
        if (!operation_id && !agentReq) return fail('vault_call needs either operation_id or request.');
        if (operation_id && agentReq) return fail('Give either operation_id or request, not both.');

        // THE WHOLE OPERATION HAPPENS IN THE BROKER.
        //
        // Everything that used to be here — fetching the entry, unwrapping the vault key,
        // decrypting the credential, verifying the signed operation definition, the tier
        // gate, the tier-2 wait, the destination record, the SSRF guard and the outbound
        // request — ran in this process, as the agent's uid, holding the plaintext.
        // `SPEC-tiered-broker.md` said of tier 1 that "the key never reaches the agent"; it
        // was describing this code, and it was not true of it.
        //
        // What comes back is a status, a body and a tier. No credential crosses the
        // socket in either direction.
        const r = await broker.send('call', {
          entry_id,
          purpose: purpose.slice(0, 200),
          ...(operation_id ? { operation_id } : {}),
          ...(operation_id ? { args: callArgs } : {}),
          ...(agentReq ? { request: agentReq } : {}),
        });
        if (r.error) return fail(String(r.error));

        return CallToolResultSchema.parse({
          content: [{ type: 'text', text:
            `✅ ${r.label} → HTTP ${r.status} (tier ${r.tier}). The credential was used here, not returned to you.\n`
            + `${JSON.stringify(r.body, null, 2)}${r.notice ? `\n\n${r.notice}` : ''}` }],
        });
      }

      if (request.params.name === 'vault_ssh_exec') {
        const entry_id = String((request.params.arguments as Record<string, unknown>)?.entry_id ?? '');
        const destination = String((request.params.arguments as Record<string, unknown>)?.destination ?? '');
        const purpose = String((request.params.arguments as Record<string, unknown>)?.purpose ?? '');
        const remoteArgvRaw = (request.params.arguments as Record<string, unknown>)?.remote_argv;
        const rsyncArgsRaw = (request.params.arguments as Record<string, unknown>)?.rsync_args;
        const timeoutSeconds = Number((request.params.arguments as Record<string, unknown>)?.timeout_seconds ?? 120);
        const workingDir = (request.params.arguments as Record<string, unknown>)?.working_dir as string | undefined;

        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
        if (!entry_id || !destination || !purpose) {
          return fail('vault_ssh_exec needs entry_id, destination and purpose.');
        }

        const remoteArgv = Array.isArray(remoteArgvRaw) ? remoteArgvRaw.map(String) : undefined;
        const rsyncArgs = Array.isArray(rsyncArgsRaw) ? rsyncArgsRaw.map(String) : undefined;
        if ((remoteArgv && rsyncArgs) || (!remoteArgv && !rsyncArgs)) {
          return fail('Give exactly one of remote_argv or rsync_args.');
        }

        const op: BrokeredOp = remoteArgv
          ? { kind: 'ssh', destination, remoteArgv }
          : { kind: 'rsync', destination, rsyncArgs: rsyncArgs as string[] };

        // THE KEY STAYS WITH THE BROKER AND THE COMMAND STAYS HERE.
        //
        // This used to fetch the entry, decrypt the private key into this process, and
        // run a signing agent on its own socket — so "the key never left this server" was
        // true of the network and false of the machine: the agent held the key.
        //
        // Now the broker loads the key, checks the destination against the entry's
        // ssh_hosts allowlist (which used to be checked HERE, by the caller, about
        // itself), and serves the ssh-agent protocol on a socket of its own. `ssh` runs
        // in this process, as this uid, and authenticates by asking the broker to sign.
        //
        // The command deliberately does NOT move to the broker. A broker that runs a
        // caller-supplied command hands that caller code execution as the uid that owns
        // /var/lib/wundervault, which is every credential on this machine.
        const opened = await broker.send('ssh_agent_open', {
          entry_id,
          purpose: purpose.slice(0, 200),
          op_spec: op,
          ttl_seconds: Math.max(1, Math.min(timeoutSeconds, 900)) + 30,
        });
        if (opened.error) return fail(String(opened.error));

        const sessionId = String(opened.session_id ?? '');
        let r: { exitCode: number; stdout: string; stderr: string };
        let signs = 0;
        try {
          r = await runSshWithAgent({
            op,
            socketPath: String(opened.socket_path ?? ''),
            publicKeyPath: String(opened.public_key_path ?? ''),
            cwd: workingDir,
            timeoutMs: Math.max(1, Math.min(timeoutSeconds, 900)) * 1000,
          });
        } finally {
          // Always closed, including on a throw and on a timeout. The broker also expires
          // the session on its own timer, because a client that dies between opening and
          // closing must not leave an ambient signing socket behind — a close that only
          // happens when the caller remembers is not a close.
          const closed = await broker.send('ssh_agent_close', { session_id: sessionId })
            .catch(() => ({ signs: 0 }));
          signs = Number((closed as { signs?: unknown }).signs ?? 0);
        }

        const head = r.exitCode === 0
          ? `✅ ${op.kind} on ${destination} completed (exit 0).`
          : `❌ ${op.kind} on ${destination} failed (exit ${r.exitCode}).`;
        return CallToolResultSchema.parse({
          content: [{ type: 'text', text:
            `${head}\n${signs} signature(s); the key never left the broker.\n`
            + `--- stdout ---\n${r.stdout || '(empty)'}\n--- stderr ---\n${r.stderr || '(empty)'}` }],
          isError: r.exitCode !== 0,
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
