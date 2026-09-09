#!/usr/bin/env node

import { parseArgs } from 'node:util';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createServer } from './server.js';
import { VERSION, semverLt } from './version.js';
import {
  acquireCredential,
  credentialIsFree,
  whoHolds,
  releaseCredential,
  describeHolder,
  agentName,
  type Holder,
} from './lock.js';

// ── CLI ────────────────────────────────────────────────────────────────────────

const { values } = parseArgs({
  options: {
    url: { type: 'string', short: 'u' },
    help: { type: 'boolean' },
  },
  allowPositionals: false,
});

if (values.help) {
  console.log(`
Wundervault MCP Server
=====================
Secure vault tool provider for AI agents via MCP protocol.

Usage: wundervault-mcp [options]

Options:
  --url <url>   API base URL override (default: from daemon)
  --help        Show this help

Credentials are loaded from the wundervault-agent daemon.
Set WUNDERVAULT_AGENT_NAME in your MCP config to identify this agent.
Run onboard.py to register an agent with the daemon.
`);
  process.exit(0);
}

// ── Held-credential mode ──────────────────────────────────────────────────────

/**
 * The vault allows one connected agent per credential at a time. When another
 * instance already holds this agent name we must not serve vault tools — but we
 * must not exit either.
 *
 * Exiting mid-handshake is what the previous version did, and it is invisible:
 * every MCP client can only report the death of the process as "Connection
 * closed", which is indistinguishable from a crash, a bad path, or a broken
 * install. Diagnosing one such case cost an hour. So instead we COMPLETE the
 * handshake and connect honestly, advertising a single diagnostic tool and no
 * vault tools. The refusal is unchanged; only its legibility is.
 */
async function serveHeldNotice(holder: Holder): Promise<void> {
  const agent = agentName() || '(unnamed agent)';
  const detail =
    `The wundervault credential for "${agent}" is already checked out by another ` +
    `MCP instance (${describeHolder(holder)}).\n\n` +
    `The vault permits one connected agent per credential at a time, so this ` +
    `session has no vault tools. This is the vault enforcing that rule — not a ` +
    `crash, and not a broken install.\n\n` +
    `To take the credential: close the session that owns the process above, then ` +
    `reconnect this MCP server (/mcp in Claude Code).`;

  console.error(`[wundervault-mcp] ${detail.replace(/\n+/g, ' ')}`);

  const server = new Server(
    { name: 'wundervault-mcp', version: VERSION },
    {
      capabilities: { tools: {} },
      instructions:
        `Vault tools are UNAVAILABLE in this session: ${detail} ` +
        `Do not report this as a server error; call vault_status for the current state.`,
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'vault_status',
        description:
          'Report why vault tools are unavailable in this session and whether the ' +
          'credential has since been released. Returns no secrets.',
        inputSchema: { type: 'object', properties: {} },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (req.params.name !== 'vault_status') {
      return {
        isError: true,
        content: [{ type: 'text' as const, text: `Vault tools are unavailable. ${detail}` }],
      };
    }
    // Re-check with the kernel, and ask whoever holds it NOW who they are.
    // Replaying the startup snapshot would name the wrong process as soon as
    // the credential changed hands while this session sat blocked.
    const free = await credentialIsFree();
    const current = free ? null : await whoHolds();
    const text = current
      ? `Vault tools are unavailable in this session. The credential for ` +
        `"${agent}" is currently held by another MCP instance ` +
        `(${describeHolder(current)}). The vault permits one connected agent per ` +
        `credential at a time; this is that rule, not a crash. To take it, close ` +
        `the session that owns that process, then reconnect this MCP server ` +
        `(/mcp in Claude Code).`
      : `The credential for "${agent}" is now FREE. This process cannot upgrade ` +
        `itself mid-session — reconnect this MCP server (/mcp in Claude Code) to ` +
        `get the vault tools.`;
    return { content: [{ type: 'text' as const, text }] };
  });

  process.stdin.on('end', () => process.exit(0));
  await server.connect(new StdioServerTransport());
}

// ── Run ──────────────────────────────────────────────────────────────────────

const claim = await acquireCredential(VERSION);
if (!claim.ok) {
  if (claim.reason) console.error(`[wundervault-mcp] ${claim.reason}`);
  // Bound nothing, so this process holds nothing: it installs no release
  // handlers and can never remove the real holder's lock file.
  await serveHeldNotice(claim.holder!);
} else {
  await serveVault();
}

async function serveVault(): Promise<void> {

process.on('exit', releaseCredential);
process.on('SIGINT', () => { releaseCredential(); process.exit(0); });
process.on('SIGTERM', () => { releaseCredential(); process.exit(0); });

// Exit when the host closes stdin (MCP client disconnected / session ended).
// NOTE: do NOT call process.stdin.resume() here. Resuming puts stdin in
// flowing mode before StdioServerTransport is attached; any bytes the client
// sends in that window (notably the `initialize` handshake) are read and
// discarded, so the transport never sees them and tools never register.
// StdioServerTransport manages the stream itself once connected.
process.stdin.on('end', () => { releaseCredential(); process.exit(0); });

// Attach the transport FIRST so the client handshake is never lost. The
// CIP-024 version self-check runs in the background and only hard-stops on a
// definitive "too old" verdict (server-side 426 is the backstop otherwise).
const server = createServer({ url: values.url });
const transport = new StdioServerTransport();
server.connect(transport).catch((err: Error) => {
  console.error('Server error:', err.message);
  process.exit(1);
});

(async () => {
  // CIP-024 §3.4: best-effort version self-check. Never block on transient
  // network/parse errors; hard-stop ONLY on a definitive "too old" verdict.
  try {
    const base = values.url || 'https://wundervault.com';
    const r = await fetch(`${base}/api/v1/mcp/requirements`, { signal: AbortSignal.timeout(5000) });
    if (r.ok) {
      const req = await r.json() as { min_mcp_version?: string; upgrade_cmd?: string };
      if (req.min_mcp_version && semverLt(VERSION, req.min_mcp_version)) {
        process.stderr.write(
          `\n[wundervault-mcp] FATAL: this MCP is v${VERSION} but the server ` +
          `requires >= v${req.min_mcp_version}. Vault tools are unavailable until you update:\n` +
          `  ${req.upgrade_cmd || 'npm install -g @wundervault/mcp-server@latest'}\n\n`);
        process.exit(1);
      }
    }
  } catch { /* transient — proceed; server-side 426 is the backstop */ }
})().catch((err: Error) => {
  console.error('Self-check error:', err.message);
  /* non-fatal: transport is already attached */
});

}
