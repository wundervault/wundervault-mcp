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
  startReclaim,
  describeHolder,
  heldNoticeText,
  agentName,
  type Holder,
} from './lock.js';

// ── CLI ────────────────────────────────────────────────────────────────────────

const { values } = parseArgs({
  options: {
    url: { type: 'string', short: 'u' },
    help: { type: 'boolean' },
    destinations: { type: 'boolean' },
  },
  allowPositionals: false,
});

// ── Destination log viewer ────────────────────────────────────────────────────
//
// Handled before anything else touches the daemon: reading your own log should work when
// the daemon is down, when the credential is held by another agent, and when you are
// looking at this precisely because something is wrong.
if (values.destinations) {
  const { writeViewer, collectShape } = await import('./log-viewer.js');
  const { defaultStorePath } = await import('./network-store.js');
  const store = defaultStorePath();
  try {
    const { shape, source } = await collectShape(store);
    const out = writeViewer(store, undefined, shape);
    const calls = shape.seen.reduce((n, s) => n + s.count, 0);
    console.log(`
Destination log — ${shape.seen.length} destination(s), ${calls} call(s)
  store:  ${store}${source === 'daemon' ? ' (read by the daemon on your behalf)' : ''}
  viewer: ${out}

Open that file in your browser. It contains the data already, loads nothing, and is
blocked by its own content-security policy from making any network request. Nothing was
sent anywhere to produce it.
`);
    process.exit(0);
  } catch (e) {
    console.error((e as Error).message);
    process.exit(1);
  }
}

if (values.help) {
  console.log(`
Wundervault MCP Server
=====================
Secure vault tool provider for AI agents via MCP protocol.

Usage: wundervault-mcp [options]

Options:
  --url <url>      Ignored: the vault's address comes from the broker
  --destinations   Write a local HTML view of where this machine's agents have sent
                   secrets, and print its path. Never leaves this machine.
  --help           Show this help

Secrets stay with the broker (wundervault-agent); no tool returns one.
Set WUNDERVAULT_AGENT_NAME in your MCP config to identify this agent.
Enrol an agent with the broker: wundervault-agent --enrol (claim code from your vault).
Setup: https://wundervault.com/quickstart
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
  const detail = heldNoticeText(agent, holder);

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
      ? `Vault tools are still unavailable in this session. ${heldNoticeText(agent, current)}`
      : `The old copy has closed, so "${agent}" is free now. This session can't pick that up by ` +
        `itself: reconnect Wundervault (in Claude Code: /mcp) to get the vault tools.`;
    return { content: [{ type: 'text' as const, text }] };
  });

  process.stdin.on('end', () => process.exit(0));
  await server.connect(new StdioServerTransport());
}

// ── Run ──────────────────────────────────────────────────────────────────────

// Demo mode (WUNDERVAULT_MOCK) answers every call with a canned reply and never reaches the
// broker, so it holds no credential and has nothing for copies to contend over. Directory
// scanners start several copies at once with no agent name: before 2.0.2 every copy after the
// first served only vault_status, and Glama listed Wundervault with one tool (2026-10-27).
const DEMO = process.env.WUNDERVAULT_MOCK === '1' || process.env.WUNDERVAULT_MOCK === 'true';
const claim = DEMO ? { ok: true as const, role: 'demo' as const }
  : await acquireCredential(VERSION, { share: true });
if (!claim.ok) {
  if (claim.reason) console.error(`[wundervault-mcp] ${claim.reason}`);
  // Bound nothing, so this process holds nothing: it installs no release
  // handlers and can never remove the real holder's lock file.
  await serveHeldNotice(claim.holder!);
} else {
  if (claim.role === 'shared') {
    // Another 2.0 copy of this agent holds the address (an MCP host that starts one process
    // per session, or two hosts). Serve beside it, and take the claim over if it exits, so
    // older copies keep standing down (SPEC-2.0-shared-agent S5, S6).
    console.error(`[wundervault-mcp] sharing "${agentName()}" with the copy already running ` +
      `(${describeHolder(claim.holder!)})`);
    startReclaim(VERSION, () => {
      console.error(`[wundervault-mcp] the other copy exited; this one now holds "${agentName()}"`);
    });
  }
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
