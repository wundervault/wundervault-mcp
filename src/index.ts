#!/usr/bin/env node

import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';
import { VERSION, semverLt } from './version.js';

// Lock file is keyed by agent name so multiple agents can run simultaneously.
function getLockFile(): string {
  const agentName = process.env.WUNDERVAULT_AGENT_NAME;
  if (agentName) {
    const slug = agentName.replace(/[^a-zA-Z0-9_-]/g, '_');
    return path.join(os.homedir(), '.wundervault', `mcp-${slug}.lock`);
  }
  return path.join(os.homedir(), '.wundervault', 'mcp.lock');
}

const LOCK_FILE = getLockFile();

function acquireLock(): boolean {
  try {
    if (existsSync(LOCK_FILE)) {
      const pidStr = readFileSync(LOCK_FILE, 'utf8').trim();
      const pid = parseInt(pidStr, 10);
      if (!isNaN(pid) && pid !== process.pid) {
        try {
          process.kill(pid, 0);
          console.error(`[wundervault-mcp] Another instance is already running (PID ${pid}). Exiting.`);
          return false;
        } catch {
          // stale lock
        }
      }
    }
    writeFileSync(LOCK_FILE, String(process.pid), 'utf8');
    return true;
  } catch {
    return true;
  }
}

function releaseLock(): void {
  try {
    if (existsSync(LOCK_FILE)) {
      const pidStr = readFileSync(LOCK_FILE, 'utf8').trim();
      if (pidStr === String(process.pid)) {
        unlinkSync(LOCK_FILE);
      }
    }
  } catch {
    // ignore
  }
}

process.on('exit', releaseLock);
process.on('SIGINT', () => { releaseLock(); process.exit(0); });
process.on('SIGTERM', () => { releaseLock(); process.exit(0); });

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

// ── Run ──────────────────────────────────────────────────────────────────────

if (!acquireLock()) {
  process.exit(0);
}

// Exit when the host closes stdin (MCP client disconnected / session ended).
// NOTE: do NOT call process.stdin.resume() here. Resuming puts stdin in
// flowing mode before StdioServerTransport is attached; any bytes the client
// sends in that window (notably the `initialize` handshake) are read and
// discarded, so the transport never sees them and tools never register.
// StdioServerTransport manages the stream itself once connected.
process.stdin.on('end', () => { releaseLock(); process.exit(0); });

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
