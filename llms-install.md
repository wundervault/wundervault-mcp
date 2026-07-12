# Wundervault MCP Server — AI Agent Installation Guide

This guide is written for AI agents (Cline, Claude Code, Cursor, etc.) installing the Wundervault MCP server on behalf of a user.

Wundervault is a zero-knowledge secrets vault: the user's secrets are encrypted client-side, decrypted only by a local process, and **plaintext is never returned into the model context**. The zero-knowledge claim is independently verifiable: https://wundervault.com/verify

## Prerequisites

- Node.js 20 or newer (`node --version`)
- npm

## Step 1 — Install the server

```bash
npm install -g @wundervault/mcp-server
```

This provides the `wundervault-mcp` binary. Verify the install:

```bash
npm ls -g @wundervault/mcp-server
```

## Step 2 — Get credentials (requires the human, once)

The server starts and lists its tools with no configuration, but real vault access needs an agent identity:

1. The user creates a free account at https://wundervault.com and clicks **NEW AGENT** on the dashboard.
2. The dashboard shows a **single setup command** with an embedded one-time setup URL. The user pastes it to you (or runs it themselves).
3. Run that command. It installs/updates this package, configures the agent's credentials locally, and **prints the exact MCP config snippet for your client** — use that snippet in Step 3.

Full flow documentation: https://wundervault.com/quickstart

## Step 3 — Configure the MCP client

For Cline, add the server to `cline_mcp_settings.json` (use the snippet printed in Step 2; the general shape is):

```json
{
  "mcpServers": {
    "wundervault": {
      "command": "wundervault-mcp"
    }
  }
}
```

Credentials can also be supplied explicitly — see "Credential Loading Priority" in README.md (CLI flags, environment variables, or `--credentials <file>`).

## Step 4 — Verify

After the client connects, you should see 6 tools: `vault_entries_list`, `vault_entry_get`, `vault_entry_forget`, `vault_entry_inject_env`, `vault_exec`, `vault_rsync`.

Call `vault_entries_list`. With credentials configured it returns the user's entries; without credentials it returns a clear "Vault unavailable" message (this is expected, not a crash).

## Demo mode (no account needed)

To exercise the tools without any Wundervault account, set `WUNDERVAULT_MOCK=1` in the server's environment. All 6 tools return canned `[DEMO MODE]` responses. Never use demo mode for real secrets.

## Troubleshooting

- **"Vault unavailable: WUNDERVAULT_AGENT_NAME is not set"** — credentials are not configured; re-run the dashboard setup command (Step 2).
- **Server won't start for a second session** — Wundervault allows one MCP server instance per agent identity (lock file at `~/.wundervault/mcp-<Agent>.lock`). Close the older session; the lock releases automatically.
- **Node version errors** — upgrade to Node 20+.

## Security notes for agents

- You will never receive plaintext secrets. Tools inject secrets into subprocesses or files and return only confirmations.
- Do not attempt shell escape patterns (`$()`, backticks, `bash -c`, `sh -c`, `eval`) in `vault_exec` commands — they are rejected before decryption.
- Treat the one-time setup URL as sensitive: use it immediately, never log or store it.
