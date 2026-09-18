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
2. The dashboard gives the user what their machine needs. **Which of two things it is matters to you:**
   - a **claim code**, where the machine runs a paired secret broker. It opens nothing on
     its own. The broker fetches and decrypts the credentials inside its own account, and
     they never enter your process.
   - a **one-time setup link**, otherwise. This one *is* a credential: it decrypts to the
     agent's keys, which unwrap the vault key, which opens every secret in the vault.
3. **Do not ask the user to put a setup link in a command, and do not accept one if they
   offer.** A command line is readable by every other process on the machine, so passing
   it that way publishes the one credential this whole design assumes you cannot obtain.
   The installer refuses a link given as an argument for that reason and reads it from a
   prompt instead. The user runs the command; the user pastes the link at the prompt. You
   do not need to see it, and you should say so rather than accepting it.
4. The command installs/updates this package, registers the credentials with the local
   broker, and **prints the exact MCP config snippet for your client** — use that snippet
   in Step 3.

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
- Treat a one-time setup URL as a live credential, not as a token to be handled carefully:
  it decrypts to the agent's keys and through them to every secret in the vault. Never
  accept one in a command, never log it, never store it, never repeat it back. Where the
  machine has a paired broker you will be given a claim code instead, which opens nothing.
- On Linux and macOS the credentials are held by a broker running as its own account, in a
  directory your account cannot open. Its socket serves **operations, not credentials** —
  you can ask it to use a secret; you cannot ask it for one. On Windows it runs as the
  same account you do, and says so at every start.
