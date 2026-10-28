# Wundervault MCP Server — AI Agent Installation Guide

This guide is written for AI agents (Claude Code, Codex, Cline, Cursor, OpenClaw, etc.)
installing the Wundervault MCP server on behalf of a user.

Wundervault lets you use the user's API keys, SSH keys, wallets and signing keys **without
ever holding them**. A broker on the user's computer, running under its own operating-system
account, keeps the secrets and makes each call for you; you get the result with the secret removed.
No tool returns a secret's value. The encryption claim is independently verifiable:
https://wundervault.com/verify

**Some of this needs the human.** Installing the broker is an administrator command, and
pairing and adding an agent need the user's approval in their vault. That is by design: you
cannot enrol yourself. Tell the user what to run; don't try to work around it.

## Prerequisites

- Node.js 22.23.4, 24.22.1 or 26.12.1 or newer (`node --version`). These carry the October 21, 2026
  security fix; the broker refuses to start on an older Node.
- npm
- The user, with administrator rights on this computer, for steps 2 and 3

## Step 1 — Install the package

```bash
npm install -g @wundervault/mcp-server@2
```

This provides two commands: `wundervault-mcp` (the MCP server you talk to) and
`wundervault-agent` (the broker). Check the install:

```bash
npm ls -g @wundervault/mcp-server
```

## Step 2 — The user installs the broker (administrator, once per computer)

Linux:

```bash
sudo sh "$(npm root -g)/@wundervault/mcp-server/packaging/install-daemon.sh"
```

Windows and macOS have their own installers:
https://wundervault.com/install. The installer downloads nothing and is short enough to read
first; reading it before the user runs it is a good idea.

## Step 3 — The user pairs the broker with their account

The user runs the pairing command the installer printed last, which names node and the broker by
their full paths, for example:

```bash
sudo /usr/bin/node /usr/bin/wundervault-agent --pair
```

Give full paths, never bare names, with `sudo`: a name may be looked up on the user's own PATH, and
a folder there that the user (or an agent) can write could hold another program. That includes node,
because the broker's launcher starts with `#!/usr/bin/env node`.

The user checks that the fingerprint it shows matches the one in their vault at
https://wundervault.com, then confirms there. They need a free account first.

## Step 4 — The user adds you as an agent

In their vault, the user adds an agent and chooses this computer. They get a **claim code**.
Then this command, entered by the user at its prompt:

```bash
wundervault-agent --enrol
```

The claim code opens nothing on its own: the broker fetches and decrypts your credentials
inside its own account, and they never enter your process.

Then add the server to your MCP client's configuration (the agent name is the one the user
chose in step 4):

```json
{
  "mcpServers": {
    "wundervault": {
      "command": "wundervault-mcp",
      "env": { "WUNDERVAULT_AGENT_NAME": "<agent name>" }
    }
  }
}
```

The configuration holds no secrets. Shapes for other clients: README-AGENTS.md.

## Step 5 — Verify

After your client connects you should see 5 tools: `vault_entries_list`, `vault_call`,
`vault_ssh_exec`, `vault_pay`, `vault_sign`.

Call `vault_entries_list`. With the broker running and you enrolled, it returns the secrets the
user has given you. Otherwise it returns a clear "Vault unavailable" message that says what
is missing (this is expected, not a crash).

## Demo mode (no account needed)

To try the tools without an account, set `WUNDERVAULT_MOCK=1` in the server's environment.
All 5 tools return canned `[DEMO MODE]` responses. Never use demo mode for real secrets.

## Troubleshooting

- **"Vault unavailable: WUNDERVAULT_AGENT_NAME is not set"** — add the `env` block in step 4.
- **"wundervault-agent is not running for agent '…'"** — the broker isn't installed on this
  computer (step 2), or this agent isn't enrolled (step 4).
- **"FATAL: this MCP is v… but the server requires >= v…"** — update:
  `npm install -g @wundervault/mcp-server@2`.
- **Server won't start for a second session** — one MCP server runs per agent name on a
  computer. Close the older session.
- **Coming from version 1** (`vault_exec`, `vault_entry_get`, `vault_entry_inject_env`,
  `vault_rsync`)? Those tools are gone. The user moves each agent:
  https://wundervault.com/install#upgrade-to-2

## How to behave with Wundervault

- You will never receive a secret's value. Use `vault_call` for web services, `vault_ssh_exec`
  for servers, `vault_pay` for x402 payments and `vault_sign` for signatures, and let the
  broker do the work.
- State a real `purpose`. It is kept in the broker's log on the user's computer, and the user
  sees it when they are asked to approve.
- If a call is waiting for approval, wait, or call again with the same request to keep
  waiting. Calling a different destination asks the user again.
- Never ask the user to paste a secret, a claim code or a setup link into your chat, and don't
  accept one if they offer. They enter the claim code at the broker's prompt themselves.
- Full tool reference: https://wundervault.com/mcp · Every known limit:
  https://wundervault.com/limitations
