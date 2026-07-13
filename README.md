# @wundervault/mcp-server

[![npm version](https://img.shields.io/npm/v/%40wundervault%2Fmcp-server)](https://www.npmjs.com/package/@wundervault/mcp-server)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.wundervault%2Fwundervault--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=wundervault)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green)](LICENSE)

**A zero-knowledge secrets vault for AI agents.** Every API key you paste into an agent chat or a `.env` file ends up in context windows, transcripts, and provider logs. Wundervault's answer: the agent never receives the secret at all. It asks for *work* — "run this deploy with the key injected" — and a local daemon decrypts the secret, injects it into the subprocess environment, zeroes the buffer, and scrubs the output before the agent sees any of it.

This repo is the MCP server that exposes that workflow to any [Model Context Protocol](https://modelcontextprotocol.io) client — Claude Code, Cursor, Cline, and others.

**Don't trust the claim — test it:** the zero-knowledge property is independently verifiable at your own network boundary in about 5 minutes (browser DevTools or a mitmproxy canary test). Guide + our own test transcript: [wundervault.com/verify](https://wundervault.com/verify).

## How it works

```
┌──────────────┐  MCP (stdio)  ┌───────────────────┐  ciphertext only  ┌───────────────────┐
│   AI agent   │──────────────▶│  wundervault-mcp  │◀─────────────────▶│  wundervault.com  │
│ (Claude, …)  │◀──────────────│  + local daemon   │                   │ stores encrypted  │
└──────────────┘ "burned" ack  │  decrypts HERE    │                   │ blobs, no keys    │
                               └─────────┬─────────┘                   └───────────────────┘
                                         │  secret → subprocess env
                                         │  (buffer zeroed after spawn)
                                         ▼
                               ┌───────────────────┐
                               │   your command    │ stdout/stderr scrubbed
                               │ (deploy, API, …)  │ before the agent sees it
                               └───────────────────┘
```

Secrets are encrypted client-side (AES-256-GCM via Web Crypto) before upload. The hosted service only ever stores ciphertext — it cannot derive the key, the passphrase, or the plaintext.

## Install

```bash
npm install -g @wundervault/mcp-server
```

## Quick Start

```json
{
  "mcpServers": {
    "wundervault": {
      "command": "wundervault-mcp",
      "env": {
        "WUNDERVault_AGENT_VAULT_URL": "https://wundervault.com",
        "WUNDERVault_AGENT_VAULT_API_KEY": "wv_agent_<AGENT_ID>|<KEY_SUFFIX>",
        "WUNDERVault_AGENT_KEY": "<BASE64_ENCRYPTION_KEY>"
      }
    }
  }
}
```

Or using a credentials file:

```bash
wundervault-mcp --credentials ~/.wundervault/creds.json
```

New account? [wundervault.com](https://wundervault.com) has a 90-second agent onboarding flow that generates this config for you.

## Security Model

- **Zero-knowledge:** The encryption key lives only in the MCP server process. The Wundervault server never sees it.
- **Burn-after-reading:** Plaintext secrets are never returned to the calling agent. After decryption, the agent receives only `"Secret retrieved and burned."`.
- **Exec scrubbing:** Command stdout/stderr are scrubbed of the plaintext before being returned; shell-escape patterns (`$()`, backticks, `sh -c`, `eval`) and file redirects of secrets are rejected *before* decryption.
- **Directive integrity:** Server-side directive signatures (PBKDF2-HMAC-SHA256, 600k iterations) are verified before any secret is released.
- **Timing-safe:** HMAC comparison uses `crypto.timingSafeEqual`.
- **Tiered access:** Per-entry access tiers are enforced server-side; high-tier secrets require human approval before an agent can use them.

### Honest limitations

- The platform is **open-core**: this MCP server and the [browser crypto](https://github.com/wundervault/wundervault-crypto) are AGPL-3.0 so you can audit everything that touches your secrets, but the hosted service itself is not open source.
- A local daemon must run next to the agent; fully air-gapped setups don't fit.
- By design the agent can never read a secret's value — if your workflow needs the model to *reason about* the secret itself, this is the wrong shape.

## Tools

### `vault_entries_list`

List all vault entries available to this agent. Returns entry IDs and secret names — no values.

```
Input: {}
Output: "Vault entries (N):\n  [entry_id]  secret_name  (tier: read)"
```

### `vault_entry_get`

Retrieve and decrypt a vault secret. Optionally execute a command with it.

```
Input:
  entry_id: string          # from vault_entries_list
  purpose: string           # audit log reason
  exec?: string             # optional shell command

Output: "Secret retrieved and burned." (plaintext NEVER returned)
```

**Secure exec pattern** (sudo example):
```bash
sudo -S systemctl restart nginx <<< "$WUNDERVault_SECRET"
```
Do NOT use `echo $WUNDERVault_SECRET | sudo -S` — that exposes the secret in process logs.

### `vault_exec`

Execute a shell command with a vault secret injected as an env var — locally or on a remote host over SSH. The secret is injected into the subprocess and the buffer is zeroed immediately after spawn; escape patterns are rejected before decryption.

```
Input:
  purpose: string           # audit log reason
  command: string           # full shell command (no escape patterns)
  entry_id?: string         # secret to inject (omit for SSH-key-only remote exec)
  working_dir?: string
  inject_as?: { env_key, pre_command?, post_command? }   # override entry's exec_config
  remote_host?: { host, user, ssh_key_entry_id? | ssh_key? }
```

With `remote_host.ssh_key_entry_id`, the SSH key is fetched from the vault and used without ever being written to disk.

### `vault_entry_inject_env`

Write a vault secret directly into a config file (`~/.npmrc`, `~/.netrc`, `~/.docker/config.json`, or a project `.env`) without the plaintext passing through the agent.

```
Input:
  entry_id: string
  purpose: string
  file_path: string         # allowed config file paths only
  env_key: string           # variable name to set
```

### `vault_rsync`

Sync a local directory to a remote host using rsync over SSH, with the SSH key fetched from the vault (temp keyfile deleted immediately after transfer).

### `vault_entry_forget`

Discard a local reference. No-op on the server.

```
Input: { entry_id: string }
Output: "Reference [id] discarded from local context."
```

## Credential Loading Priority

1. CLI flags (`--api-key`, `--enc-key`, `--url`)
2. Environment variables (`WUNDERVault_AGENT_VAULT_API_KEY`, `WUNDERVault_AGENT_KEY`, `WUNDERVault_AGENT_VAULT_URL`)
3. `WUNDERVault_CREDENTIALS_FILE` env var (explicit path)
4. `~/.wundervault/creds.json`
5. `~/.config/wundervault/credentials` (XDG)

### Credentials file format

```json
{
  "agent_vault_url": "https://wundervault.com",
  "agent_vault_api_key": "wv_agent_<ID>|<SUFFIX>",
  "agent_encryption_key": "<BASE64_URL_SAFE_32_BYTES>"
}
```

## CLI Options

```
wundervault-mcp [options]

  --api-key <key>     Agent API key
  --enc-key <key>     Encryption key (base64 URL-safe)
  --url <url>         API base URL (default: https://wundervault.com)
  --credentials <f>   Path to credentials JSON file
  --help              Show help
```

## Agent wallets (x402)

An [x402](https://x402.org) payment is just a signature, and a wallet key is a
vault secret like any other. Store the key at **tier 2**, have the agent sign the
payment payload through `vault_exec`, and the key is injected into a local signing
subprocess — it never enters the model context, and every use needs the owner's
approval first (the agent's denied call carries a request id; approval is scoped
to that agent + secret, once or for a 15/60-minute window). We ran this
end-to-end on Base Sepolia — the verified run is written up at
[wundervault.com/agent-wallets](https://wundervault.com/agent-wallets).
Payment-specific policy (spend caps, payee allowlists) is not built yet:
compatible, not productized.

## Sandbox / demo mode

Set `WUNDERVAULT_MOCK=1` to run the server **without** a `wundervault-agent`
daemon or any credentials. In this mode every tool call returns a representative
response clearly labelled `[DEMO MODE]` instead of contacting the vault — **no
real secret is ever involved**. This exists so you can poke at the tool surface
without an account, and so MCP directory scanners and CI
(e.g. [Glama](https://glama.ai)) can start the server, exercise each tool, and
validate the build with no live vault. It is **off by default** and is never
enabled in production.

```jsonc
"env": { "WUNDERVAULT_MOCK": "1" }   // demo/CI only — returns fake, labelled output
```

## Building from source

```bash
git clone https://github.com/wundervault/wundervault-mcp.git
cd wundervault-mcp
npm install
npm run build   # compiles TypeScript to dist/
npm test        # run the test suite
```

## License

Licensed under the **GNU Affero General Public License v3.0 or later** (`AGPL-3.0-or-later`). See [LICENSE](LICENSE).

Wundervault is **open-core**: this MCP server and the client are open source; the hosted service at [wundervault.com](https://wundervault.com) is a commercial offering. For commercial or hosting inquiries, get in touch via [wundervault.com/contact](https://wundervault.com/contact).
