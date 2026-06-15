# @wundervault/mcp-server

[![npm version](https://img.shields.io/npm/v/%40wundervault%2Fmcp-server)](https://www.npmjs.com/package/@wundervault/mcp-server)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.wundervault%2Fwundervault--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=wundervault)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green)](LICENSE)

MCP server for [Wundervault](https://wundervault.com) zero-knowledge secret management. Exposes vault secrets to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io) — secrets are decrypted server-side and never returned to the agent in plaintext.

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

## Security Model

- **Zero-knowledge:** The encryption key lives only in the MCP server process. The Wundervault server never sees it.
- **Burn-after-reading:** Plaintext secrets are never returned to the calling agent. After decryption, the agent receives only `"Secret retrieved and burned."`.
- **Exec scrubbing:** If you use the `exec` parameter, stdout/stderr are scrubbed of the plaintext before being returned.
- **Directive integrity:** Server-side directive signatures (PBKDF2-HMAC-SHA256, 600k iterations) are verified before any secret is released.
- **Timing-safe:** HMAC comparison uses `crypto.timingSafeEqual`.

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

## Sandbox / demo mode

Set `WUNDERVAULT_MOCK=1` to run the server **without** a `wundervault-agent`
daemon or any credentials. In this mode every tool call returns a representative
response clearly labelled `[DEMO MODE]` instead of contacting the vault — **no
real secret is ever involved**. This exists so MCP directory scanners and CI
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
