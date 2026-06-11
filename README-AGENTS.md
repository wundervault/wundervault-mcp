# Wundervault MCP Server — Agent Configuration

How to configure `@wundervault/mcp-server` for different AI agent environments.

## Claude Code

Add to `~/.claude/desktop_config.json` (or your Claude Code MCP config):

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

```json
{
  "mcpServers": {
    "wundervault": {
      "command": "wundervault-mcp",
      "args": ["--credentials", "/home/user/.wundervault/creds.json"]
    }
  }
}
```

## Cursor

Add to `.cursor/mcp.json` in your project (or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "wundervault": {
      "command": "wundervault-mcp",
      "env": {
        "WUNDERVault_AGENT_VAULT_API_KEY": "wv_agent_<AGENT_ID>|<KEY_SUFFIX>",
        "WUNDERVault_AGENT_KEY": "<BASE64_ENCRYPTION_KEY>"
      }
    }
  }
}
```

## OpenAI Agents SDK

```python
from openai_agents import Agent
from openai_agents.mcp import MCPServerStdio

wundervault_server = MCPServerStdio(
    params={
        "command": "wundervault-mcp",
        "env": {
            "WUNDERVault_AGENT_VAULT_API_KEY": "wv_agent_<AGENT_ID>|<KEY_SUFFIX>",
            "WUNDERVault_AGENT_KEY": "<BASE64_ENCRYPTION_KEY>",
        },
    }
)

agent = Agent(
    name="my-agent",
    mcp_servers=[wundervault_server],
)
```

## Generic (npx, no global install)

```json
{
  "mcpServers": {
    "wundervault": {
      "command": "npx",
      "args": [
        "@wundervault/mcp-server",
        "--credentials", "/home/user/.wundervault/creds.json"
      ]
    }
  }
}
```

## Credentials File Format

Create `~/.wundervault/creds.json`:

```json
{
  "agent_vault_url": "https://wundervault.com",
  "agent_vault_api_key": "wv_agent_<AGENT_ID>|<KEY_SUFFIX>",
  "agent_encryption_key": "<BASE64_URL_SAFE_32_BYTES>"
}
```

Set permissions: `chmod 600 ~/.wundervault/creds.json`

## Environment Variables Reference

| Variable | Description |
|---|---|
| `WUNDERVault_AGENT_VAULT_URL` | API base URL (default: `https://wundervault.com`) |
| `WUNDERVault_AGENT_VAULT_API_KEY` | Agent API key (`wv_agent_<ID>\|<HMAC>`) |
| `WUNDERVault_AGENT_KEY` | Base64 URL-safe encryption key (32 bytes) |
| `WUNDERVault_CREDENTIALS_FILE` | Explicit path to credentials JSON file |
