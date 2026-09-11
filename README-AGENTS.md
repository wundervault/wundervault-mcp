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
        "WUNDERVAULT_AGENT_NAME": "<agent-name>"
      }
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
        "WUNDERVAULT_AGENT_NAME": "<agent-name>"
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
            "WUNDERVAULT_AGENT_NAME": "<agent-name>",
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
      "args": ["@wundervault/mcp-server"],
      "env": {
        "WUNDERVAULT_AGENT_NAME": "<agent-name>"
      }
    }
  }
}
```

## Where the keys actually come from

There is no credentials file and no key in your MCP config. `onboard.py` registers
the agent and starts the local `wundervault-agent` daemon; the daemon holds the API
key and the encryption key and hands them to the MCP server over a unix socket at
`~/.wundervault/agents/<name>.sock`, authenticated with the agent token in
`~/.wundervault/agents/<name>.token`.

All your config has to say is which agent this is.

## Environment Variables Reference

| Variable | Description |
|---|---|
| `WUNDERVAULT_AGENT_NAME` | **Required.** Which registered agent this process is. |
| `WUNDERVAULT_AGENT_TOKEN` | Optional. Overrides the token file above. |
| `WUNDERVAULT_MOCK` | Optional. `1` returns labelled demo output and touches no real secret. |

## CLI Options

`--url <url>` overrides the API base URL; `--help` prints usage. There are no
`--api-key`, `--enc-key`, or `--credentials` flags — unknown options are rejected.
