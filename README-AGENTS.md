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

There is no credentials file and no key in your MCP config. `onboard.py` registers the
agent and the local `wundervault-agent` broker holds the API key and the encryption key.
The MCP server talks to it over a unix socket — `/run/wundervault/<name>.sock` on Linux,
`/var/lib/wundervault/run/<name>.sock` on macOS, and `~/.wundervault/agents/<name>.sock`
where no broker account has been installed — authenticated with the agent token in
`~/.wundervault/agents/<name>.token`. The token stays in your own home on purpose: it is
the agent's identity, and moving it into the broker's directory would make it unreadable
by the only party that needs it.

**The socket serves operations, not credentials.** The broker does not hand the keys over:
it lists entries, performs a brokered HTTP call, answers a signature request. What crosses
the socket is the result, not the secret.

All your config has to say is which agent this is.

## What the server checks, and what it does not

On Linux, once you have run `sudo wundervault-agent --pair` and repaired the agent onto
that broker, every request to Wundervault is signed with a private key that lives in
`/var/lib/wundervault` — a directory the agents cannot read. The server refuses an
unsigned request from an agent bonded to a broker, and refuses to hand over a
broker-mode secret to anyone who did not sign. A copy of the credential on its own stops
being enough.

**An agent with no paired broker is authenticated on its credential alone**, exactly as
before. That is every agent on **Windows** today, and every Linux or macOS agent until it
has been repaired onto a broker — installing the broker does not migrate anything by
itself. For those, a broker-mode secret is refused outright — there is nothing on that
machine that could use one — and everything still in the legacy mode is served to whoever
holds the credential. Nothing here is a claim about Windows; support for it is not built.

## Environment Variables Reference

| Variable | Description |
|---|---|
| `WUNDERVAULT_AGENT_NAME` | **Required.** Which registered agent this process is. |
| `WUNDERVAULT_AGENT_TOKEN` | Optional. Overrides the token file above. |
| `WUNDERVAULT_MOCK` | Optional. `1` returns labelled demo output and touches no real secret. |

## CLI Options

`--url <url>` overrides the API base URL; `--help` prints usage. There are no
`--api-key`, `--enc-key`, or `--credentials` flags — unknown options are rejected.
