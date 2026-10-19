# Wundervault MCP Server — Agent Configuration

How to configure `@wundervault/mcp-server` for different AI agent environments.

## Claude Code

Run `claude mcp add`, or add this to `~/.claude.json` (all projects) or a project's `.mcp.json`:

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
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async def main():
    async with MCPServerStdio(params={
        "command": "wundervault-mcp",
        "env": {"WUNDERVAULT_AGENT_NAME": "<agent-name>"},
    }) as wundervault:
        agent = Agent(name="my-agent", mcp_servers=[wundervault])
        result = await Runner.run(agent, "List my vault keys.")
        print(result.final_output)

asyncio.run(main())
```

## Generic (npx, no global install)

```json
{
  "mcpServers": {
    "wundervault": {
      "command": "npx",
      "args": ["-y", "--package=@wundervault/mcp-server@2", "wundervault-mcp"],
      "env": {
        "WUNDERVAULT_AGENT_NAME": "<agent-name>"
      }
    }
  }
}
```

## Where the keys actually come from

There is no credentials file and no key in your MCP config. `wundervault-agent --enrol`
(with the claim code from the owner's vault) enrols the agent with the broker, and the
broker, running under its own account, holds the agent's keys. The MCP server talks to it
over a local socket (`/run/wundervault/<name>.sock` on Linux,
`/var/lib/wundervault/run/<name>.sock` on macOS, a loopback port on Windows), authenticated
with the agent token in `~/.wundervault/agents/<name>.token`. The token stays in your own
home on purpose: it is the agent's identity, and moving it into the broker's directory would
make it unreadable by the only party that needs it.

**The socket serves operations, not credentials.** The broker does not hand the keys over:
it lists entries, makes a web call, signs an SSH login, a payment or a signature. What
crosses the socket is the result, not the key.

All your config has to say is which agent this is.

## What the server checks

Every request a broker makes to Wundervault is signed with a private key that lives in the
broker's own directory, which the agents cannot read; the owner confirmed its fingerprint
when pairing. The server refuses an unsigned request from an agent enrolled on a broker, and
serves a key's ciphertext only to the broker that signed for it. A copy of the credential on
its own is not enough.

Version 2 is brokered only. The MCP server refuses to run without a broker, and version 1's
hand-over mode, where the agent was given the key, is gone from the server too.

On all three platforms the broker has an account of its own. On Windows the boundary is an
NTFS access list rather than a file mode, an elevated administrator is inside it exactly as
root is on Linux, and `packaging\verify-windows.ps1` proves it from a throwaway unprivileged
account rather than reading the permissions back.

## Environment Variables Reference

| Variable | Description |
|---|---|
| `WUNDERVAULT_AGENT_NAME` | **Required.** Which registered agent this process is. |
| `WUNDERVAULT_AGENT_TOKEN` | Optional. Overrides the token file above. |
| `WUNDERVAULT_MOCK` | Optional. `1` returns labelled demo output and touches no real secret. |

## CLI Options

`--help` prints usage. `--url` is accepted and ignored: the vault's address comes from the
broker, so a config cannot point the agent somewhere else. There are no `--api-key`,
`--enc-key`, or `--credentials` flags — unknown options are rejected.
