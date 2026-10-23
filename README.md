# @wundervault/mcp-server

[![npm version](https://img.shields.io/npm/v/%40wundervault%2Fmcp-server)](https://www.npmjs.com/package/@wundervault/mcp-server)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.wundervault%2Fwundervault--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=wundervault)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green)](LICENSE)
[![Follow @wundervault1](https://img.shields.io/badge/follow-%40wundervault1-000000?logo=x&logoColor=white)](https://x.com/wundervault1)

**Your AI agent uses your keys. It never holds them.**

A key you paste into a chat with an AI agent, or leave in a settings file it can read, gets
copied into its memory, its transcripts and its logs. With Wundervault the agent never receives
the key at all. A small
program on your own computer, the **broker**, keeps your keys in an account of its own. Your
agent asks it to call a web service, run a command on a server, pay for something or sign
something; the broker does it with the key and hands back the result, with the key removed.

Your vault is encrypted in your browser, so our server stores it but can't read it. Keys
you mark **"ask me first"** wait for your approval, with your passkey, on your phone or
computer.

This package is the MCP server your agent talks to, and the broker beside it. It works with
any [Model Context Protocol](https://modelcontextprotocol.io) client: Claude Code, Codex,
Cursor, Cline, OpenClaw and others.

**Don't take our word for it:** check the encryption claim on your own network, and verify
the installer, at [wundervault.com/verify](https://wundervault.com/verify).

## What your agent can do

| Tool | What it does |
|---|---|
| `vault_call` | Calls a web service with a key attached, and returns the answer with the key removed. |
| `vault_ssh_exec` | Runs a command on a server you listed, or rsyncs files to it. The broker signs the SSH login; the key never leaves it. |
| `vault_pay` | Pays an x402 "402 Payment Required" in USDC on Base or Solana, inside the limits you set. |
| `vault_sign` | Signs data with a signing key. You approve every signature. |
| `vault_entries_list` | Lists the keys this agent may use, and what kind each is. Never their values. |

No tool returns a key's value. Version 1's hand-over tools (`vault_exec`, `vault_entry_get`,
`vault_entry_inject_env`, `vault_rsync`) are gone; see [Upgrading from version 1](#upgrading-from-version-1).

## How it works

```
 ┌──────────────┐  MCP (stdio)  ┌──────────────────┐
 │   AI agent   │──────────────▶│ wundervault-mcp  │  runs as you, holds no keys
 │ (Claude, …)  │◀──────────────│                  │
 └──────────────┘  result, key  └────────┬─────────┘
                   removed               │ local socket
                                         ▼
                              ┌──────────────────────┐  HTTPS / SSH  ┌─────────────┐
                              │ broker               │──────────────▶│ the service │
                              │ its own OS account,  │◀──────────────│             │
                              │ holds the keys, logs │               └─────────────┘
                              │ each call on this box│
                              └──────────┬───────────┘
                                         │ signed requests, ciphertext only
                                         ▼
                              ┌──────────────────────┐
                              │   wundervault.com    │  stores your encrypted vault,
                              │                      │  relays your approvals
                              └──────────────────────┘
```

1. Your agent asks for work: "call this API", "deploy to this server".
2. The MCP server passes the request to the broker over a local socket. It holds no keys.
3. For an "ask me first" key, the broker waits for you to approve that call.
4. The broker makes the call with the key, records it in a log on your computer, and returns
   the result. For web calls the key goes to the service it belongs to, as it must; for SSH it
   never leaves the broker at all.

## Install

You need Node.js 20 or newer, and administrator rights on the computer your agents run on.
The full guide, with every step: [wundervault.com/quickstart](https://wundervault.com/quickstart).

**1. Create a vault** at [wundervault.com](https://wundervault.com). It's free.

**2. Install the package and the broker** on the computer your agents use:

```bash
npm install -g @wundervault/mcp-server@2
sudo sh "$(npm root -g)/@wundervault/mcp-server/packaging/install-daemon.sh"
```

Windows and macOS have their own installers; see
[wundervault.com/install](https://wundervault.com/install). The installer downloads nothing
and is short enough to read first.

**3. Pair the broker with your account:**

```bash
sudo wundervault-agent --pair
```

Check that the fingerprint it shows matches the one in your vault, then confirm.

**4. Add an agent.** In your vault, add an agent and choose this computer. You get a claim
code. Run this and enter it:

```bash
wundervault-agent --enrol
```

Then add Wundervault to your agent's MCP settings:

```json
{
  "mcpServers": {
    "wundervault": {
      "command": "wundervault-mcp",
      "env": { "WUNDERVAULT_AGENT_NAME": "<your agent's name>" }
    }
  }
}
```

The config holds no keys, and there are no key flags on the command line. Configs for other
clients: [README-AGENTS.md](README-AGENTS.md). If you're an AI agent installing this for
someone: [llms-install.md](llms-install.md).

## Upgrading from version 1

Version 2 moves your keys into the broker. Your account, vault and passkeys carry over.
Agents still on version 1 can't use your keys, so move each one:

1. `npm install -g @wundervault/mcp-server@2`
2. Install the broker and pair it (steps 2 and 3 above).
3. For each agent: open **Agents** in your vault, choose **Repair**, choose this computer,
   then run `wundervault-agent --enrol` and enter the claim code.
4. When every agent has moved: `wundervault-agent --migrate --finish` removes the old
   credential store.
5. Your vault marks each key your agents could read before version 2 with **Replace it at
   the service**. Replace those keys at the services that issued them: treat them as seen.

Your agent can't do this for you. It needs an administrator command and your approval in the
vault, by design. Details: [wundervault.com/install#upgrade-to-2](https://wundervault.com/install#upgrade-to-2).

## Supported platforms

| | Broker's own account | Status |
|---|---|---|
| Linux | `wundervault` system user, systemd unit with extra sandboxing | Supported |
| Windows | `wundervault` local account, scheduled task | Supported |
| macOS | `_wundervault` system account, LaunchDaemon | Supported |

On all three the broker runs under its own account, with its keys in a folder your agents
can't open. What differs is what surrounds that boundary:

- **Linux** adds `ProtectSystem=strict`, `ProtectHome`, `ProtectProc`, a system-call filter
  and an empty capability set. The store key is sealed with `systemd-creds`, to a TPM where
  there is one; without a TPM it is sealed to a host key on the same disk.
- **macOS** has no launchd equivalent of that sandboxing, so the account split is very nearly
  the whole defence. The store key is a random key in a file only the broker's account can
  read: not sealed. FileVault is what protects a stolen disk.
- **Windows** has the same account split and none of the extra sandboxing. An **elevated**
  administrator process can read the broker's files, as root can on Linux, and Windows
  OpenSSH gives an administrator an elevated session. The store key is a random key in a file
  only the broker's account can read; BitLocker protects a stolen disk.
  `packaging\verify-windows.ps1` checks the boundary on your own machine.

If something on Windows or macOS fails, tell us what it printed:
[wundervault.com/contact](https://wundervault.com/contact).

## Security model

- **The agent never gets a key.** No tool returns a value. The broker attaches the key to the
  request itself, the way you set for that key (a header, a query parameter, a username and
  password, or part of the web address), and removes it from the answer. Keys marked
  "stamped" (AWS, exchanges) never travel: the broker signs each request with them.
- **A separate account.** Your agents run as you; the broker doesn't. They can't read its
  files or its memory.
- **End-to-end encrypted vault.** Keys are encrypted in your browser with AES-256-GCM. The
  vault key comes from your passphrase, mixed with an Account Secret that never leaves your
  device, through Argon2id (PBKDF2 for a vault made where WebAssembly is off, such as iPhone
  Lockdown Mode). We store ciphertext only.
- **Signed requests.** The broker is paired to your account with a P-256 key whose fingerprint
  you confirm. The server serves a key's ciphertext only to requests that broker signed, so a
  copied credential alone gets nothing.
- **Approvals with your passkey.** An "ask me first" web call waits until you approve that
  exact destination, method and path, once or for a short window. Every payment outside your
  rules and every signature is sealed by your browser to exactly what you saw, so a server
  that only says "approved" can't spend your money.
- **A log on your computer.** Every call is recorded by the broker, signed, and checked
  against a copy of its chain we hold, so a changed log is detected. For "run without asking"
  keys, where the key went and why stays on your computer; we never see it.
  `sudo wundervault-agent --destinations` opens it.
- **HTTPS only**, with real certificate checks; redirects are not followed; private network
  addresses are refused unless you allowed one for that key.

### Honest limitations

- A "run without asking" key goes where your agent sends it. A tricked agent could send it to
  a server someone else controls, because the request carries the key. For keys that matter,
  choose "ask me first".
- "Ask me first" approves a destination, method and path, not what the request says. Within an
  approval window, calls to the same place go ahead whatever they contain.
- The broker removes your key from the answer as it was sent. A service that sends it back in
  another form, such as encoded, could get it past; and anything the call creates, such as a
  new API token, is your agent's.
- Agents that run under the same user account can use each other's access to the broker. Run
  an agent you trust less under another account.
- The broker must run on the same computer as the agent; fully air-gapped setups don't fit.
- The platform is **open-core**: this package and the
  [browser crypto](https://github.com/wundervault/wundervault-crypto) are AGPL-3.0, so you can
  audit everything that touches your keys; the hosted service is not open source.

Every known limit, kept with the code: [wundervault.com/limitations](https://wundervault.com/limitations).

## Tool reference

The full reference, with every argument: [wundervault.com/mcp](https://wundervault.com/mcp).

### `vault_call`

```
entry_id: string       which key
purpose: string        why; kept in the broker's log on the owner's computer
request?: {            describe the call (or operation_id + args instead)
  origin: { scheme: "https", host, port }, method, path,
  query?, body?, headers?,   # your own headers; never the one carrying the key
  stamp?                     # for stamped keys: how the service signs requests
}
operation_id?, args?   run an operation the owner defined for this key
```

### `vault_ssh_exec`

```
entry_id: string            an ed25519 SSH key
destination: string         [user@]host; the host must be on the key's allowed list
purpose: string
remote_argv?: string[]      command and arguments, run without a shell
rsync_args?: string[]       instead of a command; every host:path is checked too
timeout_seconds?: number    default 120
working_dir?: string        local folder for rsync sources
```

### `vault_pay`

```
entry_id: string            a wallet
payment_required            the 402 reply's PAYMENT-REQUIRED header, or its decoded JSON
accept_index?: number       which offer, when there is more than one
purpose: string             the owner sees it if they're asked
→ the header to send when you retry the request, in the reply text
```

USDC on Base, Base Sepolia, Solana and Solana devnet. Inside the owner's rules (trusted
payees, a daily limit, allowed networks) it signs at once; anything else waits for the owner.

### `vault_sign`

```
entry_id: string            a signing key
data: string                at most 256 KB
encoding?: "utf8" | "base64" | "hex"
purpose: string             the owner sees it
→ the signature (base64), the public key and the algorithm, in the reply text
```

The owner approves every signature and is shown the data in full when it is text up to 64 KB.

### `vault_entries_list`

No arguments. Each key's id, name, tier and kind (web service, SSH, wallet or signing key),
and any operations the owner defined. Never a value.

## Sandbox / demo mode

Set `WUNDERVAULT_MOCK=1` to run the server **without** a broker or any credentials. Every
tool call then returns a representative response clearly labelled `[DEMO MODE]` instead of
contacting the vault — **no real key is ever involved**. It exists so you can try the tool
surface without an account, and so MCP directory scanners and CI (e.g.
[Glama](https://glama.ai)) can start the server and exercise each tool. It is **off by
default**.

```jsonc
"env": { "WUNDERVAULT_MOCK": "1" }   // demo/CI only — returns fake, labelled output
```

## Building from source

```bash
git clone https://github.com/wundervault/wundervault-mcp.git
cd wundervault-mcp
npm install
npm run build   # compiles TypeScript to dist/
npm test
```

## Stay updated

Releases and security notes go out on X as [@wundervault1](https://x.com/wundervault1).
Full release history: [wundervault.com/changelog](https://wundervault.com/changelog).

## License

Licensed under the **GNU Affero General Public License v3.0 or later** (`AGPL-3.0-or-later`).
See [LICENSE](LICENSE).

Wundervault is **open-core**: this MCP server, the broker and the browser crypto are open
source; the hosted service at [wundervault.com](https://wundervault.com) is a commercial
offering. For commercial or hosting inquiries: [wundervault.com/contact](https://wundervault.com/contact).
