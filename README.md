# @wundervault/mcp-server

[![npm version](https://img.shields.io/npm/v/%40wundervault%2Fmcp-server)](https://www.npmjs.com/package/@wundervault/mcp-server)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.wundervault%2Fwundervault--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=wundervault)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green)](LICENSE)
[![Follow @wundervault1](https://img.shields.io/badge/follow-%40wundervault1-000000?logo=x&logoColor=white)](https://x.com/wundervault1)

**Your AI agent uses your secrets. It never holds them.**

A secret you paste into a chat with an AI agent, or leave in a settings file it can read, gets
copied into its memory, its transcripts and its logs. With Wundervault the agent never receives
the secret at all. A small
program on your own computer, the **broker**, keeps your secrets in an account of its own. Your
agent asks it to call a web service, run a command on a server, pay for something or sign
something; the broker does it with the secret and hands back the result, with the secret removed.

Your vault is encrypted in your browser, so our server stores it but can't read it. Secrets
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
| `vault_call` | Calls a web service with a secret attached, and returns the answer with the secret removed. |
| `vault_new_key` | Makes a new key at a service and puts it straight into your vault, where it waits for you. The agent never sees it. |
| `vault_save_secret` | Saves a secret the agent already has (a file, a command's output) into your vault without reading it into the chat. It waits for you. |
| `vault_send_secret` | Puts secrets from your vault into a Cloudflare Worker's settings (encrypted Worker secrets). You approve the list once; the agent never sees the values. |
| `vault_ssh_exec` | Runs a command on a server you approved, or rsyncs files to it. The broker signs the SSH login; the key never leaves it. |
| `vault_git` | Runs git push, pull, fetch, clone or ls-remote over SSH with a vaulted key. Linux and macOS. |
| `vault_2fa_code` | Gives the current authenticator-app code for a sign-in. Never the setup key. |
| `vault_pay` | Pays an x402 "402 Payment Required" in USDC on Base or Solana, inside the limits you set. |
| `vault_sign` | Signs data with a signing key. You approve every signature. |
| `vault_entries_list` | Lists the secrets this agent may use, and what kind each is. Never their values. |

No tool returns a secret's value. Version 1's hand-over tools (`vault_exec`, `vault_entry_get`,
`vault_entry_inject_env`, `vault_rsync`) are gone; see [Upgrading from version 1](#upgrading-from-version-1).

## How it works

```
 ┌──────────────┐  MCP (stdio)  ┌──────────────────┐
 │   AI agent   │──────────────▶│ wundervault-mcp  │  runs as you, holds no secrets
 │ (Claude, …)  │◀──────────────│                  │
 └──────────────┘    result     └────────┬─────────┘
                 (secret removed)        │ local socket
                                         ▼
                              ┌──────────────────────┐  HTTPS / SSH  ┌─────────────┐
                              │ broker               │──────────────▶│ the service │
                              │ its own OS account,  │◀──────────────│             │
                              │ holds the secrets,   │               └─────────────┘
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
2. The MCP server passes the request to the broker over a local socket. It holds no secrets.
3. For an "ask me first" secret, the broker waits for you to approve that call.
4. The broker makes the call with the secret, records it in a log on your computer, and returns
   the result. For web calls the secret goes to the service it belongs to, as it must; for SSH it
   never leaves the broker at all.

## Install

You need Node.js 22.23.4, 24.22.1 or 26.12.1 or newer (the October 21, 2026 security release: the broker
refuses to start on an older Node), and administrator rights on the computer your agents run on.
Every step: [wundervault.com/help/computer](https://wundervault.com/help/computer).

**1. Create a vault** at [wundervault.com](https://wundervault.com). It's free.

**2. Install the package and the broker** on the computer your agents use:

```bash
sudo npm install -g @wundervault/mcp-server@2
sudo sh "$(npm root -g)/@wundervault/mcp-server/packaging/install-daemon.sh"
```

That is Linux: `sudo`, because the broker only runs a copy installed in a system folder, never
one inside your home folder.

Windows and macOS have their own installers; see
[wundervault.com/install](https://wundervault.com/install). The installer downloads nothing
and is short enough to read first.

**3. Pair the broker with your account.** Run the pairing command the installer printed last. It
names node and the broker by their full paths, for example:

```bash
sudo /opt/wundervault/current/node /opt/wundervault/current/app/bin/wundervault-agent --pair
```

Use full paths with `sudo`, not bare names: `sudo` may look a name up on your own PATH, and a folder
on it that you (and so your agents) can write could hold another program by that name. That goes for
node too, because the broker's launcher starts with `#!/usr/bin/env node`.

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

The config holds no secrets, and none go in command-line flags. Configs for other
clients: [README-AGENTS.md](README-AGENTS.md). If you're an AI agent installing this for
someone: [llms-install.md](llms-install.md).

## Upgrading from version 1

Version 2 moves your secrets into the broker. Your account, vault and passkeys carry over.
Agents still on version 1 can't use your secrets, so move each one:

1. `npm install -g @wundervault/mcp-server@2`
2. Install the broker and pair it (steps 2 and 3 above).
3. For each agent: open **Agents** in your vault, choose **Repair**, choose this computer,
   then run `wundervault-agent --enrol` and enter the claim code.
4. When every agent has moved: `wundervault-agent --migrate --finish` removes the old
   credential store.
5. Your vault marks each secret your agents could read before version 2 with **Replace it at
   the service**. Replace those secrets at the services that issued them: treat them as seen.

Your agent can't do this for you. It needs an administrator command and your approval in the
vault, by design. Details: [wundervault.com/install#upgrade-to-2](https://wundervault.com/install#upgrade-to-2).

## Supported platforms

| | Broker's own account | Status |
|---|---|---|
| Linux | `wundervault` system user, systemd unit with extra sandboxing | Supported |
| Windows | `wundervault` local account, scheduled task | Supported |
| macOS | `_wundervault` system account, LaunchDaemon | Supported |

On all three the broker runs under its own account, with its secrets in a folder your agents
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

- **The agent never gets a secret.** No tool returns a value. The broker attaches the secret to the
  request itself, the way you set for that secret (a header, a query parameter, a username and
  password, or part of the web address), and removes it from the answer. Secrets marked
  "stamped" (AWS, X and other OAuth 1.0a services, exchanges) never travel: the broker signs each
  request with them.
- **A separate account.** Your agents run as you; the broker doesn't. They can't read its
  files or its memory.
- **End-to-end encrypted vault.** Secrets are encrypted in your browser with AES-256-GCM. The
  vault key comes from your passphrase, mixed with an Account Key that never leaves your
  device, through Argon2id (PBKDF2 for a vault made where WebAssembly is off, such as iPhone
  Lockdown Mode). We store ciphertext only.
- **Signed requests.** The broker is paired to your account with a P-256 key whose fingerprint
  you confirm. The server serves a secret's ciphertext only to requests that broker signed, so a
  copied credential alone gets nothing.
- **Approvals with your passkey.** An "ask me first" web call waits until you approve that
  exact destination, method and path, once or for a short window. Every payment outside your
  rules and every signature is sealed by your browser to exactly what you saw, so a server
  that only says "approved" can't spend your money.
- **A log on your computer.** Every call is recorded by the broker, signed, and checked
  against a copy of its chain we hold, so a changed log is detected. For "run without asking"
  secrets, where the secret went and why stays on your computer; we never see it.
  `sudo /opt/wundervault/current/node /opt/wundervault/current/app/bin/wundervault-agent --destinations` opens it (full paths, as for pairing).
- **HTTPS only**, with real certificate checks; redirects are not followed; private network
  addresses are refused unless you allowed one for that secret.

### Admin access and everyday access for servers

For Linux servers, start guided setup from the admin key's page. It makes a separate everyday
account, named `wv-agent` by default, that can look but not change. It cannot use `sudo` to run
commands as administrator or open the admin account's home folder. You can also let it read
system logs. Setup includes a health check and a change check.

Keys are made in your browser and saved straight into the vault. Only their public halves go
to the server. The helper app runs a fixed setup script over SSH and shows each step as pass
or fail. Nothing that works is removed until a test sign-in proves the new way works. Running
setup again is safe.

After each admin access ends, the helper app uses the everyday key to check the server for
new sign-in keys, accounts, admin-group members, sudo rules (who may run commands as
administrator), SSH sign-in settings, scheduled jobs and system services. If something
changed, you get an email saying "something changed on one of your servers", with no details.
The key's page shows what changed. Use **Remove** for a new sign-in key, or **These are fine**
to accept the changes. The server's administrator, root, can change the checker too. It catches
mistakes and careless agents, not a determined one.

Setup also makes an **emergency key**. It is never given to an agent: no copy, no share and no
admin access. Open it with your passkey. Keep a copy off the site and test it once. You need
it because admin access cannot be turned on if the server is down.

For this computer's own admin key, which lets you run commands as administrator, make it in
the vault. The vault shows one command to paste:

```bash
sudo sh admin-key.sh --public 'ssh-ed25519 AAAA…'
```

No private key is ever printed in the terminal.

While admin access is on, the agent can read every secret on that server. Short admin access
reduces that time; it does not remove that risk. An agent with its own key file to the server
can get round all of this.

### Honest limitations

- A "run without asking" secret goes where your agent sends it. A tricked agent could send it to
  a server someone else controls, because the request carries the secret. For secrets that matter,
  choose "ask me first".
- "Ask me first" approves a destination, method and path, not what the request says. Within an
  approval window, calls to the same place go ahead whatever they contain.
- The broker removes your secret from the answer as it was sent. A service that sends it back in
  another form, such as encoded, could get it past; and anything the call creates, such as a
  new API token, is your agent's.
- Agents that run under the same user account can use each other's access to the broker. Run
  an agent you trust less under another account.
- The broker must run on the same computer as the agent; fully air-gapped setups don't fit.
- The platform is **open-core**: this package and the
  [browser crypto](https://github.com/wundervault/wundervault-crypto) are AGPL-3.0, so you can
  audit everything that touches your secrets; the hosted service is not open source.

Every known limit, kept with the code: [wundervault.com/limitations](https://wundervault.com/limitations).

## Tool reference

The full reference, with every argument: [wundervault.com/mcp](https://wundervault.com/mcp).

### `vault_call`

```
entry_id: string       which secret
purpose: string        why; kept in the broker's log on the owner's computer
request?: {            describe the call (or operation_id + args instead)
  origin: { scheme: "https", host, port }, method, path,
  query?, body?, headers?,   # your own headers; never the one carrying the secret
  stamp?                     # for stamped keys: how the service signs requests
  send_as?                   # a key saved without a way: {in:"header"|"query", name, template:"…{secret}…"},
                             # approved once per address by the owner
  sign_in?                   # a stored login: how to sign in and carry the session; approved once
  trust_certificate?         # a device with its own certificate; the owner approves that certificate
}
operation_id?, args?   run an operation the owner defined for this secret
```

### `vault_save_secret`

```
save_as: string        the name for the secret in the vault (1-80 characters)
from_file?: string     an absolute path, read as the agent's own user (up to 64 KB)
from_command?: string[]  the program, then its arguments; no shell, 30 s, standard output only
value?: string         the text itself, only when it is already in the chat
pick?: { env: "NAME" } | { json: "a.b" }   with a file or command: one line of a .env, or one JSON field
service?: string       a hint for the owner (e.g. "resend")
purpose: string
```

Exactly one of `from_file`, `from_command`, `value`. The agent-side MCP process reads the file or
runs the command as the agent's user (never the broker's account); only the value goes to the
broker, which locks it so only the owner's browser can read it and puts it under Needs you,
marked "Saved by an agent". The agent gets the name, the source and the length: never the value,
never any of the file or output, also not in errors. A failing or slow command saves nothing; its
standard error is never read. Same limits and outbox as `vault_new_key`.

### `vault_new_key`

```
entry_id: string       a secret that is allowed to create keys at the service
request: { origin, method: "POST", path, body?, headers? }   as for vault_call
save_as: string        the name for the new secret in the vault (1-80 characters)
replaces_entry_id?: string   rotating: the secret this key replaces (one this agent has)
purpose: string
```

Makes a new key at a service and puts it straight into the owner's vault. The broker takes
the new key out of the service's answer, encrypts it so only the owner's browser can read it,
and the agent gets the key's id and name at the service: never the key, never the rest of the
answer. The key waits under Needs you; no agent can use it until the owner saves it with a
passkey and chooses which agents may.

Works only at the key-making addresses the broker knows (Resend, Cloudflare user and account
tokens, SendGrid, OpenAI admin keys and project service accounts, Twilio, OpenRouter; the list
and where each was checked is in `RECIPES-new-key.md`). `vault_call` refuses those addresses.
If the vault cannot be reached after the key is made, the broker keeps it, locked, and hands it
over on the agent's next vault call; it makes no other key meanwhile. If no answer comes back
from the service, the agent is told it is not known whether a key was made.

### `vault_ssh_exec`

```
entry_id: string            an ed25519 SSH key
destination: string         user@host[:port]; an approved server, or a new one the owner approves on first use
purpose: string
remote_argv?: string[]      command and arguments, run without a shell
rsync_args?: string[]       instead of a command; every host:path is checked too
timeout_seconds?: number    default 120
working_dir?: string        local folder for rsync sources
```

An SSH key can be marked an **admin key**: a key that can change the server, such as running
commands as administrator, deploying code or managing containers. It always asks the owner
first. An agent can use it only while the owner allows admin access for that agent, for
5 minutes, 15 minutes or 1 hour, approved with the owner's passkey. The agent's request returns
`ADMIN_ACCESS_REQUIRED` with a request id; the agent polls for approval. The owner can also
start from **Allow admin access…** on the key's page, and can require typing the key's name
before approving. Admin access ends when time runs out, the owner presses **End now**, or the
agent calls `vault_done` if its setting says to end admin access then. Agents should call
`vault_done` when finished. The SSH connections close when admin access ends. On a server set
up for it, the server closes them too: admin sign-ins use a short-lived certificate that
allows sign-in only until admin access ends.

### `vault_git`

```
entry_id: string            an SSH key
purpose: string
subcommand: "push" | "pull" | "fetch" | "clone" | "ls-remote"
repo_dir: string            the local repository (for clone: the folder to clone into)
remote?: string             a named remote, e.g. origin (all but clone)
url?, target_dir?           clone only
refspecs?: string[]
flags?: string[]            a short allowed list per subcommand; no --force
timeout_seconds?: number    default 120, at most 870
```

Every address git would connect to, including a separate push address and config rewrites, must be
an approved server. SSH remotes only; no submodules and no hooks while the key is in use.

### `vault_2fa_code`

```
entry_id: string            an Authenticator code secret, or a login with its setup key
purpose: string             what you are signing in to; the owner sees it
→ the code and how many seconds it stays valid
```

Authenticator-app codes only (not text-message or email codes, not passkeys).

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

No arguments. Each secret's id, name, tier and kind (web service, SSH, wallet or signing key),
and any operations the owner defined. Never a value.

## Sandbox / demo mode

Set `WUNDERVAULT_MOCK=1` to run the server **without** a broker or any credentials. Every
tool call then returns a representative response clearly labelled `[DEMO MODE]` instead of
contacting the vault — **no real secret is ever involved**. It exists so you can try the tool
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
