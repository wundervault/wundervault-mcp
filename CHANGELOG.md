# Changelog

Changes to `@wundervault/mcp-server`: the MCP server, the broker (`wundervault-agent`) and the
installers. The full history, with the website's changes beside it, is at
<https://wundervault.com/changelog>.

## [2.0.1] — 2026-10-27

### Improved

- **When an approval doesn't come in time, the agent is told plainly.** A secret that asks the owner
  first now ends the wait with one of three messages, the same for web calls, SSH and signing: the
  owner hasn't answered yet (the request stays open in the vault; the same call goes through once
  it's approved), the owner declined, or the request expired. Each names the secret and says nothing
  was sent. Before, an SSH call returned the server's raw refusal, naming an address the agent can't use.
- **The Linux and macOS broker installers install the copy they came with**, not the first
  `wundervault-agent` on `PATH`, which could be an older copy left in `/usr/local`. They say when they
  skip one, and their next steps then use the installed copy's full path.
- **The installers end with the next steps, in order**: pair this computer (with `sudo`), then, only if
  it ran version 1, migrate (without). The migrate line used to come last on its own and read as the
  pairing step.
- **The "older copy" message is plain English**: which agent, which process and since when, and the
  fix (quit and reopen the agent app, then reconnect). A same-named agent under another user account,
  or a different agent on the same place, each get their own message.
- **README:** Linux installs with `sudo npm install -g`.

### Fixed

- A lock test could collide with the test before it on Linux CI (`EADDRINUSE`). Each test now uses
  its own agent name, so its own address.

## [2.0.0] — 2026-10-27

The broker release, with Wundervault 1.0: agents use secrets without receiving them. See
<https://wundervault.com/releases/1-0>.
