# Changelog

Changes to `@wundervault/mcp-server`: the MCP server, the broker (`wundervault-agent`) and the
installers. The full history, with the website's changes beside it, is at
<https://wundervault.com/changelog>.

## [2.0.2] — 2026-10-28

### Improved

- **Your broker's log looks like Wundervault.** `sudo wundervault-agent --destinations` opens a page in
  the site's design: the Wundervault header, a Light / Dark / Auto switch, and the check result in words
  ("Checks out", "Problem found", "Not confirmed"). It still loads nothing and cannot reach the network,
  and it now says that it is a snapshot: run the command again for newer activity.
- **The log shows hidden direction characters.** If text an agent wrote contains invisible
  right-to-left controls, the page shows them as visible codes (for example `⟨U+202E⟩`), so an address
  or a reason cannot display as something other than what was recorded.
- **The log's tables can be reached and scrolled with the keyboard.**
- **Demo mode (`WUNDERVAULT_MOCK=1`) needs no agent name, and any number of copies can run at once**,
  each with all five vault tools. Directories that scan MCP servers now see the full set.
- **The MCP Registry entry describes version 2**: the broker, and enrolling with `wundervault-agent --enrol`.

### Fixed

- `sudo wundervault-agent --destinations` works on macOS. It looked up your account with a Linux-only
  tool and stopped before opening the page.
- The macOS uninstaller (`install-daemon-macos.sh --uninstall`) waits up to 15 seconds for the broker to
  stop, instead of refusing while it is still closing its connections.
- `--destinations` gives up root completely before it writes the page: if root's extra groups cannot be
  dropped as well as its user, it stops instead of carrying on with them.
- A damaged record in the destination store shows as a damaged value; it no longer stops the page from
  showing the rest of the log.
- A request that changes something (a POST, a payment) and loses its connection now always says it may
  already have taken effect. On a connection kept open from an earlier call it read as a plain failure,
  which invites sending it again.
- CI runs on Node.js 22 and 24, the versions 2.0 supports (it was still testing Node.js 20).

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
