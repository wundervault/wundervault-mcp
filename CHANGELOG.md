# Changelog

Changes to `@wundervault/mcp-server`: the MCP server, the broker (`wundervault-agent`) and the
installers. The full history, with the website's changes beside it, is at
<https://wundervault.com/changelog>.

## [2.1.0] — 2026-10-29

### Security

- **Reinstalling the broker keeps root's writes inside root's own folders.** The installers create
  the broker's keys in a folder only root can enter and move them into place in one step, so a link
  left where a key belongs is refused or replaced, never followed. On a Mac, `/var/lib/wundervault`
  now belongs to root (the broker only passes through it), so its `state` and `run` folders cannot be
  swapped before an install runs, and an access list left on it is removed. On Linux, an empty key file,
  or a folder where a key belongs, is no longer taken for a key. A state folder mounted on its own is
  refused, because keys could not be moved into it in one step.
- **The fix for an exposed sudo no longer opens an editor as root.** When sudo on your computer looks
  commands up in a folder your account can change, the installers now print four commands that add
  the safe `secure_path` line, each naming its tool by full path, and check the file before sudo
  reads it. The old advice, `visudo -f`, starts an editor as root, and which editor can come from the
  very settings that are exposed.

### Fixed

- **Linux `--uninstall` waits for the broker to stop**, for up to 15 seconds, and removes the service
  only once systemd says it has. If it is still running, or systemd does not answer, nothing is
  removed, and you are told what to run. The Mac's uninstall has worked this way since 2.0.2.
- **The pairing hint is quicker on a slow disk.** Working out which `node` and broker to print checks
  each folder once, within five seconds in all.

### Added

- **Signed requests for X and other OAuth 1.0a services.** A secret marked "stamped" can now hold
  the four values X gives you (API key and secret, access token and secret), stored together as
  `{"api_key": "…", "api_secret": "…", "access_token": "…", "access_token_secret": "…"}`. Agents ask
  for `request.stamp: {"builtin": "oauth1"}` and the broker signs every request itself, with a
  fresh one-time code and the current time, so you approve it once per address and each later post
  goes through. The same option works for Tumblr and Flickr, and, with HMAC-SHA256 and a realm, for
  NetSuite. None of the four values reaches the agent, and the two secret ones are removed from
  anything the service sends back.
- **Those four values are never sent as one token.** A secret holding them that is still set to
  "Bearer token" — which is how 1.0's upgrade left an X key saved before it — is now refused with a
  note to switch it to "Signed requests", instead of being sent whole to the service.

## [2.0.3] — 2026-10-28

### Security

- **The broker installers run only the system's own tools.** They are the one step that runs as root,
  and they found tools such as `launchctl` and `id` on the PATH of whoever ran `sudo`. On a Mac that
  PATH usually starts with `/opt/homebrew/bin`, a folder your account (and so every agent) can write,
  so a program planted there could have run as root. The installers now use only `/usr/bin`, `/bin`,
  `/usr/sbin` and `/sbin`, and use your PATH only to find `node` and `wundervault-agent`.
- **Node and the broker must be reachable only through things root alone can change**: the file,
  every folder above it, and every link on the way and the folder each sits in. A root-owned file in a
  folder your account can write can be swapped, and the service starts it by that path. Every file
  in the broker's package must be root's too, and a folder whose access list lets someone else change
  it is refused, as is any link in the package — or in a folder one of its links leads to — that passes
  through a folder someone else can change. The service file each installer writes from (the macOS
  plist, the Linux unit) is held to the same rule: it decides what the service runs. A check that
  cannot finish (a folder it cannot read) is a refusal, never a pass. The Linux installer now checks
  all of this too, before it runs `node` at all. If yours does not pass, the installer says which file
  or folder and how to install somewhere safe.
- **The installers start over with an empty environment**, so nothing you exported (`NODE_OPTIONS`, a
  dynamic-loader or OpenSSL setting) can make the tools they run load other code. Until that is done
  they run nothing by name: the Mac's `sh` turns shell functions passed in the environment into
  commands — even one called `[` — so the first lines use only what such a function cannot replace.
- **The installers tell you when sudo itself is exposed.** If the PATH that sudo uses on your computer
  includes a folder someone other than root can change (on a Mac, usually `/opt/homebrew/bin`; an empty
  entry or an empty PATH, which means whatever folder you are in, counts too), every
  `sudo` command you type — `sudo npm install` included — could run a program an agent put there. The
  installers are not affected, but they now say so, name the folder, and give the one line to add to
  sudo's settings (`Defaults secure_path=…`) that closes it.
- **The Linux service names its `node`**, like the macOS one: before, systemd looked `node` up on its
  own PATH at every start, so a `node` someone put later in an earlier folder of that PATH would have
  become the broker's interpreter.
- **Every `sudo` command the broker and its installers print names `node` and the broker by their full
  paths**, and so do the README's pairing steps. `sudo` may look a name up on your own PATH, and the
  broker's launcher finds `node` the same way (`#!/usr/bin/env node`), so naming the broker alone was
  not enough. A command is printed only when both pass the same root-only check as the installers
  (access lists included); otherwise the message points to the command your installer printed.

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
