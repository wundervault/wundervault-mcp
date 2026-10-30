# SPEC — installer fixes for the next release (deferred from the 2.0.3 reviews)

The 2.0.3 reviews deferred four real findings to the next release (burnbox/NEXT-RELEASE.md). The
owner asked for them to ship in one batch with OAuth 1.0a signing (SPEC-oauth1-2026-10-29.md).

## What changes

1. **secure_path steps (both installers).** When sudo's PATH has a folder someone other than root
   can change, the warning used to say "run `sudo visudo -f /etc/sudoers.d/secure_path` and add this
   line". visudo opens an editor as root, and which editor can come from the user's settings and
   PATH — the exposed thing. Now: when /etc/sudoers reads /etc/sudoers.d (`#includedir` or
   `@includedir`, `/etc` or `/private/etc`, optionally quoted or with a trailing slash), print four commands that name every tool by full path
   and never open an editor:
   `sudo /bin/mkdir -p /etc/sudoers.d`;
   `printf '%s\n' 'Defaults secure_path="…"' | sudo /usr/bin/tee /etc/sudoers.d/secure_path.new >/dev/null`;
   `sudo /bin/chmod 0440 /etc/sudoers.d/secure_path.new`;
   `sudo /usr/sbin/visudo -cf /etc/sudoers.d/secure_path.new && sudo /bin/mv /etc/sudoers.d/secure_path.new /etc/sudoers.d/secure_path`;
   then `sudo /usr/bin/printenv PATH` to check. sudo skips files in sudoers.d whose names contain a
   dot, so nothing changes until the final rename, and only after visudo's check passed. When
   sudoers does not read the folder, say so and point at wundervault.com/help/trouble#help-trouble-sudo-path instead.
   The sudoers file read is `${SUDOERS_FILE:-/etc/sudoers}` so tests can point it elsewhere; the
   real run starts from an empty environment, so nothing outside can set it.

2. **Linux `--uninstall` checks the service really stopped** (2.0.3 r3 B2). After
   `systemctl disable --now`, ask `systemctl show -p ActiveState --value` up to 15 times a second
   apart while it says active/activating/deactivating/reloading/refreshing. Remove the unit only on
   `inactive` or `failed`. Still running after 15 s, or any other answer (including systemctl
   failing), refuses with exit 1 and leaves the unit file in place — the same rule as macOS 2.0.2.

3. **Reinstall never writes as root through a path the broker's account controls** (2.0.3 r4 B2).
   - Every key the installer creates in the broker-owned state folder (Linux `broker-key.pem`,
     `store.key.cred`; macOS `broker-key.pem`, `store.key`) is made in a fresh root-only folder
     (`mktemp -d`, Linux under `/var/lib`, macOS under the base folder — the same file system as the
     state folder), given its owner and mode THERE, then put in place by `place_file`: refuse a link
     at the destination (clear message), refuse a real folder, then `mv -f -T` (Linux) / `mv -f -h`
     (macOS) — a rename, which replaces a link planted after the check instead of following it, and
     never moves the file into a folder a link points at. The temporary folder is removed on exit.
   - No key path is passed by name to openssl, dd, systemd-creds, chown or chmod.
   - macOS: the base folder `/var/lib/wundervault` becomes root's (root:wheel 0755) instead of the
     broker account's, and is taken back FIRST — chown, then `chmod -N` (every access list entry the
     account may have given itself survives a chown), then refuse if `ls -lde` still shows one —
     before `state` and `run` are checked for links, created, chowned or chmodded.
   - Both: the temporary folder must be on the same file system as the state folder (compared by
     `stat` device number); otherwise refuse, since mv would copy instead of renaming.
   - Linux: an existing key counts only if non-empty (`-s`); an empty one is replaced. The broker only needs to pass through it. Linux's state folder
     sits directly in root-owned `/var/lib`; a link there is refused.

4. **sudo hints: one ACL check per folder, within a time limit** (2.0.3 r5 B2). `agentCommand`'s
   default root-only test shares one `aclChecker` across all the paths a message checks: each
   folder is asked once, each `ls` gets only what is left of a 5-second budget, and past the budget
   every folder not yet checked counts as "may change" (so no command is offered on a guess). An
   answer already measured within the same message stays as measured. Injected checks are unchanged.

5. **The stray `wundervault-mcp-server-1.8.0.tgz`** is removed from the public repo; `*.tgz` ignored.

## Acceptance checks

1. Both installers, warning case with a sudoers that includes the folder: exactly four step lines;
   every `sudo` runs a full path; no `visudo -f`; the steps, run as a normal user with
   `/etc/sudoers.d` pointed at a temp folder, leave `secure_path` (mode 0440, the one line) and no
   `.new`. `@includedir /private/etc/sudoers.d` counts; a sudoers without it gets the help link.
2. Real root run (Debian 13 container, systemd, no secure_path): the printed steps, run as the
   user, make `sudo printenv PATH` print the safe path, and a rerun of the installer no longer warns.
3. Linux uninstall with stand-in systemctl: 4 busy answers then inactive → removed after 4 sleeps;
   never stops → exit 1 after 15 sleeps, no rm, no daemon-reload; inactive or failed at once → no
   wait; systemctl failing or an unknown state → refused, unit kept. Mutation: accepting any state
   fails tests.
4. place_file, run from the shipped script for the platform: link at destination → refused, target
   untouched; folder → refused; with the link check stubbed out (a link planted after it), a dangling
   link and a link to a folder are both REPLACED, nothing created at their targets. Same checks run
   by hand on a real Mac (macOS 27.0.1) for the macOS copy.
5. Static: no installer passes `$BROKER_KEY`, `$STORE_KEY` or `$SEALED_KEY` to openssl/dd/
   systemd-creds or chown; macOS chowns the base folder to root before checking or creating `state`.
6. Real root run: a link the broker account plants at `broker-key.pem` (to `/etc/sudoers.d/evil`)
   or at `store.key.cred` (to a folder) makes the reinstall refuse; nothing is created at the target.
   With the link removed the reinstall recreates the key: owned by the account, 0600, regular file,
   no temporary folder left. (The same plant against the shipped 2.0.3 installer creates
   `/etc/sudoers.d/evil` owned by the broker account — observed.)
7. aclChecker: shared folders asked once; a hung `ls` uses the whole budget and later folders are
   "may" without running `ls`; a slow one leaves the next only what is left.
8. Full MCP suite on Node 22 and 24.
