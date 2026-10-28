# SPEC — 2.0.2 (2026-10-28)

The branded log page (SPEC-branded-log-page-2026-10-28.md) already went through two review rounds
(round 2: ship). This release adds the fixes found the same day. Everything below is in scope here.

## S1. `sudo wundervault-agent --destinations` works on macOS
Seen on the owner's Mac: `Ran under sudo as 'zackaryprag', but that account could not be resolved
(spawnSync getent ENOENT)`. `resolveSudoUser` shelled out to `getent`, which macOS lacks.
- macOS: look the account up with `/usr/bin/dscacheutil -q user -a name <user>` (Directory Services;
  the equivalent of NSS) — by FULL PATH, because this runs as root and sudo may keep the user's PATH.
- Linux: `getent passwd <user>`, unchanged.
- Unchanged refusals: unresolvable name, unusable entry, uid 0 → throw "Refusing to continue as root".
- New refusal: when `SUDO_UID` is set and differs from the resolved uid.
- Only the first dscacheutil record counts, and only if its `name` is the name asked for.
- The lookup's inputs (platform, env, uid, command runner) are injectable so every platform is
  tested on any CI.

## S2. The macOS uninstaller waits for launchd
`--uninstall` refused with "the job is still loaded after bootout" while the broker was still
closing its connections; a re-run seconds later worked. Poll `launchctl print` once a second for up
to 15 seconds; refuse (and do NOT remove the plist) only if it is still loaded after that.

## S3. The log page shows bidi controls instead of obeying them
U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069 in any agent-written or file-derived text are
shown as `⟨U+XXXX⟩`: in cells (page script `text()` / `fmt()`), in server-rendered text (`esc()`),
and the embedded JSON carries them as `\uXXXX` escapes so the HTML file never contains one raw.

## S4. The log page's scrolling tables are keyboard-reachable
Each `.tablewrap` has `tabindex="0"`, `role="region"` and an `aria-label`.

## S5. Demo mode holds no lock
`WUNDERVAULT_MOCK=1` (or `true`) skips `acquireCredential` entirely and serves the five vault tools
with canned replies, so any number of copies can run with no agent name (Glama starts several at
once; before this every copy after the first served only `vault_status`). Demo mode never reaches
the broker (server.ts returns `mockToolResult` before `brokerClient()`). Outside demo mode nothing
changes.

## S6. Release metadata
- package.json, package-lock.json (root), server.json (top + packages[0]) all say 2.0.2.
- server.json `description` (≤ 100 chars) and the two env var descriptions describe 2.0 (broker,
  `wundervault-agent --enrol`), not 1.x (onboard.py, "injected at runtime").
- CI matrix: Node 22 and 24 (engines: `^22.23.4 || ^24.22.1 || ^26.12.1 || >=27`; Node 20 lacks
  `tls.getCACertificates`, which is why CI failed on every push since 2.0.0).
- CHANGELOG.md has a 2.0.2 entry.

## Acceptance checks
A1. On darwin, resolveSudoUser runs exactly `/usr/bin/dscacheutil -q user -a name <user>`, never getent,
    and returns {uid, gid, home} from the real macOS output format.
A2. Linux still resolves via `getent passwd <user>`.
A3. Empty dscacheutil output, a missing tool, uid 0, a first record for another name, and a SUDO_UID
    mismatch each throw; not-root / no SUDO_USER / SUDO_USER=root return null.
A4. Uninstall with launchctl reporting loaded for 4 polls → exit 0, plist removed, 4 sleeps; loaded
    forever → exit 1, "still loaded 15 seconds", plist NOT removed; already gone → no sleep.
A5. A destination and a reason containing U+202E render as `⟨U+202E⟩`; the generated HTML contains no raw
    bidi control anywhere (script included).
A6. Every `.tablewrap` is focusable with a role and label.
A7. Three demo copies started at once with no agent name each list the five vault tools; with the
    lock re-imposed in demo mode, copies list only `vault_status` (the bug).
A8. All tests pass on the build; versions agree in all three files.
