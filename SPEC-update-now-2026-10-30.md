# SPEC — "Update now": the broker updates itself, with the owner's say-so (2026-10-30, rev 2)

Part 1 of 3 that ship TOGETHER in one release (owner 2026-10-30): **U** Update now (this file) ·
**C** service catalogue + named parts · **L** locking names and setups away from our server. U is
first in BUILD order; C and L land in the same release. L's locking engages per account only once
every broker on it reports this version or newer (it rides on U's version reporting).

Built in low-token mode: oai writes the code from this spec, Claude verifies (and reads every line of
`src/updater*.ts`, `src/release-verify.ts`, `src/tar-read.ts`, the stubs and the installer changes).

rev 1 = rev 0 + the design review in `.buildreview-update/round-0-triage.json`.
rev 2 = rev 1 + what building, the real-machine test and review round 1 settled. **Where the
text below disagrees with this list, this list wins:**

- **No per-file list in the record.** `app` is `{url, sha256}`. The archive's SHA-256 is signed and
  checked before it is opened, so its content is already signed; the list was 550 KB for the real
  package (too big to sign through the vault) and added nothing. The reader checks every entry BY
  RULE before writing it (plain files/folders only, `APP_PATH` names, no case-insensitive
  duplicates, nothing under a file, per-file and total caps) and requires `REQUIRED_APP_FILES`.
- **Archive dialects:** POSIX ustar (our packer) and GNU (`ustar  \0`, what nodejs.org ships — found
  against the real node-v22.23.4 archive); a GNU header has no name prefix.
- **Order life is 24 hours** (was 15 min), so a laptop asleep at Update now still gets it. Single use
  (seen list, terminal list, server ids) and forward-only, so a longer life adds no risk. Received/
  working orders with no answer for 2 h become `failed: no answer from the computer`.
- **The order id is chosen by the browser and is the server's id**, sealed inside; a broker refuses an
  order filed under another id. That lets any later broker process (the update restarts it) relay
  the updater's status.
- **Owner POST uses the site's standard one-use passkey check** (`require_passkey_check`, ≤ 5 min,
  spent by this request) plus CSRF — not a challenge bound to the ciphertext. The order is sealed in
  the browser; someone holding the unlocked session could seal any order anyway.
- **Inferred install:** the server may mark an order installed from a reported broker version only
  after 15 min without a real status, and a real result may still replace that guess.
- **Reopen notice:** "Reopen <app> when convenient to use the new version" whenever an agent's
  copy is older than its broker. Gentle and never a required step.
- **The install root is wholly ours** (created by us, refused if it pre-exists unless it is our empty
  skeleton from an interrupted first run; installer and updater are its only writers). Uninstall
  removes it and the spool entirely; launchers are restored.
- **Windows request.json:** the broker gets Read + Write + Synchronize (Node opens O_WRONLY as
  GENERIC_WRITE) and still no Delete, ChangePermissions or TakeOwnership. Descriptor files are
  replaced with File.Replace / File.Move, never Move-Item.
- **Installer and updater share `state/lock`** (POSIX), created with its content atomically.
- **Release order:** the site's `LATEST_MCP_VERSION` moves only after `release.json` and
  `release.json.sigs` are uploaded, so the vault never offers a version that can't be verified.
- **Durable terminal list** `state/orders.json`; a `rollback failed` is committed (no retry loop);
  every extracted file and folder is fsynced before the switch; the updater sets umask 022.
- **The updater must recognise itself as the program when started through the `current` link**
  (systemd/launchd/tasks do exactly that): compare real paths. Found on the real machine.


## Why

Owner, 2026-10-30: "Our complexity already jumped … when we added the sudo setup for broker." The
2026-09-15 decision accepted **one** admin step per computer, at install. Today every update is two
sudo commands plus reopening every agent app.

## Steps for the person (the yardstick — this build must not add any)

| | Today | After this release |
|---|---|---|
| Update | `sudo npm install -g …@latest` · `sudo sh …/install-daemon.sh` · quit and reopen every agent app | In the (open) vault: **Update now** → one passkey touch. If the vault is locked, the usual unlock comes first. Reopen agent apps only when the vault says an app's copy is two or more versions behind. |
| Getting there | — | One last update the old way (the two sudo commands). |
| Node version | must match the floor on every update | Linux/macOS: the broker and the MCP front run on the Node that comes with the update (from the first Update now on). Windows: the front still starts through the system Node, but only to hand over (any Node 18+ will do). |
| Install | unchanged in this release (installers are a later build) | unchanged |
| Publisher (owner) | tag + CI | tag + CI + **one vault approval per release** (signing the release record) |

## The design in one paragraph

A root-owned install root holds versioned copies (`versions/<v>/`) and ONE descriptor of which
version runs. A small **updater** runs as root on a timer and does nothing unless the broker has
left a request. The owner presses **Update now**; the browser seals the order with a vault key the
broker holds, and our server relays it. The broker checks the order and writes a one-line request.
The updater fetches that version's **release record**, checks its signature with keys built into the
root-owned code it is running, downloads each file named in the record and checks its SHA-256 before
use, writes a new version folder with its own strict reader (no system `tar`, no links ever
created), journals the switch, switches the descriptor, restarts the broker, and rolls back if the
new broker can't open its store within 60 s. Forward only, enforced by a durable high-water mark.

## Threat model (what each party can and cannot do)

- **An agent (runs as the person's account):** can't write any code folder, the request file, the
  updater's files, the task/unit definitions, or seal an order. Unchanged from today.
- **Our server, storing and relaying:** can't seal an order or make a release record verify; it can
  withhold orders or statuses (denial of service only). **Caveat, stated as such everywhere:** our
  server also serves the vault page's code. A server that changed that code could seal an order —
  exactly as it could already read secrets as you unlock. Even then an order can only move a broker
  to a REAL, NEWER, SIGNED release. The release signature, not the order, is what stops bad code.
- **npm, GitHub, nodejs.org, a network attacker:** can't make a downloaded file pass (every file's
  hash is in a signed record; signatures are checked with keys in already-installed root code).
- **Build infrastructure (GitHub Actions):** NOT trusted for the app files. Before signing, the
  record tool rebuilds the app files locally from the tag and requires byte-identical results to
  CI's (U6). Node's hashes are taken from `SHASUMS256.txt` only after its signature checks against
  Node's release keys pinned in the repo.
- **The broker account, if taken over:** can request an update, but only to a signed version above
  the high-water mark. It can't write code, can't choose files, can't delete or replace the request
  file, can't edit the tasks/units, and can't make root follow a link (U4). It must not gain root or
  run code as the person's account through this feature. (The 2.0.3 lesson: broker → root through a
  reinstall was live.)
- **`sudo npm install -g` itself** is unsigned root code execution. It is the trust customers
  already place in npm; this release needs it ONE last time and then stops asking for it. U3 is a
  convenience (an old habit doesn't put a stale copy in front), not a security boundary.
- **The release key:** private half only in the owner's vault (ed25519 signing key, "Asks me first").

## U1 — Layout

| | Linux | macOS | Windows |
|---|---|---|---|
| Install root (root/SYSTEM-owned; others read+execute) | `/opt/wundervault` | `/opt/wundervault` | `%ProgramFiles%\Wundervault` |
| A version | `versions/<v>/app/` (package files, `node_modules/` with no links) + `versions/<v>/node` (`node.exe`) | same | same |
| THE descriptor of what runs | `current` → symlink to `versions/<v>` (replaced by atomic rename) | same | `bin\active.cmd`: exactly two lines `set "WV_NODE=<full path>"` / `set "WV_APP=<full path to versions\<v>\app>"` (replaced by atomic `MoveFileEx(REPLACE_EXISTING)`) |
| What the broker/updater tasks run | unit/plist name `current/node` + `current/app/dist/<entry>.js` | same | tasks run `bin\broker.cmd` / `bin\updater.cmd`, which `call active.cmd` then run `%WV_NODE% %WV_APP%\dist\<entry>.js` |
| Wrappers for agents | `bin/wundervault-mcp`, `bin/wundervault-agent`: sh that resolves `current` ONCE (`readlink`) and execs that version's `node` + entry by explicit path | same | `bin\wundervault-mcp.cmd`, `bin\wundervault-agent.cmd` via `active.cmd` |
| Durable state (root-only, 0700 / SYSTEM+Admins) | `state/journal.json`, `state/highest.json`, `state/manifest.json`, `state/lock` | same | same |
| Update spool | `/var/lib/wundervault-update/` (root 0755): `request.json` (owner ROOT, mode 0620, group = broker account's group — the broker may write its contents only), `status.json` (root 0644) | same path, root:wheel / group `_wundervault` | `%ProgramData%\wundervault-update\`: dir owner SYSTEM, no rights for the broker on the dir; `request.json` owner SYSTEM, broker granted `FILE_WRITE_DATA`+`FILE_READ_DATA`+`SYNCHRONIZE` ONLY (no DELETE, WRITE_DAC, WRITE_OWNER, FILE_APPEND_DATA is fine either way); `status.json` Users read |

- The broker can't create, rename, delete or re-permission anything in the spool or install root.
- `versions/` keeps current + the previous two (fronts that weren't reopened may still run them);
  at most one failed version is kept, for diagnosis, until the next success.
- Platforms: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win-x64, win-arm64, chosen from the
  running updater's `process.platform`/`process.arch`. Anything else → status `failed: platform`.
- Units/plists/tasks carry no environment variables; the updater sets its cwd to the install root and
  runs children with a fixed minimal environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`; Windows:
  `SystemRoot`, `PATH=%SystemRoot%\System32`). The updater refuses to run if `NODE_OPTIONS`,
  `NODE_PATH`, `NODE_EXTRA_CA_CERTS` or `NODE_REPL_EXTERNAL_MODULE` is set.

## U2 — Getting there: the one last sudo update (installers, all three)

Run as today (`sudo npm install -g @wundervault/mcp-server@<this version>` then the installer):

1. Everything checked today still holds (root-only chain of the npm copy, Node floor, accounts).
   **It downloads nothing** — no network call in the installer or anything it runs (U-check 3).
2. Refuses an existing install root that has no `state/manifest.json` written by us (never adopts or
   later deletes something it didn't make).
3. Copies the npm package into `versions/<v>/app/` (root-owned, dropping `node_modules/.bin` and
   refusing any other link), and makes `versions/<v>/node` name the system Node it validated
   (Linux/macOS: symlink to its full path; Windows: `active.cmd` names it). Bundled Node arrives with
   the first Update now.
4. Writes the descriptor, `highest.json` (= this version), the spool, the units/plist/tasks (U4),
   then records everything it created or replaced (with the replaced thing's original target) in
   `manifest.json`.
5. Linux/macOS: replaces the `wundervault-mcp` / `wundervault-agent` launchers the npm copy installed
   (the files at the paths it found) with symlinks to `/opt/wundervault/bin/…`, recording the
   originals in the manifest. Windows: changes no PATH; the npm shims start the U3 stub, which hands
   over.
6. Restarts the broker as today and checks it with the management `ping` (U5).
7. Re-run is safe. `--uninstall` removes only what the manifest lists, puts replaced launchers back
   as they were, keeps the broker's secrets (its state dir) unless `--remove-data` is also given.

## U3 — The npm copy steps aside (startup stubs)

`package.json` `bin` entries point at NEW extensionless stubs `bin/wundervault-mcp` and
`bin/wundervault-agent` (a `bin/package.json` says `"type":"commonjs"`): CommonJS, ES2018 syntax,
requiring only `fs`, `path`, `child_process`, `url`, `os`, and nothing from the app. Run on Node 18+.
The unit/plist/tasks and the install-root wrappers also start the broker and the front THROUGH the
version's own stub (`<v>/app/bin/wundervault-agent`), so `process.argv[1]` keeps the names
`agent.ts` and `launcher.ts` already recognise. A stub:
- if it is already running from inside the install root, `require`s/imports the real entry;
- else, if the descriptor exists and passes the root-only chain check (a self-contained copy of
  `launcher.ts`'s `rootOnly`, ACL check included), runs that version's node + entry (explicit paths
  resolved once) with the same args, env and stdio, forwards signals, and exits with its code;
- else runs the real entry from its own package (today's behaviour, including the Node-floor check).

## U4 — The updater (runs as root)

Files: `src/updater.ts` (flow), `src/release-verify.ts` (record + signature + hashes; also used by
the tooling), `src/tar-read.ts` (reader). Entry `dist/updater.js`.

- **Schedule:** Linux `wundervault-update.timer` (`OnBootSec=60`, `OnUnitInactiveSec=60`) +
  `wundervault-update.service` (Type=oneshot, root, `TimeoutStartSec=15min`, ExecStart via `current`);
  macOS LaunchDaemon `com.wundervault.update` (root, `RunAtLoad`, `StartInterval` 60, `ExitTimeOut`);
  Windows task `wundervault-update` as SYSTEM: at startup + every minute, run whether or not anyone is
  logged on, not stopped on battery, execution limit 15 min, `MultipleInstances=IgnoreNew`, task
  object writable only by SYSTEM/Administrators.
- **Lock:** `state/lock` created exclusively with this process's pid + start time; a lock whose pid
  isn't alive (or is older than 20 min) is broken. One run at a time.
- **Resume first:** if `journal.json` shows a switch not yet committed (e.g. power cut), finish it:
  run the health check; pass → commit; fail → roll back. Then continue.
- **Each run, given no journal to resume:**
  1. Open `request.json` without following links (O_NOFOLLOW; Windows: refuse a reparse point), fstat
     the handle: regular file, expected owner, one link. Read at most 4097 bytes FROM THE HANDLE;
     more than 4096 → `refused: request file`. Empty → exit quietly.
  2. Parse strictly `{"version":"X.Y.Z","order_id":"<1–64 of [A-Za-z0-9_-]>"}` and nothing else.
     Malformed → exit quietly (a half-written file is retried next tick; three consecutive malformed
     ticks → `refused: request`).
  3. If `status.json` already holds a terminal state for this `order_id`, exit (never repeat an order).
  4. Version must be > `highest.json`. Equal to the running version → `installed`. Otherwise
     `refused: older version`.
  5. Free space: refuse (`failed: disk space`) under 600 MiB free in the install root.
  6. Fetch `release.json` and `release.json.sigs` for that version (U6 URLs): HTTPS only, ≤ 64 KiB
     each, 30 s, redirects only within the U6 hosts. Verify (release-verify.ts): at least one
     signature by a key in `src/release-keys.ts` of the RUNNING code; record format exact; version ==
     request; every URL on the U6 hosts; every `sha256` 64 hex; every file name in the app list
     matches `^[A-Za-z0-9@][A-Za-z0-9@._+-]{0,99}(/[A-Za-z0-9@][A-Za-z0-9@._+-]{0,99}){0,15}$`, no
     segment `.`/`..`, no duplicates (case-insensitively), total ≤ 20,000 files.
  7. Download the app archive and this platform's Node file into a fresh root-only temp dir inside
     the install root (≤ 200 MiB each, 10-minute total budget), check SHA-256 against the record
     BEFORE parsing.
  8. Build `versions/<v>.staging` with `tar-read.ts`, never the system `tar`:
     - reads ustar only (+ skips pax `x`/`g` headers, using their `path` if present); gzip via zlib
       with a decompressed-size cap (300 MiB) and an entry-count cap;
     - accepts entry types regular file and directory ONLY; anything else (symlink, hard link, device,
       FIFO, GNU long-name) → the whole update fails;
     - every path is checked against the record's list (app) or equals the one expected member (Node:
       `node-v<N>-<platform>/bin/node`), then written under the staging dir with
       `O_CREAT|O_EXCL|O_NOFOLLOW`, directories created by us with `mkdir` (nothing in staging was
       made by anyone else, so there is nothing to follow);
     - the extracted app tree must equal the record's file list exactly (no missing, no extra), and
       each file's SHA-256 must match the list's;
     - modes: dirs 0755, files 0644, `node` 0755; owner root.
     Windows Node: the record names `win-<arch>/node.exe` directly (no archive).
  9. Self-test the NEW version before switching: `<new>/node <new>/app/dist/updater.js --self-test`
     (loads its keys, verifies a built-in sample, exits 0; 30 s cap). Fail → `failed: self-test`.
  10. Journal (`journal.json`, written via temp file + fsync + rename): `{phase:"switching", from, to,
      order_id, at}`. Rename staging → `versions/<v>`. Switch the descriptor (atomic). Journal
      `phase:"switched"`. Restart the broker by full path (`/usr/bin/systemctl restart
      wundervault-agent.service` or `/bin/systemctl`; `/bin/launchctl kickstart -k
      system/com.wundervault.agent`; Windows `%SystemRoot%\System32\schtasks.exe /End` then `/Run`),
      each with a 60 s deadline.
  11. Health, within 60 s: the management `ping` answers with `version` == new AND `store_ok: true`. Pass → `highest.json` = new, journal `committed`, prune (U1), status
      `installed X.Y.Z`. Fail → descriptor back to `from`, restart, health check that too: pass →
      `rolled back: <reason>`; fail → `rollback failed: <reason>` (the vault shows the repair steps).
- **Status** (`status.json`, root writes via temp+rename in the root-owned spool, everyone reads):
  `{"order_id","state":"working|installed|rolled back|rollback failed|refused|failed","version",
  "detail","at"}`; detail ≤ 200 chars from a fixed set of messages plus numbers/versions, never text
  the broker wrote.
- Every external program by full path, spawned with an argument array (no shell), minimal env, a
  deadline, and its whole process tree killed on timeout.
- The management socket is reached by its fixed path; the reply is read with a 64 KiB cap.

## U5 — The broker's part (src/agent.ts + new src/broker-update.ts)

- **`ping`** (management socket) already answers `version` (the broker's version) and
  `store_unreadable`; it gains `store_ok` (true only once the store has been opened and an agent
  profile decrypted, or there are no agents yet and the store key loads). Health = `version` == new
  AND `store_ok`.
- **Poll** our server every 5 minutes (unref'd timer, first at +30 s): `GET` pending orders for this
  broker, authenticated exactly like the broker's other server calls, sending its `broker_version`.
- **Open an order:** AES-256-GCM with the vault key of the agent it names (one this broker holds);
  AAD = `wv-broker-order-v1|<broker fingerprint>`. Plaintext:
  `{"v":1,"type":"update","broker":"<fingerprint>","version":"X.Y.Z","order_id","issued_at","expires_at"}`.
  Refuse unless it decrypts; `broker` is this broker; not expired (≤ 15 min life, ≤ 2 min skew);
  `order_id` unseen (last 100 kept in the broker's state); version > its own; and `order_id` equals the
  id the server filed the order under (the browser chooses it, so a broker restarted by the update
  can still relay the updater's status for it).
- **Hand over:** truncate + write `request.json` in place. **Relay** `status.json` changes to our
  server (fixed states; the detail passed through ≤ 200 chars).
- **Store compatibility rule** (applies to every future release): a release may only change the
  broker's on-disk format if the previous release can already read the new format. This is what makes
  rollback safe without root ever writing into the broker's state.

## U6 — Releases

- **Record** `release.json` (canonical JSON, UTF-8, no trailing newline):
  `{"format":"wundervault-release-1","version":"X.Y.Z",
  "app":{"url","sha256"},
  "node":{"version":"N","linux-x64":{"url","sha256","member":"node-vN-linux-x64/bin/node"},
  "linux-arm64":…,"darwin-x64":…,"darwin-arm64":…,"win-x64":{"url","sha256"},"win-arm64":…},
  "notes_url"}` (Node: official `.tar.gz` on Linux/macOS, the standalone `node.exe` on Windows).
- **Signatures** `release.json.sigs`: JSON array of `{"key_id","sig"}` (base64 ed25519 over the record's
  exact bytes). Valid if any signature is by a key in the running code's `src/release-keys.ts`.
  **Rotation:** a new key is added to `release-keys.ts` in a release signed by the old key; releases
  are then signed by BOTH keys for at least 6 months before the old key's signature is dropped. A
  broker offline for longer, or a stolen key, is repaired the old way (the sudo update). Release
  builds fail in CI if `release-keys.ts` holds a key marked `test`.
- **App archive** `wundervault-app-X.Y.Z.tar.gz`, built by `scripts/pack-app.mjs` (our own
  deterministic writer: ustar, sorted entries, mtime 0, uid/gid 0, modes normalised, gzip header with
  no name/mtime): `app/package.json`, `app/dist/**`, `app/node_modules/**` (from `npm ci
  --omit=dev --ignore-scripts`, `.bin` removed), `app/README.md`, `app/CHANGELOG.md`,
  `app/packaging/**`. CI fails if the closure has a `.node` file, an install script, a link, or a
  dependency with `os`/`cpu` restrictions (it must be pure JS).
- **Where:** GitHub release assets of the MCP repo (`release.json`, `release.json.sigs`, the app
  archive); Node from `https://nodejs.org/dist/vN/`.
- **Hosts allowed:** `github.com`, `objects.githubusercontent.com`,
  `release-assets.githubusercontent.com`, `nodejs.org`.
- **Tooling:** `scripts/release-record.mjs` — downloads CI's app archive, REBUILDS it locally from
  the tag and requires identical bytes; fetches Node's `SHASUMS256.txt` + `.sig` and checks them with
  `gpg` against Node release keys pinned in `packaging/node-release-keys/`; prints the record for
  signing. `scripts/verify-release.mjs` checks a record + signatures + files with release-verify.ts.
  Signing: `vault_sign` with the "Wundervault release key" (owner approves), appended to
  `release.json.sigs`, uploaded with `gh release upload`.

## U7 — Our server and the vault page (burnbox)

- **Table** `broker_orders`: id, user_id, broker_fingerprint, agent_id (whose key sealed it),
  ciphertext, nonce, ciphertext_sha256, created_at, fetched_at, state, detail, state_at.
  `broker_keys` gains `broker_version` + `version_seen_at` (set from the poll).
- **Owner, one touch:** the vault (already unlocked) seals the order, computes `ciphertext_sha256`,
  asks the server for a challenge bound to (broker fingerprint, version, ciphertext_sha256), gets one
  passkey assertion over it, and posts ciphertext + assertion to `POST /dashboard/brokers/<fp>/orders`
  (session + CSRF). The server verifies the assertion with its existing passkey verification, that
  the challenge is ≤ 2 minutes old, unused (single use), and bound to exactly what was posted. One
  pending order per broker (a new one replaces it).
- **Broker:** `GET /agent/broker/orders` (broker-authenticated, reports `broker_version`),
  `POST /agent/broker/orders/<id>/state` (fixed states only).
- The server never reads, builds or changes an order's plaintext.
- **Vault page:** each computer/broker shows its version. Behind the latest release → "Update
  available — X.Y.Z", what's new, **Update now**. Then "Updating…" → "Up to date" / "Rolled back:
  <detail>" / "Couldn't update: <detail>" / "Rollback failed" + the repair steps (the sudo update).
  An agent app whose MCP copy (`mcp_version`) is two or more versions behind its broker shows "Quit
  and reopen <app>". A broker that hasn't reported a version (older than this release) shows the old
  two-command steps, once.
- `/install#update`, the changelog's MCP tab, `_mcp_update_steps.html`: from this version on, update
  from your vault; the two commands remain for brokers older than this release.

## Out of scope (later builds)

One-download installers (.pkg/.msi), automatic updates without a press, downgrades, fleet canaries
(the owner's own machines update first by pressing first), emergency withdrawal beyond lowering the
server's "latest" (machines already updated move forward with a fix release).

## Acceptance checks

1. A fresh Linux install of this version, then an order for a newer signed TEST release, ends with
   the descriptor → the new version, the broker running it with `store_ok`, `status.json`
   `installed`, and no command run by the person after pressing Update now.
2. Same on a real Mac and on win199.
3. The one-last-sudo installer, run over a 2.1.0 install, keeps pairing, agents and the store key
   working, runs the broker from the install root, and makes no network connection: on Linux, run
   under `strace -f -e trace=connect` and assert no AF_INET/AF_INET6 connect; on all three, the
   installers and stubs contain no downloader (`curl`, `wget`, `Invoke-WebRequest`, `fetch`,
   `https.get`).
4. Agent apps that launch `wundervault-mcp` by bare name, or by the npm launcher's full path, run the
   install root's copy after U2 (Linux/macOS by the replaced launcher; Windows via the stub), with no
   change to their configuration.
5. After U2, `sudo npm install -g @wundervault/mcp-server@<this version or newer>` does not change
   which version agents or the broker run.
6. The stub runs and hands over on Node 18, 20, 22 and 24.
7. An order sealed for broker A is refused by broker B.
8. An order with one ciphertext byte changed, an expired order, and a replayed `order_id` are each
   refused; no request is written.
9. A request at or below `highest.json` installs nothing — including after a rollback and after an
   installer re-run.
10. (rev 2: entries are checked by rule, not against a list.) With CORRECTLY SIGNED test fixtures (a test key compiled into a `-test` build): a record whose
    version differs from the request, an archive with a symlink / hard link / device / `..` path /
    absolute path / duplicate path / unlisted file / missing file / wrong per-file hash, a Node
    archive without the expected member, and a URL off the U6 hosts each end `failed`/`refused`
    with the descriptor unchanged, nothing written outside staging (checked by a sentinel file
    outside), and staging removed. With an unsigned record or one signed by an untrusted key, the
    same.
11. `request.json` replaced by a symlink, a directory, a 2-link hard link, a file with another owner,
    a file over 4096 bytes, and a file that grows/truncates while read → `refused: request file`, and
    root reads nothing through it beyond 4097 bytes.
12. As the broker account (all three systems): can't create, rename, delete or re-permission anything
    in the spool or install root, can't delete `request.json`, can't change the update or broker
    task/unit/plist; CAN write `request.json`'s contents.
13. A new version whose broker never reports `store_ok` with the new version is rolled back within
    ~75 s; the old version runs again, status `rolled back`. A rollback that also fails reports
    `rollback failed`.
14. Power cut simulated after each journal phase (kill the updater, then run it again) leaves either
    the old version committed or the new version committed and healthy — never a mix.
15. Every external program is named by full path: tested with a PATH whose first entry holds hostile
    `tar`, `systemctl`, `launchctl`, `schtasks`, `node`; and with `NODE_OPTIONS` set (updater refuses).
16. `versions/` holds at most three good versions plus at most one failed one after any sequence of
    updates.
17. A request repeated after a terminal status, and an `order_id` already `failed`, are not retried
    (no download happens).
18. Our server can't produce an order a broker accepts (well-formed order sealed with a wrong key is
    refused), and the server code has no path that decrypts one.
19. (rev 2: the site's one-use passkey check.) `POST …/orders` without CSRF, or without a fresh unspent passkey check, is refused; with both it is stored. Superseded text follows: without an assertion, with a stale one (> 2 min), a reused challenge, or an
    assertion bound to a different broker/version/ciphertext is refused; the right one is stored.
20. The vault page shows each broker's version, "Update available" only when behind, the status
    lines in U7 and the "reopen <app>" line, at 320 px wide with no horizontal scroll.
21. A broker older than this release keeps working unchanged with the new server.
22. `--uninstall` removes only manifest items, restores replaced launchers, keeps the broker's state
    unless `--remove-data`; a pre-existing unmanaged `/opt/wundervault` makes install refuse.
23. `scripts/verify-release.mjs` accepts a correct test release and rejects each bad case in check 10,
    through release-verify.ts; `scripts/pack-app.mjs` run twice gives identical bytes.
24. The MCP test suite passes on Node 22 and 24 against BOTH the source build and the packed app
    (unpacked by tar-read.ts); the touched site e2e suites pass.
25. An MCP front two versions behind its broker keeps working for every existing tool
    (`vault_entries_list`, `vault_call`, `vault_pay`, `vault_sign`, `vault_ssh_exec`, `vault_status`).
26. "Steps for the person" holds: nothing new for the person beyond Update now and one passkey touch
    (plus the usual unlock if locked); the owner's extra step is one vault approval per release.
