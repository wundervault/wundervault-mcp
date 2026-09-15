# Review package — round 14
generated 2026-09-15T20:25:53+00:00

## Spec — judge the build against THIS

# SPEC — phase 4, the uid split (Linux)

Everything in phases 1–3.5 is careful handling. This is the phase that makes it a
boundary.

Today the daemon runs as the same uid as the agent it serves. So the agent can read the
daemon's key files, read its memory through `/proc/<pid>/mem`, edit the record of where it
sent secrets, and replace the binary. Every claim made so far is true only against an
agent that does not try. That is worth something — most failures are accidents, not
attacks — but it is not what "the key never reaches the agent" sounds like.

**Accepted by the owner, 2026-09-15: one `sudo` per machine at install.** Enrolment stays
unprivileged — authorised by a setup link from the website, not by local privilege.
Reading the destination store is the one exception and does need sudo (D3).

## A. What actually changes

| | before | after |
|---|---|---|
| daemon uid | the user's | `wundervault` system account |
| key material | `~/.wundervault/agent-profiles.enc` | `/var/lib/wundervault/`, 0700 |
| destination store | `~/.wundervault/network.json` | `/var/lib/wundervault/network.json` |
| unit | `systemctl --user` | system unit |
| enrolment | the installer WRITES the profile store | the daemon redeems a server-issued setup link |
| agent's identity | a token in a file the agent owns | unchanged — and now load-bearing |

## B. Enrolment is authorised by the server, not by the machine

`onboard.py` used to derive the machine key and write `agent-profiles.enc` itself. After
the split that directory is not writable by the user, so enrolment had to become a request
to the daemon. The first version of that took a profile from whoever asked — and **that is
unfixable with local permissions**, because agents run as the machine's owner. The kernel
cannot separate the owner's shell from a process running as the owner, so any lock the
owner can open, an agent can open. An agent could register a name with a token it chose
and then read that agent's credentials from its own socket.

What the owner has that an agent does not is something from **outside the machine**: a
setup link, issued by the server to a person logged in to the website. So the daemon
redeems the link itself.

- B1. The only way a profile enters the daemon is `enrol`, carrying a setup link. There is
      no `register_profile`. Not guarded — absent.
- B2. The daemon performs the exchange: `GET /api/setup/agent/<token>`, PBKDF2-SHA256 over
      the fragment passphrase (salt `wv-agent-setup-v1`, 100,000 rounds), AES-256-GCM, then
      `POST .../burn`. The credentials never enter the calling process — an improvement on
      the pre-split world, where `onboard.py` held them in plaintext as the user.
- B2a. **The ORIGIN is the security property.** A link is accepted only from an origin in
      the daemon's own configuration (`WUNDERVAULT_SETUP_ORIGIN`, default
      `https://wundervault.com`), set by the unit file and not by the caller. Accepting any
      https origin — or http on loopback, for the convenience of a test — lets an agent run
      its own server, serve a blob it encrypted with a passphrase it chose, and mint the one
      credential this design assumes it cannot obtain. Every cryptographic check passes in
      that attack; only the origin refuses it.
- B2b. The link is read from **stdin, never argv**. `/proc/<pid>/cmdline` is world-readable,
      so a link on the command line is visible to every agent for as long as the command
      runs, and redemption is not instantaneous.
- B2c. Redirects are refused (`redirect: 'error'`) — the token is a bearer credential in the
      URL path — and a non-JSON content-type is refused rather than parsed.
- B3. Single-use and time-boxed are enforced server-side and are not re-derived here. The
      link is valid for 15 minutes.
- B4. The burn happens **after the profile is stored**, not merely after a successful
      decrypt. Anything that can fail in between — a missing socket token, a disk error —
      would otherwise spend a single-use link and produce no agent.
- B4a. One enrolment per connection. The handler re-parses on every `data` event, so
      without this a caller could send one valid line and then dribble bytes, re-running a
      100,000-round PBKDF2 and a fetch on each one, on the event loop every agent shares.
- B5. Migration is the same path. **Repair** in the dashboard rotates an agent's
      credentials and issues a fresh setup link while keeping its identity and every vault
      grant, so moving a pre-split agent across is: repair, then `--enrol`. No credential is
      carried, and no special case is carved for migration.
- B6. Removing an agent is authorised by that agent's own token. The socket is connectable
      by anyone, so an unauthenticated remove would let any local user delete another's
      agents.

## C. Peer identity: the token, and what it is not

Node exposes no `SO_PEERCRED`, and a native addon would put a compiled binary inside a
package whose whole pitch is that you can read it. So identity is the per-agent token in
`~/.wundervault/agents/<name>.token`, 0600, owned by the agent's uid.

- C1. The sockets are world-connectable, because the daemon is now a different uid and a
      0600 socket it owns could not be reached by the agent at all. **This includes the
      management socket.** It sat behind a 0770 directory until that was shown to lock the
      owner out too — the installer's own closing instruction, `--migrate` with no sudo,
      could not open the door it had just locked, and adding the owner to the group would
      have added all seven of their agents. Nothing behind that socket is protected by
      being hard to reach; each action carries its own proof.
- C2. Compared in constant time. A wrong token closes the connection without saying
      whether the agent name exists.
- C3. A wrong token costs the **failing caller** an exponential delay, and a valid token is
      always served. The first design locked out the agent NAME after ten failures and
      checked that before comparing the token, so any local process could take the real
      agent off the air for a minute at a time, indefinitely. A per-connection absolute
      deadline bounds resources instead; there is deliberately **no `maxConnections`**,
      since a ceiling is itself a way to exclude the legitimate agent.
- C4. **Honest limit:** `SO_PEERCRED` reports PID, UID *and* GID — so the token is slightly
      weaker than the kernel check, not equivalent: it proves possession of a file, and any
      process that can read that file presents the same identity. At uid granularity the
      two coincide, which is the granularity we claim.
- C5. One uid is one principal. Two agents under one uid cannot be told apart — by us or by
      the kernel. Seven agents currently run under one uid on the owner's machine, so this
      is the live case, not a corner. **Everything in B follows from this.**

## D. What the split actually buys, stated so it can be checked

- D1. The agent's uid cannot read `/var/lib/wundervault`. Enforced by mode 0700 on a
      directory owned by another user.
- D2. The agent cannot read the daemon's memory. Enforced by uid separation: `ptrace` and
      `/proc/<pid>/mem` require the same uid or `CAP_SYS_PTRACE`.
- D3. The destination store becomes an **integrity control**, not merely privacy. Until
      now the party being audited owned the evidence. It is therefore **not served over the
      management socket** — that socket is connectable by every agent, and one agent
      reading where the others sent secrets is the leak the store exists to expose.
      `--destinations` reads the file as root.
- D4. **`LimitCORE=0` does NOT make a process non-dumpable** — correcting the plan's B1
      bullet. It prevents a core file being written; it does nothing about `ptrace`. D2 is
      what prevents memory reading, and it is the uid, not the unit file, doing the work.
      The unit setting is defence against a crash dump landing on disk, and should be
      described as that.
- D5. The at-rest encryption of the profile store is **defence in depth, not the
      boundary**. Its key derives from the machine id, the uid, and a salt file stored
      beside the ciphertext — so anyone who can read the directory can recompute it. The
      directory mode is the control. Saying otherwise would repeat the mistake this phase
      exists to correct.

## E. The unit

- E1. A **system** unit, `User=wundervault`, `Group=wundervault`.
- E2. `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `ProtectSystem=strict`,
      `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictSUIDSGID=yes`,
      `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `MemoryDenyWriteExecute=yes`,
      `LockPersonality=yes`, `ProtectProc=invisible`, `LimitCORE=0`.
- E3. `ReadWritePaths=/var/lib/wundervault` and nothing else writable.
- E4. `RuntimeDirectory=wundervault` so the socket directory is created and cleaned up by
      systemd rather than by our code guessing at `/run`.
- E5. The daemon must refuse to start as root. A daemon that keeps root because the unit
      was edited is worse than one that never had it.

## F. Migration

- F1. Migration carries **no credentials**. The pre-split store is read only for the list
      of agent names, so the owner can be told which agents still need repairing. Repair
      invalidates the old credentials server-side, so the pre-split copy is worthless as
      soon as an agent is across.
- F2. The old `systemctl --user` unit is disabled and removed, or two daemons fight over
      one agent name and the loser's socket wins by being last to bind.
- F3. The user's `~/.wundervault/agents/<name>.token` STAYS, and migration must PRESERVE
      its value. Repair rotates the vault credentials; the socket token is a separate local
      identity, and replacing it would lock out any agent process that read it at startup —
      refused by the daemon that had just enrolled it, with 'unauthorized' as the only clue.
- F4. The old `agent-profiles.enc` is deleted once every agent is across — refused while
      any are pending, since an un-repaired agent's only credentials are in it.
- F5. Migration is idempotent and re-runnable.

## G. Install

- G1. One privileged step, doing only: create the system user, install the unit, create
      `/var/lib/wundervault`, enable the service.
- G2. **Not `curl | sudo sh`.** The product's differentiator is a verifiable installer;
      piping unverified network content into root contradicts the pitch.
- G3. **`dpkg` does not verify a downloaded `.deb`** — correcting the plan's B1 bullet.
      Package signing verifies a *repository*; a file fetched over HTTPS and installed with
      `dpkg -i` is verified by nothing but TLS. Either ship a repo, or verify a detached
      signature explicitly before installing, the way `onboard.py` already does.
- G4. The privileged step is printed in full before it runs, and is re-runnable.

## Acceptance checks

1. The daemon refuses to start as root.
2. Running as `wundervault`, the agent's uid cannot read `/var/lib/wundervault`.
3. An agent with a valid token connects and retrieves its credentials.
4. An agent with a wrong token is refused, and the refusal does not reveal whether the
   name exists.
5. A valid token is served even while another caller is flooding that socket with wrong
   ones, and the wrong ones are the only party that pays.
6. Enrolment with a valid setup link creates a usable profile, and the credentials never
   enter the calling process.
7. There is no way to enrol without a setup link. `register_profile` does not exist.
8. A used, expired or mistyped link is refused, and a wrong passphrase does not burn it.
9. The owner can reach the management socket with no group membership and no sudo.
10. `--migrate` names the agents still to be repaired; `--migrate --finish` refuses while
    any remain.
11. The destination store lives under `/var/lib/wundervault`, the agent's uid cannot write
    it, and it is not served over the management socket.
12. `--destinations` refuses rather than showing an empty page to a user who cannot read
    the store, and names sudo as the way through.
13. The unit file contains every hardening directive in E2.
14. Nothing in the codebase resolves daemon state through `os.homedir()` any more.
15. The installer refuses an `ExecStart` under a home directory, symlinks resolved.
16. Removing an agent requires that agent's token.
17. A setup link from any origin but the configured one is refused, including a server the
    caller started on loopback.
18. The setup link never appears in `argv`.
19. A failure after redemption does not burn the link, and one connection cannot trigger
    more than one enrolment.
20. `--destinations` is dispatched by the binary every message names, and does not refuse
    to run as root.

## Out of scope

- macOS (phase 4b) and Windows (phase 4c).
- The key-hierarchy migration (phase 5). This phase moves ciphertext; it does not re-wrap
  it.
- Server-side enforcement of `entry_mode` (phase 6), which needs the daemon to hold an
  identity of its own.


## What was built this round, and how it was tested

ROUND 14 — fixes for round 13. Read .buildreview/round-13-triage.json first and do not
re-raise anything there without new evidence. All seven findings were confirmed against
the code; none were rejected.

WHAT CHANGED:
- F1 (the bad one, and it was mine): the daemon trusted ANY https origin plus http on
  loopback — an exception I added so a test could run a real server. That let a malicious
  agent stand up its own listener, serve a blob it encrypted with a passphrase it chose,
  and mint the very credential the design assumes an agent cannot get. Every crypto check
  passes in that attack. Now: an origin allowlist read from the DAEMON's environment
  (WUNDERVAULT_SETUP_ORIGIN, default https://wundervault.com), set by the unit file and
  not influenceable by the caller. Test stands up a real rogue server and asserts refusal,
  plus a lookalike-host case.
- F2: the link is read from STDIN, never argv. /proc/<pid>/cmdline is world-readable.
- F3: socket_token is validated BEFORE redemption, and the burn is handed back to the
  caller and invoked only after registerProfile succeeds.
- F4: enrolment RESTORES an agent's existing socket token (new `set_socket_token` action,
  authorised by the token just set) so a running agent is not locked out by migration.
- F5: one enrolment per connection — the handler used to re-run on every data chunk.
- F6: the old unit FILE is now removed, not just disabled. The shred is deliberately kept
  unconditional at --finish: reaching it means every agent was repaired, so those
  credentials are already dead server-side. Say if you disagree with that reasoning.
- F7: --destinations is now dispatched in agent.ts. It was only in the wundervault-mcp
  binary, while three separate messages told people to run `sudo wundervault-agent
  --destinations`, which fell into refuseRoot.
- Server side: BOTH the create and repair setup links are now 15 minutes via one
  SETUP_TOKEN_TTL_MINUTES constant (they were 24h while claiming 15).

TESTS: 381 passing, no skips.

WHAT I MOST WANT ATTACKED THIS ROUND:
(a) The F4 fix. enrol() mints a token, enrols, THEN discovers the agent name from the
    reply and swaps the token back via set_socket_token. Is that two-step racy or
    abusable? It is the part I am least happy with.
(b) set_socket_token is authorised by the CURRENT token. Reason it through for a case
    where an agent could use it to take over another agent.
(c) The origin allowlist: parsing, normalisation, anything that makes u.origin compare
    equal when it should not.
(d) The stdin read — TTY vs pipe, partial lines, trailing whitespace.
(e) F6 again: is shredding at --finish really safe given every agent was repaired?

STILL NOT DONE: the installer has never been run. No wundervault user, no
/var/lib/wundervault. All tests are same-uid with the split simulated by env vars, so
acceptance checks 1, 2 and 11 are unproven by the suite.

WITHHELD: src/server.ts (67KB) and src/log-viewer.ts — diffs only. burnbox's dashboard.py
is not included; only the TTL change is described.

## File: src/enrol.ts

```
/**
 * Enrolment, done by the daemon instead of by the agent's own process.
 *
 * This is the piece that lets the uid split mean anything. Before it, the management
 * socket accepted `register_profile` from anyone who could reach it — and since agents run
 * as the same user as the person who owns them, "anyone who could reach it" included every
 * agent on the machine. An agent could register a name with a token it chose and then
 * collect that agent's credentials from its own socket. The boundary held for files and
 * memory and leaked at the front door.
 *
 * The fix is not a tighter local permission. There isn't one: the kernel cannot tell the
 * owner's shell from an agent running as the owner, so any lock the owner can open, an
 * agent can open. What the owner has that an agent does not is something from OUTSIDE the
 * machine — a setup link, issued by the server, to a person logged into the website.
 *
 * So the setup link is the authorisation, and the daemon redeems it itself:
 *
 *   https://wundervault.com/setup/agent/<token>#<passphrase>
 *                                        ^path          ^fragment, never sent to a server
 *
 *   1. GET  /api/setup/agent/<token>   -> the encrypted blob
 *   2. PBKDF2(passphrase) -> AES-256-GCM -> api_key + encryption_key
 *   3. POST /api/setup/agent/<token>/burn
 *
 * The client hands over a URL and gets back a name. The credentials exist only inside the
 * daemon and the file it owns — they are never in the address space of the process that
 * asked, which is an improvement on the pre-split world too, where onboard.py held them in
 * plaintext as the user.
 *
 * The parameters below are fixed by what the server already does (see onboard.py, which
 * this deliberately mirrors rather than reinvents). They are not ours to choose.
 */
import crypto from 'node:crypto';

const DEFAULT_ORIGIN = 'https://wundervault.com';

/**
 * Where a setup link is allowed to come from.
 *
 * Read from the daemon's environment, which after the uid split is set by the unit file.
 * That is the point: the caller hands over a URL, but it does not get to say which server
 * is trusted. `WUNDERVAULT_SETUP_ORIGIN` exists for self-hosted installs and for tests,
 * and in both cases it is set by whoever starts the daemon, never by whoever calls it.
 */
export function allowedOrigins(): string[] {
  const configured = process.env.WUNDERVAULT_SETUP_ORIGIN;
  if (!configured) return [DEFAULT_ORIGIN];
  return configured.split(',').map(o => o.trim()).filter(Boolean);
}

const PBKDF2_SALT = 'wv-agent-setup-v1';
const PBKDF2_ROUNDS = 100_000;
const UA = 'WunderVault-Agent-Daemon/1.0';

export interface EnrolledCredentials {
  agent_name: string;
  agent_id: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
}

interface ParsedLink { baseUrl: string; token: string; passphrase: string; }

/**
 * Pull the three parts out of a setup link.
 *
 * The passphrase lives in the URL fragment precisely because browsers never transmit it,
 * so the server stores a blob it cannot itself read. That property is worth preserving on
 * this side of the wire too: it is why the passphrase is never put in a query string, a
 * header, or a log line here.
 */
export function parseSetupUrl(raw: string): ParsedLink {
  let u: URL;
  try { u = new URL(String(raw ?? '').trim()); }
  catch { throw new Error('That does not look like a setup link. Paste the whole URL, including the # at the end.'); }

  // THE ORIGIN IS THE WHOLE SECURITY PROPERTY, so it is checked against an allowlist the
  // caller cannot influence.
  //
  // The first version of this accepted any https origin, plus http on loopback so a test
  // could run a real server. That defeated the entire design in one line: a malicious
  // agent could start its own listener on 127.0.0.1, serve a blob it had encrypted with a
  // passphrase it chose, and hand the daemon `http://127.0.0.1:9999/setup/agent/x#p`. The
  // daemon would decrypt it perfectly, believe it, and register whatever profile the agent
  // named — including overwriting a real one. The "setup link an agent cannot obtain"
  // becomes a setup link an agent can simply mint.
  //
  // So: exactly one origin, from the DAEMON's own environment, which systemd sets and no
  // agent controls. The test override lives there too and is therefore unreachable by a
  // caller — an agent cannot set the daemon's environment any more than it can set its uid.
  const allowed = allowedOrigins();
  if (!allowed.includes(u.origin)) {
    throw new Error(
      `A setup link must come from ${allowed.join(' or ')}. Got ${u.origin}.\n` +
      `A link from anywhere else is not a Wundervault setup link, whatever it looks like.`,
    );
  }

  const m = u.pathname.match(/\/setup\/agent\/([^/]+)\/?$/);
  if (!m) throw new Error('That URL has no setup token in it. Copy the link from the dashboard again.');

  const passphrase = decodeURIComponent(u.hash.replace(/^#/, ''));
  if (!passphrase) {
    throw new Error(
      'That link is missing the part after the #. It is the only thing that can decrypt ' +
      'your credentials, and it is never sent to the server — so a link without it is ' +
      'useless. Copy the whole URL.',
    );
  }
  return { baseUrl: u.origin, token: decodeURIComponent(m[1]), passphrase };
}

async function httpJson(url: string, method: 'GET' | 'POST'): Promise<any> {
  // `redirect: 'error'` rather than the default 'follow'. The setup token is a bearer
  // credential sitting in the URL PATH, so a 302 would hand it to whatever host the
  // response named — and this runs inside the process that holds every agent's
  // credentials. There is no legitimate reason for the setup endpoints to redirect, so
  // refusing is free, and the failure is visible rather than silent.
  const res = await fetch(url, {
    method,
    headers: { 'User-Agent': UA },
    redirect: 'error',
  });
  if (!res.ok) {
    const known: Record<number, string> = {
      404: 'That setup link is not valid. Check you copied all of it.',
      410: 'That setup link has already been used, or it has expired. ' +
           'Repair the agent in the dashboard to get a fresh one — it keeps the agent\'s ' +
           'existing vault access.',
    };
    throw new Error(known[res.status] ?? `The server answered ${res.status} for the setup link.`);
  }
  const ctype = String(res.headers.get('content-type') ?? '');
  if (!ctype.includes('json')) {
    // A captive portal or a proxy answering 200 with an HTML login page would otherwise
    // reach JSON.parse and surface as a confusing syntax error.
    throw new Error(`The setup link did not return JSON (content-type: ${ctype || 'none'}).`);
  }
  return res.json();
}

/**
 * Redeem a setup link.
 *
 * The burn is a separate call AFTER the credentials are decrypted, and that order matters:
 * burning first would mean a wrong passphrase or a network blip consumed a single-use link
 * and left the agent with nothing, forcing another trip to the dashboard. Burning last
 * means the only way to lose the link is to have already succeeded with it.
 */
export async function redeemSetupLink(
  rawUrl: string,
): Promise<{ creds: EnrolledCredentials; burn: () => Promise<void> }> {
  const { baseUrl, token, passphrase } = parseSetupUrl(rawUrl);

  const server = await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}`, 'GET');
  if (!server?.encrypted_blob) throw new Error('The server returned no credentials for that link.');

  // base64url -> base64, then pad. The server emits the URL-safe alphabet.
  let b64 = String(server.encrypted_blob).replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  const blob = Buffer.from(b64, 'base64');
  if (blob.length < 29) throw new Error('The credential blob is too short to be valid.');

  const key = crypto.pbkdf2Sync(passphrase, PBKDF2_SALT, PBKDF2_ROUNDS, 32, 'sha256');
  let plain: Buffer;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    // GCM in this format carries its tag at the END of the ciphertext, the way the Python
    // AESGCM.decrypt() on the other side expects to find it.
    const ct = blob.subarray(12, blob.length - 16);
    decipher.setAuthTag(blob.subarray(blob.length - 16));
    plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error(
      'Could not decrypt those credentials — the part of the link after the # is wrong, ' +
      'or the link was mangled in transit. Nothing has been changed and the link is unused.',
    );
  }

  const raw = JSON.parse(plain.toString('utf8'));
  const creds: EnrolledCredentials = {
    agent_name: server.agent_name ?? 'unknown',
    agent_id: server.agent_id,
    api_key: raw.api_key ?? raw.agent_vault_api_key ?? '',
    enc_key: raw.encryption_key ?? raw.agent_encryption_key ?? '',
    vault_url: baseUrl,
  };
  if (!creds.api_key || !creds.enc_key) {
    throw new Error('The decrypted credentials are missing a key. Repair the agent and try again.');
  }

  // The burn is HANDED BACK rather than done here, so the caller can do it only after the
  // profile is actually stored. Burning at this point consumed the link on any later
  // failure — a missing socket token, a disk error — leaving the owner with a spent link
  // and no agent.
  //
  // It stays non-fatal once called: the credentials are already in hand and filed, and
  // failing an enrolment that has already succeeded because the "mark as used" call timed
  // out would be the worse outcome. A link that stays live for the rest of its fifteen
  // minutes is the smaller problem, and it is logged.
  const burn = async () => {
    try {
      await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}/burn`, 'POST');
    } catch {
      console.error(
        '[wundervault-agent] Enrolled, but could not mark the setup link as used. ' +
        'It stays valid until it expires — repair the agent again if that worries you.',
      );
    }
  };

  return { creds, burn };
}

```

## File: src/migrate.ts

```
/**
 * Move agents enrolled before the uid split onto the system daemon.
 *
 * The first version of this carried credentials. It decrypted the pre-split store, pushed
 * each profile in over the management socket, and shredded the original — which meant the
 * management socket had to accept a profile from whoever asked, and that turned out to be
 * the hole the whole phase existed to close: agents run as the owner, so "whoever asked"
 * included every agent on the machine, and any of them could register a name with a token
 * of its choosing and then read that agent's credentials from its own socket.
 *
 * The product already had the answer. REPAIR, in the dashboard, rotates an agent's
 * credentials and issues a fresh setup link while keeping its identity and every one of
 * its vault grants. So migration is not a data move at all — it is the owner repairing
 * each agent and handing the daemon the link. Nothing here touches a credential.
 *
 * Three things fall out of that, all good:
 *   - No unauthenticated path into the daemon, and no special case carved for migration.
 *   - Repair invalidates the old credentials server-side, so the copy in the pre-split
 *     store is worthless the moment an agent is repaired. Deleting it becomes tidiness
 *     rather than the thing standing between the user and a leak.
 *   - The pre-split daemon, if it is still running, is serving credentials the server no
 *     longer accepts. It should still be turned off, but it is no longer a boundary hole.
 *
 * The old store is read ONLY for the list of names, so the owner can be told which agents
 * still need doing. That read is something the owner could always do; it moves no secret.
 */
import fs from 'node:fs';
import net from 'node:net';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { legacy, mgmtSocketPath } from './paths.js';

/** One request/response over a socket. */
export function ask(payload: unknown, sockPath = mgmtSocketPath(), timeoutMs = 30_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(sockPath);
    let buf = '';
    const done = (fn: () => void) => { clearTimeout(timer); sock.destroy(); fn(); };
    const timer = setTimeout(
      () => done(() => reject(new Error(`timed out talking to the daemon at ${sockPath}`))),
      timeoutMs,
    );
    sock.on('connect', () => sock.write(JSON.stringify(payload) + '\n'));
    sock.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      try { done(() => resolve(JSON.parse(buf.trim()))); }
      catch { done(() => reject(new Error('unparseable reply from the daemon'))); }
    });
    sock.on('error', (e) => done(() => reject(e)));
  });
}

/**
 * The names in the pre-split store.
 *
 * Decrypted with the key the OLD daemon used — the user's uid, the old salt path — which
 * is why this cannot be shared with the daemon's own derivation and is not imported from
 * it. Only the names are returned. The credentials in there are about to be made
 * worthless by repair, and reading them into this process would recreate, for no benefit,
 * exactly the exposure the split removes.
 */
export function legacyAgentNames(): string[] {
  const profilesPath = legacy.profiles();
  if (!fs.existsSync(profilesPath)) return [];

  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();
  const salt = fs.readFileSync(legacy.salt());
  const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;

  const buf = fs.readFileSync(profilesPath);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  const plain = Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
  return ((JSON.parse(plain).profiles ?? []) as { agent_name?: string }[])
    .map(p => String(p.agent_name ?? ''))
    .filter(Boolean);
}

type OldUnit = 'gone' | 'still-running';

/**
 * The unit this stops, and why it is a variable.
 *
 * A test for this called it with the real name and systemctl did exactly as asked: it
 * stopped and disabled the developer's own live daemon. Anything that reaches outside the
 * process has to be redirectable, or a test cannot be written for it without doing the
 * thing for real.
 */
const OLD_UNIT = () => process.env.WUNDERVAULT_OLD_UNIT || 'wundervault-agent.service';

export function stopOldUserUnit(): Promise<OldUnit> {
  return new Promise((resolve) => {
    execFile('systemctl', ['--user', 'disable', '--now', OLD_UNIT()], { timeout: 10_000 }, () => {
      // The exit code is not consulted: `disable` fails on a unit that was never there,
      // which is the good case, and can succeed while the process lives on. Only the
      // liveness check decides, and anything that is not a clear "not active" counts as
      // still running — if we cannot reach the user bus we do not know, and not knowing
      // must not read as success.
      execFile('systemctl', ['--user', 'is-active', OLD_UNIT()], { timeout: 5_000 },
        (_e, stdout) => {
          const state = String(stdout).trim();
          resolve(state === 'active' || state === '' ? 'still-running' : 'gone');
        });
    });
  });
}

/**
 * Delete the pre-split unit file.
 *
 * Disabling stops it now; the file is what starts it again. Leaving it means a reboot
 * brings up a second daemon that binds a socket the client still falls back to, and by
 * then the store it wants is gone — so it comes up serving nothing, loudly, for reasons
 * nobody will connect to a migration run weeks earlier.
 */
function removeOldUnitFile(): void {
  const home = process.env.HOME || '';
  if (!home) return;
  const unit = `${home}/.config/systemd/user/${OLD_UNIT()}`;
  try { if (fs.existsSync(unit)) fs.unlinkSync(unit); } catch { /* best effort */ }
}

export interface MigrationStatus {
  pending: string[];
  across: string[];
  alreadyDone: boolean;
  oldStorePath: string;
}

/** What still needs doing. Reads; changes nothing. */
export async function status(): Promise<MigrationStatus> {
  const oldStorePath = legacy.profiles();
  const ping = await ask({ action: 'ping' }).catch((e) => {
    throw new Error(
      `Could not reach the daemon at ${mgmtSocketPath()}: ${(e as Error).message}\n` +
      `Install it first:  sudo sh packaging/install-daemon.sh\n` +
      `Then check:        systemctl status wundervault-agent`,
    );
  });
  if (!ping?.ok) throw new Error('The daemon answered, but not with ok. Check its logs.');

  if (!fs.existsSync(oldStorePath)) {
    return { pending: [], across: [], alreadyDone: true, oldStorePath };
  }

  const roster = await ask({ action: 'known_agents' }).catch(() => ({ agents: [] }));
  const known = new Set<string>(roster.agents ?? []);
  const names = legacyAgentNames();
  return {
    pending: names.filter(n => !known.has(n)),
    across: names.filter(n => known.has(n)),
    alreadyDone: false,
    oldStorePath,
  };
}

export interface EnrolResult { agent_name: string; agent_id: string; }

/**
 * Hand one setup link to the daemon.
 *
 * The socket token is minted HERE and written to the user's own home, not by the daemon.
 * The daemon must not write into a user's home directory — that access is precisely what
 * this phase removes — and the token is the agent's identity rather than a vault
 * credential, so there is nothing to protect by having the daemon generate it.
 */
export async function enrol(setupUrl: string): Promise<EnrolResult> {
  // A new token is minted only when there is not already one for this agent.
  //
  // Repair rotates the VAULT credentials; the socket token is a separate, local thing —
  // the agent's identity at the daemon's door. Replacing it during migration would lock
  // out every already-running agent process, which read its token at startup: the agent
  // would be refused by a daemon that had just successfully enrolled it, and the only
  // clue would be 'unauthorized'. Reusing it keeps a live agent working across the move.
  //
  // The name is not known until the daemon answers, so the existing token can only be
  // looked up after the fact — hence the two-step: ask once to learn the name, and only
  // then decide. To avoid enrolling twice, the daemon is asked for the name FIRST via the
  // link it has yet to redeem... which it cannot do. So instead: mint, enrol, and if a
  // token file already existed for the returned name, re-enrol with the old value.
  const { agentTokenPath } = await import('./paths.js');
  const path = await import('node:path');

  let socketToken = crypto.randomBytes(32).toString('hex');
  const reply = await ask({ action: 'enrol', setup_url: setupUrl, socket_token: socketToken });
  if (reply?.error) throw new Error(reply.error);
  if (!reply?.ok || !reply.agent_name) throw new Error('The daemon did not confirm the enrolment.');

  // Written only after the daemon has confirmed. Writing first would leave a token file
  // for an agent that does not exist, which reads as a working setup and is not.
  const tp = agentTokenPath(reply.agent_name);

  // If this agent already had a token, put it back. The enrolment above had to send
  // something, and the name was not knowable until the daemon replied — so the existing
  // value is restored now, over the management socket, before anything is written to disk.
  if (fs.existsSync(tp)) {
    const existing = fs.readFileSync(tp, 'utf8').trim();
    if (existing && existing !== socketToken && existing.length >= 32) {
      const put = await ask({
        action: 'set_socket_token', agent_name: reply.agent_name,
        token: socketToken, new_token: existing,
      });
      if (put?.ok) socketToken = existing;
      else console.error(
        `[enrol] Could not keep ${reply.agent_name}'s existing token, so it has a new one. ` +
        `Restart that agent so it reads the new file.`);
    }
  }

  const dir = path.dirname(tp);
  // chmod unconditionally: mkdir's mode is masked by umask and ignored on an existing
  // directory, and writeFileSync's mode applies only when it creates the file. This token
  // is the agent's identity in front of a world-connectable socket.
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  fs.writeFileSync(tp, socketToken, { mode: 0o600 });
  fs.chmodSync(tp, 0o600);

  return { agent_name: reply.agent_name, agent_id: reply.agent_id };
}

export interface CleanupResult { deleted: boolean; oldUnitStopped: boolean; pending: string[]; }

/**
 * Remove the pre-split store, once every agent is across.
 *
 * Still refused while anything is pending. The old credentials for an un-repaired agent
 * are the only ones it has, and deleting them would take that agent off the air with no
 * way back except creating a new one.
 */
export async function cleanup(): Promise<CleanupResult> {
  const st = await status();
  if (st.alreadyDone) return { deleted: false, oldUnitStopped: false, pending: [] };
  if (st.pending.length) return { deleted: false, oldUnitStopped: false, pending: st.pending };

  console.error(`[migrate] deleting the pre-split store: ${st.oldStorePath}`);

  // The store is shredded even if the old unit is still up, and that is safe HERE and only
  // here: reaching this point means every agent is across, which means every one of them
  // was repaired, which means the server has already rotated the credentials in that file
  // to dead ones. It is stale ciphertext, not a live secret.
  //
  // The unit is a different matter. It is reported, and its unit FILE is removed so a
  // reboot does not quietly start a second daemon — the thing a rerun could not fix once
  // the store was gone.
  const oldUnit = await stopOldUserUnit();
  for (const f of [legacy.profiles(), legacy.salt()]) {
    try { shred(f); } catch { /* best effort */ }
  }
  if (oldUnit === 'gone') removeOldUnitFile();
  return { deleted: !fs.existsSync(legacy.profiles()), oldUnitStopped: oldUnit === 'gone', pending: [] };
}

/**
 * Overwrite before unlinking.
 *
 * Not a guarantee — a journalling or copy-on-write filesystem, or an SSD's wear
 * levelling, can keep the old blocks regardless. Worth doing because it costs nothing and
 * removes the easy case, and worth saying plainly that it does not make the data
 * unrecoverable. After repair these credentials are already rejected by the server, so
 * this is tidiness rather than the thing keeping anyone safe.
 */
function shred(file: string): void {
  if (!fs.existsSync(file)) return;
  const size = fs.statSync(file).size;
  if (size > 0) fs.writeFileSync(file, crypto.randomBytes(size));
  fs.unlinkSync(file);
}

export function describeStatus(st: MigrationStatus, dashboardUrl = 'https://wundervault.com/dashboard'): string {
  if (st.alreadyDone) {
    return 'Nothing to migrate — there is no pre-split store in your home directory.';
  }
  const lines: string[] = [];
  if (st.across.length) lines.push(`Already across: ${st.across.join(', ')}`);
  if (!st.pending.length) {
    lines.push('');
    lines.push('Every agent is across. Remove the old store:');
    lines.push('  wundervault-agent --migrate --finish');
    return lines.join('\n');
  }
  lines.push(`Still to do (${st.pending.length}): ${st.pending.join(', ')}`);
  lines.push('');
  lines.push('These agents were set up before the daemon had its own account, so their');
  lines.push('credentials are in a file your agents can read. Repair moves each one across');
  lines.push('and KEEPS its vault access — same agent, same permissions, new credentials.');
  lines.push('');
  lines.push(`  1. Open ${dashboardUrl}`);
  lines.push('  2. Press REPAIR on the agent, and copy the setup link it gives you');
  lines.push('  3. Run:  wundervault-agent --enrol "<the whole link, including the #part>"');
  lines.push('');
  lines.push('The link is good for 15 minutes and works once. Repeat for each agent, then');
  lines.push('run  wundervault-agent --migrate --finish  to delete the old file.');
  return lines.join('\n');
}

```

## File: src/agent.ts

```
#!/usr/bin/env node
/**
 * The credential daemon, running as its own user.
 *
 * Before phase 4 this process shared a uid with the agents it served, so its key file, its
 * memory and its sockets were all readable by the party it was protecting them from.
 * Everything the vault claimed was true only against an agent that did not try.
 *
 * It now runs as the `wundervault` system account with its state in /var/lib/wundervault,
 * mode 0700. That directory mode is the boundary. The at-rest encryption is defence in
 * depth and is described as such — its key derives from the machine id, the uid and a salt
 * file kept beside the ciphertext, so anyone who can read the directory can recompute it.
 *
 * WHAT CHANGED IN THE THREAT MODEL, AND WHY THE SOCKETS LOOK WEAKER
 *
 * The per-agent sockets used to be 0600. They cannot be any more: the daemon is now a
 * different uid from every agent, and a 0600 socket it owns is one no agent could reach.
 * So the sockets are world-connectable and the TOKEN is the identity — a file in the
 * agent's own home at 0600, which only that uid can read.
 *
 * That makes the token check load-bearing in a way it never was. It used to be a second
 * lock behind a file mode; it is now the only lock. Two consequences the previous version
 * got wrong and this one must not:
 *
 *   1. A profile with no token used to be served to anyone who connected, because the
 *      check was inside `if (profile.socket_token)`. Behind a 0600 socket that was
 *      merely sloppy. In front of a world-connectable one it hands credentials to any
 *      local user. A profile without a token is now refused outright.
 *   2. Anyone may knock, so bad attempts are rate-limited per agent.
 */
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { VERSION } from './version.js';
import { redeemSetupLink } from './enrol.js';
import {
  systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
  runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
} from './paths.js';
import { load as loadNetworkShape } from './network-store.js';

interface AgentProfile {
  agent_name: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
  socket_token?: string;
}

interface ProfileStore {
  profiles: AgentProfile[];
}

/**
 * Refuse to be root.
 *
 * The unit says `User=wundervault`, but a unit is a file someone can edit, and a daemon
 * that silently keeps root because of a typo in /etc is worse than one that never had it:
 * every protection below would still appear to be working. Failing here makes the mistake
 * loud at the only moment anyone is watching.
 */
function refuseRoot(): void {
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  if (uid === 0) {
    console.error(
      `[wundervault-agent] Refusing to run as root.\n` +
      `  This daemon holds credentials and must run as its own unprivileged account.\n` +
      `  Expected User=${SYSTEM_ACCOUNT} in the unit file.\n` +
      `  If you installed by hand, re-run packaging/install-daemon.sh.`,
    );
    process.exit(1);
  }
}

function deriveMachineKey(): Buffer {
  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();

  let salt: Buffer;
  const sp = saltPath();
  if (fs.existsSync(sp)) {
    salt = fs.readFileSync(sp);
  } else {
    salt = crypto.randomBytes(32);
    ensureSystemRoot();
    fs.writeFileSync(sp, salt, { mode: 0o600 });
  }
  return crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;
}

function encryptProfiles(store: ProfileStore, key: Buffer): Buffer {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(store), 'utf8'), cipher.final()]);
  return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
}

function decryptProfiles(buf: Buffer, key: Buffer): ProfileStore {
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}

/** Constant-time comparison of two hex tokens, safe against malformed input. */
export function tokenMatches(provided: string | undefined, expected: string | undefined): boolean {
  if (!expected) return false;          // no token configured: never a match
  if (!provided) return false;
  let a: Buffer, b: Buffer;
  try {
    a = Buffer.from(provided, 'hex');
    b = Buffer.from(expected, 'hex');
  } catch { return false; }
  // Length is compared first and separately on purpose: timingSafeEqual throws on a
  // length mismatch, and a thrown exception is a louder timing signal than the
  // comparison it was meant to protect.
  if (a.length === 0 || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Bad attempts, per agent name.
 *
 * The socket is world-connectable now, so any local process may knock. Guessing a 32-byte
 * token is not a real threat; an unbounded loop of connections is, and the log it would
 * produce is its own denial of service. A short lockout costs a legitimate agent one
 * retry after a genuine misconfiguration.
 */
/**
 * Make guessing expensive without letting a guesser deny the real agent.
 *
 * The first shape of this was a lockout: ten bad tokens for an agent name and that name
 * was refused for sixty seconds. Behind a 0600 socket that was defensible. It is not
 * defensible now — this phase made the per-agent sockets world-connectable, because the
 * daemon is a different uid and a 0600 socket it owns is one no agent could reach. So any
 * local process could send ten wrong tokens and take the LEGITIMATE agent off the air,
 * repeatedly, for as long as it liked. The mechanism meant to slow an attacker down had
 * become the cheapest attack available, and this phase is what introduced it.
 *
 * The rule now: a correct token is ALWAYS served. Nothing an attacker sends can change
 * what the holder of the real token gets back. The cost falls on the failing caller
 * instead, as a delay that doubles per consecutive failure — which is what actually
 * throttles guessing, since it is the attacker's own connection that has to wait.
 *
 * The delay is per agent name, and that is a deliberate, stated limit: a unix socket
 * carries no address to attribute failures to, and Node exposes no SO_PEERCRED to
 * identify the caller. So a persistent guesser does slow down a legitimate client that
 * is ALSO failing — but a legitimate client that is failing has the wrong token, and
 * telling it so a second later costs nothing.
 */
class Knocks {
  private fails = new Map<string, { n: number; until: number }>();
  private readonly WINDOW_MS = 60_000;
  // Overridable so the tests can exercise the growth curve without sitting through it.
  // Production values are the defaults; nothing in the shipped path sets these.
  private readonly BASE_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_BASE_MS) || 50;
  private readonly MAX_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_MAX_MS) || 2_000;

  /**
   * How long to make a FAILING caller wait. Never consulted before a token is checked:
   * a valid token must not be delayed or refused because somebody else guessed wrong.
   */
  penaltyMs(name: string): number {
    const f = this.fails.get(name);
    if (!f || Date.now() >= f.until) return 0;
    return Math.min(this.BASE_DELAY_MS * 2 ** Math.min(f.n, 16), this.MAX_DELAY_MS);
  }

  record(name: string): void {
    const now = Date.now();
    const f = this.fails.get(name);
    if (!f || now >= f.until) { this.fails.set(name, { n: 1, until: now + this.WINDOW_MS }); return; }
    f.n += 1;
    // Sliding, not fixed: a guesser that keeps knocking keeps paying, rather than
    // getting a clean slate sixty seconds after its first attempt.
    f.until = now + this.WINDOW_MS;
  }

  clear(name: string): void { this.fails.delete(name); }
}

class AgentDaemon {
  private key: Buffer;
  private profiles: AgentProfile[] = [];
  private agentServers: Map<string, net.Server> = new Map();
  private mgmtServer: net.Server | null = null;
  private knocks = new Knocks();

  constructor() {
    ensureSystemRoot();
    this.key = deriveMachineKey();
    this.loadProfiles();
  }

  /**
   * A store we could not read is NOT an empty store.
   *
   * This used to log the failure and carry on with `this.profiles` still `[]`. The daemon
   * would come up serving nobody, which looks like a bad day — and then the first
   * enrolment called saveProfiles(), which wrote a store containing ONLY that profile,
   * over the ciphertext holding every other agent's credentials. A recoverable problem
   * (a changed /etc/machine-id, a recreated wundervault account, a damaged file — all of
   * which leave the plaintext retrievable) became permanent loss, silently.
   *
   * So a decrypt failure is now a refusal: the daemon will not serve and will not save
   * until a person has looked at it. Refusing to start is a visible, reversible failure.
   * Overwriting is neither.
   */
  private unreadableStore: string | null = null;

  loadProfiles(): void {
    const pp = profilesPath();
    if (!fs.existsSync(pp)) { this.unreadableStore = null; return; }
    try {
      this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
      this.unreadableStore = null;
    } catch (err) {
      this.unreadableStore = (err as Error).message;
      this.profiles = [];
      console.error(
        `[wundervault-agent] Could not read the profile store at ${pp}: ${this.unreadableStore}\n` +
        `[wundervault-agent] It is encrypted against this machine's id and the daemon's uid.\n` +
        `[wundervault-agent] REFUSING to serve or to overwrite it. The credentials are still\n` +
        `[wundervault-agent] in that file; starting fresh would destroy them. Restore the file,\n` +
        `[wundervault-agent] or move it aside deliberately if you mean to start over.`,
      );
    }
  }

  /** True when the store exists but could not be read. Nothing may be written in this state. */
  get storeUnreadable(): boolean { return this.unreadableStore !== null; }

  saveProfiles(): void {
    if (this.unreadableStore) {
      throw new Error(
        `Refusing to write the profile store: it exists but could not be decrypted ` +
        `(${this.unreadableStore}). Writing now would replace every credential in it ` +
        `with only what is in memory.`,
      );
    }
    const pp = profilesPath();
    // Write-then-rename. A half-written store read after a crash decrypts to nothing and
    // every agent on the machine loses its credentials at once.
    const tmp = `${pp}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, encryptProfiles({ profiles: this.profiles }, this.key), { mode: 0o600 });
    fs.renameSync(tmp, pp);
    try { fs.chmodSync(pp, 0o600); } catch { /* best effort */ }
  }

  registerProfile(profile: AgentProfile): void {
    // The name becomes a path segment. It arrives over a socket any local process can
    // connect to, so "../../etc/cron.d/x" would otherwise have this daemon place a file
    // wherever it liked — which for the process holding the boundary is the whole game.
    profile.agent_name = safeName(profile.agent_name);

    // Refuse before touching anything. Saving first was not enough on its own: by the time
    // saveProfiles() threw, the in-memory list had already been rewritten and the previous
    // agent's socket closed, so a rejected enrolment still took a working agent off the
    // air. The state a failure leaves behind has to be the state it started from.
    if (this.storeUnreadable) {
      throw new Error(
        `Refusing to enrol while the profile store cannot be read. Writing now would ` +
        `replace every credential in it with only what is in memory.`,
      );
    }

    if (!profile.socket_token) {
      throw new Error(
        'A profile must carry a socket_token. The per-agent socket is world-connectable ' +
        'now that the daemon runs as a different user, so the token is the only thing ' +
        'identifying the caller.',
      );
    }

    const idx = this.profiles.findIndex(p => p.agent_name === profile.agent_name);
    if (idx >= 0) {
      this.profiles[idx] = profile;
      const old = this.agentServers.get(profile.agent_name);
      if (old) {
        // Not unlinked in the close callback: startAgentSocket unlinks and rebinds
        // immediately, and the async callback would race it.
        old.close();
        this.agentServers.delete(profile.agent_name);
      }
    } else {
      this.profiles.push(profile);
    }
    this.knocks.clear(profile.agent_name);
    // Saved BEFORE the socket is published. The other order started serving credentials
    // and then threw on save, so a daemon that had just declared it would not write to an
    // unreadable store was nonetheless handing out a profile it had not committed —
    // refusing the caller while serving the agent. Commit first; publish only if it stuck.
    this.saveProfiles();
    this.startAgentSocket(profile);
  }

  removeProfile(name: string): boolean {
    const safe = safeName(name);
    const before = this.profiles.length;
    this.profiles = this.profiles.filter(p => p.agent_name !== safe);
    if (this.profiles.length === before) return false;
    const srv = this.agentServers.get(safe);
    if (srv) { try { srv.close(); } catch { /* already gone */ } }
    this.agentServers.delete(safe);
    try { fs.unlinkSync(agentSocketPath(safe)); } catch { /* already gone */ }
    this.saveProfiles();
    return true;
  }

  startAgentSocket(profile: AgentProfile): void {
    const sockPath = agentSocketPath(profile.agent_name);
    try { fs.unlinkSync(sockPath); } catch { /* nothing to clear */ }

    const srv = net.createServer((socket) => {
      let buf = '';
      // A caller that never sends a newline would otherwise hold a connection open for
      // ever, and a caller that streams without one would grow this buffer without bound.
      // Inactivity timeout AND an absolute one. The inactivity timer alone is resettable
      // by any traffic, which is what let a connection be held open indefinitely.
      socket.setTimeout(5_000, () => socket.destroy());
      const deadline = setTimeout(() => socket.destroy(), 10_000);
      (deadline as unknown as { unref?: () => void }).unref?.();
      socket.on('close', () => clearTimeout(deadline));
      socket.on('data', (d) => {
        buf += d.toString();
        if (buf.length > 4096) { socket.destroy(); return; }
        if (!buf.includes('\n')) return;

        let msg: { token?: string } = {};
        try { msg = JSON.parse(buf.trim()); } catch { /* treated as no token */ }

        // The token is checked FIRST, before any penalty is consulted. The previous order
        // let a stranger's wrong guesses decide what the real agent got back.
        if (!tokenMatches(msg.token, profile.socket_token)) {
          const wait = this.knocks.penaltyMs(profile.agent_name);
          this.knocks.record(profile.agent_name);
          console.error(`[wundervault-agent] Auth failure on ${profile.agent_name} socket`);
          // The same answer for a bad token and a missing one. Anything more specific
          // tells a local prober which agent names exist on this machine.
          const refuse = () => {
            try {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
              socket.end();
            } catch { /* the prober hung up while waiting, which is fine */ }
          };
          if (wait > 0) {
            const t = setTimeout(refuse, wait);
            // Do not hold the event loop open on behalf of someone guessing tokens.
            (t as unknown as { unref?: () => void }).unref?.();
            socket.on('close', () => clearTimeout(t));
          } else {
            refuse();
          }
          return;
        }

        this.knocks.clear(profile.agent_name);
        socket.write(JSON.stringify({
          api_key: profile.api_key,
          enc_key: profile.enc_key,
          vault_url: profile.vault_url,
        }) + '\n');
        socket.end();
      });
      socket.on('error', () => { /* a client that hangs up is not an event */ });
    });

    // NO maxConnections here, deliberately — the second version of this code had one, and
    // it recreated the denial of service it was meant to prevent one layer down. A ceiling
    // of 64 means 64 held connections exclude everyone else, and the legitimate agent's
    // connection is dropped by the kernel BEFORE its token is ever read. Holding them was
    // easy: setTimeout() is an INACTIVITY timeout, so a byte every few seconds reset it
    // indefinitely, and the 4096-byte ceiling took hours to reach at that rate.
    //
    // What bounds the resource is the absolute deadline below instead: a connection dies a
    // fixed time after it was accepted, whatever it sends. Slots cannot be held, so they
    // do not need to be rationed, and nothing an attacker does can make the daemon refuse
    // a connection it has not yet authenticated.
    srv.listen(sockPath, () => {
      // World-connectable BY DESIGN — see the header. The daemon is a different uid from
      // every agent, so a mode that excluded others would exclude the agent too. The
      // token is the identity; this mode is not a control and must not be read as one.
      try { fs.chmodSync(sockPath, 0o666); } catch { /* best effort */ }
    });
    srv.on('error', (err) => {
      console.error(`[wundervault-agent] Socket error for ${profile.agent_name}:`, err.message);
    });
    this.agentServers.set(profile.agent_name, srv);
  }

  startMgmtSocket(): void {
    const mp = mgmtSocketPath();
    // The directory is the control, and it exists before the socket does. chmod-after-
    // listen leaves a window in which the socket is bound at the default mode and a
    // process watching for it can connect; a 0770 directory has no such window.
    const md = mgmtDir();
    fs.mkdirSync(md, { recursive: true, mode: 0o755 });
    fs.chmodSync(md, 0o755);
    try { fs.unlinkSync(mp); } catch { /* nothing to clear */ }

    const mgmt = net.createServer((socket) => {
      let buf = '';
      // One request per connection. The handler fires on every 'data' event and reparses
      // whatever is in the buffer, so before this flag a caller could write one valid
      // enrol line and then dribble single bytes: each one re-ran the same request, and
      // each enrol is a 100,000-round PBKDF2 plus a network fetch. A thousand of those
      // stall the event loop that every agent's credential socket shares.
      let consumed = false;
      socket.setTimeout(10_000, () => socket.destroy());
      socket.on('data', (d) => {
        buf += d.toString();
        // Enrolment carries a profile, so this ceiling is higher than the agent socket's —
        // but it is still a ceiling.
        if (buf.length > 64 * 1024) { socket.destroy(); return; }
        const nl = buf.indexOf('\n');
        if (nl < 0) return;
        if (consumed) return;
        consumed = true;

        try {
          const msg = JSON.parse(buf.slice(0, nl));
          if (msg.action === 'enrol' && msg.setup_url) {
            // The ONLY way a profile gets in. `register_profile` used to live here and
            // took whatever it was handed: any local process — every agent on this
            // machine included, since they run as the owner — could register a name with
            // a token of its choosing and then read that agent's credentials off its own
            // socket. No local permission could fix that, because the kernel cannot tell
            // the owner's shell from an agent running as the owner.
            //
            // A setup link can. It is issued by the server to someone logged in to the
            // website, it is single-use, and it expires in fifteen minutes. An agent
            // cannot obtain one. So the daemon redeems it ITSELF: the caller hands over a
            // URL and learns a name, and the credentials never exist in the asking
            // process at all.
            void (async () => {
              try {
                // Checked BEFORE anything is redeemed. Redeeming first meant a missing
                // socket_token burned a single-use link and produced no usable agent —
                // the link spent, the agent absent, and another trip to the dashboard.
                if (!msg.socket_token || String(msg.socket_token).length < 32) {
                  throw new Error('An enrolment must carry a socket_token of at least 32 characters.');
                }
                // The burn is deferred: the link is marked used only once the profile is
                // actually stored, so a disk error cannot consume it either.
                const { creds, burn } = await redeemSetupLink(String(msg.setup_url));
                this.registerProfile({
                  agent_name: creds.agent_name,
                  api_key: creds.api_key,
                  enc_key: creds.enc_key,
                  vault_url: creds.vault_url,
                  socket_token: String(msg.socket_token),
                } as AgentProfile);
                await burn();
                socket.write(JSON.stringify({
                  ok: true, agent_name: creds.agent_name, agent_id: creds.agent_id,
                }) + '\n');
              } catch (e) {
                socket.write(JSON.stringify({ error: (e as Error).message }) + '\n');
              }
              socket.end();
            })();
            return;   // the async path owns this socket from here
          } else if (msg.action === 'set_socket_token' && msg.agent_name) {
            // Used by enrolment to restore an agent's PREVIOUS token, so a migration does
            // not lock out an agent process that read its token at startup. Authorised by
            // the token currently in force — which the caller only knows because it just
            // set it, moments ago, with a valid setup link.
            const name = String(msg.agent_name);
            const target = this.profiles.find(p => p.agent_name === name);
            const next = String(msg.new_token ?? '');
            if (!target || !tokenMatches(msg.token, target.socket_token)) {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
            } else if (next.length < 32) {
              socket.write(JSON.stringify({ error: 'a socket_token must be at least 32 characters' }) + '\n');
            } else {
              this.registerProfile({ ...target, socket_token: next } as AgentProfile);
              socket.write(JSON.stringify({ ok: true }) + '\n');
            }
          } else if (msg.action === 'remove_profile' && msg.agent_name) {
            // Gated on the agent's own token. The socket is world-connectable now, so
            // without this any local user could delete another user's agents. It does NOT
            // distinguish one agent from another under the same uid — nothing can, and
            // the spec says so in C5 — but it does stop everyone else.
            const name = String(msg.agent_name);
            const target = this.profiles.find(p => p.agent_name === name);
            if (!target || !tokenMatches(msg.token, target.socket_token)) {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
              socket.end();
              return;
            }
            const gone = this.removeProfile(name);
            socket.write(JSON.stringify({ ok: true, removed: gone }) + '\n');
          } else if (msg.action === 'reload') {
            this.loadProfiles();
            socket.write(JSON.stringify({ ok: true, count: this.profiles.length }) + '\n');
          } else if (msg.action === 'destinations') {
            // Deliberately gone. It was served here while the socket sat behind a locked
            // directory; that lock is off, because the owner and their agents are the same
            // uid and any door the owner can open an agent can open too. Serving this now
            // would hand every agent the record of where all the others sent secrets.
            socket.write(JSON.stringify({
              error: 'destinations are not served over this socket. Run: ' +
                     'sudo wundervault-agent --destinations',
            }) + '\n');
          } else if (msg.action === 'ping') {
            // Liveness only. This used to return every agent name on the machine, which
            // is a roster of what holds credentials here, handed to anyone who could
            // reach the socket. Migration is the only caller that needs the names, and it
            // asks for them explicitly below.
            socket.write(JSON.stringify({
              ok: true, version: VERSION, store_unreadable: this.storeUnreadable,
            }) + '\n');
          } else if (msg.action === 'known_agents') {
            // Names only, never credentials. This is what lets migration tell you which of
            // your agents still need a repair link, and it is the reason the destination
            // store is NOT served here any more: a roster of names is a much smaller thing
            // to give away than the record of where every agent sent its secrets.
            socket.write(JSON.stringify({
              ok: true, agents: this.profiles.map(p => p.agent_name),
            }) + '\n');
          } else {
            socket.write(JSON.stringify({ error: 'unknown action' }) + '\n');
          }
        } catch (err) {
          // The message is reported because an agent-name rejection is actionable and
          // silence here reads as a hang.
          socket.write(JSON.stringify({ error: (err as Error).message || 'parse error' }) + '\n');
        }
        socket.end();
      });
      socket.on('error', () => { /* hang-ups are not events */ });
    });

    mgmt.listen(mp, () => {
      // Connectable by anyone, like the per-agent sockets, and for the same reason: the
      // daemon is a different uid, so a socket it owns at 0660 is one no agent could
      // reach. What guards the actions behind it is a server-issued setup link to enrol
      // and the agent's own token to remove — neither of which a file mode can supply.
      try { fs.chmodSync(mp, 0o666); } catch { /* best effort */ }
      console.log(`[wundervault-agent] Listening. Management: ${mp}`);
    });
    mgmt.on('error', (err) => {
      console.error('[wundervault-agent] Mgmt socket error:', err.message);
    });
    this.mgmtServer = mgmt;
  }

  start(): void {
    const rt = runtimeDir();
    fs.mkdirSync(rt, { recursive: true, mode: 0o755 });
    // Clear sockets left by a crash. A stale file makes listen() fail, and the daemon
    // would come up with no socket while reporting itself started.
    try {
      for (const f of fs.readdirSync(rt)) {
        if (f.endsWith('.sock')) { try { fs.unlinkSync(path.join(rt, f)); } catch { /* ignore */ } }
      }
    } catch { /* first run */ }

    for (const profile of this.profiles) {
      if (!profile.socket_token) {
        // Pre-split profiles may have none. Serving them now would hand credentials to
        // any local process, so they are skipped loudly rather than served quietly.
        console.error(
          `[wundervault-agent] Agent "${profile.agent_name}" has no socket token and will ` +
          `NOT be served. Re-run onboarding for it.`,
        );
        continue;
      }
      this.startAgentSocket(profile);
    }
    this.startMgmtSocket();
    console.log(
      `[wundervault-agent] Started with ${this.agentServers.size} agent(s). State: ${systemRoot()}`,
    );
  }

  shutdown(): void {
    for (const [name, srv] of this.agentServers) {
      try { srv.close(); } catch { /* already closing */ }
      try { fs.unlinkSync(agentSocketPath(name)); } catch { /* already gone */ }
    }
    if (this.mgmtServer) { try { this.mgmtServer.close(); } catch { /* already closing */ } }
    try { fs.unlinkSync(mgmtSocketPath()); } catch { /* already gone */ }
  }
}

export { AgentDaemon, deriveMachineKey, encryptProfiles, decryptProfiles, refuseRoot };
export type { AgentProfile, ProfileStore };

/**
 * Read the setup link from stdin.
 *
 * Deliberately not an argument. `/proc/<pid>/cmdline` is world-readable on Linux, so a
 * link passed on the command line is visible to every process running as the owner — which
 * is every agent — for as long as the command runs. That link is the one credential this
 * whole design assumes an agent cannot obtain, and fetching and burning are separate steps,
 * so an agent that copied it would have had time to redeem it first. Piping still works, so
 * this stays scriptable; nothing that reaches here lands in argv.
 */
function readLinkFromStdin(): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      process.stderr.write('Paste the setup link from the dashboard (it ends in #…): ');
    }
    let buf = '';
    process.stdin.setEncoding('utf8');
    const finish = (v: string) => { process.stdin.pause(); resolve(v.trim()); };
    process.stdin.on('data', (d) => {
      buf += d;
      // A terminal sends no EOF until ctrl-D, so the first newline ends the read.
      if (process.stdin.isTTY && buf.includes('\n')) finish(buf.split('\n')[0]);
    });
    process.stdin.on('end', () => finish(buf));
  });
}

// Only run when invoked as the binary, so the class can be imported by tests and by the
// migration command without starting a daemon as a side effect.
const invokedDirectly = process.argv[1] && /wundervault-agent|agent\.(js|ts)$/.test(process.argv[1]);
if (invokedDirectly && !process.env.WUNDERVAULT_AGENT_NO_AUTOSTART) {
  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`
Wundervault agent daemon ${VERSION}

Usage: wundervault-agent [--enrol] [--migrate [--finish]] [--destinations]

With no arguments it runs as the daemon. It is normally started by systemd as the
'${SYSTEM_ACCOUNT}' account, not by hand.

  --enrol       Add an agent using a setup link from the dashboard. Prompts for the link
                rather than taking it as an argument: a command line is readable by every
                process on this machine. The daemon redeems the link itself, so the
                credentials never pass through this process.
  --migrate     Show which pre-split agents still need moving across, and how.
  --finish      With --migrate: delete the pre-split store, once every agent is across.
  --destinations  Write the page showing where your agents have sent secrets.
                Needs sudo: the record belongs to the daemon so your agents cannot read it.

State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
`);
    process.exit(0);
  }

  if (argv.includes('--destinations')) {
    // Dispatched here as well as in the MCP binary, because every message that mentions
    // this names THIS command — `sudo wundervault-agent --destinations`. It was only wired
    // into wundervault-mcp, so the advice printed by the daemon and the log viewer led
    // straight into refuseRoot and a message about not running as root.
    //
    // refuseRoot is deliberately NOT called on this path: reading the store is the one
    // thing that requires being root, because the file belongs to the daemon's account and
    // that is what stops the agents reading it.
    const { writeViewer, collectShape } = await import('./log-viewer.js');
    const { defaultStorePath } = await import('./network-store.js');
    const store = defaultStorePath();
    collectShape(store)
      .then(({ shape }) => {
        const out = writeViewer(store, undefined, shape);
        const calls = shape.seen.reduce((n: number, x: { count: number }) => n + x.count, 0);
        console.log(
          `\nDestination log — ${shape.seen.length} destination(s), ${calls} call(s)\n` +
          `  store:  ${store}\n  viewer: ${out}\n\n` +
          `Open that file in your browser. It contains the data already, loads nothing, and\n` +
          `is blocked by its own content-security policy from making any network request.\n`);
        process.exit(0);
      })
      .catch((e: Error) => { console.error(e.message); process.exit(1); });
  } else if (argv.includes('--enrol')) {
    // Runs as the USER. It hands over a URL and gets back a name — the credentials are
    // fetched, decrypted and filed by the daemon, and never enter this process.
    //
    // The link is READ FROM STDIN, never taken from argv. A command line is world-readable
    // through /proc/<pid>/cmdline, so `--enrol "https://...#passphrase"` published the one
    // credential this design assumes an agent cannot get, to every agent on the machine,
    // for as long as the command ran. And because fetching and burning are separate steps,
    // an agent that copied it had time to redeem it first. Prompting costs one paste and
    // keeps the link out of argv and out of shell history.
    const url = await readLinkFromStdin();
    if (!url) {
      console.error('No setup link given.');
      process.exit(2);
    }
    const { enrol } = await import('./migrate.js');
    enrol(url)
      .then((r) => {
        console.log(`Enrolled ${r.agent_name}. Its credentials are in ${systemRoot()}, ` +
                    `which your agents cannot read.`);
        process.exit(0);
      })
      .catch((e: Error) => { console.error(e.message); process.exit(1); });
  } else if (argv.includes('--migrate')) {
    // Runs as the USER, not the daemon: it reads the old store from a home directory the
    // daemon deliberately cannot reach.
    const { status, describeStatus, cleanup } = await import('./migrate.js');
    if (argv.includes('--finish')) {
      cleanup()
        .then((r) => {
          if (r.pending.length) {
            console.error(`Not yet — these are still on the old credentials: ${r.pending.join(', ')}`);
            console.error('Deleting the store now would take them off the air for good.');
            process.exit(1);
          }
          console.log(r.deleted
            ? 'Deleted the pre-split store. Credentials now live where your agents cannot read them.'
            : 'There was no pre-split store to delete.');
          if (!r.oldUnitStopped) {
            console.log('');
            console.log('The pre-split daemon may still be running. It is serving credentials the');
            console.log('server no longer accepts, but it should not be left behind:');
            console.log('  systemctl --user disable --now wundervault-agent.service');
          }
          process.exit(0);
        })
        .catch((e: Error) => { console.error(e.message); process.exit(1); });
    } else {
      status()
        .then((st) => { console.log(describeStatus(st)); process.exit(0); })
        .catch((e: Error) => { console.error(e.message); process.exit(1); });
    }
  } else {
    refuseRoot();
    const daemon = new AgentDaemon();
    daemon.start();
    process.on('SIGTERM', () => { daemon.shutdown(); process.exit(0); });
    process.on('SIGINT', () => { daemon.shutdown(); process.exit(0); });
  }
}

```

## File: test/enrol.test.ts

```
/**
 * Enrolment, end to end, against a real HTTP server speaking the real protocol.
 *
 * The point of this file is that the daemon — not the calling process — redeems the setup
 * link. That is what replaced `register_profile`, which accepted a profile from whoever
 * asked and so handed every agent on the machine the ability to register a name with a
 * token it chose and then read that agent's credentials. A local permission could not fix
 * it, because agents run as the owner; only a credential the agent cannot obtain can, and
 * the setup link is issued by the server to someone logged in to the website.
 *
 * The blob format here is not invented for the test: it is built exactly as onboard.py
 * expects to find it — PBKDF2-SHA256 over the passphrase with the salt "wv-agent-setup-v1"
 * at 100,000 rounds, AES-256-GCM, nonce first and tag last, base64url. A test that made up
 * its own format would prove the code agrees with the test and nothing about the server.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { AgentDaemon } from '../src/agent.js';
import { parseSetupUrl } from '../src/enrol.js';

let dir: string;
let daemon: any;
let server: http.Server;
let baseUrl: string;
let burned: string[] = [];

const PASSPHRASE = 'correct horse battery staple';

function makeBlob(creds: object, passphrase = PASSPHRASE): string {
  const key = crypto.pbkdf2Sync(passphrase, 'wv-agent-setup-v1', 100_000, 32, 'sha256');
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const body = Buffer.concat([c.update(JSON.stringify(creds), 'utf8'), c.final()]);
  return Buffer.concat([nonce, body, c.getAuthTag()])
    .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Stands in for the website. Answers the two endpoints onboard.py uses, and no others. */
function startServer(tokens: Record<string, { name: string; blob: string; used?: boolean; gone?: boolean }>) {
  return new Promise<void>((resolve) => {
    server = http.createServer((req, res) => {
      const m = String(req.url).match(/^\/api\/setup\/agent\/([^/]+)(\/burn)?$/);
      if (!m) { res.writeHead(404).end('{}'); return; }
      const entry = tokens[m[1]];
      if (!entry) { res.writeHead(404).end(JSON.stringify({ detail: 'Invalid setup token' })); return; }
      if (m[2]) { entry.used = true; burned.push(m[1]); res.writeHead(200).end(JSON.stringify({ status: 'burned' })); return; }
      if (entry.used || entry.gone) { res.writeHead(410).end(JSON.stringify({ detail: 'used' })); return; }
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        agent_id: 'ag_' + entry.name, agent_name: entry.name, encrypted_blob: entry.blob,
      }));
    });
    server.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
      resolve();
    });
  });
}

async function freshDaemon() {
  // Set on the DAEMON's environment, which is exactly the point: systemd sets this, and a
  // caller cannot. An agent can hand over any URL it likes and still not widen this.
  process.env.WUNDERVAULT_SETUP_ORIGIN = baseUrl;
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'state');
  process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'home', '.wundervault');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  const d = new AgentDaemon();
  d.start();
  return d;
}

function speak(sockPath: string, payload: unknown, timeoutMs = 20_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockPath);
    let buf = '';
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutMs);
    const fin = (fn: () => void) => { clearTimeout(t); s.destroy(); fn(); };
    s.on('connect', () => s.write(JSON.stringify(payload) + '\n'));
    s.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      try { fin(() => resolve(JSON.parse(buf.trim()))); } catch { fin(() => resolve({ raw: buf })); }
    });
    s.on('error', (e) => fin(() => reject(e)));
  });
}

const mgmt = () => path.join(dir, 'run', 'mgmt', 'agent.sock');

beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-enrol-')); burned = []; });
afterEach(async () => {
  try { daemon?.shutdown(); } catch { /* down already */ }
  daemon = undefined;
  await new Promise<void>((r) => server ? server.close(() => r()) : r());
  fs.rmSync(dir, { recursive: true, force: true });
  for (const k of ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR',
                   'WUNDERVAULT_SETUP_ORIGIN']) {
    delete process.env[k];
  }
});

describe('the setup link is the authorisation', () => {
  it('enrols an agent the daemon fetched and decrypted itself', async () => {
    const blob = makeBlob({ api_key: 'wv_agent_A|secret', encryption_key: 'enc_A' });
    await startServer({ tok1: { name: 'Byte', blob } });
    daemon = await freshDaemon();

    const socketToken = crypto.randomBytes(32).toString('hex');
    const res = await speak(mgmt(), {
      action: 'enrol',
      setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
      socket_token: socketToken,
    });

    expect(res.ok).toBe(true);
    expect(res.agent_name).toBe('Byte');
    expect(burned).toEqual(['tok1']);

    // And the agent can now collect them with its token — the daemon really filed them.
    const got = await speak(path.join(dir, 'run', 'Byte.sock'), { token: socketToken });
    expect(got.api_key).toBe('wv_agent_A|secret');
    expect(got.enc_key).toBe('enc_A');
  });

  it('refuses without a setup link — there is no other way in', async () => {
    await startServer({});
    daemon = await freshDaemon();
    // The action that used to accept a profile outright is gone, not merely guarded.
    const res = await speak(mgmt(), {
      action: 'register_profile',
      profile: { agent_name: 'X', api_key: 'k', enc_key: 'e', vault_url: 'u', socket_token: 'aa'.repeat(32) },
    });
    expect(res.ok).toBeUndefined();
    expect(res.error).toBe('unknown action');
    expect(fs.existsSync(path.join(dir, 'run', 'X.sock'))).toBe(false);
  });

  it('refuses a used link, and says how to get another', async () => {
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: 'Byte', blob, used: true } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
      socket_token: crypto.randomBytes(32).toString('hex'),
    });
    expect(res.error).toMatch(/already been used|expired/i);
    expect(res.error).toMatch(/[Rr]epair/);
  });

  it('does not burn the link when the passphrase is wrong', async () => {
    // Burning first would consume a single-use link on a typo and send the owner back to
    // the dashboard for a new one.
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: 'Byte', blob } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#wrong-passphrase`,
      socket_token: crypto.randomBytes(32).toString('hex'),
    });
    expect(res.error).toMatch(/decrypt/i);
    expect(burned).toEqual([]);
  });

  it('refuses a traversing agent name, even from the server', async () => {
    // The name becomes a path segment and now arrives from the SERVER rather than the
    // caller. That is a better source, not a trusted one: a compromised or confused
    // server must not be able to make the daemon write a file wherever it likes.
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: '../../etc/cron.d/x', blob } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
      socket_token: crypto.randomBytes(32).toString('hex'),
    });
    expect(res.ok).toBeUndefined();
    expect(res.error).toMatch(/Invalid agent name/);
  });

  it('refuses an enrolment with no socket token', async () => {
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: 'Byte', blob } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
    });
    expect(res.error).toMatch(/socket_token/);
  });
});

describe('one enrolment per connection', () => {
  it('does not re-run the request when the caller keeps writing', async () => {
    // Each enrol is a 100,000-round PBKDF2 plus a fetch, on the event loop every agent's
    // credential socket shares. Before the guard, a caller could send one valid line and
    // then dribble bytes, re-running the whole thing on every chunk.
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    let gets = 0;
    await startServer({ tok1: { name: 'Byte', blob } });
    server.on('request', (req) => { if (!/burn/.test(String(req.url))) gets++; });
    daemon = await freshDaemon();

    const c = net.createConnection(mgmt());
    await new Promise((r) => c.on('connect', r));
    c.write(JSON.stringify({
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
      socket_token: crypto.randomBytes(32).toString('hex'),
    }) + '\n');
    for (let i = 0; i < 50; i++) c.write('x');
    await new Promise((r) => setTimeout(r, 600));
    c.destroy();

    expect(gets).toBe(1);
  }, 20_000);

  it('does not burn the link when there is no socket token', async () => {
    // Validation moved ahead of redemption: burning first spent a single-use link and
    // produced no agent, so the owner was sent back to the dashboard for a new one.
    const blob = makeBlob({ api_key: 'k', encryption_key: 'e' });
    await startServer({ tok1: { name: 'Byte', blob } });
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol', setup_url: `${baseUrl}/setup/agent/tok1#${PASSPHRASE}`,
    });
    expect(res.error).toMatch(/socket_token/);
    expect(burned).toEqual([]);
  });
});

describe('the origin is the whole security property', () => {
  it('refuses a link from a server the agent stood up itself', async () => {
    // THE attack the loopback exception opened, and the reason it is gone. A malicious
    // agent runs its own listener, serves a blob it encrypted with a passphrase it chose,
    // and hands the daemon the link. Every cryptographic check passes — the agent made the
    // ciphertext — so the only thing that can refuse it is not trusting the origin.
    const rogueBlob = makeBlob({ api_key: 'stolen', encryption_key: 'stolen' }, 'agent-chosen');
    const rogue = http.createServer((req, res) => {
      const m = String(req.url).match(/^\/api\/setup\/agent\/([^/]+)(\/burn)?$/);
      if (!m) { res.writeHead(404).end('{}'); return; }
      if (m[2]) { res.writeHead(200).end('{"status":"burned"}'); return; }
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        agent_id: 'rogue', agent_name: 'Byte', encrypted_blob: rogueBlob,
      }));
    });
    await new Promise<void>((r) => rogue.listen(0, '127.0.0.1', () => r()));
    const rogueUrl = `http://127.0.0.1:${(rogue.address() as net.AddressInfo).port}`;

    // The daemon trusts a DIFFERENT origin — the real one.
    await startServer({});
    daemon = await freshDaemon();

    const res = await speak(mgmt(), {
      action: 'enrol',
      setup_url: `${rogueUrl}/setup/agent/anything#agent-chosen`,
      socket_token: crypto.randomBytes(32).toString('hex'),
    });
    await new Promise<void>((r) => rogue.close(() => r()));

    expect(res.ok).toBeUndefined();
    expect(res.error).toMatch(/must come from/);
    expect(fs.existsSync(path.join(dir, 'run', 'Byte.sock'))).toBe(false);
  });

  it('refuses a link from a lookalike host', async () => {
    await startServer({});
    daemon = await freshDaemon();
    const res = await speak(mgmt(), {
      action: 'enrol',
      setup_url: 'https://wundervault.com.evil.example/setup/agent/t#p',
      socket_token: crypto.randomBytes(32).toString('hex'),
    });
    expect(res.error).toMatch(/must come from/);
  });
});

describe('parsing a setup link', () => {
  it('takes the token from the path and the passphrase from the fragment', () => {
    process.env.WUNDERVAULT_SETUP_ORIGIN = 'https://wundervault.com';
    const p = parseSetupUrl('https://wundervault.com/setup/agent/abc123#hunter2');
    expect(p).toEqual({ baseUrl: 'https://wundervault.com', token: 'abc123', passphrase: 'hunter2' });
  });

  it('refuses a link with no fragment, and explains why it matters', () => {
    process.env.WUNDERVAULT_SETUP_ORIGIN = 'https://wundervault.com';
    // A link without the fragment looks complete and cannot possibly work: the passphrase
    // is the only thing that decrypts the blob and the server never had it.
    expect(() => parseSetupUrl('https://wundervault.com/setup/agent/abc123'))
      .toThrow(/after the #/);
  });

  it('refuses plaintext http even on the right hostname', () => {
    // The blob is encrypted, but the token is a bearer credential in the path.
    process.env.WUNDERVAULT_SETUP_ORIGIN = 'https://wundervault.com';
    expect(() => parseSetupUrl('http://wundervault.com/setup/agent/abc#p')).toThrow(/must come from/);
  });

  it('refuses something that is not a setup link at all', () => {
    process.env.WUNDERVAULT_SETUP_ORIGIN = 'https://wundervault.com';
    expect(() => parseSetupUrl('https://wundervault.com/dashboard#p')).toThrow(/no setup token/);
    expect(() => parseSetupUrl('not a url')).toThrow(/does not look like/);
  });
});

```

## Already ruled on in earlier rounds

Do not raise these again unless you have new evidence, and name the evidence if you do.

- [round 1 F2] deferred: Delete the lock file, start a frozen OLDER copy of the package, and it starts alongside a live holder because it has no process scan.
  reason: True and unfixable from inside this repo — an old build cannot be taught to scan. Explicitly out of scope per the spec (frozen copies are not being rebuilt), but it means the invariant is only restored box-wide once Byte's copy in ~/.openclaw/workspace/node_modules is updated. Raised to the user as a real remaining gap, not closed.
- [round 1 B2] rejected: Agent names 'Team A' and 'Team?A' both slug to mcp-Team_A.lock and can clobber each other's lock.
  reason: Real but not fixable under this spec's compatibility constraint: changing the filename breaks every older copy on the box that reads mcp-<slug>.lock, which is a strictly worse failure. Impact is now small because arbitration is by process and the scan compares the RAW agent name from environ, not the slug. Documented, not changed.
- [round 1 B1] deferred: Containers with disjoint /proc views sharing one home directory cannot be disambiguated by a host-local (pid, start) pair.
  reason: Correct, and out of scope — no such deployment exists here. Worth recording as a known boundary of the design rather than pretending the lock is namespace-safe.
- [round 1 B3] deferred: On non-Linux there is no incarnation evidence, so a stale lock naming a reused PID refuses forever and points at the wrong process.
  reason: Accurate. Mitigated in practice by fix 2 of this build: the refusal is now legible and names the PID, so an operator can see it is wrong and delete the lock, instead of staring at CONNECTION_CLOSED. A real fix needs a non-/proc incarnation source; noted, not built.
- [round 2 F4] rejected: A reparented (PPID 1) holder yields no parent hint, so the blocked user gets no way to identify the owning session.
  reason: Accurate but not a defect. PID and connection time are still reported and are enough to find the process; naming init would identify nothing. Deliberately not falling back to the parent's argv, which is where a useful-looking hint would have to come from and which can contain tokens — that was blocker F4 in round 1.
- [round 3 B1] deferred: Any local process can bind the predictable address and impersonate occupancy without being an MCP server.
  reason: True and inherent to any same-UID lock — a process that can bind your address can also read your lock file, your socket and your home directory. It denies service rather than granting it, which is the safe direction, and the identity banner now makes an impostor visible (it cannot produce the protocol line, so the refusal reports the holder as unknown rather than pretending). Not fixable without an authenticated channel, which is out of proportion here.
- [round 3 B3] deferred: The suite covers the lock module and cross-process behaviour but not full MCP initialization, tool listing, tool rejection, or holder turnover.
  reason: Fair. Those paths ARE exercised, but by hand against the live daemon rather than in the suite — handshake, vault_status only, vault-tool rejection, and standing down for this machine's older-build holder. Worth turning into a spawned-server integration test; noted rather than done, and called out to the owner as the weakest part of the coverage.
- [round 4 F1] deferred: A rebuilt instance and a frozen pre-socket instance can both serve if they interleave around the old build's non-atomic pid-file check and write.
  reason: Confirmed, and NOT FIXABLE FROM THIS REPOSITORY. The race lives in code already installed elsewhere: an older build does existsSync, then readFile, then writeFile with no atomicity, and nothing a new build does can make another process's check-then-write atomic. Binding first and honouring the pid file narrows the window but cannot close it. The actual remedy is to stop having two versions — which is what publishing this and updating the frozen copies achieves. Raised to the owner explicitly rather than closed, because it means the invariant is not fully restored box-wide until every copy is updated.
- [round 6 F3] rejected: the tool API does not match the spec's vault_ssh_exec(entry_id, host, argv[], purpose)
  reason: the spec is stale, not the code. That exact signature IS round 1's F2 bug — an argv carrying its own destination alongside an advisory host field. Changing the API was the fix. Updating SPEC.md to match rather than reintroducing the vulnerability.
- [round 9 F3] rejected: a server-approved private origin is refused because the local store is empty after upgrade
  reason: already fixed before this review landed. Approvals were moved back server-side after the plan review found that a local approvals file let the agent forge its own. server.ts reads them from the entry again.
- [round 9 F5] rejected: bracketed IPv6 approvals do not round-trip through revoke
  reason: the approval API no longer exists in this module — it was deleted, not deprecated, after the plan review. The bracket bug is real in principle and will apply when approvals are rebuilt on a daemon-owned path; noted for that build.
- [round 9 F6] deferred: the token scheme has no verifier and conflicts with ProtectHome
  reason: correct, and my own plan contradicted itself here. Part B is not built. It is recorded as unresolved rather than papered over: SO_PEERCRED also reports PID and GID, not just uid as I claimed, so it is strictly stronger than a copyable bearer token.
- [round 9 F7] deferred: opt-in email for unattended runs is described but not built
  reason: true. The package describes a capability that does not exist yet. Recorded as not-built rather than claimed; the terminal channels are what works today, and an unattended run genuinely has no notice until this lands.
- [round 11 F1] deferred: On a real install the owner cannot traverse the 0770 mgmt directory, so --migrate and --destinations fail
  reason: CONFIRMED, and proved the mechanism locally against /var/cache/cups (root:lp 0770) -> Permission denied. Deferred to the same change as F2, not because it is minor but because the obvious fix (usermod -aG wundervault) hands F2's re-key attack to every agent: agents run as the owner's uid, so any permission the owner has the agent has. Needs the owner's decision on the read side; see the question put to the user.
- [round 11 F2] deferred: register_profile accepts no setup token; B2/B3/check 7 unimplemented
  reason: CONFIRMED. registerProfile (agent.ts:200) overwrites an existing profile by name INCLUDING socket_token, so whoever reaches the mgmt socket can re-key an agent and read its credentials off the per-agent socket. Fix is an auth redesign spanning onboard.py in the burnbox repo; putting the shape to the owner before building it rather than guessing.
- [round 11 B2] deferred: No test runs the installed unit with two real uids under the real systemd sandbox
  reason: Correct, and it is the reason every one of these blockers survived 366 passing tests. A real two-uid install test is the next piece of work, but it needs the install to be performed on this machine first - which is the owner's call, not mine.
- [round 11 B5] deferred: Agent names and sockets are machine-global across multiple human users
  reason: Real, but out of scope for this spec: the product targets one human per machine today and the spec's C5 already states one uid is one principal. Noted for the owner.
- [round 12 F1] rejected: Telling the user to sudo npm install into /usr/local contradicts G1's single privileged step
  reason: REJECTED on the security merits. The reviewer's implied alternative - accept the home path and bind-mount it back past ProtectHome - is worse than the problem: a directory under the user's home is writable by everything running as that user, agents included, so the daemon would execute code its own agents can replace. That hands over the process guarding the credentials, not just the credentials. G1 scopes what the INSTALLER does; where the package itself lives is a separate, pre-existing choice. Kept the refusal and added the reasoning to the message so nobody 'fixes' it later.
