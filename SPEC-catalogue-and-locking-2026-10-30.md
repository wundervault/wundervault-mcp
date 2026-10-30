# SPEC — C: service catalogue + named parts · L: lock names and setups away from our server (2026-10-30, rev 1)

Parts 2 and 3 of the release that ships U + C + L TOGETHER (owner 2026-10-30). U is
`SPEC-update-now-2026-10-30.md`. Decisions are in memory
`project_wundervault_catalogue_sealed_setup_2026_10_30`; this spec turns them into work.

Built in low-token mode: oai writes the code from this spec, Claude verifies. Claude reads every line
of the sealing code (browser `vault-seal.js`, broker `setup-seal.ts`), the lock endpoint and the
migration, because they decide what our server can read.

The field map behind §L3 is in the session scratchpad (`lmap/out/server-yes.txt`, 241 server-side
uses, grouped below). Line numbers are the site worktree `~/wv-build/site-update` at 62a8037 and
the MCP worktree `~/wv-build/mcp-brand` at 7a63849.

## rev 1 = rev 0 + the design review (`.buildreview-cl/round-0-triage.json`). Where the text below disagrees, THIS LIST WINS.

1. **Agent setup is the whole policy.** `setup` (agent copy) = `{v:1, rev, value_sha256, value_format,
   name, shape, service, delivery, binding, ssh_hosts, private_origins, known_addresses, approval,
   operations, chain}`. `known_addresses` (from the catalogue or added by the owner) skip the tier-1
   first-sighting notice; every other public destination behaves exactly as today. A setup that does
   not open, or fails `vault-setup` rules, refuses use (never "unrestricted").
2. **No downgrade.** The broker keeps a state file (`setup-pins.json`, broker-owned, 0600):
   per account `sealed_seen: true` once it has opened any sealed setup on it, and per entry the
   highest `rev` opened. With `sealed_seen`, an entry without `setup_ciphertext` is refused; a `rev`
   lower than the pinned one is refused. (The browser is served by us — known limit, not fixed here.)
3. **Value and setup are bound.** `value_sha256` = SHA-256 of the exact value ciphertext bytes the
   setup goes with; the broker refuses a mismatch. The browser reseals the setup (rev + 1) whenever it
   sends a new value to that agent.
4. **Format is external, never sniffed.** `value_format` = `raw` | `parts-1`. Absent (every
   pre-release entry) = `raw`: the whole value is the single part (`key`, or `private_key` for
   ssh/wallet/sign) whatever it contains — JSON included. `parts-1` values must parse as
   `{"parts":{…}}` or are refused.
5. **v1 bindings stay readable forever** in the broker, unchanged (including `{basic}` + username).
   Only the tidy-up converts them (moving the username into a `password`-shape part), on Save.
6. **Old brokers never get what they can't read.** A `parts-1` value or a v2 binding goes only to
   agents whose broker reports ≥ this release; for others the browser says "Update this computer
   first" (Update now) and sends nothing. Single-part keys keep the v1 binding for old brokers.
7. **Revisions and lock.** Every L1 row gets `rev` (int, bumped by every write). A sealed blob carries
   the `rev` it was sealed at (in AAD: `…|<row id>|<rev>`). `POST /dashboard/vault/lock` carries
   `{row id: rev}` for every row and commits only if every row's current `rev` matches and has a blob;
   otherwise it changes nothing and returns the rows to reseal.
8. **Lock and the activity chain.** In the lock transaction the server (it holds the audit key)
   verifies the account's whole chain, appends a `vault_locked` checkpoint row (head MAC, row count),
   then re-MACs the earlier rows under canonical `V4` (`label_ciphertext` in place of `target_label`).
   Rows written after the lock are V4 only. Server-written rows (expiry sweep, refusals) carry NO label;
   the browser shows the key's current name from `secret_id`.
9. **Tier-2 after lock.** The broker generates the request id (uuid4 hex) and sends
   `detail_ciphertext` (name, kind, origin, method, path, reason; sealed with its vault key, AAD
   `wv-t2-1|<agent>|<request id>`) plus `match_mac` = HMAC-SHA256(vault_key, `kind|entry|origin|method|path`).
   The server matches pending/approved requests on `match_mac` only. The browser opens the details,
   recomputes `match_mac`, and refuses to approve on a mismatch or a kind the sealed setup doesn't
   allow. At lock: pending requests and unused destination-bound grants are expired and their
   plaintext cleared; time windows (agent + secret) survive.
10. **Ids before sealing.** New secrets and entries get browser-generated ids (uuid4 hex), checked
    by the server for format and uniqueness (same pattern as U's order ids).
11. **List without spending.** `GET /agent/vault/secrets` returns `setup_ciphertext`/`setup_nonce`/`rev`
    per entry, no value, no approval spent, no email.
12. **Sizes are UTF-8 bytes.** Padding buckets 256 B · 1 KiB · 4 KiB · 16 KiB · 64 KiB · 128 KiB ·
    256 KiB · 512 KiB; larger is refused before sealing (signature details may be 72 KiB, `agent.py`
    498–500; signed operations may be 256 KiB, `dashboard.py` 1543–1544, kept as a map of op id →
    {definition, signature} with `definition.op` equal to its key, ≤ 50 ops).
17. **Server logs name nothing.** Log lines that carry a key's name, op ids, header names, hosts
    or origins (e.g. `dashboard.py` 1617 `ops=sorted(ops.keys())`) log ids and counts instead; a
    test greps every `log.*(` call site in the routes L touches.
13. **History.** Each owner-copy value version seals its own `value_format` + part ids; restoring a
    version is refused if the current setup places a part that version lacks (message says which).
14. **Redaction:** the broker scrubs, longest first, every form of every part plus the composed basic
    token, in bodies, headers and error text.
15. **Lock needs no new gesture:** it rides on the unlock's passkey check if that is ≤ 5 min old
    (`require_passkey_check`); otherwise it waits for the next unlock. (Lock is guarded because a
    session holder without the vault key could otherwise upload junk blobs and erase the names.)
16. **Deferred, told the owner:** tier-2 approval of a WEB key still rests on our server's verdict
    (`broker-ops.ts` 396–450); wallets, signers and stamped keys already use owner-sealed approvals.
    Its own build.

### Formats (exact bytes — browser and broker are built separately and must interoperate)

All sealing is AES-256-GCM, 12-byte random nonce, tag appended to the ciphertext; fields are
standard base64. Keys are HKDF-SHA256 subkeys, never the raw key:

| blob | key | AAD (UTF-8) |
|---|---|---|
| owner meta | HKDF(ikm = escrow key, salt = `meta_salt` (16 random bytes, stored), info = `wundervault-v1-meta`) | `wv-meta-1\|<user_id>\|<secret_id>\|<rev>` |
| activity label | HKDF(escrow key, salt = `label_salt` (16 random, stored), info = `wundervault-v1-label`) | `wv-label-1\|<user_id>\|<secret_id>` |
| agent setup | HKDF(ikm = agent vault_key, salt = 32 zero bytes, info = `wv-setup-1`) | `wv-setup-1\|<agent_id>\|<entry_id>\|<rev>` |
| tier-2 detail | HKDF(vault_key, 32 zero bytes, info = `wv-t2-1`) | `wv-t2-1\|<agent_id>\|<request_id>` |
| tier-2 match | HMAC-SHA256 key = HKDF(vault_key, 32 zero bytes, info = `wv-t2-match-1`) | — ; message = `kind\norigin\nmethod\npath\nentry_id` (no field may contain `\n`); output lowercase hex |

Plaintext = UTF-8 JSON, then 0x20 spaces appended up to the bucket (rev 1 item 12); the reader
`JSON.parse`s the trimmed text and refuses unknown top-level keys and a `v` other than 1. The
setup's `rev` inside the plaintext must equal the `rev` in the AAD and in the response. Ids are
`^[0-9a-f]{32}$` (new) or the existing id format (old rows). Test vectors (fixed key, nonce,
plaintext → ciphertext) live in `test/vectors/setup-v1.json` in the MCP repo and are copied
byte-for-byte into the site's node tests; both sides must pass the same vectors.

### Shapes × delivery (allowed combinations; anything else refused in browser and broker)

| shape | http | ssh | wallet | sign | parts placed |
|---|---|---|---|---|---|
| api_key | ✓ (header/query/path) | | | | `key` |
| key_id | ✓ (1–2 placements, or basic) | | | | `id` and/or `secret` |
| signed_set | ✓ (`stamp` only, no placements) | | | | all, by the recipe's part map |
| password | ✓ (basic only) or stored-only | | | | `username`+`password` via `{basic:username:password}` |
| website_login | stored-only | | | | none |
| ssh_key | | ✓ | | | `private_key` |
| wallet | | | ✓ | | `private_key` |
| signing_key | | | | ✓ | `private_key` |

A `signed_set` names its parts after the recipe's inputs (oauth1: `consumer_key`, `consumer_secret`,
`token`, `token_secret`); the stamp exception to C3's placeholder rule is explicit.

## Decisions taken in this spec (Claude, technical; the owner's decisions are not reopened)

- **The sealed setup is complete.** The browser expands a catalogue entry into the full setup
  (parts, placements, allowed addresses, approval) and seals that. The broker never consults the
  catalogue, so a catalogue change can never change what an existing key does, and the broker
  does not need to bundle it. (The owner's "bundled in page + broker" was about *no per-service
  fetch*; that still holds — the page bundles it, nothing fetches per service.)
- **Old agent apps keep working.** They get the entry list from the broker (`list_entries`), not
  from our server, so the new broker unseals locally and answers in today's shape (`secret_name`
  included). Only brokers must be on the new version before an account locks.
- **Owner 2026-10-30: keep the gate bit** (§L2) — one plaintext `gate` = `fetch` | `operation` per key.

## Steps for the person (the yardstick)

| | Today | After this release |
|---|---|---|
| Add a key for a known service (e.g. Alpaca) | Pick "web key" · type a name · paste the value · open "How is it sent" · choose header/query/path · type the header name · type the template · (for a 2nd part: impossible, or hand-typed JSON) · add allowed addresses · save | Type "Alp…" · pick **Alpaca** · paste into **Key ID** and **Secret key** (the service's own labels) · save. Name, placements, addresses, approval come from the catalogue; all editable. |
| Add a key for an unknown service | as above | **Something else** → pick a shape → paste → "How is it sent" (today's form, one placement per part) → save. Same count as today, never more. |
| Existing vault | — | **One-time tidy-up** (owner-decided): a card lists keys the vault can file better; each row has **File it** / **Leave as is**. Skipping it changes nothing. |
| Emails | Subject names the key | Names nothing unless the owner turns on "Name my keys in emails" (Settings). One tap to see which key. Accepted cost. |
| Locking | — | No step. Happens on the owner's next unlock after every broker on the account reports this version. |

Net: fewer steps for known services, equal for unknown ones, one optional one-time card.

---

## C — shapes, named parts, catalogue

### C1. Shapes (fixed, in code, same in browser and broker)

| shape id | parts (id: default label) | sent as |
|---|---|---|
| `api_key` | `key`: Key | 1 placement |
| `key_id` | `id`: ID · `secret`: Secret | 1–2 placements; either part may also be used as basic-auth user/password |
| `signed_set` | 2–4 named parts (e.g. X: consumer key/secret, access token/secret) | a stamp recipe (existing oauth1 stamp) — no placement |
| `password` | `username`: Username · `password`: Password | basic auth, or not sent over the web (stored for the coming features) |
| `website_login` | `username`, `password`, optional `totp` | not sent by the broker yet (coming features); stored and listed |
| `ssh_key` | `private_key` | SSH agent (existing) |
| `wallet` | `private_key` | wallet (existing) |
| `signing_key` | `private_key` | sign (existing) |

Part ids match `^[a-z][a-z0-9_]{0,31}$`; at most 4 parts; each value ≤ 16 KB; the whole sealed
value ≤ 64 KB (the current limit). Labels are display text only.

### C2. The sealed value with parts

Inside the value ciphertext (already sealed today; format unchanged on the wire):

```json
{"wv":"parts-1","shape":"key_id","parts":{"id":"PK…","secret":"…"}}
```

A value that is not this JSON (every value saved before this release) reads as
`{"shape":"api_key","parts":{"key":<the whole value>}}`, or for ssh/wallet/sign entries
`{"shape":<that>,"parts":{"private_key":<value>}}`. The broker reads both forever. A value that
parses as JSON but has `wv` other than `parts-1` is refused (no guessing).

### C3. Placements (binding v2)

The binding becomes a list; v1 (one object with `{secret}`/`{basic}`) reads as a one-item list
whose placeholder names the single part.

```json
{"v":2,"placements":[
  {"in":"header","name":"apca-api-key-id","template":"{part:id}"},
  {"in":"header","name":"apca-api-secret-key","template":"{part:secret}"}]}
```

- `in`: `header` | `query` | `path` (path: at most one placement, rules as today) | `stamp` (alone).
- `template`: printable, ≤ 128 chars, exactly ONE placeholder: `{part:<id>}` or
  `{basic:<user-id>:<pass-id>}` (header only).
- 1–4 placements. Every part of the shape that is placed must exist; a part may be placed at most
  once; two placements may not target the same header or query name (case-insensitive).
- Every existing rule still applies per placement (`FORBIDDEN_HEADERS`, name syntax, path dot
  segments, `validateAgentHeaders` refusing agent headers that collide with ANY placement).
- **Redaction covers every part:** `secretForms` returns the forms of every part (raw, URL-encoded,
  base64 where basic is used), so a response echoing either half of a key+ID is scrubbed.

### C4. Catalogue file

`app/static/catalogue/services.json` (site) — one file, same bytes for everyone, loaded with the
vault page (no per-service request, no logos, no third-party fetch). Entry:

```json
{"id":"alpaca","name":"Alpaca","shape":"key_id",
 "labels":{"id":"Key ID","secret":"Secret key"},
 "placements":[…as C3…],
 "addresses":["https://api.alpaca.markets","https://paper-api.alpaca.markets","https://data.alpaca.markets"],
 "approval":"first_use","help":"https://docs.alpaca.markets/docs/authentication"}
```

- `addresses`: exact `scheme://host[:port]` origins, sealed into the setup as pre-approved, so the
  first call to them asks nobody and tells us nothing.
- `help` is shown as text with a link the owner may click; nothing fetches it.
- Starting list (each checked against the service's own docs before it goes in; an entry we can't
  confirm stays out): OpenAI, Anthropic, Google Gemini, Mistral, Groq, OpenRouter, GitHub (token),
  GitLab, Cloudflare (API token), Cloudflare (global key = email + key), Alpaca, SnapTrade, Stripe,
  Resend, SendGrid, Postmark, Twilio (SID + token as basic), Telegram bot (path `/bot{part:key}`),
  Slack webhook (path), Discord webhook (path), Notion, Linear, Airtable, Listmonk (basic),
  X (signed set, the existing oauth1 recipe), Brave Search, Tavily, ElevenLabs. ≤ 40 entries.
- A unit test validates every entry with the SAME validator the browser uses for a hand-made setup
  (C3 rules + address syntax), and fails on duplicates ids/names.

### C5. Add flow (vault page)

`Add a key` → search box over catalogue names (local filter) → pick → boxes labelled from
`labels` → optional name (default = service name; a second Alpaca becomes "Alpaca 2") → Save.
"Customise" opens today's form prefilled. **Something else** → shape picker (C1) → today's "How is it
sent" form, one placement row per part, "Add another placement" up to 4. No hand-typed JSON anywhere.

### C6. One-time tidy-up

A card on the vault home, shown while at least one key matches a rule and has not been answered:

- name matches a catalogue service (case-insensitive word match) and the setup equals that
  service's placements → "File as <service>" (no value change);
- name carries the second part ("Alpaca PKXXXX…" — a token ≥ 12 chars in the name that the
  service's other part matches by pattern) → "Split into <labels>": moves that token from the
  name into the part; shows both boxes before saving;
- an SSH/PEM private key filed as a web key (`looksLikePrivateKey`) → "File as signing key / SSH key";
- a password-like entry with a username in its name → "File as password".

Each row: **File it** (opens the prefilled form; nothing saves without Save) / **Leave as is**
(remembered, sealed in the owner's settings). The card never changes a value on its own.

---

## L — lock names and setups away from our server

### L1. What gets sealed, with which key

| Row | New column | Sealed with | Contains |
|---|---|---|---|
| `persistent_secrets` (owner copy) | `meta_ciphertext`, `meta_nonce`, `meta_salt` | a key derived from the owner's escrow key exactly as the value's is (`WundervaultCrypto.deriveContentKey(escrow, salt)`, `vault-app.js` 2180), with its own salt | name, tags, shape, service id, part ids, usage (how sent, addresses, approval), tidy-up answers, optional email label flag |
| `agent_vault_entries` (each agent's copy) | `setup_ciphertext`, `setup_nonce` | that agent's `vault_key` (as the value is) | name, shape, service id, delivery (`http`/`ssh`/`wallet`/`sign`), binding v2, `ssh_hosts`, `allowed_private_origins`, signed `operations`, wallet chain |
| `secret_access_log` | `label_ciphertext` (+ nonce, salt) | derived from the escrow key, as above | the key's name at the time |
| `tier2_requests` | `detail_ciphertext` (+ nonce) | the requesting agent's `vault_key` (sealed by the broker) | name, destination, the agent's reason |

- AES-256-GCM, 12-byte random nonce, AAD = `wv-meta-1|<user_id>|<row id>` (resp. `wv-setup-1|<agent_id>|<entry id>`,
  `wv-label-1|<user_id>|<log id>`, `wv-t2-1|<agent_id>|<request id>`), so a blob moved to another row
  or account fails to open.
- Plaintext JSON is padded with spaces to the next of 256 · 1 KB · 4 KB · 16 KB · 64 KB before
  sealing, so sizes say little.
- **Server keeps:** ids, which agent has which entry, tier, timing, counts, `policy_ciphertext`
  presence, broker/agent versions, and the gate bit (L2). Nothing else about a key.

### L2. The gate bit — owner decided 2026-10-30: keep it

Today the server decides where a tier-2 key is gated from the plaintext mode
(`app/routes/agent.py:253` `gated_at_fetch = entry_mode not in (WALLET, SIGN)`): wallets and signing
keys are approved at operation-check, everything else at fetch. Without the mode it can't choose.

- **Recommended:** keep one plaintext field `gate` = `fetch` | `operation`, set by the browser.
  It says "this key is a wallet or a signer" — the server already guesses that from
  `policy_ciphertext` — and nothing about which service. A server that lies about it gains nothing
  it lacks today (it already hands out the ciphertext and runs the tier-2 gate).
- **If the owner says no:** every tier-2 use goes through operation-check before fetch (one gate
  point for all kinds), and fetch requires a fresh approved check for that (agent, entry). More
  code, one extra server round-trip per tier-2 call, no extra steps for the person.

### L3. Server behaviour that moves (from the field map)

| # | Today (file:line) | After |
|---|---|---|
| a | Save-time checks: `delivery.validate_binding/…path…/validate_ssh_hosts/build/describe` (delivery.py 51–245), `vault_meta.validate_tags` (33–53), name length (api.py 774, 1019) | Browser module `vault-setup.js` (port of delivery.py + C3) checks before sealing; the broker re-checks on use (it already does: `src/delivery.ts`). Server checks only blob format and size bounds. |
| b | Approval kind from mode: `agent.py _check_approval_kind` 748–815; `dashboard.py _policy_kind` 414–422, `_decide_approval_kind` 448, `set_entry_policy` 1531 | The broker names the kind from its sealed setup; the owner's browser opens the setup and refuses a mismatched kind before sealing an approval; the broker verifies the owner-sealed approval as today. Server checks only that `kind` is a known value. |
| c | Fetch refusal by mode (`agent.py` 194–231) | Every entry requires a verified broker signature (no mode needed). The hand-over refusal stays only for unlocked accounts with a legacy row. |
| d | `gated_at_fetch` (agent.py 253) | the `gate` bit (L2) |
| e | Emails name the key: `email.py send_new_destination_email` 451–492, `send_tier2_request_email` 504–555; callers `agent.py` 719, 861, 914, 1118 | Subject/body say "one of your keys" + agent name + a link to the request. Opt-in "Name my keys in emails" (Settings, default off): the browser stores a separate plaintext `email_label` per key, set from the name at save; turning it off deletes every `email_label`. |
| f | Activity text carries names: `audit._lookup_label` 184; purpose strings api.py 995, vault_app.py 365/406/408/522, dashboard.py 2644, vault_meta.py 100/140/242/244 | `target_label` → `label_ciphertext` (browser seals at the owner's action; for server-written rows — expiry sweep, refusals — the label is copied from the key's current `meta_ciphertext`, which the server can copy but not read). Purpose strings stop interpolating names ("Ended access for Editor"). The MAC chain covers `label_ciphertext` instead of `target_label`. |
| g | Activity view: `audit_view.subject_name` 69–74 ("now X"), `display_purpose` 51–54; CSV export `dashboard.get_audit_logs` 823 | Browser opens labels, computes "now X", and builds the CSV (same columns, same `csv_safe` rule ported). |
| h | Listing/sorting/descriptions: `vault_app.vault_overview` 95 (ORDER BY name), 158–183 (`how_sent`), `dashboard.list_vault_entries` 2686, `agent_vault_exposure_report` 2114–2206, `agent_vault_mode_counts` 1759–1769 | Server returns rows in id order with blobs; browser opens, sorts, describes. Exposure report built in the browser. Mode counts dropped (the browser counts). |
| i | Re-key nonce-reuse error lists names (dashboard.py 1938, 1957) | Lists entry ids; browser maps them to names. |
| j | Create-retry hash includes the name (api.py 802–890) | Hash includes `meta_ciphertext` instead — same logic. |
| k | Tier-2 rows keep `secret_name`, destination, purpose | Broker seals them into `detail_ciphertext`; the owner's browser opens them; spent approvals drop the blob (as today they drop destination + reason). |
| l | Private origins set/normalised on the server (dashboard.py 1661–1672) | Browser validates + seals in the setup; broker enforces (already). |
| m | Signed operations stored plain (`agent.py` 140–153, dashboard.py 1580–1598) | Sealed in the setup; the broker verifies their signatures (already). |
| n | Legacy readers: `main.py run_migration` 455–479, `delivery.convert_handover` 233–245, `agent._exec_config_is_sudo` 1172–1186, `send_to_agent_vault` 2562–2609 | Run only while an account is unlocked; a locked account has no plaintext to read and the code path refuses with a clear error. |
| o | `demo.py` fixture data | Rewritten in the new format (sealed with a demo key in the page). |

The MCP side (`src/api-client.ts`, `broker-ops.ts`, `delivery.ts`, `signing-ops.ts`, `ssh-agent.ts`,
`server.ts`) reads `secret_name`/`exec_config`/`entry_mode`/`operations`/`allowed_private_origins`
from server responses today; after this release it reads them from `setup_ciphertext` when present,
and from the plaintext fields when not (unlocked account).

### L4. Locking, per account, broker-first

1. **This release, every account:** the browser writes BOTH plaintext and sealed fields on every
   save; the broker prefers the sealed setup when present.
2. **Ready to lock** = every non-revoked broker key on the account has `broker_version ≥` this
   release, and no account-level legacy row (`LEGACY_EXEC`) remains.
3. **On the owner's next unlock** when ready: the browser seals any row missing its blob (owner
   copies, every agent copy it can reach, existing log labels), then calls
   `POST /dashboard/vault/lock` (passkey check + CSRF, same as Update now). The server, in one
   transaction: verifies every row has its blob, nulls every plaintext column of L1, sets
   `users.vault_locked_at`. From then on it refuses any request carrying those plaintext fields for
   that account (HTTP 409 `vault_locked`).
4. **New accounts** are created locked.
5. **A broker older than this release on a locked account** is refused at pairing and at fetch with
   `update_required` and the vault shows "Update this computer" (Update now if it has U, else the
   by-hand steps).
6. **There is no unlock.** A lost vault loses names as well as values (accepted cost).

### L5. Softeners (owner-accepted, small)

- **Copy a support report** (vault → Help): the browser assembles versions, counts, shapes, health
  results and recent error codes — never names, values, addresses — shows it, and copies it only on
  the owner's tap.
- **Health card** runs in the browser: for each key, does its setup pass `vault-setup.js`, does every
  agent copy open, is every broker on the version that can read it.
- **/privacy** says: we don't know which services you use; names, tags and setups are sealed; what
  we still keep (L1 list); emails name nothing unless you opt in.

---

## Acceptance checks

Each check names how it is proved. "DB scan" = dump every table of a test account to text and grep.

**C — catalogue and parts**
- C-1 Every catalogue entry passes the browser setup validator; ids and names unique (unit).
- C-2 A `parts-1` key+ID value with two header placements sends both headers on a real request to a
  local echo server through the real broker; the response echoing both parts comes back scrubbed (broker e2e).
- C-3 A value saved before this release (plain string) still works through the new broker (broker e2e).
- C-4 Refused at save in the browser AND at use in the broker: a placement naming a missing part; a
  part placed twice; two placements on the same header (any case); a forbidden header; a 5th
  placement; a `{basic}` in a query; a JSON value with `wv:"parts-2"` (unit, both sides).
- C-5 Adding Alpaca from the catalogue takes: search, pick, two pastes, Save — counted in a
  headless test that fails if the flow needs another required field.
- C-6 The tidy-up card never saves without Save; "Leave as is" survives reload and a second browser.
- C-7 The vault page loads the catalogue as one static file; no other request names a service
  (network log of a headless add-from-catalogue run).

**L — locking**
- L-1 **DB scan after locking**: none of a test account's key names, tags, header names, templates,
  basic usernames, SSH hosts, private origins, catalogue ids or operation ids appears anywhere in the
  database, including `secret_access_log` and `tier2_requests` (integration).
- L-2 **Two-user test**: a blob copied from user A's row into user B's row (or between two entries of
  one user) fails to open in the browser and in the broker (AAD) (unit + integration).
- L-3 Emails for a tier-2 request and a new destination, with opt-in off, contain no key name
  (captured Resend payload); with opt-in on they contain the email label; turning opt-in off clears
  every `email_label` (integration).
- L-4 `POST /dashboard/vault/lock` refuses while any broker key on the account is older than this
  release, or any row lacks its blob, and changes nothing in that case (integration).
- L-5 After locking, any write carrying a plaintext L1 field is refused with `vault_locked` (integration, every write route of L3).
- L-6 An old broker (2.1.0 build) on a locked account is refused with `update_required`; on an
  unlocked account it keeps working unchanged (integration with the real old build).
- L-7 An old agent app talking to the new broker gets `list_entries` in today's shape with names
  (broker test against the 2.1.0 `server.ts` parser).
- L-8 The activity chain verifies across the lock: rows written before (plaintext label) and after
  (sealed label) both verify; tampering with a `label_ciphertext` breaks the chain (unit).
- L-9 Tier-2 approve flow end to end on a locked account: the browser shows the name, destination and
  reason it opened; the server row holds only `detail_ciphertext`; a kind that doesn't match the
  sealed setup is refused by the browser and by the broker (integration + broker e2e).
- L-10 Activity CSV export built in the browser matches the old server CSV for an unlocked fixture
  account, byte for byte (unit).
- L-11 Padding: two keys whose setups differ in length within one bucket produce equal ciphertext
  lengths (unit).
- L-12 The support report contains no name, value or address of a fixture account (unit).

**Added in rev 1**
- L-13 Downgrade: after the broker has opened one sealed setup on the account, a response with the
  blob removed (plaintext supplied) is refused; so is a replayed lower `rev`; so is a value whose
  SHA-256 doesn't match `value_sha256` (broker unit + e2e, state file survives a restart).
- L-14 Legacy values: `{"token":"abc"}`, `[1,2]`, `123`, and a string that looks like a `parts-1`
  envelope, all saved before this release, are each sent as one opaque part (broker unit).
- L-15 A key+ID key added for an agent whose broker is 2.1.0: nothing is sent to that agent and the
  vault says "Update this computer first"; a single-part key to the same agent still works with the
  real 2.1.0 build (integration).
- L-16 Lock race: a save between backfill and lock makes the lock change nothing and return that row;
  a retry with the resealed row succeeds (integration).
- L-17 Chain across lock: verify passes after the lock with the plaintext labels gone; editing any
  pre-lock row's `label_ciphertext` or the checkpoint fails it (unit, on a migrated DB).
- L-18 Tier-2 on a locked account: an approval granted for `GET /status` does not let `POST /transfer`
  through (different `match_mac`); a request whose sealed details don't hash to its `match_mac` is
  refused by the browser (integration).
- L-19 Redaction: a response echoing the `id` part, the `secret` part, or the composed basic token
  comes back scrubbed in every case (broker unit).
- C-5 (widened) Step counts for three journeys are asserted in headless tests: catalogue add (search,
  pick, pastes, Save), unknown service (Something else + shape replaces today's kind pick — same
  count), lock (no gesture beyond unlock).

**Release**
- R-1 Steps table above re-counted on the built UI; no step added.
- R-2 Two `/buildreview` rounds over C+L (four areas: browser sealing + forms; server routes +
  lock + migration; broker reading both formats; catalogue + emails), plus the U interop re-run.

## Out of scope (named so nobody builds them by accident)

Google/Microsoft OAuth accounts, databases, AWS SigV4, website-login filling and the other coming
features, installers (.pkg/.msi), changing an account back to unlocked.
