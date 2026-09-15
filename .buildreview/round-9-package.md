# Review package — round 9
generated 2026-09-15T05:02:39+00:00

## Spec — judge the build against THIS

# PLAN — local network shape, then the uid split on three platforms

Review the PLAN, not an implementation. One module exists (`src/network-store.ts`);
everything else below is proposed.

## Context a reviewer needs

Wundervault is a secrets vault for AI agents. The server is genuinely blind to secret
contents — the browser generates a per-agent vault key and the server holds only
ciphertext and wrapped keys. Built so far, all local, none shipped:

- an **ssh-agent broker** — the key answers signature requests and never touches disk
- **`vault_call`** — the daemon performs a typed or agent-described HTTP request; the
  credential is attached by the daemon and never returned
- **`entry_mode`** — per-entry, non-null: `LEGACY_EXEC` | `BROKER_SSH_AGENT` | `BROKER_HTTP`
- **tiering**: Tier 1 brokers with no approval; Tier 2 refuses into an owner approval
  scoped to the exact origin, method and path

**The daemon currently runs as the SAME uid as the agent.** So none of this is a
confidentiality boundary yet: the agent can read the daemon's key files and memory. That
is stated in the code, not implied away.

---

# Part A — move the network shape off the server

## A1. What and why

Destinations are a behavioural profile: which services are called, how often, when, and
(for private origins) the customer's internal network addresses. None of it helps anyone
read a secret. All of it is competitive intelligence, and it is what a breach or a
subpoena reaches.

Proposal: **Tier 1 destinations never leave the customer's machine.** Tier 2 destinations
DO reach the server, because a human must review the request to approve it, and review
requires seeing it. That is consented disclosure of one call, not a standing profile.

## A2. What moves

| data | today | proposed |
|---|---|---|
| seen destinations (the "new destination" baseline) | server access log | local file |
| approved private origins | server, on the entry | local file |
| Tier 1 call destination | server access log | local only |
| Tier 1 fact-of-call (entry, agent, time) | server | **unchanged — stays server-side** |
| Tier 2 requested operation | server | unchanged — approval needs it |

Keeping the fact-of-call server-side preserves the tamper-evident, HMAC-chained audit
that already exists. Only the *where* becomes local.

## A3. The honest limit

The local file lives in the agent's home directory and is writable by the agent's uid, so
**a compromised agent can edit its own record of where it sent things.** The party being
audited controls the evidence. This is therefore a privacy improvement and NOT an
integrity control until Part B moves it to a daemon-owned path.

Stated plainly rather than papered over, because shipping it as "local audit log" would
claim something it does not do.

## A4. Alerting, and one unresolved choice

The daemon detects a first sighting locally. To email the owner, the server must be told.
Two options, and we have not chosen:

1. **Server relays, does not store.** The email names the destination; the server handles
   it transiently. Better UX, weaker claim ("we never store it" rather than "we never see
   it").
2. **Server knows only that something is new.** The email says a secret went somewhere
   new and to check locally (`wundervault destinations`). Purest, materially worse.

**Reviewer: which is defensible, and is option 1's distinction honest or a fig leaf?**

## A5. Also proposed

- shorter retention option (7 days) for the server-side log
- an explicit off switch for destination recording, accepting that it disables alerting —
  the metadata IS the control, so opting out of one opts out of both

---

# Part B — the uid split, three platforms

## B1. Linux (first)

- system account `wundervault`; key material in `/var/lib/wundervault`, mode 0700
- systemd **system** unit, hardened: `NoNewPrivileges`, empty `CapabilityBoundingSet`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `RestrictSUIDSGID`, `LimitCORE=0`,
  `ReadWritePaths=/var/lib/wundervault`, process non-dumpable
- the local network store moves here and becomes an integrity control
- **one privileged install per machine; enrolment stays unprivileged**
- distribution: signed `.deb`/`.rpm`, verified before install. **Not `curl | sudo sh`** —
  the product's differentiator is a verifiable installer, and piping unverified network
  content to root destroys that

### B1a. Peer identity — a constraint worth flagging

**Node has no `SO_PEERCRED`.** Verified: `net.Socket` exposes no peer credentials, and a
native addon would put a compiled dependency into an npm package whose selling point is
that you can read and verify it.

Proposal: authenticate with the **per-agent token that already exists**
(`~/.wundervault/agents/<name>.token`, mode 0600, 32 random bytes, written at enrolment).
After the split it lives in the agent's home, readable only by the agent's uid, so the
socket can be world-connectable and the token is the identity.

This gives **uid-level identity** — the same granularity `SO_PEERCRED` offers on Linux
anyway, since that only reports a uid. One uid is one security principal: two agents
under one uid cannot be told apart, by us or by the kernel.

**Reviewer: is token-in-file equivalent to `SO_PEERCRED` here, or is there a gap?**

## B2. macOS (second) — possibly without sudo

macOS offers what Linux does not:

- **Keychain ACLs** bind a secret to a specific *signed binary*. Another program running
  as the same user cannot read it.
- **Hardened runtime** blocks `task_for_pid` against signed processes, so reading the
  daemon's memory is genuinely hard rather than trivial.
- Over a Mach port, the daemon can obtain the caller's **audit token and verify its code
  signature** — "which program is this", not merely "which user".

So the strong claim may be reachable on macOS **without a privileged install**, trading
sudo for an Apple Developer account, notarisation and a signed release pipeline.

**Reviewer: is signing + Keychain ACL + hardened runtime genuinely comparable to uid
separation, or does it just raise the bar?**

## B3. Windows (last)

Service account via the SCM (requires administrator); named pipes with security
descriptors; **Authenticode verification of the connecting process**; DPAPI for binding
secrets to a user or machine.

## B4. The asymmetry

The platform where a privileged install is unavoidable (Linux) is the platform with the
weakest peer check. 1Password lands in the same place: their macOS and Windows checks
verify code signatures; their Linux check is group membership.

**Reviewer: is "macOS strong via signing, Linux strong via sudo" a coherent product
position, or does a split guarantee confuse customers into assuming the weaker one?**

---

# Sequencing

1. Part A local store + alerting + off switch  ← module written, rest proposed
2. Part B Linux
3. Migration: fresh key hierarchy, re-wrap to a device key, rotate exposed upstream
   credentials (breaking; affordable now at one active user)
4. macOS
5. Windows

# Specific questions

1. A4 — relay-but-not-store, or tell-them-nothing?
2. B1a — is the token equivalent to `SO_PEERCRED`, or is there a gap?
3. Does keeping fact-of-call server-side while destination goes local actually buy
   privacy, or is the correlation enough to reconstruct the profile anyway?
4. Is the A3 caveat (agent can edit its own local record pre-split) acceptable to ship,
   given it is documented?
5. B2 — is macOS signing genuinely comparable to uid separation?
6. What breaks first when a second customer arrives, given the local store is per-machine
   and one uid is one principal?
7. Anything in this plan that is the wrong shape, not merely incomplete.


## What was built this round, and how it was tested

Part A round 1: the local network store, plus the notice channels. Destinations and private-origin approvals now live on the customer's machine; the server is never told where a Tier 1 secret goes. First sightings are surfaced on stderr (which never passes through the model, so an agent cannot suppress it) and in the tool result (so the agent can explain it in context). Email becomes opt-in for unattended runs, labelled as the option that relays the destination. Tested: 287 pass, 30 new, every test against a temp store. Verified atomic write-then-rename, 0600, corrupt-file recovery, future-version rejection, per-entry and per-origin separation, port sensitivity, case-insensitivity, the approval cap, metadata refusal and revocation. STATED LIMIT I want judged rather than excused: the store sits in the agent's home and is writable by the agent's uid, so a compromised agent can edit its own record — privacy improvement, not integrity control, until the uid split moves it to a daemon-owned path. Is that acceptable to ship with the caveat documented, or disqualifying?

## Diff

```diff
diff --git a/src/network-store.ts b/src/network-store.ts
new file mode 100644
index 0000000..1cb0b00
--- /dev/null
+++ b/src/network-store.ts
@@ -0,0 +1,224 @@
+/**
+ * Where an agent's secrets go — held on the customer's machine, not on the server.
+ *
+ * Destinations are a behavioural profile: which services you call, how often, when, and
+ * (for approved private origins) your internal network addresses. None of that helps
+ * anyone read a secret, but it is competitive intelligence on its own and it is the kind
+ * of thing a breach or a subpoena reaches. "We cannot read your secrets" was always
+ * true; keeping this local makes "we do not know what you do with them" true as well.
+ *
+ * The split that makes this coherent:
+ *
+ *   Tier 1 — the destination NEVER leaves this machine. The server learns that a call
+ *            happened, not where it went.
+ *   Tier 2 — the destination IS sent, because the whole point of tier 2 is that a human
+ *            reviews the request, and they cannot review what they cannot see. That is
+ *            consented disclosure for one specific call, not a standing profile.
+ *
+ * HONEST LIMIT, and it is the important one: this file lives in the agent's own home
+ * directory and is writable by the agent's uid. A compromised agent can therefore edit
+ * its own record of where it sent things — the party being audited controls the
+ * evidence. That makes this a privacy improvement today and NOT an integrity control.
+ * It becomes one after the uid split, when the file moves to /var/lib/wundervault owned
+ * by a daemon account the agent cannot write to. The interface here does not change when
+ * that happens.
+ */
+import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
+import * as os from 'node:os';
+import * as path from 'node:path';
+
+export interface SeenDestination {
+  entryId: string;
+  origin: string;
+  firstSeen: string;
+  lastSeen: string;
+  count: number;
+}
+
+export interface NetworkShape {
+  version: 1;
+  seen: SeenDestination[];
+  /** entryId -> exact "scheme://host:port" strings the owner approved locally. */
+  approvedPrivateOrigins: Record<string, string[]>;
+}
+
+const EMPTY: NetworkShape = { version: 1, seen: [], approvedPrivateOrigins: {} };
+
+/** Bounded, so a long-lived install cannot grow this without limit. */
+const MAX_SEEN = 2000;
+const MAX_APPROVED_PER_ENTRY = 10;
+
+export function defaultStorePath(): string {
+  // After the uid split this becomes /var/lib/wundervault/network.json, owned by the
+  // daemon account. Same shape, same code — only the path and the owner change.
+  return process.env.WUNDERVAULT_NETWORK_STORE
+    || path.join(os.homedir(), '.wundervault', 'network.json');
+}
+
+export function load(storePath = defaultStorePath()): NetworkShape {
+  try {
+    if (!existsSync(storePath)) return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
+    const parsed = JSON.parse(readFileSync(storePath, 'utf8')) as NetworkShape;
+    if (!parsed || parsed.version !== 1) return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
+    return {
+      version: 1,
+      seen: Array.isArray(parsed.seen) ? parsed.seen : [],
+      approvedPrivateOrigins: (parsed.approvedPrivateOrigins && typeof parsed.approvedPrivateOrigins === 'object')
+        ? parsed.approvedPrivateOrigins : {},
+    };
+  } catch {
+    // A corrupt store must not break every vault call. Start clean rather than throw —
+    // the worst case is one spurious "new destination" notice.
+    return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
+  }
+}
+
+export function save(shape: NetworkShape, storePath = defaultStorePath()): void {
+  const dir = path.dirname(storePath);
+  mkdirSync(dir, { recursive: true, mode: 0o700 });
+  // Write-then-rename: a half-written store read by the next call would look like a
+  // cleared history, and every destination would alert again.
+  const tmp = `${storePath}.tmp-${process.pid}`;
+  writeFileSync(tmp, JSON.stringify(shape, null, 2), { mode: 0o600 });
+  renameSync(tmp, storePath);
+  try { chmodSync(storePath, 0o600); } catch { /* best effort */ }
+}
+
+/**
+ * Record a destination and say whether it had been seen before.
+ *
+ * Returns true the FIRST time an (entry, origin) pair appears. The caller uses that to
+ * raise a notice exactly once, rather than on every call to a familiar service.
+ */
+export function recordDestination(
+  entryId: string, origin: string, storePath = defaultStorePath(),
+): { isNew: boolean } {
+  const shape = load(storePath);
+  const now = new Date().toISOString();
+  const key = origin.trim().toLowerCase();
+
+  const existing = shape.seen.find((s) => s.entryId === entryId && s.origin === key);
+  if (existing) {
+    existing.count += 1;
+    existing.lastSeen = now;
+    save(shape, storePath);
+    return { isNew: false };
+  }
+
+  shape.seen.push({ entryId, origin: key, firstSeen: now, lastSeen: now, count: 1 });
+  // Oldest-first eviction. Evicting a record makes that destination read as new again,
+  // which raises one extra notice — the safe direction for a detective signal.
+  if (shape.seen.length > MAX_SEEN) {
+    shape.seen.sort((a, b) => a.lastSeen.localeCompare(b.lastSeen));
+    shape.seen = shape.seen.slice(shape.seen.length - MAX_SEEN);
+  }
+  save(shape, storePath);
+  return { isNew: true };
+}
+
+export function destinationsFor(entryId: string, storePath = defaultStorePath()): SeenDestination[] {
+  return load(storePath).seen.filter((s) => s.entryId === entryId);
+}
+
+// ── owner-approved private origins, held locally ───────────────────────────────
+
+/**
+ * Cloud metadata endpoints hand out instance credentials. No approval unlocks one,
+ * because it is not a decision anyone can meaningfully make on an agent's behalf.
+ */
+const NEVER_APPROVABLE = new Set(['169.254.169.254', 'fd00:ec2::254', '100.100.100.200', 'metadata.google.internal']);
+
+export function approvedPrivateOrigins(entryId: string, storePath = defaultStorePath()): string[] {
+  const list = load(storePath).approvedPrivateOrigins[entryId];
+  return Array.isArray(list) ? list.filter((s) => typeof s === 'string') : [];
+}
+
+export function approvePrivateOrigin(
+  entryId: string, origin: string, storePath = defaultStorePath(),
+): { ok: boolean; reason?: string; origins?: string[] } {
+  const m = /^(https?):\/\/([a-z0-9._\-[\]:]+?):(\d{1,5})$/i.exec(origin.trim());
+  if (!m) {
+    return { ok: false, reason: 'Origin must be exactly "scheme://host:port", for example https://10.0.0.5:9000. No ranges and no wildcards — a range is not something you can realistically evaluate.' };
+  }
+  const host = m[2].toLowerCase().replace(/^\[|\]$/g, '');
+  const port = Number(m[3]);
+  if (port < 1 || port > 65535) return { ok: false, reason: 'Port out of range.' };
+  if (NEVER_APPROVABLE.has(host)) {
+    return { ok: false, reason: `${host} is a cloud metadata endpoint. It hands out instance credentials, so it cannot be approved.` };
+  }
+
+  const shape = load(storePath);
+  const current = shape.approvedPrivateOrigins[entryId] ?? [];
+  const canonical = `${m[1].toLowerCase()}://${host}:${port}`;
+  if (current.includes(canonical)) return { ok: true, origins: current };
+  if (current.length >= MAX_APPROVED_PER_ENTRY) {
+    return { ok: false, reason: `This entry already approves ${MAX_APPROVED_PER_ENTRY} private origins.` };
+  }
+  shape.approvedPrivateOrigins[entryId] = [...current, canonical];
+  save(shape, storePath);
+  return { ok: true, origins: shape.approvedPrivateOrigins[entryId] };
+}
+
+export function revokePrivateOrigin(
+  entryId: string, origin: string, storePath = defaultStorePath(),
+): string[] {
+  const shape = load(storePath);
+  const canonical = origin.trim().toLowerCase();
+  const next = (shape.approvedPrivateOrigins[entryId] ?? []).filter((o) => o.toLowerCase() !== canonical);
+  if (next.length === 0) delete shape.approvedPrivateOrigins[entryId];
+  else shape.approvedPrivateOrigins[entryId] = next;
+  save(shape, storePath);
+  return next;
+}
+
+
+// ── telling the owner, without telling the server ──────────────────────────────
+
+export interface DestinationNotice {
+  /** For stderr — the model cannot suppress this. */
+  stderrLine: string;
+  /** For the tool result — the model reads this and can explain it in context. */
+  toolNote: string;
+}
+
+/**
+ * Compose the first-sighting notice.
+ *
+ * Two channels, deliberately, and the split matters:
+ *
+ *  - **stderr** goes from this process straight to the MCP client and never passes
+ *    through the model. A compromised agent can decide not to mention a tool result; it
+ *    cannot strip a line already written to stderr. That makes this the channel of
+ *    record.
+ *  - **the tool result** is how the agent explains it to you in the conversation, which
+ *    is where you are actually looking.
+ *
+ * Neither reaches the server. The destination stays on this machine, so the default
+ * install leaves the server knowing nothing about where a secret goes — no relay, no
+ * transient handling, nothing to store.
+ *
+ * The case this does NOT cover is an unattended run: a scheduled agent at 3am with
+ * nobody watching the terminal. Email covers that and is therefore opt-in, labelled as
+ * the choice that sends the destination to the server in order to deliver it.
+ */
+export function newDestinationNotice(
+  secretName: string, origin: string, method: string, path: string,
+): DestinationNotice {
+  const at = new Date().toISOString();
+  return {
+    stderrLine:
+      `[wundervault] NEW DESTINATION ${at} secret="${secretName}" ${method} ${origin}${path}\n`,
+    toolNote:
+      `⚠ First use of "${secretName}" against ${origin}.\n`
+      + `   ${method} ${origin}${path}\n`
+      + `   Tier 1 does not gate destinations, so this is a notice rather than a block. `
+      + `If you did not expect it, revoke this agent and rotate the secret at the provider. `
+      + `Moving the secret to Tier 2 makes each new request wait for approval.\n`
+      + `   Recorded on this machine only — the destination was not sent to the server.`,
+  };
+}
+
+/** Write the notice where the model cannot interfere with it. */
+export function emitToStderr(notice: DestinationNotice): void {
+  try { process.stderr.write(notice.stderrLine); } catch { /* never break a call over a log line */ }
+}
diff --git a/src/server.ts b/src/server.ts
index 18abd2a..0e39db4 100644
--- a/src/server.ts
+++ b/src/server.ts
@@ -17,6 +17,8 @@ import { createHash } from 'node:crypto';
 import { loadOpenSshEd25519, runSshBrokered, modeAllowsLegacyExec, modeAllowsSshBroker,
   modeAllowsHttpBroker, wrongModeMessage, type BrokeredOp } from './ssh-agent.js';
 import { verifyOperationDefinition, validateArguments } from './opdef.js';
+import { recordDestination, approvedPrivateOrigins as localApprovedOrigins,
+  newDestinationNotice, emitToStderr } from './network-store.js';
 import { definitionFromAgentRequest, originString, isApprovedPrivateOrigin, type AgentRequest } from './http-broker.js';
 import { performOperation } from './http-broker.js';
 import { runWithSecret, runWithSecretStdin, runWithSecretAskpass, runWithSecretRemote, runRsync, coerceExecConfig, resolveDeliveryConfig, isValidEnvKey, commandInvokesSudo } from './exec.js';
@@ -673,12 +675,21 @@ export function createServer(args: { url?: string } = {}) {
             );
           }
 
-          let approvedOrigins: string[] = [];
-          try {
-            const raw = secretData.allowed_private_origins as unknown;
-            const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
-            if (Array.isArray(parsed)) approvedOrigins = parsed.filter((x): x is string => typeof x === 'string');
-          } catch { approvedOrigins = []; }
+          // Approvals are read from the LOCAL store. They name the customer's internal
+          // addresses, which is exactly the kind of thing that should not sit in someone
+          // else's database.
+          const approvedOrigins = localApprovedOrigins(entry_id);
+
+          // Recorded here, on this machine. The server is never told where this went.
+          const originStr = originString(def.origin);
+          const { isNew } = recordDestination(entry_id, originStr);
+          let noticeForAgent = '';
+          if (isNew) {
+            const notice = newDestinationNotice(
+              secretData.name ?? entry_id, originStr, def.route.method, def.route.path);
+            emitToStderr(notice);
+            noticeForAgent = `\n\n${notice.toolNote}`;
+          }
 
           const result = await performOperation(
             def,
@@ -703,7 +714,7 @@ export function createServer(args: { url?: string } = {}) {
           return CallToolResultSchema.parse({
             content: [{ type: 'text', text:
               `✅ ${label} → HTTP ${result.status} (tier ${verdict.tier}). The credential was used here, not returned to you.\n`
-              + `${JSON.stringify(result.body, null, 2)}` }],
+              + `${JSON.stringify(result.body, null, 2)}${noticeForAgent}` }],
           });
         } finally {
           plaintextBytes.fill(0);
diff --git a/test/network-store.test.ts b/test/network-store.test.ts
new file mode 100644
index 0000000..00ad354
--- /dev/null
+++ b/test/network-store.test.ts
@@ -0,0 +1,175 @@
+/**
+ * Acceptance checks for the local network store (PLAN part A).
+ *
+ * Every test uses a temp store path, because the real one is the developer's own
+ * ~/.wundervault and a test must never touch it.
+ */
+import { describe, it, expect, beforeEach, afterEach } from 'vitest';
+import { mkdtempSync, rmSync, existsSync, statSync, writeFileSync, readFileSync } from 'node:fs';
+import * as os from 'node:os';
+import * as path from 'node:path';
+import {
+  load, save, recordDestination, destinationsFor,
+  approvePrivateOrigin, approvedPrivateOrigins, revokePrivateOrigin,
+  newDestinationNotice, defaultStorePath,
+} from '../src/network-store.js';
+
+let dir: string;
+let store: string;
+
+beforeEach(() => {
+  dir = mkdtempSync(path.join(os.tmpdir(), 'wv-net-'));
+  store = path.join(dir, 'network.json');
+});
+afterEach(() => { rmSync(dir, { recursive: true, force: true }); });
+
+describe('first-sighting detection', () => {
+  it('reports a destination as new exactly once', () => {
+    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(true);
+    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
+    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
+  });
+
+  it('separates entries, so one secret does not vouch for another', () => {
+    recordDestination('e1', 'https://api.cloudflare.com:443', store);
+    expect(recordDestination('e2', 'https://api.cloudflare.com:443', store).isNew).toBe(true);
+  });
+
+  it('separates origins', () => {
+    recordDestination('e1', 'https://api.cloudflare.com:443', store);
+    expect(recordDestination('e1', 'https://api.openai.com:443', store).isNew).toBe(true);
+  });
+
+  it('treats a port change as a different destination', () => {
+    recordDestination('e1', 'https://h.example:443', store);
+    expect(recordDestination('e1', 'https://h.example:8443', store).isNew).toBe(true);
+  });
+
+  it('is case-insensitive on the origin', () => {
+    recordDestination('e1', 'https://API.Cloudflare.com:443', store);
+    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
+  });
+
+  it('counts repeat use', () => {
+    for (let i = 0; i < 4; i += 1) recordDestination('e1', 'https://h.example:443', store);
+    expect(destinationsFor('e1', store)[0].count).toBe(4);
+  });
+});
+
+describe('durability', () => {
+  it('writes 0600 and survives a reload', () => {
+    recordDestination('e1', 'https://h.example:443', store);
+    expect(statSync(store).mode & 0o777).toBe(0o600);
+    expect(load(store).seen).toHaveLength(1);
+  });
+
+  it('leaves no temp file behind', () => {
+    recordDestination('e1', 'https://h.example:443', store);
+    const leftovers = require('node:fs').readdirSync(dir).filter((f: string) => f.includes('.tmp-'));
+    expect(leftovers).toEqual([]);
+  });
+
+  it('starts clean on a corrupt store rather than breaking every call', () => {
+    writeFileSync(store, '{{{not json');
+    expect(load(store).seen).toEqual([]);
+    // and can still be written afterwards
+    expect(recordDestination('e1', 'https://h.example:443', store).isNew).toBe(true);
+  });
+
+  it('ignores a store written by a future version', () => {
+    writeFileSync(store, JSON.stringify({ version: 99, seen: [{ entryId: 'x' }] }));
+    expect(load(store).seen).toEqual([]);
+  });
+});
+
+describe('locally approved private origins', () => {
+  it('accepts an exact scheme://host:port', () => {
+    const r = approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
+    expect(r.ok).toBe(true);
+    expect(approvedPrivateOrigins('e1', store)).toEqual(['https://10.0.0.5:9000']);
+  });
+
+  it('refuses a range or wildcard', () => {
+    // A range is not something an owner can realistically evaluate.
+    expect(approvePrivateOrigin('e1', 'https://10.0.0.0/24', store).ok).toBe(false);
+    expect(approvePrivateOrigin('e1', 'https://*.local:9000', store).ok).toBe(false);
+  });
+
+  it('refuses an origin with no port', () => {
+    expect(approvePrivateOrigin('e1', 'https://10.0.0.5', store).ok).toBe(false);
+  });
+
+  it('refuses cloud metadata endpoints outright', () => {
+    for (const h of ['169.254.169.254', 'metadata.google.internal', '100.100.100.200']) {
+      const r = approvePrivateOrigin('e1', `https://${h}:80`, store);
+      expect(r.ok).toBe(false);
+      expect(r.reason).toMatch(/metadata/i);
+    }
+  });
+
+  it('does not leak approvals between entries', () => {
+    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
+    expect(approvedPrivateOrigins('e2', store)).toEqual([]);
+  });
+
+  it('caps how many an entry may approve', () => {
+    for (let i = 1; i <= 10; i += 1) approvePrivateOrigin('e1', `https://10.0.0.${i}:9000`, store);
+    expect(approvePrivateOrigin('e1', 'https://10.0.0.99:9000', store).ok).toBe(false);
+  });
+
+  it('is idempotent', () => {
+    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
+    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
+    expect(approvedPrivateOrigins('e1', store)).toHaveLength(1);
+  });
+
+  it('revokes one without disturbing the others', () => {
+    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
+    approvePrivateOrigin('e1', 'https://10.0.0.6:9000', store);
+    revokePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
+    expect(approvedPrivateOrigins('e1', store)).toEqual(['https://10.0.0.6:9000']);
+  });
+});
+
+describe('the notice, and where it goes', () => {
+  const n = () => newDestinationNotice('Cloudflare', 'https://api.cloudflare.com:443', 'GET', '/client/v4/zones');
+
+  it('names the secret and the destination on both channels', () => {
+    const notice = n();
+    expect(notice.stderrLine).toContain('Cloudflare');
+    expect(notice.stderrLine).toContain('api.cloudflare.com');
+    expect(notice.toolNote).toContain('api.cloudflare.com');
+  });
+
+  it('says plainly that the destination did not go to the server', () => {
+    // The whole point of the local store; if the notice does not say so, nobody knows.
+    expect(n().toolNote).toMatch(/not sent to the server/i);
+  });
+
+  it('describes itself as a notice, not a block', () => {
+    expect(n().toolNote).toMatch(/notice rather than a block/i);
+  });
+
+  it('tells the reader what to do if it was unexpected', () => {
+    expect(n().toolNote).toMatch(/revoke/i);
+    expect(n().toolNote).toMatch(/Tier 2/i);
+  });
+
+  it('carries a timestamp on the stderr line, which is the channel of record', () => {
+    // stderr never passes through the model, so this is the line that cannot be suppressed.
+    expect(n().stderrLine).toMatch(/\d{4}-\d{2}-\d{2}T/);
+    expect(n().stderrLine.endsWith('\n')).toBe(true);
+  });
+});
+
+describe('store location', () => {
+  it('honours an explicit override', () => {
+    const prev = process.env.WUNDERVAULT_NETWORK_STORE;
+    process.env.WUNDERVAULT_NETWORK_STORE = '/tmp/elsewhere.json';
+    try { expect(defaultStorePath()).toBe('/tmp/elsewhere.json'); }
+    finally {
+      if (prev === undefined) delete process.env.WUNDERVAULT_NETWORK_STORE;
+      else process.env.WUNDERVAULT_NETWORK_STORE = prev;
+    }
+  });
+});

```

## File: src/network-store.ts

```
/**
 * Where an agent's secrets go — held on the customer's machine, not on the server.
 *
 * Destinations are a behavioural profile: which services you call, how often, when, and
 * (for approved private origins) your internal network addresses. None of that helps
 * anyone read a secret, but it is competitive intelligence on its own and it is the kind
 * of thing a breach or a subpoena reaches. "We cannot read your secrets" was always
 * true; keeping this local makes "we do not know what you do with them" true as well.
 *
 * The split that makes this coherent:
 *
 *   Tier 1 — the destination NEVER leaves this machine. The server learns that a call
 *            happened, not where it went.
 *   Tier 2 — the destination IS sent, because the whole point of tier 2 is that a human
 *            reviews the request, and they cannot review what they cannot see. That is
 *            consented disclosure for one specific call, not a standing profile.
 *
 * HONEST LIMIT, and it is the important one: this file lives in the agent's own home
 * directory and is writable by the agent's uid. A compromised agent can therefore edit
 * its own record of where it sent things — the party being audited controls the
 * evidence. That makes this a privacy improvement today and NOT an integrity control.
 * It becomes one after the uid split, when the file moves to /var/lib/wundervault owned
 * by a daemon account the agent cannot write to. The interface here does not change when
 * that happens.
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface SeenDestination {
  entryId: string;
  origin: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
}

export interface NetworkShape {
  version: 1;
  seen: SeenDestination[];
  /** entryId -> exact "scheme://host:port" strings the owner approved locally. */
  approvedPrivateOrigins: Record<string, string[]>;
}

const EMPTY: NetworkShape = { version: 1, seen: [], approvedPrivateOrigins: {} };

/** Bounded, so a long-lived install cannot grow this without limit. */
const MAX_SEEN = 2000;
const MAX_APPROVED_PER_ENTRY = 10;

export function defaultStorePath(): string {
  // After the uid split this becomes /var/lib/wundervault/network.json, owned by the
  // daemon account. Same shape, same code — only the path and the owner change.
  return process.env.WUNDERVAULT_NETWORK_STORE
    || path.join(os.homedir(), '.wundervault', 'network.json');
}

export function load(storePath = defaultStorePath()): NetworkShape {
  try {
    if (!existsSync(storePath)) return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
    const parsed = JSON.parse(readFileSync(storePath, 'utf8')) as NetworkShape;
    if (!parsed || parsed.version !== 1) return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
    return {
      version: 1,
      seen: Array.isArray(parsed.seen) ? parsed.seen : [],
      approvedPrivateOrigins: (parsed.approvedPrivateOrigins && typeof parsed.approvedPrivateOrigins === 'object')
        ? parsed.approvedPrivateOrigins : {},
    };
  } catch {
    // A corrupt store must not break every vault call. Start clean rather than throw —
    // the worst case is one spurious "new destination" notice.
    return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
  }
}

export function save(shape: NetworkShape, storePath = defaultStorePath()): void {
  const dir = path.dirname(storePath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // Write-then-rename: a half-written store read by the next call would look like a
  // cleared history, and every destination would alert again.
  const tmp = `${storePath}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(shape, null, 2), { mode: 0o600 });
  renameSync(tmp, storePath);
  try { chmodSync(storePath, 0o600); } catch { /* best effort */ }
}

/**
 * Record a destination and say whether it had been seen before.
 *
 * Returns true the FIRST time an (entry, origin) pair appears. The caller uses that to
 * raise a notice exactly once, rather than on every call to a familiar service.
 */
export function recordDestination(
  entryId: string, origin: string, storePath = defaultStorePath(),
): { isNew: boolean } {
  const shape = load(storePath);
  const now = new Date().toISOString();
  const key = origin.trim().toLowerCase();

  const existing = shape.seen.find((s) => s.entryId === entryId && s.origin === key);
  if (existing) {
    existing.count += 1;
    existing.lastSeen = now;
    save(shape, storePath);
    return { isNew: false };
  }

  shape.seen.push({ entryId, origin: key, firstSeen: now, lastSeen: now, count: 1 });
  // Oldest-first eviction. Evicting a record makes that destination read as new again,
  // which raises one extra notice — the safe direction for a detective signal.
  if (shape.seen.length > MAX_SEEN) {
    shape.seen.sort((a, b) => a.lastSeen.localeCompare(b.lastSeen));
    shape.seen = shape.seen.slice(shape.seen.length - MAX_SEEN);
  }
  save(shape, storePath);
  return { isNew: true };
}

export function destinationsFor(entryId: string, storePath = defaultStorePath()): SeenDestination[] {
  return load(storePath).seen.filter((s) => s.entryId === entryId);
}

// ── owner-approved private origins, held locally ───────────────────────────────

/**
 * Cloud metadata endpoints hand out instance credentials. No approval unlocks one,
 * because it is not a decision anyone can meaningfully make on an agent's behalf.
 */
const NEVER_APPROVABLE = new Set(['169.254.169.254', 'fd00:ec2::254', '100.100.100.200', 'metadata.google.internal']);

export function approvedPrivateOrigins(entryId: string, storePath = defaultStorePath()): string[] {
  const list = load(storePath).approvedPrivateOrigins[entryId];
  return Array.isArray(list) ? list.filter((s) => typeof s === 'string') : [];
}

export function approvePrivateOrigin(
  entryId: string, origin: string, storePath = defaultStorePath(),
): { ok: boolean; reason?: string; origins?: string[] } {
  const m = /^(https?):\/\/([a-z0-9._\-[\]:]+?):(\d{1,5})$/i.exec(origin.trim());
  if (!m) {
    return { ok: false, reason: 'Origin must be exactly "scheme://host:port", for example https://10.0.0.5:9000. No ranges and no wildcards — a range is not something you can realistically evaluate.' };
  }
  const host = m[2].toLowerCase().replace(/^\[|\]$/g, '');
  const port = Number(m[3]);
  if (port < 1 || port > 65535) return { ok: false, reason: 'Port out of range.' };
  if (NEVER_APPROVABLE.has(host)) {
    return { ok: false, reason: `${host} is a cloud metadata endpoint. It hands out instance credentials, so it cannot be approved.` };
  }

  const shape = load(storePath);
  const current = shape.approvedPrivateOrigins[entryId] ?? [];
  const canonical = `${m[1].toLowerCase()}://${host}:${port}`;
  if (current.includes(canonical)) return { ok: true, origins: current };
  if (current.length >= MAX_APPROVED_PER_ENTRY) {
    return { ok: false, reason: `This entry already approves ${MAX_APPROVED_PER_ENTRY} private origins.` };
  }
  shape.approvedPrivateOrigins[entryId] = [...current, canonical];
  save(shape, storePath);
  return { ok: true, origins: shape.approvedPrivateOrigins[entryId] };
}

export function revokePrivateOrigin(
  entryId: string, origin: string, storePath = defaultStorePath(),
): string[] {
  const shape = load(storePath);
  const canonical = origin.trim().toLowerCase();
  const next = (shape.approvedPrivateOrigins[entryId] ?? []).filter((o) => o.toLowerCase() !== canonical);
  if (next.length === 0) delete shape.approvedPrivateOrigins[entryId];
  else shape.approvedPrivateOrigins[entryId] = next;
  save(shape, storePath);
  return next;
}


// ── telling the owner, without telling the server ──────────────────────────────

export interface DestinationNotice {
  /** For stderr — the model cannot suppress this. */
  stderrLine: string;
  /** For the tool result — the model reads this and can explain it in context. */
  toolNote: string;
}

/**
 * Compose the first-sighting notice.
 *
 * Two channels, deliberately, and the split matters:
 *
 *  - **stderr** goes from this process straight to the MCP client and never passes
 *    through the model. A compromised agent can decide not to mention a tool result; it
 *    cannot strip a line already written to stderr. That makes this the channel of
 *    record.
 *  - **the tool result** is how the agent explains it to you in the conversation, which
 *    is where you are actually looking.
 *
 * Neither reaches the server. The destination stays on this machine, so the default
 * install leaves the server knowing nothing about where a secret goes — no relay, no
 * transient handling, nothing to store.
 *
 * The case this does NOT cover is an unattended run: a scheduled agent at 3am with
 * nobody watching the terminal. Email covers that and is therefore opt-in, labelled as
 * the choice that sends the destination to the server in order to deliver it.
 */
export function newDestinationNotice(
  secretName: string, origin: string, method: string, path: string,
): DestinationNotice {
  const at = new Date().toISOString();
  return {
    stderrLine:
      `[wundervault] NEW DESTINATION ${at} secret="${secretName}" ${method} ${origin}${path}\n`,
    toolNote:
      `⚠ First use of "${secretName}" against ${origin}.\n`
      + `   ${method} ${origin}${path}\n`
      + `   Tier 1 does not gate destinations, so this is a notice rather than a block. `
      + `If you did not expect it, revoke this agent and rotate the secret at the provider. `
      + `Moving the secret to Tier 2 makes each new request wait for approval.\n`
      + `   Recorded on this machine only — the destination was not sent to the server.`,
  };
}

/** Write the notice where the model cannot interfere with it. */
export function emitToStderr(notice: DestinationNotice): void {
  try { process.stderr.write(notice.stderrLine); } catch { /* never break a call over a log line */ }
}

```

## File: test/network-store.test.ts

```
/**
 * Acceptance checks for the local network store (PLAN part A).
 *
 * Every test uses a temp store path, because the real one is the developer's own
 * ~/.wundervault and a test must never touch it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, statSync, writeFileSync, readFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  load, save, recordDestination, destinationsFor,
  approvePrivateOrigin, approvedPrivateOrigins, revokePrivateOrigin,
  newDestinationNotice, defaultStorePath,
} from '../src/network-store.js';

let dir: string;
let store: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), 'wv-net-'));
  store = path.join(dir, 'network.json');
});
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('first-sighting detection', () => {
  it('reports a destination as new exactly once', () => {
    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(true);
    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
  });

  it('separates entries, so one secret does not vouch for another', () => {
    recordDestination('e1', 'https://api.cloudflare.com:443', store);
    expect(recordDestination('e2', 'https://api.cloudflare.com:443', store).isNew).toBe(true);
  });

  it('separates origins', () => {
    recordDestination('e1', 'https://api.cloudflare.com:443', store);
    expect(recordDestination('e1', 'https://api.openai.com:443', store).isNew).toBe(true);
  });

  it('treats a port change as a different destination', () => {
    recordDestination('e1', 'https://h.example:443', store);
    expect(recordDestination('e1', 'https://h.example:8443', store).isNew).toBe(true);
  });

  it('is case-insensitive on the origin', () => {
    recordDestination('e1', 'https://API.Cloudflare.com:443', store);
    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
  });

  it('counts repeat use', () => {
    for (let i = 0; i < 4; i += 1) recordDestination('e1', 'https://h.example:443', store);
    expect(destinationsFor('e1', store)[0].count).toBe(4);
  });
});

describe('durability', () => {
  it('writes 0600 and survives a reload', () => {
    recordDestination('e1', 'https://h.example:443', store);
    expect(statSync(store).mode & 0o777).toBe(0o600);
    expect(load(store).seen).toHaveLength(1);
  });

  it('leaves no temp file behind', () => {
    recordDestination('e1', 'https://h.example:443', store);
    const leftovers = require('node:fs').readdirSync(dir).filter((f: string) => f.includes('.tmp-'));
    expect(leftovers).toEqual([]);
  });

  it('starts clean on a corrupt store rather than breaking every call', () => {
    writeFileSync(store, '{{{not json');
    expect(load(store).seen).toEqual([]);
    // and can still be written afterwards
    expect(recordDestination('e1', 'https://h.example:443', store).isNew).toBe(true);
  });

  it('ignores a store written by a future version', () => {
    writeFileSync(store, JSON.stringify({ version: 99, seen: [{ entryId: 'x' }] }));
    expect(load(store).seen).toEqual([]);
  });
});

describe('locally approved private origins', () => {
  it('accepts an exact scheme://host:port', () => {
    const r = approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    expect(r.ok).toBe(true);
    expect(approvedPrivateOrigins('e1', store)).toEqual(['https://10.0.0.5:9000']);
  });

  it('refuses a range or wildcard', () => {
    // A range is not something an owner can realistically evaluate.
    expect(approvePrivateOrigin('e1', 'https://10.0.0.0/24', store).ok).toBe(false);
    expect(approvePrivateOrigin('e1', 'https://*.local:9000', store).ok).toBe(false);
  });

  it('refuses an origin with no port', () => {
    expect(approvePrivateOrigin('e1', 'https://10.0.0.5', store).ok).toBe(false);
  });

  it('refuses cloud metadata endpoints outright', () => {
    for (const h of ['169.254.169.254', 'metadata.google.internal', '100.100.100.200']) {
      const r = approvePrivateOrigin('e1', `https://${h}:80`, store);
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/metadata/i);
    }
  });

  it('does not leak approvals between entries', () => {
    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    expect(approvedPrivateOrigins('e2', store)).toEqual([]);
  });

  it('caps how many an entry may approve', () => {
    for (let i = 1; i <= 10; i += 1) approvePrivateOrigin('e1', `https://10.0.0.${i}:9000`, store);
    expect(approvePrivateOrigin('e1', 'https://10.0.0.99:9000', store).ok).toBe(false);
  });

  it('is idempotent', () => {
    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    expect(approvedPrivateOrigins('e1', store)).toHaveLength(1);
  });

  it('revokes one without disturbing the others', () => {
    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    approvePrivateOrigin('e1', 'https://10.0.0.6:9000', store);
    revokePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    expect(approvedPrivateOrigins('e1', store)).toEqual(['https://10.0.0.6:9000']);
  });
});

describe('the notice, and where it goes', () => {
  const n = () => newDestinationNotice('Cloudflare', 'https://api.cloudflare.com:443', 'GET', '/client/v4/zones');

  it('names the secret and the destination on both channels', () => {
    const notice = n();
    expect(notice.stderrLine).toContain('Cloudflare');
    expect(notice.stderrLine).toContain('api.cloudflare.com');
    expect(notice.toolNote).toContain('api.cloudflare.com');
  });

  it('says plainly that the destination did not go to the server', () => {
    // The whole point of the local store; if the notice does not say so, nobody knows.
    expect(n().toolNote).toMatch(/not sent to the server/i);
  });

  it('describes itself as a notice, not a block', () => {
    expect(n().toolNote).toMatch(/notice rather than a block/i);
  });

  it('tells the reader what to do if it was unexpected', () => {
    expect(n().toolNote).toMatch(/revoke/i);
    expect(n().toolNote).toMatch(/Tier 2/i);
  });

  it('carries a timestamp on the stderr line, which is the channel of record', () => {
    // stderr never passes through the model, so this is the line that cannot be suppressed.
    expect(n().stderrLine).toMatch(/\d{4}-\d{2}-\d{2}T/);
    expect(n().stderrLine.endsWith('\n')).toBe(true);
  });
});

describe('store location', () => {
  it('honours an explicit override', () => {
    const prev = process.env.WUNDERVAULT_NETWORK_STORE;
    process.env.WUNDERVAULT_NETWORK_STORE = '/tmp/elsewhere.json';
    try { expect(defaultStorePath()).toBe('/tmp/elsewhere.json'); }
    finally {
      if (prev === undefined) delete process.env.WUNDERVAULT_NETWORK_STORE;
      else process.env.WUNDERVAULT_NETWORK_STORE = prev;
    }
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
