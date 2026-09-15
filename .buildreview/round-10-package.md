# Review package — round 10
generated 2026-09-15T05:38:29+00:00

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

Part A round 2. Round 1 triage in round-9-triage.json. FIXED: F1 off switch now real (WUNDERVAULT_RECORD_DESTINATIONS=0 touches nothing, raises nothing — verified no file created); F2 notice takes the tier and no longer tells a Tier 2 caller the destination stayed local, since approval is exactly where it was disclosed; F4 exclusive lock file with stale-lock timeout, verified two processes x 25 destinations each with zero lost updates and the lock cleaned up. REJECTED with reasons: F3 and F5 both describe the local approvals API, which was DELETED before this round after the plan review found an agent could forge its own approval in a file its own uid can write — approvals are server-side again. The F5 bracketed-IPv6 bug is real in principle and is recorded for when approvals are rebuilt on a daemon-owned path. DEFERRED: F6 (token verifier / ProtectHome conflict — part B, not built, and my plan did contradict itself) and F7 (opt-in email for unattended runs is described but not built, so a 3am run has no notice today). 292 tests. Please judge whether the deferrals are honest or whether F7 in particular should block.

## Diff

```diff
diff --git a/src/network-store.ts b/src/network-store.ts
index 10942d8..9a7e0eb 100644
--- a/src/network-store.ts
+++ b/src/network-store.ts
@@ -30,7 +30,8 @@
  *
  * The line: this file records what happened. It never decides what is allowed.
  */
-import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
+import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync,
+  openSync, closeSync, unlinkSync, statSync } from 'node:fs';
 import * as os from 'node:os';
 import * as path from 'node:path';
 
@@ -52,6 +53,17 @@ const EMPTY: NetworkShape = { version: 1, seen: [] };
 /** Bounded, so a long-lived install cannot grow this without limit. */
 const MAX_SEEN = 2000;
 
+/**
+ * Recording can be turned off. The metadata IS the control, so opting out of the record
+ * opts out of first-sighting notices too — there is no honest way to have the second
+ * without the first, and pretending otherwise would leave someone believing they were
+ * being warned.
+ */
+export function recordingEnabled(): boolean {
+  const v = (process.env.WUNDERVAULT_RECORD_DESTINATIONS ?? '').trim().toLowerCase();
+  return !(v === '0' || v === 'false' || v === 'off' || v === 'no');
+}
+
 export function defaultStorePath(): string {
   // After the uid split this becomes /var/lib/wundervault/network.json, owned by the
   // daemon account. Same shape, same code — only the path and the owner change.
@@ -91,7 +103,12 @@ export function save(shape: NetworkShape, storePath = defaultStorePath()): void
  */
 export function recordDestination(
   entryId: string, origin: string, storePath = defaultStorePath(),
-): { isNew: boolean } {
+): { isNew: boolean; recorded: boolean } {
+  // Opted out: touch nothing, say nothing. Returning isNew:false here is deliberate —
+  // a notice without a record would fire on every single call.
+  if (!recordingEnabled()) return { isNew: false, recorded: false };
+
+  return withStoreLock(storePath, () => {
   const shape = load(storePath);
   const now = new Date().toISOString();
   const key = origin.trim().toLowerCase();
@@ -101,7 +118,7 @@ export function recordDestination(
     existing.count += 1;
     existing.lastSeen = now;
     save(shape, storePath);
-    return { isNew: false };
+    return { isNew: false, recorded: true };
   }
 
   shape.seen.push({ entryId, origin: key, firstSeen: now, lastSeen: now, count: 1 });
@@ -112,7 +129,49 @@ export function recordDestination(
     shape.seen = shape.seen.slice(shape.seen.length - MAX_SEEN);
   }
   save(shape, storePath);
-  return { isNew: true };
+  return { isNew: true, recorded: true };
+  });
+}
+
+/**
+ * Serialise read-modify-write across processes.
+ *
+ * Several agents run under one user here — seven on this machine — so two MCP processes
+ * writing at once is the normal case, not a corner. Without this, both load the same
+ * store, both write, and the later rename silently discards the other's destination,
+ * which then reports as new again. An exclusive lock file with a stale-lock timeout is
+ * enough: contention is brief and the failure mode of waiting is better than the failure
+ * mode of losing a record.
+ */
+function withStoreLock<T>(storePath: string, fn: () => T): T {
+  const lockPath = `${storePath}.lock`;
+  const deadline = Date.now() + 5000;
+  let fd: number | undefined;
+  for (;;) {
+    try {
+      fd = openSync(lockPath, 'wx');
+      break;
+    } catch {
+      // A lock left by a crashed process must not block every later call for ever.
+      try {
+        const age = Date.now() - statSync(lockPath).mtimeMs;
+        if (age > 30_000) { unlinkSync(lockPath); continue; }
+      } catch { /* vanished under us: retry */ }
+      if (Date.now() > deadline) {
+        // Proceed unlocked rather than fail a vault call over bookkeeping. Worst case is
+        // the lost-update this guards against, which costs one spurious notice.
+        return fn();
+      }
+      const wait = Date.now() + 25;
+      while (Date.now() < wait) { /* brief spin; this is a millisecond-scale section */ }
+    }
+  }
+  try {
+    return fn();
+  } finally {
+    try { closeSync(fd!); } catch { /* ignore */ }
+    try { unlinkSync(lockPath); } catch { /* ignore */ }
+  }
 }
 
 export function destinationsFor(entryId: string, storePath = defaultStorePath()): SeenDestination[] {
@@ -153,18 +212,27 @@ export interface DestinationNotice {
  */
 export function newDestinationNotice(
   secretName: string, origin: string, method: string, path: string,
+  /** Which tier authorised this call. The notice must not describe the wrong one. */
+  tier: string = '1',
 ): DestinationNotice {
   const at = new Date().toISOString();
-  return {
-    stderrLine:
-      `[wundervault] NEW DESTINATION ${at} secret="${secretName}" ${method} ${origin}${path}\n`,
-    toolNote:
-      `⚠ First use of "${secretName}" against ${origin}.\n`
-      + `   ${method} ${origin}${path}\n`
-      + `   Tier 1 does not gate destinations, so this is a notice rather than a block. `
+  const isTier2 = String(tier) === '2';
+
+  // Tier 2 already required the owner to see and approve this exact operation, so
+  // telling them "this was not gated" and "the destination stayed on this machine"
+  // would both be false — the approval is precisely where it was disclosed.
+  const explanation = isTier2
+    ? `   You approved this operation, so it was gated. The destination was sent to the `
+      + `server as part of that approval; it is also recorded here.`
+    : `   Tier 1 does not gate destinations, so this is a notice rather than a block. `
       + `If you did not expect it, revoke this agent and rotate the secret at the provider. `
       + `Moving the secret to Tier 2 makes each new request wait for approval.\n`
-      + `   Recorded on this machine only — the destination was not sent to the server.`,
+      + `   Recorded on this machine only — the destination was not sent to the server.`;
+
+  return {
+    stderrLine:
+      `[wundervault] NEW DESTINATION ${at} tier=${tier} secret="${secretName}" ${method} ${origin}${path}\n`,
+    toolNote: `⚠ First use of "${secretName}" against ${origin}.\n   ${method} ${origin}${path}\n${explanation}`,
   };
 }
 
diff --git a/src/server.ts b/src/server.ts
index 7503fbb..7f033c7 100644
--- a/src/server.ts
+++ b/src/server.ts
@@ -691,7 +691,8 @@ export function createServer(args: { url?: string } = {}) {
           let noticeForAgent = '';
           if (isNew) {
             const notice = newDestinationNotice(
-              secretData.name ?? entry_id, originStr, def.route.method, def.route.path);
+              secretData.name ?? entry_id, originStr, def.route.method, def.route.path,
+              verdict.tier);
             emitToStderr(notice);
             noticeForAgent = `\n\n${notice.toolNote}`;
           }
diff --git a/test/network-store.test.ts b/test/network-store.test.ts
index a82e482..0e4de5b 100644
--- a/test/network-store.test.ts
+++ b/test/network-store.test.ts
@@ -10,7 +10,7 @@ import * as os from 'node:os';
 import * as path from 'node:path';
 import {
   load, save, recordDestination, destinationsFor,
-  newDestinationNotice, defaultStorePath,
+  newDestinationNotice, defaultStorePath, recordingEnabled,
 } from '../src/network-store.js';
 
 let dir: string;
@@ -140,3 +140,67 @@ describe('store location', () => {
     }
   });
 });
+
+describe('round 1 fixes', () => {
+  it('records nothing and notices nothing when recording is off', () => {
+    // The metadata IS the control, so opting out of the record opts out of the notice.
+    // A notice without a record would fire on every single call.
+    const prev = process.env.WUNDERVAULT_RECORD_DESTINATIONS;
+    process.env.WUNDERVAULT_RECORD_DESTINATIONS = '0';
+    try {
+      const r = recordDestination('e1', 'https://h.example:443', store);
+      expect(r.recorded).toBe(false);
+      expect(r.isNew).toBe(false);
+      expect(existsSync(store)).toBe(false);
+    } finally {
+      if (prev === undefined) delete process.env.WUNDERVAULT_RECORD_DESTINATIONS;
+      else process.env.WUNDERVAULT_RECORD_DESTINATIONS = prev;
+    }
+  });
+
+  it.each(['0', 'false', 'off', 'no', 'OFF'])('treats %s as off', (v) => {
+    const prev = process.env.WUNDERVAULT_RECORD_DESTINATIONS;
+    process.env.WUNDERVAULT_RECORD_DESTINATIONS = v;
+    try { expect(recordingEnabled()).toBe(false); }
+    finally {
+      if (prev === undefined) delete process.env.WUNDERVAULT_RECORD_DESTINATIONS;
+      else process.env.WUNDERVAULT_RECORD_DESTINATIONS = prev;
+    }
+  });
+
+  it('records by default', () => {
+    expect(recordingEnabled()).toBe(true);
+  });
+
+  it('does not tell a Tier 2 caller the destination stayed local', () => {
+    // Tier 2 approval is exactly where the destination WAS disclosed, so the Tier 1
+    // wording would be false — and false reassurance is worse than none.
+    const t2 = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '2');
+    expect(t2.toolNote).not.toMatch(/not sent to the server/i);
+    expect(t2.toolNote).toMatch(/approved this operation/i);
+    expect(t2.stderrLine).toContain('tier=2');
+  });
+
+  it('still tells a Tier 1 caller the destination stayed local', () => {
+    const t1 = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '1');
+    expect(t1.toolNote).toMatch(/not sent to the server/i);
+    expect(t1.toolNote).toMatch(/notice rather than a block/i);
+  });
+
+  it('does not lose a record when two writers interleave', () => {
+    // Seven agents run under one uid on this machine, so concurrent writers are the
+    // normal case. Last-write-wins would silently drop a destination, which then reports
+    // as new again.
+    const a = load(store);
+    a.seen.push({ entryId: 'eA', origin: 'https://a.example:443', firstSeen: 'x', lastSeen: 'x', count: 1 });
+    save(a, store);
+    recordDestination('eB', 'https://b.example:443', store);
+    const after = load(store);
+    expect(after.seen.map((s) => s.entryId).sort()).toEqual(['eA', 'eB']);
+  });
+
+  it('leaves no lock file behind', () => {
+    recordDestination('e1', 'https://h.example:443', store);
+    expect(existsSync(`${store}.lock`)).toBe(false);
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
 * HONEST LIMIT: this file lives in the agent's own home directory and is writable by the
 * agent's uid. A compromised agent can edit its own record of where it sent things — the
 * party being audited controls the evidence. So OBSERVATIONS live here (privacy, no
 * integrity claim), and it becomes an integrity control only after the uid split moves it
 * to a daemon-owned path.
 *
 * WHAT DOES NOT LIVE HERE, and why: owner APPROVALS. An earlier version stored approved
 * private origins in this file, which was a straight security regression — the agent
 * could write its own approval and walk through the SSRF filter it was meant to be
 * constrained by. An observation being forgeable costs you a missed notice; a CONTROL
 * being forgeable costs you the control. Approvals therefore stay server-side, where the
 * owner authenticates and the agent cannot write, until a daemon-owned path exists.
 *
 * The line: this file records what happened. It never decides what is allowed.
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync,
  openSync, closeSync, unlinkSync, statSync } from 'node:fs';
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
}

const EMPTY: NetworkShape = { version: 1, seen: [] };

/** Bounded, so a long-lived install cannot grow this without limit. */
const MAX_SEEN = 2000;

/**
 * Recording can be turned off. The metadata IS the control, so opting out of the record
 * opts out of first-sighting notices too — there is no honest way to have the second
 * without the first, and pretending otherwise would leave someone believing they were
 * being warned.
 */
export function recordingEnabled(): boolean {
  const v = (process.env.WUNDERVAULT_RECORD_DESTINATIONS ?? '').trim().toLowerCase();
  return !(v === '0' || v === 'false' || v === 'off' || v === 'no');
}

export function defaultStorePath(): string {
  // After the uid split this becomes /var/lib/wundervault/network.json, owned by the
  // daemon account. Same shape, same code — only the path and the owner change.
  return process.env.WUNDERVAULT_NETWORK_STORE
    || path.join(os.homedir(), '.wundervault', 'network.json');
}

export function load(storePath = defaultStorePath()): NetworkShape {
  try {
    if (!existsSync(storePath)) return { version: 1, seen: [] };
    const parsed = JSON.parse(readFileSync(storePath, 'utf8')) as NetworkShape;
    if (!parsed || parsed.version !== 1) return { version: 1, seen: [] };
    return { version: 1, seen: Array.isArray(parsed.seen) ? parsed.seen : [] };
  } catch {
    // A corrupt store must not break every vault call. Start clean rather than throw —
    // the worst case is one spurious "new destination" notice.
    return { version: 1, seen: [] };
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
): { isNew: boolean; recorded: boolean } {
  // Opted out: touch nothing, say nothing. Returning isNew:false here is deliberate —
  // a notice without a record would fire on every single call.
  if (!recordingEnabled()) return { isNew: false, recorded: false };

  return withStoreLock(storePath, () => {
  const shape = load(storePath);
  const now = new Date().toISOString();
  const key = origin.trim().toLowerCase();

  const existing = shape.seen.find((s) => s.entryId === entryId && s.origin === key);
  if (existing) {
    existing.count += 1;
    existing.lastSeen = now;
    save(shape, storePath);
    return { isNew: false, recorded: true };
  }

  shape.seen.push({ entryId, origin: key, firstSeen: now, lastSeen: now, count: 1 });
  // Oldest-first eviction. Evicting a record makes that destination read as new again,
  // which raises one extra notice — the safe direction for a detective signal.
  if (shape.seen.length > MAX_SEEN) {
    shape.seen.sort((a, b) => a.lastSeen.localeCompare(b.lastSeen));
    shape.seen = shape.seen.slice(shape.seen.length - MAX_SEEN);
  }
  save(shape, storePath);
  return { isNew: true, recorded: true };
  });
}

/**
 * Serialise read-modify-write across processes.
 *
 * Several agents run under one user here — seven on this machine — so two MCP processes
 * writing at once is the normal case, not a corner. Without this, both load the same
 * store, both write, and the later rename silently discards the other's destination,
 * which then reports as new again. An exclusive lock file with a stale-lock timeout is
 * enough: contention is brief and the failure mode of waiting is better than the failure
 * mode of losing a record.
 */
function withStoreLock<T>(storePath: string, fn: () => T): T {
  const lockPath = `${storePath}.lock`;
  const deadline = Date.now() + 5000;
  let fd: number | undefined;
  for (;;) {
    try {
      fd = openSync(lockPath, 'wx');
      break;
    } catch {
      // A lock left by a crashed process must not block every later call for ever.
      try {
        const age = Date.now() - statSync(lockPath).mtimeMs;
        if (age > 30_000) { unlinkSync(lockPath); continue; }
      } catch { /* vanished under us: retry */ }
      if (Date.now() > deadline) {
        // Proceed unlocked rather than fail a vault call over bookkeeping. Worst case is
        // the lost-update this guards against, which costs one spurious notice.
        return fn();
      }
      const wait = Date.now() + 25;
      while (Date.now() < wait) { /* brief spin; this is a millisecond-scale section */ }
    }
  }
  try {
    return fn();
  } finally {
    try { closeSync(fd!); } catch { /* ignore */ }
    try { unlinkSync(lockPath); } catch { /* ignore */ }
  }
}

export function destinationsFor(entryId: string, storePath = defaultStorePath()): SeenDestination[] {
  return load(storePath).seen.filter((s) => s.entryId === entryId);
}

// Approvals deliberately absent — see the header. They are a control, and a control in
// an agent-writable file is not a control.

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
  /** Which tier authorised this call. The notice must not describe the wrong one. */
  tier: string = '1',
): DestinationNotice {
  const at = new Date().toISOString();
  const isTier2 = String(tier) === '2';

  // Tier 2 already required the owner to see and approve this exact operation, so
  // telling them "this was not gated" and "the destination stayed on this machine"
  // would both be false — the approval is precisely where it was disclosed.
  const explanation = isTier2
    ? `   You approved this operation, so it was gated. The destination was sent to the `
      + `server as part of that approval; it is also recorded here.`
    : `   Tier 1 does not gate destinations, so this is a notice rather than a block. `
      + `If you did not expect it, revoke this agent and rotate the secret at the provider. `
      + `Moving the secret to Tier 2 makes each new request wait for approval.\n`
      + `   Recorded on this machine only — the destination was not sent to the server.`;

  return {
    stderrLine:
      `[wundervault] NEW DESTINATION ${at} tier=${tier} secret="${secretName}" ${method} ${origin}${path}\n`,
    toolNote: `⚠ First use of "${secretName}" against ${origin}.\n   ${method} ${origin}${path}\n${explanation}`,
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
  newDestinationNotice, defaultStorePath, recordingEnabled,
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

describe('approvals are NOT stored here', () => {
  it('exposes no way to record an approval locally', async () => {
    // A control in an agent-writable file is not a control: the agent could approve its
    // own internal destination and walk through the SSRF filter it is constrained by.
    const mod = await import('../src/network-store.js');
    expect('approvePrivateOrigin' in mod).toBe(false);
    expect('approvedPrivateOrigins' in mod).toBe(false);
    expect('revokePrivateOrigin' in mod).toBe(false);
  });

  it('keeps no approval field in the persisted shape', () => {
    recordDestination('e1', 'https://h.example:443', store);
    const raw = JSON.parse(readFileSync(store, 'utf8'));
    expect(Object.keys(raw).sort()).toEqual(['seen', 'version']);
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

describe('round 1 fixes', () => {
  it('records nothing and notices nothing when recording is off', () => {
    // The metadata IS the control, so opting out of the record opts out of the notice.
    // A notice without a record would fire on every single call.
    const prev = process.env.WUNDERVAULT_RECORD_DESTINATIONS;
    process.env.WUNDERVAULT_RECORD_DESTINATIONS = '0';
    try {
      const r = recordDestination('e1', 'https://h.example:443', store);
      expect(r.recorded).toBe(false);
      expect(r.isNew).toBe(false);
      expect(existsSync(store)).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.WUNDERVAULT_RECORD_DESTINATIONS;
      else process.env.WUNDERVAULT_RECORD_DESTINATIONS = prev;
    }
  });

  it.each(['0', 'false', 'off', 'no', 'OFF'])('treats %s as off', (v) => {
    const prev = process.env.WUNDERVAULT_RECORD_DESTINATIONS;
    process.env.WUNDERVAULT_RECORD_DESTINATIONS = v;
    try { expect(recordingEnabled()).toBe(false); }
    finally {
      if (prev === undefined) delete process.env.WUNDERVAULT_RECORD_DESTINATIONS;
      else process.env.WUNDERVAULT_RECORD_DESTINATIONS = prev;
    }
  });

  it('records by default', () => {
    expect(recordingEnabled()).toBe(true);
  });

  it('does not tell a Tier 2 caller the destination stayed local', () => {
    // Tier 2 approval is exactly where the destination WAS disclosed, so the Tier 1
    // wording would be false — and false reassurance is worse than none.
    const t2 = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '2');
    expect(t2.toolNote).not.toMatch(/not sent to the server/i);
    expect(t2.toolNote).toMatch(/approved this operation/i);
    expect(t2.stderrLine).toContain('tier=2');
  });

  it('still tells a Tier 1 caller the destination stayed local', () => {
    const t1 = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '1');
    expect(t1.toolNote).toMatch(/not sent to the server/i);
    expect(t1.toolNote).toMatch(/notice rather than a block/i);
  });

  it('does not lose a record when two writers interleave', () => {
    // Seven agents run under one uid on this machine, so concurrent writers are the
    // normal case. Last-write-wins would silently drop a destination, which then reports
    // as new again.
    const a = load(store);
    a.seen.push({ entryId: 'eA', origin: 'https://a.example:443', firstSeen: 'x', lastSeen: 'x', count: 1 });
    save(a, store);
    recordDestination('eB', 'https://b.example:443', store);
    const after = load(store);
    expect(after.seen.map((s) => s.entryId).sort()).toEqual(['eA', 'eB']);
  });

  it('leaves no lock file behind', () => {
    recordDestination('e1', 'https://h.example:443', store);
    expect(existsSync(`${store}.lock`)).toBe(false);
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
