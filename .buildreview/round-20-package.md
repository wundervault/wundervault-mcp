# Review package — round 20
generated 2026-09-17T16:57:10+00:00

## Spec — judge the build against THIS

# SPEC — key custody: the broker stops handing out the vault key

Phase 4 gave the broker its own uid. It did not stop the broker handing the agent the
key. This spec closes that, and closes the two delivery holes that make the key reachable
before the broker ever holds it.

Spans two repos. `wundervault-mcp` (the broker and the MCP server) and `burnbox` (the
dashboard, the vault API, the setup flow). An acceptance check that says "anywhere" is
checked in BOTH.

---

## 0. The three defects

**D-A. Repair publishes the vault credential to the agent.**
`burnbox/app/static/js/dashboard.js:5137` — repair calls `_showAgentCreatedModal(data,
passphrase, {rekeyed:true})`, which renders "Send this message to the agent:" over
`_buildOnboardMsg()` (`:5221`). That message embeds the full setup URL — path token AND
`#passphrase` — twice, inside shell commands the agent is told to run. The link decrypts
to `encryption_key` (`:5097`), which unwraps `vault_key_for_agent` (`:5101`), which
decrypts every entry in that agent's vault.

This violates acceptance check 22 of `SPEC-uid-split.md` — "No instruction anywhere tells
a user to pass the setup link as an argument." Round 13 finding F2 fixed the CLI side; the
dashboard was in the other repo and was never checked.

Worse, the message orders the steps so the pre-split path is guaranteed: the agent runs
`onboard.py` at step 2, BEFORE step 3 installs the broker, so `/run/wundervault/mgmt/agent.sock`
does not exist, `onboard.py:452` takes the "No secret broker on this machine" branch, and
the agent decrypts the blob and files `api_key` + `encryption_key` in its own home as its
own uid. The link is then burned, so step 4's `--enrol` gets a spent token.

**D-B. The setup link is a bearer credential, so any courier sees it.**
Even with D-A fixed, the link has to travel browser → terminal. The owner accepts driving
that terminal themselves, which is enough IF the link is the only copy. It is not enough
as a design: `onboard.py:320` takes it from `sys.argv[1]`, and anything that ever puts it
in a command line, a chat log, or a shell history hands over the vault key.

**D-C. The broker hands `enc_key` to the agent on request.**
`src/agent.ts:449-456` — the per-agent socket, on a valid token, replies with
`{api_key, enc_key, vault_url}`. `src/server.ts:143` files it as `agent_encryption_key`;
`:469-470` builds `AgentVaultAPI(api_key, encKey, url)`; `src/api-client.ts:219` calls
`decryptVaultKey(encKey, vault_key_for_agent)`. The MCP server runs as the AGENT's uid, so
`vault_key` lives in the agent's memory, derived by the agent's own code.

The authorising token is `~/.wundervault/agents/<name>.token`, mode 0600, owned by the
agent's uid — it must be readable by the agent, that is how the MCP server authenticates.
The socket is 0666 (`agent.ts:475`), world-connectable by design. So obtaining the whole
vault needs no exploit: read your own token, connect, receive `enc_key`.

`entry_mode` does not stand in the way. `src/types.ts:49` says so — "set server-side,
**enforced client-side**" — and every check (`server.ts:497, 572, 625, 852, 974`) runs in
the agent's process. `SPEC-tiered-broker.md` claims for tier 1 that "the key never reaches
the agent"; `performOperation` is imported at `server.ts:23` and runs in the agent's
process, so that claim is false as built.

`PLAN-local-shape-and-uid-split.md` sequencing step 3 called for "fresh key hierarchy,
**re-wrap to a device key**, rotate exposed upstream credentials". Phase 5 built the first
and the third. `SPEC-phase5-rekey.md` never mentions a device key and has no out-of-scope
section recording the omission. Part 2 below is that missing piece.

---

## (Parts 1 and 2 omitted from this package — see NOTES)

## 3. Part 3 — the socket serves operations, not credentials

- 3.1 The per-agent socket **no longer returns `api_key` or `enc_key`**, to anyone, ever.
  The credential-dispensing reply at `agent.ts:449-456` is removed. A request in the old
  shape gets `{"error":"unsupported","upgrade":true}` and a message naming the version to
  install. It is not deprecated, kept behind a flag, or available under any env var.
- 3.2 The socket speaks newline-delimited JSON as today. Every request carries `token` and
  `op`. The token check is unchanged, still constant-time, still first, still with the
  same penalty behaviour.
- 3.3 The request byte cap rises from 4096 to 1 MiB to carry an HTTP body, and the absolute
  connection deadline rises from 10s to 120s to cover an upstream call. The inactivity
  timeout and the absolute deadline both remain, so a slow sender still dies on the
  absolute one; no per-connection ceiling is introduced (see the `maxConnections` note).
- 3.4 Operations:
  - `list_entries` → entry ids, names, tiers. No key material.
  - `profile_flags` → account flags the agent needs (`allow_env_inject`). No key material,
    and no secret access, so it costs no access-log row.
  - `get_entry {entry_id, purpose}` → plaintext, name, exec config, and the directive
    integrity verdict computed IN THE BROKER. **Refused unless the entry's mode allows
    LEGACY_EXEC.** There is deliberately no separate metadata operation: each RPC performs
    exactly ONE `getSecret`, so the access log and the tier-2 gate see precisely what they
    see today. A metadata probe would add a row per call and could trip tier 2 twice.
  - `call {entry_id, purpose, request:{origin, method, path, body?, query?}}` → the broker
    performs the HTTP operation and returns the scrubbed response. The plaintext does not
    cross the socket.
  - `ssh_agent_open {entry_id, purpose}` → the broker loads the key and serves the
    ssh-agent protocol on a socket it owns; returns the path. `ssh_agent_close {session_id}`.
    The private key does not cross the socket.
  - `settings` → the account's MCP settings. No key material.
- 3.5 `entry_mode` is enforced **in the broker**, which is the only process where
  enforcement means anything. The client-side checks may remain as a fast path for a
  better error message, but the broker's decision is the one that governs, and removing
  every client-side check must not change what an agent can obtain.
- 3.6 `performOperation` (`http-broker.ts`) and the ssh-agent protocol server
  (`ssh-agent.ts`) run in the broker process. The SSRF guards, the pinned lookup, the
  private-origin allowlist and the secret scrubbing move with them, unchanged in behaviour.
- 3.7 The broker NEVER spawns an agent-supplied command. `vault_exec`, `vault_rsync` and
  `vault_ssh_exec` continue to run in the agent's process, on plaintext obtained through
  `get_entry` — which is LEGACY_EXEC by definition — or on an ssh-agent socket. A design
  where the broker runs the agent's command would hand the agent code execution as the
  broker's uid, which is `/var/lib/wundervault`.
- 3.8 `recordDestination` runs in the broker. Today it is called at `server.ts:703` in the
  agent's process against `/var/lib/wundervault/network.json`, which that uid cannot write:
  the write either fails the call or fails silently, and either way D3 of `SPEC-uid-split.md`
  — "the party being audited owned the evidence" — is not satisfied as built. Moving
  `call` into the broker fixes it as a side effect. Verify which of the two it is today and
  state it.
- 3.9 The tier-2 wait, the unanswered-escalation report, and `checkOperation` run in the
  broker, because they are part of performing the operation.
- 3.10 `session_lock` / single-instance lock behaviour is unchanged in effect. If any part
  of it gates access to secrets, it moves to the broker; if it only guards the MCP
  process's own lifecycle, it stays.
- 3.11 Nothing in the MCP process imports `decryptVaultKey`, `decryptSecretContent`, or
  `loadEncryptionKey` after this change. Verified by grep, as a test.

## 4. Non-goals

- Server-side `entry_mode` enforcement (phase 6). Unchanged: the server will still serve
  `vault_key_for_agent` to a holder of the api_key. After this spec the broker is the only
  holder, which is why phase 6 is a backstop rather than the fix.
- macOS (phase 7) and Windows (phase 8). Both keep the pre-split shape and say so.
- Hands-off enrolment. The broker could poll for pending enrolments once paired, removing
  the claim-code step entirely. The owner has said driving the terminal is acceptable, so
  this is deliberately not built.
- Any change to what LEGACY_EXEC means. An entry in that mode still hands its plaintext to
  the agent; that is the mode's definition and the exposure report's subject.
- Retracting anything an agent has already read.

## 5. Honest limits this spec does NOT close, and must not claim to

- **One uid is one principal.** All seven agents share the owner's uid, so any agent can
  read any other agent's token file and impersonate it to the broker. `SO_PEERCRED` cannot
  separate them. This spec narrows what an impersonator gets — one entry at a time, mode-
  gated, logged — but it does not make agent A and agent B distinguishable.
- **The ssh-agent socket is world-connectable** for the same reason every broker socket is.
  A random path and a short lifetime bound the exposure; they do not eliminate it. It is
  still strictly better than today, where the agent holds the private key itself.
- **A LEGACY_EXEC entry is still handed over in full**, and anything an agent has read it
  keeps. The exposure report remains the only remedy.
- **Pairing trusts the terminal once.** An agent driving the terminal at pairing time could
  print a fingerprint for a key it controls. Pairing is the owner's job, in a session no
  agent is driving, once per machine. This is the same trust the `sudo` install already
  assumes, and it replaces a per-repair exposure with a per-machine one.

---

## 6. Acceptance checks

Numbered, each true or false, each checked in both repos where the wording says "anywhere".

**Part 3**
17. The per-agent socket never emits `api_key` or `enc_key`. A test asserts the reply to
    every operation, and to a malformed one, contains neither field.
18. An old-shape `{token}` request returns an upgrade error, not credentials.
19. `get_entry` on a BROKER_SSH_AGENT or BROKER_HTTP entry is refused BY THE BROKER, with
    every client-side mode check deleted in the test build.
19a. Each RPC causes exactly one `getSecret` against the vault API — the access log and the
    tier-2 gate behave identically to today. Asserted against a recording fake.
20. `call` performs the HTTP operation with the plaintext never appearing in any socket
    reply, verified by asserting on the raw bytes written to the socket.
21. `ssh_agent_open` lets `ssh` authenticate without the private key crossing the socket,
    and the session is closed on `ssh_agent_close` and on a timeout.
22. No file under `src/` other than the broker's own modules imports `decryptVaultKey`,
    `decryptSecretContent` or `loadEncryptionKey`. Grep test.
23. The SSRF guard, the pinned lookup, the private-origin allowlist and the scrubbing
    behave identically after the move — the existing `http-broker` tests pass unchanged
    against the broker-hosted path.
24. `recordDestination` writes `/var/lib/wundervault/network.json` as the broker, and an
    agent cannot write that file.
25. A request larger than 1 MiB is refused, and a connection held open past 120s is closed,
    while a legitimate 30s upstream call completes.
26. A wrong token still costs the failing caller the exponential penalty, and a valid token
    is still served during another caller's flood.
27. The seven live agents' flow — repair, pair, claim, enrol, then every tool — works
    end to end in the rehearsal container.
28. `SPEC-tiered-broker.md`'s "the key never reaches the agent" is true for tier 1 after
    this change, or the sentence is corrected.


## What was built this round, and how it was tested

ROUND 2, same scope as round 1: PART 3 only, broker side. Round 1's triage is in .buildreview/round-19-triage.json — do not re-raise anything marked rejected or deferred there without new evidence.

WHAT I CHANGED SINCE ROUND 1, all four findings confirmed against the real code:
F1 (blocker) JSON null crashed the broker — JSON.parse("null") does not throw, so null passed the try/catch and msg.token threw synchronously in the data callback. The parsed root must now be a non-null non-array object.
F2 (blocker) the 30s inactivity timer stayed armed during serve(), destroying the socket mid-operation — there is no traffic during an operation by design. It is now disarmed once a complete request is read, and the absolute deadline moved 120s -> 180s because 90s of tier-2 wait plus a 30s upstream call does not fit in 120s.
F3 (major) the 1 MiB cap counted UTF-16 code units. Now accumulates Buffers and caps on raw bytes.
F4 (major) per-chunk toString() corrupted multi-byte characters split across reads. Now concatenates and decodes once.
B3 rejected with reasons (recordDestination before the verdict is deliberate — a first sighting recorded only on success re-alerts on every tier-2 retry). B1, B2, B4 deferred.

AND ONE I FOUND MYSELF while re-reading the patch: my F1/F2 rewrite had DELETED the token check. The suite still passed, because no test presented a wrong token to the new dispatch. Restored, and the malformed-input tests now assert 'unauthorized' for every shape. I would like that class of gap looked for specifically.

TESTED: 446 passing. New regression tests: JSON null and every other scalar/array/non-JSON shape, asserting the broker answers afterwards; a multi-byte character split mid-character across two writes; a 700k-three-byte-character payload refused on bytes; a slow operation completing rather than being killed at 30s; and the timers read off the source.

MOST WANTED THIS ROUND: (1) anything in the rewritten framing that can still crash, hang or be made to serve without a valid token; (2) whether disarming the inactivity timer reopened the slow-loris hole the original comments were written about; (3) whether the 180s absolute deadline can be held by an authenticated caller to exhaust descriptors; (4) defects in MY ROUND-1 FIXES specifically, rather than in the original build.

## Diff

```diff
diff --git a/src/agent.ts b/src/agent.ts
index d5bcd84..ada93f3 100644
--- a/src/agent.ts
+++ b/src/agent.ts
@@ -40,6 +40,30 @@ import {
   splitAvailable, systemdCredential, sealedWithTpm,
 } from './paths.js';
 import { load as loadNetworkShape } from './network-store.js';
+import { BrokerOps } from './broker-ops.js';
+import type { BrokeredOp } from './ssh-agent.js';
+
+/**
+ * The per-agent socket request cap.
+ *
+ * Enforced before parsing, on the raw buffer, so it bounds an unauthenticated caller.
+ */
+const MAX_REQUEST_BYTES = 1024 * 1024;
+
+/** Everything a caller may ask the per-agent socket for. */
+interface SocketRequest {
+  token?: string;
+  op?: string;
+  entry_id?: string;
+  purpose?: string;
+  operation_id?: string;
+  args?: Record<string, unknown>;
+  request?: unknown;
+  session_id?: string;
+  include_plaintext?: boolean;
+  op_spec?: unknown;
+  ttl_seconds?: number;
+}
 
 interface AgentProfile {
   agent_name: string;
@@ -253,6 +277,16 @@ class AgentDaemon {
   private agentServers: Map<string, net.Server> = new Map();
   private mgmtServer: net.Server | null = null;
   private knocks = new Knocks();
+  /**
+   * One operations object per agent, built on first use and kept.
+   *
+   * Kept rather than rebuilt per connection because `AgentVaultAPI` caches the unwrapped
+   * vault key after the first call, and that cache is exactly what we want: it lives in
+   * the broker's memory and nowhere else. The consequence is that a repair — which
+   * retires the vault key — must drop it, so `registerProfile` and `removeProfile` both
+   * discard the entry rather than leaving a stale key to fail every subsequent call.
+   */
+  private ops: Map<string, BrokerOps> = new Map();
 
   constructor() {
     ensureSystemRoot();
@@ -369,6 +403,10 @@ class AgentDaemon {
     const idx = this.profiles.findIndex(p => p.agent_name === profile.agent_name);
     if (idx >= 0) {
       this.profiles[idx] = profile;
+      // A re-enrolment follows a repair, and a repair retires the vault key. The cached
+      // operations object holds the OLD one; keeping it would make every call after a
+      // repair fail to decrypt, which reads as a broken vault rather than a stale cache.
+      this.dropOps(profile.agent_name);
       const old = this.agentServers.get(profile.agent_name);
       if (old) {
         // Not unlinked in the close callback: startAgentSocket unlinks and rebinds
@@ -396,32 +434,201 @@ class AgentDaemon {
     const srv = this.agentServers.get(safe);
     if (srv) { try { srv.close(); } catch { /* already gone */ } }
     this.agentServers.delete(safe);
+    this.dropOps(safe);
     try { fs.unlinkSync(agentSocketPath(safe)); } catch { /* already gone */ }
     this.saveProfiles();
     return true;
   }
 
+  /**
+   * Answer one operation for one agent.
+   *
+   * The token has already been checked by the caller. Everything here runs as the
+   * broker's uid, and NOTHING here may return `api_key` or `enc_key` — that is the
+   * property the whole phase rests on, and it is asserted by a test that inspects the
+   * bytes written to the socket for every operation, including the failures.
+   */
+  private async serve(profile: AgentProfile, msg: SocketRequest): Promise<Record<string, unknown>> {
+    const op = typeof msg.op === 'string' ? msg.op : '';
+
+    // No `op` at all is the pre-custody client asking for credentials. Answering it with
+    // a generic "unknown operation" would send someone hunting through their config; say
+    // what actually happened and what fixes it.
+    if (!op) {
+      return {
+        error:
+          'This broker no longer hands out vault credentials. The MCP server on this '
+          + `machine is older than the broker (broker ${VERSION}). Update it: `
+          + 'npm install -g @wundervault/mcp-server, then reload your MCP connection.',
+        code: 'UPGRADE_REQUIRED',
+        upgrade: true,
+        broker_version: VERSION,
+      };
+    }
+
+    // `ping` is answered BEFORE any credential is touched. Building the operations
+    // object parses the encryption key, so a profile with an unusable one would make the
+    // liveness check fail in the same way a dead broker does — and "is the broker there"
+    // is exactly the question you ask when something is already wrong.
+    if (op === 'ping') {
+      // Deliberately says nothing about the vault. It exists so a client can tell a
+      // broker that is running from one that is not, before it has an entry to ask for.
+      return { ok: true, agent: profile.agent_name, broker_version: VERSION };
+    }
+
+    const ops = this.opsFor(profile);
+    const entry = () => String(msg.entry_id ?? '');
+    const purpose = () => String(msg.purpose ?? '');
+
+    switch (op) {
+      case 'list_entries':
+        return await ops.listEntries() as unknown as Record<string, unknown>;
+
+      case 'profile_flags':
+        return await ops.profileFlags() as unknown as Record<string, unknown>;
+
+      case 'get_entry': {
+        if (!entry() || !purpose()) return { error: 'get_entry needs entry_id and purpose.' };
+        // Defaults to sending one: a caller that omits the field is an older client whose
+        // tools all expect a plaintext. Only an explicit `false` withholds it.
+        const include = msg.include_plaintext !== false;
+        return await ops.getEntry(entry(), purpose(), include) as unknown as Record<string, unknown>;
+      }
+
+      case 'call': {
+        if (!entry() || !purpose()) return { error: 'call needs entry_id and purpose.' };
+        return await ops.call({
+          entryId: entry(),
+          purpose: purpose(),
+          operationId: typeof msg.operation_id === 'string' ? msg.operation_id : undefined,
+          callArgs: (msg.args ?? {}) as Record<string, unknown>,
+          request: msg.request as never,
+        }) as unknown as Record<string, unknown>;
+      }
+
+      case 'ssh_agent_open': {
+        if (!entry() || !purpose()) return { error: 'ssh_agent_open needs entry_id and purpose.' };
+        const ttl = Number.isFinite(msg.ttl_seconds) ? Number(msg.ttl_seconds) : 300;
+        const op = msg.op_spec as BrokeredOp | undefined;
+        if (!op || (op.kind !== 'ssh' && op.kind !== 'rsync') || typeof op.destination !== 'string') {
+          return { error: 'ssh_agent_open needs op_spec {kind, destination, remoteArgv|rsyncArgs}.' };
+        }
+        return await ops.sshAgentOpen({
+          entryId: entry(),
+          purpose: purpose(),
+          op,
+          // Clamped rather than trusted: the caller is the party the session is a
+          // capability for, so an unbounded ttl from it would be a request to leave the
+          // signing socket open for ever.
+          ttlSeconds: Math.max(10, Math.min(900, ttl)),
+        }) as unknown as Record<string, unknown>;
+      }
+
+      case 'ssh_agent_close':
+        return ops.closeSsh(String(msg.session_id ?? '')) as unknown as Record<string, unknown>;
+
+      case 'settings':
+        return await ops.settings();
+
+      default:
+        return { error: `Unknown operation "${op}".`, code: 'UNKNOWN_OP' };
+    }
+  }
+
+  /** The operations object for one agent, built on first use. */
+  private opsFor(profile: AgentProfile): BrokerOps {
+    const existing = this.ops.get(profile.agent_name);
+    if (existing) return existing;
+    const fresh = new BrokerOps(
+      profile.agent_name, profile.api_key, profile.enc_key, profile.vault_url,
+    );
+    this.ops.set(profile.agent_name, fresh);
+    return fresh;
+  }
+
+  /** Drop an agent's cached operations — and its cached vault key — and close its sessions. */
+  private dropOps(name: string): void {
+    const existing = this.ops.get(name);
+    if (!existing) return;
+    try { existing.reset(); } catch { /* closing a dead session is not an event */ }
+    this.ops.delete(name);
+  }
+
   startAgentSocket(profile: AgentProfile): void {
     const sockPath = agentSocketPath(profile.agent_name);
     try { fs.unlinkSync(sockPath); } catch { /* nothing to clear */ }
 
     const srv = net.createServer((socket) => {
-      let buf = '';
-      // A caller that never sends a newline would otherwise hold a connection open for
-      // ever, and a caller that streams without one would grow this buffer without bound.
-      // Inactivity timeout AND an absolute one. The inactivity timer alone is resettable
-      // by any traffic, which is what let a connection be held open indefinitely.
-      socket.setTimeout(5_000, () => socket.destroy());
-      const deadline = setTimeout(() => socket.destroy(), 10_000);
+      // BUFFERS, not a string, and the reasons are two separate bugs.
+      //
+      // 1. `buf.length` on a string counts UTF-16 code units, not bytes. A request of
+      //    700,000 three-byte UTF-8 characters is over 2 MiB on the wire and about
+      //    700,000 "long" as a string, so a byte cap enforced on a string is not a byte
+      //    cap. It was harmless when the only payload was `{"token":"<hex>"}`; a `call`
+      //    carries an arbitrary HTTP body.
+      // 2. `chunk.toString()` decodes each chunk independently, so a multi-byte character
+      //    split across two TCP reads becomes two replacement characters. The broker would
+      //    then forward a body that is not the one the caller sent — silently, and only
+      //    for non-ASCII content.
+      //
+      // Concatenating Buffers and decoding once, at the end, fixes both.
+      let chunks: Buffer[] = [];
+      let size = 0;
+      let consumed = false;
+
+      // TWO TIMERS, WITH DIFFERENT JOBS.
+      //
+      // The inactivity timer bounds a caller who never finishes sending — the slow-loris
+      // shape the original 5s timeout was written for. The absolute deadline bounds the
+      // connection whatever it does.
+      //
+      // The inactivity timer is DISARMED the moment a complete request has been read,
+      // because from then on there is legitimately no traffic: the broker is fetching an
+      // entry, waiting on a 30s upstream call, or parked on a tier-2 approval for up to
+      // 90s. Leaving it armed destroyed the socket mid-operation and returned nothing,
+      // while the broker carried on working for a caller that was no longer there.
+      socket.setTimeout(30_000, () => socket.destroy());
+      // 180s, not 120s: a tier-2 call waits up to 90s for a human, then re-asks the
+      // server and performs a request with its own 30s timeout. A 120s ceiling would cut
+      // off the one path that exists to survive a human taking their time.
+      const deadline = setTimeout(() => socket.destroy(), 180_000);
       (deadline as unknown as { unref?: () => void }).unref?.();
       socket.on('close', () => clearTimeout(deadline));
       socket.on('data', (d) => {
-        buf += d.toString();
-        if (buf.length > 4096) { socket.destroy(); return; }
-        if (!buf.includes('\n')) return;
+        if (consumed) return;
+        chunks.push(d);
+        size += d.length;
+        // Enforced on RAW BYTES, before parsing, which is what stops an unauthenticated
+        // caller growing this buffer. 4096 was right for a token lookup; a `call`
+        // operation carries an HTTP body, so the cap is 1 MiB.
+        if (size > MAX_REQUEST_BYTES) { socket.destroy(); return; }
 
-        let msg: { token?: string } = {};
-        try { msg = JSON.parse(buf.trim()); } catch { /* treated as no token */ }
+        const joined = Buffer.concat(chunks);
+        const nl = joined.indexOf(0x0a);
+        if (nl < 0) return;
+        consumed = true;
+        // Decoded ONCE, over the whole line, so a multi-byte character spanning chunks
+        // survives.
+        const line = joined.subarray(0, nl).toString('utf8').trim();
+
+        // The request has arrived in full; the inactivity timer has done its job and
+        // would now be measuring the broker's own work.
+        socket.setTimeout(0);
+
+        let msg: SocketRequest | null = null;
+        try {
+          const parsed = JSON.parse(line) as unknown;
+          // `JSON.parse("null")` returns null, and `null.token` throws — synchronously,
+          // inside a socket data callback, which takes the whole broker down. Any local
+          // process could send `null\n` to a world-connectable socket and kill the
+          // process holding every credential on the machine. A scalar (`5`, `"x"`) does
+          // not throw but is not a request either, so the shape is checked rather than
+          // the failure mode patched.
+          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
+            msg = parsed as SocketRequest;
+          }
+        } catch { /* treated as no token, exactly as an unparseable body always was */ }
+        if (msg === null) msg = {};
 
         // The token is checked FIRST, before any penalty is consulted. The previous order
         // let a stranger's wrong guesses decide what the real agent got back.
@@ -449,12 +656,34 @@ class AgentDaemon {
         }
 
         this.knocks.clear(profile.agent_name);
-        socket.write(JSON.stringify({
-          api_key: profile.api_key,
-          enc_key: profile.enc_key,
-          vault_url: profile.vault_url,
-        }) + '\n');
-        socket.end();
+
+        // ── THE CHANGE THIS PHASE EXISTS FOR ────────────────────────────────
+        //
+        // This used to be:
+        //
+        //     socket.write(JSON.stringify({ api_key, enc_key, vault_url }))
+        //
+        // A valid token got the credentials, and the MCP server — which runs as the
+        // AGENT's uid — used `enc_key` to unwrap `vault_key_for_agent` and decrypt the
+        // whole vault in its own memory. The uid split protected the store on disk and
+        // the broker's memory, and then the socket handed the key over anyway. The token
+        // that authorises this lives in the agent's own home at 0600, readable by the
+        // agent because that is how the MCP server authenticates, so obtaining the whole
+        // vault needed no exploit at all.
+        //
+        // The socket now serves OPERATIONS. Nothing below can return api_key or enc_key,
+        // and there is no flag, env var or legacy mode that brings the old reply back:
+        // an old client gets an upgrade error, because a deprecation path here is a
+        // downgrade path for an attacker.
+        this.serve(profile, msg as SocketRequest)
+          .then((reply) => {
+            try { socket.write(JSON.stringify(reply) + '\n'); socket.end(); }
+            catch { /* the caller hung up while we worked */ }
+          })
+          .catch((e: Error) => {
+            try { socket.write(JSON.stringify({ error: e.message }) + '\n'); socket.end(); }
+            catch { /* as above */ }
+          });
       });
       socket.on('error', () => { /* a client that hangs up is not an event */ });
     });
@@ -536,6 +765,79 @@ class AgentDaemon {
 
         try {
           const msg = JSON.parse(buf.slice(0, nl));
+          if (msg.action === 'enrol_claim' && msg.claim_code) {
+            // The claim path. What the caller hands over here is NOT a credential: it
+            // names a blob sealed to this broker's public key, and only this broker's
+            // private key opens it. So the code can cross a terminal, a chat log or a
+            // command line without mattering — which is the whole difference from the
+            // setup link, where the same journey hands over the vault key.
+            void (async () => {
+              try {
+                if (!msg.socket_token || String(msg.socket_token).length < 32) {
+                  throw new Error('An enrolment must carry a socket_token of at least 32 characters.');
+                }
+                const { claim, burnClaim } = await import('./pair.js');
+                const c = await claim(String(msg.claim_code));
+                this.registerProfile({
+                  agent_name: c.agent_name,
+                  api_key: c.api_key,
+                  enc_key: c.enc_key,
+                  vault_url: c.vault_url,
+                  socket_token: String(msg.socket_token),
+                } as AgentProfile);
+                // Burned only after the profile is stored, for the same reason the link
+                // path defers its burn: a disk error must not consume a single-use claim.
+                // The burn carries api_key_hmac from inside the blob as proof — without
+                // it, anyone who read the claim code could spend it first.
+                const burned = await burnClaim(String(msg.claim_code), c.api_key_hmac ?? '');
+                reply({ ok: true, agent_name: c.agent_name, agent_id: c.agent_id, link_burned: burned });
+              } catch (e) {
+                reply({ error: (e as Error).message });
+              } finally {
+                socket.end();
+              }
+            })();
+            return;
+          }
+
+          if (msg.action === 'whose_claim' && msg.claim_code) {
+            // Reading a claim does not spend it, so this costs one round trip and lets
+            // the caller reuse an existing socket token rather than locking out a running
+            // agent. The blob is not opened here and nothing from it is returned.
+            void (async () => {
+              try {
+                const { whoseClaim } = await import('./pair.js');
+                reply(await whoseClaim(String(msg.claim_code)));
+              } catch (e) {
+                reply({ error: (e as Error).message });
+              } finally {
+                socket.end();
+              }
+            })();
+            return;
+          }
+
+          if (msg.action === 'paired') {
+            // So a client can find out whether this machine has a broker identity bound
+            // to an account, and refuse the weaker path itself with a useful message
+            // rather than discovering it two round trips later.
+            void (async () => {
+              try {
+                const { readPaired } = await import('./pair.js');
+                const rec = readPaired();
+                reply(rec
+                  ? { paired: true, fingerprint: rec.fingerprint, origin: rec.origin,
+                      account_label: rec.account_label ?? null, paired_at: rec.paired_at }
+                  : { paired: false });
+              } catch (e) {
+                reply({ error: (e as Error).message });
+              } finally {
+                socket.end();
+              }
+            })();
+            return;
+          }
+
           if (msg.action === 'enrol' && msg.setup_url) {
             // The ONLY way a profile gets in. `register_profile` used to live here and
             // took whatever it was handed: any local process — every agent on this
@@ -557,6 +859,25 @@ class AgentDaemon {
                 if (!msg.socket_token || String(msg.socket_token).length < 32) {
                   throw new Error('An enrolment must carry a socket_token of at least 32 characters.');
                 }
+                // ACCEPTANCE CHECK 14. On a paired machine the link path is refused.
+                //
+                // Leaving it available would make every hardening above optional: an
+                // attacker who wanted the credential in bearer form would simply ask for
+                // the path that still produces one. A downgrade that remains reachable is
+                // not a fallback, it is the attack.
+                //
+                // Refused BEFORE redeeming, so a link offered to a paired broker is not
+                // spent on its way to being rejected.
+                const { readPaired: _paired } = await import('./pair.js');
+                const pairedRec = _paired();
+                if (pairedRec) {
+                  throw new Error(
+                    `This machine is paired with a broker (${pairedRec.fingerprint}), so setup `
+                    + `links are not accepted here — they are bearer credentials and the pairing `
+                    + `exists to stop one being carried.\n`
+                    + `Repair the agent in the dashboard, choose this broker, and paste the CLAIM `
+                    + `CODE instead. Nothing was redeemed, so the link you have is still valid.`);
+                }
                 // The burn is deferred: the link is marked used only once the profile is
                 // actually stored, so a disk error cannot consume it either.
                 const { creds, burn } = await redeemSetupLink(String(msg.setup_url));
@@ -745,7 +1066,7 @@ export type { AgentProfile, ProfileStore };
 function readLinkFromStdin(): Promise<string> {
   return new Promise((resolve) => {
     if (process.stdin.isTTY) {
-      process.stderr.write('Paste the setup link from the dashboard (it ends in #…): ');
+      process.stderr.write('Paste the claim code, or the setup link, from the dashboard: ');
     }
     let buf = '';
     process.stdin.setEncoding('utf8');
@@ -769,16 +1090,20 @@ if (invokedDirectly && !process.env.WUNDERVAULT_AGENT_NO_AUTOSTART) {
     console.log(`
 Wundervault secret broker ${VERSION}
 
-Usage: wundervault-agent [--enrol] [--migrate [--finish]] [--destinations]
+Usage: wundervault-agent [--pair] [--enrol] [--migrate [--finish]] [--destinations]
 
 With no arguments it runs as the secret broker: the process that holds your agents'
 credentials so the agents cannot read them. It is normally started by systemd as the
 '${SYSTEM_ACCOUNT}' account, not by hand.
 
-  --enrol       Add an agent using a setup link from the dashboard. Prompts for the link
-                rather than taking it as an argument: a command line is readable by every
-                process on this machine. The broker redeems the link itself, so the
-                credentials never pass through this process.
+  --pair        Bind this machine's broker to your account, once. Needs sudo: it writes
+                the broker's private key. Prints a code and a fingerprint, neither of
+                which is a secret, and waits for you to confirm in the dashboard.
+  --enrol       Add an agent. Prompts for a CLAIM CODE (on a paired machine) or a setup
+                link (on an unpaired one), rather than taking either as an argument: a
+                command line is readable by every process on this machine. The broker
+                fetches and decrypts the credentials itself, so they never pass through
+                this process. A claim code is not a credential; a setup link is.
   --migrate     Show which agents still need moving to the broker, and how.
   --finish      With --migrate: delete the old store, once every agent is across.
   --destinations  Show where your agents have sent secrets. Needs sudo: the record
@@ -873,6 +1198,45 @@ State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
         setTimeout(() => { cleanup(); process.exit(0); }, 10 * 60 * 1000);
       })
       .catch((e: Error) => { console.error(e.message); process.exit(1); });
+  } else if (argv.includes('--pair')) {
+    // Runs as ROOT (via sudo), because it writes the broker's private key into
+    // /var/lib/wundervault. Nothing secret leaves this command: it uploads a PUBLIC key
+    // and prints a fingerprint and a code, both of which an onlooker may read.
+    void (async () => {
+      const { startPairing, awaitConfirmation } = await import('./pair.js');
+      try {
+        const start = await startPairing();
+        console.log('');
+        console.log('  Pairing code : ' + start.code);
+        console.log('  Fingerprint  : ' + start.identity.fingerprint);
+        console.log('');
+        console.log('  In the dashboard: Settings > Agents > Pair a broker, enter the code above,');
+        console.log('  and check the fingerprint it shows matches this one EXACTLY before you');
+        console.log('  confirm. That comparison is the whole ceremony — everything after it is');
+        console.log('  sealed to the key you just approved.');
+        console.log('');
+        console.log('  Neither of those two values is a secret. Anyone reading this screen learns');
+        console.log('  a public key and a code that opens nothing.');
+        console.log('');
+        process.stdout.write('  Waiting for you to confirm...');
+        let dots = 0;
+        const rec = await awaitConfirmation(start, {
+          onTick: () => { dots += 1; if (dots % 4 === 0) process.stdout.write('.'); },
+        });
+        console.log('');
+        console.log('');
+        console.log(`  Paired. This broker is ${rec.fingerprint}`
+          + (rec.account_label ? ` (${rec.account_label})` : ''));
+        console.log('');
+        console.log('  Setup links are no longer accepted on this machine. Repair an agent in the');
+        console.log('  dashboard, choose this broker, and paste the CLAIM CODE into --enrol.');
+        process.exit(0);
+      } catch (e) {
+        console.log('');
+        console.error((e as Error).message);
+        process.exit(1);
+      }
+    })();
   } else if (argv.includes('--enrol')) {
     // Runs as the USER. It hands over a URL and gets back a name — the credentials are
     // fetched, decrypted and filed by the daemon, and never enter this process.
@@ -883,25 +1247,40 @@ State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
     // for as long as the command ran. And because fetching and burning are separate steps,
     // an agent that copied it had time to redeem it first. Prompting costs one paste and
     // keeps the link out of argv and out of shell history.
-    const url = await readLinkFromStdin();
-    if (!url) {
-      console.error('No setup link given.');
+    const input = await readLinkFromStdin();
+    if (!input) {
+      console.error('Nothing given. Paste a claim code, or a setup link on an unpaired machine.');
       process.exit(2);
     }
-    const { enrol } = await import('./migrate.js');
-    enrol(url)
-      .then((r) => {
-        console.log(`Enrolled ${r.agent_name}. Its credentials are held by the broker in ${systemRoot()}, ` +
-                    `which your agents cannot read.`);
+    void (async () => {
+      const { enrol, enrolClaim } = await import('./migrate.js');
+      const { looksLikeClaimCode } = await import('./pair.js');
+      try {
+        // A claim code and a setup link are told apart by SHAPE, not by asking the user
+        // which they have. They look nothing alike, and a wrong guess here would send a
+        // bearer credential down the path that does not expect one.
+        const isClaim = looksLikeClaimCode(input);
+        const r = isClaim ? await enrolClaim(input) : await enrol(input);
+        console.log(`Enrolled ${r.agent_name}. Its credentials are held by the broker in ${systemRoot()}, `
+                    + `which your agents cannot read.`);
         if (!r.linkBurned) {
           console.log('');
-          console.log('WARNING: the server did not confirm the setup link as used, so it stays');
-          console.log('valid until it expires and could be replayed to re-point this agent.');
-          console.log('Repair the agent again in the dashboard if that matters to you.');
+          console.log(isClaim
+            ? 'WARNING: the server did not confirm the claim as used, so it stays valid until it'
+            : 'WARNING: the server did not confirm the setup link as used, so it stays');
+          console.log(isClaim
+            ? 'expires. It opens nothing without this broker\u2019s key, but repair the agent again'
+            : 'valid until it expires and could be replayed to re-point this agent.');
+          console.log(isClaim
+            ? 'if you would rather it were dead.'
+            : 'Repair the agent again in the dashboard if that matters to you.');
         }
         process.exit(0);
-      })
-      .catch((e: Error) => { console.error(e.message); process.exit(1); });
+      } catch (e) {
+        console.error((e as Error).message);
+        process.exit(1);
+      }
+    })();
   } else if (argv.includes('--migrate')) {
     // Runs as the USER, not the daemon: it reads the old store from a home directory the
     // daemon deliberately cannot reach.
diff --git a/src/ssh-agent.ts b/src/ssh-agent.ts
index 342e114..c04afa5 100644
--- a/src/ssh-agent.ts
+++ b/src/ssh-agent.ts
@@ -273,15 +273,45 @@ export interface AgentHandle {
  * merely deleted but its parent goes too — a stray socket outliving its command is the
  * thing that turns a bounded capability into an ambient one.
  */
-export function startAgent(identity: LoadedIdentity, onSign?: (e: SignEvent) => void, host = ''): AgentHandle {
+/**
+ * Where the socket goes, and who may reach it.
+ *
+ * The default — a 0700 directory under the process's own tmpdir — is right when the
+ * agent protocol is served by the same process that will run `ssh`. It is WRONG when the
+ * broker serves it for somebody else: the unit sets `PrivateTmp=yes`, so the broker's
+ * /tmp exists only inside its own mount namespace and the agent would never find the
+ * socket; and even if it could see the path, a 0700 directory owned by `wundervault`
+ * excludes the very uid that has to connect.
+ *
+ * So the broker passes its own directory under /run and opens the modes. The secrecy
+ * moves from the file mode to the unguessable path plus the session's short life — the
+ * same trade every other broker socket makes, for the same reason, and it is recorded as
+ * a limit rather than described as a control.
+ */
+export interface AgentSocketOptions {
+  /** Pre-made directory to host the socket. Caller owns its mode and its removal. */
+  dir?: string;
+  socketMode?: number;
+  publicKeyMode?: number;
+}
+
+export function startAgent(
+  identity: LoadedIdentity,
+  onSign?: (e: SignEvent) => void,
+  host = '',
+  opts: AgentSocketOptions = {},
+): AgentHandle {
   if (process.platform === 'win32') {
     throw new Error('The ssh-agent broker needs unix domain sockets and POSIX permissions; run on Linux or macOS.');
   }
 
-  const dir = mkdtempSync(path.join(os.tmpdir(), 'wv-agent-'));
+  const providedDir = typeof opts.dir === 'string' && opts.dir.length > 0;
+  const dir = providedDir ? opts.dir! : mkdtempSync(path.join(os.tmpdir(), 'wv-agent-'));
   // mkdtemp is already 0700, but state it rather than inherit it by luck — and a umask
-  // cannot widen it back.
-  chmodSync(dir, 0o700);
+  // cannot widen it back. A caller-supplied directory keeps the mode its caller chose.
+  if (!providedDir) chmodSync(dir, 0o700);
+  const socketMode = opts.socketMode ?? 0o600;
+  const publicKeyMode = opts.publicKeyMode ?? 0o600;
   const socketPath = path.join(dir, 'agent.sock');
 
   // The PUBLIC half, written to the same 0700 directory. This is not a secret, and ssh
@@ -294,8 +324,13 @@ export function startAgent(identity: LoadedIdentity, onSign?: (e: SignEvent) =>
   writeFileSync(
     publicKeyPath,
     `ssh-ed25519 ${identity.keyBlob.toString('base64')} ${identity.comment || 'wundervault'}\n`,
-    { mode: 0o600 },
+    { mode: publicKeyMode },
   );
+  // writeFileSync's mode applies only when it CREATES the file, and is masked by umask
+  // either way. The public half is not a secret, but ssh must be able to read it, and a
+  // 0644 asked for under umask 0077 arrives as 0600 — which fails silently as "ssh did
+  // not offer the key" rather than as a permission error.
+  try { chmodSync(publicKeyPath, publicKeyMode); } catch { /* best effort */ }
 
   let signs = 0;
   const sockets = new Set<Socket>();
@@ -343,7 +378,7 @@ export function startAgent(identity: LoadedIdentity, onSign?: (e: SignEvent) =>
     // this — connecting needs traverse on the dir AND write on the socket — but the
     // socket lands 0775 under a default umask, so a single wrong directory mode would
     // otherwise leave it open to everyone. Tighten the socket itself too.
-    try { chmodSync(socketPath, 0o600); } catch { /* the directory is still the guard */ }
+    try { chmodSync(socketPath, socketMode); } catch { /* the directory is still the guard */ }
   });
 
   let closed = false;
@@ -358,7 +393,9 @@ export function startAgent(identity: LoadedIdentity, onSign?: (e: SignEvent) =>
       sockets.clear();
       try { server.close(); } catch { /* ignore */ }
       // rm -rf the directory: removing only the socket would leave the 0700 dir behind
-      // every single run.
+      // every single run. A caller-supplied directory is removed too — the broker makes
+      // one per session for exactly this reason, so leaving it would accumulate a
+      // directory per ssh call under /run.
       try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
       process.removeListener('exit', onExit);
     },
@@ -441,28 +478,49 @@ export type BrokeredOp =
   | { kind: 'ssh'; destination: string; remoteArgv: string[] }
   | { kind: 'rsync'; destination: string; rsyncArgs: string[] };
 
-export async function runSshBrokered(opts: {
-  identity: LoadedIdentity;
-  op: BrokeredOp;
-  allowedHosts: string[];
-  cwd?: string;
-  timeoutMs?: number;
-  onSign?: (e: SignEvent) => void;
-}): Promise<SshBrokerResult> {
-  const { identity, op, allowedHosts, cwd, timeoutMs = 120_000, onSign } = opts;
-
+/**
+ * Is this destination one the entry authorises, and what host should the audit name?
+ *
+ * Split out of `runSshBrokered` so the BROKER can make this decision. It used to run in
+ * the MCP server — the agent's own process — which meant the allowlist was advice the
+ * caller gave itself. The broker now refuses to open a signing session for a host the
+ * entry does not list, so the check happens where the key is.
+ */
+export function checkSshDestination(
+  op: BrokeredOp,
+  allowedHosts: string[],
+): { ok: true; auditedHost: string } | { ok: false; error: string } {
   // Fail closed. An entry that names no hosts authorises nothing — treating "unset" as
   // "anywhere" is how an allowlist becomes decoration.
   if (!allowedHosts || allowedHosts.length === 0) {
-    return { exitCode: 1, stdout: '', stderr:
+    return { ok: false, error:
       'Refused: this entry lists no permitted SSH hosts, so it authorises nothing. '
-      + "Add ssh_hosts to the entry's exec_config in the dashboard.", signCount: 0 };
+      + "Add ssh_hosts to the entry's exec_config in the dashboard." };
   }
 
-  const deny = (msg: string): SshBrokerResult => ({ exitCode: 1, stdout: '', stderr: msg, signCount: 0 });
   const host = hostOf(op.destination);
   if (!allowedHosts.includes(host)) {
-    return deny(`Refused: "${host}" is not in this entry's permitted hosts (${allowedHosts.join(', ')}).`);
+    return { ok: false, error:
+      `Refused: "${host}" is not in this entry's permitted hosts (${allowedHosts.join(', ')}).` };
+  }
+
+  if (op.kind === 'ssh') {
+    if (!Array.isArray(op.remoteArgv) || op.remoteArgv.length === 0) {
+      return { ok: false, error: 'Refused: remoteArgv must be a non-empty array.' };
+    }
+  } else {
+    if (!Array.isArray(op.rsyncArgs) || op.rsyncArgs.length === 0) {
+      return { ok: false, error: 'Refused: rsyncArgs must be a non-empty array.' };
+    }
+    // rsync carries its destination inside its path arguments, so every remote-looking
+    // argument is checked against the same allowlist rather than trusting one field.
+    for (const a of op.rsyncArgs) {
+      const h = rsyncRemoteHost(a);
+      if (h !== null && !allowedHosts.includes(h)) {
+        return { ok: false, error:
+          `Refused: rsync argument targets "${h}", which is not in this entry's permitted hosts (${allowedHosts.join(', ')}).` };
+      }
+    }
   }
 
   // rsync carries its destination in its path arguments, so with two allowlisted hosts
@@ -474,84 +532,121 @@ export async function runSshBrokered(opts: {
     const targets = [...new Set(op.rsyncArgs.map(rsyncRemoteHost).filter((h): h is string => h !== null))];
     if (targets.length > 0) auditedHost = targets.join(',');
   }
+  return { ok: true, auditedHost };
+}
 
-  const agent = startAgent(identity, onSign, auditedHost);
-  let argv: string[];
-  try {
-    if (op.kind === 'ssh') {
-      if (!Array.isArray(op.remoteArgv) || op.remoteArgv.length === 0) {
-        agent.close();
-        return deny('Refused: remoteArgv must be a non-empty array.');
-      }
-      // The destination is OURS, not the caller's. Previously the caller passed a whole
-      // argv and the validated host was merely advisory: argv ["ssh","evil.example"]
-      // sailed through a check for "good.example" and the key signed for evil.example.
-      // Building the command here makes the check the thing that decides.
-      // One quoted string, not N arguments: see quoteForRemoteShell.
-      argv = [
-        'ssh', ...hardenedSshOptions(agent.socketPath, agent.publicKeyPath), op.destination, '--',
-        op.remoteArgv.map(quoteForRemoteShell).join(' '),
-      ];
-    } else {
-      if (!Array.isArray(op.rsyncArgs) || op.rsyncArgs.length === 0) {
-        agent.close();
-        return deny('Refused: rsyncArgs must be a non-empty array.');
-      }
-      // rsync carries its destination inside its path arguments, so every remote-looking
-      // argument is checked against the same allowlist rather than trusting one field.
-      for (const a of op.rsyncArgs) {
-        const h = rsyncRemoteHost(a);
-        if (h !== null && !allowedHosts.includes(h)) {
-          agent.close();
-          return deny(`Refused: rsync argument targets "${h}", which is not in this entry's permitted hosts (${allowedHosts.join(', ')}).`);
-        }
-      }
-      const sshCmd = ['ssh', ...hardenedSshOptions(agent.socketPath, agent.publicKeyPath)]
-        .map((t) => (/[\s"']/.test(t) ? JSON.stringify(t) : t)).join(' ');
-      argv = ['rsync', '-e', sshCmd, ...op.rsyncArgs];
-    }
+/**
+ * The argv for a brokered operation, given a signing socket somebody else is hosting.
+ *
+ * The destination is OURS, not the caller's. Previously the caller passed a whole argv
+ * and the validated host was merely advisory: argv ["ssh","evil.example"] sailed through
+ * a check for "good.example" and the key signed for evil.example. Building the command
+ * here makes the check the thing that decides.
+ */
+export function buildSshArgv(op: BrokeredOp, socketPath: string, publicKeyPath: string): string[] {
+  if (op.kind === 'ssh') {
+    // One quoted string, not N arguments: see quoteForRemoteShell.
+    return [
+      'ssh', ...hardenedSshOptions(socketPath, publicKeyPath), op.destination, '--',
+      (op.remoteArgv as string[]).map(quoteForRemoteShell).join(' '),
+    ];
+  }
+  const sshCmd = ['ssh', ...hardenedSshOptions(socketPath, publicKeyPath)]
+    .map((t) => (/[\s"']/.test(t) ? JSON.stringify(t) : t)).join(' ');
+  return ['rsync', '-e', sshCmd, ...(op.rsyncArgs as string[])];
+}
 
-    // spawn, NOT spawnSync. The agent's listener lives on this process's event loop, so
-    // a synchronous spawn would block the very loop that has to answer the child's
-    // signature request — the command would hang until its timeout, every time.
-    return await new Promise<SshBrokerResult>((resolve) => {
-      const child = spawn(argv[0], argv.slice(1), {
-        shell: false,
-        cwd,
-        env: { ...process.env, SSH_AUTH_SOCK: agent.socketPath },
-      });
-
-      // Bounded. A chatty or hostile remote could otherwise grow these strings for the
-      // whole timeout window; truncation is visible rather than silent.
-      const MAX_OUTPUT = 4 * 1024 * 1024;
-      let stdout = '';
-      let stderr = '';
-      let truncated = false;
-      const append = (cur: string, add: string): string => {
-        if (cur.length >= MAX_OUTPUT) { truncated = true; return cur; }
-        const room = MAX_OUTPUT - cur.length;
-        if (add.length > room) { truncated = true; return cur + add.slice(0, room); }
-        return cur + add;
-      };
-      let settled = false;
-      const finish = (exitCode: number, extra = '') => {
-        if (settled) return;
-        settled = true;
-        clearTimeout(timer);
-        const note = truncated ? `\n[output truncated at ${MAX_OUTPUT} bytes]` : '';
-        resolve({ exitCode, stdout, stderr: stderr + extra + note, signCount: agent.signCount() });
-      };
-
-      const timer = setTimeout(() => {
-        try { child.kill('SIGKILL'); } catch { /* already gone */ }
-        finish(124, `\nCommand timed out after ${Math.round(timeoutMs / 1000)}s.`);
-      }, timeoutMs);
-
-      child.stdout?.on('data', (d) => { stdout = append(stdout, d.toString()); });
-      child.stderr?.on('data', (d) => { stderr = append(stderr, d.toString()); });
-      child.on('error', (e) => finish(1, `\nFailed to run ${argv[0]}: ${e.message}`));
-      child.on('close', (code) => finish(code ?? 1));
+/**
+ * Run the command against a signing socket this process does NOT own.
+ *
+ * This is the half that stays in the agent's process after key custody moved. The broker
+ * holds the private key and answers signatures; the command is the agent's own, run on
+ * the agent's own machine, as the agent's own uid. The broker must never run it — a
+ * broker that executes a caller-supplied command hands that caller code execution as the
+ * uid that owns every credential on the box.
+ */
+export async function runSshWithAgent(opts: {
+  op: BrokeredOp;
+  socketPath: string;
+  publicKeyPath: string;
+  cwd?: string;
+  timeoutMs?: number;
+}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
+  const { op, socketPath, publicKeyPath, cwd, timeoutMs = 120_000 } = opts;
+  const argv = buildSshArgv(op, socketPath, publicKeyPath);
+
+  // spawn, NOT spawnSync. When this process hosts the agent listener, a synchronous
+  // spawn blocks the very loop that has to answer the child's signature request. It is
+  // kept asynchronous now that the broker hosts it too, because the child still has to
+  // be able to talk while we wait.
+  return await new Promise((resolve) => {
+    const child = spawn(argv[0], argv.slice(1), {
+      shell: false,
+      cwd,
+      env: { ...process.env, SSH_AUTH_SOCK: socketPath },
+    });
+
+    // Bounded. A chatty or hostile remote could otherwise grow these strings for the
+    // whole timeout window; truncation is visible rather than silent.
+    const MAX_OUTPUT = 4 * 1024 * 1024;
+    let stdout = '';
+    let stderr = '';
+    let truncated = false;
+    const append = (cur: string, add: string): string => {
+      if (cur.length >= MAX_OUTPUT) { truncated = true; return cur; }
+      const room = MAX_OUTPUT - cur.length;
+      if (add.length > room) { truncated = true; return cur + add.slice(0, room); }
+      return cur + add;
+    };
+    let settled = false;
+    const finish = (exitCode: number, extra = '') => {
+      if (settled) return;
+      settled = true;
+      clearTimeout(timer);
+      const note = truncated ? `\n[output truncated at ${MAX_OUTPUT} bytes]` : '';
+      resolve({ exitCode, stdout, stderr: stderr + extra + note });
+    };
+
+    const timer = setTimeout(() => {
+      try { child.kill('SIGKILL'); } catch { /* already gone */ }
+      finish(124, `\nCommand timed out after ${Math.round(timeoutMs / 1000)}s.`);
+    }, timeoutMs);
+
+    child.stdout?.on('data', (d) => { stdout = append(stdout, d.toString()); });
+    child.stderr?.on('data', (d) => { stderr = append(stderr, d.toString()); });
+    child.on('error', (e) => finish(1, `\nFailed to run ${argv[0]}: ${e.message}`));
+    child.on('close', (code) => finish(code ?? 1));
+  });
+}
+
+/**
+ * Check, start an agent, run, close — the single-process path.
+ *
+ * Kept because it is the whole operation in one call for the pre-split layout, for
+ * macOS and Windows, and for the tests that exercise the allowlist and the argv
+ * construction end to end. After key custody it is composed from the three pieces above
+ * rather than duplicating them, so a change to the allowlist cannot apply to one path
+ * and not the other.
+ */
+export async function runSshBrokered(opts: {
+  identity: LoadedIdentity;
+  op: BrokeredOp;
+  allowedHosts: string[];
+  cwd?: string;
+  timeoutMs?: number;
+  onSign?: (e: SignEvent) => void;
+}): Promise<SshBrokerResult> {
+  const { identity, op, allowedHosts, cwd, timeoutMs = 120_000, onSign } = opts;
+
+  const check = checkSshDestination(op, allowedHosts);
+  if (!check.ok) return { exitCode: 1, stdout: '', stderr: check.error, signCount: 0 };
+
+  const agent = startAgent(identity, onSign, check.auditedHost);
+  try {
+    const r = await runSshWithAgent({
+      op, socketPath: agent.socketPath, publicKeyPath: agent.publicKeyPath, cwd, timeoutMs,
     });
+    return { ...r, signCount: agent.signCount() };
   } finally {
     // Always — including on throw and on timeout. A socket outliving its command is an
     // ambient signing capability.

```

## File: src/broker-ops.ts

```
/**
 * What the broker does on an agent's behalf, now that it does not hand over the key.
 *
 * Phase 4 moved the credentials into an account the agent cannot read. It did not stop
 * the broker giving them back: the per-agent socket answered a valid token with
 * `{api_key, enc_key, vault_url}`, and the MCP server — which runs as the AGENT's uid —
 * used `enc_key` to unwrap `vault_key_for_agent` and decrypt the whole vault in its own
 * memory. The boundary held for the disk and for the broker's memory, and the front door
 * handed out the key.
 *
 * So the socket stops serving credentials and starts serving OPERATIONS. Everything in
 * this file runs inside the broker's uid. `vault_key` is derived here, used here, and
 * never crosses the socket.
 *
 * THE RULE THAT SHAPES EVERY OPERATION BELOW
 *
 * The broker never runs a command the agent chose. `ProtectHome=yes` already means it
 * could not reach the agent's files, but the real reason is worse than inconvenience: a
 * broker that executes an agent-supplied command hands that agent code execution as the
 * uid that owns /var/lib/wundervault, which is every credential on the machine. So the
 * operations here are exactly three shapes, and no more:
 *
 *   - hand back a plaintext, ONLY for an entry whose mode says that is what it is for;
 *   - perform a typed HTTP request and return the scrubbed response;
 *   - answer ssh-agent signature requests on a socket, holding the private key.
 *
 * `vault_exec`, `vault_rsync` and `vault_ssh_exec` keep running in the agent's process.
 * They are the agent's own commands on the agent's own machine; what changed is where
 * their key material comes from and what the broker will agree to release.
 *
 * ONE getSecret PER OPERATION, DELIBERATELY
 *
 * Each operation makes exactly one `getSecret` call, the same one the agent used to make.
 * That keeps the server's access log and the tier-2 gate seeing precisely what they saw
 * before. A separate "just the metadata" probe would have been convenient here and would
 * have added an access-log row per call and a second chance to trip tier 2.
 */
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { AgentVaultAPI } from './api-client.js';
import { decryptSecretContent, verifyDirectiveSignature, loadEncryptionKey } from './crypto.js';
import {
  modeAllowsLegacyExec, modeAllowsSshBroker, modeAllowsHttpBroker, wrongModeMessage,
  loadOpenSshEd25519, startAgent, checkSshDestination, type AgentHandle, type BrokeredOp,
} from './ssh-agent.js';
import {
  performOperation, definitionFromAgentRequest, originString, isApprovedPrivateOrigin,
  type AgentRequest,
} from './http-broker.js';
import { verifyOperationDefinition, validateArguments } from './opdef.js';
import { recordDestination, newDestinationNotice, emitToStderr } from './network-store.js';
import { runtimeDir } from './paths.js';
import type { ExecConfig, VaultEntry } from './types.js';
import { DIRECTIVE } from './directive.js';

export interface OpError { error: string; code?: string }

function err(message: string, code?: string): OpError {
  return code ? { error: message, code } : { error: message };
}

/** Parse exec_config, which the backend sends as a JSON string on some paths. */
function coerceCfg(raw: unknown): Record<string, unknown> {
  try {
    const v = typeof raw === 'string' ? JSON.parse(raw) : (raw ?? {});
    return (v && typeof v === 'object') ? v as Record<string, unknown> : {};
  } catch { return {}; }
}

/**
 * One agent's operations. Holds the credentials; never returns them.
 *
 * `api` is built once per profile and kept, because `AgentVaultAPI` caches the unwrapped
 * vault key after the first `ensureVaultKey()`. That cache lives in the broker's memory,
 * which is the whole point of the phase — but it also means a repair (which retires the
 * vault key) must invalidate it, so `reset()` exists and `registerProfile` calls it.
 */
export class BrokerOps {
  private api: AgentVaultAPI;
  private ssh = new Map<string, { handle: AgentHandle; timer: NodeJS.Timeout; entryId: string }>();

  constructor(
    public readonly agentName: string,
    apiKey: string,
    encKeyB64: string,
    vaultUrl: string,
  ) {
    this.api = new AgentVaultAPI(apiKey, loadEncryptionKey(encKeyB64), vaultUrl);
  }

  /** Close every ssh session this agent holds. Called on re-enrolment and on shutdown. */
  reset(): void {
    for (const id of [...this.ssh.keys()]) this.closeSsh(id);
  }

  // ── list_entries ───────────────────────────────────────────────────────────
  async listEntries(): Promise<{ entries: VaultEntry[] } | OpError> {
    const data = await this.api.listSecrets();
    return { entries: data.entries ?? [] };
  }

  // ── profile_flags ──────────────────────────────────────────────────────────
  /**
   * Account-level flags the agent needs before it does local work.
   *
   * Separate from get_entry because `vault_entry_inject_env` has to know the account
   * forbids it BEFORE a secret is fetched and burned — refusing after the fetch would
   * spend a use of the secret to deliver a refusal.
   */
  async profileFlags(): Promise<{ allow_env_inject: boolean }> {
    const p = await this.api.getProfile();
    return { allow_env_inject: p.allow_env_inject ?? false };
  }

  // ── get_entry ──────────────────────────────────────────────────────────────
  /**
   * The one operation that returns a plaintext, and the one the mode gate exists for.
   *
   * The mode check happens HERE. It used to happen in the MCP server, which is the
   * agent's own process — `types.ts` said "enforced client-side" and meant it. An agent
   * that did not want to be gated simply did not run the check, or never used the MCP
   * server at all and read the credentials off the socket directly.
   */
  async getEntry(entryId: string, purpose: string, includePlaintext = true): Promise<{
    plaintext?: string; name: string; integrity: 'valid' | 'invalid' | 'unsigned';
    exec_config: ExecConfig | undefined; entry_mode: string; access_tier: string;
  } | OpError> {
    const s = await this.api.getSecret(entryId, purpose.slice(0, 200));
    if (!modeAllowsLegacyExec(s.entry_mode)) {
      return err(wrongModeMessage(s.entry_mode, 'exec'), 'WRONG_MODE');
    }
    const vaultKey = await this.api.ensureVaultKey();
    const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
    try {
      const directive = s.directive || DIRECTIVE;
      let integrity: 'valid' | 'invalid' | 'unsigned' = 'unsigned';
      if (s.directive_signature) {
        integrity = verifyDirectiveSignature(directive, s.directive_signature, bytes)
          ? 'valid' : 'invalid';
      }
      // An invalid signature is reported, not thrown, and the plaintext is NOT included.
      // The caller aborts on it; sending the secret alongside a warning would make the
      // warning advisory.
      if (integrity === 'invalid') {
        return err(
          `Security warning: directive signature is invalid for '${s.name ?? entryId}'. Aborting.`,
          'BAD_SIGNATURE',
        );
      }
      return {
        // Omitted when the caller says it does not need one. `vault_entry_get` verifies a
        // signature and reports a verdict; it never shows the secret. Sending a plaintext
        // that is going to be thrown away puts it on a socket for no reason.
        ...(includePlaintext ? { plaintext: new TextDecoder().decode(bytes) } : {}),
        name: s.name ?? entryId,
        integrity,
        exec_config: (typeof s.exec_config === 'string'
          ? JSON.parse(s.exec_config) : s.exec_config) as ExecConfig | undefined,
        entry_mode: (s.entry_mode || 'LEGACY_EXEC'),
        access_tier: String(s.access_tier ?? '1'),
      };
    } finally {
      bytes.fill(0);
    }
  }

  // ── call ───────────────────────────────────────────────────────────────────
  /**
   * Perform a typed HTTP request with the credential, and return the response.
   *
   * Moved here whole from the MCP server. `SPEC-tiered-broker.md` said of tier 1 that
   * "the key never reaches the agent" — which was written about this code and was not
   * true of it, because `performOperation` was imported into the agent's own process.
   * It is true now.
   */
  async call(args: {
    entryId: string; purpose: string; operationId?: string;
    callArgs?: Record<string, unknown>; request?: AgentRequest;
  }): Promise<{ status: number; body: unknown; tier: string; label: string; notice?: string } | OpError> {
    const { entryId, purpose } = args;
    const operationId = args.operationId || '';
    const callArgs = args.callArgs ?? {};
    const agentReq = args.request;

    const s = await this.api.getSecret(entryId, purpose.slice(0, 200));
    if (!modeAllowsHttpBroker(s.entry_mode)) {
      return err(wrongModeMessage(s.entry_mode, 'http'), 'WRONG_MODE');
    }

    const vaultKey = await this.api.ensureVaultKey();
    const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
    try {
      const secret = new TextDecoder().decode(bytes);

      // The credential binding always comes from the ENTRY. An agent may choose where a
      // request goes; it never chooses how the secret is framed on the way out.
      let binding: { in: 'header' | 'query'; name: string; template: string } = {
        in: 'header', name: 'authorization', template: 'Bearer {secret}',
      };
      const cfg = coerceCfg(s.exec_config) as { credential_binding?: typeof binding };
      if (cfg?.credential_binding?.name && cfg.credential_binding.template?.includes('{secret}')) {
        binding = cfg.credential_binding;
      }

      let def;
      let label: string;
      if (operationId) {
        let catalogue: Record<string, { definition: unknown; signature?: string }> = {};
        try {
          const raw = s.operations as unknown;
          catalogue = (typeof raw === 'string' ? JSON.parse(raw) : (raw ?? {})) as typeof catalogue;
        } catch { return err("This entry's operation catalogue is not readable."); }
        const slot = catalogue?.[operationId];
        if (!slot) {
          const known = Object.keys(catalogue || {});
          return err(`Entry has no operation "${operationId}".`
            + (known.length ? ` Available: ${known.join(', ')}.` : ' It defines none.'));
        }
        const verified = verifyOperationDefinition(entryId, slot.definition, slot.signature, bytes, operationId);
        if (!verified.ok || !verified.definition) return err(`Refused: ${verified.reason}`);
        const argCheck = validateArguments(verified.definition, callArgs);
        if (!argCheck.ok) return err(`Refused: ${argCheck.reason}`);
        def = verified.definition;
        label = operationId;
      } else {
        const r = agentReq!;
        if (!r?.origin?.host || !r.origin.scheme || !r.origin.port) {
          return err('request.origin needs scheme, host and port.');
        }
        def = definitionFromAgentRequest(r, binding);
        label = `${def.route.method} ${originString(r.origin)}${r.path || '/'}`;
      }

      const bodyHash = agentReq?.body !== undefined
        ? createHash('sha256').update(JSON.stringify(agentReq.body)).digest('hex')
        : undefined;

      // Recorded here, in the broker, which is the first time this has actually worked.
      // The call site used to be in the MCP server — the agent's uid — writing to
      // /var/lib/wundervault/network.json, a directory that uid cannot open. D3 of the
      // uid-split spec calls this store an integrity control because the audited party
      // no longer owns the evidence; until now the audited party was still the writer.
      const originStr = originString(def.origin);
      const { isNew } = recordDestination(entryId, originStr, undefined, purpose);

      const isTier2 = String(s.access_tier ?? '1') === '2';
      const destination = isTier2
        ? { origin: originStr, method: def.route.method, path: def.route.path, body_sha256: bodyHash }
        : {};

      const verdict = await this.api.checkOperation({
        entry_id: entryId, purpose: purpose.slice(0, 200), first_sighting: isNew, ...destination,
      });

      if (!verdict.allowed) {
        const approved = verdict.request_id
          ? await this.api.waitForTier2Approval(verdict.request_id)
          : false;
        if (!approved) {
          return err(`${verdict.message ?? 'This call needs owner approval.'}\n\n`
            + `Nothing was sent. The owner sees exactly: ${def.route.method} `
            + `${originString(def.origin)}${def.route.path}`);
        }
        const second = await this.api.checkOperation({
          entry_id: entryId, purpose: purpose.slice(0, 200), origin: originStr,
          method: def.route.method, path: def.route.path, body_sha256: bodyHash,
        });
        if (!second.allowed) {
          return err(`${second.message ?? 'This call needs owner approval.'}\n\n`
            + `Nothing was sent. The owner sees exactly: ${def.route.method} `
            + `${originString(def.origin)}${def.route.path}`);
        }
        verdict.tier = second.tier;
      }

      let approvedOrigins: string[] = [];
      try {
        const raw = s.allowed_private_origins as unknown;
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (Array.isArray(parsed)) approvedOrigins = parsed.filter((x): x is string => typeof x === 'string');
      } catch { approvedOrigins = []; }

      let noticeForAgent = '';
      if (isNew) {
        const notice = newDestinationNotice(
          s.name ?? entryId, originStr, def.route.method, def.route.path, verdict.tier,
          !operationId, verdict.emailed === true,
        );
        emitToStderr(notice);
        noticeForAgent = notice.toolNote;
      }

      const result = await performOperation(
        def, operationId ? callArgs : ((agentReq?.body ?? {}) as Record<string, unknown>),
        secret, approvedOrigins,
      );
      if (!result.ok && /internal or reserved address/.test(result.error ?? '')
          && !isApprovedPrivateOrigin(def.origin, approvedOrigins)) {
        return err(`${result.error}\n\nIf you host that service yourself, the owner can approve `
          + `exactly ${originString(def.origin)} for this entry in the dashboard. `
          + `Approval is per entry and per exact host and port — it does not open a range, `
          + `and cloud metadata endpoints cannot be approved at all.`);
      }
      if (!result.ok) {
        return err(`${label} failed${result.status ? ` (HTTP ${result.status})` : ''}: ${result.error ?? 'unknown error'}`);
      }
      return {
        status: result.status ?? 0, body: result.body, tier: verdict.tier, label,
        ...(noticeForAgent ? { notice: noticeForAgent } : {}),
      };
    } finally {
      bytes.fill(0);
    }
  }

  // ── ssh_agent_open / ssh_agent_close ───────────────────────────────────────
  /**
   * Hold the private key and answer signature requests on a socket.
   *
   * This is the shape that lets a brokered key be USED without being handed over, and it
   * is the only reason `vault_ssh_exec` can keep running in the agent's process: ssh
   * itself never sees a private key, it asks an agent to sign.
   *
   * THE SOCKET CANNOT LIVE IN /tmp. `startAgent`'s default is `mkdtempSync(os.tmpdir())`,
   * and the unit sets `PrivateTmp=yes`, so that directory exists only inside the broker's
   * mount namespace — the agent would not find the socket at all. It goes under the
   * RuntimeDirectory instead, in a per-session directory with a random name.
   *
   * WHAT THIS DOES NOT FIX. The socket has to be connectable by the agent's uid, and all
   * seven agents share that uid, so any agent that learns the path can ask for a
   * signature while the session is open. The random path and the short life bound that;
   * they do not close it. It is still strictly better than the status quo, where the
   * agent holds the private key itself and can sign with it for ever.
   */
  async sshAgentOpen(args: {
    entryId: string; purpose: string; op: BrokeredOp; ttlSeconds?: number;
  }): Promise<{
    session_id: string; socket_path: string; public_key_path: string; fingerprint: string;
    audited_host: string;
  } | OpError> {
    const { entryId, purpose, op } = args;
    const ttlSeconds = args.ttlSeconds ?? 300;
    const s = await this.api.getSecret(entryId, purpose.slice(0, 200));
    if (!modeAllowsSshBroker(s.entry_mode)) {
      return err(wrongModeMessage(s.entry_mode, 'ssh'), 'WRONG_MODE');
    }

    // THE ALLOWLIST IS CHECKED HERE, BEFORE A SESSION EXISTS.
    //
    // It used to be checked in the MCP server, which is the agent's own process — so the
    // entry's list of permitted hosts was advice the caller gave itself, and an agent
    // that skipped the check had the private key in hand anyway. The broker refuses to
    // OPEN a signing session for a destination the entry does not authorise, which is
    // the first time this list has been a control rather than a convention.
    //
    // The honest limit is unchanged and stated in the class header: once a session is
    // open, any same-uid process that learns the socket path can ask it to sign for some
    // other host. Closing that needs OpenSSH's session-bind extension.
    let allowedHosts: string[] = [];
    const execCfg = coerceCfg(s.exec_config);
    if (Array.isArray((execCfg as { ssh_hosts?: unknown }).ssh_hosts)) {
      allowedHosts = ((execCfg as { ssh_hosts: unknown[] }).ssh_hosts).map(String);
    }
    const check = checkSshDestination(op, allowedHosts);
    if (!check.ok) return err(check.error, 'HOST_NOT_ALLOWED');
    const vaultKey = await this.api.ensureVaultKey();
    const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
    let identity;
    try {
      identity = loadOpenSshEd25519(new TextDecoder().decode(bytes));
    } catch (e) {
      return err(`That entry is not an unencrypted OpenSSH ed25519 private key: ${(e as Error).message}`);
    } finally {
      bytes.fill(0);
    }

    const sessionId = randomId();
    const dir = path.join(runtimeDir(), 'ssh', sessionId);
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    // 0755 on the directory and 0666 on the socket, for the same reason every broker
    // socket is world-connectable: the broker is a different uid from the agent, so a
    // mode that excluded other local users would exclude the agent too. The path is the
    // unguessable part.
    fs.chmodSync(dir, 0o755);

    const handle = startAgent(identity, undefined, check.auditedHost, {
      dir, socketMode: 0o666, publicKeyMode: 0o644,
    });

    const timer = setTimeout(() => this.closeSsh(sessionId), ttlSeconds * 1000);
    (timer as unknown as { unref?: () => void }).unref?.();
    this.ssh.set(sessionId, { handle, timer, entryId });

    return {
      session_id: sessionId,
      socket_path: handle.socketPath,
      public_key_path: handle.publicKeyPath,
      fingerprint: identity.fingerprint,
      audited_host: check.auditedHost,
    };
  }

  closeSsh(sessionId: string): { closed: boolean; signs: number } {
    const rec = this.ssh.get(sessionId);
    if (!rec) return { closed: false, signs: 0 };
    const signs = rec.handle.signCount();
    clearTimeout(rec.timer);
    try { rec.handle.close(); } catch { /* already gone */ }
    this.ssh.delete(sessionId);
    return { closed: true, signs };
  }

  // ── settings ───────────────────────────────────────────────────────────────
  async settings(): Promise<Record<string, unknown>> {
    return this.api.getMcpSettings() as unknown as Record<string, unknown>;
  }
}

function randomId(): string {
  return randomBytes(16).toString('hex');
}

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
- [round 14 B1] deferred: The link is out of argv but still in the enrolment client's memory, under the same uid as the agents
  reason: True and irreducible at this layer: the owner has to paste the link into SOME process running as them. What the fix bought is real - argv is world-readable to every process continuously, process memory needs ptrace of a short-lived process at the right moment. Worth stating in the docs rather than pretending it is closed.
- [round 14 B2] deferred: Profile-store writes are not fsynced before rename
  reason: Real durability gap - a crash between rename and writeback can leave a truncated store. Out of scope for this phase, which is about who can read the file, not whether it survives power loss. Noted for the owner.
- [round 14 B3] deferred: Concurrent enrolments for the same link are not serialised
  reason: Real but now much narrower: the server enforces single-use, and the local window is one round trip. The remaining case needs a burn failure AND a concurrent caller, and F4 now surfaces the burn failure. Not worth a lock in this phase.
- [round 15 B1] deferred: The generated destinations HTML is a full copy of the protected audit store, written into a directory the agents can read
  reason: Real and worth stating: the page is 0600 and owned by the human, but every agent runs as that human, so any agent can read it. The store itself stays protected; what leaks is a snapshot the owner deliberately asked for. Not silently acceptable - it belongs in the docs and possibly behind a --output flag defaulting somewhere else. Raising with the owner rather than deciding alone.
- [round 15 B2] deferred: The installer refuses a home-directory ExecStart but never checks the package tree is not writable by the agent uid
  reason: Real gap with the same shape as the /home rule: a globally-installed tree that happens to be group- or world-writable lets an agent replace the daemon's own code. Worth a check in the installer. Out of scope for this round; noted.
- [round 15 B3] deferred: The rehearsal covers one systemd and kernel version
  reason: True, and MemoryDenyWriteExecute is proof the risk is not theoretical - it was in the list for two commits. The remaining directives now run verified on Ubuntu 24.04 / systemd 255. Broader coverage needs more images than this session should spend; noted for the owner.
- [round 16 B1] deferred: The privilege drop discards the invoking user's supplementary groups rather than restoring their normal set
  reason: True. setgroups([gid]) is deliberately narrow - it drops root's groups, which is the safety property - but it is not the user's real group set either. For writing one file into their own home that is sufficient and arguably safer. Worth initgroups() if this path ever does more; noted rather than changed.
- [round 16 B2] deferred: A low-uid non-login wundervault account may belong to an unrelated service
  reason: Real, and not distinguishable from the outside - an existing nologin account named wundervault could be another vendor's. The installer now says which account it is adopting and its uid. A --account flag would be the proper answer; noted for the owner.
- [round 16 B3] deferred: getent is a synchronous unbounded NSS call on the viewer path
  reason: True but confined to the short-lived CLI, never the daemon. A hung NSS lookup delays one interactive command the user can ctrl-C. Not worth async plumbing here.
- [round 16 B4] deferred: Store validation checks version and that seen is an array, not the field types the generated JS consumes
  reason: Fair - a store with the right shape and wrong field types renders a broken page rather than an error. The page is generated from our own daemon's writes, so this is corruption-only, and the honest-vs-empty distinction that mattered is fixed. Deeper schema validation noted.
- [round 18 B1] deferred: No end-to-end test with a credential materialised by a working TPM
  reason: True and unavoidable here: the rehearsal container has no TPM firmware and could not materialise credentials at all under LoadCredentialEncrypted. The ExecStartPre path IS now verified in-container with host-key sealing, which exercises the same delivery and fallback logic; only the TPM branch is untested. Flagged for the owner's own machine, which does have a TPM.
- [round 18 B2] deferred: Backup and restore semantics for the sealed store are undefined
  reason: Real and worth a runbook entry: a backup of /var/lib/wundervault restored onto different hardware will not decrypt under a TPM-sealed key. The recovery path exists - repair each agent and re-enrol - but it is not written down. Belongs in RESTORE.md; noted for the owner rather than invented now.
- [round 18 B3] deferred: No procedure to rotate or reseal the store key before TPM maintenance
  reason: Same family as B2. The mechanism supports it (delete the blob, re-run the installer, let the store migrate) but there is no documented drill. Worth writing alongside B2.
- [round 19 B1] deferred: listEntries and settings forward API response objects with no output-field allowlist
  reason: Real and worth doing, but it is a change to what the server may send rather than to what this build introduced — the same fields crossed the same boundary before, in the agent's own process. Recorded for the user as an open item rather than changed under this spec.
- [round 19 B2] deferred: No cancellation propagation or per-agent operation queue after a client disconnects
  reason: Real. An authenticated caller can start expensive work and hang up. Out of scope for this spec, which is about key custody rather than resource control, and the caller is already authenticated — so this is a cost question, not a boundary one. Recorded as an open item.
- [round 19 B3] rejected: recordDestination runs before tier approval and the SSRF check, so a refused request is still recorded as a destination
  reason: Correct about the ordering and wrong about it being a defect — it is deliberate and documented at the call site. A first sighting recorded only on success would alert again on every retry of a tier-2 request the owner had not yet answered. The store records ATTEMPTS, which is what an exposure review needs; recording only deliveries would hide precisely the attempts worth looking at. The reviewer's underlying point — that the store's meaning should be stated — is fair, and the comment already says so.
- [round 19 B4] deferred: Decrypted credentials become immutable JS strings; only the byte buffers are wiped
  reason: True and unfixable in this language. Already recorded as a known limit in the phase-5 handoff for the browser side; the same applies in the broker. Wiping the buffers is worth doing anyway and is done. Noted for the user rather than pretended away.
