# Review package — round 27
generated 2026-11-24T03:06:54+00:00

## Spec — judge the build against THIS

# Release review: last changes before the jobs release (2026-11-23)

The jobs release (site feat/vault-jobs, helper feat/vault-jobs = 2.6.0 incl. held 2.5.1) was reviewed
in rounds 1-9. This review covers ONLY what came after round 9:

Site
- A. Newsletter embed (60e55bc, merged): /static/newsletter/embed/* is served sandboxed so the
  issue 31 page can frame an interactive 3D model; /newsletter/issue/* may frame 'self'.
- B. 9807b63: owner's "Test run now" inside the helper's 10-minute limit is refused with
  "Try again in N minutes" instead of waiting silently.
Helper
- C. 3bedaa5: agent-facing text points at the Jobs page; demo-mode test lists the 4 job tools.
- D. c38236f: a signed local activity-log line when a job is saved / not saved / paused / resumed /
  deleted on this machine (real-machine run: pause + resume lines appeared within one poll).

## Acceptance checks
1. An embed page's scripts can never read wundervault.com cookies, localStorage or call the API as
   the signed-in user: every response under the embed prefix carries `sandbox allow-scripts`
   (never allow-same-origin), including when opened directly as a top-level page.
2. No other path gets the embed's looser headers (frame-ancestors 'self', XFO SAMEORIGIN, CORP
   cross-origin) — including encoded / dot-segment / case variants of the prefix.
3. Only /newsletter/issue/* gains frame-src 'self'; nowhere gains a wider frame-src.
4. The embed loads nothing from other hosts and cannot send data out (default-src 'none').
5. B: the refusal is computed from the same 10-minute limit the helper enforces; no run is queued
   when refused; a run allowed after the limit still queues.
6. D: a log write failure never stops an order or a job run; each change logs at most once per real
   state change; no secret, argv or command output goes into the line.
7. C: no tool, schema or behaviour change beyond text and the test.


## What was built this round, and how it was tested

Helper part of the release review (C + D). vitest 2663 all pass at this head. Real machine (iamwyse, branch dist): pausing then resuming a job on the site wrote 'job paused: Hourly backup' then 'job resumed: Hourly backup' lines (kind ssh, outcome sent, extra job_change/version) in sys/activity.log, one each, within one 60s poll. record() is the existing signed hash-chained activity log writer; it redacts the user part of address. Site parts A+B reviewed separately.

## Diff

```diff
diff --git a/src/agent.ts b/src/agent.ts
index 81d56b2..e4d33f7 100644
--- a/src/agent.ts
+++ b/src/agent.ts
@@ -852,6 +852,10 @@ class AgentDaemon {
             const check = await route.ops.jobKeyCheck(job.entry_id);
             const applied = check.ok ? jobs.apply(job, jobKey(route.name), new Date()) : check;
             ok = applied.ok;
+            try {
+              route.ops.recordJobChange({ entryId: job.entry_id, name: job.name, destination: job.destination,
+                version: job.version, change: ok ? 'saved' : 'not saved', ...(applied.ok ? {} : { detail: applied.reason }) });
+            } catch { /* the log write must not stop the order */ }
             lines = applied.ok ? [`PASS job "${job.name}" saved (version ${job.version}); it runs on its schedule`]
               : [`FAIL job "${job.name}" not saved: ${applied.reason}`];
           } catch (e) {
@@ -886,6 +890,10 @@ class AgentDaemon {
               exitCode: run.exit_code, bytes: run.bytes, trigger: run.trigger,
               ms: Math.max(0, Date.parse(run.finished_at) - Date.parse(run.started_at)), ...(run.error ? { detail: run.error } : {}),
             }),
+            recordChange: async (job, change) => r.ops.recordJobChange({
+              entryId: job.def.entry_id, name: job.def.name, destination: job.def.destination,
+              version: job.def.version, change,
+            }),
           }));
           await runDue({ store: jobs, routes: jobRoutes, now: new Date(), running: jobRunning });
         } catch { log('Jobs could not run this poll'); }
diff --git a/src/broker-ops.ts b/src/broker-ops.ts
index 4f4d32b..c6e5cb1 100644
--- a/src/broker-ops.ts
+++ b/src/broker-ops.ts
@@ -209,6 +209,18 @@ export class BrokerOps {
     });
   }
 
+  /** One line in the signed activity log when a job is taken on, refused, paused, resumed or
+   *  deleted on this machine: each changes what runs here with no one watching (owner 11-23). */
+  recordJobChange(r: { entryId: string; name: string; destination: string; version: number;
+    change: 'saved' | 'not saved' | 'paused' | 'resumed' | 'deleted'; detail?: string }): void {
+    this.record({
+      kind: 'ssh', outcome: r.change === 'not saved' ? 'refused' : 'sent', agent: this.agentName, entry_id: r.entryId,
+      reason: `job ${r.change}: ${r.name}`, address: `ssh://${r.destination}`,
+      ...(r.detail ? { detail: r.detail.slice(0, 160) } : {}),
+      extra: { job_change: r.change, version: r.version },
+    });
+  }
+
   /** This agent's route to the server's copy of the log's chain. */
   /** Update now: this agent's route for the owner's update orders, and the key that opens them. */
   orderRoute(): {
@@ -1417,7 +1429,7 @@ export class BrokerOps {
         request_id: r.id,
         state: r.state,
         expires_at: r.expires_at,
-        notice: 'The owner approves this in the vault, under Approvals, with their passkey. '
+        notice: 'The owner approves this on the Jobs page in their vault, with their passkey. '
           + 'Nothing runs until they approve it. Check vault_job_status with this request_id.',
       };
     } catch {
diff --git a/src/jobs.ts b/src/jobs.ts
index da1713b..461c366 100644
--- a/src/jobs.ts
+++ b/src/jobs.ts
@@ -88,6 +88,8 @@ export interface JobRoute extends JobClient {
   /** Seal a failed run's last lines for the owner (the account's vault key). Optional. */
   sealForOwner?(aad: string, value: unknown): Promise<{ ciphertext: string; nonce: string }>;
   recordRun(job: StoredJob, run: LocalJobRun): Promise<void>;
+  /** A signed local line when the owner pauses, resumes or deletes a job (optional). */
+  recordChange?(job: StoredJob, change: 'paused' | 'resumed' | 'deleted'): Promise<void>;
 }
 
 const ID = /^[A-Za-z0-9_-]{8,64}$/;
@@ -516,12 +518,17 @@ export async function runDue(args: {
         // seven days), so it is dropped here too (review r1 F2). Only ever stops a job.
         status = { id, version: saved.def.version, state: 'deleted', run_now: false };
       }
+      const before = saved.state;
       if (status.state === 'deleted' && status.version >= saved.def.version) {
         store.setState(id, 'deleted');
       } else if (status.version === saved.def.version && STATES.includes(status.state)) {
         store.setState(id, status.state);
       } else continue;
       const job = store.get(id)!;
+      if (job.state !== before && route.recordChange) {
+        const change = job.state === 'deleted' ? 'deleted' : job.state === 'paused' ? 'paused' : 'resumed';
+        try { await route.recordChange(job, change); } catch { /* the log write must not stop jobs */ }
+      }
       if (job.state === 'deleted') {
         if (!running.has(jobLock(id)) && !job.pending_runs?.length) store.remove(id);
         continue;
diff --git a/src/server.ts b/src/server.ts
index de2df3c..59a0cd3 100644
--- a/src/server.ts
+++ b/src/server.ts
@@ -99,7 +99,7 @@ function mockToolResult(name: string, args: Record<string, any>) {
   switch (name) {
     case 'vault_job_request':
       return CallToolResultSchema.parse({ content: [{ type: 'text', text:
-        `Demo request demo-job-request is pending. The owner approves it in the vault under Approvals with their passkey. Nothing runs until then. Check vault_job_status with request_id demo-job-request.${MOCK_NOTE}` }] });
+        `Demo request demo-job-request is pending. The owner approves it on the Jobs page in their vault, with their passkey. Nothing runs until then. Check vault_job_status with request_id demo-job-request.${MOCK_NOTE}` }] });
     case 'vault_job_status':
       return CallToolResultSchema.parse({ content: [{ type: 'text', text:
         `Request ${args.request_id ?? 'demo-job-request'}: pending. No job has been created yet.${MOCK_NOTE}` }] });
@@ -286,7 +286,7 @@ export function createServer(args: { url?: string } = {}) {
         description: (
           'Ask the owner for a SCHEDULED JOB the helper app runs for you on a server, with one of your SSH keys. '
           + 'Give a name, entry_id, destination user@host[:port], exact argv (program and arguments, no shell), '
-          + 'schedule, and why it is needed. The owner approves it in the vault under Approvals with a passkey '
+          + 'schedule, and why it is needed. The owner approves it on the Jobs page in their vault, with a passkey '
           + 'and sees the exact command. Nothing runs until then. The job then runs on its own, with no agent involved. '
           + 'Jobs use everyday SSH keys that run without asking, never admin or ask-first keys. '
           + 'Only one job runs per server at a time. Timeout defaults to 300 seconds and cannot exceed 600 seconds. '
diff --git a/test/demo-mode.test.ts b/test/demo-mode.test.ts
index b0d2a10..3c58d0a 100644
--- a/test/demo-mode.test.ts
+++ b/test/demo-mode.test.ts
@@ -65,12 +65,13 @@ describe('demo mode holds no lock (2.0.2: Glama listed one tool)', () => {
     expect(existsSync(ENTRY)).toBe(true);
     const all = await Promise.all([listTools(), listTools(), listTools()]);
     for (const tools of all) {
-      expect(tools.sort()).toEqual(['vault_2fa_code', 'vault_call', 'vault_done', 'vault_entries_list', 'vault_git', 'vault_new_key', 'vault_pay', 'vault_save_secret', 'vault_send_secret', 'vault_sign', 'vault_ssh_exec']);
+      expect(tools.sort()).toEqual(['vault_2fa_code', 'vault_call', 'vault_done', 'vault_entries_list', 'vault_git', 'vault_job_request', 'vault_job_run_now', 'vault_job_status', 'vault_jobs', 'vault_new_key', 'vault_pay', 'vault_save_secret', 'vault_send_secret', 'vault_sign', 'vault_ssh_exec']);
     }
   }, 60_000);
 
   it('every tool answers in demo mode with a demo reply, and none tries to reach a broker', async () => {
-    const tools = ['vault_entries_list', 'vault_call', 'vault_new_key', 'vault_save_secret', 'vault_send_secret', 'vault_ssh_exec', 'vault_pay', 'vault_sign', 'vault_2fa_code', 'vault_git'];
+    const tools = ['vault_entries_list', 'vault_call', 'vault_new_key', 'vault_save_secret', 'vault_send_secret', 'vault_ssh_exec', 'vault_pay', 'vault_sign', 'vault_2fa_code', 'vault_git',
+      'vault_job_request', 'vault_job_status', 'vault_jobs', 'vault_job_run_now'];
     const got = await session(tools.map((name, i) => ({
       id: 10 + i, method: 'tools/call', params: { name, arguments: { entry_id: 'demo-0001', purpose: 'scan',
         destination: 'demo-host', command: 'true', request: { method: 'GET' } } },
diff --git a/test/jobs.test.ts b/test/jobs.test.ts
index d1e55ba..9de7a58 100644
--- a/test/jobs.test.ts
+++ b/test/jobs.test.ts
@@ -495,3 +495,37 @@ describe('failed-run details for the owner', () => {
     expect(JSON.stringify(body)).not.toContain('disk full');
   });
 });
+
+describe('local log of job changes (owner 11-23)', () => {
+  it('records pause, resume and delete once each, and nothing when the state is unchanged', async () => {
+    const dir = directory();
+    const store = storeIn(dir);
+    const changes: string[] = [];
+    const statuses: JobStatus[] = [{ id: 'job_12345', version: 1, state: 'active', run_now: false }];
+    const route = routeFor(dir, statuses);
+    route.getJobs = vi.fn(async () => ({ jobs: statuses.map((s) => ({ ...s })) }));
+    route.recordChange = vi.fn(async (_job, change) => { changes.push(change); });
+    const at = new Date('2026-03-07T01:00:00Z');   // not due: only state changes happen
+    await runDue({ store, routes: [route], now: at, running: new Set() });
+    expect(changes).toEqual([]);
+    statuses[0]!.state = 'paused';
+    await runDue({ store, routes: [route], now: at, running: new Set() });
+    await runDue({ store, routes: [route], now: at, running: new Set() });
+    statuses[0]!.state = 'active';
+    await runDue({ store, routes: [route], now: at, running: new Set() });
+    statuses[0]!.state = 'deleted';
+    await runDue({ store, routes: [route], now: at, running: new Set() });
+    expect(changes).toEqual(['paused', 'resumed', 'deleted']);
+    expect(store.get('job_12345')).toBeUndefined();
+  });
+
+  it('a failing log write does not stop the job loop', async () => {
+    const dir = directory();
+    const store = storeIn(dir);
+    const route = routeFor(dir, [{ id: 'job_12345', version: 1, state: 'paused', run_now: false }]);
+    route.recordChange = vi.fn(async () => { throw new Error('disk full'); });
+    await runDue({ store, routes: [route], now: new Date('2026-03-07T01:00:00Z'), running: new Set() });
+    expect(route.recordChange).toHaveBeenCalledTimes(1);
+    expect(store.get('job_12345')?.state).toBe('paused');
+  });
+});

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
- [round 20 F2] rejected: server.ts still sends the old {token} request, so every agent breaks against the new broker
  reason: Wrong in fact, and correctly hedged by the reviewer ('if src/server.ts remains as described'). server.ts WAS rewritten: getCredentials and tryDaemonConnect are gone, every tool handler calls src/broker-client.ts, which sends {token, op, ...}. Evidence: grep shows zero occurrences of decryptVaultKey/decryptSecretContent/loadEncryptionKey and zero of AgentVaultAPI in server.ts, and test/key-custody.test.ts asserts the whole tool surface over the new protocol. The diff was withheld from this package for the payload cap and the notes said so — this is the blind-spot-shaped finding that arrives when you withhold a file, which is why the notes ask for exactly that flagging.
- [round 21 F3] rejected: The legacy fallback cannot open a pre-phase-7 macOS store after the uid split, because the old store was keyed on the owner uid and the daemon now runs as another
  reason: The arithmetic is right and the conclusion does not follow, because nothing ever asks the daemon to open that store. Migration deliberately carries no credentials: `--migrate` runs as the OWNER, and legacyAgentNames() in migrate.ts derives with the owner's uid to read only the agent NAMES; the credentials are replaced by REPAIR in the dashboard, which is the phase-4 design. The daemon's loadProfiles fallback exists for a store THIS ACCOUNT wrote under the previous derivation, not for the pre-split user store. Reviewer was not shown migrate.ts. What it did catch is a comment of mine that implied the fallback carried a macOS store across — that overclaim is now corrected in the source, with an explicit note not to 'fix' it into reaching across the uid boundary.
- [round 21 F7] rejected: The Windows pre-split warning changed, though the spec requires it byte-for-byte unchanged
  reason: The text did change and it had to. The removed sentence was 'The boundary is Linux-only for now.', which this phase makes FALSE — keeping it byte-for-byte would ship a statement the release contradicts. The spec's 'byte for byte' was about Windows BEHAVIOUR being untouched, which it is: shape 'none', splitAvailable() false, pre-split layout, warning printed. Spec amended to say behaviour rather than bytes, so the next round is not told the same thing.
- [round 22 F2] rejected: Umask 63 makes Node create the unix sockets at 0700, so agents get EACCES connecting
  reason: The code explicitly chmods every socket to 0666 in its listen callback — src/agent.ts:941 for the per-agent sockets, :1215 for the management socket — and chmod is absolute, so umask does not apply to it. The reviewer was not shown agent.ts this round, which is exactly the case I asked it to flag rather than assume, and it was right to raise it. What is real and smaller: between listen() and the chmod there is a brief window at the umask-masked mode, which fails CLOSED (an agent connecting in that window is refused and retries), so it is not worth a startup-ordering change. The same reviewer reflex found the genuine version of this bug in the DIRECTORIES, which is fixed.
- [round 24 B1] deferred: blind spot: the combined machine identity is unstable if one source is transiently unavailable
  reason: Real. A PowerShell hiccup drops the SMBIOS source, the identity changes, and the store will not decrypt. It fails SAFE -- the daemon refuses to serve or overwrite and says the store is unreadable -- so it is confusing rather than destructive, and the supported install path uses store.key rather than a derived key at all. Recorded as an open item: the fix is to record which sources produced the identity and refuse with an accurate message when the set changes, rather than silently deriving a different key.
- [round 24 B2] deferred: blind spot: the installer resets an existing account password before the ACL and task work is known to succeed
  reason: True and low: a failure leaves an account whose password nobody knows, which the next run of the installer fixes, because that is the first thing it does. Noted.
- [round 24 B3] deferred: blind spot: SeDenyBatchLogonRight inherited through group membership or a later GPO is not detected
  reason: Real but niche. Its effect is caught downstream -- the installer now FAILS when the task registers and the broker is not running (F3), which is what a denied logon right produces. Noted rather than checked directly.
- [round 25 B1] deferred: npm install -g can resolve newer deps than the lockfile
  reason: true of every release; the signed archive (what Update now installs) uses the lockfile. Range floor ^1.32.2 guarantees the fixed SDK. Not in scope.
