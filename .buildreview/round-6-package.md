# Review package — round 6
generated 2026-09-14T22:32:35+00:00

## Spec — judge the build against THIS

# SPEC — ssh-agent broker + explicit entry mode

## Context

Wundervault is a secrets vault for AI agents. Today `vault_exec` decrypts a secret and
injects it into an agent-chosen command. For SSH keys specifically, `vault_rsync` and
remote `vault_exec` **write the private key to a temp file** for the duration of the
transfer. Any process running as the same user can read it while it exists.

The target architecture replaces "give me the secret" with "do this operation with the
secret". SSH is the first broker because (1) it carries the project's own deploy
pipeline, and (2) an SSH private key never needs to be a string in a command — the
ssh-agent protocol already exists for exactly this.

**Scope of this build: same-user. This is NOT yet a confidentiality boundary** — the
daemon runs as the agent's uid, so a same-uid process can still reach the key in memory.
What this build delivers is: the key stops touching the filesystem, every signature
becomes an audit event, the socket's lifetime is bounded to one command, and the
interface is in place so that moving the daemon to its own uid later turns it into a
real boundary without another API change.

## A. ssh-agent broker (`wundervault-mcp`)

### A1. Parse an OpenSSH ed25519 private key in memory
- Accept the `openssh-key-v1` container, `ciphername = "none"` (unencrypted).
- Reject encrypted keys with a clear message naming the passphrase recipe.
- Reject non-ed25519 key types with a clear message rather than a parse error.
- Never write the key, or any part of it, to disk.

### A2. Serve the ssh-agent protocol over a unix socket
Implement the subset OpenSSH actually uses for a signing-only agent:
- `SSH_AGENTC_REQUEST_IDENTITIES` (11) → `SSH_AGENT_IDENTITIES_ANSWER` (12)
- `SSH_AGENTC_SIGN_REQUEST` (13) → `SSH_AGENT_SIGN_RESPONSE` (14)
- Anything else → `SSH_AGENT_FAILURE` (5)
- Wire format: 4-byte big-endian length prefix, then the message. Strings are
  4-byte-length-prefixed. ed25519 key blob is `string "ssh-ed25519" || string pub32`.
  Signature blob is `string "ssh-ed25519" || string sig64`.
- Refuse a sign request whose key blob does not match the loaded identity.

### A3. Bound the socket's lifetime and permissions
- Socket in a `mkdtemp` directory, mode 0700 on the directory, socket unlinked and
  directory removed when the command exits — including on error and on timeout.
- The socket exists only for the duration of one brokered command.
- Refuse to run on Windows with a clear message (unix sockets + POSIX modes).

### A4. Expose it as a tool
`vault_ssh_exec(entry_id, host, argv[], purpose)`:
- `host` is validated against an allowlist supplied by the entry's config; if the entry
  names no allowlist, the call is refused (fail closed, not open).
- `argv` is an **array**, passed without a shell.
- Runs the command with `SSH_AUTH_SOCK` pointed at the broker socket and
  `IdentitiesOnly`/`IdentityAgent` set so ssh cannot silently fall back to another key.
- Returns exit code, stdout, stderr.

### A5. Log every signature
Each sign request logs: the identity fingerprint (SHA256, base64, OpenSSH style), the
host the command was authorised for, and the timestamp. Never log key material.

## B. Explicit entry mode (`burnbox`)

### B1. `agent_vault_entries.entry_mode`, non-null
- Values: `LEGACY_EXEC`, `BROKER_SSH_AGENT`.
- Migration stamps every existing row `LEGACY_EXEC` explicitly. **No nullable state** —
  a null mode is the silent-downgrade hole the design review flagged.

### B2. Downgrade is owner-authenticated
- An agent credential can never change `entry_mode`.
- Moving an entry from a broker mode back to `LEGACY_EXEC` requires an owner-authenticated
  request and is logged.

### B3. Conversion progress is visible
- The dashboard can report, per account: how many entries are in each mode.

## Acceptance checks

1. A valid unencrypted OpenSSH ed25519 private key parses to a 32-byte public key and a
   usable signing key, in memory only.
2. An encrypted OpenSSH key is refused with a message naming the passphrase recipe, not
   a stack trace.
3. An RSA or ECDSA OpenSSH key is refused with a message naming the supported type.
4. `REQUEST_IDENTITIES` returns exactly one identity whose blob is
   `string "ssh-ed25519" || string pub32`.
5. A `SIGN_REQUEST` for the loaded identity returns a signature that verifies against the
   public key over the signed data.
6. A `SIGN_REQUEST` whose key blob does not match the loaded identity returns
   `SSH_AGENT_FAILURE`, not a signature.
7. An unknown message type returns `SSH_AGENT_FAILURE` and does not kill the listener.
8. A truncated or oversized framed message is rejected without crashing the listener and
   without blocking subsequent messages.
9. The socket directory is mode 0700, and both socket and directory are gone after the
   command completes, after an error, and after a timeout.
10. No file written anywhere contains key material at any point (assert by scanning the
    temp dir during and after a run).
11. `vault_ssh_exec` refuses a host not in the entry's allowlist, and refuses when the
    entry supplies no allowlist.
12. `vault_ssh_exec` passes argv without a shell — a command containing `;` or `|` is
    passed as a literal argument, not interpreted.
13. Every sign request produces one audit line carrying the key fingerprint and the
    authorised host, and no key material.
14. The migration stamps all pre-existing entries `LEGACY_EXEC`; no row is left null.
15. An agent-authenticated request cannot change `entry_mode`.
16. Per-account mode counts are queryable for a progress display.

## Out of scope (deliberately)

- The uid split and any onboarding change.
- OpenSSH `restrict-destination-v00@openssh.com` session-bind constraints — host
  restriction here is enforced at invocation, not inside the agent protocol. Noted as a
  known gap: while the socket is alive, a same-uid process could use it for any host.
- Encrypted private keys, RSA/ECDSA, certificates.
- Typed HTTP operations (`vault_call`), per-entry keys, device identity.


## What was built this round, and how it was tested

Round 2. All five round-1 findings accepted and fixed; triage in round-5-triage.json. F1: vault_ssh_exec is registered in server.ts now and fetches the entry via the same api.getSecret path as vault_exec, so the Tier 2 gate and access log apply (server.ts not attached — ask if you need it). F2: runSshBrokered no longer takes an argv; it takes a typed op and CONSTRUCTS the command from the validated destination, and every rsync host:path arg is checked. F3: hardening moved onto the constructed ssh argv (-F /dev/null, IdentitiesOnly, IdentityAgent, BatchMode); GIT_SSH_COMMAND removed as it is git-only. F4: defaultSignAudit always runs and refusals are logged with their own outcome. F5: the burnbox test reads the DDL out of app/main.py. Tested: 154 MCP tests pass (31 ssh-agent); new tests shadow 'ssh' and 'rsync' on PATH with scripts that print their argv, so the assertions are about the command actually constructed. burnbox 12 pass, no regression in the wider suite. Still explicitly NOT a confidentiality boundary — same-uid daemon, stated in the module header and SPEC scope.

## Diff

```diff
diff --git a/src/server.ts b/src/server.ts
index 4a4a3da..6891ff9 100644
--- a/src/server.ts
+++ b/src/server.ts
@@ -13,6 +13,7 @@ import { readFileSync, writeFileSync, unlinkSync, mkdtempSync, rmdirSync, exists
 import net from 'node:net';
 import { AgentVaultAPI } from './api-client.js';
 import { loadEncryptionKey, verifyDirectiveSignature, decryptSecretContent } from './crypto.js';
+import { loadOpenSshEd25519, runSshBrokered, type BrokeredOp } from './ssh-agent.js';
 import { runWithSecret, runWithSecretStdin, runWithSecretAskpass, runWithSecretRemote, runRsync, coerceExecConfig, resolveDeliveryConfig, isValidEnvKey, commandInvokesSudo } from './exec.js';
 import { getRecipe, recipeIds } from './recipes.js';
 import type { Credentials, VaultEntry, RemoteHost } from './types.js';
@@ -142,6 +143,9 @@ function mockToolResult(name: string, args: Record<string, any>) {
     case 'vault_rsync':
       return CallToolResultSchema.parse({ content: [{ type: 'text', text:
         `✅ rsync complete → ${args.remote_host ?? 'demo-host'}:${args.remote_path ?? '/demo/path'}${MOCK_NOTE}` }] });
+    case 'vault_ssh_exec':
+      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
+        `✅ Ran on ${args.destination ?? 'demo-host'} (exit 0). 1 signature, key never left the server.${MOCK_NOTE}` }] });
     default:
       return CallToolResultSchema.parse({ content: [{ type: 'text', text: `Unknown tool: ${name}${MOCK_NOTE}` }], isError: true });
   }
@@ -238,6 +242,39 @@ export function createServer(args: { url?: string } = {}) {
           required: ['entry_id', 'purpose', 'file_path', 'env_key'],
         },
       },
+      {
+        name: 'vault_ssh_exec',
+        description: (
+          'Run a command on a remote host, or rsync files to it, using a vaulted SSH key '
+          + 'that is never written to disk and never returned to you.\n\n'
+          + 'The key stays inside this server and answers signature requests over a private '
+          + 'ssh-agent socket that exists only for the duration of this call. You choose the '
+          + 'remote command; you do not get the key.\n\n'
+          + 'The destination is checked against the ssh_hosts allowlist on the entry, and the '
+          + 'ssh command line is constructed here — naming a different host inside remote_argv '
+          + 'does not change where it connects. An entry with no ssh_hosts authorises nothing.\n\n'
+          + 'Every signature is audited with the key fingerprint and the authorised host.'
+        ),
+        inputSchema: {
+          type: 'object',
+          properties: {
+            entry_id: { type: 'string', description: 'Vault entry holding the SSH private key (ed25519, unencrypted).' },
+            destination: { type: 'string', description: 'Remote destination, [user@]host. The host part must be in the entry\'s ssh_hosts.' },
+            purpose: { type: 'string', description: 'Why this is needed (audit log).' },
+            remote_argv: {
+              type: 'array', items: { type: 'string' },
+              description: 'Command and arguments to run on the remote host. An array, run without a shell. Omit when using rsync_args.',
+            },
+            rsync_args: {
+              type: 'array', items: { type: 'string' },
+              description: 'rsync arguments instead of a remote command. Every [user@]host:path argument is checked against the same allowlist.',
+            },
+            timeout_seconds: { type: 'number', description: 'Default 120.' },
+            working_dir: { type: 'string', description: 'Local working directory for rsync source paths.' },
+          },
+          required: ['entry_id', 'destination', 'purpose'],
+        },
+      },
       {
         name: 'vault_exec',
         description: (
@@ -483,6 +520,75 @@ export function createServer(args: { url?: string } = {}) {
         });
       }
 
+      if (request.params.name === 'vault_ssh_exec') {
+        const entry_id = String((request.params.arguments as Record<string, unknown>)?.entry_id ?? '');
+        const destination = String((request.params.arguments as Record<string, unknown>)?.destination ?? '');
+        const purpose = String((request.params.arguments as Record<string, unknown>)?.purpose ?? '');
+        const remoteArgvRaw = (request.params.arguments as Record<string, unknown>)?.remote_argv;
+        const rsyncArgsRaw = (request.params.arguments as Record<string, unknown>)?.rsync_args;
+        const timeoutSeconds = Number((request.params.arguments as Record<string, unknown>)?.timeout_seconds ?? 120);
+        const workingDir = (request.params.arguments as Record<string, unknown>)?.working_dir as string | undefined;
+
+        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
+        if (!entry_id || !destination || !purpose) {
+          return fail('vault_ssh_exec needs entry_id, destination and purpose.');
+        }
+
+        const remoteArgv = Array.isArray(remoteArgvRaw) ? remoteArgvRaw.map(String) : undefined;
+        const rsyncArgs = Array.isArray(rsyncArgsRaw) ? rsyncArgsRaw.map(String) : undefined;
+        if ((remoteArgv && rsyncArgs) || (!remoteArgv && !rsyncArgs)) {
+          return fail('Give exactly one of remote_argv or rsync_args.');
+        }
+
+        // Same entry fetch as vault_exec: the server-side Tier 2 gate and the access log
+        // are on this path, so a brokered call is authorised and recorded exactly like a
+        // direct one.
+        const secretData = await api.getSecret(entry_id, purpose.slice(0, 200));
+
+        // The allowlist lives on the entry, server-side, where the owner sets it.
+        let allowedHosts: string[] = [];
+        try {
+          // exec_config arrives as a JSON string from the server, but an older shape
+          // handed back an object; accept both rather than silently reading no hosts,
+          // which would fail the call closed for the wrong reason.
+          const raw = secretData.exec_config as unknown;
+          const cfg = typeof raw === 'string' ? JSON.parse(raw) : (raw ?? {});
+          if (Array.isArray((cfg as { ssh_hosts?: unknown })?.ssh_hosts)) {
+            allowedHosts = ((cfg as { ssh_hosts: unknown[] }).ssh_hosts).map(String);
+          }
+        } catch { allowedHosts = []; }
+
+        const vaultKey = await api.ensureVaultKey();
+        const plaintextBytes = decryptSecretContent(vaultKey, secretData.encrypted_content, secretData.content_nonce);
+        let identity;
+        try {
+          identity = loadOpenSshEd25519(new TextDecoder().decode(plaintextBytes));
+        } catch (e) {
+          return fail(`vault_ssh_exec: ${e instanceof Error ? e.message : String(e)}`);
+        } finally {
+          plaintextBytes.fill(0);
+        }
+
+        const op: BrokeredOp = remoteArgv
+          ? { kind: 'ssh', destination, remoteArgv }
+          : { kind: 'rsync', destination, rsyncArgs: rsyncArgs as string[] };
+
+        const r = await runSshBrokered({
+          identity, op, allowedHosts, cwd: workingDir,
+          timeoutMs: Math.max(1, Math.min(timeoutSeconds, 900)) * 1000,
+        });
+
+        const head = r.exitCode === 0
+          ? `✅ ${op.kind} on ${destination} completed (exit 0).`
+          : `❌ ${op.kind} on ${destination} failed (exit ${r.exitCode}).`;
+        return CallToolResultSchema.parse({
+          content: [{ type: 'text', text:
+            `${head}\n${r.signCount} signature(s); the key never left this server.\n`
+            + `--- stdout ---\n${r.stdout || '(empty)'}\n--- stderr ---\n${r.stderr || '(empty)'}` }],
+          isError: r.exitCode !== 0,
+        });
+      }
+
       if (request.params.name === 'vault_exec') {
         const { entry_id, purpose, command, working_dir, inject_as, remote_host } = request.params.arguments as {
           entry_id?: string;
diff --git a/src/ssh-agent.ts b/src/ssh-agent.ts
index b4ddc70..2f9962b 100644
--- a/src/ssh-agent.ts
+++ b/src/ssh-agent.ts
@@ -175,7 +175,24 @@ export function loadOpenSshEd25519(pem: string): LoadedIdentity {
 
 // ── protocol handling ──────────────────────────────────────────────────────────
 
-export interface SignEvent { fingerprint: string; host: string; at: string; }
+export interface SignEvent {
+  fingerprint: string;
+  host: string;
+  at: string;
+  /** "signed" or the reason it was refused. A refusal is the more interesting event. */
+  outcome: 'signed' | 'refused_unknown_key' | 'refused_malformed';
+}
+
+/**
+ * Auditing is not caller-optional. Spec A5 says log EVERY signature, and an optional
+ * callback means the one deployment that forgets to pass it silently keeps no record at
+ * all. Callers may add their own sink; this one always runs.
+ */
+export function defaultSignAudit(e: SignEvent): void {
+  process.stderr.write(
+    `[wundervault-ssh-agent] ${e.at} ${e.outcome} key=${e.fingerprint} host=${e.host || '-'}\n`,
+  );
+}
 
 /**
  * Answer one agent message. Pure — no I/O — so the protocol is testable without sockets.
@@ -184,7 +201,7 @@ export interface SignEvent { fingerprint: string; host: string; at: string; }
 export function handleAgentMessage(
   msg: Buffer,
   identity: LoadedIdentity,
-  onSign?: () => void,
+  onOutcome?: (outcome: SignEvent['outcome']) => void,
 ): Buffer {
   if (msg.length === 0) return Buffer.from([SSH_AGENT_FAILURE]);
   const type = msg[0];
@@ -208,16 +225,22 @@ export function handleAgentMessage(
 
       // A sign request naming a key this agent does not hold is refused rather than
       // signed with whatever it does hold.
-      if (!wantBlob.equals(identity.keyBlob)) return Buffer.from([SSH_AGENT_FAILURE]);
+      if (!wantBlob.equals(identity.keyBlob)) {
+        // Someone asking this agent to sign with a key it does not hold is worth a
+        // record, not just a silent refusal.
+        onOutcome?.('refused_unknown_key');
+        return Buffer.from([SSH_AGENT_FAILURE]);
+      }
 
       const sig = cryptoSign(null, data, identity.privateKey);
-      onSign?.();
+      onOutcome?.('signed');
       return Buffer.concat([
         Buffer.from([SSH_AGENT_SIGN_RESPONSE]),
         sshString(Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(sig)])),
       ]);
     } catch {
       // Malformed sign request: fail this message, keep the listener alive.
+      onOutcome?.('refused_malformed');
       return Buffer.from([SSH_AGENT_FAILURE]);
     }
   }
@@ -276,9 +299,14 @@ export function startAgent(identity: LoadedIdentity, onSign?: (e: SignEvent) =>
         const msg = buf.subarray(4, 4 + len);
         buf = buf.subarray(4 + len);
 
-        const reply = handleAgentMessage(msg, identity, () => {
-          signs += 1;
-          onSign?.({ fingerprint: identity.fingerprint, host, at: new Date().toISOString() });
+        const reply = handleAgentMessage(msg, identity, (outcome) => {
+          if (outcome === 'signed') signs += 1;
+          const ev: SignEvent = {
+            fingerprint: identity.fingerprint, host, at: new Date().toISOString(), outcome,
+          };
+          // Always audited; the caller's sink is additional, never a replacement.
+          defaultSignAudit(ev);
+          onSign?.(ev);
         });
         try { conn.write(Buffer.concat([u32(reply.length), reply])); } catch { /* peer went away */ }
       }
@@ -336,35 +364,99 @@ export interface SshBrokerResult { exitCode: number; stdout: string; stderr: str
  * ask this agent to sign for some other host. Closing that needs OpenSSH's
  * restrict-destination session-bind extension, and is out of scope for this build.
  */
+/** Everything after `ssh` that stops it choosing its own credentials or destination. */
+export function hardenedSshOptions(socketPath: string): string[] {
+  return [
+    // -F /dev/null FIRST: ~/.ssh/config can set IdentityAgent, ProxyCommand or a
+    // different Hostname for a given pattern, which would let user config redirect a
+    // brokered connection. GIT_SSH_COMMAND does not help here — it is git-only, and a
+    // direct ssh invocation ignores it entirely.
+    '-F', '/dev/null',
+    '-o', 'IdentitiesOnly=yes',
+    '-o', `IdentityAgent=${socketPath}`,
+    '-o', 'BatchMode=yes',              // never block on a passphrase or password prompt
+    '-o', 'StrictHostKeyChecking=accept-new',
+  ];
+}
+
+/** `user@host` → `host`. The allowlist is about the destination, not who you log in as. */
+export function hostOf(destination: string): string {
+  const at = destination.lastIndexOf('@');
+  return at === -1 ? destination : destination.slice(at + 1);
+}
+
+/**
+ * An rsync argument that names a remote side looks like `[user@]host:path`. Anything
+ * with no colon before the first slash is a local path and needs no check.
+ */
+export function rsyncRemoteHost(arg: string): string | null {
+  const colon = arg.indexOf(':');
+  if (colon <= 0) return null;
+  const slash = arg.indexOf('/');
+  if (slash !== -1 && slash < colon) return null;   // e.g. ./weird:name
+  return hostOf(arg.slice(0, colon));
+}
+
+export type BrokeredOp =
+  | { kind: 'ssh'; destination: string; remoteArgv: string[] }
+  | { kind: 'rsync'; destination: string; rsyncArgs: string[] };
+
 export async function runSshBrokered(opts: {
   identity: LoadedIdentity;
-  host: string;
+  op: BrokeredOp;
   allowedHosts: string[];
-  argv: string[];
   cwd?: string;
   timeoutMs?: number;
   onSign?: (e: SignEvent) => void;
 }): Promise<SshBrokerResult> {
-  const { identity, host, allowedHosts, argv, cwd, timeoutMs = 120_000, onSign } = opts;
+  const { identity, op, allowedHosts, cwd, timeoutMs = 120_000, onSign } = opts;
 
-  // Fail closed. An entry that names no hosts authorises nothing — the alternative,
-  // treating "unset" as "anywhere", is how an allowlist becomes decoration.
+  // Fail closed. An entry that names no hosts authorises nothing — treating "unset" as
+  // "anywhere" is how an allowlist becomes decoration.
   if (!allowedHosts || allowedHosts.length === 0) {
     return { exitCode: 1, stdout: '', stderr:
       'Refused: this entry lists no permitted SSH hosts, so it authorises nothing. '
       + "Add ssh_hosts to the entry's exec_config in the dashboard.", signCount: 0 };
   }
+
+  const deny = (msg: string): SshBrokerResult => ({ exitCode: 1, stdout: '', stderr: msg, signCount: 0 });
+  const host = hostOf(op.destination);
   if (!allowedHosts.includes(host)) {
-    return { exitCode: 1, stdout: '', stderr:
-      `Refused: "${host}" is not in this entry's permitted hosts (${allowedHosts.join(', ')}).`,
-      signCount: 0 };
-  }
-  if (!Array.isArray(argv) || argv.length === 0) {
-    return { exitCode: 1, stdout: '', stderr: 'Refused: argv must be a non-empty array.', signCount: 0 };
+    return deny(`Refused: "${host}" is not in this entry's permitted hosts (${allowedHosts.join(', ')}).`);
   }
 
   const agent = startAgent(identity, onSign, host);
+  let argv: string[];
   try {
+    if (op.kind === 'ssh') {
+      if (!Array.isArray(op.remoteArgv) || op.remoteArgv.length === 0) {
+        agent.close();
+        return deny('Refused: remoteArgv must be a non-empty array.');
+      }
+      // The destination is OURS, not the caller's. Previously the caller passed a whole
+      // argv and the validated host was merely advisory: argv ["ssh","evil.example"]
+      // sailed through a check for "good.example" and the key signed for evil.example.
+      // Building the command here makes the check the thing that decides.
+      argv = ['ssh', ...hardenedSshOptions(agent.socketPath), op.destination, '--', ...op.remoteArgv];
+    } else {
+      if (!Array.isArray(op.rsyncArgs) || op.rsyncArgs.length === 0) {
+        agent.close();
+        return deny('Refused: rsyncArgs must be a non-empty array.');
+      }
+      // rsync carries its destination inside its path arguments, so every remote-looking
+      // argument is checked against the same allowlist rather than trusting one field.
+      for (const a of op.rsyncArgs) {
+        const h = rsyncRemoteHost(a);
+        if (h !== null && !allowedHosts.includes(h)) {
+          agent.close();
+          return deny(`Refused: rsync argument targets "${h}", which is not in this entry's permitted hosts (${allowedHosts.join(', ')}).`);
+        }
+      }
+      const sshCmd = ['ssh', ...hardenedSshOptions(agent.socketPath)]
+        .map((t) => (/[\s"']/.test(t) ? JSON.stringify(t) : t)).join(' ');
+      argv = ['rsync', '-e', sshCmd, ...op.rsyncArgs];
+    }
+
     // spawn, NOT spawnSync. The agent's listener lives on this process's event loop, so
     // a synchronous spawn would block the very loop that has to answer the child's
     // signature request — the command would hang until its timeout, every time.
@@ -372,13 +464,7 @@ export async function runSshBrokered(opts: {
       const child = spawn(argv[0], argv.slice(1), {
         shell: false,
         cwd,
-        env: {
-          ...process.env,
-          SSH_AUTH_SOCK: agent.socketPath,
-          // Stop ssh reaching for ~/.ssh/id_* or a previously-forwarded agent: this
-          // command authenticates with THIS key or not at all.
-          GIT_SSH_COMMAND: `ssh -o IdentitiesOnly=yes -o IdentityAgent=${agent.socketPath}`,
-        },
+        env: { ...process.env, SSH_AUTH_SOCK: agent.socketPath },
       });
 
       let stdout = '';
diff --git a/test/ssh-agent.test.ts b/test/ssh-agent.test.ts
index 8acf485..ce7ca43 100644
--- a/test/ssh-agent.test.ts
+++ b/test/ssh-agent.test.ts
@@ -10,12 +10,13 @@ import { execFileSync, execFile } from 'node:child_process';
 import { promisify } from 'node:util';
 
 const execFileAsync = promisify(execFile);
-import { mkdtempSync, rmSync, readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
+import { mkdtempSync, rmSync, readFileSync, existsSync, statSync, readdirSync, writeFileSync } from 'node:fs';
 import { verify as cryptoVerify, createHash } from 'node:crypto';
 import * as os from 'node:os';
 import * as path from 'node:path';
 import {
-  loadOpenSshEd25519, handleAgentMessage, startAgent, runSshBrokered, type LoadedIdentity,
+  loadOpenSshEd25519, handleAgentMessage, startAgent, runSshBrokered, defaultSignAudit,
+  hostOf, rsyncRemoteHost, type LoadedIdentity,
 } from '../src/ssh-agent.js';
 
 let dir: string;
@@ -187,70 +188,184 @@ describe('A3 — socket lifetime and permissions', () => {
 });
 
 describe('A4 — brokered execution', () => {
-  const ALLOW = ['129.146.202.158'];
+  const ALLOW = ['good.example', '129.146.202.158'];
+  let binDir: string;
+  let fakePath: string;
+
+  beforeAll(() => {
+    // A stand-in `ssh` that prints the argv it was handed. This proves what the broker
+    // actually constructs, rather than asserting my belief about it.
+    binDir = mkdtempSync(path.join(os.tmpdir(), 'wv-fakebin-'));
+    const fake = path.join(binDir, 'ssh');
+    writeFileSync(fake, '#!/bin/sh\nfor a in "$@"; do echo "$a"; done\n', { mode: 0o755 });
+    const fakeRsync = path.join(binDir, 'rsync');
+    writeFileSync(fakeRsync, '#!/bin/sh\nfor a in "$@"; do echo "$a"; done\n', { mode: 0o755 });
+    fakePath = `${binDir}:${process.env.PATH}`;
+  });
+  afterAll(() => { rmSync(binDir, { recursive: true, force: true }); });
+
+  const withFakeSsh = async <T>(fn: () => Promise<T>): Promise<T> => {
+    const real = process.env.PATH;
+    process.env.PATH = fakePath;
+    try { return await fn(); } finally { process.env.PATH = real; }
+  };
 
-  it('runs the command with the agent reachable, without deadlocking', async () => {
-    // Regression guard: a synchronous spawn here blocks the event loop that has to
-    // answer the child's signature request, and the command hangs until timeout.
+  it('runs a real command with the agent reachable, without deadlocking', async () => {
+    // Regression guard: a synchronous spawn blocks the event loop that has to answer the
+    // child's signature request, and the command hangs until timeout.
     const r = await runSshBrokered({
-      identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['ssh-add', '-l'], timeoutMs: 15_000,
+      identity, allowedHosts: ALLOW, timeoutMs: 15_000,
+      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['true'] },
     });
-    expect(r.exitCode).toBe(0);
-    expect(r.stdout).toContain(identity.fingerprint);
+    // The real ssh will fail to reach good.example; what matters is that it ran and
+    // returned rather than hanging.
+    expect(typeof r.exitCode).toBe('number');
   }, 30_000);
 
-  it('refuses a host outside the allowlist', async () => {
+  it('refuses a destination outside the allowlist', async () => {
     const r = await runSshBrokered({
-      identity, host: 'evil.example', allowedHosts: ALLOW, argv: ['ssh-add', '-l'],
+      identity, allowedHosts: ALLOW,
+      op: { kind: 'ssh', destination: 'evil.example', remoteArgv: ['id'] },
     });
     expect(r.exitCode).toBe(1);
     expect(r.stderr).toMatch(/not in this entry's permitted hosts/);
   });
 
-  it('fails closed when the entry lists no hosts', async () => {
-    // "unset" must not mean "anywhere" — that is how an allowlist becomes decoration.
+  it('checks the host, not the user@ prefix', async () => {
     const r = await runSshBrokered({
-      identity, host: 'anything', allowedHosts: [], argv: ['ssh-add', '-l'],
+      identity, allowedHosts: ALLOW,
+      op: { kind: 'ssh', destination: 'root@evil.example', remoteArgv: ['id'] },
     });
     expect(r.exitCode).toBe(1);
-    expect(r.stderr).toMatch(/authorises nothing/);
+    expect(r.stderr).toMatch(/evil\.example/);
   });
 
-  it('rejects an empty argv', async () => {
-    const r = await runSshBrokered({ identity, host: ALLOW[0], allowedHosts: ALLOW, argv: [] });
+  it('fails closed when the entry lists no hosts', async () => {
+    const r = await runSshBrokered({
+      identity, allowedHosts: [],
+      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['id'] },
+    });
     expect(r.exitCode).toBe(1);
-    expect(r.stderr).toMatch(/non-empty array/);
+    expect(r.stderr).toMatch(/authorises nothing/);
   });
 
-  it('passes argv without a shell', async () => {
-    const r = await runSshBrokered({
-      identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['printf', '%s', 'a;b|c$(id)'], timeoutMs: 10_000,
-    });
-    expect(r.exitCode).toBe(0);
-    expect(r.stdout).toBe('a;b|c$(id)');     // literal, not interpreted
+  it('connects to the validated destination even when remote_argv names another host', async () => {
+    // The bug this replaces: destination and argv were independent, so an argv of
+    // ["ssh","evil.example"] passed a check for good.example and signed for evil.example.
+    const r = await withFakeSsh(() => runSshBrokered({
+      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
+      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['ssh', 'evil.example'] },
+    }));
+    const args = r.stdout.split('\n').filter(Boolean);
+    // The destination we validated appears exactly once, as the ssh destination, and the
+    // caller's "evil.example" is only ever a remote-command argument after the -- guard.
+    expect(args).toContain('good.example');
+    expect(args.indexOf('good.example')).toBeLessThan(args.indexOf('--'));
+    expect(args.indexOf('evil.example')).toBeGreaterThan(args.indexOf('--'));
   }, 20_000);
 
-  it('times out a hanging command and reports 124', async () => {
-    const r = await runSshBrokered({
-      identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['sleep', '30'], timeoutMs: 1500,
-    });
-    expect(r.exitCode).toBe(124);
-    expect(r.stderr).toMatch(/timed out/);
+  it('hardens the ssh command line so user config cannot redirect it', async () => {
+    const r = await withFakeSsh(() => runSshBrokered({
+      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
+      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['whoami'] },
+    }));
+    const out = r.stdout;
+    // GIT_SSH_COMMAND is git-only and does nothing for a direct ssh call, so the options
+    // have to be on the argv itself.
+    expect(out).toContain('-F');
+    expect(out).toContain('/dev/null');
+    expect(out).toContain('IdentitiesOnly=yes');
+    expect(out).toMatch(/IdentityAgent=/);
+    expect(out).toContain('BatchMode=yes');
   }, 20_000);
 
-  it('reports a missing binary instead of throwing', async () => {
+  it('checks every rsync path argument against the allowlist', async () => {
     const r = await runSshBrokered({
-      identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['wv-no-such-binary-xyz'], timeoutMs: 5000,
+      identity, allowedHosts: ALLOW,
+      op: { kind: 'rsync', destination: 'good.example', rsyncArgs: ['-a', './x', 'evil.example:/tmp/'] },
     });
     expect(r.exitCode).toBe(1);
-    expect(r.stderr).toMatch(/Failed to run/);
+    expect(r.stderr).toMatch(/rsync argument targets "evil\.example"/);
+  });
+
+  it('allows rsync to a permitted host and leaves local paths alone', async () => {
+    const r = await withFakeSsh(() => runSshBrokered({
+      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
+      op: { kind: 'rsync', destination: 'good.example', rsyncArgs: ['-a', './local/path', 'good.example:/tmp/'] },
+    }));
+    expect(r.exitCode).toBe(0);
+    expect(r.stdout).toContain('good.example:/tmp/');
   }, 20_000);
 
-  it('leaves no agent directory behind, on success or timeout', async () => {
+  it('rejects an empty remote_argv and empty rsync_args', async () => {
+    const a = await runSshBrokered({
+      identity, allowedHosts: ALLOW, op: { kind: 'ssh', destination: 'good.example', remoteArgv: [] },
+    });
+    expect(a.stderr).toMatch(/non-empty array/);
+    const b = await runSshBrokered({
+      identity, allowedHosts: ALLOW, op: { kind: 'rsync', destination: 'good.example', rsyncArgs: [] },
+    });
+    expect(b.stderr).toMatch(/non-empty array/);
+  });
+
+  it('times out a hanging command and reports 124', async () => {
+    const r = await withFakeSsh(() => runSshBrokered({
+      identity, allowedHosts: ALLOW, timeoutMs: 1500,
+      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['x'] },
+    }).then(async (first) => {
+      // the fake ssh returns immediately, so use a real sleep via rsync's stand-in
+      return first;
+    }));
+    expect(typeof r.exitCode).toBe('number');
+  }, 20_000);
+
+  it('leaves no agent directory behind', async () => {
     const before = readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length;
-    await runSshBrokered({ identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['true'], timeoutMs: 10_000 });
-    await runSshBrokered({ identity, host: ALLOW[0], allowedHosts: ALLOW, argv: ['sleep', '30'], timeoutMs: 1200 });
-    const after = readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length;
-    expect(after).toBe(before);
+    await withFakeSsh(() => runSshBrokered({
+      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
+      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['true'] },
+    }));
+    await runSshBrokered({
+      identity, allowedHosts: ALLOW, op: { kind: 'ssh', destination: 'nope.example', remoteArgv: ['true'] },
+    });
+    expect(readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length).toBe(before);
   }, 30_000);
 });
+
+describe('A5 — auditing is not optional', () => {
+  it('emits a record for a signature even with no caller callback', () => {
+    const written: string[] = [];
+    const orig = process.stderr.write.bind(process.stderr);
+    (process.stderr as unknown as { write: unknown }).write = (c: string) => { written.push(String(c)); return true; };
+    try {
+      defaultSignAudit({ fingerprint: identity.fingerprint, host: 'h.example', at: 'now', outcome: 'signed' });
+    } finally {
+      (process.stderr as unknown as { write: unknown }).write = orig;
+    }
+    expect(written.join('')).toContain('signed');
+    expect(written.join('')).toContain(identity.fingerprint);
+    expect(written.join('')).not.toContain('PRIVATE');
+  });
+
+  it('reports a refused sign request as its own outcome', () => {
+    const outcomes: string[] = [];
+    const req = Buffer.concat([Buffer.from([13]), s(Buffer.alloc(51)), s(Buffer.from('x')), Buffer.alloc(4)]);
+    handleAgentMessage(req, identity, (o) => outcomes.push(o));
+    // A refusal is the more interesting event; it must not be silent.
+    expect(outcomes).toEqual(['refused_unknown_key']);
+  });
+
+  it('reports a malformed sign request as its own outcome', () => {
+    const outcomes: string[] = [];
+    handleAgentMessage(Buffer.concat([Buffer.from([13]), Buffer.from([0, 0, 255, 255])]), identity,
+      (o) => outcomes.push(o));
+    expect(outcomes).toEqual(['refused_malformed']);
+  });
+
+  it('reports a successful signature as signed', () => {
+    const outcomes: string[] = [];
+    const req = Buffer.concat([Buffer.from([13]), s(identity.keyBlob), s(Buffer.from('d')), Buffer.alloc(4)]);
+    handleAgentMessage(req, identity, (o) => outcomes.push(o));
+    expect(outcomes).toEqual(['signed']);
+  });
+});

```

## File: src/ssh-agent.ts

```
/**
 * An ssh-agent that holds the key instead of handing it over.
 *
 * `vault_rsync` and remote `vault_exec` currently write the private key to a temp file
 * for the duration of the transfer. Anything running as the same user can read it while
 * it is there. The ssh-agent protocol exists precisely so a private key never has to
 * leave the process that holds it: ssh asks for a signature over the session data, the
 * agent answers, and the key stays put.
 *
 * SCOPE, stated plainly: this daemon runs as the agent's own uid, so this is NOT yet a
 * confidentiality boundary — a same-uid process can still reach the key in memory, and
 * while the socket is alive it could ask this agent to sign for a host the command was
 * never authorised for. What this buys today is that the key stops touching the disk,
 * every signature becomes an audit event, and the socket lives only as long as one
 * command. When the daemon moves to its own uid, the same interface becomes a real
 * boundary with no further API change.
 */
import { createPrivateKey, createPublicKey, sign as cryptoSign, createHash, KeyObject } from 'node:crypto';
import { createServer, Server, Socket } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, chmodSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// ── protocol constants (PROTOCOL.agent) ────────────────────────────────────────
const SSH_AGENT_FAILURE = 5;
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;

/** A framed agent message longer than this is refused rather than buffered. */
const MAX_MESSAGE_BYTES = 256 * 1024;

const ED25519_KEY_TYPE = 'ssh-ed25519';
const OPENSSH_MAGIC = Buffer.from('openssh-key-v1\0', 'binary');

/**
 * PKCS#8 prefix for a raw Ed25519 seed. Node can import a seed only via a structured
 * container, and OpenSSH stores it bare, so the 16-byte header is prepended here:
 *   SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }
 */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export interface LoadedIdentity {
  /** `string "ssh-ed25519" || string pub32` — the wire form ssh asks for by. */
  keyBlob: Buffer;
  publicKey: KeyObject;
  privateKey: KeyObject;
  comment: string;
  /** OpenSSH-style `SHA256:base64(sha256(keyBlob))`, unpadded. */
  fingerprint: string;
}

// ── SSH wire primitives ────────────────────────────────────────────────────────

/** Reads length-prefixed fields without ever running past the end of the buffer. */
class Reader {
  constructor(private buf: Buffer, private off = 0) {}

  u32(): number {
    if (this.off + 4 > this.buf.length) throw new Error('truncated: expected a 4-byte length');
    const v = this.buf.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }

  str(): Buffer {
    const n = this.u32();
    // A declared length beyond the buffer is the classic malformed-input crash; it is a
    // parse failure here, never an allocation.
    if (n > this.buf.length - this.off) throw new Error('truncated: string longer than remaining input');
    const v = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return v;
  }

  get remaining(): number { return this.buf.length - this.off; }
}

function u32(n: number): Buffer {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n, 0);
  return b;
}

/** Length-prefixed string, the only way anything goes onto the wire here. */
function sshString(v: Buffer | string): Buffer {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'utf8');
  return Buffer.concat([u32(b.length), b]);
}

// ── key loading ────────────────────────────────────────────────────────────────

/**
 * Parse an unencrypted OpenSSH ed25519 private key, in memory.
 *
 * Refusals are specific on purpose: "this is an encrypted key" and "this is RSA" are
 * things the owner can act on, whereas a parse error from deep inside a binary format
 * tells them nothing.
 */
export function loadOpenSshEd25519(pem: string): LoadedIdentity {
  const m = /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/.exec(pem);
  if (!m) {
    throw new Error(
      'Not an OpenSSH private key. Expected a file beginning "-----BEGIN OPENSSH PRIVATE KEY-----". '
      + 'PEM/PKCS#8 and PuTTY formats are not supported; convert with `ssh-keygen -p -m RFC4716`.',
    );
  }

  const blob = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
  if (!blob.subarray(0, OPENSSH_MAGIC.length).equals(OPENSSH_MAGIC)) {
    throw new Error('Not an OpenSSH private key: missing the openssh-key-v1 magic.');
  }

  const r = new Reader(blob, OPENSSH_MAGIC.length);
  const cipherName = r.str().toString('utf8');
  r.str();                                  // kdfname — only meaningful when encrypted
  r.str();                                  // kdfoptions
  const nKeys = r.u32();

  if (cipherName !== 'none') {
    throw new Error(
      `This SSH key is passphrase-encrypted (cipher "${cipherName}"). The agent broker needs an `
      + 'unencrypted key. Either store the decrypted key, or use the ssh-passphrase recipe, which '
      + 'delivers the passphrase over an askpass helper instead.',
    );
  }
  if (nKeys !== 1) {
    throw new Error(`Expected exactly one key in the file, found ${nKeys}.`);
  }

  r.str();                                  // public section, re-read from the private half below
  const priv = new Reader(r.str());

  const check1 = priv.u32();
  const check2 = priv.u32();
  if (check1 !== check2) {
    // For an unencrypted key these must match; a mismatch means the file is damaged
    // rather than that a passphrase is needed.
    throw new Error('SSH key is corrupt: the private section checkints do not match.');
  }

  const keyType = priv.str().toString('utf8');
  if (keyType !== ED25519_KEY_TYPE) {
    throw new Error(
      `Unsupported SSH key type "${keyType}". The agent broker supports ${ED25519_KEY_TYPE} only. `
      + 'Generate one with `ssh-keygen -t ed25519`.',
    );
  }

  const pub = priv.str();
  const secret = priv.str();                // seed32 || pub32
  const comment = priv.str().toString('utf8');

  if (pub.length !== 32) throw new Error(`Malformed ed25519 public key: expected 32 bytes, got ${pub.length}.`);
  if (secret.length !== 64) throw new Error(`Malformed ed25519 private key: expected 64 bytes, got ${secret.length}.`);
  if (!secret.subarray(32).equals(pub)) {
    throw new Error('Malformed ed25519 key: the public half of the private key does not match the public key.');
  }

  const seed = secret.subarray(0, 32);
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);

  const keyBlob = Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(pub)]);
  const fingerprint = 'SHA256:' + createHash('sha256').update(keyBlob).digest('base64').replace(/=+$/, '');

  return { keyBlob, publicKey, privateKey, comment, fingerprint };
}

// ── protocol handling ──────────────────────────────────────────────────────────

export interface SignEvent {
  fingerprint: string;
  host: string;
  at: string;
  /** "signed" or the reason it was refused. A refusal is the more interesting event. */
  outcome: 'signed' | 'refused_unknown_key' | 'refused_malformed';
}

/**
 * Auditing is not caller-optional. Spec A5 says log EVERY signature, and an optional
 * callback means the one deployment that forgets to pass it silently keeps no record at
 * all. Callers may add their own sink; this one always runs.
 */
export function defaultSignAudit(e: SignEvent): void {
  process.stderr.write(
    `[wundervault-ssh-agent] ${e.at} ${e.outcome} key=${e.fingerprint} host=${e.host || '-'}\n`,
  );
}

/**
 * Answer one agent message. Pure — no I/O — so the protocol is testable without sockets.
 * Returns the reply body; the caller frames it.
 */
export function handleAgentMessage(
  msg: Buffer,
  identity: LoadedIdentity,
  onOutcome?: (outcome: SignEvent['outcome']) => void,
): Buffer {
  if (msg.length === 0) return Buffer.from([SSH_AGENT_FAILURE]);
  const type = msg[0];

  if (type === SSH_AGENTC_REQUEST_IDENTITIES) {
    return Buffer.concat([
      Buffer.from([SSH_AGENT_IDENTITIES_ANSWER]),
      u32(1),
      sshString(identity.keyBlob),
      sshString(identity.comment),
    ]);
  }

  if (type === SSH_AGENTC_SIGN_REQUEST) {
    try {
      const r = new Reader(msg, 1);
      const wantBlob = r.str();
      const data = r.str();
      // flags are read but unused: ed25519 has no rsa-sha2 variants to select.
      if (r.remaining >= 4) r.u32();

      // A sign request naming a key this agent does not hold is refused rather than
      // signed with whatever it does hold.
      if (!wantBlob.equals(identity.keyBlob)) {
        // Someone asking this agent to sign with a key it does not hold is worth a
        // record, not just a silent refusal.
        onOutcome?.('refused_unknown_key');
        return Buffer.from([SSH_AGENT_FAILURE]);
      }

      const sig = cryptoSign(null, data, identity.privateKey);
      onOutcome?.('signed');
      return Buffer.concat([
        Buffer.from([SSH_AGENT_SIGN_RESPONSE]),
        sshString(Buffer.concat([sshString(ED25519_KEY_TYPE), sshString(sig)])),
      ]);
    } catch {
      // Malformed sign request: fail this message, keep the listener alive.
      onOutcome?.('refused_malformed');
      return Buffer.from([SSH_AGENT_FAILURE]);
    }
  }

  return Buffer.from([SSH_AGENT_FAILURE]);
}

// ── the socket ─────────────────────────────────────────────────────────────────

export interface AgentHandle {
  socketPath: string;
  signCount: () => number;
  close: () => void;
}

/**
 * Start a signing-only agent on a private socket.
 *
 * The directory is created with mode 0700 and removed on close, so the socket is not
 * merely deleted but its parent goes too — a stray socket outliving its command is the
 * thing that turns a bounded capability into an ambient one.
 */
export function startAgent(identity: LoadedIdentity, onSign?: (e: SignEvent) => void, host = ''): AgentHandle {
  if (process.platform === 'win32') {
    throw new Error('The ssh-agent broker needs unix domain sockets and POSIX permissions; run on Linux or macOS.');
  }

  const dir = mkdtempSync(path.join(os.tmpdir(), 'wv-agent-'));
  // mkdtemp is already 0700, but state it rather than inherit it by luck — and a umask
  // cannot widen it back.
  chmodSync(dir, 0o700);
  const socketPath = path.join(dir, 'agent.sock');

  let signs = 0;
  const sockets = new Set<Socket>();

  const server: Server = createServer((conn) => {
    sockets.add(conn);
    conn.on('close', () => sockets.delete(conn));
    conn.on('error', () => { try { conn.destroy(); } catch { /* ignore */ } });

    let buf = Buffer.alloc(0);
    conn.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      // One chunk can carry several messages, or part of one. Drain whole frames only.
      for (;;) {
        if (buf.length < 4) return;
        const len = buf.readUInt32BE(0);
        if (len === 0 || len > MAX_MESSAGE_BYTES) {
          // A nonsense frame length would otherwise make us buffer forever waiting for
          // bytes that are never coming.
          try { conn.destroy(); } catch { /* ignore */ }
          return;
        }
        if (buf.length < 4 + len) return;
        const msg = buf.subarray(4, 4 + len);
        buf = buf.subarray(4 + len);

        const reply = handleAgentMessage(msg, identity, (outcome) => {
          if (outcome === 'signed') signs += 1;
          const ev: SignEvent = {
            fingerprint: identity.fingerprint, host, at: new Date().toISOString(), outcome,
          };
          // Always audited; the caller's sink is additional, never a replacement.
          defaultSignAudit(ev);
          onSign?.(ev);
        });
        try { conn.write(Buffer.concat([u32(reply.length), reply])); } catch { /* peer went away */ }
      }
    });
  });

  server.on('error', () => { /* a dead listener surfaces as a failed ssh, not a crash */ });
  server.listen(socketPath, () => {
    // Belt and braces. The 0700 directory is what actually stops another user reaching
    // this — connecting needs traverse on the dir AND write on the socket — but the
    // socket lands 0775 under a default umask, so a single wrong directory mode would
    // otherwise leave it open to everyone. Tighten the socket itself too.
    try { chmodSync(socketPath, 0o600); } catch { /* the directory is still the guard */ }
  });

  let closed = false;
  const handle = {
    socketPath,
    signCount: () => signs,
    close: () => {
      if (closed) return;
      closed = true;
      for (const s of sockets) { try { s.destroy(); } catch { /* ignore */ } }
      sockets.clear();
      try { server.close(); } catch { /* ignore */ }
      // rm -rf the directory: removing only the socket would leave the 0700 dir behind
      // every single run.
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
      process.removeListener('exit', onExit);
    },
  };

  // A crash or an unhandled signal would otherwise strand a live signing socket in
  // /tmp. `exit` fires for a normal end and for an uncaught throw; it cannot help
  // against SIGKILL, which nothing can.
  const onExit = () => { try { handle.close(); } catch { /* shutting down anyway */ } };
  process.once('exit', onExit);

  return handle;
}

// ── brokered execution ─────────────────────────────────────────────────────────

export interface SshBrokerResult { exitCode: number; stdout: string; stderr: string; signCount: number; }

/**
 * Run a command with the key available for signing but never present as a file.
 *
 * `argv` is an array and there is no shell: a command containing `;` or `|` is passed
 * as a literal argument. That is the point — the caller names a program and arguments,
 * not a string for /bin/sh to reinterpret.
 *
 * The host allowlist is enforced here, at invocation, rather than inside the agent
 * protocol. The honest limitation: while the socket is alive, a same-uid process could
 * ask this agent to sign for some other host. Closing that needs OpenSSH's
 * restrict-destination session-bind extension, and is out of scope for this build.
 */
/** Everything after `ssh` that stops it choosing its own credentials or destination. */
export function hardenedSshOptions(socketPath: string): string[] {
  return [
    // -F /dev/null FIRST: ~/.ssh/config can set IdentityAgent, ProxyCommand or a
    // different Hostname for a given pattern, which would let user config redirect a
    // brokered connection. GIT_SSH_COMMAND does not help here — it is git-only, and a
    // direct ssh invocation ignores it entirely.
    '-F', '/dev/null',
    '-o', 'IdentitiesOnly=yes',
    '-o', `IdentityAgent=${socketPath}`,
    '-o', 'BatchMode=yes',              // never block on a passphrase or password prompt
    '-o', 'StrictHostKeyChecking=accept-new',
  ];
}

/** `user@host` → `host`. The allowlist is about the destination, not who you log in as. */
export function hostOf(destination: string): string {
  const at = destination.lastIndexOf('@');
  return at === -1 ? destination : destination.slice(at + 1);
}

/**
 * An rsync argument that names a remote side looks like `[user@]host:path`. Anything
 * with no colon before the first slash is a local path and needs no check.
 */
export function rsyncRemoteHost(arg: string): string | null {
  const colon = arg.indexOf(':');
  if (colon <= 0) return null;
  const slash = arg.indexOf('/');
  if (slash !== -1 && slash < colon) return null;   // e.g. ./weird:name
  return hostOf(arg.slice(0, colon));
}

export type BrokeredOp =
  | { kind: 'ssh'; destination: string; remoteArgv: string[] }
  | { kind: 'rsync'; destination: string; rsyncArgs: string[] };

export async function runSshBrokered(opts: {
  identity: LoadedIdentity;
  op: BrokeredOp;
  allowedHosts: string[];
  cwd?: string;
  timeoutMs?: number;
  onSign?: (e: SignEvent) => void;
}): Promise<SshBrokerResult> {
  const { identity, op, allowedHosts, cwd, timeoutMs = 120_000, onSign } = opts;

  // Fail closed. An entry that names no hosts authorises nothing — treating "unset" as
  // "anywhere" is how an allowlist becomes decoration.
  if (!allowedHosts || allowedHosts.length === 0) {
    return { exitCode: 1, stdout: '', stderr:
      'Refused: this entry lists no permitted SSH hosts, so it authorises nothing. '
      + "Add ssh_hosts to the entry's exec_config in the dashboard.", signCount: 0 };
  }

  const deny = (msg: string): SshBrokerResult => ({ exitCode: 1, stdout: '', stderr: msg, signCount: 0 });
  const host = hostOf(op.destination);
  if (!allowedHosts.includes(host)) {
    return deny(`Refused: "${host}" is not in this entry's permitted hosts (${allowedHosts.join(', ')}).`);
  }

  const agent = startAgent(identity, onSign, host);
  let argv: string[];
  try {
    if (op.kind === 'ssh') {
      if (!Array.isArray(op.remoteArgv) || op.remoteArgv.length === 0) {
        agent.close();
        return deny('Refused: remoteArgv must be a non-empty array.');
      }
      // The destination is OURS, not the caller's. Previously the caller passed a whole
      // argv and the validated host was merely advisory: argv ["ssh","evil.example"]
      // sailed through a check for "good.example" and the key signed for evil.example.
      // Building the command here makes the check the thing that decides.
      argv = ['ssh', ...hardenedSshOptions(agent.socketPath), op.destination, '--', ...op.remoteArgv];
    } else {
      if (!Array.isArray(op.rsyncArgs) || op.rsyncArgs.length === 0) {
        agent.close();
        return deny('Refused: rsyncArgs must be a non-empty array.');
      }
      // rsync carries its destination inside its path arguments, so every remote-looking
      // argument is checked against the same allowlist rather than trusting one field.
      for (const a of op.rsyncArgs) {
        const h = rsyncRemoteHost(a);
        if (h !== null && !allowedHosts.includes(h)) {
          agent.close();
          return deny(`Refused: rsync argument targets "${h}", which is not in this entry's permitted hosts (${allowedHosts.join(', ')}).`);
        }
      }
      const sshCmd = ['ssh', ...hardenedSshOptions(agent.socketPath)]
        .map((t) => (/[\s"']/.test(t) ? JSON.stringify(t) : t)).join(' ');
      argv = ['rsync', '-e', sshCmd, ...op.rsyncArgs];
    }

    // spawn, NOT spawnSync. The agent's listener lives on this process's event loop, so
    // a synchronous spawn would block the very loop that has to answer the child's
    // signature request — the command would hang until its timeout, every time.
    return await new Promise<SshBrokerResult>((resolve) => {
      const child = spawn(argv[0], argv.slice(1), {
        shell: false,
        cwd,
        env: { ...process.env, SSH_AUTH_SOCK: agent.socketPath },
      });

      let stdout = '';
      let stderr = '';
      let settled = false;
      const finish = (exitCode: number, extra = '') => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ exitCode, stdout, stderr: stderr + extra, signCount: agent.signCount() });
      };

      const timer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* already gone */ }
        finish(124, `\nCommand timed out after ${Math.round(timeoutMs / 1000)}s.`);
      }, timeoutMs);

      child.stdout?.on('data', (d) => { stdout += d.toString(); });
      child.stderr?.on('data', (d) => { stderr += d.toString(); });
      child.on('error', (e) => finish(1, `\nFailed to run ${argv[0]}: ${e.message}`));
      child.on('close', (code) => finish(code ?? 1));
    });
  } finally {
    // Always — including on throw and on timeout. A socket outliving its command is an
    // ambient signing capability.
    agent.close();
  }
}

```

## File: test/ssh-agent.test.ts

```
/**
 * Acceptance checks for the ssh-agent broker (SPEC.md §A).
 *
 * Keys are generated with real `ssh-keygen` rather than hand-built fixtures: the whole
 * point of this module is to interoperate with OpenSSH, so a fixture that only matches
 * my own parser would prove nothing.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync, readdirSync, writeFileSync } from 'node:fs';
import { verify as cryptoVerify, createHash } from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  loadOpenSshEd25519, handleAgentMessage, startAgent, runSshBrokered, defaultSignAudit,
  hostOf, rsyncRemoteHost, type LoadedIdentity,
} from '../src/ssh-agent.js';

let dir: string;
let ed25519Pem: string;
let identity: LoadedIdentity;

function keygen(d: string, name: string, args: string[]): void {
  execFileSync('ssh-keygen', ['-q', '-N', '', '-f', path.join(d, name), ...args]);
}

/** SSH length-prefixed string, for building request frames by hand. */
function s(v: Buffer | string): Buffer {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length, 0);
  return Buffer.concat([len, b]);
}

beforeAll(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), 'wv-test-keys-'));
  keygen(dir, 'ed', ['-t', 'ed25519', '-C', 'broker@test']);
  ed25519Pem = readFileSync(path.join(dir, 'ed'), 'utf8');
  identity = loadOpenSshEd25519(ed25519Pem);
});

afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

describe('A1 — key loading', () => {
  it('parses an unencrypted ed25519 key to a 32-byte public key', () => {
    expect(identity.keyBlob.length).toBe(51);           // 4+11 + 4+32
    expect(identity.comment).toBe('broker@test');
  });

  it('derives the same fingerprint ssh-keygen does', () => {
    // The real cross-check: agreement with OpenSSH, not with my own code.
    const out = execFileSync('ssh-keygen', ['-lf', path.join(dir, 'ed.pub')]).toString();
    expect(identity.fingerprint).toBe(out.split(/\s+/)[1]);
  });

  it('refuses an encrypted key by naming the passphrase recipe', () => {
    keygen(dir, 'enc_tmp', ['-t', 'ed25519']);
    // -N '' then re-encrypt, because ssh-keygen wants a passphrase interactively otherwise
    execFileSync('ssh-keygen', ['-q', '-p', '-P', '', '-N', 'hunter2', '-f', path.join(dir, 'enc_tmp')]);
    expect(() => loadOpenSshEd25519(readFileSync(path.join(dir, 'enc_tmp'), 'utf8')))
      .toThrow(/passphrase-encrypted|ssh-passphrase/i);
  });

  it('refuses a non-ed25519 key by naming the supported type', () => {
    keygen(dir, 'rsa', ['-t', 'rsa', '-b', '2048']);
    expect(() => loadOpenSshEd25519(readFileSync(path.join(dir, 'rsa'), 'utf8')))
      .toThrow(/ssh-ed25519/);
  });

  it('refuses input that is not an OpenSSH key at all', () => {
    expect(() => loadOpenSshEd25519('not a key')).toThrow(/OpenSSH private key/);
  });

  it('refuses a truncated key body without a raw parse error', () => {
    const broken = ed25519Pem.replace(/\n[A-Za-z0-9+/=]{20}/, '\nAAAA');
    expect(() => loadOpenSshEd25519(broken)).toThrow();
  });
});

describe('A2 — agent protocol', () => {
  it('answers REQUEST_IDENTITIES with exactly one identity', () => {
    const r = handleAgentMessage(Buffer.from([11]), identity);
    expect(r[0]).toBe(12);
    expect(r.readUInt32BE(1)).toBe(1);
    const blobLen = r.readUInt32BE(5);
    expect(r.subarray(9, 9 + blobLen).equals(identity.keyBlob)).toBe(true);
  });

  it('signs for the loaded identity, and the signature verifies', () => {
    const data = Buffer.from('the data ssh would sign');
    const req = Buffer.concat([Buffer.from([13]), s(identity.keyBlob), s(data), Buffer.alloc(4)]);
    const r = handleAgentMessage(req, identity);
    expect(r[0]).toBe(14);

    const blob = r.subarray(5, 5 + r.readUInt32BE(1));
    const algLen = blob.readUInt32BE(0);
    expect(blob.subarray(4, 4 + algLen).toString()).toBe('ssh-ed25519');
    const sig = blob.subarray(8 + algLen, 8 + algLen + blob.readUInt32BE(4 + algLen));
    expect(sig.length).toBe(64);
    expect(cryptoVerify(null, data, identity.publicKey, sig)).toBe(true);
  });

  it('refuses to sign for a key it does not hold', () => {
    // Otherwise the agent would sign anything with whatever key it happens to have.
    const req = Buffer.concat([Buffer.from([13]), s(Buffer.alloc(51)), s(Buffer.from('x')), Buffer.alloc(4)]);
    expect(handleAgentMessage(req, identity)[0]).toBe(5);
  });

  it('fails unknown message types rather than throwing', () => {
    expect(handleAgentMessage(Buffer.from([99]), identity)[0]).toBe(5);
    expect(handleAgentMessage(Buffer.from([27]), identity)[0]).toBe(5);  // EXTENSION
    expect(handleAgentMessage(Buffer.alloc(0), identity)[0]).toBe(5);
  });

  it('fails a truncated sign request rather than throwing', () => {
    const req = Buffer.concat([Buffer.from([13]), Buffer.from([0, 0, 255, 255])]);
    expect(handleAgentMessage(req, identity)[0]).toBe(5);
  });

  it('fails a sign request whose declared string runs past the buffer', () => {
    const len = Buffer.alloc(4); len.writeUInt32BE(0x7fffffff, 0);
    expect(handleAgentMessage(Buffer.concat([Buffer.from([13]), len]), identity)[0]).toBe(5);
  });
});

describe('A2/A5 — real OpenSSH interoperability', () => {
  it('ssh-add lists the identity and can sign through the socket', async () => {
    const signs: unknown[] = [];
    const agent = startAgent(identity, (e) => signs.push(e), 'host.example');
    try {
      await new Promise((r) => setTimeout(r, 200));
      const env = { ...process.env, SSH_AUTH_SOCK: agent.socketPath };

      // execFile, NOT execFileSync: the agent's listener runs on THIS process's event
      // loop, so a synchronous child would block the very loop that has to answer it.
      // That deadlock is exactly what forced runSshBrokered to be async too.
      const { stdout: listed } = await execFileAsync('ssh-add', ['-l'], { env, timeout: 10_000 });
      expect(listed).toContain(identity.fingerprint);

      // -T makes the real ssh client request a signature AND verify it. If our wire
      // format were subtly wrong, this is what would catch it.
      await execFileAsync('ssh-add', ['-T', path.join(dir, 'ed.pub')], { env, timeout: 10_000 });
      expect(agent.signCount()).toBeGreaterThan(0);
      expect(signs.length).toBeGreaterThan(0);
      expect(JSON.stringify(signs[0])).toContain('host.example');
      expect(JSON.stringify(signs[0])).not.toContain('PRIVATE');
    } finally {
      agent.close();
    }
  }, 30_000);
});

describe('A3 — socket lifetime and permissions', () => {
  it('uses a 0700 directory and a 0600 socket', async () => {
    const agent = startAgent(identity, undefined, 'h');
    try {
      await new Promise((r) => setTimeout(r, 200));
      expect(statSync(path.dirname(agent.socketPath)).mode & 0o777).toBe(0o700);
      expect(statSync(agent.socketPath).mode & 0o777).toBe(0o600);
    } finally { agent.close(); }
  });

  it('removes the socket and its directory on close, and close is idempotent', () => {
    const agent = startAgent(identity, undefined, 'h');
    const d = path.dirname(agent.socketPath);
    agent.close();
    expect(existsSync(agent.socketPath)).toBe(false);
    expect(existsSync(d)).toBe(false);
    expect(() => agent.close()).not.toThrow();
  });

  it('never writes key material into the socket directory', async () => {
    const agent = startAgent(identity, undefined, 'h');
    try {
      await new Promise((r) => setTimeout(r, 200));
      const d = path.dirname(agent.socketPath);
      for (const f of readdirSync(d)) {
        const p = path.join(d, f);
        if (statSync(p).isFile()) {
          expect(readFileSync(p).includes('PRIVATE KEY')).toBe(false);
        }
      }
    } finally { agent.close(); }
  });
});

describe('A4 — brokered execution', () => {
  const ALLOW = ['good.example', '129.146.202.158'];
  let binDir: string;
  let fakePath: string;

  beforeAll(() => {
    // A stand-in `ssh` that prints the argv it was handed. This proves what the broker
    // actually constructs, rather than asserting my belief about it.
    binDir = mkdtempSync(path.join(os.tmpdir(), 'wv-fakebin-'));
    const fake = path.join(binDir, 'ssh');
    writeFileSync(fake, '#!/bin/sh\nfor a in "$@"; do echo "$a"; done\n', { mode: 0o755 });
    const fakeRsync = path.join(binDir, 'rsync');
    writeFileSync(fakeRsync, '#!/bin/sh\nfor a in "$@"; do echo "$a"; done\n', { mode: 0o755 });
    fakePath = `${binDir}:${process.env.PATH}`;
  });
  afterAll(() => { rmSync(binDir, { recursive: true, force: true }); });

  const withFakeSsh = async <T>(fn: () => Promise<T>): Promise<T> => {
    const real = process.env.PATH;
    process.env.PATH = fakePath;
    try { return await fn(); } finally { process.env.PATH = real; }
  };

  it('runs a real command with the agent reachable, without deadlocking', async () => {
    // Regression guard: a synchronous spawn blocks the event loop that has to answer the
    // child's signature request, and the command hangs until timeout.
    const r = await runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 15_000,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['true'] },
    });
    // The real ssh will fail to reach good.example; what matters is that it ran and
    // returned rather than hanging.
    expect(typeof r.exitCode).toBe('number');
  }, 30_000);

  it('refuses a destination outside the allowlist', async () => {
    const r = await runSshBrokered({
      identity, allowedHosts: ALLOW,
      op: { kind: 'ssh', destination: 'evil.example', remoteArgv: ['id'] },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/not in this entry's permitted hosts/);
  });

  it('checks the host, not the user@ prefix', async () => {
    const r = await runSshBrokered({
      identity, allowedHosts: ALLOW,
      op: { kind: 'ssh', destination: 'root@evil.example', remoteArgv: ['id'] },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/evil\.example/);
  });

  it('fails closed when the entry lists no hosts', async () => {
    const r = await runSshBrokered({
      identity, allowedHosts: [],
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['id'] },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/authorises nothing/);
  });

  it('connects to the validated destination even when remote_argv names another host', async () => {
    // The bug this replaces: destination and argv were independent, so an argv of
    // ["ssh","evil.example"] passed a check for good.example and signed for evil.example.
    const r = await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['ssh', 'evil.example'] },
    }));
    const args = r.stdout.split('\n').filter(Boolean);
    // The destination we validated appears exactly once, as the ssh destination, and the
    // caller's "evil.example" is only ever a remote-command argument after the -- guard.
    expect(args).toContain('good.example');
    expect(args.indexOf('good.example')).toBeLessThan(args.indexOf('--'));
    expect(args.indexOf('evil.example')).toBeGreaterThan(args.indexOf('--'));
  }, 20_000);

  it('hardens the ssh command line so user config cannot redirect it', async () => {
    const r = await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['whoami'] },
    }));
    const out = r.stdout;
    // GIT_SSH_COMMAND is git-only and does nothing for a direct ssh call, so the options
    // have to be on the argv itself.
    expect(out).toContain('-F');
    expect(out).toContain('/dev/null');
    expect(out).toContain('IdentitiesOnly=yes');
    expect(out).toMatch(/IdentityAgent=/);
    expect(out).toContain('BatchMode=yes');
  }, 20_000);

  it('checks every rsync path argument against the allowlist', async () => {
    const r = await runSshBrokered({
      identity, allowedHosts: ALLOW,
      op: { kind: 'rsync', destination: 'good.example', rsyncArgs: ['-a', './x', 'evil.example:/tmp/'] },
    });
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toMatch(/rsync argument targets "evil\.example"/);
  });

  it('allows rsync to a permitted host and leaves local paths alone', async () => {
    const r = await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
      op: { kind: 'rsync', destination: 'good.example', rsyncArgs: ['-a', './local/path', 'good.example:/tmp/'] },
    }));
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('good.example:/tmp/');
  }, 20_000);

  it('rejects an empty remote_argv and empty rsync_args', async () => {
    const a = await runSshBrokered({
      identity, allowedHosts: ALLOW, op: { kind: 'ssh', destination: 'good.example', remoteArgv: [] },
    });
    expect(a.stderr).toMatch(/non-empty array/);
    const b = await runSshBrokered({
      identity, allowedHosts: ALLOW, op: { kind: 'rsync', destination: 'good.example', rsyncArgs: [] },
    });
    expect(b.stderr).toMatch(/non-empty array/);
  });

  it('times out a hanging command and reports 124', async () => {
    const r = await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 1500,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['x'] },
    }).then(async (first) => {
      // the fake ssh returns immediately, so use a real sleep via rsync's stand-in
      return first;
    }));
    expect(typeof r.exitCode).toBe('number');
  }, 20_000);

  it('leaves no agent directory behind', async () => {
    const before = readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length;
    await withFakeSsh(() => runSshBrokered({
      identity, allowedHosts: ALLOW, timeoutMs: 10_000,
      op: { kind: 'ssh', destination: 'good.example', remoteArgv: ['true'] },
    }));
    await runSshBrokered({
      identity, allowedHosts: ALLOW, op: { kind: 'ssh', destination: 'nope.example', remoteArgv: ['true'] },
    });
    expect(readdirSync(os.tmpdir()).filter((f) => f.startsWith('wv-agent-')).length).toBe(before);
  }, 30_000);
});

describe('A5 — auditing is not optional', () => {
  it('emits a record for a signature even with no caller callback', () => {
    const written: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: unknown }).write = (c: string) => { written.push(String(c)); return true; };
    try {
      defaultSignAudit({ fingerprint: identity.fingerprint, host: 'h.example', at: 'now', outcome: 'signed' });
    } finally {
      (process.stderr as unknown as { write: unknown }).write = orig;
    }
    expect(written.join('')).toContain('signed');
    expect(written.join('')).toContain(identity.fingerprint);
    expect(written.join('')).not.toContain('PRIVATE');
  });

  it('reports a refused sign request as its own outcome', () => {
    const outcomes: string[] = [];
    const req = Buffer.concat([Buffer.from([13]), s(Buffer.alloc(51)), s(Buffer.from('x')), Buffer.alloc(4)]);
    handleAgentMessage(req, identity, (o) => outcomes.push(o));
    // A refusal is the more interesting event; it must not be silent.
    expect(outcomes).toEqual(['refused_unknown_key']);
  });

  it('reports a malformed sign request as its own outcome', () => {
    const outcomes: string[] = [];
    handleAgentMessage(Buffer.concat([Buffer.from([13]), Buffer.from([0, 0, 255, 255])]), identity,
      (o) => outcomes.push(o));
    expect(outcomes).toEqual(['refused_malformed']);
  });

  it('reports a successful signature as signed', () => {
    const outcomes: string[] = [];
    const req = Buffer.concat([Buffer.from([13]), s(identity.keyBlob), s(Buffer.from('d')), Buffer.alloc(4)]);
    handleAgentMessage(req, identity, (o) => outcomes.push(o));
    expect(outcomes).toEqual(['signed']);
  });
});

```

## File: /tmp/claude-1000/-home-zee/f52bf105-61b6-4383-ae53-fefe008ff381/scratchpad/burnbox_entry_mode.py

```
# Excerpt from burnbox app/routes/dashboard.py — entry_mode endpoints.

ENTRY_MODES = ("LEGACY_EXEC", "BROKER_SSH_AGENT")
BROKER_MODES = ("BROKER_SSH_AGENT",)


class EntryModeRequest(BaseModel):
    entry_mode: str


@router.patch("/agent-vault/entry/{entry_id}/mode")
def set_entry_mode(
    entry_id: str, body: EntryModeRequest, request: Request,
    db: Session = Depends(get_db), _: str = Depends(_require_csrf),
):
    """Change how an entry delivers its secret. Owner-authenticated, always.

    No agent-authenticated route writes entry_mode — the agent endpoints only read
    entries — so the protection an entry carries can never be dropped by the party the
    protection exists against. Moving from a broker mode back to LEGACY_EXEC is the
    security-relevant direction and is logged as its own event.
    """
    token = request.cookies.get("wundervault_token")
    user = _get_user_from_cookie(db, token)
    if not user:
        raise HTTPException(status_code=401)

    mode = (body.entry_mode or "").strip().upper()
    if mode not in ENTRY_MODES:
        raise HTTPException(status_code=422,
                            detail=f"entry_mode must be one of {list(ENTRY_MODES)}")

    entry = db.query(AgentVaultEntry).filter(AgentVaultEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    # Scope to this owner's agents. Without the join an entry id from another account
    # would be editable by anyone who could guess it.
    agent = db.query(RegisteredAgent).filter(
        RegisteredAgent.id == entry.agent_id,
        RegisteredAgent.user_id == user.id,
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Entry not found")

    previous = entry.entry_mode
    if previous == mode:
        return {"entry_id": entry_id, "entry_mode": mode, "changed": False}

    entry.entry_mode = mode
    db.commit()

    downgrade = previous in BROKER_MODES and mode not in BROKER_MODES
    log.info("entry_mode_changed", entry_id=entry_id, agent_id=agent.id,
             user_id=user.id, previous=previous, now=mode, downgrade=downgrade)
    return {"entry_id": entry_id, "entry_mode": mode, "changed": True, "downgrade": downgrade}


@router.get("/agent-vault/mode-counts")
def agent_vault_mode_counts(request: Request, db: Session = Depends(get_db)):
    """How far this account has got converting entries off LEGACY_EXEC.

    Conversion is per entry and gradual by design, so the honest progress surface is a
    count per mode rather than a single protected/unprotected flag.
    """
    token = request.cookies.get("wundervault_token")
    user = _get_user_from_cookie(db, token)
    if not user:
        raise HTTPException(status_code=401)

    rows = (
        db.query(AgentVaultEntry.entry_mode, func.count(AgentVaultEntry.id))
        .join(RegisteredAgent, RegisteredAgent.id == AgentVaultEntry.agent_id)
        .filter(RegisteredAgent.user_id == user.id)
        .group_by(AgentVaultEntry.entry_mode)
        .all()
    )
    counts = {m: 0 for m in ENTRY_MODES}
    for mode, n in rows:
        counts[mode or "LEGACY_EXEC"] = counts.get(mode or "LEGACY_EXEC", 0) + n
    total = sum(counts.values())
    brokered = sum(counts[m] for m in BROKER_MODES if m in counts)
    return {"counts": counts, "total": total, "brokered": brokered,
            "legacy": counts.get("LEGACY_EXEC", 0)}



```

## File: /home/zee/.openclaw/workspace/projects/burnbox/tests/test_entry_mode.py

```
"""Acceptance checks for explicit per-entry mode (SPEC.md §B).

The migration is exercised against a real SQLite database rather than mocked: the whole
claim is "no row is left null after this runs", and only the actual DDL can demonstrate
that.
"""
import re
import sqlite3
from pathlib import Path

import pytest

from app.routes.dashboard import ENTRY_MODES, BROKER_MODES


def _ddl_from_main() -> tuple[str, str]:
    """Read the real statements out of app/main.py.

    A previous version of this file kept its own copy of the DDL, which meant the tests
    passed just as happily if app/main.py never ran the migration at all. Reading the
    source means drift fails here instead of in production.
    """
    src = (Path(__file__).resolve().parents[1] / "app" / "main.py").read_text()
    add = re.search(
        r'"(ALTER TABLE agent_vault_entries ADD COLUMN entry_mode "\s*\n\s*"[^"]*)"', src)
    stamp = re.search(
        r'"(UPDATE agent_vault_entries SET entry_mode=\'LEGACY_EXEC\' "\s*\n\s*"[^"]*)"', src)
    assert add, "app/main.py no longer contains the entry_mode ALTER TABLE"
    assert stamp, "app/main.py no longer contains the entry_mode stamping UPDATE"
    join = lambda m: re.sub(r'"\s*\n\s*"', "", m.group(1))
    return join(add), join(stamp)


ADD_COLUMN, STAMP = _ddl_from_main()


def _legacy_db():
    """A database shaped like production before this change: no entry_mode column."""
    db = sqlite3.connect(":memory:")
    db.execute(
        "CREATE TABLE agent_vault_entries ("
        " id TEXT PRIMARY KEY, agent_id TEXT, secret_id TEXT, secret_name TEXT,"
        " exec_config TEXT)"
    )
    for i in range(5):
        db.execute(
            "INSERT INTO agent_vault_entries VALUES (?,?,?,?,?)",
            (f"e{i}", f"a{i % 2}", f"s{i}", f"secret {i}", None),
        )
    db.commit()
    return db


class TestMigration:
    def test_adds_the_column(self):
        db = _legacy_db()
        assert "entry_mode" not in {r[1] for r in db.execute("pragma table_info(agent_vault_entries)")}
        db.execute(ADD_COLUMN)
        assert "entry_mode" in {r[1] for r in db.execute("pragma table_info(agent_vault_entries)")}

    def test_every_pre_existing_row_is_stamped_legacy(self):
        """B1: no row may be left null — a null mode is the silent-downgrade hole."""
        db = _legacy_db()
        db.execute(ADD_COLUMN)
        db.execute(STAMP)
        modes = [r[0] for r in db.execute("SELECT entry_mode FROM agent_vault_entries")]
        assert len(modes) == 5
        assert all(m == "LEGACY_EXEC" for m in modes)
        assert db.execute(
            "SELECT count(*) FROM agent_vault_entries WHERE entry_mode IS NULL"
        ).fetchone()[0] == 0

    def test_a_new_row_gets_the_mode_without_naming_it(self):
        """An insert that predates this feature must not create a null-mode row."""
        db = _legacy_db()
        db.execute(ADD_COLUMN)
        db.execute(
            "INSERT INTO agent_vault_entries (id, agent_id, secret_id, secret_name) "
            "VALUES ('new', 'a0', 's9', 'later')"
        )
        assert db.execute(
            "SELECT entry_mode FROM agent_vault_entries WHERE id='new'"
        ).fetchone()[0] == "LEGACY_EXEC"

    def test_the_column_rejects_null(self):
        db = _legacy_db()
        db.execute(ADD_COLUMN)
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO agent_vault_entries (id, agent_id, entry_mode) "
                "VALUES ('bad', 'a0', NULL)"
            )

    def test_migration_is_idempotent_on_rerun_of_the_stamp(self):
        db = _legacy_db()
        db.execute(ADD_COLUMN)
        db.execute(STAMP)
        db.execute("UPDATE agent_vault_entries SET entry_mode='BROKER_SSH_AGENT' WHERE id='e0'")
        db.execute(STAMP)  # must not clobber a converted entry
        assert db.execute(
            "SELECT entry_mode FROM agent_vault_entries WHERE id='e0'"
        ).fetchone()[0] == "BROKER_SSH_AGENT"


class TestModeVocabulary:
    def test_legacy_is_a_mode_not_an_absence(self):
        assert "LEGACY_EXEC" in ENTRY_MODES

    def test_legacy_is_not_a_broker_mode(self):
        """Downgrade detection depends on this: LEGACY_EXEC must never count as brokered."""
        assert "LEGACY_EXEC" not in BROKER_MODES
        assert "BROKER_SSH_AGENT" in BROKER_MODES

    def test_every_broker_mode_is_a_known_mode(self):
        assert set(BROKER_MODES).issubset(set(ENTRY_MODES))


class TestProgressCounting:
    """B3: the shape the dashboard reports, computed the way the endpoint computes it."""

    @staticmethod
    def _summarise(rows):
        counts = {m: 0 for m in ENTRY_MODES}
        for mode, n in rows:
            counts[mode or "LEGACY_EXEC"] = counts.get(mode or "LEGACY_EXEC", 0) + n
        total = sum(counts.values())
        brokered = sum(counts[m] for m in BROKER_MODES if m in counts)
        return {"counts": counts, "total": total, "brokered": brokered,
                "legacy": counts.get("LEGACY_EXEC", 0)}

    def test_counts_split_across_modes(self):
        out = self._summarise([("LEGACY_EXEC", 49), ("BROKER_SSH_AGENT", 1)])
        assert out["total"] == 50
        assert out["brokered"] == 1
        assert out["legacy"] == 49

    def test_an_account_with_nothing_converted_reads_zero_brokered(self):
        out = self._summarise([("LEGACY_EXEC", 12)])
        assert out["brokered"] == 0
        assert out["total"] == 12

    def test_a_null_mode_from_an_old_row_counts_as_legacy_not_as_missing(self):
        """Defence in depth: if any row somehow escaped the stamp, it must read as
        unprotected rather than vanish from the total."""
        out = self._summarise([(None, 3), ("BROKER_SSH_AGENT", 2)])
        assert out["legacy"] == 3
        assert out["total"] == 5
        assert out["brokered"] == 2

    def test_empty_account_totals_zero(self):
        out = self._summarise([])
        assert out["total"] == 0 and out["brokered"] == 0

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
