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
