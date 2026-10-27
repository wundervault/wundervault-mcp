# Wundervault 1.0 / 2.0 — standout features

Running list for marketing materials. **Only things that are BUILT go above the line.**
Anything unbuilt or unverified is in "Not yet true" at the bottom — the fastest way to lose
a security audience is one claim they can disprove.

Each entry: what it is, why it is unusual, and the one-line version for a page.

---

## Shipped and verified

### 1. The secret broker
The credentials your agents use are held by a separate process running under its own system
account. An agent asks the broker for a credential over a socket and proves who it is with a
token; it cannot read the credential store on disk, and cannot read the broker's memory
through `/proc`, because it is a different user.

**Why it is unusual:** most agent tooling puts credentials in an env var or a dotfile owned
by the same user the agent runs as — which means "the agent has the secret" is literally true.
Here it never does.

**Verified:** on a two-uid install the agent's account gets `Permission denied` on the store
directory, on writing it, and on `/proc/<pid>/mem`.

> *Your agents can use your credentials without ever holding them.*

### 2. A local access log you own
Every destination an agent sends a secret to is recorded, and the record is held by the
broker — not by us. You read it with `sudo wundervault-agent --destinations`, which opens a
self-contained page and then deletes it, because the page is a copy your agents could
otherwise read. Nothing is uploaded; the page has a `default-src 'none'` policy and makes no
network request.

**Why it is unusual:** the party being audited does not own the evidence, and the vendor
never sees it.

> *The record of where your secrets went stays on your machine — and we cannot read it.*

<a id="3-two-secret-key-derivation-the-1password-property"></a>

### 3. Two-Part Key Derivation (the 1Password property)
A 16-byte Account Key is generated on your device and never sent to the server. It is
mixed with your passphrase through PBKDF2 (600,000 iterations) and HKDF to produce the auth
and vault keys.

**Why it matters:** if our server is breached AND your passphrase is guessed, an attacker
still has nothing, because a factor that never left your device is missing.

> *Breaching our server is not enough. Guessing your passphrase is not enough. They need both,
> plus something that never left your laptop.*

### 4. The server cannot decrypt your vault
The vault key is generated in your browser and stored only wrapped — once for you, once for
each agent. We hold two opaque blobs and can open neither. Revoking an agent means discarding
its wrapping rather than re-encrypting anything.

> *We store your secrets. We cannot read them.*

### 5. Enrolment the agent cannot forge
Adding an agent to the broker requires a single-use, 15-minute setup link issued by the
website to someone logged in. The broker redeems it itself, so credentials never pass through
the process that asked. An agent cannot obtain such a link — and cannot mint one, because the
broker only accepts links from a configured origin.

**Why it is unusual:** it closes the case where the machine's owner and its agents are the
same user account, which no file permission can separate.

> *Only you can add an agent, even though your agents run as you.*

### 6. A verifiable installer
The onboarding script checks its own signature before it installs anything, and the same file
is published on GitHub so an agent can diff what we served against what is public. The script
is written to be read by the agent being asked to run it.

> *We wrote the installer for the sceptic who has to run it.*

### 7. Tiered access with real approvals
Tier 1 secrets are available once your vault is unlocked. Tier 2 requires your explicit
approval per use, with biometric unlock, and the agent is blocked until you answer.

> *Some secrets should need a human. Those ones do.*

### 8. Repairing an agent replaces the lock, not just the key
Repairing an agent gives it a brand-new vault key and re-encrypts everything it holds under
that key, in one step that either completes or changes nothing. A credential that was ever
exposed stops being able to open what you send next.

And we tell you what that does **not** fix. A secret an agent has already read is out — no
amount of re-encryption calls it back — so the dashboard lists exactly which credentials to
replace at their providers, and which ones are handed over in full every time they are used.

> *A new key is only half the job. We show you the other half rather than letting it read
> as done.*

---

## Not yet true — do NOT put these on a page

- **Argon2id for every vault.** Switched ON in the 1.0 build (2026-10-02) for new vaults, and
  existing vaults move to it on their next unlock. A vault created where WebAssembly is off
  (iPhone Lockdown Mode) falls back to PBKDF2, so "every vault" is not true; "new vaults use
  Argon2id" is. (This line used to say it was off.)
- **"We rotated your exposed credentials."** We cannot. We can only name them; replacing them
  at the provider is the owner's action and we have no way to verify it happened.
- **"Sealed" on a machine with no TPM.** Where there is no TPM the key is sealed to systemd's
  host key, which lives on the same disk — an offline copy plus root DOES open it. Say which
  kind of sealing the machine actually got.
- **Post-quantum signatures.** The TRANSPORT is already hybrid post-quantum
  (X25519MLKEM768, verified) and the vault is symmetric end to end, so both of those are
  claimable. PQ *signatures* are not — we do not have them.
- **Windows brokers.** All three now have one, as of phase 8 — but it has run on exactly
  one Windows machine, and until `packaging\verify-windows.ps1` exits 0 on a customer's
  own box, do not describe Windows as supported for them.
- **Windows parity with the Linux hardening.** Same as macOS below: the account split is
  the same, the sandboxing around it is not there. Task Scheduler has no equivalent of
  ProtectSystem, ProtectProc or a syscall filter.
- **A sealed store key on Windows.** There isn't one. It is a random key in a file only
  the broker's account can open. BitLocker covers a stolen disk and BitLocker is the
  customer's to switch on — the installer reports its state and claims nothing.
- **Anything about what the broker RUNS.** The boundary protects whatever is inside it,
  including code somebody else chose. If node or the package sits where an ordinary user
  can write — nvm-windows puts node under %APPDATA% — the account split protects their
  code instead of ours. The verifier fails on it; the copy must not gloss it.
- **macOS parity with the Linux hardening.** The uid split is the same on both. The
  systemd unit's sandboxing — ProtectSystem, ProtectHome, ProtectProc, the syscall filter —
  has no launchd equivalent, so on macOS the uid split is very nearly the whole defence.
  Do not describe the two as equivalent beyond the boundary itself.
- **A sealed store key on macOS.** There isn't one. It is a random key in a 0600 file owned
  by the broker's account: not recomputable, not sealed. A disk copy plus root opens it.
- **"Hardened encryption" as a phase-4 claim.** Phase 4 added an access boundary. The
  encryption is unchanged. The strong crypto (2SKD, wrapped vault keys) predates it and should
  be credited to itself.
