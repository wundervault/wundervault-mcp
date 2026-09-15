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
by the same user the agent runs as — which means "the agent has the key" is literally true.
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

### 3. Two-Secret Key Derivation (the 1Password property)
A 16-byte Account Secret is generated on your device and never sent to the server. It is
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

> *Some keys should need a human. Those ones do.*

---

## Not yet true — do NOT put these on a page

- **Hardware-sealed local storage.** The broker's own store is protected by file permissions,
  not by a key you cannot recompute. TPM / Secure Enclave sealing is phase 5.
- **Argon2id.** Implemented in `app/crypto.py` and not called by anything. PBKDF2 is what runs.
- **Post-quantum anything.** No hybrid key exchange, no PQ signatures.
- **macOS and Windows brokers.** Linux only. On other platforms the credentials are held by a
  process running as the same user as the agents — say so, do not imply otherwise.
- **"Hardened encryption" as a phase-4 claim.** Phase 4 added an access boundary. The
  encryption is unchanged. The strong crypto (2SKD, wrapped vault keys) predates it and should
  be credited to itself.
