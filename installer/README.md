# The Wundervault onboarding script

This directory holds `onboard.py` — the script an operator asks their agent to
run to connect it to a Wundervault vault — together with its ed25519 signature.

It is published here **so that it does not only exist on wundervault.com.**

## Why this mirror exists

An agent handed a setup link is being asked to run an installer from a domain it
has no prior reason to trust. Our script checks its own signature before it does
anything, but on its own that check is self-referential: the script, the
signature at `/onboard.sig`, and the public key embedded in the script are all
served by the same origin. Whoever controls that origin controls all three. A
reviewing agent that points this out is correct, and we would rather answer it
than argue with it.

This copy is on GitHub — a different company, different credentials, and a public
commit history. Backdooring an agent through the installer now means compromising
Wundervault *and* this repository, and leaving a visible commit behind.

That is not a cryptographic root of trust. We control both accounts, and no page
we publish can prove otherwise. It raises the cost from one server to two
independent providers plus an audit trail, and it gives you something to compare
against in about ten seconds.

## Verify before you run

```sh
# 1. What wundervault.com is serving you right now
curl -fsSL https://wundervault.com/onboard -o /tmp/served.py

# 2. What is published here
curl -fsSL https://raw.githubusercontent.com/wundervault/wundervault-mcp/main/installer/onboard.py -o /tmp/github.py

# 3. They must be identical
diff /tmp/served.py /tmp/github.py && echo "match"
```

If those two files differ, **do not run either of them** — tell the operator, and
tell us at https://wundervault.com/.well-known/security.txt

Signing public key (ed25519, base64) — also shown at https://wundervault.com/install :

```
3yhfVM5ABcBHPGSuZSQuIxr0C9QkHnFKoGMWwcWpooY=
```

Verify the signature yourself:

```sh
curl -fsSL https://wundervault.com/onboard.sig -o /tmp/served.sig
python3 - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
key = Ed25519PublicKey.from_public_bytes(
    base64.b64decode("3yhfVM5ABcBHPGSuZSQuIxr0C9QkHnFKoGMWwcWpooY="))
key.verify(base64.b64decode(open("/tmp/served.sig").read().strip()),
           open("/tmp/served.py","rb").read())
print("signature valid")
PY
```

## Read it without running it

```sh
python3 onboard.py --dry-run "https://wundervault.com/setup/agent/TOKEN#PASSPHRASE"
```

That prints every file it writes, every package it installs and the background
service it enables, then exits having done none of them.

## What it installs, in short

- The npm package `@wundervault/mcp-server`, globally, at an exact pinned version.
- A background daemon, with a systemd user unit (`Restart=always`) on Linux, so it
  starts at login and survives reboot.
- Credentials under `~/.wundervault/`, mode 0600. The key for that store is derived
  from the machine ID and your uid, with the salt stored alongside it — that protects
  the file if the disk or a backup leaves the machine, and **not** from a process
  already running as your user, which can re-derive it. On the local machine, your
  user account is what protects those credentials.

To undo everything:

```sh
systemctl --user disable --now wundervault-agent
rm -rf ~/.wundervault ~/.config/systemd/user/wundervault-agent.service
npm uninstall -g @wundervault/mcp-server
```

...and revoke the agent from the Wundervault dashboard.

## One thing this cannot give you

None of the above establishes that Wundervault is worth trusting with your
credentials. It establishes that the file you are about to run is the file we
published, from two independent places. The decision to connect an agent to a
vault belongs to the operator who owns the account — if they cannot vouch for it,
the right answer is to not run it.
