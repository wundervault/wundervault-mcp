#!/bin/sh
# The one privileged step: install the secret broker. Run it once per machine.
#
# The broker is the process that holds your agents' credentials. It gets its own account
# so that the agents — which run as you — cannot read what it holds.
#
# It creates a system account, a directory it owns, and a systemd unit. It does not
# download anything, does not touch the network, and does not install the daemon binary —
# npm already did that, unprivileged, and you verified it then. Keeping the privileged
# part small enough to read in one sitting is the point: this is the script that asks for
# root, so it should be the script you can audit in a minute.
#
#   sudo sh install-daemon.sh [--exec /path/to/wundervault-agent] [--uninstall]
#
# Re-runnable. Running it twice leaves the same machine as running it once.

set -eu

ACCOUNT=wundervault
STATE_DIR=/var/lib/wundervault
UNIT_NAME=wundervault-agent.service
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXEC=""
MODE=install

while [ $# -gt 0 ]; do
  case "$1" in
    --exec) EXEC="${2:?--exec needs a path}"; shift 2 ;;
    --uninstall) MODE=uninstall; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "This step needs root. Re-run with sudo." >&2; exit 1; }
case "$(uname -s)" in
  Linux) ;;
  *)
    echo "This installer is for Linux. The uid split is not available on $(uname -s) yet —" >&2
    echo "the daemon there runs as you, with the pre-split threat model. Nothing to install." >&2
    exit 1 ;;
esac
command -v systemctl >/dev/null 2>&1 || {
  echo "systemd not found. This installer is for systemd Linux; see the docs for other init systems." >&2
  exit 1
}

if [ "$MODE" = uninstall ]; then
  echo "Stopping and removing the secret broker (${UNIT_NAME})…"
  systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
  rm -f "$UNIT_PATH"
  systemctl daemon-reload
  # The account and its state are LEFT BEHIND on purpose. They hold the credentials this
  # machine's agents use; deleting them here would turn "stop the service" into
  # "irreversibly destroy the vault contents" for anyone who typed --uninstall to debug a
  # startup problem. Removing them is a separate, deliberate act:
  echo "Removed the unit. Credentials are left at ${STATE_DIR}."
  echo "To destroy them:  sudo rm -rf ${STATE_DIR} && sudo userdel ${ACCOUNT}"
  exit 0
fi

# ── the binary ───────────────────────────────────────────────────────────────
# Resolved before anything is created, so a bad path fails before it has changed the
# machine rather than after.
if [ -z "$EXEC" ]; then
  EXEC=$(command -v wundervault-agent 2>/dev/null || true)
fi
[ -n "$EXEC" ] || {
  echo "Could not find wundervault-agent on PATH." >&2
  echo "Install it first:  npm install -g @wundervault/mcp-server" >&2
  echo "Or point at it:    sudo sh $0 --exec /path/to/wundervault-agent" >&2
  exit 1
}
case "$EXEC" in /*) ;; *) EXEC=$(CDPATH= cd -- "$(dirname -- "$EXEC")" && pwd)/$(basename -- "$EXEC") ;; esac
[ -x "$EXEC" ] || { echo "Not executable: $EXEC" >&2; exit 1; }

# Resolve symlinks BEFORE the ProtectHome check. `npm install -g` into a user prefix
# leaves ~/.local/bin/wundervault-agent pointing at ~/.local/lib/node_modules/..., so a
# path that looks fine can still land the real file under /home.
REAL_EXEC=$(readlink -f "$EXEC" 2>/dev/null || echo "$EXEC")

# ProtectHome=yes makes /home, /root and /run/user empty FOR THIS SERVICE. An ExecStart
# under any of them does not fail at install time — it fails at start with 203/EXEC, after
# the account and the state directory already exist, and the message points at the binary
# rather than at the sandbox that hid it. Node resolves its package directory at runtime
# too, so a launcher outside /home whose library sits inside it fails the same way, one
# step later and even less legibly. Refuse both here, where the fix is still cheap.
for CANDIDATE in "$EXEC" "$REAL_EXEC"; do
  case "$CANDIDATE" in
    /home/*|/root/*|/run/user/*)
      echo "ERROR: $CANDIDATE is inside a home directory." >&2
      # A plain `a && b` list here would return non-zero whenever the symlink note does
      # not apply, and `set -e` would take that as a failure and exit before the
      # explanation below ever printed — leaving only "ERROR:" and no way forward.
      if [ "$CANDIDATE" = "$REAL_EXEC" ] && [ "$EXEC" != "$REAL_EXEC" ]; then
        echo "       (reached via the symlink $EXEC)" >&2
      fi
      cat >&2 <<EOM
The unit sets ProtectHome=yes, which makes /home invisible to the service, so this
would install cleanly and then fail to start with status=203/EXEC.

Install the package somewhere the service can see it:

  sudo npm install -g --prefix /usr/local @wundervault/mcp-server
  sudo sh $0 --exec /usr/local/bin/wundervault-agent

ProtectHome is not negotiable here: it is what stops the daemon reading the home
directories of the agents it holds credentials for.

And no, this cannot be solved by bind-mounting the path back in. A directory under your
home is WRITABLE by everything that runs as you, agents included — so the daemon would be
executing code its own agents can replace. That is a worse hole than the one this whole
step exists to close: it would hand over not just the credentials but the process that
guards them. The package has to live somewhere the agent cannot write.
EOM
      exit 1 ;;
  esac
done

UNIT_SRC="${HERE}/${UNIT_NAME}"
[ -f "$UNIT_SRC" ] || { echo "Missing unit template: $UNIT_SRC" >&2; exit 1; }

echo "This will:"
echo "  1. create the system account '${ACCOUNT}' for the secret broker (no login, no home)"
echo "  2. create ${STATE_DIR}, mode 0700, owned by ${ACCOUNT}"
echo "  3. install ${UNIT_PATH}, which runs the broker: ${EXEC}"
echo "  4. enable and start the broker"
echo

# ── 1. the account ───────────────────────────────────────────────────────────
if id -u "$ACCOUNT" >/dev/null 2>&1; then
  # An existing account is NOT automatically the right account.
  #
  # If a human logs in as `wundervault` — their own uid, the uid their agents run as — then
  # skipping creation here chowns the credential store to that uid and starts the daemon as
  # them. The agent can then read the store and the daemon's memory, and the install prints
  # "Running. /var/lib/wundervault is now readable only by wundervault." The boundary is
  # gone and every message says it is there, which is worse than not installing at all.
  EXISTING_UID=$(id -u "$ACCOUNT")
  EXISTING_SHELL=$(getent passwd "$ACCOUNT" | cut -d: -f7)
  INVOKER_UID=""
  [ -n "${SUDO_UID:-}" ] && INVOKER_UID="$SUDO_UID"

  # The decisive test is NOT the uid number.
  #
  # An earlier version refused only uid >= 1000, on the assumption that below that means a
  # system account. That is a convention, not a rule — plenty of hosts have human logins at
  # uid 500 — and getting it wrong means running the daemon as the very account its agents
  # use, with the installer printing that the directory is readable only by wundervault.
  #
  # So: refuse if this is the account that invoked us, and refuse if it can log in. A
  # daemon account has no shell; if it has one, a person can become it, and everything this
  # phase builds rests on nobody being able to.
  if [ -n "$INVOKER_UID" ] && [ "$EXISTING_UID" = "$INVOKER_UID" ]; then
    echo "ERROR: '${ACCOUNT}' is the account you are running as (uid ${EXISTING_UID})." >&2
    echo "       The broker must not run as the account its agents run as — that is the" >&2
    echo "       entire boundary. Use a different account name for the daemon." >&2
    exit 1
  fi

  case "$EXISTING_SHELL" in
    */nologin|*/false) ;;
    *)
      cat >&2 <<EOM
ERROR: an account named '${ACCOUNT}' already exists with uid ${EXISTING_UID} and login
shell ${EXISTING_SHELL:-<none>}.

The broker's account must not be able to log in. This one can, so a person can become it
and read every credential the broker holds — while the install reports that the directory
is readable only by ${ACCOUNT}. That is worse than not installing at all.

If this account is meant to be the daemon's:
  sudo usermod -s /usr/sbin/nologin ${ACCOUNT}
If it belongs to a person or another service, the daemon needs a different name.
EOM
      exit 1 ;;
  esac

  if [ "$EXISTING_UID" -ge 1000 ] 2>/dev/null; then
    echo "NOTE: ${ACCOUNT} has uid ${EXISTING_UID}, which is usually a login range." >&2
    echo "      It has no login shell, so continuing." >&2
  fi
  echo "account ${ACCOUNT}: already exists (uid ${EXISTING_UID}, system account)"
else
  # --system: no ageing, a low uid, and no login. --shell nologin so a credential leak
  # elsewhere cannot turn this into a way to get a shell.
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$STATE_DIR" \
            --shell /usr/sbin/nologin "$ACCOUNT" 2>/dev/null \
      || useradd --system --no-create-home --home-dir "$STATE_DIR" \
                 --shell /sbin/nologin "$ACCOUNT"
  elif command -v adduser >/dev/null 2>&1; then
    adduser --system --no-create-home --home "$STATE_DIR" --group "$ACCOUNT"
  else
    echo "Neither useradd nor adduser found; create the '${ACCOUNT}' system user manually." >&2
    exit 1
  fi
  echo "account ${ACCOUNT}: created"
fi

# ── 2. the directory ─────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
chown "${ACCOUNT}:$(id -gn "$ACCOUNT")" "$STATE_DIR"
# Unconditional, because mkdir's mode is masked by umask and ignored outright when the
# directory already exists. A directory left at 0755 by an earlier run would leave the
# boundary open while every other check here passed.
chmod 0700 "$STATE_DIR"
ACTUAL=$(stat -c '%a' "$STATE_DIR" 2>/dev/null || stat -f '%Lp' "$STATE_DIR")
[ "$ACTUAL" = "700" ] || { echo "ERROR: ${STATE_DIR} is mode ${ACTUAL}, expected 700." >&2; exit 1; }
echo "state dir ${STATE_DIR}: 0700 ${ACCOUNT}"

# ── 2b. the sealed store key ─────────────────────────────────────────────────
#
# A random 32-byte key, sealed so that the file on disk is useless on its own.
#
# What this replaces: a key DERIVED from /etc/machine-id and the account's uid, with the
# salt stored beside the ciphertext. Every input to that is readable by anyone who can read
# the directory, so the key was recomputable — the directory mode was doing all the work and
# the encryption was decoration. Someone who walked off with the disk had everything.
#
# `systemd-creds encrypt` seals to the TPM where there is one, and to the root-only host key
# otherwise. Either way the blob does not open on another machine, and the broker never needs
# TPM access itself: systemd unseals it as root at start and hands it over through a private
# tmpfs (LoadCredentialEncrypted= in the unit).
SEALED_KEY="${STATE_DIR}/store.key.cred"
if [ -f "$SEALED_KEY" ]; then
  echo "store key: already sealed at ${SEALED_KEY}"
elif command -v systemd-creds >/dev/null 2>&1; then
  TPM_STATE=$(systemd-creds has-tpm2 2>/dev/null | head -1 || echo no)
  if head -c 32 /dev/urandom \
      | systemd-creds encrypt --name=wv-store-key - "$SEALED_KEY" 2>/dev/null; then
    chown "${ACCOUNT}:$(id -gn "$ACCOUNT")" "$SEALED_KEY"
    chmod 0600 "$SEALED_KEY"
    case "$TPM_STATE" in
      yes) echo "store key: sealed to this machine's TPM" ;;
      *)   echo "store key: sealed to the host key (no TPM found — still not portable,"
           echo "           but a disk copy plus root would open it)" ;;
    esac
  else
    echo "WARNING: could not seal a store key with systemd-creds." >&2
    echo "         The broker will fall back to a key derived from /etc/machine-id and its" >&2
    echo "         uid, which anyone able to read ${STATE_DIR} can recompute. The directory" >&2
    echo "         mode still protects it; the encryption does not." >&2
  fi
else
  echo "WARNING: systemd-creds not found, so the store key cannot be sealed." >&2
  echo "         The broker falls back to a derived, recomputable key. See the docs." >&2
fi

# ── 3. the unit ──────────────────────────────────────────────────────────────
# The template is shipped alongside this script and read from disk rather than written
# inline, so what lands in /etc/systemd/system is the file you reviewed in the repo.
sed "s|^ExecStart=.*|ExecStart=${EXEC}|" "$UNIT_SRC" > "$UNIT_PATH"

# No sealed key on this machine? Then the unit must not ask systemd for one: a missing
# credential source is fatal (243/CREDENTIALS), and a broker that will not start is worse
# than one running on the derived key and saying so.
if [ ! -f "$SEALED_KEY" ]; then
  sed -i '/^LoadCredentialEncrypted=wv-store-key:/d' "$UNIT_PATH"
  echo "unit: no sealed key, so the credential line was removed"
fi
chmod 0644 "$UNIT_PATH"
grep -q "^User=${ACCOUNT}\$" "$UNIT_PATH" || {
  echo "ERROR: the installed unit does not run as ${ACCOUNT}. Refusing to continue." >&2
  rm -f "$UNIT_PATH"; exit 1
}
echo "unit ${UNIT_PATH}: installed"

# ── 4. start ─────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
# restart, not `enable --now`. `--now` starts a stopped unit and leaves a RUNNING one
# exactly as it was — so re-running the installer after a package upgrade rewrote the unit,
# reported "Running", and left the old process going under the old configuration, including
# an ExecStart pointing at the previous binary.
systemctl restart "$UNIT_NAME"

sleep 1

# Did the sealing actually take EFFECT? Sealing a key and delivering it are separate things,
# and the gap between them is silent: systemd can set CREDENTIALS_DIRECTORY and still fail to
# materialise the file, which leaves the broker on the derived key while a sealed blob sits
# on disk looking like proof of something. Ask the broker what key it is actually using.
if [ -f "$SEALED_KEY" ] && systemctl is-active --quiet "$UNIT_NAME"; then
  sleep 1
  if journalctl -u "$UNIT_NAME" -n 20 --no-pager 2>/dev/null | grep -q "Store key: DERIVED"; then
    echo >&2
    echo "WARNING: a sealed key exists but the broker is NOT using it." >&2
    echo "         systemd did not deliver the credential — check:" >&2
    echo "           systemd-creds decrypt --name=wv-store-key ${SEALED_KEY} -" >&2
    echo "           journalctl -u ${UNIT_NAME} | grep -i credential" >&2
    echo "         The store is running on a key derived from /etc/machine-id and the" >&2
    echo "         broker's uid, which anyone able to read ${STATE_DIR} can recompute." >&2
    echo "         Do not describe this machine as having a sealed store." >&2
  fi
fi

if systemctl is-active --quiet "$UNIT_NAME"; then
  echo
  echo "The secret broker is running. ${STATE_DIR} is readable only by ${ACCOUNT},"
  echo "which means your agents cannot read the credentials it holds."
  echo
  echo "Next, as your normal user (no sudo):"
  echo "  wundervault-agent --migrate     # hand existing agents over to the daemon"
else
  echo
  echo "The secret broker did not start. What it said:" >&2
  systemctl status "$UNIT_NAME" --no-pager -l 2>&1 | tail -20 >&2
  exit 1
fi
