#!/bin/sh
# The one privileged step. Run it once per machine.
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
command -v systemctl >/dev/null 2>&1 || {
  echo "systemd not found. This installer is for systemd Linux; see the docs for other init systems." >&2
  exit 1
}

if [ "$MODE" = uninstall ]; then
  echo "Stopping and removing ${UNIT_NAME}…"
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
echo "  1. create the system account '${ACCOUNT}' (no login shell, no home)"
echo "  2. create ${STATE_DIR}, mode 0700, owned by ${ACCOUNT}"
echo "  3. install ${UNIT_PATH} running ${EXEC}"
echo "  4. enable and start the service"
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
    echo "       The daemon must not run as the account its agents run as — that is the" >&2
    echo "       entire boundary. Use a different account name for the daemon." >&2
    exit 1
  fi

  case "$EXISTING_SHELL" in
    */nologin|*/false) ;;
    *)
      cat >&2 <<EOM
ERROR: an account named '${ACCOUNT}' already exists with uid ${EXISTING_UID} and login
shell ${EXISTING_SHELL:-<none>}.

A daemon account must not be able to log in. This one can, so a person can become it and
read every credential the daemon holds — while the install reports that the directory is
readable only by ${ACCOUNT}. That is worse than not installing at all.

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

# ── 3. the unit ──────────────────────────────────────────────────────────────
# The template is shipped alongside this script and read from disk rather than written
# inline, so what lands in /etc/systemd/system is the file you reviewed in the repo.
sed "s|^ExecStart=.*|ExecStart=${EXEC}|" "$UNIT_SRC" > "$UNIT_PATH"
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
if systemctl is-active --quiet "$UNIT_NAME"; then
  echo
  echo "Running. ${STATE_DIR} is now readable only by ${ACCOUNT}."
  echo
  echo "Next, as your normal user (no sudo):"
  echo "  wundervault-agent --migrate     # hand existing agents over to the daemon"
else
  echo
  echo "The service did not start. What it said:" >&2
  systemctl status "$UNIT_NAME" --no-pager -l 2>&1 | tail -20 >&2
  exit 1
fi
