#!/bin/sh
# The one privileged step, on macOS. Install the secret broker. Run it once per machine.
#
# The broker is the process that holds your agents' credentials. It gets its own account
# so that the agents — which run as you — cannot read what it holds.
#
# It creates a hidden service account, a directory it owns, and a LaunchDaemon. It does not
# download anything, does not touch the network, and does not install the daemon itself —
# npm already did that, unprivileged, and you verified it then. Keeping the privileged part
# small enough to read in one sitting is the point: this is the script that asks for root,
# so it should be the script you can audit in a minute.
#
#   sudo sh install-daemon-macos.sh [--exec /path/to/wundervault-agent] [--node /path/to/node] [--uninstall]
#
# Re-runnable. Running it twice leaves the same machine as running it once.

set -eu

ACCOUNT=_wundervault
# THREE directories, and the split between them is not tidiness.
#
# On Linux systemd puts the sockets in /run/wundervault, at 0755, OUTSIDE the 0700 state
# directory. macOS has no /run and no RuntimeDirectory=, and putting the sockets inside the
# state directory is fatally wrong: 0700 denies search permission to everyone but this
# account, so an agent — which runs as the OWNER — cannot traverse in to reach its own
# socket, and every connection fails with EACCES on a perfect install.
#
#   BASE_DIR   0755  traversable, holds nothing readable
#   STATE_DIR  0700  the boundary: credentials, keys, the store
#   RUN_DIR    0755  sockets, which agents must be able to reach
BASE_DIR=/var/lib/wundervault
STATE_DIR="${BASE_DIR}/state"
RUN_DIR="${BASE_DIR}/run"
LABEL=com.wundervault.agent
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXEC=""
NODE=""
MODE=install

while [ $# -gt 0 ]; do
  case "$1" in
    --exec) EXEC="${2:?--exec needs a path}"; shift 2 ;;
    --node) NODE="${2:?--node needs a path}"; shift 2 ;;
    --uninstall) MODE=uninstall; shift ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "This step needs root. Re-run with sudo." >&2; exit 1; }
case "$(uname -s)" in
  Darwin) ;;
  Linux)
    echo "This is the macOS installer. On Linux use install-daemon.sh." >&2
    exit 1 ;;
  *)
    echo "The uid split is not available on $(uname -s). The daemon there runs as you," >&2
    echo "with the pre-split threat model. Nothing to install." >&2
    exit 1 ;;
esac

if [ "$MODE" = uninstall ]; then
  echo "Stopping and removing the secret broker (${LABEL})…"
  # bootout fails on a job that is not loaded, which is fine and expected. What is NOT fine
  # is deleting the plist while the job IS still loaded: launchd keeps running from the
  # definition it already has, so the broker carries on serving credentials from a
  # configuration nobody can read any more, and the next install's bootstrap has nothing to
  # replace. Ask launchd what is true rather than trusting the exit code.
  launchctl bootout "system/${LABEL}" 2>/dev/null || true
  if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    echo "ERROR: the job is still loaded after bootout." >&2
    echo "       Refusing to remove ${PLIST_PATH} — deleting it now would leave the" >&2
    echo "       broker running from a definition you can no longer see or replace." >&2
    echo "       Try:  sudo launchctl bootout system/${LABEL}" >&2
    exit 1
  fi
  rm -f "$PLIST_PATH"
  # The account and its state are LEFT BEHIND on purpose. They hold the credentials this
  # machine's agents use; deleting them here would turn "stop the service" into
  # "irreversibly destroy the vault contents" for anyone who typed --uninstall to debug a
  # startup problem. Removing them is a separate, deliberate act:
  echo "Removed the job. Credentials are left at ${STATE_DIR}."
  echo "To destroy them:"
  echo "  sudo rm -rf ${BASE_DIR}"
  echo "  sudo dscl . -delete /Users/${ACCOUNT} && sudo dscl . -delete /Groups/${ACCOUNT}"
  exit 0
fi

# ── the binary ───────────────────────────────────────────────────────────────
# Resolved before anything is created, so a bad path fails before it has changed the
# machine rather than after.
real_path() {
  if command -v readlink >/dev/null 2>&1 && readlink -f / >/dev/null 2>&1; then
    readlink -f "$1"
    return
  fi
  # macOS readlink has no -f before Ventura. Follow it by hand.
  R="$1"
  while [ -L "$R" ]; do
    LINK=$(readlink "$R")
    case "$LINK" in
      /*) R="$LINK" ;;
      *)  R="$(dirname -- "$R")/$LINK" ;;
    esac
  done
  # pwd -P, so a symlinked directory (/tmp is /private/tmp) compares equal to pick_broker's own.
  printf '%s\n' "$(CDPATH= cd -- "$(dirname -- "$R")" && pwd -P)/$(basename -- "$R")"
}

# >>> pick the broker: the copy this installer came with (2.0.1). The first
# wundervault-agent on sudo's PATH used to win, so an old copy elsewhere on PATH could be
# installed over the one beside this script. Windows has always installed the copy beside it.
# test/installer-pick.test.ts runs this function on its own; it sets EXEC and reads nothing
# else but real_path above.
pick_broker() {
  _self_pkg=$(CDPATH= cd -- "$1/.." 2>/dev/null && pwd -P) || _self_pkg=""
  _own=""
  if [ -n "$_self_pkg" ] && [ -f "$_self_pkg/dist/agent.js" ]; then
    # npm's global layout: <prefix>/lib/node_modules/@wundervault/mcp-server, launchers in <prefix>/bin.
    _bin=$(CDPATH= cd -- "$_self_pkg/../../../../bin" 2>/dev/null && pwd -P) || _bin=""
    if [ -n "$_bin" ] && [ -x "$_bin/wundervault-agent" ] \
       && [ "$(real_path "$_bin/wundervault-agent")" = "$(real_path "$_self_pkg/dist/agent.js")" ]; then
      _own="$_bin/wundervault-agent"
    fi
  fi
  _first=$(command -v wundervault-agent 2>/dev/null || true)
  if [ -n "$_own" ]; then
    EXEC="$_own"
    if [ -n "$_first" ] && [ "$(real_path "$_first")" != "$(real_path "$_own")" ]; then
      echo "note: using $_own, the copy this installer came with."
      echo "      $_first comes first on PATH but is a different copy, so it was skipped."
    fi
  else
    EXEC="$_first"
    if [ -n "$EXEC" ] && [ -n "$_self_pkg" ]; then
      case "$(real_path "$EXEC")" in
        "$_self_pkg"/*) ;;
        *)
          echo "WARNING: no wundervault-agent launcher found for the copy at $_self_pkg," >&2
          echo "         so this installs $EXEC from PATH, which is a different copy." >&2
          echo "         To choose:  sudo sh $0 --exec /path/to/wundervault-agent" >&2 ;;
      esac
    fi
  fi
}
# <<< pick the broker
if [ -z "$EXEC" ]; then
  pick_broker "$HERE"
fi
[ -n "$EXEC" ] || {
  echo "Could not find wundervault-agent on PATH." >&2
  echo "Install it first:  npm install -g @wundervault/mcp-server" >&2
  echo "Or point at it:    sudo sh $0 --exec /path/to/wundervault-agent" >&2
  exit 1
}
case "$EXEC" in /*) ;; *) EXEC=$(CDPATH= cd -- "$(dirname -- "$EXEC")" && pwd)/$(basename -- "$EXEC") ;; esac
[ -x "$EXEC" ] || { echo "Not executable: $EXEC" >&2; exit 1; }

# Resolve symlinks BEFORE the home-directory check. `npm install -g` into a user prefix
# leaves ~/.local/bin/wundervault-agent pointing at ~/.local/lib/node_modules/..., so a
# path that looks fine can still land the real file under /Users.
REAL_EXEC=$(real_path "$EXEC")

# On Linux the reason to refuse a home directory is ProtectHome=yes, which makes the path
# invisible to the service. launchd has no ProtectHome, so the job WOULD start — and that
# is worse, not better. A directory under /Users is writable by the account the agents run
# as, so the daemon would be executing code its own agents can replace: not just the
# credentials handed over, but the process that guards them.
for CANDIDATE in "$EXEC" "$REAL_EXEC"; do
  case "$CANDIDATE" in
    /Users/*|/private/var/root/*|/var/root/*)
      echo "ERROR: $CANDIDATE is inside a home directory." >&2
      if [ "$CANDIDATE" = "$REAL_EXEC" ] && [ "$EXEC" != "$REAL_EXEC" ]; then
        echo "       (reached via the symlink $EXEC)" >&2
      fi
      cat >&2 <<EOM

A home directory is writable by the account your agents run as. Installing from there
would have the broker execute code those agents can replace — which hands over not only
the credentials but the process that guards them. That is a worse hole than the one this
step exists to close.

Install the package somewhere the agent cannot write:

  sudo npm install -g --prefix /usr/local @wundervault/mcp-server
  sudo sh $0 --exec /usr/local/bin/wundervault-agent
EOM
      exit 1 ;;
  esac
done

# ── the interpreter ──────────────────────────────────────────────────────────
# The broker is a Node script whose first line is `#!/usr/bin/env node`, and launchd starts
# a daemon with PATH=/usr/bin:/bin:/usr/sbin:/sbin. No Mac has node there (the nodejs.org
# installer uses /usr/local/bin, Homebrew /opt/homebrew/bin), so the job exited 127 on every
# start and launchd respawned it for ever. Found on the first real Mac, 2026-10-20. The job
# now names the interpreter by its full path, resolved here, where the PATH is yours.
#
# The interpreter is code the broker runs exactly as much as its own script is, so both are
# held to one rule: owned by root and writable by nobody else. A node the agents' account
# can replace is a broker the agents can replace.
if [ -z "$NODE" ]; then
  NODE=$(command -v node 2>/dev/null || true)
fi
[ -n "$NODE" ] || {
  echo "ERROR: there is no node on your PATH. Install Node.js from nodejs.org, or pass --node /path/to/node." >&2
  exit 1
}
case "$NODE" in /*) ;; *) echo "ERROR: --node needs a full path, not: $NODE" >&2; exit 1 ;; esac
[ -x "$NODE" ] || { echo "Not executable: $NODE" >&2; exit 1; }
REAL_NODE=$(real_path "$NODE")
for F in "$REAL_EXEC" "$REAL_NODE"; do
  F_OWNER=$(stat -f '%Su' "$F")
  F_MODE=$(stat -f '%Lp' "$F")
  F_GROUP_W=$(printf '%s' "$F_MODE" | cut -c2)
  F_OTHER_W=$(printf '%s' "$F_MODE" | cut -c3)
  case "$F_GROUP_W$F_OTHER_W" in
    *[2367]*) F_BAD="writable by group or others (mode $F_MODE)" ;;
    *) F_BAD="" ;;
  esac
  [ "$F_OWNER" = root ] || F_BAD="owned by ${F_OWNER}, not root"
  if [ -n "$F_BAD" ]; then
    cat >&2 <<EOM
ERROR: $F is $F_BAD.

The broker runs this file. Anyone who can replace it can replace the broker, and with it
everything the broker holds. Install it as root, somewhere only root can write: for node,
the installer from nodejs.org (/usr/local/bin/node); for the broker,
  sudo npm install -g --prefix /usr/local @wundervault/mcp-server
EOM
    exit 1
  fi
done

# ── Node.js with the October 21, 2026 security fix ──────────────────────────
# That release fixed a memory-corruption flaw in Node's Brotli decoder and two TLS hostname
# checks. The broker decompresses replies from services an agent chooses, so on an unpatched
# Node an agent could corrupt the memory of the process that holds your keys. The broker
# refuses to start on one (src/node-floor.ts); this says so before anything is installed.
NODE_NEED="Node.js 22.23.4, 24.22.1 or 26.12.1 or newer (the October 21, 2026 security release)"
node_ok() {  # $1: what `node -p process.version` printed, e.g. v24.22.1
  _v=${1#v}; _maj=${_v%%.*}; _r=${_v#*.}; _min=${_r%%.*}; _pat=${_r#*.}; _pre=${_pat#"${_pat%%[!0-9]*}"}; _pat=${_pat%%[!0-9]*}
  for _n in "$_maj" "$_min" "$_pat"; do case "$_n" in ''|*[!0-9]*) return 1 ;; esac; done
  case "$_maj" in
    22) _fm=23; _fp=4 ;;
    24) _fm=22; _fp=1 ;;
    26) _fm=12; _fp=1 ;;
    *) [ "$_maj" -gt 26 ]; return ;;
  esac
  # A pre-release OF the floor version (22.23.4-rc.1) comes before it, and may predate the fix.
  [ "$_min" -gt "$_fm" ] || { [ "$_min" -eq "$_fm" ] && { [ "$_pat" -gt "$_fp" ] || { [ "$_pat" -eq "$_fp" ] && [ -z "$_pre" ]; }; }; }
}
NODE_VERSION=$("$NODE" -p process.version 2>/dev/null || echo unknown)
node_ok "$NODE_VERSION" || {
  echo "ERROR: $NODE is Node.js $NODE_VERSION, which lacks the October 21, 2026 security fix." >&2
  echo "Install ${NODE_NEED} from nodejs.org, then run this again. Nothing has been changed." >&2
  exit 1
}

PLIST_SRC="${HERE}/${LABEL}.plist"
[ -f "$PLIST_SRC" ] || { echo "Missing plist template: $PLIST_SRC" >&2; exit 1; }

echo "This will:"
echo "  1. create the hidden service account '${ACCOUNT}' for the secret broker"
echo "  2. create ${STATE_DIR} (0700) and ${RUN_DIR} (0755), owned by ${ACCOUNT}"
echo "  3. install ${PLIST_PATH}, which runs the broker: ${NODE} ${EXEC}"
echo "  4. start the broker"
echo

# ── 1. the account ───────────────────────────────────────────────────────────
if dscl . -read "/Users/${ACCOUNT}" >/dev/null 2>&1; then
  # An existing account is NOT automatically the right account.
  #
  # If a human logs in as this name — their own uid, the uid their agents run as — then
  # skipping creation here chowns the credential store to that uid and starts the daemon as
  # them. The agent can then read the store and attach to the daemon, while the install
  # prints that the directory is readable only by the broker. The boundary is gone and
  # every message says it is there, which is worse than not installing at all.
  EXISTING_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
  EXISTING_SHELL=$(dscl . -read "/Users/${ACCOUNT}" UserShell 2>/dev/null | awk '{print $2}')
  ACCOUNT_GID=$(dscl . -read "/Users/${ACCOUNT}" PrimaryGroupID 2>/dev/null | awk '{print $2}')

  if [ -n "${SUDO_UID:-}" ] && [ "$EXISTING_UID" = "$SUDO_UID" ]; then
    echo "ERROR: '${ACCOUNT}' is the account you are running as (uid ${EXISTING_UID})." >&2
    echo "       The broker must not run as the account its agents run as — that is the" >&2
    echo "       entire boundary." >&2
    exit 1
  fi

  case "$EXISTING_SHELL" in
    /usr/bin/false|/usr/bin/nologin|/sbin/nologin|/dev/null) ;;
    *)
      cat >&2 <<EOM
ERROR: an account named '${ACCOUNT}' already exists with uid ${EXISTING_UID} and login
shell ${EXISTING_SHELL:-<none>}.

The broker's account must not be able to log in. This one can, so a person can become it
and read every credential the broker holds — while the install reports that the directory
is readable only by ${ACCOUNT}. That is worse than not installing at all.

If this account is meant to be the daemon's:
  sudo dscl . -create /Users/${ACCOUNT} UserShell /usr/bin/false
If it belongs to a person or another service, the daemon needs a different name.
EOM
      exit 1 ;;
  esac
  echo "account ${ACCOUNT}: already exists (uid ${EXISTING_UID})"
else
  # A free id below 500, which is where macOS keeps service accounts. Both lists are
  # checked so the user and the group can share a number.
  ACCOUNT_UID=""
  TAKEN_UIDS=$(dscl . -list /Users UniqueID | awk '{print $2}')
  TAKEN_GIDS=$(dscl . -list /Groups PrimaryGroupID | awk '{print $2}')
  N=200
  while [ "$N" -lt 400 ]; do
    if ! printf '%s\n' "$TAKEN_UIDS" | grep -qx "$N" \
       && ! printf '%s\n' "$TAKEN_GIDS" | grep -qx "$N"; then
      ACCOUNT_UID="$N"; break
    fi
    N=$((N + 1))
  done
  [ -n "$ACCOUNT_UID" ] || {
    echo "ERROR: no free uid/gid between 200 and 399 for the service account." >&2
    exit 1
  }
  ACCOUNT_GID="$ACCOUNT_UID"

  dscl . -create "/Groups/${ACCOUNT}"
  dscl . -create "/Groups/${ACCOUNT}" PrimaryGroupID "$ACCOUNT_GID"
  dscl . -create "/Groups/${ACCOUNT}" RealName "Wundervault secret broker"
  dscl . -create "/Groups/${ACCOUNT}" Password '*'

  dscl . -create "/Users/${ACCOUNT}"
  dscl . -create "/Users/${ACCOUNT}" UniqueID "$ACCOUNT_UID"
  dscl . -create "/Users/${ACCOUNT}" PrimaryGroupID "$ACCOUNT_GID"
  dscl . -create "/Users/${ACCOUNT}" RealName "Wundervault secret broker"
  # No shell and no home. If a credential leak elsewhere ever reaches this name, it must
  # not also be a way to get a session.
  dscl . -create "/Users/${ACCOUNT}" UserShell /usr/bin/false
  dscl . -create "/Users/${ACCOUNT}" NFSHomeDirectory /var/empty
  dscl . -create "/Users/${ACCOUNT}" Password '*'
  # Keeps it off the login window and out of Users & Groups.
  dscl . -create "/Users/${ACCOUNT}" IsHidden 1

  # dscl writes one attribute per call and there is no transaction. An interruption part
  # way through leaves a user record with, say, a UniqueID and no PrimaryGroupID or shell —
  # and the NEXT run takes the existing-account branch, reads a blank UserShell, and either
  # refuses permanently or fails later at chown. Verify what was actually written while we
  # still have root and know what it should be.
  V_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
  V_GID=$(dscl . -read "/Users/${ACCOUNT}" PrimaryGroupID 2>/dev/null | awk '{print $2}')
  V_SHELL=$(dscl . -read "/Users/${ACCOUNT}" UserShell 2>/dev/null | awk '{print $2}')
  if [ "$V_UID" != "$ACCOUNT_UID" ] || [ "$V_GID" != "$ACCOUNT_GID" ] \
     || [ "$V_SHELL" != "/usr/bin/false" ]; then
    echo "ERROR: the account was only partly created." >&2
    echo "       uid=${V_UID:-<missing>} gid=${V_GID:-<missing>} shell=${V_SHELL:-<missing>}" >&2
    echo "       Remove it and re-run, rather than leaving a half-made account behind:" >&2
    echo "         sudo dscl . -delete /Users/${ACCOUNT}" >&2
    echo "         sudo dscl . -delete /Groups/${ACCOUNT}" >&2
    exit 1
  fi
  echo "account ${ACCOUNT}: created (uid ${ACCOUNT_UID})"
fi

# ── 2. the directories ───────────────────────────────────────────────────────
mkdir -p "$STATE_DIR" "$RUN_DIR"
chown "${ACCOUNT}:${ACCOUNT}" "$BASE_DIR" "$STATE_DIR" "$RUN_DIR"
# Unconditional, because mkdir's mode is masked by umask and ignored outright when the
# directory already exists. A state directory left at 0755 by an earlier run would leave
# the boundary open while every other check here passed.
chmod 0755 "$BASE_DIR"
chmod 0700 "$STATE_DIR"
chmod 0755 "$RUN_DIR"
ACTUAL=$(stat -f '%Lp' "$STATE_DIR")
[ "$ACTUAL" = "700" ] || { echo "ERROR: ${STATE_DIR} is mode ${ACTUAL}, expected 700." >&2; exit 1; }
# And the other direction, which is just as fatal and fails far more quietly: a run
# directory the agents cannot traverse means every socket connection returns EACCES.
RUN_MODE=$(stat -f '%Lp' "$RUN_DIR")
case "$RUN_MODE" in
  755|775|777) ;;
  *) echo "ERROR: ${RUN_DIR} is mode ${RUN_MODE}; agents could not reach their sockets." >&2; exit 1 ;;
esac
BASE_MODE=$(stat -f '%Lp' "$BASE_DIR")
case "$BASE_MODE" in
  755|775|777) ;;
  *) echo "ERROR: ${BASE_DIR} is mode ${BASE_MODE}; agents could not traverse to ${RUN_DIR}." >&2; exit 1 ;;
esac
echo "state dir ${STATE_DIR}: 0700 ${ACCOUNT}"
echo "run dir   ${RUN_DIR}: 0755 ${ACCOUNT} — agents reach their sockets through here"

# ── 2b. the broker's own identity ────────────────────────────────────────────
#
# A P-256 keypair, generated HERE and never leaving this machine. Its public half is what
# an owner pairs with their account; after that, a repair seals the agent's credential to
# it and the thing the owner carries to this terminal is a claim code, which opens nothing.
#
# Generated with openssl rather than by the broker at first start, so that the key exists
# before anything can ask for it and so the mode is set by root while root is still here.
# A path inside a directory the SERVICE ACCOUNT owns, about to be written BY ROOT.
#
# That account can replace either key file with a symlink before a reinstall. openssl or dd
# would then follow it as root, create or clobber whatever it points at, and the chown that
# follows would hand that target to the service account. A privileged installer must not
# resolve a path through a directory an unprivileged account can rearrange under it — the
# same rule that keeps `--destinations` from following a path in the agent's home.
#
# -h is the test that matters: -f follows the link and answers about the TARGET.
refuse_symlink() {
  if [ -h "$1" ]; then
    echo "ERROR: $1 is a symbolic link." >&2
    echo "       This installer writes that path as root. A link there would have root" >&2
    echo "       create or overwrite whatever it points at. Remove it and re-run:" >&2
    echo "         sudo rm -- '$1'" >&2
    exit 1
  fi
}

BROKER_KEY="${STATE_DIR}/broker-key.pem"
STORE_KEY="${STATE_DIR}/store.key"
refuse_symlink "$BROKER_KEY"
refuse_symlink "$STORE_KEY"

if [ -f "$BROKER_KEY" ]; then
  echo "broker key: already present at ${BROKER_KEY}"
else
  # umask before the write, not chmod after: openssl creates the file itself, and a chmod
  # that lands a moment later is a moment in which the key was world-readable.
  # `|| true` is load-bearing under `set -e`. Without it a failing openssl exits the whole
  # script here, and the guarded fallback below — the one that prints a warning and lets
  # the broker make its own key at first --pair — can never run.
  ( umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out "$BROKER_KEY" 2>/dev/null ) || true
  if [ -s "$BROKER_KEY" ]; then
    chown "${ACCOUNT}:${ACCOUNT}" "$BROKER_KEY"
    chmod 0600 "$BROKER_KEY"
    BK_MODE=$(stat -f '%Lp' "$BROKER_KEY")
    [ "$BK_MODE" = "600" ] || { echo "ERROR: ${BROKER_KEY} is mode ${BK_MODE}, expected 600." >&2; exit 1; }
    echo "broker key: created, 0600 ${ACCOUNT}"
  else
    rm -f "$BROKER_KEY"
    echo "WARNING: could not generate the broker key with openssl." >&2
    echo "         The broker will create one at first --pair instead." >&2
  fi
fi

# ── 2c. the store key ────────────────────────────────────────────────────────
#
# What this replaces: a key DERIVED from a machine id and the account's uid. On macOS there
# is no /etc/machine-id, the read failed, and the code carried on with the literal string
# "unknown" — so every Mac running this daemon derived THE SAME store key. Anyone holding a
# copy of the ciphertext could open it without the machine.
#
# There is no macOS analogue of systemd-creds: no TPM sealing we can reach, and the System
# keychain is root-only, so a daemon that is deliberately not root cannot read it without a
# privileged unseal step — which lands on the same promise anyway, because the keychain's
# master key is on this same disk. So: a random key in a 0600 file owned by the account.
#
# NOT RECOMPUTABLE, which the derived key was. NOT SEALED, which the TPM tier is. A copy of
# this disk plus root opens it, and FileVault is what covers that. Say both.
# "Present" is not "usable". An interrupted first run can leave this file written by dd but
# not yet chowned — root-owned, so the daemon cannot read it — or short, which
# systemdCredential() ignores outright. Either way the next run would take the present
# branch, report the key as already there, and start a broker that silently falls back to
# the derived key while the install said otherwise. Check what is actually there.
STORE_KEY_OK=0
if [ -f "$STORE_KEY" ]; then
  SK_SIZE=$(stat -f '%z' "$STORE_KEY" 2>/dev/null || echo 0)
  SK_OWNER=$(stat -f '%Su' "$STORE_KEY" 2>/dev/null || echo '?')
  if [ "$SK_SIZE" -ge 32 ] && [ "$SK_OWNER" = "$ACCOUNT" ]; then
    STORE_KEY_OK=1
  else
    echo "store key: found an unusable one (${SK_SIZE} bytes, owned by ${SK_OWNER}) — replacing it"
    echo "           An interrupted earlier run leaves exactly this."
    rm -f "$STORE_KEY"
  fi
fi

if [ "$STORE_KEY_OK" = "1" ]; then
  echo "store key: already present at ${STORE_KEY}"
else
  ( umask 077 && dd if=/dev/urandom of="$STORE_KEY" bs=32 count=1 2>/dev/null ) || true
  # Unlike the broker key there is no acceptable fallback here: continuing without this
  # file means the broker silently runs on the DERIVED key while the install reports a
  # random one. Fail loudly instead.
  if [ ! -s "$STORE_KEY" ]; then
    rm -f "$STORE_KEY"
    echo "ERROR: could not write ${STORE_KEY}." >&2
    echo "       Without it the broker falls back to a key derived from this machine's" >&2
    echo "       identity and uid, which is weaker and must not be described otherwise." >&2
    exit 1
  fi
  chown "${ACCOUNT}:${ACCOUNT}" "$STORE_KEY"
  chmod 0600 "$STORE_KEY"
  SK_SIZE=$(stat -f '%z' "$STORE_KEY")
  [ "$SK_SIZE" -ge 32 ] || { echo "ERROR: ${STORE_KEY} is only ${SK_SIZE} bytes." >&2; exit 1; }
  SK_MODE=$(stat -f '%Lp' "$STORE_KEY")
  [ "$SK_MODE" = "600" ] || { echo "ERROR: ${STORE_KEY} is mode ${SK_MODE}, expected 600." >&2; exit 1; }
  echo "store key: created, 0600 ${ACCOUNT} — random, so it cannot be recomputed"
fi
echo "           It is NOT sealed to hardware: a copy of this disk plus root opens it."
if fdesetup status 2>/dev/null | grep -qi 'FileVault is On'; then
  echo "           FileVault is ON, which is what covers that case."
else
  echo "           FileVault appears to be OFF. Turn it on: a stolen disk opens this store."
fi


# ── 3. the job ───────────────────────────────────────────────────────────────
# The template is shipped alongside this script and read from disk rather than written
# inline, so what lands in /Library/LaunchDaemons is the file you reviewed in the repo.
# Only ProgramArguments is substituted: the interpreter, then the script, both full paths.
awk -v exec_path="$EXEC" -v node_path="$NODE" '
  prev ~ /<key>ProgramArguments<\/key>/ && $0 ~ /<array>/ { print; inarr = 1; prev = $0; next }
  inarr && /<string>/ {
    indent = $0; sub(/<string>.*/, "", indent)
    print indent "<string>" node_path "</string>"
    print indent "<string>" exec_path "</string>"
    inarr = 0; prev = $0; next
  }
  { print; prev = $0 }
' "$PLIST_SRC" > "$PLIST_PATH"

chown root:wheel "$PLIST_PATH"
chmod 0644 "$PLIST_PATH"

# launchd refuses a plist it considers insecure, and a job that runs as the wrong account
# is the one failure this whole script exists to prevent. Check both before loading.
grep -q "<string>${ACCOUNT}</string>" "$PLIST_PATH" || {
  echo "ERROR: the installed plist does not run as ${ACCOUNT}. Refusing to continue." >&2
  rm -f "$PLIST_PATH"; exit 1
}
grep -q "<string>${EXEC}</string>" "$PLIST_PATH" || {
  echo "ERROR: the installed plist does not point at ${EXEC}. Refusing to continue." >&2
  rm -f "$PLIST_PATH"; exit 1
}
grep -q "<string>${NODE}</string>" "$PLIST_PATH" || {
  echo "ERROR: the installed plist does not name the interpreter ${NODE}. Refusing to continue." >&2
  rm -f "$PLIST_PATH"; exit 1
}
plutil -lint "$PLIST_PATH" >/dev/null || {
  echo "ERROR: the installed plist is not valid. Refusing to continue." >&2
  rm -f "$PLIST_PATH"; exit 1
}
echo "job ${PLIST_PATH}: installed"

# ── 4. start ─────────────────────────────────────────────────────────────────
# bootout then bootstrap, not a bare bootstrap. Re-running the installer after an upgrade
# rewrote the plist must not leave the OLD process running under the OLD configuration,
# including a ProgramArguments pointing at the previous binary. `bootout` on a job that is
# not loaded is an error, so it is allowed to fail.
launchctl bootout "system/${LABEL}" 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH"
launchctl enable "system/${LABEL}"

sleep 2

# Did it actually come up, as the right account, on the right key?
#
# Ask the broker directly rather than reading a log: a log can be stale, truncated, or
# describe a previous run, and then a machine reports a clean install while running on the
# weaker key or as the wrong user.
PING='{"action":"ping"}'
SOCK="${RUN_DIR}/mgmt/agent.sock"
REPLY=""
if command -v socat >/dev/null 2>&1; then
  # -t2 bounds the wait. A wedged listener that accepts and never replies would otherwise
  # hang the installer with no output and no way to know why.
  REPLY=$(printf '%s\n' "$PING" | socat -t2 - "UNIX-CONNECT:${SOCK}" 2>/dev/null || true)
elif command -v nc >/dev/null 2>&1; then
  # The daemon ends the socket after replying, so nc exits on its own. -w is a belt for
  # the case where the socket file exists and nothing is accepting on it.
  REPLY=$(printf '%s\n' "$PING" | nc -U -w 5 "$SOCK" 2>/dev/null || true)
fi

# args=, not comm=. The broker is a JavaScript file run by Node, so `ps -o comm=` reports
# the NODE binary and never the script path — a check written against comm= silently
# matches nothing and skips the one test that decides whether there is a boundary at all.
#
# And it must not match THIS SCRIPT. The documented form is
# `sudo sh install-daemon-macos.sh --exec /usr/local/bin/wundervault-agent`, whose own argv
# contains the string being searched for — so a bare substring match finds the installer,
# running as root, and reports the broker as running as root.
RUNNING_UID=$(ps -axo pid=,user=,args= \
  | awk -v me="$$" -v parent="$PPID" -v exe="$EXEC" '
      $1 == me || $1 == parent { next }
      index($0, exe) && !/install-daemon/ && !/awk/ { print $2; exit }
    ')

# LOADED IS NOT RUNNING, and launchctl print cannot tell you the difference.
#
# A KeepAlive job whose process dies immediately — a bad ExecStart, a configuration the
# daemon refuses, a crash on start — is still a job launchd knows about, so `launchctl
# print` exits zero. An earlier version of this check ended there and printed "the broker
# is running, your agents cannot read the credentials it holds" over a machine where
# nothing was running at all. That is the single worst sentence this installer could get
# wrong, because it is the one people act on.
#
# So success requires POSITIVE evidence: the daemon answered on its socket, or a process
# owned by the service account is there. Absence of both is a failure, not a silence.
if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  if [ -z "$REPLY" ] && [ -z "$RUNNING_UID" ]; then
    echo >&2
    echo "ERROR: the job is loaded but nothing is running." >&2
    echo "       Neither the management socket nor the process table shows a broker." >&2
    echo "       This machine has NO boundary; do not migrate agents to it." >&2
    echo >&2
    tail -20 "${STATE_DIR}/agent.log" 2>/dev/null >&2 || true
    launchctl print "system/${LABEL}" 2>&1 | sed -n '1,25p' >&2 || true
    exit 1
  fi
  echo
  if [ -n "$REPLY" ]; then
    KEY_MODE=$(printf '%s' "$REPLY" | sed -n 's/.*"key_mode":"\([a-z-]*\)".*/\1/p')
    case "$KEY_MODE" in
      local-file)
        echo "The secret broker is running, on the random store key." ;;
      derived|derived-shared)
        echo "WARNING: the broker is running on a DERIVED store key, not the one this" >&2
        echo "         installer wrote. Check ${STORE_KEY} is readable by ${ACCOUNT}:" >&2
        echo "           sudo ls -l ${STORE_KEY}" >&2
        echo "           sudo tail -20 ${STATE_DIR}/agent.log" >&2
        echo "         Do not describe this machine as having a random store key." >&2 ;;
      *)
        echo "The secret broker is running. Store key mode: ${KEY_MODE:-unreported}." ;;
    esac
  else
    echo "The secret broker is loaded, but the management socket did not answer."
    echo "Neither socat nor nc could reach ${SOCK}; check it by hand:"
    echo "  sudo tail -20 ${STATE_DIR}/agent.log"
  fi

  if [ -n "$RUNNING_UID" ] && [ "$RUNNING_UID" != "$ACCOUNT" ]; then
    echo >&2
    echo "ERROR: the broker is running as '${RUNNING_UID}', not '${ACCOUNT}'." >&2
    echo "       There is no boundary in that state. Do not migrate agents to it." >&2
    exit 1
  fi

  echo
  echo "${STATE_DIR} is readable only by ${ACCOUNT}, which means your agents cannot"
  echo "read the credentials it holds."
  # One block, in order, and the last thing printed (2.0.1): the --migrate line used to come
  # after the pair line, marked "no sudo", and read as "pair without sudo".
  # The short command only when it runs the copy just installed (review rounds 1-2): an older
  # copy first on PATH, --exec, or a prefix that isn't on PATH at all would otherwise send the
  # owner to the wrong program, or to none. Quoted when the path has a space in it.
  AGENT_CMD=wundervault-agent
  _onpath=$(command -v wundervault-agent 2>/dev/null || true)
  if [ -z "$_onpath" ] || [ "$(real_path "$_onpath")" != "$(real_path "$EXEC")" ]; then
    case "$EXEC" in *" "*) AGENT_CMD="\"$EXEC\"" ;; *) AGENT_CMD="$EXEC" ;; esac
    echo
    if [ -n "$_onpath" ]; then
      echo "Note: wundervault-agent on PATH ($_onpath) is a different copy, so the steps below"
      echo "      use the full path of the one installed. Remove the other copy to use the short command."
    else
      echo "Note: wundervault-agent isn't on PATH here, so the steps below use its full path."
    fi
  fi
  echo
  echo "Next, in this order:"
  echo "  1. Pair this computer, once:   sudo ${AGENT_CMD} --pair"
  echo "     It prints a code and a fingerprint. Type the code into your vault and check the"
  echo "     fingerprint matches before you confirm. Neither value is a secret."
  echo "  2. Only if this computer ran Wundervault version 1, as your normal user (no sudo):"
  echo "       ${AGENT_CMD} --migrate"
else
  echo
  echo "The secret broker did not start. What it said:" >&2
  tail -20 "${STATE_DIR}/agent.log" 2>/dev/null >&2 || true
  launchctl print "system/${LABEL}" 2>&1 | head -20 >&2 || true
  exit 1
fi
