#!/bin/sh
# Phase 7 acceptance, run on the Mac.
#
# Everything in phase 7 except the installer itself was built and tested on Linux, through
# WUNDERVAULT_PLATFORM_SHAPE=darwin and WUNDERVAULT_LOCK_STRATEGY=port. That covers the
# paths and the lock semantics. It cannot cover dscl, launchctl, ioreg, or whether the
# account the job actually runs as is the account the plist names.
#
# This script covers those. Until it has been run and passed, phase 7 is BUILT and
# UNVERIFIED on its target platform, and the handoff says exactly that.
#
#   sh verify-macos.sh            # read-only: checks the install that is there
#   sh verify-macos.sh --full     # also exercises reinstall and uninstall (needs sudo)
#
# Read-only mode changes nothing. --full stops the broker and starts it again.

set -u

ACCOUNT=_wundervault
BASE_DIR=/var/lib/wundervault
STATE_DIR="${BASE_DIR}/state"
RUN_DIR="${BASE_DIR}/run"
LABEL=com.wundervault.agent
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FULL=0
[ "${1:-}" = "--full" ] && FULL=1

PASS=0
FAIL=0
SKIP=0
SKIPPED_REQUIRED=0
WARN=0

# A SKIPPED CHECK IS NOT A PASSED CHECK, and an exit code that says otherwise is worse
# than no script at all.
#
# The first version of this counted skips separately and then exited on FAIL alone — so
# running it without passwordless sudo and without a build skipped the store-key checks and
# the entire lock test, asserted almost nothing, and exited zero. Anyone reading that exit
# code would have concluded the machine was verified.
#
# So: skip() is for things that genuinely do not apply here. Any check the spec REQUIRES
# uses need() instead, which records that it could not be run and fails the script.
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }
skip() { SKIP=$((SKIP+1)); printf '  SKIP  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }
need() {
  SKIPPED_REQUIRED=$((SKIPPED_REQUIRED+1))
  printf '  NOT RUN  %s\n' "$1"
  [ $# -gt 1 ] && printf '           %s\n' "$2"
  return 0
}
# Something worth telling you that is not a verdict on this build.
warn() { WARN=$((WARN+1)); printf '  WARN  %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }

case "$(uname -s)" in
  Darwin) ;;
  *) echo "This script is for macOS. On Linux there is nothing here to verify." >&2; exit 1 ;;
esac

echo "Phase 7 acceptance — $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)"
echo

# ── the account (spec C1, C2) ────────────────────────────────────────────────
echo "The service account"
if dscl . -read "/Users/${ACCOUNT}" >/dev/null 2>&1; then
  ok "${ACCOUNT} exists"
  A_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
  A_SHELL=$(dscl . -read "/Users/${ACCOUNT}" UserShell 2>/dev/null | awk '{print $2}')
  case "$A_SHELL" in
    /usr/bin/false|/usr/bin/nologin|/sbin/nologin|/dev/null) ok "cannot log in (shell ${A_SHELL})" ;;
    *) bad "the account can log in" "UserShell is ${A_SHELL}; a person who becomes this account reads every credential" ;;
  esac
  if [ "$A_UID" -lt 500 ] 2>/dev/null; then
    ok "uid ${A_UID} is in the service range"
  else
    bad "uid ${A_UID} is in the login range" "a human account at this uid would dissolve the boundary"
  fi
  if [ "${SUDO_UID:-x}" = "$A_UID" ]; then
    bad "the broker account IS the invoking user" "there is no boundary between an account and itself"
  else
    ok "the broker account is not the invoking user"
  fi
  # Exactly one account, however many times the installer ran (spec check 14).
  N=$(dscl . -list /Users | grep -cx "${ACCOUNT}")
  [ "$N" = "1" ] && ok "exactly one ${ACCOUNT} account" || bad "${N} accounts named ${ACCOUNT}"
else
  bad "${ACCOUNT} does not exist" "run: sudo sh ${HERE}/install-daemon-macos.sh"
fi
echo

# ── the state directory (spec B1, check 6) ───────────────────────────────────
echo "Daemon state"
if [ -d "$STATE_DIR" ]; then
  MODE=$(stat -f '%Lp' "$STATE_DIR")
  OWNER=$(stat -f '%Su' "$STATE_DIR")
  [ "$MODE" = "700" ] && ok "${STATE_DIR} is 0700" || bad "${STATE_DIR} is ${MODE}, not 700" "the mode IS the boundary"
  [ "$OWNER" = "$ACCOUNT" ] && ok "owned by ${ACCOUNT}" || bad "owned by ${OWNER}, not ${ACCOUNT}"

  # The check that matters most, and the one only this machine can make: can the OWNER,
  # who is who the agents run as, read it? Run deliberately as the invoking user.
  if [ -n "${SUDO_USER:-}" ]; then
    if sudo -u "$SUDO_USER" test -r "$STATE_DIR" 2>/dev/null; then
      bad "the invoking user CAN read ${STATE_DIR}" "the agents run as that user; there is no boundary"
    else
      ok "the invoking user cannot read ${STATE_DIR}"
    fi
  elif [ "$(id -u)" != "0" ]; then
    if [ -r "$STATE_DIR" ]; then
      bad "this user CAN read ${STATE_DIR}" "the agents run as this user; there is no boundary"
    else
      ok "this user cannot read ${STATE_DIR}"
    fi
  else
    need "reading ${STATE_DIR} as the owner" "run without sudo, or with sudo from a user shell"
  fi

  # The runtime directory is a SIBLING of the state directory, not a child (spec B2).
  # A child would be inside a 0700 directory and no agent could traverse to its socket.
  if [ -d "$RUN_DIR" ]; then
    ok "runtime directory is ${RUN_DIR}"
    R_MODE=$(stat -f '%Lp' "$RUN_DIR")
    case "$R_MODE" in
      755|775|777) ok "run dir is ${R_MODE} — agents can reach their sockets" ;;
      *) bad "run dir is ${R_MODE}" "agents cannot traverse it; every socket connect returns EACCES" ;;
    esac
    B_MODE=$(stat -f '%Lp' "$BASE_DIR")
    case "$B_MODE" in
      755|775|777) ok "base dir is ${B_MODE} — traversable" ;;
      *) bad "base dir is ${B_MODE}" "agents cannot traverse to ${RUN_DIR}" ;;
    esac
    # The decisive one: can the OWNER actually connect? Checked as the invoking user.
    if [ -n "${SUDO_USER:-}" ] && sudo -u "$SUDO_USER" test -x "$RUN_DIR" 2>/dev/null; then
      ok "the invoking user can traverse ${RUN_DIR}"
    elif [ -n "${SUDO_USER:-}" ]; then
      bad "the invoking user CANNOT traverse ${RUN_DIR}" "its agents cannot reach their sockets"
    elif [ -x "$RUN_DIR" ]; then
      ok "this user can traverse ${RUN_DIR}"
    else
      bad "this user CANNOT traverse ${RUN_DIR}" "its agents cannot reach their sockets"
    fi
  else
    bad "no ${RUN_DIR}" "the installer creates it; the daemon cannot, ${BASE_DIR} being root-made"
  fi
  [ -e /run/wundervault ] && bad "/run/wundervault exists" "the darwin shape must not use it" \
                          || ok "/run is not used"

  # Socket path length (spec check 7). 104 is the macOS sun_path limit.
  # Built without seq, and VERIFIED to be 64 characters before it is used. The previous
  # form was `printf 'a%.0s' $(seq 1 64)`; where seq is missing that expands to nothing,
  # LONGEST becomes a short path, and the check reports PASS for having measured the wrong
  # string — the exact vacuous pass this script exists to avoid.
  NAME64=$(awk 'BEGIN { s = ""; while (length(s) < 64) s = s "a"; print s }')
  if [ "${#NAME64}" -ne 64 ]; then
    bad "could not build a 64-character name" "cannot measure the longest socket path"
    NAME64=""
  fi
  LONGEST="${RUN_DIR}/${NAME64}.sock"
  if [ -n "$NAME64" ] && [ ${#LONGEST} -le 103 ]; then
    ok "longest possible socket path is ${#LONGEST} bytes (limit 104)"
  else
    bad "longest socket path is ${#LONGEST} bytes" "over the macOS sun_path limit; long agent names will fail to bind"
  fi
else
  bad "${STATE_DIR} does not exist" "run the installer"
fi
echo

# ── the store key (spec B3, check 9) ─────────────────────────────────────────
echo "The store key"
if sudo -n true 2>/dev/null || [ "$(id -u)" = "0" ]; then
  SK="${STATE_DIR}/store.key"
  if sudo test -s "$SK"; then
    SK_MODE=$(sudo stat -f '%Lp' "$SK")
    SK_SIZE=$(sudo stat -f '%z' "$SK")
    [ "$SK_MODE" = "600" ] && ok "store.key is 0600" || bad "store.key is ${SK_MODE}, not 600"
    [ "$SK_SIZE" -ge 32 ] && ok "store.key is ${SK_SIZE} bytes" || bad "store.key is only ${SK_SIZE} bytes"
  else
    bad "no store.key" "the broker is running on a derived key; the installer writes this one"
  fi
else
  need "store.key mode and size (spec check 9)" "needs sudo — re-run with sudo"
fi

# The hardware UUID is what the derived fallback uses if the store key is ever missing.
# Before phase 7 this was the string "unknown" on every Mac.
UUID=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | sed -n 's/.*"IOPlatformUUID" = "\([^"]*\)".*/\1/p')
if [ -n "$UUID" ]; then
  ok "IOPlatformUUID is readable (${UUID})"
else
  bad "cannot read IOPlatformUUID" "the derived fallback would have no machine identity here"
fi

if fdesetup status 2>/dev/null | grep -qi 'FileVault is On'; then
  ok "FileVault is on — a stolen disk does not open the store"
else
  # NOT a failure of this build. The store key is honestly described as unsealed, and
  # FileVault is the owner's setting — failing the whole verification over it would train
  # people to ignore a red result.
  warn "FileVault is off" "the store key is not sealed to hardware, so a copy of this disk plus root opens the store. FileVault is what covers that."
fi
echo

# ── the job (spec C3, C4) ────────────────────────────────────────────────────
echo "The LaunchDaemon"
if [ -f "$PLIST_PATH" ]; then
  ok "${PLIST_PATH} installed"
  P_MODE=$(stat -f '%Lp' "$PLIST_PATH")
  P_OWNER=$(stat -f '%Su' "$PLIST_PATH")
  [ "$P_MODE" = "644" ] && ok "plist is 0644" || bad "plist is ${P_MODE}" "launchd refuses a writable plist"
  [ "$P_OWNER" = "root" ] && ok "plist owned by root" || bad "plist owned by ${P_OWNER}"
  plutil -lint "$PLIST_PATH" >/dev/null 2>&1 && ok "plist is valid" || bad "plist is not valid XML"
  grep -q "<string>${ACCOUNT}</string>" "$PLIST_PATH" && ok "plist names ${ACCOUNT}" \
    || bad "plist does not name ${ACCOUNT}" "the job would run as root or as you"
else
  bad "no ${PLIST_PATH}"
fi

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  ok "job is bootstrapped"
  # The decisive one. A plist that NAMES the account and a process RUNNING as it are two
  # different facts, and only the second is the boundary.
  RUNNING_AS=$(ps -axo user=,args= | awk '/wundervault-agent/ && !/awk/ {print $1; exit}')
  if [ -n "$RUNNING_AS" ]; then
    [ "$RUNNING_AS" = "$ACCOUNT" ] && ok "the broker process runs as ${ACCOUNT}" \
      || bad "the broker runs as ${RUNNING_AS}, not ${ACCOUNT}" "there is no boundary in this state"
  else
    bad "no broker process found" "the job is loaded but nothing is running"
  fi
else
  bad "job is not bootstrapped" "sudo launchctl bootstrap system ${PLIST_PATH}"
fi

# key_mode straight from the daemon, not from a log (spec C4).
SOCK="${RUN_DIR}/mgmt/agent.sock"
REPLY=""
if command -v nc >/dev/null 2>&1; then
  # -w bounds the wait: a wedged listener that accepts and never replies would otherwise
  # hang the verifier with no output.
  REPLY=$(printf '{"action":"ping"}\n' | sudo nc -U -w 5 "$SOCK" 2>/dev/null)
fi
if [ -n "$REPLY" ]; then
  KM=$(printf '%s' "$REPLY" | sed -n 's/.*"key_mode":"\([a-z-]*\)".*/\1/p')
  case "$KM" in
    local-file) ok "daemon reports key_mode=local-file" ;;
    derived|derived-shared) bad "daemon reports key_mode=${KM}" "it is NOT using the key the installer wrote" ;;
    *) bad "daemon reported key_mode=${KM:-nothing}" ;;
  esac
else
  need "key_mode from the daemon (spec check 9)" "could not reach ${SOCK} with nc"
fi
echo

# ── the lock, on the real platform (spec checks 17-20) ───────────────────────
echo "The single-instance lock, on this machine"
if command -v node >/dev/null 2>&1 && [ -d "${HERE}/../dist" ]; then
  # --input-type=module with import(), not require(). The package is "type": "module", so
  # require("../dist/lock.js") throws ERR_REQUIRE_ESM — which would have looked like the
  # lock failing rather than the harness being wrong.
  # --input-type=module with import(), not require(). The package is "type": "module", so
  # require("../dist/lock.js") throws ERR_REQUIRE_ESM — which would have looked like the
  # lock failing rather than the harness being wrong. This exact script was run against a
  # real build on Linux before being put here, because a verification script that cannot
  # itself run reports nothing and looks like a pass.
  node --input-type=module -e '
    const lock = await import("'"${HERE}"'/../dist/lock.js");
    process.env.WUNDERVAULT_AGENT_NAME = "VerifyMacOS_" + process.pid;
    const first = await lock.acquireCredential("verify");
    if (!first.ok) { console.log("FAIL first claim refused: " + (first.reason || "")); process.exit(1); }
    const second = await lock.acquireCredential("verify");
    if (second.ok) { console.log("FAIL second claim SUCCEEDED — two holders of one credential"); process.exit(1); }
    if (!second.holder || second.holder.source !== "holder") {
      console.log("FAIL second claim refused but the holder was not identified: " + JSON.stringify(second.holder));
      process.exit(1);
    }
    const port = lock._addressPortForTests();
    if (port < 20000 || port > 32767) { console.log("FAIL derived port " + port + " is in the ephemeral range"); process.exit(1); }
    if (lock.lockStrategy() !== "port") { console.log("FAIL strategy is " + lock.lockStrategy() + ", expected port on macOS"); process.exit(1); }
    await lock.releaseCredential();

    // whoHolds() with nobody holding must fall back to the lock file, not find some other
    // occupant. This is one of the two assertions macOS CI used to fail.
    const net = await import("node:net");
    const nobody = await lock.whoHolds();
    if (nobody.source === "holder") { console.log("FAIL whoHolds found a holder when none is running"); process.exit(1); }

    // A stranger on the address must be a REFUSAL naming the port, never a silent move to
    // a different one — which is what allowed two holders of one credential.
    const squatter = net.createServer(() => {});
    await new Promise((r, j) => { squatter.once("error", j); squatter.listen({host: "127.0.0.1", port}, r); });
    const blocked = await lock.acquireCredential("verify");
    await new Promise((r) => squatter.close(r));
    if (blocked.ok) { console.log("FAIL claimed the credential while a stranger held the address"); process.exit(1); }
    if (!String(blocked.reason || "").includes(String(port))) {
      console.log("FAIL refusal did not name the port: " + blocked.reason); process.exit(1);
    }

    // The override has to actually move the address, or an operator cannot resolve a
    // collision or a port conflict at all.
    process.env.WUNDERVAULT_LOCK_PORT = String(port === 32767 ? 20001 : port + 1);
    const moved = await lock.acquireCredential("verify");
    if (!moved.ok) { console.log("FAIL WUNDERVAULT_LOCK_PORT did not move the address: " + moved.reason); process.exit(1); }
    if (lock.addressDescription() !== "127.0.0.1:" + process.env.WUNDERVAULT_LOCK_PORT) {
      console.log("FAIL address is " + lock.addressDescription()); process.exit(1);
    }
    await lock.releaseCredential();

    console.log("OK port=" + port);
  ' > /tmp/wv-lock-verify.$$ 2>&1
  if grep -q '^OK' /tmp/wv-lock-verify.$$; then
    ok "a second claim is refused and names the holder ($(sed -n 's/^OK //p' /tmp/wv-lock-verify.$$))"
  else
    bad "the lock did not behave" "$(cat /tmp/wv-lock-verify.$$)"
  fi
  rm -f /tmp/wv-lock-verify.$$
else
  need "the lock on this machine (spec checks 17-20)" "build first: npm run build"
fi
echo

# ── reinstall and uninstall (spec checks 12, 13, 14) ─────────────────────────
if [ "$FULL" = "1" ]; then
  echo "Reinstall and uninstall"
  if [ "$(id -u)" != "0" ]; then
    need "--full reinstall and uninstall checks (spec checks 12-14)" "re-run with sudo"
  else
    # Reinstall with the path the INSTALLED plist names, not with whatever happens to be
    # on root's PATH. An install done with --exec /opt/... would otherwise fail here, and
    # the script would carry on to uninstall and leave the machine with no broker at all.
    INSTALLED_EXEC=$(sed -n 's/.*<string>\(\/[^<]*wundervault-agent\)<\/string>.*/\1/p' "$PLIST_PATH" | head -1)
    if [ -z "$INSTALLED_EXEC" ] || [ ! -x "$INSTALLED_EXEC" ]; then
      bad "cannot determine the installed broker path from ${PLIST_PATH}" \
          "skipping the reinstall checks would leave this machine half-tested; fix the plist first"
      FULL=0
    fi

    BEFORE_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
    sh "${HERE}/install-daemon-macos.sh" --exec "$INSTALLED_EXEC" >/tmp/wv-reinstall.$$ 2>&1
    if [ $? -eq 0 ]; then ok "re-running the installer succeeds"; else bad "re-running the installer failed" "$(tail -5 /tmp/wv-reinstall.$$)"; fi
    AFTER_UID=$(dscl . -read "/Users/${ACCOUNT}" UniqueID 2>/dev/null | awk '{print $2}')
    [ "$BEFORE_UID" = "$AFTER_UID" ] && ok "the account uid did not move (${AFTER_UID})" \
      || bad "the uid changed from ${BEFORE_UID} to ${AFTER_UID}" "every file it owns is now orphaned"
    N=$(dscl . -list /Users | grep -cx "${ACCOUNT}")
    [ "$N" = "1" ] && ok "still exactly one account" || bad "${N} accounts after reinstall"
    rm -f /tmp/wv-reinstall.$$

    sh "${HERE}/install-daemon-macos.sh" --uninstall >/dev/null 2>&1
    [ -f "$PLIST_PATH" ] && bad "uninstall left the plist" || ok "uninstall removed the job"
    [ -d "$STATE_DIR" ] && ok "uninstall LEFT the credentials (${STATE_DIR})" \
      || bad "uninstall destroyed ${STATE_DIR}" "--uninstall must never be a way to lose the vault"
    dscl . -read "/Users/${ACCOUNT}" >/dev/null 2>&1 && ok "uninstall left the account" \
      || bad "uninstall deleted the account" "every file it owned is now orphaned"

    if sh "${HERE}/install-daemon-macos.sh" --exec "$INSTALLED_EXEC" >/tmp/wv-reinstall2.$$ 2>&1; then
      ok "reinstalled after uninstall"
    else
      bad "could not reinstall after uninstall — THIS MACHINE NOW HAS NO BROKER" \
          "$(tail -5 /tmp/wv-reinstall2.$$)"
    fi
    rm -f /tmp/wv-reinstall2.$$
  fi
  echo
fi

echo "─────────────────────────────────────────"
printf '%d passed, %d failed, %d warnings, %d not applicable\n' "$PASS" "$FAIL" "$WARN" "$SKIP"
if [ "$SKIPPED_REQUIRED" != "0" ]; then
  printf '%d REQUIRED check(s) could not be run.\n' "$SKIPPED_REQUIRED"
  echo "This machine is NOT verified. A check that did not run has not passed."
fi
if [ "$FAIL" != "0" ] || [ "$SKIPPED_REQUIRED" != "0" ]; then
  echo
  echo "Phase 7 is NOT verified on this machine."
  exit 1
fi
echo
echo "Phase 7 verified on this machine."

