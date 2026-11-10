#!/bin/sh
# Wundervault guided setup for a Linux server (site SPEC-admin-access §5a, D13, D14, D15).
#
# Run by the helper app over SSH as root (sudo sh -s -- STEP ARGS < this file), inside an
# admin access the owner approved. Fixed script: every input is checked against a strict
# pattern before use and never evaluated. Idempotent: running a step again is safe.
#
#   prepare ADMIN_USER EVERYDAY_USER ADMIN_CA_PUB EVERYDAY_PUB EMERGENCY_PUB [logs]
#       Everyday account (no sudo/wheel/docker/adm), its key, the admin home locked (700),
#       the session check and change check installed, the admin key trusted AS A CERTIFICATE
#       AUTHORITY next to (not instead of) whatever already works, the emergency key added,
#       the change-check baseline recorded. Nothing that works today is removed.
#   finalize ADMIN_USER ADMIN_CA_PUB
#       Only after the helper proved a certificate login: the admin key's plain (always-on)
#       line is removed, so it works only inside admin access. Other keys are left alone and
#       reported. The baseline is recorded again.
#   status ADMIN_USER EVERYDAY_USER
#       Read-only self-test lines (PASS/FAIL ...).
#   remove-key USER FINGERPRINT
#       D14 "Remove": take out exactly the authorized_keys line of USER whose change-check
#       fingerprint (first 16 hex of its sha256) is FINGERPRINT. Never the certificate-authority
#       line or the emergency key (that would lock the owner out). The baseline is NOT recorded
#       again, so any other change still shows on the next check.
#   accept
#       D14 "Accept as normal": record the baseline again.
set -eu
umask 077
LIB=/usr/local/lib/wundervault
STATE=/var/lib/wundervault

die() { echo "FAIL $*"; exit 2; }
ok() { echo "PASS $*"; }
[ "$(id -u)" = 0 ] || die "setup must run as root (sudo)"
[ "$(uname -s)" = Linux ] || die "guided setup supports Linux servers only"

user_ok() { printf '%s' "$1" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$'; }
key_ok() { printf '%s' "$1" | grep -Eq '^ssh-ed25519 [A-Za-z0-9+/]{68}$'; }
home_of() { getent passwd "$1" | cut -d: -f6; }

step=${1:-}; shift || true

# The two server-side programs are embedded below, so the helper sends one fixed file.
install_programs() {
  install -d -o root -g root -m 755 "$LIB"
  install -d -o root -g root -m 700 "$STATE"
  cat > "$LIB/wv-admin-session.new" <<'WVSESSION'
#!/bin/sh
# Wundervault admin access: the server's half of the cut-off (SPEC-admin-access D13).
#
# Admin sign-ins use a short-lived SSH certificate signed by the helper app. The certificate
# carries "force-command=/usr/local/lib/wundervault/wv-admin-session <end> [<tag>]", where <end>
# is when the owner's admin access ends (Unix seconds) and <tag> names the helper's signing
# session. The signature covers both, so the agent cannot change them. sshd itself refuses the
# certificate after its valid-before; this script ends the session that is already open at the
# same moment, including one the agent opened with its own ssh client and multiplexed sessions
# started later on that connection.
#
# "end-now <tag>" (whole-build review F1): when the owner ends admin access EARLY (End now, done,
# a revoke), the helper signs one last certificate whose forced command is this mode, and every
# session opened under that tag is ended now instead of at <end>.
#
# Fails closed: if this file is missing or broken, the forced command fails and the admin
# session does not start; if its timer cannot start, the session does not start either.
# The everyday account and the emergency key do not pass through here.
set -u
tag_ok() { case ${1:-} in ''|*[!0-9a-f]*) return 1;; esac; [ ${#1} -le 32 ]; }

if [ "${1:-}" = end-now ]; then
  tag_ok "${2:-}" || { echo "wundervault: no session to end." >&2; exit 2; }
  # The timers of that tag end their sessions on this signal (same account, so allowed).
  pkill -USR1 -f "wv-cutoff-$2 " 2>/dev/null
  echo "ended"
  exit 0
fi

end=${1:-}
case $end in ''|*[!0-9]*) echo "wundervault: admin access has no valid end time; refused." >&2; exit 126;; esac
tag=${2:-none}
tag_ok "$tag" || tag=none
now=$(date +%s)
left=$((end - now))
if [ "$left" -le 0 ]; then
  echo "wundervault: admin access has ended; ask your owner to allow it again." >&2
  exit 126
fi
# sshd made this process the leader of a new session (setsid) for this channel. At the end
# time, kill every process still in that session: the command, an interactive shell and
# whatever they started without detaching. Detached daemons are outside it (spec §6 limits;
# the change check reports new services and scheduled jobs). macOS has no session ids in ps:
# there the timer kills this process and everything descended from it instead.
sid=$(ps -o sid= -p $$ 2>/dev/null | tr -d ' ')
case $sid in ''|*[!0-9]*) sid=;; esac
f=
if [ -n "$sid" ]; then
  # Made HERE, not in the timer: a full or read-only /tmp refuses the session instead of
  # leaving it without a cut-off (whole-build review F3).
  f=$(mktemp 2>/dev/null) || { echo "wundervault: the admin session check could not start; refused." >&2; exit 126; }
fi
# The timer is its own small process. It stops early once nothing else is left in this
# session, so a finished command leaves nothing behind; at the end time (or on end-now) it
# kills the rest.
# shellcheck disable=SC2016
sh -c '
  end=$1; sid=$2; root=$3; f=$4
  [ -n "$f" ] && trap "rm -f \"$f\"" EXIT
  kill_all() {
    if [ -n "$sid" ]; then pkill -KILL -s "$sid"; return; fi
    set -- "$root"; all=$(ps -A -o pid= -o ppid=); grew=1
    while [ "$grew" = 1 ]; do
      grew=0
      for p in $(printf "%s\n" "$all" | awk -v s=" $* " "index(s, \" \" \$2 \" \") && !index(s, \" \" \$1 \" \") {print \$1}"); do
        set -- "$@" "$p"; grew=1
      done
    done
    for p in "$@"; do [ "$p" = "$$" ] || kill -KILL "$p" 2>/dev/null; done
  }
  trap "kill_all; exit 0" USR1
  while [ "$(date +%s)" -lt "$end" ]; do
    if [ -n "$sid" ]; then
      # A failed write (a full disk) is not "empty": keep watching and cut off at the end.
      if pgrep -s "$sid" > "$f" 2>/dev/null && [ -s "$f" ]; then grep -qvx "$$" "$f" || exit 0; fi
    else
      kill -0 "$root" 2>/dev/null || exit 0
    fi
    sleep 1
  done
  kill_all
' "wv-cutoff-$tag " "$end" "$sid" "$$" "$f" </dev/null >/dev/null 2>&1 &
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  exec "${SHELL:-/bin/sh}" -c "$SSH_ORIGINAL_COMMAND"
fi
exec "${SHELL:-/bin/sh}" -l
WVSESSION
  cat > "$LIB/wv-check.new" <<'WVCHECK'
#!/bin/sh
# Wundervault change check (site SPEC-admin-access D14). Root-owned, installed by setup.
#
#   wv-check baseline   record the server as it is now (root only; setup and finalize run it)
#   wv-check report     what is NEW or GONE since the baseline (the everyday account may run
#                       this through sudo, and nothing else; it never prints a key or a secret,
#                       only short fingerprints, names and comments)
#   wv-check health     up time, load, disk and memory (everyday account, through sudo)
#
# Honest limit: whoever has root can change this program and its baseline too. It catches
# mistakes and careless agents, not a determined one.
set -eu
umask 077
STATE=/var/lib/wundervault
LIB=/usr/local/lib/wundervault

fp() { sha256sum | cut -c1-16; }
fp_file() { [ -f "$1" ] && sha256sum "$1" | cut -c1-16 || echo none; }

snapshot() {
  # Every account that can hold SSH keys: a fingerprint and comment per authorized key line.
  getent passwd | while IFS=: read -r name _ uid _ _ home _; do
    f="$home/.ssh/authorized_keys"
    [ -f "$f" ] || continue
    grep -Ev '^[[:space:]]*(#|$)' "$f" 2>/dev/null | while IFS= read -r line; do
      comment=$(printf '%s' "$line" | awk '{print $NF}' | tr -cd 'A-Za-z0-9@._:-' | cut -c1-60)
      printf 'key\t%s\t%s\t%s\n' "$name" "$(printf '%s' "$line" | fp)" "$comment"
    done
  done
  # uid and primary group too (whole-build review F4): an account moved to uid 0, or to a
  # privileged primary group, keeps its name and shell. Any account at uid 0 is listed.
  getent passwd | awk -F: '$3 >= 1000 || $3 == 0 { print "account\t" $1 "\t" $3 ":" $4 "\t" $7 }'
  for g in sudo wheel docker adm root; do
    members=$(getent group "$g" | cut -d: -f4)
    [ -n "$members" ] && printf '%s\n' "$members" | tr ',' '\n' | sed "s/^/group\t$g\t/"
  done
  for f in /etc/passwd /etc/group /etc/sudoers /etc/sudoers.d/* /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/crontab /etc/cron.d/* \
           /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] && printf 'file\t%s\t%s\n' "$f" "$(fp_file "$f")"
  done
  for d in /etc/systemd/system; do
    [ -d "$d" ] && find "$d" -maxdepth 2 \( -name '*.service' -o -name '*.timer' \) -type f 2>/dev/null |
      while read -r f; do printf 'unit\t%s\t%s\n' "$f" "$(fp_file "$f")"; done
  done
  for f in "$LIB/wv-admin-session" "$LIB/wv-check"; do printf 'program\t%s\t%s\n' "$f" "$(fp_file "$f")"; done
  admin=$(cat "$STATE/admin_user" 2>/dev/null || true)
  if [ -n "$admin" ]; then
    # Programs the admin account left running on their own (parent is init: a daemon or an
    # orphan). Names only; a new one shows as NEW after admin access.
    # On systemd servers orphans are adopted by the user's own "systemd --user", not PID 1.
    ps -e -o pid=,comm= 2>/dev/null > "$STATE/.ps.$$" || true
    ps -u "$admin" -o ppid=,comm= 2>/dev/null | awk -v psf="$STATE/.ps.$$" '
      BEGIN { while ((getline l < psf) > 0) { split(l, a, " "); name[a[1]] = a[2] } }
      $1 == 1 || name[$1] == "systemd" { print $2 }' | sort -u | sed "s/^/process\t$admin\t/"
    rm -f "$STATE/.ps.$$"
  fi
}

case ${1:-} in
baseline)
  [ "$(id -u)" = 0 ] || { echo "baseline needs root" >&2; exit 2; }
  install -d -o root -g root -m 700 "$STATE"
  snapshot | sort -u > "$STATE/baseline.new"
  mv -f "$STATE/baseline.new" "$STATE/baseline"
  echo "baseline recorded ($(wc -l < "$STATE/baseline") items)"
  ;;
report)
  [ -f "$STATE/baseline" ] || { echo "NO-BASELINE run setup again"; exit 0; }
  now=$(mktemp); trap 'rm -f "$now"' EXIT
  snapshot | sort -u > "$now"
  comm -13 "$STATE/baseline" "$now" | sed 's/^/NEW\t/'
  comm -23 "$STATE/baseline" "$now" | grep -v '^process' | sed 's/^/GONE\t/' || true
  echo "END"
  ;;
health)
  printf 'uptime\t%s\n' "$(cut -d' ' -f1 /proc/uptime)"
  printf 'load\t%s\n' "$(cut -d' ' -f1-3 /proc/loadavg)"
  df -P / | awk 'NR == 2 { print "disk\t" $5 }'
  awk '/MemTotal/ { t = $2 } /MemAvailable/ { a = $2 } END { printf "memory\t%d%%\n", (t - a) * 100 / t }' /proc/meminfo
  ;;
*) echo "usage: wv-check baseline | report | health" >&2; exit 2;;
esac
WVCHECK
  for f in wv-admin-session wv-check; do
    chown root:root "$LIB/$f.new"; chmod 755 "$LIB/$f.new"; mv -f "$LIB/$f.new" "$LIB/$f"
  done
}

# Replace or add one exact line in a root-written copy, then move it into place.
ak_file() { echo "$(home_of "$1")/.ssh/authorized_keys"; }
ak_has() { [ -f "$1" ] && grep -Fqx -- "$2" "$1"; }
ak_add() {
  file=$1; line=$2; owner=$3
  dir=$(dirname "$file"); install -d -o "$owner" -g "$(id -gn "$owner")" -m 700 "$dir"
  ak_has "$file" "$line" && return 0
  tmp=$(mktemp "$dir/.wv-ak.XXXXXX")
  [ -f "$file" ] && cat "$file" > "$tmp"
  [ -s "$tmp" ] && [ -n "$(tail -c1 "$tmp")" ] && echo >> "$tmp"
  printf '%s\n' "$line" >> "$tmp"
  chown "$owner":"$(id -gn "$owner")" "$tmp"; chmod 600 "$tmp"; mv -f "$tmp" "$file"
}

case $step in
prepare)
  admin=${1:-}; everyday=${2:-}; ca=${3:-}; daily=${4:-}; emergency=${5:-}; logs=${6:-}
  user_ok "$admin" || die "admin account name"
  user_ok "$everyday" || die "everyday account name"
  [ "$admin" != "$everyday" ] || die "the everyday account must be a different account"
  key_ok "$ca" && key_ok "$daily" && key_ok "$emergency" || die "keys must be single ed25519 public keys"
  getent passwd "$admin" >/dev/null || die "admin account $admin does not exist"
  ahome=$(home_of "$admin"); [ -d "$ahome" ] || die "admin home missing"

  # 1. The everyday account: no sudo, no admin groups.
  if ! getent passwd "$everyday" >/dev/null; then
    useradd -m -s /bin/bash -c "Wundervault everyday access" "$everyday"
  fi
  for g in sudo wheel docker adm root lxd libvirt; do
    if id -nG "$everyday" | tr ' ' '\n' | grep -qx "$g"; then die "$everyday is in group $g; remove it and run setup again"; fi
  done
  if [ -n "$logs" ] && getent group systemd-journal >/dev/null; then usermod -aG systemd-journal "$everyday"; fi
  ak_add "$(ak_file "$everyday")" "$daily wundervault-everyday" "$everyday"

  # 2. Lock the admin account's home so the everyday account cannot read .env, data or keys.
  chmod 700 "$ahome"

  # 3. Programs, then trust the admin key as a certificate authority for principal wv-admin.
  install_programs
  ak_add "$(ak_file "$admin")" "cert-authority,principals=\"wv-admin\" $ca wundervault-admin-ca" "$admin"
  # 4. The emergency key: a plain key, never given to an agent, outside the session check.
  ak_add "$(ak_file "$admin")" "$emergency wundervault-emergency" "$admin"

  # 5. The everyday account may run exactly two read-only checks as root.
  printf '%s ALL=(root) NOPASSWD: %s/wv-check report, %s/wv-check health\n' "$everyday" "$LIB" "$LIB" > /etc/sudoers.d/.wv-new
  chmod 440 /etc/sudoers.d/.wv-new
  visudo -cf /etc/sudoers.d/.wv-new >/dev/null || { rm -f /etc/sudoers.d/.wv-new; die "sudoers rule did not validate"; }
  mv -f /etc/sudoers.d/.wv-new /etc/sudoers.d/wundervault

  printf '%s\n' "$admin" > "$STATE/admin_user"
  "$LIB/wv-check" baseline >/dev/null
  ok "prepared (nothing that worked before was removed)"
  ;;
finalize)
  admin=${1:-}; ca=${2:-}
  user_ok "$admin" && key_ok "$ca" || die "arguments"
  file=$(ak_file "$admin"); [ -f "$file" ] || die "no authorized_keys for $admin"
  grep -Fq "cert-authority,principals=\"wv-admin\" $ca" "$file" || die "run prepare first"
  grep -Fq "wundervault-emergency" "$file" || die "the emergency key is missing; refusing to finalize"
  blob=$(printf '%s' "$ca" | cut -d' ' -f2)
  tmp=$(mktemp "$(dirname "$file")/.wv-ak.XXXXXX")
  # Drop only lines that use the admin key PLAINLY (any options), keep everything else.
  awk -v blob="$blob" '{ plain = 0; for (i = 1; i <= NF; i++) if ($i == blob) { plain = ($0 !~ /^cert-authority/) } if (!plain) print }' "$file" > "$tmp"
  chown "$admin":"$(id -gn "$admin")" "$tmp"; chmod 600 "$tmp"; mv -f "$tmp" "$file"
  others=$(grep -Ev 'wundervault-admin-ca|wundervault-emergency|^[[:space:]]*(#|$)' "$file" | wc -l | tr -d ' ')
  "$LIB/wv-check" baseline >/dev/null
  ok "finalized: the admin key now works only inside admin access"
  [ "$others" = 0 ] || echo "NOTE $others other key(s) can still sign in to $admin; review them on the Server card"
  ;;
status)
  admin=${1:-}; everyday=${2:-}
  user_ok "$admin" && user_ok "$everyday" || die "arguments"
  [ "$(stat -c %a "$(home_of "$admin")")" = 700 ] && ok "admin home is locked (700)" || echo "FAIL admin home is not 700"
  if id -nG "$everyday" | tr ' ' '\n' | grep -Eqx 'sudo|wheel|docker|adm|root'; then echo "FAIL $everyday is in an admin group"; else ok "$everyday has no admin groups"; fi
  [ -x "$LIB/wv-admin-session" ] && ok "session check installed" || echo "FAIL session check missing"
  ak=$(ak_file "$admin")
  grep -q 'cert-authority,principals="wv-admin"' "$ak" && ok "admin key trusted as certificate authority only" || echo "FAIL no certificate trust"
  grep -q wundervault-emergency "$ak" && ok "emergency key installed" || echo "FAIL emergency key missing"
  ;;
remove-key)
  user=${1:-}; want=${2:-}
  user_ok "$user" || die "account name"
  printf '%s' "$want" | grep -Eq '^[0-9a-f]{16}$' || die "fingerprint"
  getent passwd "$user" >/dev/null || die "no such account"
  file=$(ak_file "$user"); [ -f "$file" ] || die "no authorized_keys for that account"
  tmp=$(mktemp "$(dirname "$file")/.wv-ak.XXXXXX")
  found=0; kept=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$(printf '%s' "$line" | sha256sum | cut -c1-16)" = "$want" ]; then
      case $line in
        *wundervault-admin-ca*|*wundervault-emergency*) rm -f "$tmp"; die "that is the admin certificate or emergency key line; refusing";;
      esac
      found=$((found + 1)); continue
    fi
    printf '%s\n' "$line" >> "$tmp"; kept=$((kept + 1))
  done < "$file"
  [ "$found" -gt 0 ] || { rm -f "$tmp"; die "no key with that fingerprint (already removed?)"; }
  chown "$user":"$(id -gn "$user")" "$tmp"; chmod 600 "$tmp"; mv -f "$tmp" "$file"
  ok "removed $found key line(s) from $user"
  ;;
accept)
  [ -x "$LIB/wv-check" ] || die "change check not installed; run setup first"
  "$LIB/wv-check" baseline >/dev/null
  ok "the server as it is now is the new normal"
  ;;
*) die "unknown step (prepare | finalize | status | remove-key | accept)";;
esac
