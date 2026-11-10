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

# Every folder above the programs must be root's and closed to others, or a non-root user could
# swap the folder out and have root run their copy (whole-build review r2 F2).
safe_ancestors() {
  _d=$1; _want=${2:-0}
  while :; do
    if [ -e "$_d" ] || [ -L "$_d" ]; then
      [ -L "$_d" ] && return 1
      _m=$(ls -ldn "$_d" | awk '{print $1}'); _o=$(ls -ldn "$_d" | awk '{print $3}')
      [ "$_o" = 0 ] || [ "$_o" = "$_want" ] || return 1
      # Writable by others only with the sticky bit (like /tmp): then no one else can rename
      # what is inside it.
      case $_m in ?????????[tT]*) ;; ?????w*|????????w*) return 1;; esac
    fi
    [ "$_d" = / ] && return 0
    _d=$(dirname "$_d")
  done
}
# The two server-side programs are embedded below, so the helper sends one fixed file.
install_programs() {
  safe_ancestors "$(dirname "$LIB")" || die "a folder above $LIB can be changed by someone other than root; refusing"
  install -d -o root -g root -m 755 "$LIB"
  install -d -o root -g root -m 700 "$STATE"
  cat > "$LIB/wv-admin-session.new" <<'WVSESSION'
@@WV_ADMIN_SESSION@@
WVSESSION
  cat > "$LIB/wv-check.new" <<'WVCHECK'
@@WV_CHECK@@
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
