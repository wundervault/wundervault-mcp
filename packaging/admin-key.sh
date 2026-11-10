#!/bin/sh
set -eu

umask 077
LC_ALL=C
export LC_ALL

usage() {
    cat <<'EOF'
Usage: sudo sh admin-key.sh --public 'ssh-ed25519 AAAA...' [--from ADDR[,ADDR...]] [--skip-checks]
       sudo sh admin-key.sh --remove
       sudo sh admin-key.sh --list
       sudo sh admin-key.sh --help

Add an admin key so your broker can run admin commands without your password.
Make the key in your vault first (Add a key > "Let agents do admin (sudo) work on a
computer?" > Make this computer's admin key): the vault keeps the private half and shows
this command with the public half filled in. Nothing secret is printed here. By default,
the key works only from this computer, and only while you allow admin access: sign-ins
use a short-lived certificate from the helper app, and the session ends when it does.

  --public KEY          The public key the vault showed (one ssh-ed25519 key).
  --from ADDR[,ADDR...]  Allow connections from these addresses instead.
  --remove              Remove all admin keys created by this script.
  --list                Show existing admin keys without showing their key material.
  --skip-checks         Add the key even if this computer's SSH settings cannot be checked.
  --help                Show these instructions.

With --from, give the address the broker's computer is seen from by this one
(behind a VPN or a router it may differ from the address it has at home).
EOF
}

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

mode=add
from=127.0.0.1,::1
public_key=
skip_checks=0

while [ $# -gt 0 ]; do
    case "$1" in
        --remove) mode=remove ;;
        --list) mode=list ;;
        --skip-checks) skip_checks=1 ;;
        --public)
            [ $# -ge 2 ] || { usage >&2; exit 1; }
            public_key=$2
            shift
            ;;
        --from)
            [ $# -ge 2 ] || { usage >&2; exit 1; }
            from=$2
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
    shift
done

system=$(uname -s)
case "$system" in
    Linux)
        default_ssh_dir=/root/.ssh
        root_group=root
        ;;
    Darwin)
        default_ssh_dir=/var/root/.ssh
        root_group=wheel
        ;;
    *)
        fail "This script supports Linux and macOS."
        ;;
esac

overridden=0
if [ "${WV_ADMIN_ROOT_SSH_DIR+x}" = x ]; then
    overridden=1
    ssh_dir=$WV_ADMIN_ROOT_SSH_DIR
    [ -n "$ssh_dir" ] || fail "Choose a separate folder for the test admin keys."
else
    [ "$(id -u)" = 0 ] || fail "Run this with sudo: sudo sh admin-key.sh"
    ssh_dir=$default_ssh_dir
fi

# A trailing slash must not hide a link to another folder.
while [ "$ssh_dir" != / ] && [ "${ssh_dir%/}" != "$ssh_dir" ]; do
    ssh_dir=${ssh_dir%/}
done
[ "$ssh_dir" != / ] || fail "Choose a separate folder for the admin keys."

case "$ssh_dir" in
    /*) ;;
    *) ssh_dir=$PWD/$ssh_dir ;;
esac

keys_file=$ssh_dir/authorized_keys
# The server half of the admin-access cut-off (same file guided setup installs on servers).
session_src=$(cd "$(dirname "$0")" && pwd)/server/wv-admin-session
lib_dir=${WV_ADMIN_LIB_DIR:-/usr/local/lib/wundervault}

remaining=$from
while :; do
    address=${remaining%%,*}
    case "$address" in
        ''|*[!a-zA-Z0-9.:-]*)
            fail "Use a comma-separated list of addresses or computer names, without spaces."
            ;;
    esac
    if [ "${#address}" -gt 253 ]; then
        fail "Each address or computer name must be at most 253 characters long."
    fi
    case "$remaining" in
        *,*) remaining=${remaining#*,} ;;
        *) break ;;
    esac
done

key_tmp=
write_tmp=
session_tmp=
lock_dir=

cleanup() {
    if [ -n "$session_tmp" ]; then
        rm -f -- "$session_tmp"
    fi
    if [ -n "$write_tmp" ]; then
        rm -f -- "$write_tmp"
    fi
    if [ -n "$lock_dir" ]; then
        rmdir -- "$lock_dir" 2>/dev/null || :
    fi
    if [ -n "$key_tmp" ]; then
        rm -rf -- "$key_tmp"
    fi
}

trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

check_paths() {
    if [ -L "$ssh_dir" ]; then
        fail "The admin key folder is a link to another folder. No changes were made."
    fi
    if [ -L "$keys_file" ]; then
        fail "The admin key file is a link to another file. No changes were made."
    fi
    if [ -e "$ssh_dir" ] && [ ! -d "$ssh_dir" ]; then
        fail "The admin key folder is not a folder. No changes were made."
    fi
    if [ -e "$keys_file" ] && [ ! -f "$keys_file" ]; then
        fail "The admin key file is not a regular file. No changes were made."
    fi
}

prepare_directory() {
    check_paths
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    if [ "$overridden" = 0 ]; then
        chown "root:$root_group" "$ssh_dir"
    fi
    # One change at a time: a second run waits, so neither undoes the other's key.
    tries=0
    until mkdir -- "$ssh_dir/.wundervault-admin.lock" 2>/dev/null; do
        tries=$((tries + 1))
        [ "$tries" -lt 30 ] || fail "Another admin-key change is still running. Try again in a minute. If none is, delete the folder $ssh_dir/.wundervault-admin.lock. No changes were made."
        sleep 1
    done
    lock_dir=$ssh_dir/.wundervault-admin.lock
}

finish_write() {
    chmod 600 "$write_tmp"
    if [ "$overridden" = 0 ]; then
        chown "root:$root_group" "$write_tmp"
    fi
    check_paths
    mv -f "$write_tmp" "$keys_file"
    write_tmp=
}

check_paths

case "$mode" in
    list)
        if [ ! -f "$keys_file" ]; then
            printf '%s\n' "No admin keys were found."
            exit 0
        fi
        awk '
            index($0, " wundervault-admin ") {
                comment = substr($0, index($0, " wundervault-admin ") + 1)
                source = "from=(any address)"
                if (match($0, /from="[^"]*"/)) {
                    source = substr($0, RSTART, RLENGTH)
                }
                printf "%s  %s\n", comment, source
            }
        ' "$keys_file"
        exit 0
        ;;
    remove)
        if [ ! -f "$keys_file" ]; then
            printf '%s\n' "Removed 0 admin keys."
            exit 0
        fi
        prepare_directory
        write_tmp=$(mktemp "$ssh_dir/.wundervault-admin.XXXXXX")
        removed=0
        # Preserve unrelated lines, including a final line without a newline.
        {
            while :; do
                line=
                if IFS= read -r line; then
                    line_ended=1
                elif [ -n "$line" ]; then
                    line_ended=0
                else
                    break
                fi
                case "$line" in
                    *" wundervault-admin "*)
                        removed=$((removed + 1))
                        ;;
                    *)
                        printf '%s' "$line"
                        if [ "$line_ended" = 1 ]; then
                            printf '\n'
                        fi
                        ;;
                esac
                if [ "$line_ended" = 0 ]; then
                    break
                fi
            done < "$keys_file"
        } > "$write_tmp"
        finish_write
        printf 'Removed %s admin keys.\n' "$removed"
        exit 0
        ;;
esac

# These checks apply when adding a key; removal must still work if SSH is off.
# A failed check stops here unless --skip-checks: a key that cannot sign in is worse than none.
cant_check() {
    if [ "$skip_checks" = 1 ]; then
        printf '%s\n' "Warning: $1 Adding the key anyway (--skip-checks)." >&2
    else
        fail "$1 No admin key was added. If you are sure SSH accepts root key sign-in here, run again with --skip-checks."
    fi
}
if [ "$overridden" = 0 ] || [ -n "${WV_ADMIN_SSHD:-}" ]; then
    if [ "$system" = Darwin ] && [ "$overridden" = 0 ]; then
        remote_login_command=
        if [ -x /usr/sbin/systemsetup ]; then
            remote_login_command=/usr/sbin/systemsetup
        elif command -v systemsetup >/dev/null 2>&1; then
            remote_login_command=systemsetup
        fi
        if [ -n "$remote_login_command" ]; then
            if remote_login=$("$remote_login_command" -getremotelogin 2>/dev/null); then
                case "$remote_login" in
                    *"Off"*)
                        fail "Turn on Remote Login in System Settings > General > Sharing, then try again. No admin key was added."
                        ;;
                    *"On"*) ;;
                    *)
                        cant_check "Remote Login could not be checked (System Settings > General > Sharing)."
                        ;;
                esac
            else
                cant_check "Remote Login could not be checked (System Settings > General > Sharing)."
            fi
        else
            cant_check "Remote Login could not be checked (System Settings > General > Sharing)."
        fi
    fi

    # -C: the settings for THIS connection (root, from the first allowed address), so a
    # "Match User root" rule that forbids it is seen (review round 1, F1).
    sshd_bin=${WV_ADMIN_SSHD:-/usr/sbin/sshd}
    # Every allowed address, each as the connection sshd will really see (round 2, F1/F2):
    # a Match Address or Match Host rule for any of them must not hide behind the first.
    remaining=$from
    while :; do
        address=${remaining%%,*}
        case "$address" in
            127.0.0.1|::1) host=localhost ;;
            *) host=$address ;;
        esac
        if sshd_settings=$("$sshd_bin" -T -C "user=root,host=$host,addr=$address" 2>/dev/null); then
            if ! printf '%s\n' "$sshd_settings" | awk '
                $1 == "permitrootlogin" { root_login = $2 }
                $1 == "pubkeyauthentication" { public_keys = $2 }
                # Space-separated alternatives; one of them must be the key alone.
                $1 == "authenticationmethods" { methods_seen = 1; for (i = 2; i <= NF; i++) if ($i == "any" || $i == "publickey") methods_ok = 1 }
                $1 == "forcecommand" { forced = $2 }
                $1 == "authorizedkeysfile" { for (i = 2; i <= NF; i++) if ($i == ".ssh/authorized_keys" || $i == "%h/.ssh/authorized_keys") keys_file_ok = 1 }
                END {
                    # forced-commands-only, a forced command, or a second required sign-in step
                    # would accept the key yet refuse the commands; a different keys file would
                    # never read the line this script writes (round 2, B1/B2).
                    ok = root_login != "" && root_login != "no" && root_login != "forced-commands-only" \
                        && public_keys == "yes" && (!methods_seen || methods_ok) \
                        && (forced == "" || forced == "none") && keys_file_ok
                    exit !ok
                }
            '; then
                fail "This computer does not let an admin key sign in as root and run commands from $address. Enable SSH key sign-in for root (no password, no extra sign-in step, no forced command, keys in .ssh/authorized_keys), then try again. No admin key was added."
            fi
        else
            cant_check "This computer's SSH settings could not be checked (is SSH installed and on?)."
        fi
        case "$remaining" in
            *,*) remaining=${remaining#*,} ;;
            *) break ;;
        esac
    done
fi

# The key is made in the vault (SPEC-admin-access §13, 5b): only its public half comes here.
# Exactly "ssh-ed25519 <68 base64 characters>", whatever comment followed it is replaced.
key_type=${public_key%% *}
key_rest=${public_key#* }
key_body=${key_rest%% *}
printf '%s' "$key_body" | grep -Eq '^[A-Za-z0-9+/]{68}$' && [ "$key_type" = ssh-ed25519 ] \
    || fail "Give the public key the vault showed: sudo sh admin-key.sh --public 'ssh-ed25519 AAAA...'. No admin key was added."

# Admin access ends on this computer too (whole-build review F2): the key is trusted only as a
# certificate authority, and the certificate's forced command ends the session at its end.
[ -f "$session_src" ] || fail "The admin session check ($session_src) is missing; reinstall the helper app. No admin key was added."
sh -n "$session_src" || fail "The admin session check is damaged; reinstall the helper app. No admin key was added."
# A test that redirects the keys folder must redirect this too, or it would write the live one.
if [ "$overridden" = 1 ] && [ -z "${WV_ADMIN_LIB_DIR:-}" ]; then
    fail "Choose a separate folder for the test session check (WV_ADMIN_LIB_DIR)."
fi
mkdir -p "$lib_dir"
session_tmp=$(mktemp "$lib_dir/.wv-admin-session.XXXXXX")
cat "$session_src" > "$session_tmp"
chmod 755 "$session_tmp"
if [ "$overridden" = 0 ]; then
    chown "root:$root_group" "$session_tmp" "$lib_dir"
    chmod 755 "$lib_dir"
fi
mv -f "$session_tmp" "$lib_dir/wv-admin-session"
session_tmp=

prepare_directory
write_tmp=$(mktemp "$ssh_dir/.wundervault-admin.XXXXXX")
{
    if [ -f "$keys_file" ]; then
        cat "$keys_file"
        if [ -s "$keys_file" ] && [ -n "$(tail -c 1 "$keys_file")" ]; then
            printf '\n'
        fi
    fi
    printf 'cert-authority,principals="wv-admin",from="%s",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc ssh-ed25519 %s %s\n' \
        "$from" "$key_body" "wundervault-admin $(hostname | tr -cd 'A-Za-z0-9._-') $(date +%Y-%m-%d)"
} > "$write_tmp"
finish_write

printf '%s\n' "Admin key added. Go back to your vault: it is already saved there as this computer's admin key, and agents can use it only while you allow admin access."
