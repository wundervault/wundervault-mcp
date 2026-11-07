#!/bin/sh
set -eu

umask 077
LC_ALL=C
export LC_ALL

usage() {
    cat <<'EOF'
Usage: sudo sh admin-key.sh [--from ADDR[,ADDR...]]
       sudo sh admin-key.sh --remove
       sudo sh admin-key.sh --list
       sudo sh admin-key.sh --help

Add an admin key so your broker can run admin commands without your password.
By default, the key works only from this computer.

  --from ADDR[,ADDR...]  Allow connections from these addresses instead.
  --remove              Remove all admin keys created by this script.
  --list                Show existing admin keys without showing their key material.
  --help                Show these instructions.
EOF
}

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

mode=add
from=127.0.0.1,::1

case $# in
    0) ;;
    1)
        case "$1" in
            --remove) mode=remove ;;
            --list) mode=list ;;
            --help)
                usage
                exit 0
                ;;
            *)
                usage >&2
                exit 1
                ;;
        esac
        ;;
    2)
        if [ "$1" != --from ]; then
            usage >&2
            exit 1
        fi
        from=$2
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac

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

cleanup() {
    if [ -n "$write_tmp" ]; then
        rm -f -- "$write_tmp"
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
if [ "$overridden" = 0 ]; then
    if [ "$system" = Darwin ]; then
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
                        printf '%s\n' "Warning: Remote Login could not be checked. Make sure it is on in System Settings > General > Sharing." >&2
                        ;;
                esac
            else
                printf '%s\n' "Warning: Remote Login could not be checked. Make sure it is on in System Settings > General > Sharing." >&2
            fi
        else
            printf '%s\n' "Warning: Remote Login could not be checked. Make sure it is on in System Settings > General > Sharing." >&2
        fi
    fi

    if sshd_settings=$(/usr/sbin/sshd -T 2>/dev/null); then
        if ! printf '%s\n' "$sshd_settings" | awk '
            $1 == "permitrootlogin" { root_login = $2 }
            $1 == "pubkeyauthentication" { public_keys = $2 }
            END {
                # forced-commands-only would accept the key yet refuse every command it runs.
                exit !(root_login != "" && root_login != "no" && root_login != "forced-commands-only" && public_keys == "yes")
            }
        '; then
            fail "This computer does not allow admin keys to sign in as root. Enable SSH key sign-in for root, without enabling password sign-in, then try again. No admin key was added."
        fi
    else
        printf '%s\n' "Warning: This computer's SSH settings could not be checked. The admin key will work only if SSH allows root to sign in with a key." >&2
    fi
fi

key_tmp=$(mktemp -d "${TMPDIR:-/tmp}/wundervault-admin.XXXXXX")
ssh-keygen -q -t ed25519 -N '' \
    -C "wundervault-admin $(hostname) $(date +%Y-%m-%d)" \
    -f "$key_tmp/key"

prepare_directory
write_tmp=$(mktemp "$ssh_dir/.wundervault-admin.XXXXXX")
{
    if [ -f "$keys_file" ]; then
        cat "$keys_file"
        if [ -s "$keys_file" ] && [ -n "$(tail -c 1 "$keys_file")" ]; then
            printf '\n'
        fi
    fi
    printf 'from="%s",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc %s\n' \
        "$from" "$(cat "$key_tmp/key.pub")"
} > "$write_tmp"
finish_write

cat <<'EOF'
Admin key added.

Copy everything between the lines into the vault: Add a secret > SSH key. For its server, type localhost (or this computer's name if your broker runs on another computer). Then come back here and press Enter.

---------- Private key starts below ----------
EOF
cat "$key_tmp/key"
printf '%s\n' '---------- Private key ends above ----------'

if [ "${WV_ADMIN_NO_WAIT:-0}" != 1 ]; then
    IFS= read -r _ || :
fi
