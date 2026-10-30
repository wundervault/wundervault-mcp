#!/bin/sh
set -eu
set -f
umask 022

die() {
    printf '%s\n' "layout: $*" >&2
    exit 1
}

ACTION=${1-}
[ "$#" -gt 0 ] || die "expected install or uninstall"
shift
PLATFORM=
ACCOUNT=
NODE=
PKG=
VERSION=
LAUNCHERS=
REMOVE_DATA=no
while [ "$#" -gt 0 ]; do
    case "$1" in
        --platform|--account|--node|--pkg|--version|--launchers)
            [ "$#" -ge 2 ] || die "missing value for $1"
            case "$1" in
                --platform) PLATFORM=$2 ;;
                --account) ACCOUNT=$2 ;;
                --node) NODE=$2 ;;
                --pkg) PKG=$2 ;;
                --version) VERSION=$2 ;;
                --launchers) LAUNCHERS=$2 ;;
            esac
            shift 2
            ;;
        --remove-data) REMOVE_DATA=yes; shift ;;
        *) die "unknown argument: $1" ;;
    esac
done
case "$ACTION" in install|uninstall) ;; *) die "expected install or uninstall" ;; esac
case "$PLATFORM" in linux|darwin) ;; *) die "expected --platform linux or darwin" ;; esac

# The JSON helper is trusted code too; do not let Node load an injected module.
[ "${NODE_OPTIONS+x}" != x ] || die "NODE_OPTIONS is set"
[ "${NODE_PATH+x}" != x ] || die "NODE_PATH is set"
[ "${NODE_EXTRA_CA_CERTS+x}" != x ] || die "NODE_EXTRA_CA_CERTS is set"
[ "${NODE_REPL_EXTERNAL_MODULE+x}" != x ] || die "NODE_REPL_EXTERNAL_MODULE is set"
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

UID_NOW=$(/usr/bin/id -u)
TEST_MODE=no
PREFIX=
if [ "${WV_LAYOUT_TEST_PREFIX+x}" = x ]; then
    [ "$UID_NOW" != 0 ] || die "root cannot use WV_LAYOUT_TEST_PREFIX"
    PREFIX=$WV_LAYOUT_TEST_PREFIX
    case "$PREFIX" in
        /*) ;;
        *) die "test prefix must be absolute" ;;
    esac
    case "$PREFIX" in
        /|*/|*[!A-Za-z0-9_./-]*) die "unsafe test prefix" ;;
    esac
    case "/$PREFIX/" in */../*|*/./*) die "unsafe test prefix" ;; esac
    TEST_MODE=yes
else
    [ "$UID_NOW" = 0 ] || die "run as root"
fi

ROOT=$PREFIX/opt/wundervault
SPOOL=$PREFIX/var/lib/wundervault-update
UNIT_DIR=$PREFIX/etc/systemd/system
PLIST=$PREFIX/Library/LaunchDaemons/com.wundervault.update.plist
SCRIPT_DIR=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)
MANIFEST=$ROOT/state/manifest.json
ROOT_GROUP=root
CHOWN=/bin/chown
if [ "$PLATFORM" = darwin ]; then
    ROOT_GROUP=wheel
    CHOWN=/usr/sbin/chown
fi
SYSTEMCTL=
LAUNCHCTL=/bin/launchctl
if [ "$TEST_MODE" = yes ]; then
    SYSTEMCTL=$PREFIX/usr/bin/systemctl
    LAUNCHCTL=$PREFIX/bin/launchctl
elif [ "$PLATFORM" = linux ]; then
    if [ -x /usr/bin/systemctl ]; then
        SYSTEMCTL=/usr/bin/systemctl
    elif [ -x /bin/systemctl ]; then
        SYSTEMCTL=/bin/systemctl
    else
        die "systemctl not found at an approved path"
    fi
fi

safe_dir() {
    [ ! -L "$1" ] || die "directory is a symlink: $1"
    [ -d "$1" ] || die "not a directory: $1"
    if [ "$TEST_MODE" = no ]; then
        if [ "$PLATFORM" = linux ]; then
            owner=$(/usr/bin/stat -c %u "$1")
            mode=$(/usr/bin/stat -c %a "$1")
        else
            owner=$(/usr/bin/stat -f %u "$1")
            mode=$(/usr/bin/stat -f %Lp "$1")
        fi
        [ "$owner" = 0 ] || die "directory is not root-owned: $1"
        [ "$((0$mode & 022))" = 0 ] || die "directory is writable by another account: $1"
    fi
}

# chmod alone masks an ACL; it does not remove its named entries. setfacl removes them where it
# exists; where it doesn't (minimal installs without the acl package) there must be no ACL to remove.
no_linux_acl() {
    if [ -x /usr/bin/setfacl ]; then
        /usr/bin/setfacl -b "$1"
        if [ -d "$1" ] && [ ! -L "$1" ]; then /usr/bin/setfacl -k "$1"; fi
    else
        perms=$(/bin/ls -ld -- "$1")
        case "$perms" in ??????????+*) die "an access-control list is set on $1 and /usr/bin/setfacl is not installed to remove it" ;; esac
    fi
}

secure_dir() {
    if [ "$TEST_MODE" = no ]; then
        "$CHOWN" "root:$ROOT_GROUP" "$1"
        if [ "$PLATFORM" = darwin ]; then
            /bin/chmod -N "$1"
        else
            no_linux_acl "$1"
        fi
    fi
    /bin/chmod "$2" "$1"
}

if [ -e "$ROOT" ] || [ -L "$ROOT" ]; then
    safe_dir "$ROOT"
    [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] ||
        die "won't adopt a folder it didn't make: $ROOT"
    safe_dir "$ROOT/state"
fi

if [ "$ACTION" = install ]; then
    case "$NODE" in /*) ;; *) die "--node must be absolute" ;; esac
    case "$PKG" in /*) ;; *) die "--pkg must be absolute" ;; esac
    [ -x "$NODE" ] || die "validated Node is not executable"
    [ -d "$PKG" ] && [ ! -L "$PKG" ] || die "package root must be a real directory"
    [ -n "$ACCOUNT" ] || die "--account is required"
    "$NODE" --input-type=commonjs - "$VERSION" <<'JS'
if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(process.argv[2])) {
  throw new Error('invalid version');
}
JS
else
    [ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || die "no managed manifest"
    safe_dir "$ROOT/versions"
    # Never use a Node found through PATH during uninstall.
    set +f   # the script runs with globbing off; this loop is the one place that needs it
    for candidate in "$ROOT"/versions/*/node; do
        if [ -x "$candidate" ]; then
            safe_dir "${candidate%/node}"
            NODE=$candidate
            break
        fi
    done
    set -f
    [ -n "$NODE" ] || die "no installed Node available to read the manifest"
fi

# Keep JSON parsing out of shell quoting. All writes are exclusive temp + fsync + rename.
manifest() {
    "$NODE" --input-type=commonjs - "$ROOT" "$PLATFORM" "$@" <<'JS'
const fs = require('fs');
const path = require('path');
const [root, platform, op, ...args] = process.argv.slice(2);
const name = path.join(root, 'state', 'manifest.json');
let m;
if (op === 'init') {
  m = { format: 'wundervault-layout-1', root, platform, paths: [], launchers: [] };
} else {
  const st = fs.lstatSync(name);
  if (!st.isFile() || st.nlink !== 1) throw new Error('unsafe manifest');
  m = JSON.parse(fs.readFileSync(name, 'utf8'));
  if (m.format !== 'wundervault-layout-1' || m.root !== root ||
      m.platform !== platform || !Array.isArray(m.paths) || !Array.isArray(m.launchers)) {
    throw new Error('not our manifest');
  }
}
function add(p, kind) {
  if (!m.paths.some(x => x.path === p)) m.paths.push({ path: p, kind });
}
function save() {
  const tmp = name + '.tmp.' + process.pid;
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(m) + '\n');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, name);
  const dir = fs.openSync(path.dirname(name), 'r');
  try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
}
switch (op) {
  case 'init':
    add(root, 'dir');
    add(path.join(root, 'versions'), 'dir');
    add(path.join(root, 'bin'), 'dir');
    add(path.join(root, 'state'), 'dir');
    add(name, 'file');
    save();
    break;
  case 'check': break;
  case 'owns':
    process.exit(m.paths.some(x => x.path === args[0]) ? 0 : 1);
    break;
  case 'add':
    add(args[0], args[1]);
    save();
    break;
  case 'tree': {
    function walk(p) {
      const st = fs.lstatSync(p);
      add(p, st.isSymbolicLink() ? 'link' : st.isDirectory() ? 'dir' : 'file');
      if (st.isDirectory()) {
        for (const child of fs.readdirSync(p).sort()) walk(path.join(p, child));
      }
    }
    walk(args[0]);
    save();
    break;
  }
  case 'launcher-known':
    process.exit(m.launchers.some(x => x.path === args[0]) ? 0 : 1);
    break;
  case 'launcher': {
    const p = args[0];
    if (!path.isAbsolute(p) || /[\r\n\t]/.test(p) ||
        !['wundervault-mcp', 'wundervault-agent'].includes(path.basename(p))) {
      throw new Error('invalid launcher path');
    }
    if (!m.launchers.some(x => x.path === p)) {
      const st = fs.lstatSync(p);
      if (!st.isFile() && !st.isSymbolicLink()) throw new Error('invalid launcher');
      m.launchers.push({
        path: p,
        original_target: st.isSymbolicLink() ? fs.readlinkSync(p) : 'file'
      });
      add(p, 'link');
      add(p + '.wv-orig', st.isSymbolicLink() ? 'link' : 'file');
      save();
    }
    break;
  }
  case 'restore':
    for (const entry of m.launchers) {
      const p = entry.path;
      if (!path.isAbsolute(p) || /[\r\n\t]/.test(p) ||
          !['wundervault-mcp', 'wundervault-agent'].includes(path.basename(p))) {
        throw new Error('invalid launcher in manifest');
      }
      const expected = path.join(root, 'bin', path.basename(p));
      let st;
      try { st = fs.lstatSync(p); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      if (st && st.isSymbolicLink() && fs.readlinkSync(p) === expected) {
        fs.lstatSync(p + '.wv-orig');
        fs.unlinkSync(p);
        fs.renameSync(p + '.wv-orig', p);
      } else {
        console.log('layout: launcher changed; leaving it and its backup untouched: ' + p);
      }
    }
    break;
  case 'highest': {
    const p = path.join(root, 'state', 'highest.json');
    if (fs.existsSync(p)) {
      const st = fs.lstatSync(p);
      if (!st.isFile() || st.nlink !== 1) throw new Error('unsafe high-water file');
      const value = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (Object.keys(value).length !== 1 ||
          !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value.version)) {
        throw new Error('invalid high-water file');
      }
      console.log(value.version);
    }
    break;
  }
  case 'spool-file': {
    const st = fs.lstatSync(args[0]);
    if (!st.isFile() || st.nlink !== 1 ||
        (process.getuid() === 0 && st.uid !== 0)) throw new Error('unsafe spool file');
    break;
  }
  default: throw new Error('unknown manifest operation');
}
JS
}

# Compare arbitrary-length decimal components without shell integer overflow.
number_gt() {
    left=$1
    right=$2
    if [ "${#left}" != "${#right}" ]; then
        [ "${#left}" -gt "${#right}" ]
        return
    fi
    while [ -n "$left" ]; do
        ld=${left%"${left#?}"}
        rd=${right%"${right#?}"}
        if [ "$ld" != "$rd" ]; then
            [ "$ld" -gt "$rd" ]
            return
        fi
        left=${left#?}
        right=${right#?}
    done
    return 1
}

version_gt() {
    vl=$1
    vr=$2
    while :; do
        lc=${vl%%.*}
        rc=${vr%%.*}
        if [ "$lc" != "$rc" ]; then
            number_gt "$lc" "$rc"
            return
        fi
        case "$vl" in
            *.*) vl=${vl#*.}; vr=${vr#*.} ;;
            *) return 1 ;;
        esac
    done
}

claim() {
    if ! manifest owns "$1"; then
        [ ! -e "$1" ] && [ ! -L "$1" ] || die "won't replace an unmanaged path: $1"
        manifest add "$1" "$2"
    fi
}

if [ "$ACTION" = uninstall ]; then
    manifest check
    if [ "$PLATFORM" = linux ]; then
        "$SYSTEMCTL" disable --now wundervault-update.timer
        "$SYSTEMCTL" stop wundervault-update.service
        for unit in wundervault-update.timer wundervault-update.service; do
            if manifest owns "$UNIT_DIR/$unit"; then
                /bin/rm -f "$UNIT_DIR/$unit"
            fi
        done
        "$SYSTEMCTL" daemon-reload
    else
        "$LAUNCHCTL" bootout system/com.wundervault.update || :
        if manifest owns "$PLIST"; then
            /bin/rm -f "$PLIST"
        fi
    fi
    manifest restore
    if manifest owns "$SPOOL"; then
        [ ! -L "$SPOOL" ] || die "spool is a symlink"
        /bin/rm -rf "$SPOOL"
    fi
    [ "$ROOT" = "$PREFIX/opt/wundervault" ] && [ ! -L "$ROOT" ] || die "unsafe removal root"
    if [ "$TEST_MODE" = no ]; then
        [ "$ROOT" = /opt/wundervault ] || die "unsafe removal root"
    fi
    /bin/rm -rf "$ROOT"
    if [ "$REMOVE_DATA" = yes ]; then
        printf '%s\n' 'layout: --remove-data is handled by the caller; broker data was not touched here'
    fi
    exit 0
fi

if [ ! -e "$ROOT" ]; then
    /bin/mkdir -p "$ROOT"
    secure_dir "$ROOT" 0755
    /bin/mkdir "$ROOT/versions" "$ROOT/bin" "$ROOT/state"
    secure_dir "$ROOT/versions" 0755
    secure_dir "$ROOT/bin" 0755
    secure_dir "$ROOT/state" 0700
    manifest init
else
    manifest check
    for dir in "$ROOT" "$ROOT/versions" "$ROOT/bin" "$ROOT/state"; do
        safe_dir "$dir"
    done
    secure_dir "$ROOT" 0755
    secure_dir "$ROOT/versions" 0755
    secure_dir "$ROOT/bin" 0755
    secure_dir "$ROOT/state" 0700
fi

HIGHEST=$(manifest highest)
if [ -n "$HIGHEST" ] && version_gt "$HIGHEST" "$VERSION"; then
    die "refusing an installer version below the high-water mark"
fi

V=$ROOT/versions/$VERSION
COPY=yes
if [ -e "$V" ] || [ -L "$V" ]; then
    safe_dir "$V"
    if [ -L "$ROOT/current" ] &&
        [ "$(/usr/bin/readlink "$ROOT/current")" = "versions/$VERSION" ]; then
        [ -d "$V/app" ] && [ ! -L "$V/app" ] && [ -x "$V/node" ] ||
            die "current version is incomplete"
        COPY=no
    else
        # Left by a run that stopped part-way (a crash, a power cut). Ours and not running, so it
        # is removed and copied again; refusing it would block every later run for good.
        manifest owns "$V" || die "version directory exists and was not made by this layout: $V"
        /bin/rm -rf "$V"
    fi
fi
if [ "$COPY" = yes ]; then
    manifest add "$V" dir
    /bin/mkdir "$V"
    secure_dir "$V" 0755
    if [ "$PLATFORM" = linux ]; then
        /bin/cp -a --no-preserve=ownership "$PKG" "$V/app.staging"
    else
        /bin/cp -R "$PKG" "$V/app.staging"
    fi
    /bin/rm -rf "$V/app.staging/node_modules/.bin"
    LINKS=$(/usr/bin/find "$V/app.staging" -type l -print)
    if [ -n "$LINKS" ]; then
        /bin/rm -rf "$V/app.staging"
        /bin/rmdir "$V"
        die "package contains a symlink outside node_modules/.bin"
    fi
    SPECIAL=$(/usr/bin/find "$V/app.staging" ! -type d ! -type f -print)
    if [ -n "$SPECIAL" ]; then
        /bin/rm -rf "$V/app.staging"
        /bin/rmdir "$V"
        die "package contains a non-file entry"
    fi
    if [ "$TEST_MODE" = no ]; then
        "$CHOWN" -R "root:$ROOT_GROUP" "$V/app.staging"
        if [ "$PLATFORM" = darwin ]; then
            /bin/chmod -RN "$V/app.staging"
        else
            if [ -x /usr/bin/setfacl ]; then
                /usr/bin/setfacl -R -b "$V/app.staging"
                /usr/bin/find "$V/app.staging" -type d -exec /usr/bin/setfacl -k '{}' +
            else
                ACLS=$(/usr/bin/find "$V/app.staging" -exec /bin/ls -ld -- '{}' + | /usr/bin/awk 'substr($1,11,1)=="+"')
                [ -z "$ACLS" ] || { /bin/rm -rf "$V/app.staging"; /bin/rmdir "$V"; die "the package carries access-control lists and /usr/bin/setfacl is not installed"; }
            fi
        fi
    fi
    /usr/bin/find "$V/app.staging" -type d -exec /bin/chmod 0755 '{}' +
    /usr/bin/find "$V/app.staging" -type f -exec /bin/chmod 0644 '{}' +
    /bin/mv "$V/app.staging" "$V/app"
    /bin/ln -s "$NODE" "$V/node"
    manifest tree "$V"
fi

manifest add "$ROOT/current" link
[ ! -e "$ROOT/current" ] || [ -L "$ROOT/current" ] || die "current is not a symlink"
CURRENT_TMP=$ROOT/current.tmp.$$
[ ! -e "$CURRENT_TMP" ] && [ ! -L "$CURRENT_TMP" ] || die "descriptor temp already exists"
/bin/ln -s "versions/$VERSION" "$CURRENT_TMP"
if [ "$PLATFORM" = linux ]; then
    /bin/mv -fT "$CURRENT_TMP" "$ROOT/current"
else
    /bin/mv -fh "$CURRENT_TMP" "$ROOT/current"
fi

if [ -z "$HIGHEST" ] || version_gt "$VERSION" "$HIGHEST"; then
    manifest add "$ROOT/state/highest.json" file
    (
        umask 077
        set -C
        printf '{"version":"%s"}\n' "$VERSION" > "$ROOT/state/highest.json.tmp.$$"
    )
    /bin/mv -f "$ROOT/state/highest.json.tmp.$$" "$ROOT/state/highest.json"
fi

for name in wundervault-mcp wundervault-agent; do
    manifest add "$ROOT/bin/$name" file
    [ ! -L "$ROOT/bin/$name" ] || die "wrapper is a symlink"
    /bin/cat > "$ROOT/bin/$name" <<EOF
#!/bin/sh
set -eu
ROOT='$ROOT'
target=\$(/usr/bin/readlink "\$ROOT/current") || exit 1
case "\$target" in versions/*) v=\${target#versions/} ;; *) exit 1 ;; esac
case "\$v" in ''|*[!0-9.]*|.*|*.|*..*) exit 1 ;; esac
a=\${v%%.*}
rest=\${v#*.}
[ "\$rest" != "\$v" ] || exit 1
b=\${rest%%.*}
c=\${rest#*.}
[ "\$c" != "\$rest" ] || exit 1
case "\$c" in *.*) exit 1 ;; esac
[ -n "\$a" ] && [ -n "\$b" ] && [ -n "\$c" ] || exit 1
exec "\$ROOT/versions/\$v/node" "\$ROOT/versions/\$v/app/bin/$name" "\$@"
EOF
    if [ "$TEST_MODE" = no ]; then
        "$CHOWN" "root:$ROOT_GROUP" "$ROOT/bin/$name"
    fi
    /bin/chmod 0755 "$ROOT/bin/$name"
done

# This interface is a space-separated pair, not shell source or a glob.
# shellcheck disable=SC2086
set -- $LAUNCHERS
[ "$#" = 2 ] || die "--launchers must contain exactly two paths without whitespace"
SEEN_MCP=no
SEEN_AGENT=no
for launcher do
    case "$launcher" in /*) ;; *) die "launcher must be absolute" ;; esac
    name=${launcher##*/}
    case "$name" in
        wundervault-mcp) [ "$SEEN_MCP" = no ] || die "duplicate launcher"; SEEN_MCP=yes ;;
        wundervault-agent) [ "$SEEN_AGENT" = no ] || die "duplicate launcher"; SEEN_AGENT=yes ;;
        *) die "unexpected launcher basename" ;;
    esac
    if [ -e "$launcher.wv-orig" ] || [ -L "$launcher.wv-orig" ]; then
        manifest launcher-known "$launcher" || die "unmanaged launcher backup"
        if [ -e "$launcher" ] || [ -L "$launcher" ]; then
            [ -L "$launcher" ] &&
                [ "$(/usr/bin/readlink "$launcher")" = "$ROOT/bin/$name" ] ||
                die "launcher changed since installation"
            continue
        fi
    elif [ -e "$launcher" ] || [ -L "$launcher" ]; then
        manifest launcher "$launcher"
        /bin/mv "$launcher" "$launcher.wv-orig"
    else
        continue
    fi
    /bin/ln -s "$ROOT/bin/$name" "$launcher"
done

claim "$SPOOL" dir
if [ ! -e "$SPOOL" ]; then
    /bin/mkdir -p "$SPOOL"
fi
safe_dir "$SPOOL"
secure_dir "$SPOOL" 0755
BROKER_GROUP=$(/usr/bin/id -gn "$ACCOUNT")
# request.json is writable by this group, so it must be the broker's OWN group: a shared one
# (nogroup, staff) would let every account in it ask root for an update.
if [ "$TEST_MODE" = no ]; then
    [ "$BROKER_GROUP" = "$ACCOUNT" ] || die "the broker account's group is $BROKER_GROUP, not its own group $ACCOUNT"
fi
for file in request.json status.json; do
    claim "$SPOOL/$file" file
    [ ! -L "$SPOOL/$file" ] || die "spool file is a symlink"
    if [ ! -e "$SPOOL/$file" ]; then
        (
            set -C
            if [ "$file" = request.json ]; then
                : > "$SPOOL/$file"
            else
                printf '{}\n' > "$SPOOL/$file"
            fi
        )
    fi
    manifest spool-file "$SPOOL/$file"
    if [ "$TEST_MODE" = no ]; then
        if [ "$PLATFORM" = darwin ]; then
            /bin/chmod -N "$SPOOL/$file"
        else
            no_linux_acl "$SPOOL/$file"
        fi
    fi
    if [ "$file" = request.json ]; then
        if [ "$TEST_MODE" = no ]; then
            "$CHOWN" "root:$BROKER_GROUP" "$SPOOL/$file"
        fi
        /bin/chmod 0620 "$SPOOL/$file"
    else
        if [ "$TEST_MODE" = no ]; then
            "$CHOWN" "root:$ROOT_GROUP" "$SPOOL/$file"
        fi
        /bin/chmod 0644 "$SPOOL/$file"
    fi
done

if [ "$PLATFORM" = linux ]; then
    [ -d "$UNIT_DIR" ] || /bin/mkdir -p "$UNIT_DIR"
    safe_dir "$UNIT_DIR"
    for unit in wundervault-update.service wundervault-update.timer; do
        claim "$UNIT_DIR/$unit" unit
        [ ! -L "$UNIT_DIR/$unit" ] || die "unit is a symlink"
        /bin/cp "$SCRIPT_DIR/$unit" "$UNIT_DIR/$unit"
        if [ "$TEST_MODE" = no ]; then
            "$CHOWN" "root:$ROOT_GROUP" "$UNIT_DIR/$unit"
        fi
        /bin/chmod 0644 "$UNIT_DIR/$unit"
    done
    "$SYSTEMCTL" daemon-reload
    "$SYSTEMCTL" enable --now wundervault-update.timer
else
    [ -d "${PLIST%/*}" ] || /bin/mkdir -p "${PLIST%/*}"
    safe_dir "${PLIST%/*}"
    claim "$PLIST" plist
    [ ! -L "$PLIST" ] || die "plist is a symlink"
    /bin/cp "$SCRIPT_DIR/com.wundervault.update.plist" "$PLIST"
    if [ "$TEST_MODE" = no ]; then
        "$CHOWN" root:wheel "$PLIST"
    fi
    /bin/chmod 0644 "$PLIST"
    "$LAUNCHCTL" bootout system/com.wundervault.update || :
    "$LAUNCHCTL" bootstrap system "$PLIST"
fi

printf 'SERVICE_NODE=%s/current/node EXEC=%s/current/app/bin/wundervault-agent\n' "$ROOT" "$ROOT"
