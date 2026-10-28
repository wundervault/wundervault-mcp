/**
 * SPEC-2.0.3: nothing the user's account can change runs as root.
 *
 * The installers are run here as an ordinary user. A planted tool would leave a marker file if
 * it ever ran; the root-only check is run on its own (between markers, as installer-pick does)
 * against real paths and against a stand-in `stat` defined as a shell function.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { agentCommand, rootOnly, sudoHint, aclMayAllowChange } from '../src/launcher.js';

const ROOT = path.resolve(__dirname, '..');
const SCRIPTS = {
  linux: { file: path.join(ROOT, 'packaging', 'install-daemon.sh'), pin: 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' },
  macos: { file: path.join(ROOT, 'packaging', 'install-daemon-macos.sh'), pin: 'PATH=/usr/bin:/bin:/usr/sbin:/sbin' },
};
let tmp: string;
beforeEach(() => { tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'wv-rootpath-'))); });
afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

function between(text: string, from: string, to: string): string {
  const a = text.indexOf(from); const b = text.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`markers not found: ${from}`);
  return text.slice(a, b + to.length);
}

for (const which of ['linux', 'macos'] as const) {
  describe(`the ${which} installer runs only system tools`, () => {
    /** Run the script's prologue (through `export PATH`) with `env` and `args`, then print the environment. */
    const prologue = (env: NodeJS.ProcessEnv, args: string[] = [], shell = '/bin/sh') => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      // Through the clean-environment check that follows the pin (round 4 moved it after the restart).
      const at = text.indexOf('_dirty=$(');
      const head = text.slice(0, text.indexOf('\nesac\n', at) + '\nesac\n'.length);
      const f = path.join(tmp, 'head.sh');
      fs.writeFileSync(f, head + 'printf "ARGS=%s\\n" "$*"\n/usr/bin/env | /usr/bin/sort\n');
      return spawnSync(shell, [f, ...args], { env, encoding: 'utf8' });
    };
    const DIRTY = { PATH: '/opt/homebrew/bin:/usr/bin:/bin', NODE_OPTIONS: '--require=/tmp/x.js', LD_PRELOAD: '/tmp/x.so',
                    OPENSSL_CONF: '/tmp/x.cnf', SUDO_UID: '501', SUDO_GID: '20', SUDO_USER: 'zack' };

    it('restarts with an empty environment: nothing exported survives; PATH pinned; who ran sudo kept', () => {
      const r = prologue(DIRTY, ['--exec', '/usr/bin/x']);
      expect(r.status).toBe(0);
      const names = r.stdout.split('\n').filter((l) => /^[A-Z_]+=/.test(l)).map((l) => l.split('=')[0]);
      for (const bad of ['NODE_OPTIONS', 'LD_PRELOAD', 'OPENSSL_CONF']) expect(names).not.toContain(bad);
      expect(r.stdout).toContain('USER_PATH=/opt/homebrew/bin:/usr/bin:/bin\n');
      expect(r.stdout).toContain(`${SCRIPTS[which].pin}\n`);
      // sudo's record of the caller survives (round 3: env -i had dropped SUDO_UID, which the
      // installers use to refuse a broker account equal to the caller's).
      expect(r.stdout).toContain('SUDO_UID=501\n');
      expect(r.stdout).toContain('SUDO_USER=zack\n');
      expect(r.stdout).toContain('ARGS=--exec /usr/bin/x\n');   // the restart's own flag is gone
    });

    it('--clean-env typed by hand skips nothing: with anything else in the environment it refuses (round 3, F1)', () => {
      const forged = prologue(DIRTY, ['--clean-env']);
      expect(forged.status).toBe(1);
      expect(forged.stderr).toMatch(/--clean-env is the installer's own restart/);
      const clean = prologue({ PATH: '/usr/bin:/bin', USER_PATH: '/usr/bin:/bin' }, ['--clean-env']);
      expect(clean.status).toBe(0);
    });

    it('a newline in the caller\'s PATH cannot smuggle a variable: the restarted script refuses', () => {
      const r = prologue({ PATH: '/usr/bin:/bin\nNODE_OPTIONS=--require=/tmp/x.js' });
      expect(r.status).toBe(1);
      expect(r.stdout).not.toMatch(/^NODE_OPTIONS=/m);
    });

    it('its first command is the restart, by full path: nothing runs before the pin but /usr/bin/env (round 4, F1)', () => {
      const lines = fs.readFileSync(SCRIPTS[which].file, 'utf8').split('\n');
      const code = lines.slice(lines.indexOf('set -eu') + 1).filter((l) => l.trim() && !l.trim().startsWith('#'));
      // `case`, not `[`: macOS's sh imports a function named `[` from the environment (round 5).
      expect(code.slice(0, 2)).toEqual(['case "${1:-}" in', '  --clean-env) ;;']);
      expect(code[2]).toMatch(/^  \*\) exec \/usr\/bin\/env -i "USER_PATH=\$\{PATH:-\}" "SUDO_UID=/);
      expect(code.slice(4, 8)).toEqual(['esac', 'shift', 'USER_PATH=${USER_PATH:-}', SCRIPTS[which].pin]);
    });

    it('a function passed in the environment never runs, with or without a hand-typed --clean-env (round 5, F1)', () => {
      // bash started as `sh` imports BASH_FUNC_name%% variables as functions (macOS's sh is bash 3.2,
      // which takes `[` too; Fedora's is bash 5). Each planted function would leave a marker.
      const sh = path.join(tmp, 'sh'); fs.symlinkSync('/bin/bash', sh);
      const mark = path.join(tmp, 'ran');
      const fns: NodeJS.ProcessEnv = {};
      for (const n of ['[', 'env', 'sed', 'echo', 'printf', 'test']) fns[`BASH_FUNC_${n}%%`] = `() { /usr/bin/touch '${mark}-${n}'; }`;
      // the stand-in shell really does import them (else this test proves nothing)
      expect(spawnSync(sh, ['-c', 'env'], { env: { PATH: '/usr/bin:/bin', ...fns }, encoding: 'utf8' }).status).toBe(0);
      expect(fs.existsSync(`${mark}-env`)).toBe(true); fs.rmSync(`${mark}-env`);
      const forged = prologue({ ...DIRTY, ...fns }, ['--clean-env'], sh);
      expect(forged.status).toBe(1);
      expect(forged.stderr).toMatch(/--clean-env is the installer's own restart/);
      const normal = prologue({ ...DIRTY, ...fns }, ['--exec', '/usr/bin/x'], sh);
      expect(normal.status).toBe(0);
      expect(normal.stdout).not.toMatch(/BASH_FUNC/);
      expect(fs.readdirSync(tmp).filter((n) => n.startsWith('ran-'))).toEqual([]);
    });

    it('never runs a tool planted first on the caller\'s PATH', () => {
      const planted = path.join(tmp, 'planted');
      fs.mkdirSync(planted);
      for (const t of ['id', 'uname', 'stat', 'launchctl', 'systemctl', 'dirname', 'cut', 'rm', 'sleep', 'readlink', 'awk', 'grep', 'dscl', 'sed']) {
        fs.writeFileSync(path.join(planted, t), `#!/bin/sh\ntouch "${tmp}/RAN-${t}"\nexit 0\n`, { mode: 0o755 });
      }
      for (const args of [[], ['--uninstall']]) {
        spawnSync('/bin/sh', [SCRIPTS[which].file, ...args], { env: { PATH: `${planted}:/usr/bin:/bin`, HOME: tmp }, encoding: 'utf8' });
      }
      expect(fs.readdirSync(tmp).filter((f) => f.startsWith('RAN-'))).toEqual([]);
    });
  });
}

/**
 * Run root_only_chain from `which` on `p`. `stub` is shell code that may define stand-ins for
 * `stat` and `ls` as shell functions; the walk itself (-L, -e, readlink) uses the real disk, so
 * every test builds a real tree under tmp.
 */
function chain(which: keyof typeof SCRIPTS, p: string, stub = ''): { ok: boolean; why: string } {
  const fn = between(fs.readFileSync(SCRIPTS[which].file, 'utf8'), '# >>> root-only chain', '# <<< root-only chain');
  const file = path.join(tmp, 'chain.sh');
  fs.writeFileSync(file, `${stub}\n${fn}\nif root_only_chain "$1"; then echo OK; else echo "BAD $CHAIN_BAD"; fi\n`);
  const r = spawnSync('/bin/sh', ['-eu', file, p], { env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
  const out = r.stdout.trim();
  return out === 'OK' ? { ok: true, why: '' } : { ok: false, why: out.replace(/^BAD /, '') || r.stderr };
}
/** A GNU-style stat stand-in: listed paths answer from the table, everything else is root 755. */
function gnu(table: Record<string, string>): string {
  const cases = Object.entries(table).map(([p, v]) => `    '${p}') echo '${v}' ;;`).join('\n');
  return `stat() {\n  [ "$1" = -c ] || return 1\n  case "$3" in\n${cases}\n    *) echo 'root 755' ;;\n  esac\n}`;
}
const file = (p: string) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, ''); return p; };
const link = (target: string, at: string) => { fs.mkdirSync(path.dirname(at), { recursive: true }); fs.symlinkSync(target, at); return at; };

for (const which of ['linux', 'macos'] as const) {
  describe(`${which}: root_only_chain`, () => {
    it('passes a root-owned file whose every folder is root-owned (real /usr/bin/env)', () => {
      expect(chain(which, '/usr/bin/env')).toEqual({ ok: true, why: '' });
    });
    it('refuses sticky, world-writable /tmp on the way (real)', () => {
      // On a Mac /tmp is a link to /private/tmp: the walk follows it and names the real folder.
      expect(chain(which, '/tmp').why).toBe(`${fs.realpathSync('/tmp')} is writable by group or others (mode 777)`);
    });
    it('refuses a file another user owns, naming it', () => {
      const f = file(path.join(tmp, 'bin', 'node'));
      expect(chain(which, f, gnu({ [f]: 'zack 755' })).why).toBe(`${f} is owned by zack, not root`);
    });
    it('refuses a root-owned file inside a folder a user owns', () => {
      const f = file(path.join(tmp, 'homebrew', 'bin', 'node'));
      const d = path.dirname(f);
      expect(chain(which, f, gnu({ [d]: 'zackaryprag 775' })).why).toBe(`${d} is owned by zackaryprag, not root`);
    });
    it('refuses group- or other-writable files and folders even when root owns them', () => {
      const f = file(path.join(tmp, 'local', 'bin', 'node'));
      expect(chain(which, f, gnu({ [f]: 'root 775' })).why).toBe(`${f} is writable by group or others (mode 775)`);
      expect(chain(which, f, gnu({ [path.join(tmp, 'local')]: 'root 757' })).why).toMatch(/local is writable by group or others \(mode 757\)$/);
    });
    it('follows a link in the middle: a hop through a folder a user owns is refused (round 1, F1)', () => {
      // bin/node -> alice/redirect -> /usr/bin/env. Checking only the path as given and its final
      // target never looked at alice/, where the redirect can be re-pointed later.
      const alice = path.join(tmp, 'alice');
      link('/usr/bin/env', path.join(alice, 'redirect'));
      const start = link(path.join(alice, 'redirect'), path.join(tmp, 'bin', 'node'));
      expect(chain(which, start, gnu({ [alice]: 'alice 755' })).why).toBe(`${alice} is owned by alice, not root`);
      expect(chain(which, start, gnu({})).ok).toBe(true);
    });
    it('follows relative links with .. the way the system does', () => {
      file(path.join(tmp, 'lib', 'node_modules', 'pkg', 'dist', 'agent.js'));
      const start = link('../lib/node_modules/pkg/dist/agent.js', path.join(tmp, 'bin', 'wundervault-agent'));
      expect(chain(which, start, gnu({})).ok).toBe(true);
      expect(chain(which, start, gnu({ [path.join(tmp, 'lib', 'node_modules')]: 'zack 755' })).why).toMatch(/node_modules is owned by zack/);
    });
    it('never judges a link by its own mode (always 777 on Linux), only where it sits and leads', () => {
      const at = link('/usr/bin/env', path.join(tmp, 'bin', 'wundervault-agent'));
      expect(chain(which, at, gnu({ [at]: 'root 777' })).ok).toBe(true);
    });
    it('stops on a link loop instead of spinning', () => {
      const at = path.join(tmp, 'loop'); fs.symlinkSync(at, at);
      expect(chain(which, at, gnu({})).why).toMatch(/too many symbolic links/);
    });
    it('reads the BSD form when GNU stat is not there (macOS)', () => {
      const f = file(path.join(tmp, 'b', 'node'));
      const bsd = (owner: string) => `stat() {\n  [ "$1" = -f ] || return 1\n  echo '${owner} 755'\n}`;
      expect(chain(which, f, bsd('root')).ok).toBe(true);
      expect(chain(which, f, bsd('zack')).why).toBe('/ is owned by zack, not root');
    });
    it('refuses an access control list that allows a change, even behind an @ marker; ignores deny-only', () => {
      const f = file(path.join(tmp, 'acl', 'node'));
      const d = path.dirname(f);
      // ls stand-in. macOS: `ls -lde` lists the entries (here under a mode shown with @, which hides
      // the + — round 2, F3). Linux: no -e, and `ls -ld` marks a list with +.
      const mac = (entry: string) => `ls() {\n  case "$1 $2" in\n    "-lde ${d}") printf '%s\\n' 'drwxr-xr-x@ 2 root wheel 64 Oct 28 10:00 ${d}' '${entry}' ;;\n    *) command ls "$@" ;;\n  esac\n}`;
      const linux = `ls() {\n  case "$1 $2" in\n    "-lde ${d}") return 1 ;;\n    "-ld ${d}") echo 'drwxr-xr-x+ 2 root root 64 Oct 28 10:00 ${d}' ;;\n    *) command ls "$@" ;;\n  esac\n}`;
      expect(chain(which, f, gnu({}) + '\n' + mac(' 0: user:alice allow add_file,delete_child')).why).toBe(`${d} has an access control list that lets others change it`);
      expect(chain(which, f, gnu({}) + '\n' + mac(' 0: group:everyone deny delete')).ok).toBe(true);
      expect(chain(which, f, gnu({}) + '\n' + linux).why).toBe(`${d} has an access control list`);
    });
  });
}


describe('what the installers write and print names node, so nothing looks it up (round 2, F1/F4)', () => {
  it('linux: the unit runs the checked node on the broker, and says so after writing it', () => {
    const text = fs.readFileSync(SCRIPTS.linux.file, 'utf8');
    expect(text).toContain('sed "s|^ExecStart=.*|ExecStart=${SERVICE_NODE} ${EXEC}|" "$UNIT_SRC" > "$UNIT_PATH"');
    expect(text).toMatch(/grep -q "\^ExecStart=\$\{SERVICE_NODE\} \$\{EXEC\}\\\$" "\$UNIT_PATH"/);
  });
  for (const [which, node] of [['linux', 'SERVICE_NODE'], ['macos', 'NODE']] as const) {
    it(`${which}: the printed pairing command is sudo <node> <broker>`, () => {
      expect(fs.readFileSync(SCRIPTS[which].file, 'utf8')).toContain(`echo "  1. Pair this computer, once:   sudo \${${node}} \${AGENT_CMD} --pair"`);
    });
    it(`${which}: refuses a path a service file or a shell would split, before the chain check`, () => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      const cs = text.indexOf('*[!A-Za-z0-9_./@+-]*)');
      expect(cs).toBeGreaterThan(0);
      expect(cs).toBeLessThan(text.indexOf(`for F in "$EXEC" "$REAL_EXEC" "$${node}" "$REAL_${node}"; do\n  root_only_chain`));
      const ok = (p: string) => spawnSync('/bin/sh', ['-c', `case "$1" in *[!A-Za-z0-9_./@+-]*) exit 1 ;; esac`, 'x', p]).status === 0;
      expect(ok('/usr/local/lib/node_modules/@wundervault/mcp-server/dist/agent.js')).toBe(true);
      for (const bad of ['/Volumes/My Disk/node', '/opt/a&b/node', "/opt/it's/node", '/opt/a|b/node']) expect(ok(bad)).toBe(false);
    });
    it(`${which}: the package scan and the template check run before node does`, () => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      const nodeRun = text.indexOf(`"$${node}" -p process.version 2>/dev/null`);
      expect(text.indexOf('package_scan "$PKG_DIR" ||')).toBeGreaterThan(0);
      expect(text.indexOf('package_scan "$PKG_DIR" ||')).toBeLessThan(nodeRun);
      // The service template is held to the same rule as the programs (round 4, F2) — by its own
      // variable: a doubled $ here once read as the shell's process number.
      const tmpl = which === 'linux' ? 'UNIT_SRC' : 'PLIST_SRC';
      expect(text).toContain(`root_only_chain "$${tmpl}" || {`);
      expect(text).not.toContain('"$$' + tmpl);
      // ... and before the template is first read into the service file.
      const read = which === 'linux' ? '"$UNIT_SRC" > "$UNIT_PATH"' : `' "$PLIST_SRC" > "$PLIST_PATH"`;
      expect(text.indexOf(read)).toBeGreaterThan(text.indexOf(`root_only_chain "$${tmpl}" || {`));
    });
  }
});

describe('package_scan', () => {
  for (const which of ['linux', 'macos'] as const) {
    /** Run the script's package_scan on `pkg`, with "owned by root" read as "owned by this test user". */
    const scan = (pkg: string, stub = '') => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      const me = os.userInfo().username;
      const fns = between(text, '# >>> root-only chain', '# <<< root-only chain') + '\n'
        + between(text, '# >>> package scan', '# <<< package scan').replace('! -user root', `! -user ${me}`);
      const f = path.join(tmp, 'pkgscan.sh');
      fs.writeFileSync(f, `${stub}\n${fns}\nif package_scan '${pkg}'; then echo OK; else echo "BAD $PKG_BAD"; fi\n`);
      return spawnSync('/bin/sh', ['-eu', f], { env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' }).stdout.trim();
    };
    const tree = () => {
      const pkg = path.join(tmp, 'pkg'); const js = file(path.join(pkg, 'dist', 'agent.js'));
      fs.chmodSync(js, 0o644); fs.chmodSync(path.dirname(js), 0o755); fs.chmodSync(pkg, 0o755);
      fs.mkdirSync(path.join(pkg, 'node_modules'), { mode: 0o755 }); fs.chmodSync(path.join(pkg, 'node_modules'), 0o755);
      return pkg;
    };
    it(`${which}: passes a clean package (owner and modes right, no links)`, () => {
      expect(scan(tree(), gnu({}))).toBe('OK');
    });
    it(`${which}: scans through a link to a folder: a group-writable file there is found (round 3, F2)`, () => {
      const pkg = tree();
      const vendor = path.join(tmp, 'vendor', 'widget'); const idx = file(path.join(vendor, 'index.js'));
      fs.chmodSync(vendor, 0o755); fs.chmodSync(idx, 0o664);
      link(vendor, path.join(pkg, 'node_modules', 'widget'));
      expect(scan(pkg, gnu({}))).toBe(`BAD ${path.join(pkg, 'node_modules', 'widget', 'index.js')} can be changed by someone other than root`);
    });
    it(`${which}: follows a link nested inside a linked folder, to a folder a user owns (round 4, F3)`, () => {
      const pkg = tree();
      const vendor = path.join(tmp, 'vendor', 'dep'); fs.mkdirSync(vendor, { recursive: true }); fs.chmodSync(vendor, 0o755);
      const agentDir = path.join(tmp, 'agent-owned'); const evil = file(path.join(agentDir, 'mod.js'));
      fs.chmodSync(agentDir, 0o755); fs.chmodSync(evil, 0o644);
      link(evil, path.join(vendor, 'mod.js'));
      link(vendor, path.join(pkg, 'node_modules', 'dep'));
      // Every real path is "root 755" to the stand-in stat, except the agent's folder.
      expect(scan(pkg, gnu({ [agentDir]: 'agent 755' }))).toBe(`BAD ${agentDir} is owned by agent, not root — reached through ${path.join(vendor, 'mod.js')}`);
    });
    it(`${which}: a scan that cannot finish is a refusal, never a pass (round 4, B3)`, () => {
      const pkg = tree(); const locked = path.join(pkg, 'locked'); fs.mkdirSync(locked); fs.chmodSync(locked, 0o000);
      try { expect(scan(pkg, gnu({}))).toBe(`BAD ${pkg} could not be scanned completely`); }
      finally { fs.chmodSync(locked, 0o755); }
    });
    // Each later step's failure, alone: a find or ls stand-in that fails only for that step, and a
    // uname stand-in for the macOS branch (round 4, B3 — the -acl scan's failure had no test).
    const failing = (step: string, os_: string) =>
      `uname() { echo ${os_}; }\n`
      // (the args are joined by hand: the walk sets IFS to a newline, which "$*" would join with)
      + `find() { _sa=; for _sx in "$@"; do _sa="$_sa $_sx"; done; case "$_sa " in *' ${step} '*) return 1 ;; esac; command find "$@"; }\n`
      + `ls() { [ "$1" = '${step}' ] && return 1; command ls "$@"; }`;
    it(`${which}: the ownership scan failing alone, and the link walk failing alone, are refusals`, () => {
      const pkg = tree();
      expect(scan(pkg, gnu({}) + '\n' + failing('! -type l (', 'Linux'))).toBe(`BAD ${pkg} could not be scanned completely`);
      // `-type l -print` is the walk's own find only: the first scan has `! -type l \(`.
      expect(scan(pkg, gnu({}) + '\n' + failing('-type l -print', 'Linux'))).toBe(`BAD ${pkg} could not be scanned completely`);
    });
    it(`${which}: the access-control-list scan failing is a refusal, on macOS (find -acl) and Linux (ls -lRL)`, () => {
      const pkg = tree();
      expect(scan(pkg, gnu({}) + '\n' + failing('-acl', 'Darwin'))).toBe(`BAD ${pkg} could not be scanned for access control lists`);
      expect(scan(pkg, gnu({}) + '\n' + failing('-lRL', 'Linux'))).toBe(`BAD ${pkg} could not be scanned for access control lists`);
      expect(scan(pkg, gnu({}) + '\n' + failing('-none', 'Linux'))).toBe('OK');   // the stand-ins alone change nothing
    });
    it(`${which}: an access control list in the package is refused (Linux: ls marks it with +)`, () => {
      const pkg = tree();
      const ls = `ls() {\n  if [ "$1" = -lRL ]; then printf '%s\\n' '${pkg}:' '-rw-r--r--+ 1 root root 0 Oct 28 10:00 agent.js'; else command ls "$@"; fi\n}`;
      // the Linux branch, wherever the test runs (a Mac takes the find -acl branch, tested below)
      expect(scan(pkg, gnu({}) + '\nuname() { echo Linux; }\n' + ls)).toMatch(/has an access control list \(-rw-r--r--\+/);
    });
    it.runIf(process.platform === 'darwin')(`${which}: a real access control list in the package is refused (macOS: find -acl)`, () => {
      const pkg = tree(); const js = path.join(pkg, 'dist', 'agent.js');
      expect(scan(pkg, gnu({}))).toBe('OK');
      expect(spawnSync('/bin/chmod', ['+a', 'everyone allow write', js]).status).toBe(0);
      expect(scan(pkg, gnu({}))).toBe(`BAD ${pkg} has an access control list (${js}), so someone other than root may change it`);
    });
  }
});

describe('the sudo PATH warning', () => {
  for (const which of ['linux', 'macos'] as const) {
    /** Run sudo_path_check + sudo_path_warning with USER_PATH and SUDO_UID as given. */
    const check = (userPath: string, sudoUid = '501') => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      const fns = between(text, '# >>> root-only chain', '# <<< root-only chain') + '\n' + between(text, '# >>> sudo path check', '# <<< sudo path check');
      const f = path.join(tmp, 'sudocheck.sh');
      fs.writeFileSync(f, `${fns}\nUSER_PATH='${userPath}'\nSUDO_UID='${sudoUid}'\nsudo_path_check\nsudo_path_warning\necho "BAD=$SUDO_PATH_BAD"\n`);
      return spawnSync('/bin/sh', ['-eu', f], { env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8' });
    };
    it(`${which}: warns, naming the folder and the exact secure_path line, when sudo's PATH has a folder a user owns`, () => {
      const brew = path.join(tmp, 'homebrew-bin'); fs.mkdirSync(brew);
      const r = check(`${brew}:/usr/bin:/bin`);
      expect(r.stdout).toContain(`BAD=${brew} — `);
      expect(r.stderr).toMatch(/WARNING: sudo on this computer looks commands up in a folder someone other than root can change/);
      expect(r.stderr).toMatch(/Defaults secure_path="[^"]*\/usr\/bin[^"]*"/);
      expect(r.stderr).not.toContain(`secure_path="${brew}`);
    });
    it(`${which}: says nothing when sudo's PATH is root-only, or when not run through sudo`, () => {
      expect(check('/usr/bin:/bin').stderr).toBe('');
      const brew = path.join(tmp, 'b2'); fs.mkdirSync(brew);
      expect(check(`${brew}:/usr/bin`, '').stderr).toBe('');
    });
    it(`${which}: a relative entry (.) in sudo's PATH is flagged too`, () => {
      expect(check('.:/usr/bin').stdout).toMatch(/^BAD=\. — \. is not a full path$/m);
    });
    it(`${which}: so is an empty entry, which means the current folder (round 4, F5)`, () => {
      expect(check('/usr/bin::/bin').stdout).toMatch(/^BAD=\. — \. is not a full path$/m);
      expect(check('/usr/bin:/bin:').stdout).toMatch(/^BAD=\. — /m);
      expect(check('').stdout).toMatch(/^BAD=\. — /m);   // a wholly empty PATH is one empty entry (round 5, F2)
    });
    it(`${which}: is run right after the platform checks, and its warning repeated beside the next steps`, () => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      expect(text).toMatch(/\nsudo_path_check\nsudo_path_warning\n/);
      expect(text).toContain('  sudo_path_warning\n  echo\n  echo "Next, in this order:"');
    });
  }
});


describe('the next steps always name the broker by its full path (round 1, F2)', () => {
  for (const which of ['linux', 'macos'] as const) {
    it(which, () => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      expect(text).not.toMatch(/AGENT_CMD=wundervault-agent/);
      expect(text).toMatch(/^  case "\$EXEC" in \*" "\*\) AGENT_CMD="\\"\$EXEC\\"" ;; \*\) AGENT_CMD="\$EXEC" ;; esac$/m);
    });
  }
});

describe('the caller\'s environment cannot make node or the loader pull in other code (round 1, B1)', () => {
  for (const which of ['linux', 'macos'] as const) {
    it(which, () => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      const unset = text.indexOf('unset NODE_OPTIONS NODE_PATH');
      expect(unset).toBeGreaterThan(text.indexOf('export PATH'));
      expect(unset).toBeLessThan(text.indexOf('[ "$(id -u)" = "0" ]'));
      for (const v of ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'NODE_OPTIONS']) expect(text.slice(unset, unset + 400)).toContain(v);
    });
  }
});

describe('the check is wired in before anything found on the user\'s PATH runs', () => {
  for (const [which, node] of [['linux', 'SERVICE_NODE'], ['macos', 'NODE']] as const) {
    it(`${which}: all four paths are checked, before node is first run`, () => {
      const text = fs.readFileSync(SCRIPTS[which].file, 'utf8');
      const loop = text.indexOf(`for F in "$EXEC" "$REAL_EXEC" "$${node}" "$REAL_${node}"; do\n  root_only_chain "$F" ||`);
      const firstRun = text.indexOf(`"$${node}" -p process.version`);
      expect(loop).toBeGreaterThan(0);
      expect(firstRun).toBeGreaterThan(loop);
    });
  }
});

describe('rootOnly (the node a sudo hint may name)', () => {
  type St = { uid: number; mode: number; isSymbolicLink(): boolean };
  const fsys = (table: Record<string, { uid?: number; mode?: number; link?: string }>) => ({
    lstat: (q: string): St => {
      const e = table[q] ?? {};
      return { uid: e.uid ?? 0, mode: e.mode ?? 0o40755, isSymbolicLink: () => e.link !== undefined };
    },
    readlink: (q: string) => table[q].link!,
  });
  it('passes a real root-only file (/usr/bin/env)', () => { expect(rootOnly('/usr/bin/env')).toBe(true); });
  it('refuses a folder on the way that a user owns, or that others can write', () => {
    const a = fsys({ '/opt/homebrew': { uid: 501 } });
    expect(rootOnly('/opt/homebrew/bin/node', a.lstat, a.readlink, () => false)).toBe(false);
    const b = fsys({ '/usr/local': { mode: 0o40775 } });
    expect(rootOnly('/usr/local/bin/node', b.lstat, b.readlink, () => false)).toBe(false);
  });
  it('follows links hop by hop: a middle hop in a user folder is refused', () => {
    const f = fsys({ '/usr/local/bin/node': { link: '/srv/alice/node' }, '/srv/alice': { uid: 1000 } });
    expect(rootOnly('/usr/local/bin/node', f.lstat, f.readlink, () => false)).toBe(false);
    const g = fsys({ '/usr/local/bin/node': { link: '../Cellar/node/bin/node' } });
    expect(rootOnly('/usr/local/bin/node', g.lstat, g.readlink, () => false)).toBe(true);
    // ...and an access control list on any folder or file of the way is a no (round 4, F4).
    expect(rootOnly('/usr/local/bin/node', g.lstat, g.readlink, (q) => q === '/usr/local/bin')).toBe(false);
  });
  it('reads access control lists the way the installers do', () => {
    const mac = (entry: string) => () => `drwxr-xr-x@ 2 root wheel 64 Oct 28 10:00 /x\n${entry}\n`;
    expect(aclMayAllowChange('/x', 'darwin', mac(' 0: user:agent allow add_file,delete_child'))).toBe(true);
    expect(aclMayAllowChange('/x', 'darwin', mac(' 0: group:everyone deny delete'))).toBe(false);
    expect(aclMayAllowChange('/x', 'linux', () => 'drwxr-xr-x+ 2 root root 64 Oct 28 10:00 /x\n')).toBe(true);
    expect(aclMayAllowChange('/x', 'linux', () => 'drwxr-xr-x. 2 root root 64 Oct 28 10:00 /x\n')).toBe(false);
    expect(aclMayAllowChange('/x', 'linux', () => { throw new Error('ls failed'); })).toBe(true);
  });
  it('a missing path or a relative one is not root-only', () => {
    expect(rootOnly('relative/node')).toBe(false);
    expect(rootOnly('/no/such/node/here')).toBe(false);
  });
});

describe('messages name a node and a broker that only root can change', () => {
  const only = (...ok: string[]) => (p: string) => ok.includes(p);
  it('names a root-only node first, then the launcher (round 2, F1)', () => {
    expect(agentCommand('/usr/bin/wundervault-agent', () => false, '/usr/bin/node', only('/usr/bin/node', '/usr/bin/wundervault-agent')))
      .toBe('/usr/bin/node /usr/bin/wundervault-agent');
    expect(agentCommand('/usr/local/bin/wundervault-mcp', () => true, '/opt/homebrew/bin/node',
      only('/usr/local/bin/node', '/usr/local/bin/wundervault-agent'))).toBe('/usr/local/bin/node /usr/local/bin/wundervault-agent');
  });
  it('never offers sudo a broker copy the user can change, or no node at all (round 3, F3)', () => {
    expect(agentCommand('/home/alice/.local/bin/wundervault-agent', () => true, '/usr/bin/node', only('/usr/bin/node'))).toBeNull();
    expect(agentCommand('/usr/bin/wundervault-agent', () => false, '/opt/homebrew/bin/node', only('/usr/bin/wundervault-agent'))).toBeNull();
    expect(agentCommand('/usr/local/bin/wundervault-mcp', () => false, '/usr/bin/node', () => true)).toBeNull();
    expect(agentCommand('dist/agent.js', () => true, '/usr/bin/node', () => true)).toBeNull();
  });
  it('quotes a path the shell would split', () => {
    expect(agentCommand('/Volumes/My Disk/bin/wundervault-agent', () => false, '/usr/bin/node', () => true))
      .toBe("/usr/bin/node '/Volumes/My Disk/bin/wundervault-agent'");
  });
  it('sudoHint: the command when there is one; otherwise where to find it, never a bare name', () => {
    expect(sudoHint('--pair', '/usr/bin/node /usr/bin/wundervault-agent')).toBe('sudo /usr/bin/node /usr/bin/wundervault-agent --pair');
    const none = sudoHint('--pair', null);
    expect(none).toMatch(/full paths of node and of the broker your installer set up/);
    expect(none).not.toMatch(/sudo wundervault-agent/);
  });
});
