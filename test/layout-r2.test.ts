import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'vitest';
import type { TestContext } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

const project = fileURLToPath(new URL('../', import.meta.url));
const layout = path.join(project, 'packaging/layout-posix.sh');
const posixSkip = process.platform !== 'linux' || !process.getuid || process.getuid() === 0
  ? 'requires an unprivileged Linux account'
  : false;

async function waitFor(check: () => boolean, detail: string): Promise<void> {
  const deadline = Date.now() + 30000;
  while (!check()) {
    assert.ok(Date.now() < deadline, detail);
    await delay(25);
  }
}

function fixture(t: TestContext) {
  // The shell deliberately accepts only simple absolute prefixes, including in test mode.
  const prefix = fs.mkdtempSync('/tmp/wv-layout-r2-');
  const root = path.join(prefix, 'opt/wundervault');
  const spool = path.join(prefix, 'var/lib/wundervault-update');
  const pkg = path.join(prefix, 'package');
  const lock = path.join(root, 'state/lock');
  const hold = path.join(prefix, 'hold');
  const entered = path.join(prefix, 'entered');
  const calls = path.join(prefix, 'calls');
  const children = new Set<ChildProcess>();
  fs.mkdirSync(path.join(prefix, 'usr/bin'), { recursive: true });
  fs.mkdirSync(pkg);
  fs.writeFileSync(path.join(pkg, 'package.json'), '{"name":"layout-fixture","version":"1.2.3"}');
  fs.writeFileSync(path.join(prefix, 'usr/bin/systemctl'), `#!/bin/sh
set -eu
printf '%s\\n' "$*" >> '${calls}'
if [ "$1" = daemon-reload ] && /bin/mkdir '${entered}' 2>/dev/null; then
    while [ -f '${hold}' ]; do /bin/sleep 1; done
fi
`, { mode: 0o755 });

  const env = { ...process.env, WV_LAYOUT_TEST_PREFIX: prefix };
  for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_REPL_EXTERNAL_MODULE']) {
    delete env[name];
  }

  function run(action: 'install' | 'uninstall', node = process.execPath) {
    const args = [layout, action, '--platform', 'linux'];
    if (action === 'install') {
      args.push('--node', node, '--pkg', pkg, '--version', '1.2.3',
        '--account', os.userInfo().username, '--launchers',
        `${prefix}/wundervault-mcp ${prefix}/wundervault-agent`);
    }
    const child = spawn('/bin/sh', args, {
      env,
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.add(child);
    let output = '';
    child.stdout.on('data', chunk => { output += String(chunk); });
    child.stderr.on('data', chunk => { output += String(chunk); });
    const done = new Promise<{ code: number | null; output: string }>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', code => {
        children.delete(child);
        resolve({ code, output });
      });
    });
    return { child, done };
  }

  function skeleton() {
    for (const name of ['versions', 'bin', 'state']) {
      fs.mkdirSync(path.join(root, name), { recursive: true });
    }
  }

  t.onTestFinished(async () => {
    for (const child of children) {
      if (child.pid) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch (e) {
          if ((e as NodeJS.ErrnoException).code !== 'ESRCH') throw e;
        }
      }
    }
    await waitFor(() => children.size === 0, 'fixture children did not exit');
    fs.rmSync(prefix, { recursive: true, force: true });
  });
  return { prefix, root, spool, pkg, lock, hold, entered, calls, run, skeleton };
}

test('two installers breaking one stale lock remain mutually exclusive', {
  skip: posixSkip,
  timeout: 90000,
}, async t => {
  const f = fixture(t);
  f.skeleton();
  // A valid, old lock is stale even if this PID is still alive.
  fs.writeFileSync(f.lock, `${process.pid} 0`);
  fs.writeFileSync(f.hold, '');
  const first = f.run('install');
  const second = f.run('install');
  await waitFor(() => fs.existsSync(f.entered), 'neither installer reached the service step');
  const held = fs.statSync(f.lock);
  const contents = fs.readFileSync(f.lock, 'utf8');
  const pid = Number(contents.split(' ')[0]);
  assert.ok(pid === first.child.pid || pid === second.child.pid);
  await delay(1500);
  assert.equal(first.child.exitCode, null);
  assert.equal(second.child.exitCode, null);
  assert.equal(fs.statSync(f.lock).ino, held.ino);
  assert.equal(fs.readFileSync(f.lock, 'utf8'), contents);
  assert.equal(fs.readFileSync(f.calls, 'utf8'), 'daemon-reload\n');
  fs.unlinkSync(f.hold);
  for (const running of [first, second]) {
    const result = await running.done;
    assert.equal(result.code, 0, result.output);
  }
  assert.equal(fs.existsSync(f.lock), false);
  assert.equal(fs.existsSync(f.lock + '.break'), false);
  assert.equal(fs.readlinkSync(path.join(f.root, 'current')), 'versions/1.2.3');
});

test('a first install killed immediately after take_lock leaves an adoptable skeleton', {
  skip: posixSkip,
  timeout: 90000,
}, async t => {
  const f = fixture(t);
  const marker = path.join(f.prefix, 'before-manifest');
  const wrapper = path.join(f.prefix, 'node-wrapper');
  // The first Node invocation after take_lock is manifest init. Stop there, before any write.
  fs.writeFileSync(wrapper, `#!/bin/sh
set -eu
if [ "\${5-}" = init ]; then
    : > '${marker}'
    while :; do /bin/sleep 1; done
fi
exec '${process.execPath.replace(/'/g, "'\\''")}' "$@"
`, { mode: 0o755 });
  const interrupted = f.run('install', wrapper);
  await waitFor(() => fs.existsSync(marker), 'installer did not stop before manifest init');
  assert.equal(fs.existsSync(path.join(f.root, 'state/manifest.json')), false);
  assert.equal(Number(fs.readFileSync(f.lock, 'utf8').split(' ')[0]), interrupted.child.pid);
  assert.ok(interrupted.child.pid);
  process.kill(-interrupted.child.pid, 'SIGKILL');
  await interrupted.done;
  assert.equal(fs.existsSync(f.lock), true);
  // Exercise recovery of a breaker killed during an earlier recovery as well.
  fs.writeFileSync(f.lock + '.break', '1 0');
  const old = new Date(Date.now() - 61000);
  fs.utimesSync(f.lock + '.break', old, old);
  const result = await f.run('install').done;
  assert.equal(result.code, 0, result.output);
  assert.equal(fs.existsSync(path.join(f.root, 'state/manifest.json')), true);
  assert.equal(fs.existsSync(f.lock), false);
  assert.equal(fs.existsSync(f.lock + '.break'), false);
});

test('skeleton adoption ignores only the named regular lock files', {
  skip: posixSkip,
  timeout: 90000,
}, async t => {
  const f = fixture(t);
  f.skeleton();
  fs.writeFileSync(path.join(f.root, 'state/unrelated'), '');
  const result = await f.run('install').done;
  assert.notEqual(result.code, 0);
  assert.match(result.output, /won't adopt a folder it didn't make/);
  assert.equal(fs.existsSync(path.join(f.root, 'state/manifest.json')), false);
});

test('uninstall waits for the shared lock before removing anything', {
  skip: posixSkip,
  timeout: 90000,
}, async t => {
  const f = fixture(t);
  const installed = await f.run('install').done;
  assert.equal(installed.code, 0, installed.output);
  const before = fs.readFileSync(f.calls, 'utf8');
  fs.writeFileSync(f.lock, `${process.pid} ${Date.now()}`);
  const held = fs.statSync(f.lock);
  const removing = f.run('uninstall');
  await waitFor(() => fs.readdirSync(path.join(f.root, 'state'))
    .some(name => name === `lock.tmp.${removing.child.pid}`), 'uninstall did not attempt the lock');
  await delay(1500);
  assert.equal(removing.child.exitCode, null);
  assert.equal(fs.statSync(f.lock).ino, held.ino);
  assert.equal(fs.existsSync(f.spool), true);
  assert.equal(fs.existsSync(path.join(f.root, 'state/manifest.json')), true);
  assert.equal(fs.existsSync(path.join(f.prefix, 'etc/systemd/system/wundervault-update.timer')), true);
  assert.equal(fs.readFileSync(f.calls, 'utf8'), before);
  fs.unlinkSync(f.lock);
  const result = await removing.done;
  assert.equal(result.code, 0, result.output);
  assert.equal(fs.existsSync(f.root), false);
  assert.equal(fs.existsSync(f.spool), false);
});

test('POSIX stale-lock recovery uses a serialized inode-and-content comparison', () => {
  const source = fs.readFileSync(layout, 'utf8');
  // Round 3 (B-F1): the break-lock is a fresh file, so its age is its own, not the waiter's temp's.
  assert.match(source, /fs\.linkSync\(fresh, breaker\)/);
  assert.doesNotMatch(source, /fs\.linkSync\(temp, breaker\)/);
  assert.match(source, /same\(inspected\.st, current\.st\)/);
  assert.match(source, /inspected\.data\.equals\(current\.data\)/);
  assert.match(source, /same\(ours, stat\(breaker\)\)/);
  assert.match(source, /old\.mtimeMs <= 60 \* 1000/);
  assert.match(source, /if \[ "\$ACTION" = uninstall \]; then\s+take_lock\s+manifest check/);
});

test('Windows layout pauses updates in try/finally and persists the version-specific Node', () => {
  const source = fs.readFileSync(path.join(project, 'packaging/layout-windows.ps1'), 'utf8');
  const pause = source.indexOf("Disable-ScheduledTask -TaskName 'wundervault-update'");
  const manifest = source.indexOf('$script:Manifest = $null');
  const resume = source.lastIndexOf("Enable-ScheduledTask -TaskName 'wundervault-update'");
  assert.ok(pause > source.indexOf('try {'));
  assert.ok(pause < manifest);
  assert.ok(resume > source.lastIndexOf('} finally {'));
  assert.match(source, /\$Task\.State -eq 'Running'/);
  assert.match(source, /\$Wait\.Elapsed\.TotalSeconds -ge 120/);
  assert.doesNotMatch(source, /Stop-ScheduledTask/);
  assert.match(source, /\$VersionNodePath = Join-Path \$V 'node\.path'/);
  assert.match(source, /if \(-not \(Test-Path -LiteralPath \$VersionNodePath\)\)/);
  assert.match(source, /Write-LayoutFile \$VersionNodePath \$ActiveNode/);
  assert.match(source, /Add-ManifestPath \$VersionNodePath 'file'/);
  assert.match(source, /\$Ascii\.GetString\(\$Ascii\.GetBytes\(\$ActiveNode\)\)/);
  assert.match(source, /\$NodePathItem\.Length -gt 1024/);
  assert.match(source, /Assert-RealPath \$ActiveNode/);
});

test('ustar rejects Windows aliases in every path segment', () => {
  const moduleUrl = pathToFileURL(path.join(project, 'scripts/lib/ustar.mjs')).href;
  execFileSync(process.execPath, ['--input-type=module', '-e', `
import assert from 'node:assert/strict';
import { ustarHeader, buildArchive } from ${JSON.stringify(moduleUrl)};
for (const name of [
  'CON.js', 'con', 'PrN.txt', 'AUX', 'nul.json', 'COM1.js', 'com9', 'LPT1', 'lpt9.txt',
  'a./b', 'a /b', 'a/b.', 'a/b ', 'a/CON.js/b',
]) {
  assert.throws(() => ustarHeader(name, 0), /Invalid archive path/, name);
  assert.throws(() => buildArchive([{ path: 'app/' + name, data: Buffer.alloc(0) }]),
    /Invalid archive path/, name);
}
for (const name of ['app/config.js', 'app/console.js', 'app/COM10.js', 'app/lpt0.txt']) {
  assert.equal(ustarHeader(name, 0).length, 512);
}
`], { encoding: 'utf8' });
});
