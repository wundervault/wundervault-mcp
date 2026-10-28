/**
 * install-daemon-macos.sh --uninstall, run on Linux against stand-ins for launchctl, id,
 * uname, sleep and rm. The stand-ins only record what they were asked, so nothing here can
 * stop a real service or delete a real file whatever the script does. The run uses a copy
 * whose PATH pin names the stand-ins; the shipped script cannot be pointed at them.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

const SCRIPT = path.join(__dirname, '..', 'packaging', 'install-daemon-macos.sh');
let dir: string;

function shim(name: string, body: string) {
  const p = path.join(dir, name);
  writeFileSync(p, `#!/bin/sh\necho "${name} $*" >> "${dir}/calls"\n${body}\n`);
  chmodSync(p, 0o755);
}

/** launchctl reports the job loaded for the first `loadedFor` prints, then `after` (113 = no such service). */
function run(loadedFor: number, after = 113) {
  writeFileSync(path.join(dir, 'prints'), '0');
  shim('id', 'echo 0');
  shim('uname', 'echo Darwin');
  shim('sleep', 'exit 0');
  shim('rm', 'exit 0');
  shim('launchctl', `
case "$1" in
  print) n=$(cat "${dir}/prints"); echo $((n + 1)) > "${dir}/prints"
         [ "$n" -lt ${loadedFor} ] && exit 0 || exit ${after} ;;
  *) exit 0 ;;
esac`);
  // The shipped script pins PATH to the system directories (2.0.3), which is exactly what keeps
  // stand-ins like these from running as root. A COPY points that one line at them instead.
  const pin = 'PATH=/usr/bin:/bin:/usr/sbin:/sbin\n';
  const text = readFileSync(SCRIPT, 'utf8');
  if (text.split(pin).length !== 2) throw new Error('the PATH pin line is not in the script exactly once');
  const copy = path.join(dir, 'install-daemon-macos.sh');
  writeFileSync(copy, text.replace(pin, `PATH=${dir}:/usr/bin:/bin\n`));
  const r = spawnSync('/bin/sh', [copy, '--uninstall'], {
    env: { PATH: `${dir}:/usr/bin:/bin` }, encoding: 'utf8',
  });
  const calls = existsSync(path.join(dir, 'calls')) ? readFileSync(path.join(dir, 'calls'), 'utf8') : '';
  return { r, calls };
}

beforeEach(() => { dir = mkdtempSync(path.join(os.tmpdir(), 'wv-macos-un-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('macOS --uninstall waits for launchd instead of refusing at once', () => {
  it('a broker that takes a few seconds to stop is removed cleanly', () => {
    const { r, calls } = run(4);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Removed the job/);
    expect(calls).toMatch(/rm -f \/Library\/LaunchDaemons\/com\.wundervault\.agent\.plist/);
    expect(calls.match(/^sleep 1$/gm)?.length).toBe(4);
  });

  it('a job that never unloads is still refused, and the plist is NOT removed', () => {
    const { r, calls } = run(1000);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/still loaded 15 seconds after bootout/);
    expect(calls).not.toMatch(/^rm /m);
    expect(calls.match(/^sleep 1$/gm)?.length).toBe(15);
  });

  it('an already-stopped job does not wait at all', () => {
    const { r, calls } = run(0);
    expect(r.status).toBe(0);
    expect(calls).not.toMatch(/^sleep/m);
  });

  it('launchd failing to answer is not taken as "gone": refused, plist kept', () => {
    const { r, calls } = run(0, 5);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/did not say whether the job is gone \(launchctl print exited 5\)/);
    expect(calls).not.toMatch(/^rm /m);
  });
});
