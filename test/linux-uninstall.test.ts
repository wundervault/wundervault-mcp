/**
 * install-daemon.sh --uninstall, run against stand-ins for systemctl, id, uname, sleep and rm
 * (2.0.3 review round 3, B2: the unit was removed even when the stop had failed). The stand-ins
 * only record what they were asked, so nothing here can stop a real service or delete a real
 * file whatever the script does. The run uses a copy whose PATH pin names the stand-ins; the
 * shipped script cannot be pointed at them.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

const SCRIPT = path.join(__dirname, '..', 'packaging', 'install-daemon.sh');
let dir: string;

function shim(name: string, body: string) {
  const p = path.join(dir, name);
  writeFileSync(p, `#!/bin/sh\necho "${name} $*" >> "${dir}/calls"\n${body}\n`);
  chmodSync(p, 0o755);
}

/** systemd reports `busy` for the first `busyFor` asks, then `after`; `fail` makes `show` itself fail. */
function run(busyFor: number, after = 'inactive', busy = 'deactivating', fail = false) {
  writeFileSync(path.join(dir, 'asks'), '0');
  shim('id', 'echo 0');
  shim('uname', 'echo Linux');
  shim('sleep', 'exit 0');
  shim('rm', 'exit 0');
  shim('systemctl', `
case "$1" in
  show) ${fail ? 'exit 1' : ''}
        n=$(cat "${dir}/asks"); echo $((n + 1)) > "${dir}/asks"
        [ "$n" -lt ${busyFor} ] && echo ${busy} || echo ${after} ;;
  *) exit 0 ;;
esac`);
  const pin = 'PATH=/usr/sbin:/usr/bin:/sbin:/bin\n';
  const text = readFileSync(SCRIPT, 'utf8');
  if (text.split(pin).length !== 2) throw new Error('the PATH pin line is not in the script exactly once');
  const copy = path.join(dir, 'install-daemon.sh');
  writeFileSync(copy, text.replace(pin, `PATH=${dir}:/usr/bin:/bin\n`));
  const r = spawnSync('/bin/sh', [copy, '--uninstall'], { env: { PATH: `${dir}:/usr/bin:/bin` }, encoding: 'utf8' });
  const calls = existsSync(path.join(dir, 'calls')) ? readFileSync(path.join(dir, 'calls'), 'utf8') : '';
  return { r, calls };
}

beforeEach(() => { dir = mkdtempSync(path.join(os.tmpdir(), 'wv-linux-un-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('Linux --uninstall removes the unit only once systemd says the broker stopped', () => {
  it('a broker that takes a few seconds to stop is removed cleanly', () => {
    const { r, calls } = run(4);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/Removed the unit/);
    expect(calls).toMatch(/^rm -f \/etc\/systemd\/system\/wundervault-agent\.service$/m);
    expect(calls).toMatch(/^systemctl daemon-reload$/m);
    expect(calls.match(/^sleep 1$/gm)?.length).toBe(4);
  });

  it('a broker that never stops is refused, and the unit is NOT removed', () => {
    const { r, calls } = run(1000, 'inactive', 'active');
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/still active 15 seconds after it was told to stop/);
    expect(calls).not.toMatch(/^rm /m);
    expect(calls).not.toMatch(/daemon-reload/);
    expect(calls.match(/^sleep 1$/gm)?.length).toBe(15);
  });

  it('an already-stopped broker, or one that failed, is removed without waiting', () => {
    for (const after of ['inactive', 'failed']) {
      rmSync(path.join(dir, 'calls'), { force: true });
      const { r, calls } = run(0, after);
      expect(r.status, after).toBe(0);
      expect(calls).not.toMatch(/^sleep/m);
      expect(calls).toMatch(/^rm -f /m);
    }
  });

  it('systemd failing to answer is not taken as "stopped": refused, unit kept', () => {
    const { r, calls } = run(0, 'inactive', 'active', true);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/systemd did not say whether the broker stopped \(it answered: \?\)/);
    expect(calls).not.toMatch(/^rm /m);
  });

  it('an answer it does not know is refused too', () => {
    const { r, calls } = run(0, 'maintenance');
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/it answered: maintenance/);
    expect(calls).not.toMatch(/^rm /m);
  });
});
