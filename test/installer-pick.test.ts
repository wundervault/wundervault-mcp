/**
 * Which broker copy the Linux and macOS installers install, and what they say last (2.0.1, B1-B2).
 *
 * Cutover day: the owner installed 2.0 with `sudo npm install -g` (into /usr), ran the installer,
 * and it registered /usr/local/bin/wundervault-agent instead, an old test build that sudo's PATH
 * finds first. The installers now take the copy they ship in, as Windows always has.
 *
 * The choice is a shell function between markers in each script, run here on its own against
 * fake npm trees in a temp directory. Nothing runs as root, and nothing outside the temp
 * directory is read or written: the function only sets EXEC and prints.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(__dirname, '..');
const SCRIPTS = {
  linux: path.join(ROOT, 'packaging', 'install-daemon.sh'),
  macos: path.join(ROOT, 'packaging', 'install-daemon-macos.sh'),
};

function between(text: string, from: string, to: string): string {
  const a = text.indexOf(from);
  const b = text.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`markers not found: ${from} … ${to}`);
  return text.slice(a, b + to.length);
}

/** The function under test, plus real_path on macOS (which it uses). */
function picker(which: keyof typeof SCRIPTS): string {
  const text = fs.readFileSync(SCRIPTS[which], 'utf8');
  const pick = between(text, '# >>> pick the broker', '# <<< pick the broker');
  return which === 'macos' ? between(text, 'real_path() {', '\n}\n') + '\n' + pick : pick;
}

let tmp: string;

/** An npm global prefix holding one copy of the package, its launcher linked the way npm links it. */
function prefix(name: string, launcher = true): { pkg: string; bin: string } {
  const pkg = path.join(tmp, name, 'lib', 'node_modules', '@wundervault', 'mcp-server');
  fs.mkdirSync(path.join(pkg, 'dist'), { recursive: true });
  fs.mkdirSync(path.join(pkg, 'packaging'), { recursive: true });
  fs.writeFileSync(path.join(pkg, 'dist', 'agent.js'), '#!/usr/bin/env node\n', { mode: 0o755 });
  const bin = path.join(tmp, name, 'bin');
  fs.mkdirSync(bin, { recursive: true });
  if (launcher) fs.symlinkSync('../lib/node_modules/@wundervault/mcp-server/dist/agent.js', path.join(bin, 'wundervault-agent'));
  return { pkg, bin };
}

function run(which: keyof typeof SCRIPTS, selfDir: string, pathDirs: string[]): { exec: string; out: string; err: string } {
  const file = path.join(tmp, 'pick.sh');
  fs.writeFileSync(file, `${picker(which)}\npick_broker "$1"\nprintf 'EXEC=%s\\n' "$EXEC"\n`);
  // Only the tools the function uses, so no real wundervault-agent on this machine is ever found.
  const tools = path.join(tmp, 'tools');
  if (!fs.existsSync(tools)) {
    fs.mkdirSync(tools);
    for (const t of ['readlink', 'dirname', 'basename']) {
      const real = spawnSync('sh', ['-c', `command -v ${t}`], { encoding: 'utf8' }).stdout.trim();
      fs.symlinkSync(real, path.join(tools, t));
    }
  }
  const r = spawnSync('/bin/sh', ['-eu', file, selfDir], {
    env: { PATH: [...pathDirs, tools].join(':') }, encoding: 'utf8',
  });
  if (r.status !== 0) throw new Error(`pick.sh exited ${r.status}: ${r.stderr}`);
  return { exec: (r.stdout.match(/^EXEC=(.*)$/m) ?? [])[1] ?? '', out: r.stdout, err: r.stderr };
}

beforeEach(() => { tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'wv-pick-'))); });
afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

for (const which of ['linux', 'macos'] as const) {
  describe(`the ${which} installer installs the copy it came with`, () => {
    it('skips an older copy that comes first on PATH, and says so in one note', () => {
      const fresh = prefix('usr');
      const stale = prefix('usr-local');
      const r = run(which, path.join(fresh.pkg, 'packaging'), [stale.bin, fresh.bin]);
      expect(r.exec).toBe(path.join(fresh.bin, 'wundervault-agent'));
      expect(r.out).toContain(`note: using ${path.join(fresh.bin, 'wundervault-agent')}, the copy this installer came with.`);
      expect(r.out).toContain(`${path.join(stale.bin, 'wundervault-agent')} comes first on PATH but is a different copy`);
      expect(r.err).toBe('');
    });

    it('says nothing extra when its own copy is the one on PATH', () => {
      const fresh = prefix('usr');
      const r = run(which, path.join(fresh.pkg, 'packaging'), [fresh.bin]);
      expect(r.exec).toBe(path.join(fresh.bin, 'wundervault-agent'));
      expect(r.out).not.toContain('note:');
      expect(r.err).toBe('');
    });

    it('finds its own launcher even when no copy is on PATH (sudo\'s PATH lacks the prefix)', () => {
      const fresh = prefix('opt');
      const r = run(which, path.join(fresh.pkg, 'packaging'), []);
      expect(r.exec).toBe(path.join(fresh.bin, 'wundervault-agent'));
    });

    it('falls back to PATH with a warning naming both when its own launcher is missing', () => {
      const fresh = prefix('usr', false);
      const stale = prefix('usr-local');
      const r = run(which, path.join(fresh.pkg, 'packaging'), [stale.bin]);
      expect(r.exec).toBe(path.join(stale.bin, 'wundervault-agent'));
      expect(r.err).toContain(`WARNING: no wundervault-agent launcher found for the copy at ${fresh.pkg},`);
      expect(r.err).toContain(`so this installs ${path.join(stale.bin, 'wundervault-agent')} from PATH`);
    });

    it('leaves EXEC empty when there is no copy anywhere (the script then says how to install one)', () => {
      const fresh = prefix('usr', false);
      const r = run(which, path.join(fresh.pkg, 'packaging'), []);
      expect(r.exec).toBe('');
    });

    it('lets --exec win: the picker only runs when EXEC is still empty', () => {
      const text = fs.readFileSync(SCRIPTS[which], 'utf8');
      expect(text).toMatch(/# <<< pick the broker\nif \[ -z "\$EXEC" \]; then\n {2}pick_broker "\$HERE"\nfi/);
    });
  });

  describe(`the ${which} installer ends with the next steps, in order`, () => {
    const text = fs.readFileSync(SCRIPTS[which], 'utf8');
    const echoes = text.split('\n').filter((l) => /^\s*echo /.test(l));

    it('mentions --migrate once, inside the block, after the pair line', () => {
      const migrate = echoes.filter((l) => l.includes('--migrate'));
      expect(migrate).toHaveLength(1);
      const pairAt = echoes.findIndex((l) => l.includes('1. Pair this computer, once:   sudo ${AGENT_CMD} --pair'));
      const nextAt = echoes.findIndex((l) => l.includes('Next, in this order:'));
      expect(nextAt).toBeGreaterThan(-1);
      expect(pairAt).toBe(nextAt + 1);
      expect(echoes.indexOf(migrate[0])).toBeGreaterThan(pairAt);
    });

    it('prints nothing after the block on success, and no other "Next" line anywhere', () => {
      const ok = between(text, 'echo "Next, in this order:"', '\nelse\n').slice(0, -'\nelse\n'.length);
      expect(ok.trim().split('\n').pop()).toContain('${AGENT_CMD} --migrate');
      expect(echoes.filter((l) => /Next[,:]/.test(l))).toHaveLength(1);
    });
  });
}

describe('the next steps use the short command only when it runs the installed copy', () => {
  for (const which of ['linux', 'macos'] as const) {
    it(`${which}: short when PATH finds that copy; full path for an older copy first, none on PATH, or a space`, () => {
      const text = fs.readFileSync(SCRIPTS[which], 'utf8');
      const block = between(text, '  AGENT_CMD=wundervault-agent', 'echo "Next, in this order:"');
      const helper = which === 'macos' ? between(text, 'real_path() {', '\n}\n') + '\n' : '';
      const fresh = prefix('usr');
      const stale = prefix('usr-local');
      const spaced = prefix('Vault Tools');
      const file = path.join(tmp, 'next.sh');
      fs.writeFileSync(file, `${helper}EXEC="$1"\n${block}\nprintf 'CMD=%s\\n' "$AGENT_CMD"\n`);
      const tools = path.join(tmp, 'tools2');
      fs.mkdirSync(tools);
      for (const t of ['readlink', 'dirname', 'basename']) {
        fs.symlinkSync(spawnSync('sh', ['-c', `command -v ${t}`], { encoding: 'utf8' }).stdout.trim(), path.join(tools, t));
      }
      const go = (exec: string, dirs: string[]) => spawnSync('/bin/sh', ['-eu', file, exec],
        { encoding: 'utf8', env: { PATH: [...dirs, tools].join(':') } }).stdout;
      const own = path.join(fresh.bin, 'wundervault-agent');
      expect(go(own, [fresh.bin])).toContain('CMD=wundervault-agent\n');
      const olderFirst = go(own, [stale.bin, fresh.bin]);
      expect(olderFirst).toContain(`CMD=${own}`);
      expect(olderFirst).toContain(`wundervault-agent on PATH (${path.join(stale.bin, 'wundervault-agent')}) is a different copy`);
      const nowhere = go(own, []);
      expect(nowhere).toContain(`CMD=${own}`);
      expect(nowhere).toContain("isn't on PATH here");
      const sp = path.join(spaced.bin, 'wundervault-agent');
      expect(go(sp, [])).toContain(`CMD="${sp}"`);
    });
  }
});
