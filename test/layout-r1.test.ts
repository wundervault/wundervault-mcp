import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const script = join(root, 'packaging/layout-posix.sh');
const windows = readFileSync(join(root, 'packaging/layout-windows.ps1'), 'utf8');
const canRun = process.platform === 'linux' &&
  process.getuid?.() !== undefined && process.getuid?.() !== 0 &&
  existsSync('/bin/sh');

function fixture() {
  const prefix = mkdtempSync(join(tmpdir(), 'wv-layout-r1-'));
  const pkg = join(prefix, 'node_modules/@wundervault/mcp-server');
  const launchers = join(prefix, 'launchers');
  const installed = join(prefix, 'opt/wundervault');
  const mcp = join(launchers, 'wundervault-mcp');
  const agent = join(launchers, 'wundervault-agent');
  mkdirSync(join(pkg, 'bin'), { recursive: true });
  mkdirSync(join(pkg, 'dist'), { recursive: true });
  mkdirSync(join(pkg, 'node_modules/.bin'), { recursive: true });
  mkdirSync(launchers);
  mkdirSync(join(prefix, 'usr/bin'), { recursive: true });
  writeFileSync(join(prefix, 'usr/bin/systemctl'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  writeFileSync(join(pkg, 'package.json'), '{"name":"layout-fixture","version":"3.0.0"}\n');
  writeFileSync(join(pkg, 'dist/updater.js'), '');
  writeFileSync(join(pkg, 'bin/wundervault-mcp'), '');
  writeFileSync(join(pkg, 'bin/wundervault-agent'), '');
  writeFileSync(mcp, 'original MCP launcher\n');
  symlinkSync(join(pkg, 'bin/wundervault-agent'), agent);

  const env = { ...process.env, WV_LAYOUT_TEST_PREFIX: prefix };
  for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_REPL_EXTERNAL_MODULE']) {
    delete env[name as keyof typeof env];
  }
  const account = spawnSync('/usr/bin/id', ['-un'], { encoding: 'utf8' });
  expect(account.status).toBe(0);

  return {
    prefix,
    pkg,
    installed,
    mcp,
    agent,
    run(version = '3.0.0') {
      return spawnSync('/bin/sh', [
        script, 'install', '--platform', 'linux',
        '--account', account.stdout.trim(),
        '--node', process.execPath,
        '--pkg', pkg,
        '--version', version,
        '--launchers', `${mcp} ${agent}`,
      ], { env, encoding: 'utf8', timeout: 140_000 });
    },
    cleanup() {
      rmSync(prefix, { recursive: true, force: true });
    },
  };
}

describe('round 1 Windows layout boundaries', () => {
  it('replaces existing descriptors atomically and moves new files without forcing', () => {
    const writer = windows.slice(
      windows.indexOf('function Write-LayoutFile {'),
      windows.indexOf("if ($Action -eq 'uninstall') {"),
    );
    expect(writer).toContain('if ([System.IO.File]::Exists($Path))');
    expect(writer).toContain('[System.IO.File]::Replace($Temp, $Path, $null)');
    expect(writer).toContain('[System.IO.File]::Move($Temp, $Path)');
    expect(writer).not.toContain('Move-Item');
    expect(windows).not.toMatch(/Move-Item[^\r\n]*-Force/);
    expect(windows).toContain('Write-LayoutFile $Active (');
    expect(windows).toContain('[System.IO.File]::Replace($Temp, $ManifestPath, $null)');
  });

  it('grants and verifies exactly Read, Write, Synchronize without destructive rights', () => {
    expect(windows).toContain(
      "$RequestRights = [System.Security.AccessControl.FileSystemRights]'Read, Write, Synchronize'",
    );
    expect(windows).toContain(
      "$Allowed = [System.Security.AccessControl.FileSystemRights]'Read, Write, Synchronize'",
    );
    expect(windows).toContain(
      "$Forbidden = [System.Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'",
    );
    expect(windows).toContain('$Broker, $RequestRights,');
    expect(windows).toContain('-Broker $BrokerSid -Request $true');
    expect(windows).toContain('[int64]$BrokerRules[0].FileSystemRights -ne [int64]$Allowed');
    expect(windows).toContain(
      '([int64]$BrokerRules[0].FileSystemRights -band [int64]$Forbidden) -ne 0',
    );
    expect(windows).toContain('Broker request permissions are not exactly Read, Write, Synchronize.');
    expect(windows).toContain('Broker must have no rights on the spool directory.');
  });
});

describe.skipIf(!canRun)('round 1 non-root POSIX layouts', () => {
  it('captures an npm-recreated launcher over its old backup on rerun', () => {
    const f = fixture();
    try {
      const first = f.run();
      expect(first.stderr).toBe('');
      expect(first.status).toBe(0);
      expect(existsSync(join(f.installed, 'state/lock'))).toBe(false);

      rmSync(f.mcp);
      const npmTarget = join(f.pkg, 'bin/wundervault-mcp');
      symlinkSync(npmTarget, f.mcp);
      const second = f.run('3.1.0');
      expect(second.stderr).toBe('');
      expect(second.status).toBe(0);
      expect(readlinkSync(join(f.installed, 'current'))).toBe('versions/3.1.0');
      expect(readlinkSync(f.mcp)).toBe(join(f.installed, 'bin/wundervault-mcp'));
      expect(readlinkSync(`${f.mcp}.wv-orig`)).toBe(npmTarget);
      const manifest = JSON.parse(readFileSync(join(f.installed, 'state/manifest.json'), 'utf8'));
      expect(manifest.launchers).toContainEqual({
        path: f.mcp,
        original_target: npmTarget,
      });
      expect(manifest.paths).toContainEqual({ path: `${f.mcp}.wv-orig`, kind: 'link' });
      expect(existsSync(join(f.installed, 'state/lock'))).toBe(false);
      expect(readdirSync(join(f.installed, 'state')).some(name => name.startsWith('lock.tmp.'))).toBe(false);
    } finally {
      f.cleanup();
    }
  });

  it('refuses a foreign launcher before changing current, highest, or either backup', () => {
    const f = fixture();
    try {
      const first = f.run();
      expect(first.stderr).toBe('');
      expect(first.status).toBe(0);
      const manifestPath = join(f.installed, 'state/manifest.json');
      const highestPath = join(f.installed, 'state/highest.json');
      const manifest = readFileSync(manifestPath, 'utf8');
      const highest = readFileSync(highestPath, 'utf8');

      // The first launcher is eligible for recapture, but the second invalidates the whole plan.
      rmSync(f.mcp);
      const npmTarget = join(f.pkg, 'bin/wundervault-mcp');
      symlinkSync(npmTarget, f.mcp);
      rmSync(f.agent);
      writeFileSync(f.agent, 'foreign launcher\n');

      const result = f.run('3.1.0');
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('launcher changed since installation');
      expect(readlinkSync(join(f.installed, 'current'))).toBe('versions/3.0.0');
      expect(readFileSync(highestPath, 'utf8')).toBe(highest);
      expect(readFileSync(manifestPath, 'utf8')).toBe(manifest);
      expect(existsSync(join(f.installed, 'versions/3.1.0'))).toBe(false);
      expect(readlinkSync(f.mcp)).toBe(npmTarget);
      expect(readFileSync(`${f.mcp}.wv-orig`, 'utf8')).toBe('original MCP launcher\n');
      expect(readFileSync(f.agent, 'utf8')).toBe('foreign launcher\n');
      expect(readlinkSync(`${f.agent}.wv-orig`)).toBe(join(f.pkg, 'bin/wundervault-agent'));
      expect(existsSync(join(f.installed, 'state/lock'))).toBe(false);
    } finally {
      f.cleanup();
    }
  });

  it('adopts exactly the empty skeleton of an interrupted first install', () => {
    const f = fixture();
    try {
      for (const name of ['versions', 'bin', 'state']) {
        mkdirSync(join(f.installed, name), { recursive: true });
      }
      const result = f.run();
      expect(result.stderr).toBe('');
      expect(result.status).toBe(0);
      expect(readlinkSync(join(f.installed, 'current'))).toBe('versions/3.0.0');
      const manifest = JSON.parse(readFileSync(join(f.installed, 'state/manifest.json'), 'utf8'));
      expect(manifest.format).toBe('wundervault-layout-1');
      expect(manifest.paths).toContainEqual({ path: f.installed, kind: 'dir' });
      expect(existsSync(join(f.installed, 'state/lock'))).toBe(false);
    } finally {
      f.cleanup();
    }
  });

  it('does not adopt a skeleton with an extra entry', () => {
    const f = fixture();
    try {
      for (const name of ['versions', 'bin', 'state']) {
        mkdirSync(join(f.installed, name), { recursive: true });
      }
      writeFileSync(join(f.installed, 'foreign'), 'keep\n');
      const result = f.run();
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("won't adopt a folder it didn't make");
      expect(readFileSync(join(f.installed, 'foreign'), 'utf8')).toBe('keep\n');
      expect(existsSync(join(f.installed, 'state/manifest.json'))).toBe(false);
    } finally {
      f.cleanup();
    }
  });

  it('waits up to 120 seconds for a live updater lock, then fails without removing it', () => {
    const f = fixture();
    try {
      const first = f.run();
      expect(first.stderr).toBe('');
      expect(first.status).toBe(0);
      const lock = join(f.installed, 'state/lock');
      const contents = `${process.pid} ${Date.now()}\n`;
      writeFileSync(lock, contents, { mode: 0o600 });
      const manifestPath = join(f.installed, 'state/manifest.json');
      const manifest = readFileSync(manifestPath, 'utf8');
      const started = Date.now();
      const result = f.run('3.1.0');
      const elapsed = Date.now() - started;

      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('updater lock held for 120 seconds');
      expect(elapsed).toBeGreaterThanOrEqual(118_000);
      expect(elapsed).toBeLessThan(140_000);
      expect(readFileSync(lock, 'utf8')).toBe(contents);
      expect(readFileSync(manifestPath, 'utf8')).toBe(manifest);
      expect(readlinkSync(join(f.installed, 'current'))).toBe('versions/3.0.0');
      expect(existsSync(join(f.installed, 'versions/3.1.0'))).toBe(false);
      expect(readdirSync(join(f.installed, 'state')).some(name => name.startsWith('lock.tmp.'))).toBe(false);
    } finally {
      f.cleanup();
    }
  }, 150_000);
});
