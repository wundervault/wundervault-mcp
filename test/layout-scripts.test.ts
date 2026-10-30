import { spawnSync } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
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
const packaging = join(root, 'packaging');
const script = join(packaging, 'layout-posix.sh');
const posix = readFileSync(script, 'utf8');
const windows = readFileSync(join(packaging, 'layout-windows.ps1'), 'utf8');
const hasSh = existsSync('/bin/sh');
const shellcheckProbe = spawnSync('shellcheck', ['--version'], { encoding: 'utf8' });
const hasShellcheck = !shellcheckProbe.error && shellcheckProbe.status === 0;

describe('update layout scripts', () => {
  it.skipIf(!hasSh)('is valid POSIX shell syntax', () => {
    const result = spawnSync('/bin/sh', ['-n', script], { encoding: 'utf8' });
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
  });

  it.skipIf(!hasShellcheck)('passes shellcheck', () => {
    const result = spawnSync('shellcheck', ['--shell=sh', script], {
      encoding: 'utf8',
    });
    expect(result.stdout + result.stderr).toBe('');
    expect(result.status).toBe(0);
  });

  it('does not invoke filesystem or service programs by bare name', () => {
    const bare = /(?:^|[;&|()]|\bthen\b|\bdo\b)\s*(?:cp|mv|ln|rm|chown|chmod|find|id|systemctl|launchctl|readlink|mkdir|cat|sed|grep)(?=\s|$)/;
    for (const line of posix.split('\n')) {
      if (line.trimStart().startsWith('#')) continue;
      expect(line, `bare command in: ${line}`).not.toMatch(bare);
    }
    expect(posix).toContain('set -eu');
    expect(posix).toContain('/usr/bin/systemctl');
    expect(posix).toContain('/bin/systemctl');
    expect(posix).toContain('/bin/launchctl');
    expect(posix).toContain('/usr/bin/readlink');
    expect(posix).toContain('root cannot use WV_LAYOUT_TEST_PREFIX');
    expect(posix).not.toMatch(/\beval\b/);
  });

  it('defines the required Linux updater service and timer', () => {
    const service = readFileSync(join(packaging, 'wundervault-update.service'), 'utf8');
    const timer = readFileSync(join(packaging, 'wundervault-update.timer'), 'utf8');
    for (const line of [
      '[Unit]',
      'After=network-online.target',
      'Wants=network-online.target',
      '[Service]',
      'Type=oneshot',
      'User=root',
      'ExecStart=/opt/wundervault/current/node /opt/wundervault/current/app/dist/updater.js',
      'TimeoutStartSec=15min',
      'Environment=',
      'UMask=0022',
      'NoNewPrivileges=yes',
      'PrivateTmp=yes',
    ]) {
      expect(service.split('\n')).toContain(line);
    }
    expect(service).toMatch(/^Description=.+$/m);
    for (const line of [
      '[Timer]',
      'OnBootSec=60',
      'OnUnitInactiveSec=60',
      'AccuracySec=5s',
      'Unit=wundervault-update.service',
      '[Install]',
      'WantedBy=timers.target',
    ]) {
      expect(timer.split('\n')).toContain(line);
    }
  });

  it('defines the required root LaunchDaemon without an environment', () => {
    const plist = readFileSync(join(packaging, 'com.wundervault.update.plist'), 'utf8');
    for (const text of [
      '<key>Label</key>\n    <string>com.wundervault.update</string>',
      '<string>/opt/wundervault/current/node</string>',
      '<string>/opt/wundervault/current/app/dist/updater.js</string>',
      '<key>RunAtLoad</key>\n    <true/>',
      '<key>StartInterval</key>\n    <integer>60</integer>',
      '<key>ExitTimeOut</key>\n    <integer>30</integer>',
      '<key>StandardOutPath</key>\n    <string>/var/log/wundervault-update.log</string>',
      '<key>StandardErrorPath</key>\n    <string>/var/log/wundervault-update.log</string>',
    ]) {
      expect(plist).toContain(text);
    }
    expect(plist).not.toContain('<key>UserName</key>');
    expect(plist).not.toContain('<key>EnvironmentVariables</key>');
  });

  it('uses explicit Windows permissions and absolute program paths', () => {
    expect(windows).toContain("$ErrorActionPreference = 'Stop'");
    // Review round 1 (B-B1): Node opens O_WRONLY as GENERIC_WRITE, so the broker needs Read, Write and
    // Synchronize on request.json — still never Delete, ChangePermissions or TakeOwnership.
    expect(windows).toMatch(/FileSystemRights\]'Read, Write, Synchronize'/);
    expect(windows).toContain('-Broker $BrokerSid -Request $true');
    expect(windows).toContain('[int64]$BrokerRules[0].FileSystemRights -ne [int64]$Allowed');
    expect(windows).toContain('Broker must have no rights on the spool directory.');
    expect(windows).toContain("Join-Path $env:SystemRoot 'System32\\icacls.exe'");
    expect(windows).toContain("Join-Path $env:SystemRoot 'System32\\cmd.exe'");
    expect(windows).toContain('& $Icacls $Path /setowner');
    expect(windows).toContain('New-ScheduledTaskAction -Execute $Cmd');
    expect(windows).not.toMatch(/^\s*(?:&\s*)?(?:icacls|cmd|schtasks)(?:\.exe)?\s/im);
    expect(windows).toContain("-UserId 'S-1-5-18'");
    expect(windows).toContain('-LogonType ServiceAccount -RunLevel Highest');
    expect(windows).toContain('-MultipleInstances IgnoreNew');
    expect(windows).toContain('-RepetitionInterval (New-TimeSpan -Minutes 1)');
    expect(windows).toContain('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');
  });

  it.skipIf(process.platform !== 'linux' || process.getuid?.() !== 0)(
    'never accepts a test redirect as root',
    () => {
      const result = spawnSync('/bin/sh', [script, 'uninstall', '--platform', 'linux'], {
        encoding: 'utf8',
        env: { ...process.env, WV_LAYOUT_TEST_PREFIX: '/tmp/wv-must-not-be-used' },
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('root cannot use WV_LAYOUT_TEST_PREFIX');
    },
  );

  it.skipIf(process.platform !== 'linux' || process.getuid?.() === undefined || process.getuid?.() === 0)(
    'installs, reruns, and uninstalls in a non-root fake layout',
    () => {
      const prefix = mkdtempSync(join(tmpdir(), 'wv-layout-'));
      try {
        const pkg = join(prefix, 'package');
        const launchers = join(prefix, 'launchers');
        const installed = join(prefix, 'opt/wundervault');
        const spool = join(prefix, 'var/lib/wundervault-update');
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
        symlinkSync('../../bin/wundervault-mcp', join(pkg, 'node_modules/.bin/mcp'));

        const mcp = join(launchers, 'wundervault-mcp');
        const agent = join(launchers, 'wundervault-agent');
        writeFileSync(mcp, 'original MCP launcher\n');
        symlinkSync(join(pkg, 'bin/wundervault-agent'), agent);

        const env = { ...process.env, WV_LAYOUT_TEST_PREFIX: prefix };
        for (const name of ['NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_REPL_EXTERNAL_MODULE']) {
          delete env[name as keyof typeof env];
        }
        const account = spawnSync('/usr/bin/id', ['-un'], { encoding: 'utf8' });
        expect(account.status).toBe(0);
        const installArgs = [
          script, 'install', '--platform', 'linux',
          '--account', account.stdout.trim(),
          '--node', process.execPath,
          '--pkg', pkg,
          '--version', '3.0.0',
          '--launchers', `${mcp} ${agent}`,
        ];
        const run = (args: string[]) => spawnSync('/bin/sh', args, { env, encoding: 'utf8' });
        const first = run(installArgs);
        expect(first.stderr).toBe('');
        expect(first.status).toBe(0);
        expect(first.stdout.trim().split('\n').at(-1)).toBe(
          `SERVICE_NODE=${installed}/current/node EXEC=${installed}/current/app/bin/wundervault-agent`,
        );
        expect(readlinkSync(join(installed, 'current'))).toBe('versions/3.0.0');
        expect(readlinkSync(join(installed, 'versions/3.0.0/node'))).toBe(process.execPath);
        expect(existsSync(join(installed, 'versions/3.0.0/app/node_modules/.bin'))).toBe(false);
        expect(lstatSync(join(installed, 'state')).mode & 0o777).toBe(0o700);
        expect(lstatSync(join(installed, 'state/manifest.json')).mode & 0o777).toBe(0o600);
        expect(lstatSync(join(spool, 'request.json')).mode & 0o777).toBe(0o620);
        expect(readFileSync(join(spool, 'request.json'), 'utf8')).toBe('');
        expect(readFileSync(join(spool, 'status.json'), 'utf8').trim()).toBe('{}');
        expect(readlinkSync(mcp)).toBe(join(installed, 'bin/wundervault-mcp'));
        expect(readlinkSync(agent)).toBe(join(installed, 'bin/wundervault-agent'));
        expect(readFileSync(join(installed, 'bin/wundervault-agent'), 'utf8')).toContain(
          'app/bin/wundervault-agent',
        );
        const manifest = JSON.parse(readFileSync(join(installed, 'state/manifest.json'), 'utf8'));
        expect(manifest.format).toBe('wundervault-layout-1');
        expect(manifest.launchers).toEqual([
          { path: mcp, original_target: 'file' },
          { path: agent, original_target: join(pkg, 'bin/wundervault-agent') },
        ]);
        expect(manifest.paths).toContainEqual({ path: spool, kind: 'dir' });
        expect(manifest.paths).toContainEqual({
          path: join(prefix, 'etc/systemd/system/wundervault-update.timer'), kind: 'unit',
        });

        writeFileSync(join(spool, 'request.json'), '{"pending":true}');
        const second = run(installArgs);
        expect(second.stderr).toBe('');
        expect(second.status).toBe(0);
        expect(readFileSync(join(spool, 'request.json'), 'utf8')).toBe('{"pending":true}');
        expect(readFileSync(`${mcp}.wv-orig`, 'utf8')).toBe('original MCP launcher\n');

        const olderArgs = [...installArgs];
        olderArgs[olderArgs.indexOf('--version') + 1] = '2.9.9';
        expect(run(olderArgs).status).toBe(1);
        expect(readlinkSync(join(installed, 'current'))).toBe('versions/3.0.0');

        const uninstall = run([script, 'uninstall', '--platform', 'linux', '--remove-data']);
        expect(uninstall.stderr).toBe('');
        expect(uninstall.status).toBe(0);
        expect(uninstall.stdout).toContain('--remove-data is handled by the caller');
        expect(existsSync(installed)).toBe(false);
        expect(existsSync(spool)).toBe(false);
        expect(readFileSync(mcp, 'utf8')).toBe('original MCP launcher\n');
        expect(readlinkSync(agent)).toBe(join(pkg, 'bin/wundervault-agent'));
        expect(existsSync(`${mcp}.wv-orig`)).toBe(false);
        expect(existsSync(join(prefix, 'etc/systemd/system/wundervault-update.timer'))).toBe(false);
      } finally {
        rmSync(prefix, { recursive: true, force: true });
      }
    },
  );
});
