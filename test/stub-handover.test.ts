import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const require = createRequire(import.meta.url);
const { plan } = require('../bin/_handover.js');
const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const temporaryDirectories: string[] = [];

function missing(): never {
  throw new Error('missing fixture file');
}

function posixFiles(current = 'versions/2.2.0', packageRoot = '/home/person/package') {
  return {
    realpathSync: () => packageRoot,
    readlinkSync: (filename: string) => {
      if (filename === '/opt/wundervault/current') return current;
      return missing();
    },
    statSync: (filename: string) => ({
      isDirectory: () => filename === '/opt/wundervault/versions/2.2.0',
      isFile: () => filename !== '/opt/wundervault/versions/2.2.0'
    })
  };
}

function posixPlan(overrides: Record<string, unknown> = {}) {
  return plan({
    platform: 'linux',
    installRoot: '/opt/wundervault',
    packageRoot: '/home/person/package',
    ownName: 'wundervault-mcp',
    fs: posixFiles(),
    isRootOnly: () => true,
    ...overrides
  });
}

const windowsRoot = 'C:\\Program Files\\Wundervault';
const windowsApp = windowsRoot + '\\versions\\2.2.0\\app';
const windowsNode = windowsRoot + '\\versions\\2.2.0\\node.exe';

function active(node = windowsNode, app = windowsApp) {
  return `set "WV_NODE=${node}"\r\nset "WV_APP=${app}"\r\n`;
}

function windowsFiles(contents: string | null) {
  const data = Buffer.from(contents || '');
  let offset = 0;
  return {
    realpathSync: () => 'C:\\Users\\person\\package',
    openSync: (filename: string) => {
      if (contents === null || filename !== windowsRoot + '\\bin\\active.cmd') return missing();
      offset = 0;
      return 1;
    },
    readSync: (_fd: number, buffer: Buffer, start: number, length: number) => {
      const count = Math.min(length, data.length - offset);
      data.copy(buffer, start, offset, offset + count);
      offset += count;
      return count;
    },
    closeSync: () => undefined,
    lstatSync: () => ({ isSymbolicLink: () => false }),
    statSync: () => ({ isFile: () => true })
  };
}

function windowsPlan(contents: string | null = active(), overrides: Record<string, unknown> = {}) {
  return plan({
    platform: 'win32',
    installRoot: windowsRoot,
    packageRoot: 'C:\\Users\\person\\package',
    ownName: 'wundervault-agent',
    fs: windowsFiles(contents),
    ...overrides
  });
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('stub handover plan', () => {
  it('runs its own entry when the real package root is already installed', () => {
    expect(posixPlan({
      fs: posixFiles('versions/9.9.9', '/opt/wundervault/versions/2.2.0/app')
    })).toEqual({ mode: 'self' });
  });

  it('does not confuse a sibling directory with the install root', () => {
    expect(posixPlan({
      fs: posixFiles('versions/2.2.0', '/opt/wundervault-other/app')
    }).mode).toBe('handover');
  });

  it.each(['linux', 'darwin'])('resolves %s current once into explicit version paths', (platform) => {
    const checks: string[] = [];
    let reads = 0;
    const files = posixFiles();
    const readlink = files.readlinkSync;
    files.readlinkSync = (filename: string) => {
      reads++;
      return readlink(filename);
    };
    expect(posixPlan({
      platform,
      fs: files,
      isRootOnly: (filename: string) => {
        checks.push(filename);
        return true;
      }
    })).toEqual({
      mode: 'handover',
      node: '/opt/wundervault/versions/2.2.0/node',
      target: '/opt/wundervault/versions/2.2.0/app/bin/wundervault-mcp'
    });
    expect(reads).toBe(1);
    expect(checks).toEqual([
      '/opt/wundervault/versions/2.2.0',
      '/opt/wundervault/versions/2.2.0/node',
      '/opt/wundervault/versions/2.2.0/app/bin/wundervault-mcp'
    ]);
  });

  it('accepts the absolute equivalent of the version descriptor', () => {
    expect(posixPlan({
      fs: posixFiles('/opt/wundervault/versions/2.2.0')
    }).mode).toBe('handover');
  });

  it.each([
    '/tmp/versions/2.2.0',
    '../versions/2.2.0',
    'elsewhere/2.2.0',
    'versions/../2.2.0',
    'versions/2.2',
    'versions/2.2.0-beta',
    'versions/02.2.0',
    'versions/2.2.0/extra',
    'versions/2.2.0\n'
  ])('rejects an outside or malformed current descriptor: %s', (current) => {
    expect(posixPlan({ fs: posixFiles(current) }).mode).toBe('self');
  });

  it('falls back if any handover path is untrusted', () => {
    expect(posixPlan({ isRootOnly: () => false })).toMatchObject({
      mode: 'self',
      reason: 'handover path is not root-only'
    });
  });

  it('falls back when the descriptor is missing', () => {
    expect(posixPlan({
      fs: { realpathSync: () => '/home/person/package', readlinkSync: missing }
    }).mode).toBe('self');
  });

  it('uses Windows active.cmd paths without a shell', () => {
    expect(windowsPlan()).toEqual({
      mode: 'handover',
      node: windowsNode,
      target: windowsApp + '\\bin\\wundervault-agent'
    });
  });

  it('compares Windows install paths case-insensitively', () => {
    expect(windowsPlan(active(windowsNode.toUpperCase(), windowsApp.toUpperCase())).mode)
      .toBe('handover');
  });

  it('permits an existing external bootstrap node.exe', () => {
    expect(windowsPlan(active('C:\\Program Files\\nodejs\\node.exe')).mode).toBe('handover');
  });

  it('rejects an external Windows node with another filename', () => {
    expect(windowsPlan(active('C:\\Tools\\other.exe')).mode).toBe('self');
  });

  it.each([
    active() + 'echo extra\r\n',
    active() + '\r\n',
    'set "WV_NODE=relative\\node.exe"\nset "WV_APP=' + windowsApp + '"',
    'set "WV_NODE=' + windowsNode + '"',
    'x'.repeat(4097),
    null
  ])('rejects an extra line, malformed, oversized or missing active.cmd', (contents) => {
    expect(windowsPlan(contents).mode).toBe('self');
  });

  it.each([
    'C:\\Users\\person\\app',
    windowsRoot + '-other\\app',
    windowsRoot + '\\..\\outside\\app'
  ])('rejects a Windows target outside the install root: %s', (app) => {
    expect(windowsPlan(active(windowsNode, app)).mode).toBe('self');
  });

  it.each([
    windowsRoot,
    windowsRoot + '\\bin',
    windowsApp + '\\bin\\wundervault-agent'
  ])('rejects a Windows symbolic link or junction at %s', (linked) => {
    const files = windowsFiles(active());
    files.lstatSync = (filename?: string) => ({
      isSymbolicLink: () => filename === linked
    });
    expect(windowsPlan(active(), { fs: files }).mode).toBe('self');
  });

  it('rejects a missing Windows node', () => {
    const files = windowsFiles(active());
    files.statSync = missing;
    expect(windowsPlan(active(), { fs: files }).mode).toBe('self');
  });
});

describe('real startup stubs', () => {
  it.each([
    ['wundervault-mcp', 'index'],
    ['wundervault-agent', 'agent']
  ])('imports its own dist entry from %s when there is no install descriptor', (ownName, entry) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-stub-'));
    temporaryDirectories.push(directory);
    const bin = path.join(directory, 'bin');
    const dist = path.join(directory, 'dist');
    fs.mkdirSync(bin);
    fs.mkdirSync(dist);
    fs.writeFileSync(path.join(directory, 'package.json'), '{"type":"module"}');
    for (const filename of ['package.json', '_handover.js', ownName]) {
      fs.copyFileSync(path.join(repositoryRoot, 'bin', filename), path.join(bin, filename));
    }

    const marker = path.join(directory, 'imported.json');
    fs.writeFileSync(path.join(dist, entry + '.js'),
      'import fs from "node:fs";\n' +
      'fs.writeFileSync(' + JSON.stringify(marker) + ', JSON.stringify(process.argv.slice(1)));\n');

    // Simulate a missing descriptor even on a developer machine with a real broker installed.
    const preload = path.join(directory, 'no-install.cjs');
    const descriptor = process.platform === 'win32'
      ? path.win32.join(process.env.ProgramFiles || 'C:\\Program Files',
        'Wundervault', 'bin', 'active.cmd')
      : '/opt/wundervault/current';
    fs.writeFileSync(preload,
      'const fs = require("fs");\n' +
      'const descriptor = ' + JSON.stringify(descriptor) + ';\n' +
      'for (const name of ["readlinkSync", "openSync"]) {\n' +
      '  const original = fs[name];\n' +
      '  fs[name] = function (filename) {\n' +
      '    if (filename === descriptor) {\n' +
      '      const error = new Error("no installed descriptor");\n' +
      '      error.code = "ENOENT";\n' +
      '      throw error;\n' +
      '    }\n' +
      '    return original.apply(this, arguments);\n' +
      '  };\n' +
      '}\n');

    const stub = path.join(bin, ownName);
    const env = { ...process.env };
    delete env.NODE_OPTIONS;
    delete env.WUNDERVAULT_DEBUG_HANDOVER;
    const result = spawnSync(process.execPath, ['--require', preload, stub, 'kept-argument'], {
      env,
      encoding: 'utf8',
      timeout: 10000,
      windowsHide: true
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('');
    expect(JSON.parse(fs.readFileSync(marker, 'utf8'))).toEqual([stub, 'kept-argument']);
  });
});
