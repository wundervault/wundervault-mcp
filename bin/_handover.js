'use strict';

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');
const url = require('url');

function installRoot(platform) {
  return platform === 'win32'
    ? path.win32.join(process.env.ProgramFiles || 'C:\\Program Files', 'Wundervault')
    : '/opt/wundervault';
}

function aclMayAllowChange(q, platform, exec, timeout) {
  try {
    const output = exec('/bin/ls', [platform === 'darwin' ? '-lde' : '-ld', q], {
      encoding: 'utf8',
      timeout: timeout
    });
    if (platform === 'darwin') {
      return output.split('\n').slice(1).some(function (line) {
        return /allow.*(write|add_file|add_subdirectory|delete|append|chown|security)/.test(line);
      });
    }
    return output.charAt(10) === '+';
  } catch (error) {
    return true;
  }
}

function monotonicNow() {
  const time = process.hrtime();
  return time[0] * 1000 + time[1] / 1000000;
}

// All paths in one plan share the ACL cache and its five-second budget.
function aclChecker(platform, exec) {
  const seen = new Map();
  const deadline = monotonicNow() + 5000;
  return function (q) {
    if (seen.has(q)) return seen.get(q);
    const left = deadline - monotonicNow();
    const result = left < 1
      ? true
      : aclMayAllowChange(q, platform, exec, Math.floor(Math.min(5000, left)));
    seen.set(q, result);
    return result;
  };
}

function rootOnly(p, files, aclAllows) {
  const paths = path.posix;
  if (!paths.isAbsolute(p)) return false;
  function safe(st) {
    return st.uid === 0 && (st.mode & 0o022) === 0;
  }
  try {
    if (!safe(files.lstatSync('/')) || aclAllows('/')) return false;
    let cur = '/';
    const rest = p.split('/').filter(Boolean);
    let hops = 0;
    while (rest.length) {
      const component = rest.shift();
      if (component === '.') continue;
      if (component === '..') {
        cur = paths.dirname(cur);
        continue;
      }
      const next = paths.join(cur, component);
      const st = files.lstatSync(next);
      if (st.isSymbolicLink()) {
        if (++hops > 40) return false;
        const target = files.readlinkSync(next, 'utf8');
        if (paths.isAbsolute(target)) cur = '/';
        rest.unshift.apply(rest, target.split('/').filter(Boolean));
        continue;
      }
      if (!safe(st) || aclAllows(next)) return false;
      cur = next;
    }
    return true;
  } catch (error) {
    return false;
  }
}

function self(reason) {
  return reason ? { mode: 'self', reason: reason } : { mode: 'self' };
}

function inside(paths, root, candidate, windows) {
  const base = paths.resolve(root);
  const name = paths.resolve(candidate);
  const relative = paths.relative(
    windows ? base.toLowerCase() : base,
    windows ? name.toLowerCase() : name
  );
  return relative.indexOf('..') !== 0 && !paths.isAbsolute(relative);
}

// Read no more than 4097 bytes, even if the descriptor is unexpectedly large.
function readActive(files, filename) {
  const fd = files.openSync(filename, 'r');
  try {
    const buffer = Buffer.alloc(4097);
    let length = 0;
    while (length < buffer.length) {
      const count = files.readSync(fd, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > 4096) return null;
    let text = buffer.toString('utf8', 0, length).replace(/\r\n/g, '\n');
    if (text.charAt(text.length - 1) === '\n') text = text.slice(0, -1);
    const lines = text.split('\n');
    if (lines.length !== 2) return null;
    const node = /^set "WV_NODE=(.+)"$/.exec(lines[0]);
    const app = /^set "WV_APP=(.+)"$/.exec(lines[1]);
    if (!node || !app || /\r/.test(text)) return null;
    return { node: node[1], app: app[1] };
  } finally {
    files.closeSync(fd);
  }
}

// fs and exec are injectable; isRootOnly can replace the POSIX trust walk in tests.
function plan(opts) {
  opts = opts || {};
  const platform = opts.platform || process.platform;
  const paths = platform === 'win32' ? path.win32 : path.posix;
  const root = opts.installRoot || installRoot(platform);
  const packageRoot = opts.packageRoot || path.dirname(__dirname);
  const files = opts.fs || fs;
  const exec = opts.exec || childProcess.execFileSync;
  const ownName = opts.ownName;

  try {
    if (inside(paths, root, files.realpathSync(packageRoot), platform === 'win32')) {
      return self();
    }
    if (ownName !== 'wundervault-mcp' && ownName !== 'wundervault-agent') {
      return self('invalid launcher name');
    }

    if (platform === 'win32') {
      const bin = paths.join(root, 'bin');
      const active = readActive(files, paths.join(bin, 'active.cmd'));
      if (!active) return self('malformed active.cmd');
      if (!paths.isAbsolute(active.node) || !paths.isAbsolute(active.app)) {
        return self('active.cmd paths are not absolute');
      }
      const node = paths.resolve(active.node);
      const target = paths.resolve(active.app, 'bin', ownName);
      if (!inside(paths, root, target, true)) {
        return self('active.cmd target is outside the install root');
      }
      if (!inside(paths, root, node, true) && paths.basename(node).toLowerCase() !== 'node.exe') {
        return self('active.cmd node is not an allowed node.exe');
      }
      if (files.lstatSync(root).isSymbolicLink() ||
          files.lstatSync(bin).isSymbolicLink() ||
          files.lstatSync(target).isSymbolicLink()) {
        return self('handover path is a symbolic link or reparse point');
      }
      if (!files.statSync(node).isFile() || !files.statSync(target).isFile()) {
        return self('handover executable is not a file');
      }
      return { mode: 'handover', node: node, target: target };
    }

    if (platform !== 'linux' && platform !== 'darwin') {
      return self('unsupported handover platform');
    }
    const current = files.readlinkSync(paths.join(root, 'current'), 'utf8');
    const prefix = paths.join(root, 'versions') + '/';
    let relative = current;
    if (paths.isAbsolute(current)) {
      if (current.indexOf(prefix) !== 0) return self('current is outside versions');
      relative = 'versions/' + current.slice(prefix.length);
    }
    if (!/^versions\/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(relative)) {
      return self('malformed current version');
    }
    const versionDir = paths.join(root, relative);
    const node = paths.join(versionDir, 'node');
    const target = paths.join(versionDir, 'app', 'bin', ownName);
    const acl = aclChecker(platform, exec);
    const isRootOnly = opts.isRootOnly || function (q) {
      return rootOnly(q, files, acl);
    };
    if (!isRootOnly(versionDir) || !isRootOnly(node) || !isRootOnly(target)) {
      return self('handover path is not root-only');
    }
    if (!files.statSync(versionDir).isDirectory() ||
        !files.statSync(node).isFile() ||
        !files.statSync(target).isFile()) {
      return self('handover paths have unexpected file types');
    }
    return { mode: 'handover', node: node, target: target };
  } catch (error) {
    return self('handover files are missing or unreadable');
  }
}

function debug(reason) {
  if (reason && process.env.WUNDERVAULT_DEBUG_HANDOVER) {
    process.stderr.write('Wundervault handover: ' + reason + '\n');
  }
}

function run(entry, ownName) {
  const packageRoot = path.dirname(__dirname);

  function runOwn(reason) {
    debug(reason);
    return import(url.pathToFileURL(path.join(packageRoot, 'dist', entry + '.js')).href)
      .catch(function (error) {
        process.stderr.write(String(error && error.stack ? error.stack : error) + '\n');
        process.exitCode = 1;
      });
  }

  const result = plan({ packageRoot: packageRoot, ownName: ownName });
  if (result.mode === 'self') return runOwn(result.reason);

  let child;
  try {
    child = childProcess.spawn(result.node, [result.target].concat(process.argv.slice(2)), {
      stdio: 'inherit',
      env: process.env,
      windowsHide: true
    });
  } catch (error) {
    return runOwn('could not start the installed launcher');
  }

  let settled = false;
  const signals = process.platform === 'win32'
    ? ['SIGINT', 'SIGTERM']
    : ['SIGINT', 'SIGTERM', 'SIGHUP'];
  const handlers = {};
  signals.forEach(function (signal) {
    handlers[signal] = function () {
      try {
        child.kill(signal);
      } catch (error) {
        // The child may already have exited.
      }
    };
    process.on(signal, handlers[signal]);
  });

  function removeHandlers() {
    signals.forEach(function (signal) {
      process.removeListener(signal, handlers[signal]);
    });
  }

  child.once('error', function () {
    if (settled) return;
    settled = true;
    removeHandlers();
    runOwn('could not start the installed launcher');
  });
  child.once('exit', function (code, signal) {
    if (settled) return;
    settled = true;
    removeHandlers();
    if (signal) {
      try {
        process.kill(process.pid, signal);
      } catch (error) {
        process.exit(1);
      }
      return;
    }
    process.exit(typeof code === 'number' ? code : 1);
  });
}

module.exports = { plan: plan, run: run };
