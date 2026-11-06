import * as fs from 'node:fs';
import * as path from 'node:path';
import * as net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { RELEASE_KEYS } from './release-keys.js';
import {
  DEFAULT_LIMITS,
  isAllowedUrl,
  parseVersion,
  platformKey,
  type ReleaseRecord,
} from './release-verify.js';
import { extractNodeMember } from './tar-read.js';
import { connectToEndpoint } from './endpoint.js';
import type { UpdaterDeps } from './updater.js';

function syncDirectory(dir: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(dir, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EPERM', 'EISDIR', 'EBADF'].includes(
      (error as NodeJS.ErrnoException).code ?? '',
    )) throw error;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function atomicText(file: string, text: string): void {
  const temp = `${file}.tmp-${process.pid}`;
  let fd: number | undefined;
  try {
    fs.rmSync(temp, { force: true });
    fd = fs.openSync(temp, 'wx', 0o644);
    fs.writeFileSync(fd, text);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temp, file);
    syncDirectory(path.dirname(file));
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.rmSync(temp, { force: true });
  }
}

export function windowsNode(
  dir: string,
  stat: (file: string) => fs.Stats = file => fs.lstatSync(file),
): string {
  const bundled = path.join(dir, 'node.exe');
  try {
    const info = stat(bundled);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error('no node for version');
    return bundled;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  try {
    const file = path.join(dir, 'node.path');
    const info = stat(file);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 1024) {
      throw new Error('no node for version');
    }
    const bytes = fs.readFileSync(file);
    if (bytes.length === 0 || bytes.length > 1024 ||
        bytes.some(byte => byte < 32 || byte > 126)) throw new Error('no node for version');
    const node = bytes.toString('ascii');
    if (!path.win32.isAbsolute(node) ||
        !/^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\)/.test(node) ||
        !/\\node\.exe$/i.test(node) || /["%!^&|<>]/.test(node)) {
      throw new Error('no node for version');
    }
    const target = stat(node);
    if (!target.isFile() || target.isSymbolicLink()) throw new Error('no node for version');
    return node;
  } catch {
    throw new Error('no node for version');
  }
}

export function writeWindowsDescriptor(
  root: string,
  v: string,
  stat: (file: string) => fs.Stats = file => fs.lstatSync(file),
): void {
  if (parseVersion(v) === null) throw new Error('descriptor');
  const dir = path.join(root, 'versions', v);
  const node = windowsNode(dir, stat);
  if (/["\r\n%!^&|<>]/.test(node) || /["\r\n%!^&|<>]/.test(dir)) {
    throw new Error('descriptor');
  }
  atomicText(path.join(root, 'bin', 'active.cmd'),
    `set "WV_NODE=${node}"\r\nset "WV_APP=${path.join(dir, 'app')}"\r\n`);
}

function systemRoot(): string {
  const value = process.env.SystemRoot ?? 'C:\\Windows';
  if (!path.win32.isAbsolute(value) || /[\r\n"]/.test(value)) throw new Error('SystemRoot');
  return value;
}

function minimalEnv(windows: boolean): NodeJS.ProcessEnv {
  if (!windows) return { PATH: '/usr/sbin:/usr/bin:/sbin:/bin' };
  const root = systemRoot();
  return { SystemRoot: root, PATH: path.join(root, 'System32') };
}

function killTree(pid: number, windows: boolean, env: NodeJS.ProcessEnv): Promise<void> {
  if (!windows) {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
    }
    return Promise.resolve();
  }
  return new Promise(resolve => {
    const child = spawn(path.join(systemRoot(), 'System32', 'taskkill.exe'),
      ['/T', '/F', '/PID', String(pid)], { env, stdio: 'ignore', windowsHide: true });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve();
    }, 5_000);
    const finish = (): void => {
      clearTimeout(timer);
      resolve();
    };
    child.once('error', finish);
    child.once('close', finish);
  });
}

function runProgram(
  file: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  windows: boolean,
  timeoutMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    // A separate process group lets a timeout kill children as well as their parent.
    const child = spawn(file, args, {
      cwd, env, detached: !windows, stdio: 'ignore', windowsHide: true,
    });
    let settled = false;
    let timingOut = false;
    const finish = (ok: boolean): void => {
      if (settled || timingOut) return;
      settled = true;
      clearTimeout(timer);
      if (ok) resolve();
      else reject(new Error('program failed'));
    };
    const timer = setTimeout(() => {
      timingOut = true;
      const pid = child.pid;
      void (pid === undefined ? Promise.resolve() : killTree(pid, windows, env))
        .catch(() => undefined)
        .finally(() => {
          if (!settled) {
            settled = true;
            reject(new Error('program timeout'));
          }
        });
    }, timeoutMs);
    child.once('error', () => finish(false));
    child.once('close', code => finish(code === 0));
  });
}

function brokerGid(darwin: boolean, env: NodeJS.ProcessEnv): number {
  let value: string | undefined;
  if (!darwin) {
    const row = fs.readFileSync('/etc/group', 'utf8').split('\n')
      .find(line => line.startsWith('wundervault:'));
    value = row?.split(':')[2];
  } else {
    const options = {
      env, encoding: 'utf8' as const, timeout: 60_000,
      killSignal: 'SIGKILL' as const, detached: true,
    };
    const result = spawnSync('/usr/bin/dscl',
      ['.', '-read', '/Groups/_wundervault', 'PrimaryGroupID'], options);
    if (result.error) {
      if ((result.error as NodeJS.ErrnoException).code === 'ETIMEDOUT' && result.pid > 0) {
        try {
          process.kill(-result.pid, 'SIGKILL');
        } catch {
          // dscl may already have exited when its process group is killed.
        }
      }
      throw new Error('broker group');
    }
    if (result.status !== 0) throw new Error('broker group');
    value = /^PrimaryGroupID:\s*(\d+)\s*$/m.exec(result.stdout)?.[1];
  }
  if (value === undefined || !/^\d+$/.test(value)) throw new Error('broker group');
  const gid = Number(value);
  if (!Number.isSafeInteger(gid) || gid <= 0) throw new Error('broker group');
  return gid;
}

async function transfer(
  url: string,
  maxBytes: number,
  deadline: number,
  consume: (chunk: Buffer) => void,
): Promise<void> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new Error('download timeout');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), remaining);
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    let target = url;
    for (let redirects = 0; ; redirects++) {
      if (!isAllowedUrl(target) || new URL(target).protocol !== 'https:') {
        throw new Error('download URL');
      }
      const reply = await fetch(target, { redirect: 'manual', signal: controller.signal });
      if ([301, 302, 303, 307, 308].includes(reply.status)) {
        const location = reply.headers.get('location');
        await reply.body?.cancel();
        if (!location || redirects >= 5) throw new Error('download redirect');
        target = new URL(location, target).href;
        continue;
      }
      if (!reply.ok || !reply.body) {
        await reply.body?.cancel();
        throw new Error('download response');
      }
      const length = reply.headers.get('content-length');
      if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
        await reply.body.cancel();
        throw new Error('download size');
      }
      reader = reply.body.getReader();
      let total = 0;
      while (true) {
        if (Date.now() >= deadline) throw new Error('download timeout');
        const part = await reader.read();
        if (part.done) break;
        total += part.value.byteLength;
        if (total > maxBytes) throw new Error('download size');
        consume(Buffer.from(part.value));
      }
      return;
    }
  } finally {
    controller.abort();
    if (reader) {
      try {
        await reader.cancel();
      } catch {
        // Aborting a failed transfer can also reject cancellation.
      }
      reader.releaseLock();
    }
    clearTimeout(timer);
  }
}

export function defaultDeps(): UpdaterDeps {
  const windows = process.platform === 'win32';
  const darwin = process.platform === 'darwin';
  const root = windows ?
    path.join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Wundervault') : '/opt/wundervault';
  const programData = process.env.ProgramData ?? 'C:\\ProgramData';
  const spool = windows ?
    path.join(programData, 'wundervault-update') : '/var/lib/wundervault-update';
  const platform = platformKey(process.platform, process.arch);
  if (platform === null) {
    atomicText(path.join(spool, 'status.json'), JSON.stringify({
      order_id: '', state: 'failed', version: '', detail: 'platform', at: new Date().toISOString(),
    }));
    throw new Error('platform');
  }
  const env = minimalEnv(windows);
  const expectRequestOwner = windows ? null : { uid: 0, gid: brokerGid(darwin, env) };
  process.chdir(root);

  const activeFile = path.join(root, 'bin', 'active.cmd');
  const currentFile = path.join(root, 'current');
  const versionDir = (v: string): string => {
    if (parseVersion(v) === null) throw new Error('descriptor');
    return path.join(root, 'versions', v);
  };
  const readActive = (): { version: string; node: string } | null => {
    let text: string;
    try {
      text = fs.readFileSync(activeFile, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
    const match = /^set "WV_NODE=([^"\r\n]+)"\r\nset "WV_APP=([^"\r\n]+)"\r\n$/.exec(text);
    if (!match) throw new Error('descriptor');
    const node = match[1]!;
    const app = match[2]!;
    const v = path.basename(path.dirname(app));
    if (parseVersion(v) === null || app !== path.join(versionDir(v), 'app') ||
        !path.isAbsolute(node) || /[%!^&|<>]/.test(node)) throw new Error('descriptor');
    return { version: v, node };
  };
  const readDescriptor = (): string | null => {
    if (windows) return readActive()?.version ?? null;
    let target: string;
    try {
      target = fs.readlinkSync(currentFile);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
    const v = path.basename(target);
    if (parseVersion(v) === null || target !== `versions/${v}`) throw new Error('descriptor');
    return v;
  };
  const writeDescriptor = (v: string): void => {
    const dir = versionDir(v);
    if (windows) {
      writeWindowsDescriptor(root, v);
    } else {
      const temp = `${currentFile}.tmp-${process.pid}`;
      fs.rmSync(temp, { force: true });
      try {
        fs.symlinkSync(`versions/${v}`, temp);
        fs.renameSync(temp, currentFile);
        syncDirectory(root);
      } finally {
        fs.rmSync(temp, { force: true });
      }
    }
  };
  const socket = windows ?
    path.join(programData, 'wundervault', 'run', 'mgmt', 'agent.sock') :
    darwin ? '/var/lib/wundervault/run/mgmt/agent.sock' : '/run/wundervault/mgmt/agent.sock';

  return {
    root, spool, platform, keys: RELEASE_KEYS, limits: DEFAULT_LIMITS, expectRequestOwner,
    openRequest(file) {
      let fd: number | undefined;
      try {
        const before = fs.lstatSync(file);
        if (before.isSymbolicLink()) return { refused: 'request file' };
        fd = fs.openSync(file, fs.constants.O_RDONLY |
          (windows ? 0 : fs.constants.O_NOFOLLOW) | (windows ? 0 : fs.constants.O_NONBLOCK));
        const info = fs.fstatSync(fd);
        if (!info.isFile() || info.nlink !== 1 ||
            info.dev !== before.dev || info.ino !== before.ino ||
            (expectRequestOwner !== null &&
             (info.uid !== expectRequestOwner.uid || info.gid !== expectRequestOwner.gid ||
              (info.mode & 0o7777) !== 0o620))) {
          fs.closeSync(fd);
          fd = undefined;
          return { refused: 'request file' };
        }
        return { fd };
      } catch (error) {
        if (fd !== undefined) fs.closeSync(fd);
        return { refused: (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'missing' : 'request file' };
      }
    },
    async fetchBytes(url, maxBytes, timeoutMs) {
      const chunks: Buffer[] = [];
      await transfer(url, maxBytes, Date.now() + timeoutMs, chunk => chunks.push(chunk));
      return Buffer.concat(chunks);
    },
    async download(url, dest, maxBytes, deadlineMs) {
      const fd = fs.openSync(dest, 'wx', 0o600);
      try {
        await transfer(url, maxBytes, deadlineMs, chunk => {
          let offset = 0;
          while (offset < chunk.length) offset += fs.writeSync(fd, chunk, offset, chunk.length - offset);
        });
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    },
    freeBytes(dir) {
      const info = fs.statfsSync(dir);
      return info.bavail * info.bsize;
    },
    readDescriptor,
    writeDescriptor,
    async installNode(dir: string, record: ReleaseRecord, temp: string) {
      const entry = record.node[platform];
      if (!entry) throw new Error('platform');
      if (windows) {
        const exe = path.join(dir, 'node.exe');
        fs.copyFileSync(path.join(temp, 'node.exe'), exe, fs.constants.COPYFILE_EXCL);
        // On disk before active.cmd can name it: a power cut must not leave the descriptor pointing
        // at an executable whose bytes were still in the cache (review round 3, A-F1).
        const fd = fs.openSync(exe, 'r+');
        try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      } else {
        const member = 'member' in entry ? entry.member : undefined;
        if (!member) throw new Error('node member');
        const dest = path.join(dir, 'node');
        await extractNodeMember(path.join(temp, 'node.tar.gz'), member, dest, DEFAULT_LIMITS);
        fs.chmodSync(dest, 0o755);
      }
    },
    async restartBroker() {
      if (windows) {
        const exe = path.join(systemRoot(), 'System32', 'schtasks.exe');
        // /End can fail when the previous broker has already stopped.
        try {
          await runProgram(exe, ['/End', '/TN', 'wundervault-agent'], root, env, true, 60_000);
        } catch {
          // /Run is still needed after a crash or an already stopped task.
        }
        await runProgram(exe, ['/Run', '/TN', 'wundervault-agent'], root, env, true, 60_000);
      } else if (darwin) {
        await runProgram('/bin/launchctl', ['kickstart', '-k', 'system/com.wundervault.agent'],
          root, env, false, 60_000);
      } else {
        const exe = ['/usr/bin/systemctl', '/bin/systemctl'].find(file => fs.existsSync(file));
        if (!exe) throw new Error('service manager');
        await runProgram(exe, ['restart', 'wundervault-agent.service'], root, env, false, 60_000);
      }
    },
    async ping() {
      // Windows has no socket path: the broker listens on a loopback port named in mgmt.port and
      // proves itself with a signed hello. Connecting to `socket` there could never succeed, so
      // every Windows update was judged unhealthy and its rollback too ("rollback failed"; found
      // on win199, 2026-11-05). Same connection as every agent's, key at its fixed path.
      let client: net.Socket;
      if (windows) {
        const run = path.join(programData, 'wundervault', 'run');
        try {
          client = await connectToEndpoint(
            { kind: 'port', file: path.join(run, 'mgmt', 'mgmt.port') }, 5_000,
            path.join(run, 'broker.pub'));
        } catch {
          return null;
        }
      } else {
        client = net.createConnection(socket);
      }
      return new Promise(resolve => {
        let buffer = Buffer.alloc(0);
        let finished = false;
        const finish = (reply: { version: string; store_ok: boolean } | null): void => {
          if (finished) return;
          finished = true;
          clearTimeout(timer);
          client.destroy();
          resolve(reply);
        };
        const timer = setTimeout(() => finish(null), 5_000);
        if (windows) client.write('{"action":"ping"}\n');
        else client.once('connect', () => client.write('{"action":"ping"}\n'));
        client.on('data', (chunk: Buffer) => {
          if (finished) return;
          if (buffer.length + chunk.length > 64 * 1024) {
            finish(null);
            return;
          }
          buffer = Buffer.concat([buffer, chunk]);
          const newline = buffer.indexOf(10);
          if (newline === -1) return;
          try {
            const reply = JSON.parse(buffer.subarray(0, newline).toString('utf8')) as Record<string, unknown>;
            if (reply === null || typeof reply !== 'object') {
              finish(null);
              return;
            }
            // U5 calls this broker_version; accept version for older management replies too.
            const v = reply.broker_version ?? reply.version;
            finish({ version: String(v), store_ok: reply.store_ok === true });
          } catch {
            finish(null);
          }
        });
        client.once('error', () => finish(null));
        client.once('end', () => finish(null));
      });
    },
    async selfTest(dir) {
      try {
        const exe = windows ? windowsNode(dir) : path.join(dir, 'node');
        await runProgram(exe, [path.join(dir, 'app', 'dist', 'updater.js'), '--self-test'],
          root, env, windows, 30_000);
        return true;
      } catch {
        return false;
      }
    },
    now: () => Date.now(),
    sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
    log: message => console.error(message),
  };
}
