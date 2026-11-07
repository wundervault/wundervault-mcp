#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const counts = { pass: 0, fail: 0, skip: 0 };
const secrets = new Set();

function rememberSecret(value) {
  if (!value) return;
  const escaped = JSON.stringify(value).slice(1, -1);
  for (const form of [
    value,
    escaped,
    escaped.replace(/\//g, '\\/'),
    Array.from(value, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
    encodeURIComponent(value),
    encodeURIComponent(value).replace(/%[0-9A-F]{2}/g, (match) => match.toLowerCase()),
    Buffer.from(value).toString('base64'),
    Buffer.from(value).toString('base64url'),
  ]) {
    secrets.add(form);
    secrets.add(JSON.stringify(form).slice(1, -1));
  }
}

function reason(error) {
  let text = error instanceof Error ? error.message : String(error);
  text = text.replace(/-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?(?:-----END OPENSSH PRIVATE KEY-----|$)/g, '[private key]');
  for (const secret of [...secrets].sort((a, b) => b.length - a.length)) {
    text = text.split(secret).join('[secret]');
  }
  return text.replace(/[\r\n\x00-\x1f\x7f]+/g, ' ').slice(0, 800);
}

function report(kind, name, detail) {
  counts[kind.toLowerCase()]++;
  console.log(`${kind} ${name}${detail ? `: ${reason(detail)}` : ''}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function noSecrets(value) {
  const text = JSON.stringify(value);
  assert(typeof text === 'string', 'expected a serializable result');
  for (const secret of secrets) {
    assert(!text.includes(secret), 'a secret appeared in the result or activity log');
  }
}

function command(file, args) {
  try {
    return execFileSync(file, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30000,
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    // execFileSync errors can embed stdout, including private key material.
    throw new Error(`${path.basename(file)} failed (${error.code ?? error.status ?? 'unknown status'})`);
  }
}

function sshVersion() {
  const result = spawnSync('ssh', ['-V'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 5000,
  });
  if (result.error || result.status !== 0) return 'none';
  return (result.stderr || result.stdout || '').trim() || 'none';
}

function parseArgs() {
  const options = { dist: null };
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dist' && args[i + 1] && !args[i + 1].startsWith('--')) {
      assert(options.dist === null, '--dist was supplied twice');
      options.dist = path.resolve(args[++i]);
    } else {
      throw new Error('usage: node real-machine-13.mjs --dist <built dist folder>');
    }
  }
  assert(options.dist, '--dist <built dist folder> is required');
  return options;
}

async function reachable() {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port: 22 });
    const finish = (ok) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(3000);
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.once('timeout', () => finish(false));
  });
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  return server.address().port;
}

async function closeServer(server) {
  if (!server?.listening) return;
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}

function sendJson(res, body, status = 200) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function encrypt(key, plaintext) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  return {
    nonce,
    ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]),
  };
}

function snapshot(filename) {
  try {
    const stat = fs.lstatSync(filename);
    assert(!stat.isSymbolicLink(), `refusing symlink: ${filename}`);
    assert(stat.isFile() || stat.isDirectory(), `unsupported file type: ${filename}`);
    return { stat, bytes: stat.isFile() ? fs.readFileSync(filename) : null };
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function restoreFile(filename, saved) {
  if (!saved) {
    fs.rmSync(filename, { force: true });
    return;
  }
  const current = snapshot(filename);
  if (!current || !current.bytes?.equals(saved.bytes)) fs.writeFileSync(filename, saved.bytes);
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    fs.chownSync(filename, saved.stat.uid, saved.stat.gid);
  }
  fs.chmodSync(filename, saved.stat.mode & 0o7777);
}

function restoreDirectory(dirname, saved) {
  if (!saved) {
    if (fs.existsSync(dirname)) fs.rmdirSync(dirname);
    return;
  }
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    fs.chownSync(dirname, saved.stat.uid, saved.stat.gid);
  }
  fs.chmodSync(dirname, saved.stat.mode & 0o7777);
}

function fingerprint(hostKey) {
  const fields = hostKey.trim().split(/\s+/);
  assert(fields.length === 2, 'expected a host key in type/base64 form');
  return `SHA256:${crypto.createHash('sha256').update(Buffer.from(fields[1], 'base64')).digest('base64').replace(/=+$/, '')}`;
}

async function runSsh(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('ssh', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, 60000);
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      resolve({ code: timedOut ? 124 : code, stdout, stderr });
    });
  });
}

async function main() {
  const user = os.userInfo().username;
  console.log(`INFO platform=${process.platform} node=${process.version} openssh=${reason(sshVersion())} user=${reason(user)}`);

  let options;
  try {
    options = parseArgs();
  } catch (error) {
    report('FAIL', 'arguments', error);
    return;
  }

  if (process.platform === 'win32') {
    report('SKIP', 'ssh checks', 'broker SSH is unavailable on Windows');
    return;
  }
  if (!await reachable()) {
    report('SKIP', 'ssh checks', 'sshd is not reachable on 127.0.0.1:22');
    return;
  }

  let root;
  let vaultServer;
  let ops;
  let modules;
  let setupError;
  let authorizedState;
  let privateKey;
  let publicKey;
  let target;
  let realKey;
  let differentKey;
  let unapprovedEntryId;
  let pinnedEntryId;
  let changedEntryId;
  let opened;
  let secondAgent;
  const entries = new Map();
  const activities = [];
  const approvals = [];
  const unexpected = [];
  const sessions = new Set();
  const savedEnv = new Map();
  const vaultKey = crypto.randomBytes(32);
  const encKey = crypto.randomBytes(32);
  const agentId = crypto.randomBytes(16).toString('hex');
  const apiKey = `e2e-${crypto.randomBytes(16).toString('hex')}`;
  const marker = 'wv-e2e-13-temp';
  const op = {
    kind: 'ssh',
    destination: `${user}@127.0.0.1`,
    remoteArgv: ['id', '-un'],
  };

  function ready() {
    if (setupError) throw setupError;
    assert(ops, 'broker was not initialized');
  }

  async function check(name, expectedApprovals, fn) {
    const approvalCount = approvals.length;
    const unexpectedCount = unexpected.length;
    let error;
    try {
      await fn();
      noSecrets(activities);
    } catch (caught) {
      error = caught;
    }
    if (approvals.length !== approvalCount + expectedApprovals) {
      error ??= new Error(`expected ${expectedApprovals} owner approval request(s), received ${approvals.length - approvalCount}`);
    }
    if (unexpected.length !== unexpectedCount) {
      error ??= new Error(`unexpected vault request: ${unexpected.at(-1)}`);
    }
    if (error) report('FAIL', name, error);
    else report('PASS', name);
  }

  function makeEntry(approved) {
    const id = crypto.randomBytes(16).toString('hex');
    const value = encrypt(vaultKey, Buffer.from(privateKey, 'utf8'));
    const setup = {
      v: 1,
      rev: 1,
      value_sha256: crypto.createHash('sha256').update(value.ciphertext).digest('hex'),
      value_format: 'raw',
      name: 'Real-machine 1.3 check',
      shape: 'ssh_key',
      service: null,
      delivery: 'ssh',
      binding: null,
      ssh_hosts: [],
      ask: true,
      private_origins: [],
      known_addresses: [],
      approval: null,
      operations: {},
      chain: null,
    };
    const sealed = modules.sealSetup(vaultKey, agentId, id, 1, setup);
    assert(sealed.ok, 'could not seal the test entry setup');
    const policy = approved === null ? null : encrypt(vaultKey, Buffer.from(JSON.stringify({
      v: 1,
      entry_id: id,
      version: 1,
      kind: 'stamped',
      stamped: { approved },
    })));
    entries.set(id, {
      id,
      agent_id: agentId,
      rev: 1,
      entry_mode: 'BROKER_SSH_AGENT',
      delivery: 'ssh',
      allowed_private_origins: [],
      ssh_hosts: [],
      encrypted_content: value.ciphertext.toString('base64'),
      content_nonce: value.nonce.toString('base64'),
      setup_ciphertext: sealed.ciphertext,
      setup_nonce: sealed.nonce,
      policy_ciphertext: policy ? policy.ciphertext.toString('base64') : null,
      policy_nonce: policy ? policy.nonce.toString('base64') : null,
      access_tier: '1',
      vault_locked: false,
    });
    return id;
  }

  function approvalFor(hostKey) {
    return {
      recipe_sha256: modules.sshHostSha(target, hostKey),
      ssh: { user, host: '127.0.0.1', port: 22, host_key: hostKey },
    };
  }

  async function openSession(entryId, purpose) {
    const result = await ops.sshAgentOpen({ entryId, purpose, op, ttlSeconds: 120 });
    if (result?.session_id) sessions.add(result.session_id);
    noSecrets(result);
    return result;
  }

  function installAuthorizedKey() {
    const sshDir = path.join(os.homedir(), '.ssh');
    const authorized = path.join(sshDir, 'authorized_keys');
    const knownHosts = path.join(sshDir, 'known_hosts');
    const savedDir = snapshot(sshDir);
    assert(!savedDir || savedDir.stat.isDirectory(), '.ssh is not a directory');
    const savedAuthorized = snapshot(authorized);
    const savedKnownHosts = snapshot(knownHosts);
    assert(!savedAuthorized || savedAuthorized.stat.isFile(), 'authorized_keys is not a file');
    assert(!savedKnownHosts || savedKnownHosts.stat.isFile(), 'known_hosts is not a file');
    assert(!savedAuthorized?.bytes.toString('utf8').includes(marker), 'authorized_keys already contains the test marker');
    const original = savedAuthorized?.bytes ?? Buffer.alloc(0);
    const separator = original.length && original.at(-1) !== 10 ? '\n' : '';
    const line = `from="127.0.0.1,::1" ${publicKey} ${marker}`;
    const installed = Buffer.concat([original, Buffer.from(`${separator}${line}\n`)]);
    authorizedState = {
      sshDir, authorized, knownHosts, savedDir, savedAuthorized, savedKnownHosts, installed,
    };
    if (!savedDir) fs.mkdirSync(sshDir, { mode: 0o700 });
    fs.writeFileSync(authorized, installed, { mode: 0o600 });
    fs.chmodSync(authorized, savedAuthorized ? savedAuthorized.stat.mode & 0o7777 : 0o600);
  }

  function removeAuthorizedKey() {
    if (!authorizedState) return;
    const { authorized, savedAuthorized, installed } = authorizedState;
    const current = snapshot(authorized);
    if (!current || current.bytes?.equals(installed)) {
      restoreFile(authorized, savedAuthorized);
      return;
    }
    assert(current.stat.isFile(), 'authorized_keys is no longer a file');
    // Preserve concurrent edits, but never leave our authorization behind.
    const filtered = current.bytes.toString('utf8').split('\n')
      .filter((line) => !line.includes(marker)).join('\n');
    if (!savedAuthorized && filtered === '') fs.rmSync(authorized);
    else {
      fs.writeFileSync(authorized, filtered);
      fs.chmodSync(authorized, current.stat.mode & 0o7777);
    }
    const restored = snapshot(authorized);
    assert(!restored?.bytes.toString('utf8').includes(marker), 'temporary authorization was not removed');
  }

  try {
    try {
      // Keep Unix socket paths below the macOS limit, regardless of the user's TMPDIR.
      root = fs.mkdtempSync('/tmp/wv13-');
      const redirected = {
        WUNDERVAULT_SYSTEM_ROOT: path.join(root, 'sys'),
        WUNDERVAULT_USER_ROOT: path.join(root, 'user'),
        WUNDERVAULT_RUNTIME_DIR: path.join(root, 'run'),
        WUNDERVAULT_NETWORK_STORE: path.join(root, 'sys', 'network.json'),
        TMPDIR: root,
        TMP: root,
        TEMP: root,
      };
      for (const [name, value] of Object.entries(redirected)) {
        savedEnv.set(name, process.env[name]);
        process.env[name] = value;
      }
      for (const sub of ['sys', 'run', 'user']) {
        const dirname = path.join(root, sub);
        fs.mkdirSync(dirname, { mode: 0o755 });
        fs.chmodSync(dirname, 0o755);
      }

      const load = (name) => import(pathToFileURL(path.join(options.dist, name)).href);
      const { BrokerOps } = await load('broker-ops.js');
      modules = {
        ...await load('setup-seal.js'),
        ...await load('opdef.js'),
        ...await load('ssh-pin.js'),
        ...await load('ssh-agent.js'),
      };

      const keyPath = path.join(root, 'client-key');
      const differentPath = path.join(root, 'different-host-key');
      command('ssh-keygen', ['-t', 'ed25519', '-N', '', '-f', keyPath]);
      command('ssh-keygen', ['-t', 'ed25519', '-N', '', '-f', differentPath]);
      privateKey = fs.readFileSync(keyPath, 'utf8');
      rememberSecret(privateKey);
      rememberSecret(privateKey.trim());
      rememberSecret(fs.readFileSync(differentPath, 'utf8'));
      publicKey = fs.readFileSync(`${keyPath}.pub`, 'utf8').trim().split(/\s+/).slice(0, 2).join(' ');
      differentKey = fs.readFileSync(`${differentPath}.pub`, 'utf8').trim().split(/\s+/).slice(0, 2).join(' ');
      target = modules.normalizeSshTarget(op.destination);
      assert(target?.user === user && target.host === '127.0.0.1' && target.port === 22, 'SSH target did not normalize to the current user on 127.0.0.1:22');
      realKey = await modules.scanHostKey(target);
      assert(typeof realKey === 'string' && realKey.startsWith('ssh-ed25519 '), 'sshd did not provide an ed25519 host key');
      assert(realKey !== differentKey, 'generated host key unexpectedly matches the server');

      const wrapped = encrypt(encKey, vaultKey);
      const wrappedKey = Buffer.concat([wrapped.nonce, wrapped.ciphertext]).toString('base64');
      vaultServer = http.createServer((req, res) => {
        const pathname = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
        if (req.method === 'GET' && pathname === '/agent/profile') {
          sendJson(res, { vault_key_for_agent: wrappedKey });
          return;
        }
        if (req.method === 'GET' && pathname.startsWith('/agent/vault/secrets/')) {
          const found = entries.get(pathname.slice('/agent/vault/secrets/'.length));
          sendJson(res, found ?? { error: 'not found' }, found ? 200 : 404);
          return;
        }
        if (req.method === 'POST') {
          const chunks = [];
          req.on('data', (chunk) => chunks.push(chunk));
          req.on('error', () => res.destroy());
          req.on('end', () => {
            let body;
            try {
              body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            } catch {
              unexpected.push(`${req.method} ${pathname}: invalid JSON`);
              sendJson(res, { error: 'invalid JSON' }, 400);
              return;
            }
            if (pathname === '/agent/vault/operation-check' && body.kind !== 'recipe') {
              sendJson(res, { allowed: true, tier: '1' });
              return;
            }
            approvals.push({ pathname, body });
            sendJson(res, { allowed: false, error: 'Owner approval denied by the test harness' }, 403);
          });
          return;
        }
        unexpected.push(`${req.method} ${pathname}`);
        sendJson(res, { error: 'not found' }, 404);
      });
      const vaultUrl = `http://127.0.0.1:${await listen(vaultServer)}`;
      ops = new BrokerOps('Real-machine 1.3', apiKey, encKey.toString('base64url'), vaultUrl, null, undefined, {}, {
        pinsPath: path.join(root, 'setup-pins.json'),
      });
      ops.activity = { record: (record) => activities.push(record) };
      unapprovedEntryId = makeEntry(null);
      pinnedEntryId = makeEntry([approvalFor(realKey)]);
      changedEntryId = makeEntry([approvalFor(differentKey)]);
      installAuthorizedKey();
    } catch (error) {
      setupError = error;
    }

    await check('ssh first use asks the owner', 1, async () => {
      ready();
      const before = approvals.length;
      // A denied approval may come back as an error result or as a thrown refusal.
      let result;
      try { result = await openSession(unapprovedEntryId, 'Ask before using an SSH key for the first time'); }
      catch (error) { result = { error: String(error?.message ?? error) }; }
      assert(result?.error, 'denied approval did not return an error');
      assert(!result.session_id && !result.socket_path, 'denied approval opened a signing session');
      assert(approvals.length === before + 1, 'first use did not request exactly one approval');
      const request = approvals[before];
      assert(request.body.kind === 'recipe', 'first use requested the wrong approval kind');
      const recipe = request.body.detail?.recipe;
      assert(recipe && typeof recipe === 'object', 'approval did not include detail.recipe');
      const expected = {
        type: 'ssh_host',
        v: 1,
        user,
        host: '127.0.0.1',
        port: 22,
        host_key: realKey,
      };
      assert(modules.canonicalJson(recipe) === modules.canonicalJson(expected), 'approval recipe does not describe the scanned server');
      const sha = crypto.createHash('sha256').update(modules.canonicalJson(recipe)).digest('hex');
      assert(sha === modules.sshHostSha(target, realKey), 'approval recipe hash does not match sshHostSha');
      noSecrets(request);
    });

    await check('pinned ssh runs', 0, async () => {
      ready();
      opened = await openSession(pinnedEntryId, 'Run id through an owner-approved pinned SSH session');
      assert(opened && !opened.error, opened?.error ?? 'SSH session was not opened');
      assert(opened.session_id && opened.socket_path && opened.public_key_path, 'SSH session returned incomplete paths');
      assert(typeof opened.known_hosts_path === 'string' && opened.known_hosts_path, 'SSH session did not return known_hosts_path');
      assert(opened.pinned_host_key === realKey, 'SSH session returned the wrong pinned host key');
      const knownHosts = fs.readFileSync(opened.known_hosts_path, 'utf8').split(/\r?\n/)
        .filter((line) => line.trim() && !line.trim().startsWith('#'));
      assert(knownHosts.length === 1, 'session known_hosts does not contain exactly one server key');
      assert(knownHosts[0].trim().split(/\s+/).slice(1, 3).join(' ') === realKey, 'session known_hosts contains the wrong key');
      const result = await modules.runSshWithAgent({
        op,
        socketPath: opened.socket_path,
        publicKeyPath: opened.public_key_path,
        knownHostsPath: opened.known_hosts_path,
        timeoutMs: 60000,
      });
      noSecrets(result);
      assert(result.exitCode === 0, `pinned SSH failed: ${result.stderr}`);
      assert(result.stdout.trim() === user, 'pinned SSH did not run as the current user');
      // Leave this session open until the socket-binding check has completed.
    });

    await check('changed server identity refused', 0, async () => {
      ready();
      const result = await openSession(changedEntryId, 'Refuse a server whose identity differs from its approval');
      assert(result?.error, 'the broker accepted a changed server identity');
      assert(!result.session_id && !result.socket_path, 'changed server identity opened a signing session');
      const code = result.code ?? result.error?.code;
      const message = typeof result.error === 'string' ? result.error : result.error?.message;
      assert(code === 'HOST_KEY_CHANGED', 'changed server identity did not return HOST_KEY_CHANGED');
      assert(typeof message === 'string', 'changed server identity did not return a message');
      assert(message.includes(fingerprint(realKey)), 'refusal did not include the observed fingerprint');
      assert(message.includes(fingerprint(differentKey)), 'refusal did not include the approved fingerprint');
    });

    await check('socket refuses another server', 0, async () => {
      ready();
      assert(opened?.session_id && !opened.error, 'the pinned session is not open');
      const signEvents = [];
      const agentDir = fs.mkdtempSync(path.join(root, 'a2-'));
      fs.chmodSync(agentDir, 0o755);
      secondAgent = modules.startAgent(
        modules.loadOpenSshEd25519(privateKey),
        (event) => { signEvents.push([event]); },
        '127.0.0.1',
        { dir: agentDir, socketMode: 0o666, publicKeyMode: 0o644, pinnedHostKey: differentKey, pinnedUser: target.user },
      );

      // A HostKeyAlias alone is still the same server. Pin the second agent to a
      // different key so this real sshd must be refused at the signing socket.
      // Use a public-only file with no private-key sibling, and no user config,
      // multiplexing, other agent or interactive authentication as a fallback.
      const publicOnlyPath = path.join(root, 'public-only');
      fs.writeFileSync(publicOnlyPath, `${publicKey}\n`, { mode: 0o600 });
      const result = await runSsh([
        '-F', '/dev/null',
        '-p', '22',
        '-l', user,
        '-o', `IdentityAgent=${secondAgent.socketPath}`,
        '-o', `IdentityFile=${publicOnlyPath}`,
        '-o', 'IdentitiesOnly=no',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'HostKeyAlias=imposter',
        '-o', 'BatchMode=yes',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'GSSAPIAuthentication=no',
        '-o', 'HostbasedAuthentication=no',
        '-o', 'ForwardAgent=no',
        '-o', 'AddKeysToAgent=no',
        '-o', 'ControlMaster=no',
        '-o', 'ControlPath=none',
        '-o', 'ConnectTimeout=10',
        '-o', 'ConnectionAttempts=1',
        '127.0.0.1', 'id', '-un',
      ]);
      noSecrets(result);
      assert(result.code !== null && result.code !== 0 && result.code !== 124, 'SSH did not fail promptly for the differently pinned agent');
      assert(result.stdout.trim() === '', 'the differently pinned agent allowed the remote command to run');
      const refused = signEvents.some((args) => args.some((event) =>
        event === false || (event && typeof event === 'object' &&
          (event.refused === true || event.allowed === false || event.ok === false)),
      ));
      assert(refused, 'the agent onSign callback did not report a refusal');
    });
  } finally {
    const cleanupErrors = [];
    const cleanups = [
      async () => { if (secondAgent) await secondAgent.close(); },
      ...[...sessions].map((sessionId) => async () => { await ops.closeSsh(sessionId); }),
      async () => { if (ops) await ops.reset(); },
      async () => closeServer(vaultServer),
      async () => removeAuthorizedKey(),
      async () => {
        if (authorizedState) {
          restoreFile(authorizedState.knownHosts, authorizedState.savedKnownHosts);
        }
      },
      async () => {
        if (authorizedState) {
          restoreDirectory(authorizedState.sshDir, authorizedState.savedDir);
        }
      },
      async () => {
        for (const [name, value] of savedEnv) {
          if (value === undefined) delete process.env[name];
          else process.env[name] = value;
        }
      },
      async () => { if (root) fs.rmSync(root, { recursive: true, force: true }); },
    ];
    for (const cleanup of cleanups) {
      try {
        await cleanup();
      } catch (error) {
        cleanupErrors.push(reason(error));
      }
    }
    if (cleanupErrors.length) report('FAIL', 'cleanup', cleanupErrors.join('; '));
  }
}

try {
  await main();
} catch (error) {
  report('FAIL', 'harness', error);
}
console.log(`RESULT pass=${counts.pass} fail=${counts.fail} skip=${counts.skip}`);
process.exitCode = counts.fail ? 1 : 0;
