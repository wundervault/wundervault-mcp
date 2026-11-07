#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const counts = { pass: 0, fail: 0, skip: 0 };
const secrets = new Set();
const seedText = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const password = `router/pw+${crypto.randomBytes(24).toString('hex')}=&`;

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

rememberSecret(seedText);
rememberSecret(seedText.slice(0, 10));
rememberSecret(password);

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
  for (const secret of secrets) {
    assert(!text.includes(secret), 'a secret appeared in the result or activity log');
  }
}

class Skip extends Error {}

function command(file, args, options = {}) {
  try {
    return execFileSync(file, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30000,
      maxBuffer: 4 * 1024 * 1024,
      ...options,
    });
  } catch (error) {
    // execFileSync errors can embed stdout, including the admin private key.
    throw new Error(`${path.basename(file)} failed (${error.code ?? error.status ?? 'unknown status'})`);
  }
}

function version(file, args, stderr = false) {
  try {
    const result = execFileSync(file, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', stderr ? 'pipe' : 'ignore'],
      timeout: 5000,
    });
    return result.trim() || 'none';
  } catch {
    return 'none';
  }
}

function sshVersion() {
  try {
    let output = '';
    execFileSync('ssh', ['-V'], {
      timeout: 5000,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    // ssh -V writes its version to stderr, even on success.
    const child = spawnSyncVersion();
    output = child;
    return output || 'none';
  } catch {
    return 'none';
  }
}

function spawnSyncVersion() {
  // A shell is deliberately not used to combine stdout and stderr.
  const script = "const {spawnSync}=require('node:child_process');const r=spawnSync('ssh',['-V'],{encoding:'utf8'});if(r.error||r.status!==0)process.exit(1);process.stdout.write((r.stderr||r.stdout||'').trim());";
  return execFileSync(process.execPath, ['-e', script], {
    encoding: 'utf8',
    timeout: 5000,
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}

function parseArgs() {
  const options = { dist: null, admin: false, git: false, noSignin: false };
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--dist' && args[i + 1] && !args[i + 1].startsWith('--')) {
      assert(options.dist === null, '--dist was supplied twice');
      options.dist = path.resolve(args[++i]);
    } else if (args[i] === '--admin') {
      options.admin = true;
    } else if (args[i] === '--git') {
      options.git = true;
    } else if (args[i] === '--no-signin') {
      options.noSignin = true;
    } else {
      throw new Error('usage: node real-machine-12.mjs --dist <built dist folder> [--admin] [--git] [--no-signin]');
    }
  }
  assert(options.dist, '--dist <built dist folder> is required');
  return options;
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
    return {
      stat,
      bytes: stat.isFile() ? fs.readFileSync(filename) : null,
    };
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
  const gitVersion = version('git', ['--version']);
  const user = os.userInfo().username;
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  console.log(`INFO platform=${process.platform} node=${process.version} git=${reason(gitVersion)} openssh=${reason(sshVersion())} user=${reason(user)} root=${isRoot}`);

  let options;
  try {
    options = parseArgs();
  } catch (error) {
    report('FAIL', 'arguments', error);
    return;
  }

  let root;
  let vaultServer;
  let routerServer;
  let ops;
  let modules;
  let setupError;
  let gitFixturePromise;
  let routerFixturePromise;
  const entries = new Map();
  const activities = [];
  const approvals = [];
  const unexpected = [];
  const savedEnv = new Map();
  const vaultKey = crypto.randomBytes(32);
  const encKey = crypto.randomBytes(32);
  const agentId = crypto.randomBytes(16).toString('hex');
  const apiKey = `e2e-${crypto.randomBytes(16).toString('hex')}`;

  async function check(name, fn) {
    const approvalCount = approvals.length;
    const unexpectedCount = unexpected.length;
    let error;
    try {
      await fn();
      noSecrets(activities);
    } catch (caught) {
      error = caught;
    }
    if (approvals.length !== approvalCount) {
      error = new Error('the broker requested owner approval; the harness refused it');
    } else if (unexpected.length !== unexpectedCount) {
      error = new Error(`unexpected vault request: ${unexpected.at(-1)}`);
    }
    if (error instanceof Skip) report('SKIP', name, error);
    else if (error) report('FAIL', name, error);
    else report('PASS', name);
  }

  function ready() {
    if (setupError) throw setupError;
    assert(ops, 'broker was not initialized');
  }

  function makeEntry({ shape, parts, raw, sshHosts = [], privateOrigins = [], approved = [] }) {
    ready();
    const id = crypto.randomBytes(16).toString('hex');
    const ssh = raw !== undefined;
    const value = encrypt(vaultKey, Buffer.from(ssh ? raw : JSON.stringify({ parts }), 'utf8'));
    const setup = {
      v: 1,
      rev: 1,
      value_sha256: crypto.createHash('sha256').update(value.ciphertext).digest('hex'),
      value_format: ssh ? 'raw' : 'parts-1',
      name: 'Real-machine 1.2 check',
      shape,
      service: null,
      delivery: ssh ? 'ssh' : 'http',
      binding: null,
      ssh_hosts: sshHosts,
      private_origins: privateOrigins,
      known_addresses: [],
      approval: null,
      operations: {},
      chain: null,
    };
    const sealed = modules.sealSetup(vaultKey, agentId, id, 1, setup);
    assert(sealed.ok, 'could not seal the test entry setup');
    const policy = encrypt(vaultKey, Buffer.from(JSON.stringify({
      v: 1,
      entry_id: id,
      version: 1,
      kind: 'stamped',
      stamped: {
        approved: approved.map(({ recipe, origin, hashOrigin }) => ({
          recipe_sha256: modules.signInRecipeSha(recipe, hashOrigin ?? origin),
          origin,
        })),
      },
    })));
    const entry = {
      id,
      agent_id: agentId,
      rev: 1,
      entry_mode: ssh ? 'BROKER_SSH_AGENT' : 'BROKER_HTTP',
      delivery: setup.delivery,
      allowed_private_origins: privateOrigins,
      ssh_hosts: sshHosts,
      encrypted_content: value.ciphertext.toString('base64'),
      content_nonce: value.nonce.toString('base64'),
      setup_ciphertext: sealed.ciphertext,
      setup_nonce: sealed.nonce,
      policy_ciphertext: policy.ciphertext.toString('base64'),
      policy_nonce: policy.nonce.toString('base64'),
      access_tier: '1',
      vault_locked: false,
    };
    entries.set(id, entry);
    return id;
  }

  async function openSession(args) {
    const opened = await ops.sshAgentOpen(args);
    assert(opened && !opened.error, opened?.error ?? 'SSH session was not opened');
    assert(opened.session_id && opened.socket_path && opened.public_key_path, 'SSH session returned incomplete paths');
    return opened;
  }

  async function gitFixture() {
    ready();
    if (!gitFixturePromise) {
      gitFixturePromise = (async () => {
        const match = /git version (\d+)\.(\d+)/.exec(gitVersion);
        if (!match) throw new Skip('git is not installed');
        if (Number(match[1]) < 2 || (Number(match[1]) === 2 && Number(match[2]) < 24)) {
          throw new Skip('git 2.24 or newer is required');
        }
        try {
          command('ssh-keygen', ['-V']);
        } catch {
          // -V needs an argument; use the actual generation below to test availability.
        }
        const keyPath = path.join(root, 'git-key');
        command('ssh-keygen', ['-t', 'ed25519', '-N', '', '-f', keyPath]);
        const privateKey = fs.readFileSync(keyPath, 'utf8');
        rememberSecret(privateKey);
        const publicKey = fs.readFileSync(`${keyPath}.pub`, 'utf8').trim().split(/\s+/).slice(0, 2).join(' ');
        const entryId = makeEntry({ shape: 'ssh_key', raw: privateKey, sshHosts: ['localhost', '127.0.0.1'] });
        const remote = path.join(root, 'remote.git');
        const work = path.join(root, 'work');
        fs.mkdirSync(work);
        const env = modules.gitEnv(process.env, 'false');
        command('git', ['init', '--bare', remote], { env });
        command('git', ['init', work], { env });
        command('git', ['config', 'user.name', 'Wundervault E2E'], { cwd: work, env });
        command('git', ['config', 'user.email', 'wv-e2e@example.invalid'], { cwd: work, env });
        command('git', ['config', 'commit.gpgsign', 'false'], { cwd: work, env });
        fs.writeFileSync(path.join(work, 'check.txt'), 'real-machine 1.2\n');
        command('git', ['add', 'check.txt'], { cwd: work, env });
        command('git', ['-c', 'core.hooksPath=/dev/null', 'commit', '-m', 'real-machine check'], { cwd: work, env });
        command('git', ['remote', 'add', 'origin', `${user}@localhost:${remote}`], { cwd: work, env });
        const validated = modules.validateGitRequest({
          subcommand: 'push',
          remote: 'origin',
          refspecs: ['HEAD:refs/heads/main'],
        });
        assert(validated.ok, validated.reason ?? 'git request was refused');
        return { entryId, publicKey, remote, work, env, req: validated.req };
      })();
    }
    return gitFixturePromise;
  }

  async function routerFixture() {
    ready();
    if (!routerFixturePromise) {
      routerFixturePromise = (async () => {
        try {
          command('openssl', ['version']);
        } catch {
          throw new Skip('openssl is not installed');
        }
        const keyPath = path.join(root, 'router-key.pem');
        const certPath = path.join(root, 'router-cert.pem');
        command('openssl', [
          'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
          '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '2',
          '-subj', '/CN=router', '-addext', 'subjectAltName=IP:127.0.0.1',
        ]);
        const cert = fs.readFileSync(certPath);
        const fingerprint = new crypto.X509Certificate(cert).fingerprint256.replace(/:/g, '').toLowerCase();
        const state = { logins: 0, sid: null };
        routerServer = https.createServer({ key: fs.readFileSync(keyPath), cert }, (req, res) => {
          const chunks = [];
          req.on('data', (chunk) => chunks.push(chunk));
          req.on('error', () => res.destroy());
          req.on('end', () => {
            if (req.method === 'POST' && req.url === '/login') {
              state.logins++;
              let body;
              try {
                body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              } catch {
                sendJson(res, { error: 'invalid JSON' }, 400);
                return;
              }
              if (body.user !== 'admin' || body.password !== password) {
                sendJson(res, { error: 'invalid credentials' }, 401);
                return;
              }
              state.sid = crypto.randomBytes(32).toString('hex');
              rememberSecret(state.sid);
              res.setHeader('Set-Cookie', `sid=${state.sid}; Path=/`);
              sendJson(res, { signed_in: true });
              return;
            }
            if (req.method === 'GET' && req.url === '/status') {
              if (!state.sid || req.headers.cookie !== `sid=${state.sid}`) {
                sendJson(res, { error: 'signed out' }, 401);
                return;
              }
              sendJson(res, { ok: true, echo: state.sid });
              return;
            }
            sendJson(res, { error: 'not found' }, 404);
          });
        });
        const port = await listen(routerServer);
        const origin = `https://127.0.0.1:${port}`;
        const recipe = {
          login: {
            method: 'POST',
            path: '/login',
            body_format: 'json',
            body: { user: '{{username}}', password: '{{password}}' },
          },
          session_from: { cookie: 'sid' },
          send_session_as: { cookie: 'sid' },
        };
        const checked = modules.validateSignInRecipe(recipe);
        assert(checked.ok, checked.reason ?? 'invalid test sign-in recipe');
        const entryId = makeEntry({
          shape: 'password',
          parts: { username: 'admin', password },
          privateOrigins: [origin],
          approved: [
            { recipe: checked.recipe, origin },
            { recipe: checked.recipe, origin, hashOrigin: `${origin}#cert-sha256=${fingerprint}` },
          ],
        });
        return {
          state,
          args: {
            entryId,
            purpose: 'Check the test router without receiving its password or session',
            request: {
              origin: { scheme: 'https', host: '127.0.0.1', port },
              method: 'GET',
              path: '/status',
              sign_in: recipe,
            },
          },
        };
      })();
    }
    return routerFixturePromise;
  }

  try {
    try {
      root = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-real-machine-12-'));
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
        ...await load('signin.js'),
        ...await load('totp.js'),
        ...await load('git-op.js'),
        ...await load('ssh-agent.js'),
      };

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
            sendJson(res, { allowed: false, error: 'Owner approval is forbidden in this test' }, 403);
          });
          return;
        }
        unexpected.push(`${req.method} ${pathname}`);
        sendJson(res, { error: 'not found' }, 404);
      });
      const vaultUrl = `http://127.0.0.1:${await listen(vaultServer)}`;
      ops = new BrokerOps('Real-machine 1.2', apiKey, encKey.toString('base64url'), vaultUrl, null, undefined, {}, {
        pinsPath: path.join(root, 'setup-pins.json'),
      });
      ops.activity = { record: (record) => activities.push(record) };
    } catch (error) {
      setupError = error;
    }

    await check('2fa code', async () => {
      ready();
      const entryId = makeEntry({ shape: 'two_factor', parts: { seed: seedText } });
      const parsed = modules.parseSeed(seedText);
      assert(parsed && parsed.ok !== false, 'the built broker refused the test seed');

      // Decode independently so a parser/code-generator disagreement cannot pass.
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = '';
      for (const char of seedText) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
      const key = Buffer.from(bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)));
      rememberSecret(key.toString('latin1'));
      const before = Date.now();
      const result = await ops.twoFactorCode({ entryId, purpose: 'Verify a real-machine authenticator code' });
      const after = Date.now();
      noSecrets(result);
      assert(!result?.error, result?.error ?? '2FA failed');
      assert(/^\d{6}$/.test(result.code), 'the result is not a six-digit code');
      const remaining = result.expires_in_seconds;
      assert(Number.isFinite(remaining) && remaining > 0 && remaining <= 30, 'invalid code lifetime');

      const currentWindow = Math.floor(after / 30000);
      const windows = [currentWindow];
      if (Math.floor(before / 30000) < currentWindow) windows.push(currentWindow - 1);
      let matched = false;
      for (const window of windows) {
        const seconds = window * 30;
        const counter = Buffer.alloc(8);
        counter.writeBigUInt64BE(BigInt(window));
        const digest = crypto.createHmac('sha1', key).update(counter).digest();
        const offset = digest.at(-1) & 15;
        const reference = String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
        const params = parsed.params ?? parsed.options ?? parsed;
        let builtCode;
        // Built releases may accept the decoded key or the seed text.
        for (const seed of [key, seedText]) {
          try {
            const generated = modules.totpAt(seed, seconds, params);
            const code = typeof generated === 'string' ? generated : generated?.code;
            if (code === reference) {
              builtCode = code;
              break;
            }
          } catch {
            // Try the other seed representation without exposing parser errors.
          }
        }
        assert(builtCode === reference, 'the built totpAt did not match the independent code');
        const expectedRemaining = (window + 1) * 30 - after / 1000;
        if (result.code === builtCode && Math.abs(remaining - expectedRemaining) <= 2) matched = true;
      }
      assert(matched, 'code or reported lifetime does not match the returned window');
    });

    await check('sign-in with own certificate', async () => {
      if (options.noSignin) throw new Skip('--no-signin');
      const fixture = await routerFixture();
      const result = await ops.call({
        ...fixture.args,
        request: { ...fixture.args.request, trust_certificate: true },
      });
      noSecrets(result);
      assert(result.status === 200 && !result.error, result.error ?? 'router did not return status 200');
      const body = typeof result.body === 'string' ? JSON.parse(result.body) : result.body;
      assert(body?.ok === true, 'router status body was not successful');
      assert(fixture.state.logins === 1, 'router did not see exactly one login');
      assert(!Object.hasOwn(result, 'headers'), 'response headers reached the agent');
    });

    await check('sign-in refuses an unpinned certificate', async () => {
      if (options.noSignin) throw new Skip('--no-signin');
      const fixture = await routerFixture();
      const before = fixture.state.logins;
      let refusal;
      try {
        const result = await ops.call(fixture.args);
        noSecrets(result);
        if (result?.error) refusal = result.error;
      } catch (error) {
        refusal = error instanceof Error ? error.message : String(error);
      }
      assert(refusal, 'the broker accepted an unpinned self-signed certificate');
      noSecrets(refusal);
      assert(/certificate|self.signed|verify|issuer|trust/i.test(refusal), 'refusal did not explain the certificate problem');
      assert(fixture.state.logins === before, 'an unpinned call sent a login');
    });

    if (process.platform === 'win32') {
      await check('git refuses on Windows', async () => {
        if (!options.git) throw new Skip('--git was not supplied');
        ready();
        const validated = modules.validateGitRequest({ subcommand: 'push', remote: 'origin' });
        assert(validated.ok, validated.reason ?? 'invalid git request');
        const result = await modules.resolveGitUrls(
          validated.req, root, modules.runGit, modules.gitEnv(process.env, 'false'),
        );
        assert(result.ok === false && /Windows/i.test(result.reason), 'git did not explain that Windows is unsupported');
      });
      await check('git refuses an unapproved push address', async () => {
        throw new Skip(options.git ? 'broker SSH is unavailable on Windows' : '--git was not supplied');
      });
    } else {
      await check('git push through the broker', async () => {
        if (!options.git) throw new Skip('--git was not supplied');
        const fixture = await gitFixture();
        if (!await reachable()) throw new Skip('sshd is not reachable on 127.0.0.1:22');
        const sshDir = path.join(os.homedir(), '.ssh');
        const authorized = path.join(sshDir, 'authorized_keys');
        const knownHosts = path.join(sshDir, 'known_hosts');
        const savedDir = snapshot(sshDir);
        assert(!savedDir || savedDir.stat.isDirectory(), '.ssh is not a directory');
        const savedAuthorized = snapshot(authorized);
        const savedKnownHosts = snapshot(knownHosts);
        const marker = 'wv-e2e-12-temp';
        assert(!savedAuthorized?.bytes.toString('utf8').includes(marker), 'authorized_keys already contains the test marker');
        const original = savedAuthorized?.bytes ?? Buffer.alloc(0);
        const separator = original.length && original.at(-1) !== 10 ? '\n' : '';
        const line = `from="127.0.0.1,::1" ${fixture.publicKey} ${marker}`;
        const installed = Buffer.concat([original, Buffer.from(`${separator}${line}\n`)]);
        let opened;
        try {
          if (!savedDir) fs.mkdirSync(sshDir, { mode: 0o700 });
          fs.writeFileSync(authorized, installed, { mode: 0o600 });
          fs.chmodSync(authorized, savedAuthorized ? savedAuthorized.stat.mode & 0o7777 : 0o600);
          const urls = await modules.resolveGitUrls(fixture.req, fixture.work, modules.runGit, fixture.env);
          assert(urls.ok, urls.reason ?? 'could not resolve git URLs');
          for (const url of urls.urls) assert(modules.parseGitSshUrl(url).ok, 'resolved URL is not SSH');
          opened = await openSession({
            entryId: fixture.entryId,
            purpose: 'Push a temporary repository through the broker',
            op: { kind: 'git', destination: `${user}@localhost`, urls: urls.urls, subcommand: 'push' },
            ttlSeconds: 120,
          });
          const result = await modules.runGit(
            modules.buildGitArgv(fixture.req),
            fixture.work,
            modules.gitEnv(process.env, modules.sshCommandFor(opened.socket_path, opened.public_key_path)),
            60000,
          );
          assert(result.code === 0, `git push failed: ${result.stderr}`);
          const remoteHead = command('git', ['--git-dir', fixture.remote, 'rev-parse', 'main'], { env: fixture.env }).trim();
          const localHead = command('git', ['rev-parse', 'HEAD'], { cwd: fixture.work, env: fixture.env }).trim();
          assert(remoteHead === localHead, 'remote main does not match work HEAD');
        } finally {
          try {
            if (opened) await ops.closeSsh(opened.session_id);
          } finally {
            try {
              const current = snapshot(authorized);
              if (current?.bytes.equals(installed)) {
                restoreFile(authorized, savedAuthorized);
              } else if (current) {
                const filtered = current.bytes.toString('utf8').split('\n')
                  .filter((value) => !value.includes(marker)).join('\n');
                fs.writeFileSync(authorized, filtered);
                fs.chmodSync(authorized, current.stat.mode & 0o7777);
              }
            } finally {
              try {
                restoreFile(knownHosts, savedKnownHosts);
              } finally {
                restoreDirectory(sshDir, savedDir);
              }
            }
          }
        }
      });

      await check('git refuses an unapproved push address', async () => {
        if (!options.git) throw new Skip('--git was not supplied');
        const fixture = await gitFixture();
        command('git', ['config', 'remote.origin.pushurl', 'git@evil.example:x.git'], { cwd: fixture.work, env: fixture.env });
        let opened;
        try {
          const urls = await modules.resolveGitUrls(fixture.req, fixture.work, modules.runGit, fixture.env);
          assert(urls.ok, urls.reason ?? 'could not resolve the push address');
          assert(urls.urls.includes('git@evil.example:x.git'), 'pushurl was not resolved');
          let refusal;
          try {
            opened = await ops.sshAgentOpen({
              entryId: fixture.entryId,
              purpose: 'Verify refusal of an unapproved push address',
              op: { kind: 'git', destination: `${user}@localhost`, urls: urls.urls, subcommand: 'push' },
              ttlSeconds: 120,
            });
            refusal = opened?.error;
          } catch (error) {
            refusal = error instanceof Error ? error.message : String(error);
          }
          assert(!opened?.session_id, 'the broker opened a signing session for the disallowed host');
          assert(refusal && /evil\.example/i.test(refusal), 'refusal did not name evil.example');
          noSecrets(refusal);
        } finally {
          try {
            if (opened?.session_id) await ops.closeSsh(opened.session_id);
          } finally {
            command('git', ['config', '--unset-all', 'remote.origin.pushurl'], { cwd: fixture.work, env: fixture.env });
          }
        }
      });
    }

    await check('admin key runs as root', async () => {
      if (!options.admin) throw new Skip('--admin was not supplied');
      if (!isRoot) throw new Skip('--admin requires root');
      if (!['linux', 'darwin'].includes(process.platform)) throw new Skip('admin keys require Linux or macOS');
      ready();
      const script = path.resolve(options.dist, '..', 'packaging', 'admin-key.sh');
      const sshDir = process.platform === 'darwin' ? '/var/root/.ssh' : '/root/.ssh';
      const authorized = path.join(sshDir, 'authorized_keys');
      const knownHosts = path.join(sshDir, 'known_hosts');
      const savedDir = snapshot(sshDir);
      assert(!savedDir || savedDir.stat.isDirectory(), 'root .ssh is not a directory');
      const savedAuthorized = snapshot(authorized);
      const savedKnownHosts = snapshot(knownHosts);
      // Do not inherit test overrides: --admin intentionally exercises real root and sshd.
      const env = { ...process.env, WV_ADMIN_NO_WAIT: '1' };
      for (const key of Object.keys(env)) {
        if (key.startsWith('WV_ADMIN_') && key !== 'WV_ADMIN_NO_WAIT') delete env[key];
      }
      let opened;
      try {
        const output = command('sh', [script], { env });
        const match = /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/.exec(output);
        assert(match, 'admin-key.sh did not print an OpenSSH private key');
        const privateKey = `${match[0]}\n`;
        rememberSecret(privateKey);
        rememberSecret(match[0]);
        const entryId = makeEntry({ shape: 'ssh_key', raw: privateKey, sshHosts: ['localhost'] });
        const op = { kind: 'ssh', destination: 'root@localhost', remoteArgv: ['id', '-u'] };
        opened = await openSession({
          entryId,
          purpose: 'Verify the temporary admin key runs id as root',
          op,
          ttlSeconds: 120,
        });
        const hardened = modules.hardenedSshOptions(opened.socket_path, opened.public_key_path);
        const equivalent = [...hardened, 'root@localhost', 'id -u'];
        let args = equivalent;
        // The fixed-command equivalent also works with builds whose argv helper
        // has a different internal parameter layout. Never drop SSH hardening.
        try {
          const built = modules.buildSshArgv(op, opened.socket_path, opened.public_key_path);
          if (Array.isArray(built)
            && built.every((arg) => typeof arg === 'string')
            && JSON.stringify(built.slice(0, hardened.length)) === JSON.stringify(hardened)
            && built[hardened.length] === 'root@localhost'
            && ['id -u', "'id' '-u'"].includes(built.slice(hardened.length + 1).join(' '))) {
            args = built;
          }
        } catch {
          // Use the equivalent hardened argv for this fixed, non-user-supplied command.
        }
        const result = await runSsh(args);
        assert(result.code === 0, `admin SSH failed: ${result.stderr}`);
        assert(result.stdout.trim() === '0', 'admin command did not return uid 0');
      } finally {
        try {
          if (opened) await ops.closeSsh(opened.session_id);
        } finally {
          try {
            command('sh', [script, '--remove'], { env });
            const listed = command('sh', [script, '--list'], { env });
            assert(!/ssh-ed25519[^\r\n]*wundervault-admin/.test(listed), 'admin-key.sh --remove left an admin key');
          } finally {
            try {
              restoreFile(authorized, savedAuthorized);
            } finally {
              try {
                restoreFile(knownHosts, savedKnownHosts);
              } finally {
                restoreDirectory(sshDir, savedDir);
              }
            }
          }
        }
      }
    });

    await check('admin key refused from elsewhere', async () => {
      throw new Skip('needs a second machine');
    });
  } finally {
    const cleanupErrors = [];
    for (const cleanup of [
      async () => { if (ops) await ops.reset(); },
      async () => closeServer(routerServer),
      async () => closeServer(vaultServer),
      async () => {
        for (const [name, value] of savedEnv) {
          if (value === undefined) delete process.env[name];
          else process.env[name] = value;
        }
      },
      async () => { if (root) fs.rmSync(root, { recursive: true, force: true }); },
    ]) {
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
