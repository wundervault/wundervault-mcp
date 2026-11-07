import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { pathToFileURL } from 'node:url';
const dist = process.argv[2];
const { startAgent, loadOpenSshEd25519, hardenedSshOptions } = await import(pathToFileURL(path.join(dist, 'ssh-agent.js')));
const tmp = fs.mkdtempSync('/tmp/wvbind-');
const ak = path.join(os.homedir(), '.ssh', 'authorized_keys');
const before = fs.existsSync(ak) ? fs.readFileSync(ak, 'utf8') : null;
const scan = execFileSync('ssh-keyscan', ['-t', 'ed25519', '127.0.0.1'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim().split('\n').find((l) => l.includes('ssh-ed25519'));
const realHostKey = scan.split(' ').slice(1, 3).join(' ');
execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path.join(tmp, 'other')]);
const wrongHostKey = fs.readFileSync(path.join(tmp, 'other.pub'), 'utf8').trim().split(' ').slice(0, 2).join(' ');
async function attempt(label, pin) {
  const id = loadOpenSshEd25519(fs.readFileSync(path.join(tmp, 'k'), 'utf8'));
  const dir = fs.mkdtempSync(path.join(tmp, 's')); fs.chmodSync(dir, 0o755);
  const events = [];
  const h = startAgent(id, (e) => events.push(e), '127.0.0.1', { dir, socketMode: 0o666, publicKeyMode: 0o644, ...(pin ? { pinnedHostKey: pin } : {}) });
  const kh = path.join(dir, 'known_hosts'); fs.writeFileSync(kh, `127.0.0.1 ${realHostKey}\n`);
  const r = await new Promise((res) => { const c = spawn('ssh', [...hardenedSshOptions(h.socketPath, h.publicKeyPath), '-o', `UserKnownHostsFile=${kh}`, '-o', 'StrictHostKeyChecking=yes', `${os.userInfo().username}@127.0.0.1`, 'echo', 'OK'], { env: { ...process.env, SSH_AUTH_SOCK: h.socketPath } }); let o = '', e = ''; c.stdout.on('data', (d) => o += d); c.stderr.on('data', (d) => e += d); const t = setTimeout(() => c.kill(), 20000); c.on('close', (code) => { clearTimeout(t); res({ code, o, e }); }); });
  h.close();
  console.log(label, 'exit', r.code, 'out', r.o.trim(), 'refused', events.filter((x) => x.refused).length, 'signed', events.filter((x) => !x.refused).length);
}
try {
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'wv-bind-temp', '-f', path.join(tmp, 'k')]);
  fs.appendFileSync(ak, (before && !before.endsWith('\n') ? '\n' : '') + `from="127.0.0.1,::1" ${fs.readFileSync(path.join(tmp, 'k.pub'), 'utf8').trim()}\n`);
  await attempt('UNPINNED   ', null);
  await attempt('PINNED-REAL ', realHostKey);
  await attempt('PINNED-WRONG', wrongHostKey);
} finally {
  if (before === null) fs.rmSync(ak, { force: true }); else fs.writeFileSync(ak, before);
  fs.rmSync(tmp, { recursive: true, force: true });
}
