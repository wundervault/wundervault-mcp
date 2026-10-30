import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { args, required, main } from './lib/release-cli.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const hosts = new Set([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'nodejs.org',
]);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function download(url, limit) {
  const signal = AbortSignal.timeout(600_000);
  for (let redirects = 0; redirects <= 5; redirects++) {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
        (parsed.port && parsed.port !== '443') || !hosts.has(parsed.hostname)) {
      throw new Error(`Download URL refused: ${url}`);
    }
    const response = await fetch(parsed, { redirect: 'manual', signal });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      await response.body?.cancel();
      if (!location) throw new Error(`Redirect without location: ${url}`);
      url = new URL(location, parsed).href;
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Download failed (${response.status}): ${url}`);
    }
    const chunks = [];
    let size = 0;
    if (!response.body) throw new Error(`Empty response: ${url}`);
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > limit) throw new Error(`Download too large: ${url}`);
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  throw new Error('Too many download redirects');
}

main(async () => {
  const values = args({
    version: { type: 'string' },
    'node-version': { type: 'string' },
    out: { type: 'string' },
    'ci-archive': { type: 'string' },
  });
  required(values, ['version', 'node-version', 'out']);
  for (const name of ['version', 'node-version']) {
    if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(values[name])) {
      throw new Error(`--${name} must be X.Y.Z`);
    }
  }
  const version = values.version;
  const nodeVersion = values['node-version'];
  const out = path.resolve(values.out);
  const ciArchive = values['ci-archive'] ? path.resolve(values['ci-archive']) : undefined;
  const git = arguments_ => execFileSync('git', arguments_, { cwd: root, encoding: 'utf8' }).trim();
  if (git(['status', '--porcelain', '--untracked-files=all'])) {
    throw new Error('A clean git tree is required');
  }
  if (git(['describe', '--exact-match', '--tags', 'HEAD']) !== `v${version}`) {
    throw new Error(`HEAD must be exactly tag v${version}`);
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (pkg.version !== version) throw new Error('Tag and package.json version differ');

  const keyDir = path.join(root, 'packaging', 'node-release-keys');
  const keyFiles = fs.readdirSync(keyDir).filter(name => name.endsWith('.asc')).sort();
  if (!keyFiles.length) {
    throw new Error('packaging/node-release-keys/ has no .asc keys; pin the Node release keys first');
  }
  for (const name of keyFiles) {
    if (!fs.lstatSync(path.join(keyDir, name)).isFile()) {
      throw new Error(`Node release key must be a regular file: ${name}`);
    }
  }

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'wundervault-record-'));
  try {
    execFileSync('npm', ['ci'], { cwd: root, stdio: 'inherit' });
    execFileSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' });
    const { parseRecord } = await import('../dist/release-verify.js');
    const packed = path.join(temp, 'packed');
    execFileSync(process.execPath, [path.join(root, 'scripts', 'pack-app.mjs'), '--out', packed], {
      cwd: root,
      stdio: 'inherit',
    });
    const archiveName = `wundervault-app-${version}.tar.gz`;
    const appURL = `https://github.com/wundervault/wundervault-mcp/releases/download/v${version}/${archiveName}`;
    const localArchive = fs.readFileSync(path.join(packed, archiveName));
    const ciBytes = ciArchive
      ? fs.readFileSync(ciArchive)
      : await download(appURL, 200 * 1024 * 1024);
    if (hash(localArchive) !== hash(ciBytes)) throw new Error("CI's archive differs from the local rebuild");

    const nodeBase = `https://nodejs.org/dist/v${nodeVersion}/`;
    const sums = await download(`${nodeBase}SHASUMS256.txt`, 1024 * 1024);
    const signature = await download(`${nodeBase}SHASUMS256.txt.sig`, 1024 * 1024);
    const sumsPath = path.join(temp, 'SHASUMS256.txt');
    const sigPath = path.join(temp, 'SHASUMS256.txt.sig');
    fs.writeFileSync(sumsPath, sums);
    fs.writeFileSync(sigPath, signature);
    const home = path.join(temp, 'gpg');
    fs.mkdirSync(home, { mode: 0o700 });
    const keyring = path.join(home, 'release-keys.gpg');
    const gpgArgs = [
      '--no-options', '--homedir', home, '--batch', '--no-default-keyring', '--keyring', keyring,
    ];
    for (const name of keyFiles) {
      execFileSync('gpg', [...gpgArgs, '--import', path.join(keyDir, name)], { stdio: 'inherit' });
    }
    execFileSync('gpg', [...gpgArgs, '--verify', sigPath, sumsPath], { stdio: 'inherit' });

    const hashes = new Map();
    for (const line of sums.toString('utf8').split('\n')) {
      if (!line.trim()) continue;
      const match = /^([a-fA-F0-9]{64}) {1,2}\*?(\S+)\r?$/.exec(line);
      if (!match || hashes.has(match[2])) throw new Error('Invalid or duplicate Node SHASUMS256 entry');
      hashes.set(match[2], match[1].toLowerCase());
    }
    const node = { version: nodeVersion };
    for (const platform of ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'win-x64', 'win-arm64']) {
      const windows = platform.startsWith('win-');
      const name = windows ? `${platform}/node.exe` : `node-v${nodeVersion}-${platform}.tar.gz`;
      const sha256 = hashes.get(name);
      if (!sha256) throw new Error(`Node SHASUMS256 is missing ${name}`);
      node[platform] = { url: `${nodeBase}${name}`, sha256 };
      if (!windows) node[platform].member = `node-v${nodeVersion}-${platform}/bin/node`;
    }

    const record = Buffer.from(canonical({
      format: 'wundervault-release-1',
      version,
      app: { url: appURL, sha256: hash(localArchive) },
      node,
      notes_url: `https://wundervault.com/changelog#mcp-${version}`,
    }));
    const checked = parseRecord(record, version);
    if (!checked.ok) throw new Error(`The record this tool built fails the updater's own check: ${checked.reason}`);
    fs.mkdirSync(out, { recursive: true });
    const recordPath = path.join(out, 'release.json');
    fs.writeFileSync(recordPath, record);
    console.log(`${hash(record)}  ${recordPath}`);
    console.log('Next: sign release.json\'s exact bytes with the vault\'s "Wundervault release key", then run:');
    console.log(`node scripts/add-signature.mjs --dir ${JSON.stringify(out)} --key-id <id> --sig <base64>`);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
