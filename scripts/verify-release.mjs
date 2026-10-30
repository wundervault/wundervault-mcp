import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { verifySignatures, parseRecord, sha256File } from '../dist/release-verify.js';
import { RELEASE_KEYS } from '../dist/release-keys.js';
import { extractApp, extractNodeMember } from '../dist/tar-read.js';
import { REQUIRED_APP_FILES } from '../dist/updater.js';
import {
  args, required, testKeyOptions, verificationKeys, main,
} from './lib/release-cli.mjs';

main(async () => {
  const values = args({
    dir: { type: 'string' },
    version: { type: 'string' },
    ...testKeyOptions,
  });
  required(values, ['dir', 'version']);
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(values.version)) {
    throw new Error('--version must be X.Y.Z');
  }
  const keys = verificationKeys(values, RELEASE_KEYS);
  const bytes = fs.readFileSync(path.join(values.dir, 'release.json'));
  const signatures = fs.readFileSync(path.join(values.dir, 'release.json.sigs'));
  const verified = verifySignatures(bytes, signatures, keys);
  if (!verified.ok) throw new Error(`Release signatures do not verify (${verified.reason})`);
  const parsed = parseRecord(bytes, values.version);
  if (!parsed.ok) throw new Error(`Release record refused (${parsed.reason})`);
  const record = parsed.record;
  const archivePath = path.join(values.dir, `wundervault-app-${values.version}.tar.gz`);
  if (await sha256File(archivePath) !== record.app.sha256) {
    throw new Error('App archive SHA-256 differs from the release record');
  }
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'wundervault-verify-'));
  try {
    const staging = path.join(temp, 'staging');
    fs.mkdirSync(staging);
    await extractApp(archivePath, staging, REQUIRED_APP_FILES);
    for (const [platform, entry] of Object.entries(record.node)) {
      if (platform === 'version') continue;
      const pathname = new URL(entry.url).pathname;
      const basename = path.posix.basename(pathname);
      const filename = platform.startsWith('win-') && basename === 'node.exe'
        ? `${platform}-node.exe`
        : basename;
      const file = path.join(values.dir, filename);
      if (!fs.existsSync(file)) {
        console.log(`node ${platform}: not present`);
        continue;
      }
      if (await sha256File(file) !== entry.sha256) {
        throw new Error(`Node ${platform} SHA-256 differs from the release record`);
      }
      if (filename.endsWith('.tar.gz')) {
        const destination = path.join(temp, 'node');
        try {
          await extractNodeMember(file, entry.member, destination);
        } finally {
          fs.rmSync(destination, { force: true });
        }
      }
      console.log(`node ${platform}: verified`);
    }
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
  console.log(`OK ${values.version}`);
});
