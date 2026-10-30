import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';

const comparePaths = (a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path));
const hash = data => createHash('sha256').update(data).digest('hex');

// The same rule the updater's reader applies (src/release-verify.ts APP_PATH), checked here so a
// release that the updater would refuse can never be packed in the first place.
const APP_PATH = /^[A-Za-z0-9@_][A-Za-z0-9@._+-]{0,99}(\/[A-Za-z0-9@_][A-Za-z0-9@._+-]{0,99}){0,15}$/;

function checkPath(name) {
  if (!name || !APP_PATH.test(name) ||
      name.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error(`Invalid archive path: ${name}`);
  }
}

function writeString(header, offset, length, value) {
  const bytes = Buffer.from(value);
  if (bytes.length > length) throw new Error(`ustar field too long: ${value}`);
  bytes.copy(header, offset);
}

function writeOctal(header, offset, length, value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid ustar number');
  const text = value.toString(8);
  if (text.length > length - 1) throw new Error('ustar numeric field overflow');
  writeString(header, offset, length, text.padStart(length - 1, '0') + '\0');
}

export function ustarHeader(name, size, directory = false) {
  checkPath(name);
  const fullName = directory ? `${name}/` : name;
  let leaf = fullName;
  let prefix = '';
  if (Buffer.byteLength(fullName) > 100) {
    let split = fullName.lastIndexOf('/', fullName.length - 2);
    while (split > 0) {
      const left = fullName.slice(0, split);
      const right = fullName.slice(split + 1);
      if (Buffer.byteLength(left) <= 155 && Buffer.byteLength(right) <= 100) {
        prefix = left;
        leaf = right;
        break;
      }
      split = fullName.lastIndexOf('/', split - 1);
    }
    if (!prefix) throw new Error(`Path cannot fit in ustar: ${name}`);
  }

  const header = Buffer.alloc(512);
  writeString(header, 0, 100, leaf);
  writeOctal(header, 100, 8, directory ? 0o755 : 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, directory ? 0 : size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = directory ? 0x35 : 0x30;
  writeString(header, 257, 6, 'ustar\0');
  writeString(header, 263, 2, '00');
  writeString(header, 345, 155, prefix);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeString(header, 148, 8, checksum.toString(8).padStart(6, '0') + '\0 ');
  return header;
}

// lstat is intentional: no link in either the source tree or the dependency closure
// may silently turn into bytes from somewhere else.
export function collectTree(source, archivePath, include = () => true) {
  const entries = [];
  function visit(file, name) {
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink()) throw new Error(`Symlink refused: ${file}`);
    if (!stat.isDirectory() && !stat.isFile()) throw new Error(`Non-file refused: ${file}`);
    if (!include(name, stat.isDirectory())) return;
    // Dotfiles (.npmignore, .github/ …) are never needed at runtime, and the signed record's path
    // rule refuses names that start with a dot — so they are left out here, not failed later.
    if (path.basename(name).startsWith('.')) return;
    checkPath(name);
    if (stat.isDirectory()) {
      entries.push({ path: name, directory: true });
      for (const child of fs.readdirSync(file).sort()) {
        visit(path.join(file, child), `${name}/${child}`);
      }
    } else {
      entries.push({ path: name, data: fs.readFileSync(file) });
    }
  }
  visit(source, archivePath);
  // A folder with no file under it would be refused by the updater's reader (every folder must lead
  // to a listed file), so empty ones are not written at all.
  const used = new Set();
  for (const entry of entries) {
    if (entry.directory) continue;
    const parts = entry.path.split('/');
    for (let i = 1; i < parts.length; i++) used.add(parts.slice(0, i).join('/'));
  }
  return entries.filter(entry => !entry.directory || used.has(entry.path));
}

export function buildArchive(entries) {
  const sorted = [...entries].sort(comparePaths);
  const seen = new Set();
  const chunks = [];
  const files = [];
  for (const entry of sorted) {
    checkPath(entry.path);
    if (entry.path !== 'app' && !entry.path.startsWith('app/')) {
      throw new Error(`Entry is outside app/: ${entry.path}`);
    }
    const folded = entry.path.toLowerCase();
    if (seen.has(folded)) throw new Error(`Duplicate archive path: ${entry.path}`);
    seen.add(folded);
    if (entry.directory) {
      chunks.push(ustarHeader(entry.path, 0, true));
    } else {
      if (!Buffer.isBuffer(entry.data)) throw new Error(`Missing file bytes: ${entry.path}`);
      chunks.push(ustarHeader(entry.path, entry.data.length), entry.data);
      const padding = (512 - entry.data.length % 512) % 512;
      if (padding) chunks.push(Buffer.alloc(padding));
      files.push({
        path: entry.path.slice(4),
        sha256: hash(entry.data),
        size: entry.data.length,
      });
    }
  }
  chunks.push(Buffer.alloc(1024));
  const archive = gzipSync(Buffer.concat(chunks), { level: 9 });
  archive.fill(0, 4, 8);
  archive[9] = 255;
  return { archive, sha256: hash(archive), files };
}
