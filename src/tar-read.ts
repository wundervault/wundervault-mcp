import { createHash } from 'node:crypto';
import {
  constants, chmodSync, closeSync, createReadStream, fchmodSync, fstatSync, fsyncSync,
  lstatSync, mkdirSync, openSync, readdirSync, writeSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { TextDecoder } from 'node:util';
import { createGunzip } from 'node:zlib';
import { DEFAULT_LIMITS, safeAppPath } from './release-verify.js';
import type { ReleaseLimits } from './release-verify.js';

class ArchiveProblem extends Error {}

function fail(detail: string): never {
  throw new ArchiveProblem(`archive: ${detail}`);
}

function fixedError(error: unknown): Error {
  return error instanceof ArchiveProblem ? error : new Error('archive: read or write failed');
}

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const safePath = safeAppPath;

/**
 * Only a chunk and a header are held at once. The byte budget includes headers,
 * skipped data and trailing padding, not just files we decide to keep.
 */
class Bytes {
  private readonly iterator: AsyncIterator<Buffer>;
  private chunk: Buffer = Buffer.alloc(0);
  private offset = 0;
  private total = 0;

  constructor(stream: AsyncIterable<Buffer>, private readonly cap: number) {
    this.iterator = stream[Symbol.asyncIterator]();
  }

  private async available(): Promise<boolean> {
    while (this.offset === this.chunk.length) {
      const next = await this.iterator.next();
      if (next.done) return false;
      this.chunk = next.value;
      this.offset = 0;
      this.total += this.chunk.length;
      if (this.total > this.cap) fail('unpacked size limit');
    }
    return true;
  }

  async block(): Promise<Buffer | null> {
    if (!await this.available()) return null;
    const block = Buffer.alloc(512);
    let offset = 0;
    await this.consume(512, chunk => {
      chunk.copy(block, offset);
      offset += chunk.length;
    });
    return block;
  }

  async consume(length: number, use?: (chunk: Buffer) => void): Promise<void> {
    while (length > 0) {
      if (!await this.available()) fail('truncated data');
      const count = Math.min(length, this.chunk.length - this.offset);
      const chunk = this.chunk.subarray(this.offset, this.offset + count);
      if (use) use(chunk);
      this.offset += count;
      length -= count;
    }
  }
}

function allZero(bytes: Buffer): boolean {
  return bytes.every(byte => byte === 0);
}

function textField(header: Buffer, start: number, length: number): string {
  const field = header.subarray(start, start + length);
  const end = field.indexOf(0);
  const text = end === -1 ? field : field.subarray(0, end);
  if (end !== -1 && !allZero(field.subarray(end))) fail('invalid header');
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(text);
  } catch {
    return fail('invalid header');
  }
}

function octal(field: Buffer): number {
  // Base-256 numbers have different signedness rules. Our packer never needs them.
  if ((field[0]! & 0x80) !== 0) fail('base-256 size');
  const text = field.toString('latin1').replace(/^[ ]+/, '').replace(/[\0 ]+$/, '');
  if (!/^[0-7]+$/.test(text)) fail('invalid octal field');
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value) || value < 0) fail('invalid octal field');
  return value;
}

interface Header {
  name: string;
  type: string;
  size: number;
}

function readHeader(block: Buffer): Header {
  const expected = octal(block.subarray(148, 156));
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : block[i]!;
  if (sum !== expected) fail('checksum mismatch');
  // Two header dialects. POSIX ustar is what our own packer writes. GNU's ("ustar  \0") is what
  // the official Node archives use (found 2026-10-30 against node-v22.23.4-linux-x64.tar.gz: every
  // unit test passed while the real download was refused). GNU keeps access/change times where
  // POSIX keeps the name prefix, so a GNU header has no prefix to read.
  const posix = block.subarray(257, 263).equals(Buffer.from('ustar\0', 'latin1')) &&
    block.subarray(263, 265).equals(Buffer.from('00', 'latin1'));
  const gnu = block.subarray(257, 265).equals(Buffer.from('ustar  \0', 'latin1'));
  if (!posix && !gnu) fail('not ustar');
  const name = textField(block, 0, 100);
  const prefix = posix ? textField(block, 345, 155) : '';
  if (!name) fail('invalid name');
  return {
    name: prefix ? `${prefix}/${name}` : name,
    type: String.fromCharCode(block[156]!),
    size: octal(block.subarray(124, 136)),
  };
}

function regular(header: Header): boolean {
  return header.type === '0' || header.type === '\0';
}

async function entries(
  bytes: Bytes,
  limits: Readonly<ReleaseLimits>,
  use: (header: Header, bytes: Bytes) => Promise<void>,
): Promise<void> {
  let count = 0;
  for (;;) {
    const block = await bytes.block();
    if (!block) fail('missing end blocks');
    if (allZero(block)) {
      const second = await bytes.block();
      if (!second || !allZero(second)) fail('invalid end blocks');
      for (;;) {
        const padding = await bytes.block();
        if (!padding) return;
        if (!allZero(padding)) fail('nonzero trailing data');
      }
    }
    if (++count > limits.maxEntries) fail('entry count limit');
    const header = readHeader(block);
    await use(header, bytes);
    const padding = (512 - header.size % 512) % 512;
    await bytes.consume(padding, chunk => {
      if (!allZero(chunk)) fail('nonzero entry padding');
    });
  }
}

async function withArchive(
  archive: string,
  limits: Readonly<ReleaseLimits>,
  use: (bytes: Bytes) => Promise<void>,
): Promise<void> {
  let fd: number | undefined;
  try {
    for (const value of Object.values(limits)) {
      if (!Number.isSafeInteger(value) || value < 0) fail('invalid limits');
    }
    fd = openSync(archive, constants.O_RDONLY | NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile()) fail('not a regular archive');
    if (stat.size > limits.maxArchiveBytes) fail('compressed size limit');

    const input = createReadStream(archive, { fd, autoClose: true });
    fd = undefined;
    let compressed = 0;
    const budget = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        compressed += chunk.length;
        if (compressed > limits.maxArchiveBytes) {
          callback(new ArchiveProblem('archive: compressed size limit'));
        } else {
          callback(null, chunk);
        }
      },
    });
    const gunzip = createGunzip();
    const completion = pipeline(input, budget, gunzip);
    // A read-side failure can happen while the callback is writing a file.
    void completion.catch(() => {});
    try {
      await use(new Bytes(gunzip, limits.maxUnpackedBytes));
      await completion;
    } finally {
      input.destroy();
      budget.destroy();
      gunzip.destroy();
      await completion.catch(() => {});
    }
  } catch (error) {
    throw fixedError(error);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function realDirectory(path: string): void {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('unsafe directory');
}

function makeDirectory(path: string): void {
  try {
    mkdirSync(path, { mode: 0o755 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  realDirectory(path);
  chmodSync(path, 0o755);
}

function syncDirectory(path: string): void {
  if (process.platform === 'win32') return;
  const fd = openSync(path, constants.O_RDONLY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function syncDirectories(path: string): void {
  if (process.platform === 'win32') return;
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.isDirectory()) syncDirectories(join(path, entry.name));
  }
  syncDirectory(path);
}

function parents(root: string, relative: string): string {
  let current = root;
  for (const part of relative.split('/').filter(Boolean)) {
    current = join(current, part);
    makeDirectory(current);
  }
  return current;
}

function writeAll(fd: number, chunk: Buffer): void {
  let offset = 0;
  while (offset < chunk.length) {
    const written = writeSync(fd, chunk, offset, chunk.length - offset);
    if (written <= 0) fail('write failed');
    offset += written;
  }
}

async function writeEntry(bytes: Bytes, size: number, path: string, mode: number): Promise<string> {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, mode);
  try {
    fchmodSync(fd, mode);
    const hash = createHash('sha256');
    await bytes.consume(size, chunk => {
      writeAll(fd, chunk);
      hash.update(chunk);
    });
    fsyncSync(fd);
    return hash.digest('hex');
  } finally {
    closeSync(fd);
  }
}

/**
 * Unpack the app archive into stagingDir/app. Every entry is checked BEFORE anything is written:
 * plain files and folders only (no links of any kind, devices or extension headers), names under
 * 'app/' that pass safeAppPath, no name used twice (compared case-insensitively, so it can't collide
 * on macOS/Windows), no file inside something that was a file, per-file and total size caps. Files
 * are created O_EXCL|O_NOFOLLOW in folders this function made. `required` names files (relative to
 * app/) that must be present, so a release missing its own entry points fails here, not at restart.
 */
export async function extractApp(
  archive: string,
  stagingDir: string,
  required: readonly string[],
  limits: Readonly<ReleaseLimits> = DEFAULT_LIMITS,
): Promise<void> {
  try {
    realDirectory(stagingDir);
    if (readdirSync(stagingDir).length !== 0) fail('staging not empty');
    for (const name of required) if (!safePath(name)) fail('invalid required file');

    const files = new Set<string>();          // exact names written
    const folded = new Map<string, 'file' | 'dir'>();   // case-folded name -> kind
    let fileCount = 0;
    const claim = (path: string, kind: 'file' | 'dir'): void => {
      const lower = path.toLowerCase();
      const before = folded.get(lower);
      if (before === 'file' || (before === 'dir' && kind === 'file')) fail(`duplicate entry app/${path}`);
      // A file may not sit under something that is already a file.
      const parts = lower.split('/');
      for (let i = 1; i < parts.length; i++) {
        if (folded.get(parts.slice(0, i).join('/')) === 'file') fail(`entry under a file app/${path}`);
      }
      folded.set(lower, kind);
    };
    await withArchive(archive, limits, async bytes => {
      await entries(bytes, limits, async (header, data) => {
        if (!regular(header) && header.type !== '5') {
          fail(header.type === '1' || header.type === '2' ? 'link entry' : 'unsupported entry type');
        }
        if (header.name !== 'app/' && !header.name.startsWith('app/')) fail('invalid app path');
        let path = header.name.slice(4);
        if (header.type === '5') {
          if (path.endsWith('/')) path = path.slice(0, -1);
          if (header.size !== 0) fail('directory has data');
          makeDirectory(join(stagingDir, 'app'));
          if (path === '') return;
          if (!safePath(path)) fail('invalid app path');
          claim(path, 'dir');
          parents(join(stagingDir, 'app'), path);
          return;
        }
        if (!safePath(path)) fail('invalid app path');
        if (header.size > limits.maxFileBytes) fail('file size limit');
        if (++fileCount > limits.maxFiles) fail('file count limit');
        claim(path, 'file');
        for (let i = path.indexOf('/'); i !== -1; i = path.indexOf('/', i + 1)) claim(path.slice(0, i), 'dir');
        files.add(path);
        makeDirectory(join(stagingDir, 'app'));
        const parent = dirname(path);
        if (parent !== '.') parents(join(stagingDir, 'app'), parent);
        await writeEntry(data, header.size, join(stagingDir, 'app', path), 0o644);
      });
    });
    for (const name of required) if (!files.has(name)) fail(`missing required file app/${name}`);
    syncDirectories(stagingDir);
  } catch (error) {
    throw fixedError(error);
  }
}

export async function extractNodeMember(
  archive: string,
  member: string,
  destFile: string,
  limits: Readonly<ReleaseLimits> = DEFAULT_LIMITS,
): Promise<void> {
  try {
    if (!safePath(member)) fail('invalid node member');
    let seen = false;
    await withArchive(archive, limits, async bytes => {
      await entries(bytes, limits, async (header, data) => {
        if (header.name !== member) {
          // Official Node archives contain links. Skipping their bytes never creates a link.
          await data.consume(header.size);
          return;
        }
        if (seen) fail('duplicate node member');
        if (!regular(header)) fail('node member not regular');
        if (header.size > limits.maxFileBytes) fail('node member size limit');
        seen = true;
        await writeEntry(data, header.size, destFile, 0o755);
      });
      if (!seen) fail('node member missing');
    });
    syncDirectory(dirname(destFile));
  } catch (error) {
    throw fixedError(error);
  }
}
