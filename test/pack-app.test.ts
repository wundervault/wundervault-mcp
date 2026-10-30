import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
// @ts-ignore Build-tool modules are plain ESM, shared with the CLI.
import { buildArchive, collectTree, ustarHeader } from '../scripts/lib/ustar.mjs';
// @ts-ignore Build-tool modules are plain ESM, shared with the CLI.
import { checkClosure } from '../scripts/lib/closure-check.mjs';

const temps: string[] = [];

function temporary() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wundervault-pack-test-'));
  temps.push(dir);
  return dir;
}

function write(root: string, name: string, contents: string) {
  const file = path.join(root, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  return file;
}

function fixture() {
  const root = temporary();
  write(root, 'package.json', '{"name":"fixture","version":"1.2.3"}');
  write(root, 'dist/main.js', 'export const answer = 42;\n');
  write(root, 'node_modules/example/package.json', '{"name":"example","version":"1.0.0"}');
  write(root, 'node_modules/example/index.js', 'export default 1;\n');
  fs.mkdirSync(path.join(root, 'empty'));
  return root;
}

function octal(header: Buffer, start: number, size: number) {
  return parseInt(header.subarray(start, start + size).toString('ascii').replace(/\0/g, '').trim(), 8);
}

function text(header: Buffer, start: number, size: number) {
  return header.subarray(start, start + size).toString('utf8').replace(/\0.*$/s, '');
}

afterEach(() => {
  for (const dir of temps.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('deterministic ustar writer', () => {
  it('writes checksum, zero timestamps and normalized modes', () => {
    const header = ustarHeader('app/dist/main.js', 17);
    expect(header.length).toBe(512);
    expect(text(header, 0, 100)).toBe('app/dist/main.js');
    expect(octal(header, 100, 8)).toBe(0o644);
    expect(octal(header, 108, 8)).toBe(0);
    expect(octal(header, 116, 8)).toBe(0);
    expect(octal(header, 124, 12)).toBe(17);
    expect(octal(header, 136, 12)).toBe(0);
    expect(header[156]).toBe('0'.charCodeAt(0));
    expect(text(header, 257, 6)).toBe('ustar');
    expect(text(header, 263, 2)).toBe('00');
    expect(text(header, 265, 32)).toBe('');
    expect(text(header, 297, 32)).toBe('');
    const checksum = octal(header, 148, 8);
    const copy = Buffer.from(header);
    copy.fill(0x20, 148, 156);
    expect(checksum).toBe(copy.reduce((sum, byte) => sum + byte, 0));
    const directory = ustarHeader('app/dist', 0, true);
    expect(octal(directory, 100, 8)).toBe(0o755);
    expect(directory[156]).toBe('5'.charCodeAt(0));
    expect(text(directory, 0, 100)).toBe('app/dist/');
  });

  it('splits long names at a slash and refuses names ustar cannot represent', () => {
    const prefix = `app/${'a'.repeat(90)}`;
    const leaf = `${'b'.repeat(60)}.js`;
    const header = ustarHeader(`${prefix}/${leaf}`, 1);
    expect(text(header, 345, 155)).toBe(prefix);
    expect(text(header, 0, 100)).toBe(leaf);
    expect(() => ustarHeader(`app/${'x'.repeat(101)}`, 1)).toThrow(/cannot fit|Invalid archive path/);
    expect(() => ustarHeader(`app/${'x'.repeat(156)}/a.js`, 1)).toThrow(/cannot fit|Invalid archive path/);
    expect(() => ustarHeader('app/../escape', 1)).toThrow(/Invalid archive path/);
  });

  it('packs a fixture identically regardless of traversal order, mtimes or modes', () => {
    const root = fixture();
    const first = buildArchive(collectTree(root, 'app'));
    const target = path.join(root, 'dist/main.js');
    fs.chmodSync(target, 0o755);
    fs.utimesSync(target, new Date(1_000_000), new Date(2_000_000));
    const second = buildArchive(collectTree(root, 'app').reverse());
    expect(second.archive.equals(first.archive)).toBe(true);
    expect(second.files).toEqual(first.files);
    expect(second.sha256).toBe(first.sha256);
    expect(first.archive.subarray(4, 8).equals(Buffer.alloc(4))).toBe(true);
    expect(first.archive[9]).toBe(255);
    const tar = gunzipSync(first.archive);
    expect(tar.subarray(-1024).equals(Buffer.alloc(1024))).toBe(true);
    expect(text(tar.subarray(0, 512), 0, 100)).toBe('app/');
    expect(first.files.map((file: { path: string }) => file.path)).toEqual([
      'dist/main.js',
      'node_modules/example/index.js',
      'node_modules/example/package.json',
      'package.json',
    ]);
  });

  it('rejects case-insensitive duplicate paths', () => {
    expect(() => buildArchive([
      { path: 'app/A.js', data: Buffer.from('a') },
      { path: 'app/a.js', data: Buffer.from('b') },
    ])).toThrow(/Duplicate archive path/);
  });

  it('round trips through the updater reader with a required package.json', async () => {
    const root = fixture();
    const result = buildArchive(collectTree(root, 'app'));
    const work = temporary();
    const destination = path.join(work, 'staging');
    fs.mkdirSync(destination);
    const archivePath = path.join(work, 'app.tar.gz');
    fs.writeFileSync(archivePath, result.archive);
    const modulePath = '../dist/tar-read.js';
    const { extractApp } = await import(modulePath);
    await extractApp(archivePath, destination, ['package.json']);
    // The staging root contains app/; compare every listed file, including its bytes.
    for (const file of result.files) {
      expect(fs.readFileSync(path.join(destination, 'app', file.path)).equals(
        fs.readFileSync(path.join(root, file.path)),
      )).toBe(true);
    }
  });
});

describe('pure JS dependency closure', () => {
  it('accepts the fixture closure', () => {
    const root = fixture();
    expect(() => checkClosure(path.join(root, 'node_modules'))).not.toThrow();
  });

  it('refuses symlinks and names the file', () => {
    const root = fixture();
    const link = path.join(root, 'node_modules/example/link.js');
    fs.symlinkSync('index.js', link);
    expect(() => checkClosure(path.join(root, 'node_modules'))).toThrow(link);
    expect(() => collectTree(root, 'app')).toThrow(link);
  });

  it('refuses native modules and names the file', () => {
    const root = fixture();
    const file = write(root, 'node_modules/example/native.node', '');
    expect(() => checkClosure(path.join(root, 'node_modules'))).toThrow(file);
  });

  it.each(['preinstall', 'install', 'postinstall'])('refuses a %s script', script => {
    const root = fixture();
    const file = write(root, 'node_modules/example/package.json',
      JSON.stringify({ scripts: { [script]: 'node build.js' } }));
    expect(() => checkClosure(path.join(root, 'node_modules'))).toThrow(file);
  });

  it.each(['os', 'cpu'])('refuses a %s field even when empty', field => {
    const root = fixture();
    const file = write(root, 'node_modules/example/package.json',
      JSON.stringify({ [field]: [] }));
    expect(() => checkClosure(path.join(root, 'node_modules'))).toThrow(file);
  });
});
