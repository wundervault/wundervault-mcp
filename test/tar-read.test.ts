import { describe, it, expect } from 'vitest';
import {
  existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { statSync } from 'node:fs';
import { extractApp, extractNodeMember } from '../src/tar-read.js';
import { DEFAULT_LIMITS } from '../src/release-verify.js';
import type { ReleaseLimits } from '../src/release-verify.js';
import { tarBytes, tarGzip } from './helpers/tar-write.js';
import type { TarEntry } from './helpers/tar-write.js';

interface Workspace {
  root: string;
  staging: string;
  sentinel: string;
  archive: string;
}

function workspace(): Workspace {
  const root = mkdtempSync(join(tmpdir(), 'wv-tar-'));
  const staging = join(root, 'staging');
  const sentinel = join(root, 'sentinel');
  mkdirSync(staging);
  mkdirSync(sentinel);
  return { root, staging, sentinel, archive: join(root, 'archive.tar.gz') };
}

async function isolated(use: (work: Workspace) => Promise<void>): Promise<void> {
  const work = workspace();
  try {
    await use(work);
  } finally {
    // Check this even when the rejection assertion itself fails.
    try {
      expect(readdirSync(work.sentinel)).toEqual([]);
      expect(readdirSync(work.root).sort()).toEqual(['archive.tar.gz', 'sentinel', 'staging']);
    } finally {
      rmSync(work.root, { recursive: true, force: true });
    }
  }
}

const goodPath = 'dist/index.js';
const goodEntry: TarEntry = { name: 'app/dist/index.js', data: 'hello' };

async function refusedApp(
  work: Workspace,
  entries: readonly TarEntry[],
  required: readonly string[] = [goodPath],
  limits: Readonly<ReleaseLimits> = DEFAULT_LIMITS,
  reason?: string,
): Promise<void> {
  writeFileSync(work.archive, tarGzip(entries));
  const result = extractApp(work.archive, work.staging, required, limits);
  if (reason) await expect(result).rejects.toThrow(reason);
  else await expect(result).rejects.toThrow(/^archive: /);
}

describe('the root updater app archive reader', () => {
  it('extracts a safe tree, with explicit and implicit directories', async () => {
    await isolated(async work => {
      const entries: TarEntry[] = [
        { name: 'app/', type: '5' },
        { name: 'app/dist/', type: '5' },
        goodEntry,
        { name: 'app/package.json', data: '{}' },
        { name: 'app/node_modules/pkg/index.js', data: 'export {};' },
        { name: 'app/bin/_handover.js', data: 'handover' },
        { name: 'app/node_modules/@noble/hashes/_blake.js', data: 'hash' },
        { name: 'app/empty.txt', data: '' },
        { name: 'app/empty-dir/', type: '5' },
      ];
      const files: [string, string][] = [
        [goodPath, 'hello'], ['package.json', '{}'], ['node_modules/pkg/index.js', 'export {};'],
        ['bin/_handover.js', 'handover'], ['node_modules/@noble/hashes/_blake.js', 'hash'], ['empty.txt', ''],
      ];
      writeFileSync(work.archive, tarGzip(entries));
      await extractApp(work.archive, work.staging, [goodPath, 'package.json']);
      for (const [relative, data] of files) {
        const path = join(work.staging, 'app', relative);
        expect(readFileSync(path, 'utf8')).toBe(data);
        if (process.platform !== 'win32') expect(lstatSync(path).mode & 0o777).toBe(0o644);
      }
      expect(readdirSync(join(work.staging, 'app')).sort()).toEqual([
        'bin', 'dist', 'empty-dir', 'empty.txt', 'node_modules', 'package.json',
      ]);
      if (process.platform !== 'win32') {
        expect(lstatSync(join(work.staging, 'app', 'node_modules')).mode & 0o777).toBe(0o755);
      }
    });
  });

  it('accepts a NUL regular-file typeflag', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([{ ...goodEntry, type: '\0' }]));
      await extractApp(work.archive, work.staging, [goodPath]);
      expect(readFileSync(join(work.staging, 'app', goodPath), 'utf8')).toBe('hello');
    });
  });

  it('combines the ustar prefix and name fields', async () => {
    await isolated(async work => {
      const path = `${'a'.repeat(90)}/${'b'.repeat(90)}/x.js`;
      writeFileSync(work.archive, tarGzip([{ prefix: `app/${'a'.repeat(90)}`, name: `${'b'.repeat(90)}/x.js`, data: 'x' }]));
      await extractApp(work.archive, work.staging, [path]);
      expect(readFileSync(join(work.staging, 'app', path), 'utf8')).toBe('x');
    });
  });

  const types: [string, string][] = [
    ['symlink', '2'], ['hardlink', '1'], ['character device', '3'], ['block device', '4'],
    ['FIFO', '6'], ['contiguous file', '7'], ['pax local header', 'x'], ['pax global header', 'g'],
    ['GNU long name', 'L'], ['GNU long link', 'K'], ['unknown type', 'Z'],
  ];
  for (const [name, type] of types) {
    it(`refuses ${name} entries`, async () => {
      await isolated(async work => {
        await refusedApp(work, [{ ...goodEntry, type, linkname: '../../sentinel/escape' }]);
        expect(readdirSync(work.staging)).toEqual([]);
      });
    });
  }

  const rejected: [string, readonly TarEntry[], readonly string[], string][] = [
    ['missing required file', [], [goodPath], 'archive: missing required file app/dist/index.js'],
    ['directory instead of required file', [{ name: 'app/dist/index.js/', type: '5' }],
      [goodPath], 'archive: missing required file app/dist/index.js'],
    ['wrong case for required file', [{ name: 'app/DIST/INDEX.JS', data: 'hello' }],
      [goodPath], 'archive: missing required file app/dist/index.js'],
    ['duplicate file', [goodEntry, goodEntry], [goodPath], 'archive: duplicate entry app/dist/index.js'],
    ['case-insensitive duplicate file', [goodEntry, { name: 'app/DIST/INDEX.JS', data: 'x' }],
      [goodPath], 'archive: duplicate entry app/DIST/INDEX.JS'],
    ['file then directory', [goodEntry, { name: 'app/dist/index.js/', type: '5' }],
      [goodPath], 'archive: duplicate entry app/dist/index.js'],
    ['directory then file', [{ name: 'app/DIST/INDEX.JS/', type: '5' }, goodEntry],
      [goodPath], 'archive: duplicate entry app/dist/index.js'],
    ['implicit directory then file', [goodEntry, { name: 'app/DIST', data: 'x' }],
      [goodPath], 'archive: duplicate entry app/DIST'],
    ['file under a file', [{ name: 'app/dist', data: 'x' }, goodEntry],
      [goodPath], 'archive: entry under a file app/dist/index.js'],
    ['file under a case-insensitive file', [{ name: 'app/DIST', data: 'x' }, goodEntry],
      [goodPath], 'archive: entry under a file app/dist/index.js'],
    ['parent traversal', [{ name: 'app/../../sentinel/escape', data: 'x' }], [goodPath], 'archive: invalid app path'],
    ['nested parent traversal', [{ name: 'app/dist/../../../sentinel/escape', data: 'x' }],
      [goodPath], 'archive: invalid app path'],
    ['absolute path', [{ name: '/sentinel/escape', data: 'x' }], [goodPath], 'archive: invalid app path'],
    ['absolute path under app', [{ name: 'app//sentinel/escape', data: 'x' }], [goodPath], 'archive: invalid app path'],
    ['dot segment', [{ name: 'app/./dist/index.js', data: 'hello' }], [goodPath], 'archive: invalid app path'],
    ['dotfile', [{ name: 'app/dist/.hidden', data: 'x' }], [goodPath], 'archive: invalid app path'],
    ['backslash path', [{ name: 'app/..\\sentinel\\escape', data: 'x' }], [goodPath], 'archive: invalid app path'],
    ['17-deep path', [{ name: `app/${Array(17).fill('a').join('/')}`, data: 'x' }],
      [goodPath], 'archive: invalid app path'],
    ['wrong top-level directory', [{ name: 'other/dist/index.js', data: 'hello' }],
      [goodPath], 'archive: invalid app path'],
    ['directory traversal', [{ name: 'app/../sentinel/', type: '5' }], [goodPath], 'archive: invalid app path'],
    ['directory data', [{ name: 'app/dist/', type: '5', data: 'x' }], [goodPath], 'archive: directory has data'],
    ['bad checksum', [{ ...goodEntry, badChecksum: true }], [goodPath], 'archive: checksum mismatch'],
    ['base-256 size', [{ ...goodEntry, base256Size: true }], [goodPath], 'archive: base-256 size'],
    ['non-ustar header', [{ ...goodEntry, magic: 'other\0' }], [goodPath], 'archive: not ustar'],
    ['unsafe required path', [goodEntry], ['../../sentinel/escape'], 'archive: invalid required file'],
  ];
  for (const [name, entries, required, reason] of rejected) {
    it(`refuses ${name} without writing outside staging`, async () => {
      await isolated(async work => refusedApp(work, entries, required, DEFAULT_LIMITS, reason));
    });
  }

  it('rejects a pre-planted directory symlink without following it', async () => {
    await isolated(async work => {
      symlinkSync(work.sentinel, join(work.staging, 'app'), process.platform === 'win32' ? 'junction' : 'dir');
      await refusedApp(work, [goodEntry], [goodPath], DEFAULT_LIMITS, 'archive: staging not empty');
    });
  });

  it('rejects a symlink as staging itself', async () => {
    await isolated(async work => {
      rmSync(work.staging, { recursive: true });
      symlinkSync(work.sentinel, work.staging, process.platform === 'win32' ? 'junction' : 'dir');
      await refusedApp(work, [goodEntry], [goodPath], DEFAULT_LIMITS, 'archive: unsafe directory');
    });
  });

  it('refuses a non-empty staging directory', async () => {
    await isolated(async work => {
      writeFileSync(join(work.staging, 'existing'), 'keep');
      await refusedApp(work, [goodEntry], [goodPath], DEFAULT_LIMITS, 'archive: staging not empty');
      expect(readFileSync(join(work.staging, 'existing'), 'utf8')).toBe('keep');
    });
  });

  it('enforces the compressed size cap', async () => {
    await isolated(async work => {
      await refusedApp(work, [goodEntry], [goodPath], { ...DEFAULT_LIMITS, maxArchiveBytes: 1 }, 'archive: compressed size limit');
    });
  });

  it('enforces the decompressed size cap', async () => {
    await isolated(async work => {
      const data = Buffer.alloc(128 * 1024, 0);
      await refusedApp(work, [{ name: 'app/large', data }], ['large'],
        { ...DEFAULT_LIMITS, maxUnpackedBytes: 4096 }, 'archive: unpacked size limit');
    });
  });

  it('counts directory entries against the entry cap', async () => {
    await isolated(async work => {
      await refusedApp(work, [{ name: 'app/', type: '5' }, goodEntry], [goodPath],
        { ...DEFAULT_LIMITS, maxEntries: 1 }, 'archive: entry count limit');
    });
  });

  it('enforces the file-count cap before writing the excess file', async () => {
    await isolated(async work => {
      await refusedApp(work, [goodEntry, { name: 'app/extra', data: 'x' }], [goodPath],
        { ...DEFAULT_LIMITS, maxFiles: 1 }, 'archive: file count limit');
      expect(readFileSync(join(work.staging, 'app', goodPath), 'utf8')).toBe('hello');
      expect(existsSync(join(work.staging, 'app', 'extra'))).toBe(false);
    });
    await isolated(async work => {
      await refusedApp(work, [goodEntry], [goodPath],
        { ...DEFAULT_LIMITS, maxFiles: 0 }, 'archive: file count limit');
      expect(readdirSync(work.staging)).toEqual([]);
    });
  });

  it('enforces the per-file cap before writing the file', async () => {
    await isolated(async work => {
      await refusedApp(work, [goodEntry], [goodPath],
        { ...DEFAULT_LIMITS, maxFileBytes: 4 }, 'archive: file size limit');
      expect(readdirSync(work.staging)).toEqual([]);
    });
  });

  it('accepts exact file-count and per-file limits', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([goodEntry]));
      await extractApp(work.archive, work.staging, [goodPath], {
        ...DEFAULT_LIMITS, maxFiles: 1, maxFileBytes: 5,
      });
      expect(readFileSync(join(work.staging, 'app', goodPath), 'utf8')).toBe('hello');
    });
  });

  it('rejects invalid limits', async () => {
    for (const value of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      await isolated(async work => {
        await refusedApp(work, [goodEntry], [goodPath],
          { ...DEFAULT_LIMITS, maxFiles: value }, 'archive: invalid limits');
        expect(readdirSync(work.staging)).toEqual([]);
      });
    }
  });

  it('requires two end blocks', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([goodEntry], 1));
      await expect(extractApp(work.archive, work.staging, [goodPath])).rejects.toThrow('archive: invalid end blocks');
    });
  });

  it('accepts trailing zero padding', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([goodEntry], 8));
      await extractApp(work.archive, work.staging, [goodPath]);
    });
  });

  it('refuses nonzero data after the end blocks', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, gzipSync(Buffer.concat([tarBytes([goodEntry]), Buffer.alloc(512, 1)])));
      await expect(extractApp(work.archive, work.staging, [goodPath])).rejects.toThrow('archive: nonzero trailing data');
    });
  });

  it('refuses truncated headers and truncated file data', async () => {
    for (const length of [100, 514]) {
      await isolated(async work => {
        writeFileSync(work.archive, gzipSync(tarBytes([goodEntry]).subarray(0, length)));
        await expect(extractApp(work.archive, work.staging, [goodPath])).rejects.toThrow('archive: truncated data');
      });
    }
  });

  it('refuses a corrupt gzip stream', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, Buffer.from('not gzip'));
      await expect(extractApp(work.archive, work.staging, [goodPath])).rejects.toThrow(/^archive: /);
    });
  });

  it('refuses non-octal sizes even with a correct checksum', async () => {
    await isolated(async work => {
      const tar = tarBytes([goodEntry]);
      tar[124] = 0x39;
      tar.fill(32, 148, 156);
      let sum = 0;
      for (const byte of tar.subarray(0, 512)) sum += byte;
      tar.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
      writeFileSync(work.archive, gzipSync(tar));
      await expect(extractApp(work.archive, work.staging, [goodPath])).rejects.toThrow('archive: invalid octal field');
    });
  });

  it('does not trust a traversal hidden in the ustar prefix', async () => {
    await isolated(async work => {
      await refusedApp(work, [{ prefix: 'app/../../sentinel', name: 'escape', data: 'x' }], [goodPath],
        DEFAULT_LIMITS, 'archive: invalid app path');
    });
  });
});

describe('the root updater Node archive reader', () => {
  const member = 'node-v22.23.4-linux-x64/bin/node';

  it('writes only the expected member and skips links and unrelated data', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([
        { name: 'node-v22.23.4-linux-x64/', type: '5' },
        { name: 'node-v22.23.4-linux-x64/bin/npm', type: '2', linkname: '../lib/npm.js' },
        { name: '../../sentinel/escape', type: '1', linkname: member },
        { name: '/absolute/ignored', data: 'ignored' },
        { name: member, data: 'node binary' },
      ]));
      const destination = join(work.staging, 'node');
      await extractNodeMember(work.archive, member, destination);
      expect(readFileSync(destination, 'utf8')).toBe('node binary');
      expect(readdirSync(work.staging)).toEqual(['node']);
      if (process.platform !== 'win32') expect(lstatSync(destination).mode & 0o777).toBe(0o755);
    });
  });

  const failures: [string, readonly TarEntry[], string][] = [
    ['missing member', [{ name: 'other', data: 'x' }], 'archive: node member missing'],
    ['symlink member', [{ name: member, type: '2', linkname: '../../sentinel/escape' }], 'archive: node member not regular'],
    ['hardlink member', [{ name: member, type: '1', linkname: '../../sentinel/escape' }], 'archive: node member not regular'],
    ['directory member', [{ name: member, type: '5' }], 'archive: node member not regular'],
    ['duplicate member', [{ name: member, data: 'one' }, { name: member, data: 'two' }], 'archive: duplicate node member'],
    ['bad checksum', [{ name: member, data: 'x', badChecksum: true }], 'archive: checksum mismatch'],
    ['base-256 size', [{ name: member, data: 'x', base256Size: true }], 'archive: base-256 size'],
  ];
  for (const [name, entries, reason] of failures) {
    it(`refuses ${name} without writing outside staging`, async () => {
      await isolated(async work => {
        writeFileSync(work.archive, tarGzip(entries));
        await expect(extractNodeMember(work.archive, member, join(work.staging, 'node'))).rejects.toThrow(reason);
      });
    });
  }

  it('does not replace an existing destination', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([{ name: member, data: 'new' }]));
      const destination = join(work.staging, 'node');
      writeFileSync(destination, 'original');
      await expect(extractNodeMember(work.archive, member, destination)).rejects.toThrow(/^archive: /);
      expect(readFileSync(destination, 'utf8')).toBe('original');
    });
  });

  it('does not follow a destination symlink', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([{ name: member, data: 'new' }]));
      const destination = join(work.staging, 'node');
      const outside = join(work.sentinel, 'escape');
      // A directory junction avoids Windows' privilege requirement for file symlinks.
      symlinkSync(work.sentinel, destination, process.platform === 'win32' ? 'junction' : 'dir');
      await expect(extractNodeMember(work.archive, member, destination)).rejects.toThrow(/^archive: /);
      expect(existsSync(outside)).toBe(false);
    });
  });

  it('enforces the Node member size cap', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([{ name: member, data: 'node' }]));
      await expect(extractNodeMember(work.archive, member, join(work.staging, 'node'),
        { ...DEFAULT_LIMITS, maxFileBytes: 3 })).rejects.toThrow('archive: node member size limit');
    });
  });

  it('counts skipped data against the decompressed cap', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([
        { name: 'ignored', data: Buffer.alloc(128 * 1024) },
        { name: member, data: 'node' },
      ]));
      await expect(extractNodeMember(work.archive, member, join(work.staging, 'node'),
        { ...DEFAULT_LIMITS, maxUnpackedBytes: 4096 })).rejects.toThrow('archive: unpacked size limit');
    });
  });

  it('counts skipped entries against the entry cap', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([{ name: 'ignored', data: '' }, { name: member, data: 'node' }]));
      await expect(extractNodeMember(work.archive, member, join(work.staging, 'node'),
        { ...DEFAULT_LIMITS, maxEntries: 1 })).rejects.toThrow('archive: entry count limit');
    });
  });

  it('enforces the Node compressed-size cap', async () => {
    await isolated(async work => {
      writeFileSync(work.archive, tarGzip([{ name: member, data: 'node' }]));
      await expect(extractNodeMember(work.archive, member, join(work.staging, 'node'),
        { ...DEFAULT_LIMITS, maxArchiveBytes: 1 })).rejects.toThrow('archive: compressed size limit');
    });
  });
});

describe('GNU-format headers (the official Node archives use them)', () => {
  it('extracts the member from GNU headers whose prefix bytes hold timestamps', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'wv-gnu-'));
    const archive = join(dir, 'node.tar.gz');
    const body = Buffer.from('#!node binary stand-in');
    writeFileSync(archive, tarGzip([
      { name: 'node-v1.2.3-linux-x64/', type: '5', gnu: true },
      { name: 'node-v1.2.3-linux-x64/bin/', type: '5', gnu: true },
      { name: 'node-v1.2.3-linux-x64/bin/node', data: body, gnu: true },
      { name: 'node-v1.2.3-linux-x64/bin/npm', type: '2', linkname: '../lib/npm.js', gnu: true },
    ]));
    const dest = join(dir, 'node');
    await extractNodeMember(archive, 'node-v1.2.3-linux-x64/bin/node', dest);
    expect(readFileSync(dest)).toEqual(body);
  });

  // Opt-in: WV_REAL_NODE_TARBALL=/path/node-vX-linux-x64.tar.gz WV_REAL_NODE_MEMBER=node-vX-linux-x64/bin/node
  const real = process.env.WV_REAL_NODE_TARBALL;
  it.skipIf(!real || !existsSync(real))('extracts bin/node from a real Node release archive', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'wv-realnode-'));
    const dest = join(dir, 'node');
    try {
      await extractNodeMember(real!, process.env.WV_REAL_NODE_MEMBER!, dest);
      expect(statSync(dest).size).toBeGreaterThan(10_000_000);
    } finally {
      rmSync(dir, { recursive: true, force: true });   // a 120 MB binary per run otherwise stays in /tmp
    }
  }, 120_000);
});
