import { gzipSync } from 'node:zlib';

export interface TarEntry {
  name: string;
  prefix?: string;
  type?: string;
  data?: Buffer | string;
  size?: number;
  linkname?: string;
  badChecksum?: boolean;
  base256Size?: boolean;
  magic?: string;
  /** GNU dialect: magic "ustar  \0" and access/change times where POSIX keeps the prefix. */
  gnu?: boolean;
}

function field(header: Buffer, offset: number, length: number, value: string): void {
  const bytes = Buffer.from(value);
  if (bytes.length > length) throw new Error('test tar: field too long');
  bytes.copy(header, offset);
}

function octal(header: Buffer, offset: number, length: number, value: number): void {
  field(header, offset, length, value.toString(8).padStart(length - 1, '0') + '\0');
}

/** Test fixtures are deterministic so failures can be reproduced from the entry list. */
export function tarBytes(entries: readonly TarEntry[], endBlocks = 2): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data ?? '');
    const header = Buffer.alloc(512);
    field(header, 0, 100, entry.name);
    octal(header, 100, 8, entry.type === '5' ? 0o755 : 0o644);
    octal(header, 108, 8, 0);
    octal(header, 116, 8, 0);
    octal(header, 124, 12, entry.size ?? data.length);
    if (entry.base256Size) header[124] = 0x80;
    octal(header, 136, 12, 0);
    header.fill(32, 148, 156);
    header[156] = (entry.type ?? '0').charCodeAt(0);
    field(header, 157, 100, entry.linkname ?? '');
    if (entry.gnu) {
      field(header, 257, 8, 'ustar  \0');
      octal(header, 345, 12, 0o14721530000);   // atime: nonzero bytes where a POSIX prefix would be
      octal(header, 357, 12, 0o14721530000);   // ctime
    } else {
      field(header, 257, 6, entry.magic ?? 'ustar\0');
      field(header, 263, 2, '00');
      field(header, 345, 155, entry.prefix ?? '');
    }
    let sum = 0;
    for (const byte of header) sum += byte;
    field(header, 148, 8, sum.toString(8).padStart(6, '0') + '\0 ');
    if (entry.badChecksum) header[0] = header[0]! ^ 1;
    chunks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  chunks.push(Buffer.alloc(endBlocks * 512));
  return Buffer.concat(chunks);
}

export function tarGzip(entries: readonly TarEntry[], endBlocks = 2): Buffer {
  return gzipSync(tarBytes(entries, endBlocks));
}

/** Alias used by the updater tests. */
export const tarGz = tarGzip;
