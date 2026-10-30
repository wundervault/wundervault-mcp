import { createHash, createPublicKey, verify } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { TextDecoder } from 'node:util';
import type { ReleaseKey } from './release-keys.js';

export type Platform = 'linux-x64' | 'linux-arm64' | 'darwin-x64' | 'darwin-arm64' | 'win-x64' | 'win-arm64';

const PLATFORMS: readonly Platform[] = [
  'linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'win-x64', 'win-arm64',
];

export const ALLOWED_HOSTS: readonly string[] = [
  'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com', 'nodejs.org',
];

export interface ReleaseLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxArchiveBytes: number;
  maxUnpackedBytes: number;
  maxEntries: number;
}

export const DEFAULT_LIMITS: Readonly<ReleaseLimits> = {
  maxFiles: 20000,
  maxFileBytes: 200 * 1024 * 1024,
  maxArchiveBytes: 200 * 1024 * 1024,
  maxUnpackedBytes: 300 * 1024 * 1024,
  maxEntries: 40000,
};

export interface ReleaseFile {
  path: string;
  sha256: string;
  size: number;
}

interface NodeArchive {
  url: string;
  sha256: string;
  member: string;
}

interface NodeExecutable {
  url: string;
  sha256: string;
}

export interface ReleaseRecord {
  format: 'wundervault-release-1';
  version: string;
  app: {
    url: string;
    sha256: string;
  };
  node: {
    version: string;
    'linux-x64'?: NodeArchive;
    'linux-arm64'?: NodeArchive;
    'darwin-x64'?: NodeArchive;
    'darwin-arm64'?: NodeArchive;
    'win-x64'?: NodeExecutable;
    'win-arm64'?: NodeExecutable;
  };
  notes_url: string;
}

export function platformKey(platform: string, arch: string): Platform | null {
  const key = `${platform === 'win32' ? 'win' : platform}-${arch}`;
  return PLATFORMS.includes(key as Platform) ? key as Platform : null;
}

function urlOnHosts(value: string, hosts: readonly string[]): boolean {
  // URL accepts backslashes, whitespace and empty userinfo. None belongs in a release URL.
  if (typeof value !== 'string' || /[\s\\\u0000-\u001f\u007f]/.test(value)) return false;
  const authority = /^https:\/\/([^/?#]*)/i.exec(value);
  if (!authority || authority[1]!.includes('@')) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password &&
      (url.port === '' || url.port === '443') && hosts.includes(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

export function isAllowedUrl(value: string): boolean {
  return urlOnHosts(value, ALLOWED_HOSTS);
}

/** Keep components as decimal strings so even very large versions compare without rounding. */
export function parseVersion(version: string): [string, string, string] | null {
  if (typeof version !== 'string' || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
    return null;
  }
  const parts = version.split('.');
  return [parts[0]!, parts[1]!, parts[2]!];
}

export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) throw new Error('version: invalid');
  for (let i = 0; i < 3; i++) {
    const x = left[i]!;
    const y = right[i]!;
    if (x.length !== y.length) return x.length < y.length ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function decodeJson(bytes: Buffer): unknown {
  // Replacement characters would let the verifier and the publisher read different text.
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  return JSON.parse(text) as unknown;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function base64(value: unknown, length: number): Buffer | null {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === length && bytes.toString('base64') === value ? bytes : null;
}

export function verifySignatures(
  record: Buffer,
  sigs: Buffer,
  keys: readonly ReleaseKey[],
): { ok: true; keyId: string } | { ok: false; reason: string } {
  let entries: { keyId: string; signature: Buffer }[];
  try {
    if (sigs.length > 64 * 1024) return { ok: false, reason: 'signatures: too large' };
    const parsed = decodeJson(sigs);
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 8) {
      return { ok: false, reason: 'signatures: invalid list' };
    }
    entries = [];
    for (const entry of parsed) {
      if (!object(entry) || Object.keys(entry).length !== 2 ||
          !Object.hasOwn(entry, 'key_id') || !Object.hasOwn(entry, 'sig') ||
          typeof entry.key_id !== 'string' || entry.key_id.length === 0) {
        return { ok: false, reason: 'signatures: invalid entry' };
      }
      const signature = base64(entry.sig, 64);
      if (!signature) return { ok: false, reason: 'signatures: invalid signature' };
      entries.push({ keyId: entry.key_id, signature });
    }
  } catch {
    return { ok: false, reason: 'signatures: invalid JSON' };
  }

  // Validate the whole envelope before accepting any signature in it.
  for (const entry of entries) {
    for (const key of keys) {
      if (key.id !== entry.keyId) continue;
      const raw = base64(key.publicKey, 32);
      if (!raw) continue;
      try {
        const publicKey = createPublicKey({
          format: 'jwk',
          key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
        });
        if (verify(null, record, publicKey, entry.signature)) return { ok: true, keyId: key.id };
      } catch {
        // A bad configured key must not hide a valid signature from another configured key.
      }
    }
  }
  return { ok: false, reason: 'signatures: no trusted signature' };
}

class RecordProblem extends Error {}

function fail(reason: string): never {
  throw new RecordProblem(`record: ${reason}`);
}

function shape(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  path: string,
): Record<string, unknown> {
  if (!object(value)) fail(`invalid ${path}`);
  for (const key of Object.keys(value)) {
    if (!required.includes(key) && !optional.includes(key)) fail(`unknown key ${path}.${key}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) fail(`missing key ${path}.${key}`);
  }
  return value;
}

function checkHash(value: unknown, path: string): void {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail(`invalid ${path}`);
}

function checkUrl(value: unknown, path: string): asserts value is string {
  if (typeof value !== 'string' || !isAllowedUrl(value)) fail(`invalid ${path}`);
}

/**
 * The only path shape an app archive entry may have: relative, '/'-separated, at most 16 deep,
 * each part 1–100 of letters, digits and @ _ . + - and not starting with a dot (no '.', '..' or
 * dotfiles). '_' may lead: our own bin/_handover.js and @noble/hashes/_blake.js do (found
 * 2026-10-30 packing the real repo).
 */
export const APP_PATH = /^[A-Za-z0-9@_][A-Za-z0-9@._+-]{0,99}(\/[A-Za-z0-9@_][A-Za-z0-9@._+-]{0,99}){0,15}$/;

export function safeAppPath(path: string): boolean {
  return APP_PATH.test(path) && !path.split('/').some(part => part === '.' || part === '..');
}

export function parseRecord(
  bytes: Buffer,
  expectVersion: string,
  limits: Readonly<ReleaseLimits> = DEFAULT_LIMITS,
): { ok: true; record: ReleaseRecord } | { ok: false; reason: string } {
  try {
    if (bytes.length > 64 * 1024) fail('too large');
    for (const value of Object.values(limits)) {
      if (!Number.isSafeInteger(value) || value < 0) fail('invalid limits');
    }
    const root = shape(decodeJson(bytes), ['format', 'version', 'app', 'node', 'notes_url'], [], 'record');
    if (root.format !== 'wundervault-release-1') fail('invalid format');
    if (typeof root.version !== 'string' || !parseVersion(root.version)) fail('invalid version');
    if (root.version !== expectVersion) fail('version mismatch');

    // No per-file list: the archive's SHA-256 is in this signed record and is checked before the
    // archive is opened, so its whole content is already signed. The reader checks every entry by
    // rule instead (src/tar-read.ts). A list of ~3,000 files made the record 550 KB — too big to
    // sign through the vault — and added nothing (found 2026-10-30 packing the real repo).
    const app = shape(root.app, ['url', 'sha256'], [], 'app');
    checkUrl(app.url, 'app.url');
    checkHash(app.sha256, 'app.sha256');

    const node = shape(root.node, ['version'], PLATFORMS, 'node');
    if (typeof node.version !== 'string' || !parseVersion(node.version)) fail('invalid node.version');
    for (const platform of PLATFORMS) {
      if (!Object.hasOwn(node, platform)) continue;
      const tar = !platform.startsWith('win-');
      const where = `node.${platform}`;
      const item = shape(node[platform], tar ? ['url', 'sha256', 'member'] : ['url', 'sha256'], [], where);
      checkUrl(item.url, `${where}.url`);
      checkHash(item.sha256, `${where}.sha256`);
      const url = new URL(item.url);
      const suffix = tar ? `/node-v${node.version}-${platform}.tar.gz` : `/${platform}/node.exe`;
      if (!url.pathname.endsWith(suffix) || url.search !== '' || url.hash !== '') fail(`invalid ${where}.url`);
      if (tar && item.member !== `node-v${node.version}-${platform}/bin/node`) fail(`invalid ${where}.member`);
    }

    if (typeof root.notes_url !== 'string' ||
        !(isAllowedUrl(root.notes_url) || urlOnHosts(root.notes_url, ['wundervault.com']))) {
      fail('invalid notes_url');
    }
    return { ok: true, record: root as unknown as ReleaseRecord };
  } catch (error) {
    return { ok: false, reason: error instanceof RecordProblem ? error.message : 'record: invalid JSON' };
  }
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}
