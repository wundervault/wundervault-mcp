import { describe, it, expect } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ALLOWED_HOSTS, APP_PATH, DEFAULT_LIMITS, compareVersions, isAllowedUrl, parseRecord, parseVersion,
  platformKey, safeAppPath, sha256File, verifySignatures,
} from '../src/release-verify.js';
import type { ReleaseRecord } from '../src/release-verify.js';
import type { ReleaseKey } from '../src/release-keys.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const exported = publicKey.export({ format: 'jwk' });
const key: ReleaseKey = {
  id: 'test-owner',
  publicKey: Buffer.from(exported.x!, 'base64url').toString('base64'),
  test: true,
};
const hash = 'a'.repeat(64);

function fixture(): ReleaseRecord {
  return {
    format: 'wundervault-release-1',
    version: '2.2.0',
    app: {
      url: 'https://github.com/wundervault/mcp/releases/download/v2.2.0/wundervault-app-2.2.0.tar.gz',
      sha256: hash,
    },
    node: {
      version: '22.23.4',
      'linux-x64': {
        url: 'https://nodejs.org/dist/v22.23.4/node-v22.23.4-linux-x64.tar.gz',
        sha256: hash,
        member: 'node-v22.23.4-linux-x64/bin/node',
      },
      'win-x64': {
        url: 'https://nodejs.org/dist/v22.23.4/win-x64/node.exe',
        sha256: hash,
      },
    },
    notes_url: 'https://wundervault.com/changelog',
  };
}

function bytes(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value));
}

function signatures(record: Buffer): Buffer {
  return bytes([{ key_id: key.id, sig: sign(null, record, privateKey).toString('base64') }]);
}

describe('release signatures', () => {
  it('accepts the exact bytes signed by a configured ed25519 key', () => {
    const record = bytes(fixture());
    expect(verifySignatures(record, signatures(record), [key])).toEqual({ ok: true, keyId: key.id });
  });

  it('refuses a changed record byte', () => {
    const record = bytes(fixture());
    const changed = Buffer.from(record);
    changed[10] = changed[10]! ^ 1;
    expect(verifySignatures(changed, signatures(record), [key]).ok).toBe(false);
  });

  it('skips unknown key ids but refuses an unknown key alone', () => {
    const record = bytes(fixture());
    const sig = sign(null, record, privateKey).toString('base64');
    expect(verifySignatures(record, signatures(record), []).ok).toBe(false);
    expect(verifySignatures(record, bytes([{ key_id: 'unknown', sig }]), [key]).ok).toBe(false);
    expect(verifySignatures(record, bytes([
      { key_id: 'unknown', sig },
      { key_id: key.id, sig },
    ]), [key]).ok).toBe(true);
  });

  it('refuses a bad signature by a trusted key', () => {
    const record = bytes(fixture());
    expect(verifySignatures(record, bytes([
      { key_id: key.id, sig: Buffer.alloc(64).toString('base64') },
    ]), [key])).toEqual({ ok: false, reason: 'signatures: no trusted signature' });
  });

  it('accepts a good signature after a bad signature', () => {
    const record = bytes(fixture());
    expect(verifySignatures(record, bytes([
      { key_id: key.id, sig: Buffer.alloc(64).toString('base64') },
      { key_id: key.id, sig: sign(null, record, privateKey).toString('base64') },
    ]), [key]).ok).toBe(true);
  });

  const badEnvelopes: [string, Buffer][] = [
    ['invalid JSON', Buffer.from('{')],
    ['invalid UTF-8', Buffer.from([0xff])],
    ['object instead of array', bytes({})],
    ['empty array', bytes([])],
    ['too many signatures', bytes(Array.from({ length: 9 }, () => ({
      key_id: key.id, sig: Buffer.alloc(64).toString('base64'),
    })))],
    ['null entry', bytes([null])],
    ['missing key id', bytes([{ sig: Buffer.alloc(64).toString('base64') }])],
    ['empty key id', bytes([{ key_id: '', sig: Buffer.alloc(64).toString('base64') }])],
    ['non-string key id', bytes([{ key_id: 1, sig: Buffer.alloc(64).toString('base64') }])],
    ['unknown entry key', bytes([{ key_id: key.id, sig: Buffer.alloc(64).toString('base64'), extra: 1 }])],
    ['missing signature', bytes([{ key_id: key.id }])],
    ['non-string signature', bytes([{ key_id: key.id, sig: 1 }])],
    ['wrong signature length', bytes([{ key_id: key.id, sig: Buffer.alloc(63).toString('base64') }])],
    ['invalid base64', bytes([{ key_id: key.id, sig: '!'.repeat(88) }])],
    ['noncanonical base64', bytes([{ key_id: key.id, sig: Buffer.alloc(64).toString('base64').replace(/=+$/, '') }])],
    ['oversized envelope', Buffer.alloc(64 * 1024 + 1, 32)],
  ];
  for (const [name, envelope] of badEnvelopes) {
    it(`refuses ${name}`, () => expect(verifySignatures(bytes(fixture()), envelope, [key]).ok).toBe(false));
  }

  it('does not accept a valid signature before a malformed entry', () => {
    const record = bytes(fixture());
    const good = { key_id: key.id, sig: sign(null, record, privateKey).toString('base64') };
    expect(verifySignatures(record, bytes([good, { key_id: 'unknown', sig: 'bad' }]), [key]).ok).toBe(false);
  });

  it('does not throw for malformed configured key material', () => {
    const record = bytes(fixture());
    expect(verifySignatures(record, signatures(record), [{ id: key.id, publicKey: 'bad' }]).ok).toBe(false);
  });
});

describe('release URLs', () => {
  for (const host of ALLOWED_HOSTS) {
    it(`accepts ${host}`, () => expect(isAllowedUrl(`https://${host}/release`)).toBe(true));
  }
  it('compares hosts without case and permits the HTTPS port', () => {
    expect(isAllowedUrl('https://GITHUB.COM:443/release')).toBe(true);
  });
  const refused = [
    'http://github.com/release',
    'ftp://github.com/release',
    'https://github.com:444/release',
    'https://user@github.com/release',
    'https://user:password@github.com/release',
    'https://@github.com/release',
    'https://github.com.evil.example/release',
    'https://evil.github.com/release',
    'https://github.com./release',
    'https://wundervault.com/release',
    'https://127.0.0.1/release',
    ' https://github.com/release',
    'https://github.com\\evil/release',
    'https://github.com/\nrelease',
    'not a URL',
  ];
  for (const url of refused) it(`refuses ${JSON.stringify(url)}`, () => expect(isAllowedUrl(url)).toBe(false));
});

describe('release versions and platforms', () => {
  for (const version of ['0.0.0', '1.2.3', '999999999999999999999999.0.1']) {
    it(`parses ${version}`, () => expect(parseVersion(version)).not.toBeNull());
  }
  for (const version of ['', '1.2', '1.2.3.4', '01.2.3', '1.02.3', '1.2.03', '-1.2.3', 'v1.2.3',
    '1.2.3-rc.1', '1.2.3+build', ' 1.2.3', '1.2.3\n', '1.a.3']) {
    it(`refuses version ${JSON.stringify(version)}`, () => expect(parseVersion(version)).toBeNull());
  }
  it('compares components numerically without rounding', () => {
    expect(compareVersions('2.10.0', '2.9.99')).toBe(1);
    expect(compareVersions('2.0.0', '2.0.1')).toBe(-1);
    expect(compareVersions('2.0.0', '2.0.0')).toBe(0);
    expect(compareVersions('999999999999999999999998.0.0', '999999999999999999999999.0.0')).toBe(-1);
    expect(() => compareVersions('bad', '1.0.0')).toThrow('version: invalid');
  });
  for (const platform of ['linux', 'darwin', 'win32']) {
    for (const arch of ['x64', 'arm64']) {
      it(`selects ${platform}/${arch}`, () => {
        expect(platformKey(platform, arch)).toBe(`${platform === 'win32' ? 'win' : platform}-${arch}`);
      });
    }
  }
  it('refuses unsupported platforms and architectures', () => {
    expect(platformKey('freebsd', 'x64')).toBeNull();
    expect(platformKey('linux', 'ia32')).toBeNull();
  });
});

describe('safe app paths', () => {
  for (const path of [
    'dist/index.js', 'bin/_handover.js', 'node_modules/@noble/hashes/_blake.js',
    '_leading/_segment.js', '@scope/pkg/node_modules/x.js',
    Array(16).fill('a'.repeat(100)).join('/'),
  ]) {
    it(`accepts ${JSON.stringify(path)}`, () => {
      expect(APP_PATH.test(path)).toBe(true);
      expect(safeAppPath(path)).toBe(true);
    });
  }

  for (const path of [
    '', '/absolute', '..', '../outside', 'a/../b', '.', 'a/./b', './a', 'a//b', 'a/', 'a\\b',
    '-a', '.hidden', 'a/.hidden', 'a b', 'a:stream', 'a\u0000b', 'é',
    'a'.repeat(101), Array(17).fill('a').join('/'),
  ]) {
    it(`refuses ${JSON.stringify(path)}`, () => expect(safeAppPath(path)).toBe(false));
  }
});

describe('release record shape', () => {
  it('accepts a complete record', () => {
    const record = fixture();
    expect(parseRecord(bytes(record), record.version)).toEqual({ ok: true, record });
  });
  it('allows omitted platform records', () => {
    const record = fixture();
    record.node = { version: '22.23.4' };
    expect(parseRecord(bytes(record), record.version).ok).toBe(true);
  });
  it('accepts every platform record', () => {
    const record = fixture();
    for (const platform of ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64'] as const) {
      record.node[platform] = {
        url: `https://nodejs.org/dist/v22.23.4/node-v22.23.4-${platform}.tar.gz`,
        sha256: hash,
        member: `node-v22.23.4-${platform}/bin/node`,
      };
    }
    record.node['win-arm64'] = {
      url: 'https://nodejs.org/dist/v22.23.4/win-arm64/node.exe',
      sha256: hash,
    };
    expect(parseRecord(bytes(record), record.version).ok).toBe(true);
  });

  const invalid: [string, (record: ReleaseRecord) => unknown][] = [
    ['root is an array', () => []],
    ['root is null', () => null],
    ['wrong format', r => ({ ...r, format: 'other' })],
    ['invalid release version', r => ({ ...r, version: '02.2.0' })],
    ['version mismatch', r => ({ ...r, version: '2.2.1' })],
    ['missing root key', r => { const { notes_url: _notes, ...rest } = r; return rest; }],
    ['unknown root key', r => ({ ...r, extra: true })],
    ['app is null', r => ({ ...r, app: null })],
    ['missing app key', r => ({ ...r, app: { url: r.app.url } })],
    ['unknown app key', r => ({ ...r, app: { ...r.app, extra: true } })],
    ['off-host app URL', r => ({ ...r, app: { ...r.app, url: 'https://evil.example/app.tar.gz' } })],
    ['non-string app URL', r => ({ ...r, app: { ...r.app, url: 1 } })],
    ['uppercase app hash', r => ({ ...r, app: { ...r.app, sha256: 'A'.repeat(64) } })],
    ['short app hash', r => ({ ...r, app: { ...r.app, sha256: 'a'.repeat(63) } })],
    ['non-hex app hash', r => ({ ...r, app: { ...r.app, sha256: 'g'.repeat(64) } })],
    ['non-string app hash', r => ({ ...r, app: { ...r.app, sha256: null } })],
    ['node is null', r => ({ ...r, node: null })],
    ['missing node version', r => ({ ...r, node: {} })],
    ['invalid node version', r => ({ ...r, node: { ...r.node, version: 'v22.23.4' } })],
    ['unknown node key', r => ({ ...r, node: { ...r.node, 'freebsd-x64': {} } })],
    ['null platform', r => ({ ...r, node: { ...r.node, 'linux-x64': null } })],
    ['missing tar member', r => ({
      ...r, node: { ...r.node, 'linux-x64': { url: r.node['linux-x64']!.url, sha256: hash } },
    })],
    ['unknown tar key', r => ({
      ...r, node: { ...r.node, 'linux-x64': { ...r.node['linux-x64']!, extra: true } },
    })],
    ['wrong tar member', r => ({
      ...r, node: { ...r.node, 'linux-x64': { ...r.node['linux-x64']!, member: 'elsewhere/bin/node' } },
    })],
    ['wrong tar suffix', r => ({
      ...r, node: { ...r.node, 'linux-x64': { ...r.node['linux-x64']!, url: 'https://nodejs.org/wrong.tar.gz' } },
    })],
    ['tar query suffix trick', r => ({
      ...r, node: { ...r.node, 'linux-x64': {
        ...r.node['linux-x64']!, url: 'https://nodejs.org/wrong?x=/node-v22.23.4-linux-x64.tar.gz',
      } },
    })],
    ['off-host node URL', r => ({
      ...r, node: { ...r.node, 'linux-x64': {
        ...r.node['linux-x64']!, url: 'https://evil.example/node-v22.23.4-linux-x64.tar.gz',
      } },
    })],
    ['bad node hash', r => ({
      ...r, node: { ...r.node, 'linux-x64': { ...r.node['linux-x64']!, sha256: 'bad' } },
    })],
    ['missing Windows hash', r => ({
      ...r, node: { ...r.node, 'win-x64': { url: r.node['win-x64']!.url } },
    })],
    ['unknown Windows member', r => ({
      ...r, node: { ...r.node, 'win-x64': { ...r.node['win-x64']!, member: 'node.exe' } },
    })],
    ['wrong Windows architecture', r => ({
      ...r, node: { ...r.node, 'win-x64': {
        ...r.node['win-x64']!, url: 'https://nodejs.org/dist/v22.23.4/win-arm64/node.exe',
      } },
    })],
    ['bad notes host', r => ({ ...r, notes_url: 'https://evil.wundervault.com/changelog' })],
    ['HTTP notes', r => ({ ...r, notes_url: 'http://wundervault.com/changelog' })],
    ['notes userinfo', r => ({ ...r, notes_url: 'https://user@wundervault.com/changelog' })],
    ['notes port', r => ({ ...r, notes_url: 'https://wundervault.com:444/changelog' })],
    ['non-string notes', r => ({ ...r, notes_url: null })],
  ];
  for (const [name, change] of invalid) {
    it(`refuses ${name}`, () => expect(parseRecord(bytes(change(fixture())), '2.2.0').ok).toBe(false));
  }

  it('rejects app.files as an unknown key', () => {
    const record = fixture();
    const changed = { ...record, app: { ...record.app, files: [] } };
    expect(parseRecord(bytes(changed), record.version)).toEqual({
      ok: false,
      reason: 'record: unknown key app.files',
    });
  });

  it('accepts notes on an allowed asset host', () => {
    const record = fixture();
    record.notes_url = 'https://github.com/wundervault/mcp/releases/tag/v2.2.0';
    expect(parseRecord(bytes(record), record.version).ok).toBe(true);
  });

  it('validates limits without applying archive file limits to the record', () => {
    const record = fixture();
    expect(parseRecord(bytes(record), record.version, {
      ...DEFAULT_LIMITS, maxFiles: 0, maxFileBytes: 0,
    }).ok).toBe(true);
    for (const value of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(parseRecord(bytes(record), record.version, {
        ...DEFAULT_LIMITS, maxFiles: value,
      })).toEqual({ ok: false, reason: 'record: invalid limits' });
    }
  });

  it('rejects invalid JSON, UTF-8, a BOM and oversized records', () => {
    for (const record of [
      Buffer.from('{'), Buffer.from([0xff]),
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes(fixture())]),
      Buffer.alloc(64 * 1024 + 1, 32),
    ]) {
      expect(parseRecord(record, '2.2.0').ok).toBe(false);
    }
  });

  it('streams a file hash', async () => {
    const root = mkdtempSync(join(tmpdir(), 'wv-release-hash-'));
    try {
      const data = Buffer.alloc(1024 * 1024 + 7, 42);
      const path = join(root, 'file');
      writeFileSync(path, data);
      expect(await sha256File(path)).toBe(createHash('sha256').update(data).digest('hex'));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
