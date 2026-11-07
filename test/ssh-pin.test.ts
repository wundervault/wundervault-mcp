import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  describeSshHost,
  fingerprint,
  isSshHostKey,
  knownHostsLine,
  normalizeSshTarget,
  scanHostKey,
  sshHostRecipe,
  sshHostSha,
} from '../src/ssh-pin.js';

function sshString(value: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length);
  return Buffer.concat([length, value]);
}

function makeHostKey(type: string, marker = 1): string {
  const fields = [sshString(Buffer.from(type))];

  if (type === 'ssh-ed25519') {
    fields.push(sshString(Buffer.alloc(32, marker)));
  } else if (type.startsWith('ecdsa-sha2-')) {
    const curve = type.slice('ecdsa-sha2-'.length);
    const size = curve === 'nistp256' ? 32 : curve === 'nistp384' ? 48 : 66;
    fields.push(sshString(Buffer.from(curve)));
    fields.push(sshString(Buffer.concat([
      Buffer.from([4]),
      Buffer.alloc(size * 2, marker),
    ])));
  } else {
    fields.push(sshString(Buffer.from([1, 0, 1])));
    fields.push(sshString(Buffer.concat([
      Buffer.from([0, 0x80]),
      Buffer.alloc(255, marker),
    ])));
  }

  return `${type} ${Buffer.concat(fields).toString('base64')}`;
}

const target = { user: 'deploy', host: 'example.com', port: 22 };
const ed25519 = makeHostKey('ssh-ed25519');
const ecdsa = makeHostKey('ecdsa-sha2-nistp256');
const rsa = makeHostKey('ssh-rsa');

describe('normalizeSshTarget', () => {
  it.each([
    ['deploy@EXAMPLE.COM', undefined, { ...target }],
    ['deploy@Example.COM.', undefined, { ...target }],
    ['_svc-1.name@build-host', undefined, {
      user: '_svc-1.name',
      host: 'build-host',
      port: 22,
    }],
    ['opc@129.146.202.158', undefined, {
      user: 'opc',
      host: '129.146.202.158',
      port: 22,
    }],
    ['deploy@example.com:2222', undefined, { ...target, port: 2222 }],
    ['deploy@example.com', 2222, { ...target, port: 2222 }],
    ['deploy@example.com:2222', 2222, { ...target, port: 2222 }],
    ['deploy@example.com:00022', undefined, { ...target }],
    ['deploy@example.com:1', undefined, { ...target, port: 1 }],
    ['deploy@example.com:65535', undefined, { ...target, port: 65535 }],
  ])('normalizes %s with port %s', (destination, port, expected) => {
    expect(normalizeSshTarget(destination, port)).toEqual(expected);
  });

  it.each([
    'example.com',
    '@example.com',
    'Deploy@example.com',
    '1deploy@example.com',
    '-deploy@example.com',
    `${'a'.repeat(33)}@example.com`,
    'deploy@@example.com',
    'deploy@-host',
    'deploy@host-',
    'deploy@bad_host',
    'deploy@bad..host',
    'deploy@example.com..',
    'deploy@.',
    `deploy@${'a'.repeat(64)}.com`,
    `deploy@${Array(4).fill('a'.repeat(63)).join('.')}`,
    'deploy@256.1.2.3',
    'deploy@127.00.0.1',
    'deploy@127.1',
    'deploy@2130706433',
    'deploy@[::1]',
    'deploy@::1',
    'deploy@https://example.com',
    'deploy@example.com/path',
    'deploy@example.com?query',
    'deploy@example.com#fragment',
    ' deploy@example.com',
    'deploy@example.com ',
    'deploy@example.com\n',
    'deploy@example.com:0',
    'deploy@example.com:65536',
    'deploy@example.com:-1',
    'deploy@example.com:+22',
    'deploy@example.com:22.5',
    'deploy@example.com:',
    'deploy@example.com:22:23',
  ])('rejects %s', destination => {
    expect(normalizeSshTarget(destination)).toBeNull();
  });

  it.each([0, -1, 65536, 1.5, NaN, Infinity])(
    'rejects invalid separate port %s',
    port => {
      expect(normalizeSshTarget('deploy@example.com', port)).toBeNull();
    },
  );

  it('rejects conflicting embedded and separate ports', () => {
    expect(normalizeSshTarget('deploy@example.com:2222', 22)).toBeNull();
  });
});

describe('SSH host keys', () => {
  it.each([
    'ssh-ed25519',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'ssh-rsa',
    'rsa-sha2-256',
    'rsa-sha2-512',
  ])('recognizes %s', type => {
    expect(isSshHostKey(makeHostKey(type))).toBe(true);
  });

  it.each([
    undefined,
    null,
    42,
    '',
    'ssh-ed25519',
    'ssh-ed25519 !!!!',
    'ssh-ed25519 AAAA',
    'ssh-ed25519 AAA',
    `${ed25519} comment`,
    `${ed25519}\n`,
    ed25519.replace(' ', '\t'),
    `unknown ${ed25519.split(' ')[1]}`,
    `ssh-rsa ${ed25519.split(' ')[1]}`,
  ])('rejects invalid host key %s', value => {
    expect(isSshHostKey(value)).toBe(false);
  });

  it('rejects a truncated first SSH string', () => {
    const blob = Buffer.alloc(5);
    blob.writeUInt32BE(100);
    expect(isSshHostKey(`ssh-ed25519 ${blob.toString('base64')}`)).toBe(false);
  });

  it('rejects invalid keys in recipes, fingerprints and known_hosts', () => {
    expect(() => sshHostRecipe(target, 'invalid')).toThrow('Invalid SSH host key');
    expect(() => fingerprint('invalid')).toThrow('Invalid SSH host key');
    expect(() => knownHostsLine(target, 'invalid')).toThrow('Invalid SSH host key');
  });
});

describe('SSH host recipes', () => {
  it('contains only the recipe fields', () => {
    expect(sshHostRecipe(target, ed25519)).toEqual({
      type: 'ssh_host',
      v: 1,
      user: 'deploy',
      host: 'example.com',
      port: 22,
      host_key: ed25519,
    });
  });

  it('hashes canonical JSON and is stable across target property order', () => {
    const canonical = '{"host":"example.com","host_key":' +
      JSON.stringify(ed25519) +
      ',"port":22,"type":"ssh_host","user":"deploy","v":1}';
    const expected = createHash('sha256').update(canonical).digest('hex');

    expect(sshHostSha(target, ed25519)).toBe(expected);
    expect(sshHostSha({
      port: 22,
      host: 'example.com',
      user: 'deploy',
    }, ed25519)).toBe(expected);
    expect(expected).toMatch(/^[a-f0-9]{64}$/);
  });

  it('normalizes base64 padding before storage and hashing', () => {
    const unpadded = ed25519.replace(/=+$/, '');
    expect(sshHostRecipe(target, unpadded)).toEqual(sshHostRecipe(target, ed25519));
    expect(sshHostSha(target, unpadded)).toBe(sshHostSha(target, ed25519));
  });

  it('changes the hash for every target field and the host key', () => {
    const original = sshHostSha(target, ed25519);
    const changed = [
      sshHostSha({ ...target, user: 'other' }, ed25519),
      sshHostSha({ ...target, host: 'other.example.com' }, ed25519),
      sshHostSha({ ...target, port: 2222 }, ed25519),
      sshHostSha(target, makeHostKey('ssh-ed25519', 2)),
    ];

    for (const hash of changed) expect(hash).not.toBe(original);
    expect(new Set(changed).size).toBe(changed.length);
  });
});

describe('SSH host descriptions', () => {
  it('describes the default port without mentioning it', () => {
    expect(describeSshHost(target, ed25519)).toBe(
      `Let agents use this key to sign in to deploy@example.com? Server identity ${fingerprint(ed25519)}`,
    );
  });

  it('includes a non-default port', () => {
    expect(describeSshHost({ ...target, port: 2222 }, ed25519)).toBe(
      `Let agents use this key to sign in to deploy@example.com (port 2222)? Server identity ${fingerprint(ed25519)}`,
    );
  });

  it('fingerprints the decoded blob without base64 padding', () => {
    const blob = Buffer.from(ed25519.split(' ')[1], 'base64');
    const expected = createHash('sha256')
      .update(blob)
      .digest('base64')
      .replace(/=+$/, '');

    expect(fingerprint(ed25519)).toBe(`SHA256:${expected}`);
    expect(fingerprint(ed25519)).not.toContain('=');
  });

  const hasSshKeygen = !spawnSync('ssh-keygen', ['-?'], {
    encoding: 'utf8',
    timeout: 10_000,
  }).error;

  (hasSshKeygen ? it : it.skip)('matches ssh-keygen for a generated key', () => {
    const directory = mkdtempSync(join(tmpdir(), 'ssh-pin-'));
    try {
      const path = join(directory, 'host');
      const generated = spawnSync(
        'ssh-keygen',
        ['-q', '-t', 'ed25519', '-N', '', '-f', path],
        { encoding: 'utf8', timeout: 10_000 },
      );
      expect(generated.error).toBeUndefined();
      expect(generated.status).toBe(0);

      const hostKey = readFileSync(`${path}.pub`, 'utf8')
        .trim()
        .split(/\s+/)
        .slice(0, 2)
        .join(' ');
      const listed = spawnSync(
        'ssh-keygen',
        ['-l', '-f', `${path}.pub`, '-E', 'sha256'],
        { encoding: 'utf8', timeout: 10_000 },
      );
      expect(listed.error).toBeUndefined();
      expect(listed.status).toBe(0);
      expect(fingerprint(hostKey)).toBe(listed.stdout.trim().split(/\s+/)[1]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

describe('knownHostsLine', () => {
  it('uses an unbracketed host for port 22', () => {
    expect(knownHostsLine(target, ed25519)).toBe(`example.com ${ed25519}`);
  });

  it('uses bracketed host:port for a non-default port', () => {
    expect(knownHostsLine({ ...target, port: 2222 }, ed25519)).toBe(
      `[example.com]:2222 ${ed25519}`,
    );
  });

  it('handles IPv4 targets', () => {
    expect(knownHostsLine({ ...target, host: '192.0.2.1' }, ed25519)).toBe(
      `192.0.2.1 ${ed25519}`,
    );
  });
});

describe('scanHostKey', () => {
  it('runs ssh-keyscan with the prescribed timeout, port and key types', async () => {
    const run = vi.fn(async () => ({
      code: 0,
      stdout: `[example.com]:2222 ${ed25519}\n`,
    }));

    expect(await scanHostKey({ ...target, port: 2222 }, run)).toBe(ed25519);
    expect(run).toHaveBeenCalledTimes(1);
    expect(run).toHaveBeenCalledWith('ssh-keyscan', [
      '-T',
      '5',
      '-p',
      '2222',
      '-t',
      'ed25519,ecdsa,rsa',
      'example.com',
    ]);
  });

  it('prefers the first ed25519 key regardless of line order', async () => {
    const another = makeHostKey('ssh-ed25519', 2);
    const run = async () => ({
      code: 0,
      stdout: [
        `example.com ${rsa}`,
        `example.com ${ecdsa}`,
        `example.com ${ed25519}`,
        `example.com ${another}`,
      ].join('\n'),
    });

    expect(await scanHostKey(target, run)).toBe(ed25519);
  });

  it.each([
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
  ])('prefers %s over RSA', async type => {
    const key = makeHostKey(type);
    const run = async () => ({
      code: 0,
      stdout: `example.com ${rsa}\nexample.com ${key}\n`,
    });

    expect(await scanHostKey(target, run)).toBe(key);
  });

  it.each(['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'])(
    'falls back to %s',
    async type => {
      const key = makeHostKey(type);
      const run = async () => ({
        code: 0,
        stdout: `example.com ${key}\n`,
      });

      expect(await scanHostKey(target, run)).toBe(key);
    },
  );

  it('ignores blank lines, comments, invalid keys and trailing comments', async () => {
    const run = async () => ({
      code: 0,
      stdout: [
        '',
        '# example.com:22 SSH-2.0-OpenSSH',
        `  # example.com ${ed25519}`,
        `example.com ssh-ed25519 ${rsa.split(' ')[1]}`,
        'example.com ssh-ed25519 not-base64',
        `example.com unknown ${ed25519.split(' ')[1]}`,
        `example.com ${rsa} trailing comment`,
        '',
      ].join('\r\n'),
    });

    expect(await scanHostKey(target, run)).toBe(rsa);
  });

  it('returns null for a non-zero exit even with usable output', async () => {
    const run = async () => ({
      code: 1,
      stdout: `example.com ${ed25519}\n`,
    });

    expect(await scanHostKey(target, run)).toBeNull();
  });

  it('returns null when there are no supported valid keys', async () => {
    const run = async () => ({
      code: 0,
      stdout: '# no keys\nexample.com ssh-ed25519 invalid\n',
    });

    expect(await scanHostKey(target, run)).toBeNull();
  });

  it('returns null when the runner fails', async () => {
    const run = async (): Promise<{ code: number; stdout: string }> => {
      throw new Error('ssh-keyscan unavailable');
    };

    expect(await scanHostKey(target, run)).toBeNull();
  });
});
