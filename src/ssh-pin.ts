import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { canonicalJson } from './opdef.js';

type SshTarget = {
  user: string;
  host: string;
  port: number;
};

type ScanRunner = (
  cmd: string,
  args: string[],
) => Promise<{ code: number; stdout: string }>;

const HOST_KEY_TYPES = new Set([
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'ssh-rsa',
  'rsa-sha2-256',
  'rsa-sha2-512',
]);

export function normalizeSshTarget(
  destination: string,
  port?: number,
): SshTarget | null {
  if (typeof destination !== 'string') return null;

  const match = /^([a-z_][a-z0-9_.-]{0,31})@([^:@\s]+)(?::([0-9]+))?$/.exec(destination);
  if (!match) return null;

  const user = match[1];
  const host = match[2].toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253) return null;

  if (/^[0-9.]+$/.test(host)) {
    if (isIP(host) !== 4) return null;
  } else if (
    !host.split('.').every(
      label =>
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    return null;
  }

  if (
    port !== undefined &&
    (!Number.isInteger(port) || port < 1 || port > 65535)
  ) {
    return null;
  }

  const embeddedPort = match[3] === undefined ? undefined : Number(match[3]);
  if (
    embeddedPort !== undefined &&
    (!Number.isInteger(embeddedPort) || embeddedPort < 1 || embeddedPort > 65535)
  ) {
    return null;
  }

  if (embeddedPort !== undefined && port !== undefined && embeddedPort !== port) {
    return null;
  }

  return { user, host, port: embeddedPort ?? port ?? 22 };
}

function hostKeyBlob(value: unknown): Buffer | null {
  if (typeof value !== 'string') return null;

  const match = /^(\S+) ([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!match || !HOST_KEY_TYPES.has(match[1])) return null;

  const blob = Buffer.from(match[2], 'base64');
  const canonical = blob.toString('base64');
  if (match[2] !== canonical && match[2] !== canonical.replace(/=+$/, '')) {
    return null;
  }

  const type = Buffer.from(match[1], 'ascii');
  if (
    blob.length < 4 + type.length ||
    blob.readUInt32BE(0) !== type.length ||
    !blob.subarray(4, 4 + type.length).equals(type)
  ) {
    return null;
  }

  return blob;
}

export function isSshHostKey(value: unknown): boolean {
  return hostKeyBlob(value) !== null;
}

function requireHostKeyBlob(hostKey: string): Buffer {
  const blob = hostKeyBlob(hostKey);
  if (!blob) throw new Error('Invalid SSH host key');
  return blob;
}

function canonicalHostKey(hostKey: string): string {
  const blob = requireHostKeyBlob(hostKey);
  return `${hostKey.slice(0, hostKey.indexOf(' '))} ${blob.toString('base64')}`;
}

export function sshHostRecipe(t: SshTarget, hostKey: string) {
  return {
    type: 'ssh_host',
    v: 1,
    user: t.user,
    host: t.host,
    port: t.port,
    host_key: canonicalHostKey(hostKey),
  };
}

export function sshHostSha(t: SshTarget, hostKey: string): string {
  return createHash('sha256')
    .update(canonicalJson(sshHostRecipe(t, hostKey)))
    .digest('hex');
}

export function fingerprint(hostKey: string): string {
  const digest = createHash('sha256')
    .update(requireHostKeyBlob(hostKey))
    .digest('base64')
    .replace(/=+$/, '');
  return `SHA256:${digest}`;
}

export function describeSshHost(t: SshTarget, hostKey: string): string {
  const port = t.port === 22 ? '' : ` (port ${t.port})`;
  return `Let agents use this key to sign in to ${t.user}@${t.host}${port}? Server identity ${fingerprint(hostKey)}`;
}

export function knownHostsLine(t: SshTarget, hostKey: string): string {
  const host = t.port === 22 ? t.host : `[${t.host}]:${t.port}`;
  return `${host} ${canonicalHostKey(hostKey)}`;
}

const runKeyscan: ScanRunner = (cmd, args) =>
  new Promise(resolve => {
    execFile(
      cmd,
      args,
      { encoding: 'utf8', timeout: 10_000 },
      (error, stdout) => {
        resolve({ code: error ? 1 : 0, stdout });
      },
    );
  });

export async function scanHostKey(
  t: SshTarget,
  run: ScanRunner = runKeyscan,
): Promise<string | null> {
  try {
    const result = await run('ssh-keyscan', [
      '-T',
      '5',
      '-p',
      String(t.port),
      '-t',
      'ed25519,ecdsa,rsa',
      t.host,
    ]);
    if (result.code !== 0) return null;

    let selected: string | null = null;
    let selectedRank = Infinity;

    for (const line of result.stdout.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const fields = trimmed.split(/\s+/);
      if (fields.length < 3) continue;

      const type = fields[1];
      const key = `${type} ${fields[2]}`;
      if (!isSshHostKey(key)) continue;

      const rank = type === 'ssh-ed25519'
        ? 0
        : type.startsWith('ecdsa-sha2-')
          ? 1
          : 2;

      if (rank < selectedRank) {
        selected = canonicalHostKey(key);
        selectedRank = rank;
      }
    }

    return selected;
  } catch {
    return null;
  }
}
