/** A pinned session trusts only the broker-written server identity, never client config. */
export function pinnedSshOptions(socketPath: string, publicKeyPath: string, knownHostsPath: string): string[] {
  return [
    '-F', '/dev/null',
    '-o', `IdentityFile=${publicKeyPath}`,
    '-o', 'IdentitiesOnly=yes',
    '-o', `IdentityAgent=${socketPath}`,
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    '-o', 'GlobalKnownHostsFile=/dev/null',
  ];
}
