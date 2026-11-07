/**
 * Session binding for pinned ssh-agent sessions (SPEC 1.3, R0-F1).
 *
 * Host proofs use real crypto keys; socket checks use an OpenSSH client identity loaded
 * from ssh-keygen output, as in ssh-agent.test.ts. No sshd or network host is needed.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createHash, KeyObject } from 'node:crypto';
import { createConnection, Socket } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  loadOpenSshEd25519, handleAgentMessage, startAgent, parseOpenSshPublicKey, verifySessionBind,
  type LoadedIdentity, type AgentConnectionState, type AgentHandle, type SignEvent,
} from '../src/ssh-agent.js';

function s(v: Buffer | string): Buffer {
  const b = Buffer.isBuffer(v) ? v : Buffer.from(v, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length, 0);
  return Buffer.concat([len, b]);
}

function mpint(v: Buffer): Buffer {
  let off = 0;
  while (off < v.length && v[off] === 0) off += 1;
  const magnitude = v.subarray(off);
  return s(magnitude.length > 0 && (magnitude[0] & 0x80) !== 0
    ? Buffer.concat([Buffer.from([0]), magnitude])
    : magnitude);
}

interface HostKey {
  blob: Buffer;
  privateKey: KeyObject;
  publicKey: KeyObject;
  algo: string;
  hash: string | null;
  width: number;
}

type HostKind = 'ed25519' | 'P-256' | 'P-384' | 'P-521' | 'rsa';

function makeHost(kind: HostKind, rsaAlgo = 'rsa-sha2-256'): HostKey {
  if (kind === 'ed25519') {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' });
    return {
      blob: Buffer.concat([s('ssh-ed25519'), s(Buffer.from(jwk.x!, 'base64url'))]),
      privateKey, publicKey, algo: 'ssh-ed25519', hash: null, width: 0,
    };
  }
  if (kind === 'rsa') {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    return {
      blob: Buffer.concat([
        s('ssh-rsa'), mpint(Buffer.from(jwk.e!, 'base64url')), mpint(Buffer.from(jwk.n!, 'base64url')),
      ]),
      privateKey, publicKey, algo: rsaAlgo,
      hash: rsaAlgo === 'rsa-sha2-512' ? 'sha512' : 'sha256', width: 0,
    };
  }
  const curves = {
    'P-256': { namedCurve: 'prime256v1', ssh: 'nistp256', width: 32, hash: 'sha256' },
    'P-384': { namedCurve: 'secp384r1', ssh: 'nistp384', width: 48, hash: 'sha384' },
    'P-521': { namedCurve: 'secp521r1', ssh: 'nistp521', width: 66, hash: 'sha512' },
  };
  const curve = curves[kind];
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: curve.namedCurve });
  const jwk = publicKey.export({ format: 'jwk' });
  const algo = `ecdsa-sha2-${curve.ssh}`;
  return {
    blob: Buffer.concat([
      s(algo), s(curve.ssh),
      s(Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x!, 'base64url'), Buffer.from(jwk.y!, 'base64url')])),
    ]),
    privateKey, publicKey, algo, hash: curve.hash, width: curve.width,
  };
}

function hostSignature(host: HostKey, sessionId: Buffer): Buffer {
  if (host.width > 0) {
    const sig = cryptoSign(host.hash, sessionId, { key: host.privateKey, dsaEncoding: 'ieee-p1363' });
    return Buffer.concat([
      s(host.algo), s(Buffer.concat([mpint(sig.subarray(0, host.width)), mpint(sig.subarray(host.width))])),
    ]);
  }
  return Buffer.concat([s(host.algo), s(cryptoSign(host.hash, sessionId, host.privateKey))]);
}

function bindRequest(host: HostKey, sessionId: Buffer, forwarding = false, signature?: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([27]), s('session-bind@openssh.com'), s(host.blob), s(sessionId),
    s(signature ?? hostSignature(host, sessionId)), Buffer.from([forwarding ? 1 : 0]),
  ]);
}

function signRequest(identity: LoadedIdentity, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([13]), s(identity.keyBlob), s(data), Buffer.alloc(4)]);
}

function userauth(identity: LoadedIdentity, sessionId: Buffer, hostBound?: Buffer): Buffer {
  return Buffer.concat([
    s(sessionId), Buffer.from([50]), s('opc'), s('ssh-connection'),
    s(hostBound ? 'publickey-hostbound-v00@openssh.com' : 'publickey'),
    Buffer.from([1]), s('ssh-ed25519'), s(identity.keyBlob),
    ...(hostBound ? [s(hostBound)] : []),
  ]);
}

function expectSignature(reply: Buffer, data: Buffer, identity: LoadedIdentity): void {
  expect(reply[0]).toBe(14);
  const blobLength = reply.readUInt32BE(1);
  expect(reply.length).toBe(5 + blobLength);
  const blob = reply.subarray(5);
  const algoLength = blob.readUInt32BE(0);
  expect(blob.subarray(4, 4 + algoLength).toString()).toBe('ssh-ed25519');
  const sigLength = blob.readUInt32BE(4 + algoLength);
  const sig = blob.subarray(8 + algoLength);
  expect(sig.length).toBe(sigLength);
  expect(cryptoVerify(null, data, identity.publicKey, sig)).toBe(true);
}

let identity: LoadedIdentity;
let pinned: HostKey;
let other: HostKey;
const sessionId = Buffer.from('a server exchange hash used as the session identifier');

beforeAll(() => {
  const client = makeHost('ed25519');
  identity = {
    keyBlob: client.blob, privateKey: client.privateKey, publicKey: client.publicKey,
    comment: 'bind@test',
    fingerprint: 'SHA256:' + createHash('sha256').update(client.blob).digest('base64').replace(/=+$/, ''),
  };
  pinned = makeHost('ed25519');
  other = makeHost('ed25519');
});

describe('session-bind host proof verification', () => {
  const cases: Array<{ kind: HostKind; algo: string }> = [
    { kind: 'ed25519', algo: 'ssh-ed25519' },
    { kind: 'P-256', algo: 'ecdsa-sha2-nistp256' },
    { kind: 'P-384', algo: 'ecdsa-sha2-nistp384' },
    { kind: 'P-521', algo: 'ecdsa-sha2-nistp521' },
    { kind: 'rsa', algo: 'rsa-sha2-256' },
    { kind: 'rsa', algo: 'rsa-sha2-512' },
  ];

  for (const testCase of cases) {
    it(`accepts a verified ${testCase.algo} bind and records its fields`, () => {
      const host = makeHost(testCase.kind, testCase.algo);
      const signature = hostSignature(host, sessionId);
      const conn: AgentConnectionState = { binds: [] };
      expect(verifySessionBind(host.blob, sessionId, signature)).toBe(true);
      expect(handleAgentMessage(bindRequest(host, sessionId), identity, undefined, conn)[0]).toBe(6);
      expect(conn.binds).toEqual([{ hostKeyBlob: host.blob, sessionId, forwarding: false }]);
    });

    it(`refuses a damaged ${testCase.algo} signature without recording a bind`, () => {
      const host = makeHost(testCase.kind, testCase.algo);
      const signature = hostSignature(host, sessionId);
      signature[signature.length - 1] ^= 1;
      const conn: AgentConnectionState = { binds: [] };
      expect(verifySessionBind(host.blob, sessionId, signature)).toBe(false);
      expect(handleAgentMessage(bindRequest(host, sessionId, false, signature), identity, undefined, conn)[0]).toBe(5);
      expect(conn.binds).toEqual([]);
    });

    it(`refuses a ${testCase.algo} signature made by another key`, () => {
      const host = makeHost(testCase.kind, testCase.algo);
      const impostor = makeHost(testCase.kind, testCase.algo);
      const signature = hostSignature(impostor, sessionId);
      const conn: AgentConnectionState = { binds: [] };
      expect(verifySessionBind(host.blob, sessionId, signature)).toBe(false);
      expect(handleAgentMessage(bindRequest(host, sessionId, false, signature), identity, undefined, conn)[0]).toBe(5);
      expect(conn.binds).toEqual([]);
    });
  }

  it('refuses an otherwise valid RSA SHA-1 signature', () => {
    const host = makeHost('rsa');
    const signature = Buffer.concat([s('ssh-rsa'), s(cryptoSign('sha1', sessionId, host.privateKey))]);
    const conn: AgentConnectionState = { binds: [] };
    expect(verifySessionBind(host.blob, sessionId, signature)).toBe(false);
    expect(handleAgentMessage(bindRequest(host, sessionId, false, signature), identity, undefined, conn)[0]).toBe(5);
    expect(conn.binds).toEqual([]);
  });

  it('refuses a signature over another session identifier', () => {
    const conn: AgentConnectionState = { binds: [] };
    const signature = hostSignature(pinned, Buffer.from('another exchange'));
    expect(handleAgentMessage(bindRequest(pinned, sessionId, false, signature), identity, undefined, conn)[0]).toBe(5);
    expect(conn.binds).toEqual([]);
  });

  it('refuses malformed proofs and unknown extensions without changing state', () => {
    const conn: AgentConnectionState = { binds: [] };
    const valid = bindRequest(pinned, sessionId);
    const malformed = [
      Buffer.from([27]),
      Buffer.concat([Buffer.from([27]), s('unknown@example.com')]),
      valid.subarray(0, valid.length - 1),
      Buffer.concat([valid, Buffer.from([0])]),
      bindRequest(pinned, sessionId, false, Buffer.from([0, 0, 255, 255])),
    ];
    for (const msg of malformed) {
      expect(handleAgentMessage(msg, identity, undefined, conn)[0]).toBe(5);
      expect(conn.binds).toEqual([]);
    }
    expect(verifySessionBind(Buffer.alloc(0), sessionId, hostSignature(pinned, sessionId))).toBe(false);
    expect(verifySessionBind(pinned.blob, Buffer.alloc(0), hostSignature(pinned, Buffer.alloc(0)))).toBe(false);
  });

  it('accepts at most eight binds and retains forwarding state', () => {
    const conn: AgentConnectionState = { binds: [] };
    for (let i = 0; i < 8; i += 1) {
      expect(handleAgentMessage(bindRequest(pinned, Buffer.from(`session-${i}`), true), identity, undefined, conn)[0]).toBe(6);
    }
    expect(conn.binds).toHaveLength(8);
    expect(conn.binds.every((bind) => bind.forwarding)).toBe(true);
    expect(handleAgentMessage(bindRequest(other, sessionId), identity, undefined, conn)[0]).toBe(5);
    expect(conn.binds).toHaveLength(8);
    expect(conn.binds[7].sessionId.toString()).toBe('session-7');
  });

  it('copies recorded fields instead of retaining mutable request buffers', () => {
    const conn: AgentConnectionState = { binds: [] };
    const request = bindRequest(pinned, sessionId);
    expect(handleAgentMessage(request, identity, undefined, conn)[0]).toBe(6);
    request.fill(0);
    expect(conn.binds[0].hostKeyBlob.equals(pinned.blob)).toBe(true);
    expect(conn.binds[0].sessionId.equals(sessionId)).toBe(true);
  });
});

describe('OpenSSH public key pins', () => {
  it('parses a line with a comment and a bare base64 blob', () => {
    const encoded = pinned.blob.toString('base64');
    expect(parseOpenSshPublicKey(`ssh-ed25519 ${encoded} server identity\n`).equals(pinned.blob)).toBe(true);
    expect(parseOpenSshPublicKey(encoded).equals(pinned.blob)).toBe(true);
  });

  it('refuses malformed, mismatched and trailing key data', () => {
    expect(() => parseOpenSshPublicKey('not a key')).toThrow();
    expect(() => parseOpenSshPublicKey(`ssh-rsa ${pinned.blob.toString('base64')}`)).toThrow();
    expect(() => parseOpenSshPublicKey(Buffer.concat([pinned.blob, Buffer.from([0])]).toString('base64'))).toThrow();
    expect(() => parseOpenSshPublicKey('!!!!')).toThrow();
  });
});

describe('pinned signing through handleAgentMessage', () => {
  it('requires a bind and reports a reason for refusing', () => {
    const outcomes: Array<{ outcome: string; reason?: string }> = [];
    const conn: AgentConnectionState = { binds: [] };
    const reply = handleAgentMessage(
      signRequest(identity, userauth(identity, sessionId)), identity,
      (outcome, reason) => outcomes.push({ outcome, reason }), conn,
      { pinnedHostKey: pinned.blob.toString('base64') },
    );
    expect(reply[0]).toBe(5);
    expect(outcomes[0].outcome).toBe('refused_binding');
    expect(outcomes[0].reason).toMatch(/No verified server session bind/);
  });

  it('signs only userauth for the last non-forwarding pinned bind', () => {
    const conn: AgentConnectionState = { binds: [] };
    const opts = { pinnedHostKey: pinned.blob.toString('base64') };
    const sign = (data: Buffer) => handleAgentMessage(signRequest(identity, data), identity, undefined, conn, opts);
    expect(handleAgentMessage(bindRequest(pinned, sessionId), identity, undefined, conn)[0]).toBe(6);

    const data = userauth(identity, sessionId);
    expectSignature(sign(data), data, identity);
    expect(sign(userauth(identity, Buffer.from('another session')))[0]).toBe(5);
    expect(sign(s(sessionId))[0]).toBe(5);
    expect(sign(Buffer.concat([s(sessionId), Buffer.from('not userauth')]))[0]).toBe(5);
    expect(sign(Buffer.concat([data, Buffer.from([0])]))[0]).toBe(5);

    expect(handleAgentMessage(bindRequest(other, sessionId), identity, undefined, conn)[0]).toBe(6);
    expect(sign(data)[0]).toBe(5);
    expect(handleAgentMessage(bindRequest(pinned, sessionId, true), identity, undefined, conn)[0]).toBe(6);
    expect(sign(data)[0]).toBe(5);
  });

  it('supports host-bound userauth and checks its server key too', () => {
    const conn: AgentConnectionState = { binds: [] };
    const opts = { pinnedHostKey: pinned.blob.toString('base64') };
    expect(handleAgentMessage(bindRequest(pinned, sessionId), identity, undefined, conn)[0]).toBe(6);
    const data = userauth(identity, sessionId, pinned.blob);
    expectSignature(handleAgentMessage(signRequest(identity, data), identity, undefined, conn, opts), data, identity);
    expect(handleAgentMessage(
      signRequest(identity, userauth(identity, sessionId, other.blob)), identity, undefined, conn, opts,
    )[0]).toBe(5);
  });

  it('leaves an unpinned caller free to sign without state or after a forwarding bind', () => {
    const data = Buffer.from('legacy arbitrary signing data');
    expectSignature(handleAgentMessage(signRequest(identity, data), identity), data, identity);
    const conn: AgentConnectionState = { binds: [] };
    expect(handleAgentMessage(bindRequest(pinned, sessionId, true), identity, undefined, conn)[0]).toBe(6);
    expectSignature(handleAgentMessage(signRequest(identity, data), identity, undefined, conn), data, identity);
  });
});

const hasSshKeygen = process.platform !== 'win32'
  && !spawnSync('ssh-keygen', ['-V'], { stdio: 'ignore' }).error;

function connect(socketPath: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    const timer = setTimeout(() => {
      socket.destroy(new Error('Timed out connecting to ssh-agent'));
    }, 3_000);
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.once('connect', () => {
      clearTimeout(timer);
      resolve(socket);
    });
  });
}

/** Exchange a single frame, allowing the reply to arrive in arbitrarily small chunks. */
function exchange(socket: Socket, body: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onClose = () => onError(new Error('ssh-agent closed before replying'));
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length < 4) return;
      const length = buffered.readUInt32BE(0);
      if (buffered.length < 4 + length) return;
      cleanup();
      resolve(buffered.subarray(4, 4 + length));
    };
    const timer = setTimeout(() => onError(new Error('Timed out waiting for ssh-agent reply')), 3_000);
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
    socket.write(s(body));
  });
}

(hasSshKeygen ? describe : describe.skip)('session binding over a real agent socket', () => {
  let dir: string;
  let socketIdentity: LoadedIdentity;

  beforeAll(() => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'wv-test-bind-'));
    execFileSync('ssh-keygen', [
      '-q', '-t', 'ed25519', '-N', '', '-C', 'bind-socket@test', '-f', path.join(dir, 'ed'),
    ]);
    socketIdentity = loadOpenSshEd25519(readFileSync(path.join(dir, 'ed'), 'utf8'));
  });

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  async function withAgent(
    pin: string | undefined,
    run: (agent: AgentHandle, open: () => Promise<Socket>, events: SignEvent[]) => Promise<void>,
  ): Promise<void> {
    const events: SignEvent[] = [];
    const agent = startAgent(socketIdentity, (event) => events.push(event), 'approved.example',
      pin === undefined ? {} : { pinnedHostKey: pin });
    const sockets: Socket[] = [];
    const open = async () => {
      const socket = await connect(agent.socketPath);
      sockets.push(socket);
      return socket;
    };
    try {
      await run(agent, open, events);
    } finally {
      for (const socket of sockets) socket.destroy();
      agent.close();
    }
  }

  it('refuses signing without a bind and audits the refusal', async () => {
    await withAgent(pinned.blob.toString('base64'), async (agent, open, events) => {
      const socket = await open();
      expect((await exchange(socket, signRequest(socketIdentity, userauth(socketIdentity, sessionId))))[0]).toBe(5);
      expect(agent.signCount()).toBe(0);
      expect(events).toHaveLength(1);
      expect(events[0].refused).toBe(true);
      expect(events[0].reason).toMatch(/No verified server session bind/);
      expect(events[0].host).toBe('approved.example');
    });
  });

  it('signs bound userauth with the client identity and counts only signatures', async () => {
    const line = `ssh-ed25519 ${pinned.blob.toString('base64')} approved server`;
    await withAgent(line, async (agent, open, events) => {
      const socket = await open();
      expect((await exchange(socket, bindRequest(pinned, sessionId)))[0]).toBe(6);
      const data = userauth(socketIdentity, sessionId);
      expectSignature(await exchange(socket, signRequest(socketIdentity, data)), data, socketIdentity);
      expect(agent.signCount()).toBe(1);
      expect(events.map((event) => event.outcome)).toEqual(['signed']);
    });
  });

  it('refuses a valid bind to a different server as signing authority', async () => {
    await withAgent(pinned.blob.toString('base64'), async (agent, open, events) => {
      const socket = await open();
      expect((await exchange(socket, bindRequest(other, sessionId)))[0]).toBe(6);
      expect((await exchange(socket, signRequest(socketIdentity, userauth(socketIdentity, sessionId))))[0]).toBe(5);
      expect(events[0].refused).toBe(true);
      expect(events[0].reason).toMatch(/does not match the approved server/);
      expect(agent.signCount()).toBe(0);
    });
  });

  it('refuses a different session id after a valid pinned bind', async () => {
    await withAgent(pinned.blob.toString('base64'), async (agent, open) => {
      const socket = await open();
      expect((await exchange(socket, bindRequest(pinned, sessionId)))[0]).toBe(6);
      const data = userauth(socketIdentity, Buffer.from('different session'));
      expect((await exchange(socket, signRequest(socketIdentity, data)))[0]).toBe(5);
      expect(agent.signCount()).toBe(0);
    });
  });

  it('refuses signing after a forwarding bind', async () => {
    await withAgent(pinned.blob.toString('base64'), async (agent, open, events) => {
      const socket = await open();
      expect((await exchange(socket, bindRequest(pinned, sessionId, true)))[0]).toBe(6);
      expect((await exchange(socket, signRequest(socketIdentity, userauth(socketIdentity, sessionId))))[0]).toBe(5);
      expect(events[0].reason).toMatch(/forwarding/);
      expect(agent.signCount()).toBe(0);
    });
  });

  it('does not let connection B borrow the bind on connection A', async () => {
    await withAgent(pinned.blob.toString('base64'), async (agent, open) => {
      const a = await open();
      const b = await open();
      expect((await exchange(a, bindRequest(pinned, sessionId)))[0]).toBe(6);
      const data = userauth(socketIdentity, sessionId);
      expect((await exchange(b, signRequest(socketIdentity, data)))[0]).toBe(5);
      expectSignature(await exchange(a, signRequest(socketIdentity, data)), data, socketIdentity);

      // A second client can prove possession of another server's session, but that
      // still cannot turn this pinned socket into authority for the other server.
      expect((await exchange(b, bindRequest(other, sessionId)))[0]).toBe(6);
      expect((await exchange(b, signRequest(socketIdentity, data)))[0]).toBe(5);
      expect(agent.signCount()).toBe(1);
    });
  });

  it('still signs without any bind when no pin was supplied', async () => {
    await withAgent(undefined, async (agent, open) => {
      const socket = await open();
      const data = Buffer.from('legacy signing over the real socket');
      expectSignature(await exchange(socket, signRequest(socketIdentity, data)), data, socketIdentity);
      expect(agent.signCount()).toBe(1);
    });
  });
});
