import { describe, it, expect } from 'vitest';
import {
  evmAddressOf, parseEvmPrivateKey, transferDigest, signDigest, recoverAddress, checksumAddress,
} from '../src/evm.js';

describe('evm', () => {
  it('derives the address web3.js documents for its example key', () => {
    const k = parseEvmPrivateKey('0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318');
    expect(evmAddressOf(k)).toBe('0x2c7536E3605D9C16a7a3D7b1898e529396a65c23');
  });
  it('checksums per EIP-55', () => {
    expect(checksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed')).toBe('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');
  });
  it('reproduces the x402 v2 spec example: its signature recovers to its from under our digest', () => {
    const domain = { name: 'USDC', version: '2', chainId: 84532, verifyingContract: '0x036CbD53842c5426634e7929541eC2318f3dCF7e' };
    const a = {
      from: '0x857b06519E91e3A54538791bDbb0E22373e36b66', to: '0x209693Bc6afc0C5328bA36FaF03C514EF312287C',
      value: '10000', validAfter: '1740672089', validBefore: '1740672154',
      nonce: '0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480',
    };
    const sig = '0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c';
    expect(recoverAddress(transferDigest(domain, a), sig)).toBe(a.from);
    // A one-character change to the domain name breaks it: the vector really pins the digest.
    expect(recoverAddress(transferDigest({ ...domain, name: 'USD Coin' }, a), sig)).not.toBe(a.from);
  });
  it('signs and recovers round trip', () => {
    const k = parseEvmPrivateKey('4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318');
    const d = new Uint8Array(32).fill(7);
    expect(recoverAddress(d, signDigest(d, k))).toBe(evmAddressOf(k));
  });
});
