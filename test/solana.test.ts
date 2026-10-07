import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  associatedTokenAddress, base58Decode, base58Encode, buildTransferMessage, signTransfer,
  parseSolanaSecretKey, decodeAddress,
} from '../src/solana.js';

// Generated once with the official @solana-program/token findAssociatedTokenPda.
const OWNER = '2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4';
const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const OWNER_USDC_ATA = '3XZXfFJHF5ox3yPop16oqYfSWxLpkjsEuvTe2S67G2rj';
const GOLDEN_TX = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADnG+bsCtNaR3QN+oWO+cHEIUMBKrUM2GS9SFWrdNZw18F/akDYmsigj3YrvI3alzHAUrdBLyySJw5JidtBKooGgAIBBAjPHwZnA01T2C3HtlAjTEVC4T/PLYANrujgwBsph3Jm2v0XJDhaoMdbZPt4zWAvodmR/ev3axPFjtcC6sg16fYYX2T04wNrpLMW2lPp+jEzMMd93xpUhLu5Y6gojNTgQeYli5QOPue0ZnsV0FrYqj8Aa/QDiRzUOVhlQ7PImfYPAMb6evO+2606PWXzaqvJdDGxu+TC0vbg5HymAgNFL11hBt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKkDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAVKU1qZKSEGTSTocWDaOHx8NbXdvJK7geQfqEBBBUSNAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEEBgAFAiBOAAAGAAkDAQAAAAAAAAAFBAIEAwEKDBAnAAAAAAAABgcAEHBpXzNhYmMxMjNkZWY0NTYA';

describe('solana', () => {
  it('derives the associated token account the official library derives', () => {
    expect(associatedTokenAddress(OWNER, USDC)).toBe(OWNER_USDC_ATA);
  });
  it('base58 round-trips with leading zeros', () => {
    const b = new Uint8Array([0, 0, 1, 2, 255]);
    expect(base58Decode(base58Encode(b))).toEqual(b);
    expect(base58Encode(new Uint8Array(32))).toBe('11111111111111111111111111111111');
  });
  // The transaction below was decoded with the official @solana/kit decoder
  // (getTransactionDecoder → decompileTransactionMessage) on 2026-10-06: fee payer EwWq…,
  // instructions ComputeBudget(02 204e0000) · ComputeBudget(03 01…) · Token TransferChecked
  // [7RP22… w, EPjF… r, 3XZX… w, J2xcc… signer] data 0c 1027000000000000 06 · Memo "pi_3abc123def456";
  // signature slots: fee payer empty, wallet signed. ed25519 is deterministic, so it is pinned.
  it('builds byte-for-byte the transaction the official decoder accepted', () => {
    const seed = new Uint8Array(32).fill(9);
    const key = parseSolanaSecretKey(base58Encode(seed));
    const msg = buildTransferMessage({
      wallet: key.address, payTo: OWNER, mint: USDC, amount: 10_000n, decimals: 6,
      feePayer: 'EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd',
      recentBlockhash: '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi',
      memo: new TextEncoder().encode('pi_3abc123def456'),
    });
    const tx = signTransfer(msg, key);
    expect(key.address).toBe('J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf');
    expect(associatedTokenAddress(key.address, USDC)).toBe('7RP22uEk2BNSbZaQDPAXEqFzcqgoo7qiDiM3VwpgwXc1');
    expect(tx).toBe(GOLDEN_TX);
    expect(ed25519.verify(Buffer.from(tx, 'base64').subarray(65, 129), msg, key.publicKey)).toBe(true);
  });
  it('refuses a transaction that names one account twice (fee payer = wallet, payee = wallet)', () => {
    const key = parseSolanaSecretKey(base58Encode(new Uint8Array(32).fill(9)));
    const base = { wallet: key.address, payTo: OWNER, mint: USDC, amount: 1n, decimals: 6,
      feePayer: 'EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd', recentBlockhash: '4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi',
      memo: new Uint8Array([1]) };
    expect(() => buildTransferMessage({ ...base, feePayer: key.address })).toThrow(/twice/);
    expect(() => buildTransferMessage({ ...base, payTo: key.address })).toThrow(/twice/);
    expect(() => buildTransferMessage({ ...base, memo: new Uint8Array(257) })).toThrow(/memo/);
  });
});
