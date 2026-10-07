/**
 * x402: reading a merchant's "402 Payment Required" and writing the payment header back.
 *
 * Everything a merchant sends is checked here before it reaches a comparison, a ledger or a
 * signature: a hostile 402 is the normal adversary of this file. Numbers are decimal
 * strings handled as BigInt; addresses are checked for their chain; and the token's
 * identity (contract, EIP-712 domain, decimals) comes from the table below, never from the
 * merchant — a merchant that names "USDC" at some other contract is offering something else.
 *
 * See SPEC-1.0-signing.md §C9–C12.
 */
import { isEvmAddress, checksumAddress } from './evm.js';
import { isSolanaAddress, MAX_MEMO_BYTES } from './solana.js';

export type Chain = 'evm' | 'solana';
export type NetworkName = 'base' | 'base-sepolia' | 'solana' | 'solana-devnet';

export interface NetworkInfo {
  name: NetworkName;
  chain: Chain;
  caip2: string;
  /** The USDC contract (EVM) or mint (Solana) on this network. */
  asset: string;
  decimals: number;
  /** EVM only: the token's EIP-712 domain. */
  domain?: { name: string; version: string; chainId: number };
  /** Solana only: the default public RPC for a recent blockhash. */
  rpc?: string;
  label: string;
}

export const NETWORKS: Readonly<Record<NetworkName, NetworkInfo>> = Object.freeze({
  'base': {
    name: 'base', chain: 'evm', caip2: 'eip155:8453', decimals: 6, label: 'Base',
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    domain: { name: 'USD Coin', version: '2', chainId: 8453 },
  },
  'base-sepolia': {
    name: 'base-sepolia', chain: 'evm', caip2: 'eip155:84532', decimals: 6, label: 'Base Sepolia (test)',
    asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    domain: { name: 'USDC', version: '2', chainId: 84532 },
  },
  'solana': {
    name: 'solana', chain: 'solana', caip2: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', decimals: 6,
    label: 'Solana', asset: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    rpc: 'https://api.mainnet-beta.solana.com',
  },
  'solana-devnet': {
    name: 'solana-devnet', chain: 'solana', caip2: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1', decimals: 6,
    label: 'Solana devnet (test)', asset: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    rpc: 'https://api.devnet.solana.com',
  },
});

export function networkFromId(id: unknown): NetworkInfo | null {
  if (typeof id !== 'string') return null;
  for (const n of Object.values(NETWORKS)) if (n.caip2 === id || n.name === id) return n;
  return null;
}

/** A positive or zero decimal integer with no sign, exponent, fraction or leading zero. */
export const UINT_STRING = /^(0|[1-9][0-9]{0,17})$/;

export function parseAmount(raw: unknown): bigint | null {
  if (typeof raw !== 'string' || !UINT_STRING.test(raw)) return null;
  return BigInt(raw);
}

/** 10000 base units of a 6-decimal token → "0.01". Exact; no floating point. */
export function formatUnits(n: bigint, decimals = 6): string {
  const s = n.toString().padStart(decimals + 1, '0');
  const whole = s.slice(0, -decimals);
  const frac = s.slice(-decimals).replace(/0+$/, '');
  return frac ? `${whole}.${frac.padEnd(2, '0')}` : `${whole}.00`;
}

export function sameAddress(chain: Chain, a: string, b: string): boolean {
  return chain === 'evm' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

export function isAddressFor(chain: Chain, s: unknown): s is string {
  return chain === 'evm' ? isEvmAddress(s) : isSolanaAddress(s);
}

/** One offer from a 402, checked and normalised. */
export interface Offer {
  index: number;
  network: NetworkInfo;
  amount: bigint;
  payTo: string;
  maxTimeoutSeconds: number;
  feePayer?: string;
  memo?: string;
  /** The requirements object exactly as the merchant sent it; v2 echoes it as `accepted`. */
  raw: Record<string, unknown>;
}

export interface PaymentRequired {
  version: 1 | 2;
  resource: unknown;
  /** The merchant's resource URL, for display only — it is the agent's claim, not verified. */
  resourceUrl: string;
  offers: Array<{ index: number; offer?: Offer; skipped?: string }>;
}

function decodeRequired(raw: unknown): Record<string, unknown> {
  let v = raw;
  if (typeof v === 'string') {
    const s = v.trim();
    if (s.startsWith('{')) {
      try { v = JSON.parse(s); } catch { throw new Error('payment_required is not valid JSON'); }
    } else {
      if (!/^[A-Za-z0-9+/=_-]+$/.test(s) || s.length > 65_536) throw new Error('payment_required is neither JSON nor base64');
      try { v = JSON.parse(Buffer.from(s, 'base64').toString('utf8')); } catch {
        throw new Error('payment_required is base64 but does not decode to JSON');
      }
    }
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('payment_required must be an object');
  return v as Record<string, unknown>;
}

function checkOffer(index: number, r: unknown, version: 1 | 2): { offer?: Offer; skipped?: string } {
  if (!r || typeof r !== 'object' || Array.isArray(r)) return { skipped: 'not an object' };
  const o = r as Record<string, unknown>;
  if (o.scheme !== 'exact') return { skipped: `scheme ${String(o.scheme).slice(0, 32)} is not supported (exact only)` };
  const network = networkFromId(o.network);
  if (!network) return { skipped: `network ${String(o.network).slice(0, 64)} is not supported` };
  // Each version has one spelling: CAIP-2 in v2, the short name in v1. The payload echoes
  // the merchant's spelling, so a mixed one is refused rather than echoed back wrong.
  if ((version === 2 ? network.caip2 : network.name) !== o.network) {
    return { skipped: `network ${String(o.network).slice(0, 64)} is not spelled as x402 v${version} spells it` };
  }
  const asset = typeof o.asset === 'string' ? o.asset : '';
  if (!sameAddress(network.chain, asset, network.asset)) {
    return { skipped: `asset ${asset.slice(0, 64)} is not USDC on ${network.label}` };
  }
  const amount = parseAmount(version === 2 ? o.amount : o.maxAmountRequired);
  if (amount === null || amount === 0n) return { skipped: 'the amount is not a positive whole number of base units' };
  if (!isAddressFor(network.chain, o.payTo)) return { skipped: `payTo is not a ${network.label} address` };
  const t = o.maxTimeoutSeconds;
  if (typeof t !== 'number' || !Number.isInteger(t) || t < 1 || t > 3600) {
    return { skipped: 'maxTimeoutSeconds must be a whole number from 1 to 3600' };
  }
  const extra = (o.extra && typeof o.extra === 'object' && !Array.isArray(o.extra)) ? o.extra as Record<string, unknown> : {};
  const offer: Offer = { index, network, amount, payTo: o.payTo as string, maxTimeoutSeconds: t, raw: o };
  if (network.chain === 'evm') {
    const method = extra.assetTransferMethod;
    if (method !== undefined && method !== 'eip3009') {
      return { skipped: `asset transfer method ${String(method).slice(0, 32)} is not supported (EIP-3009 only)` };
    }
    offer.payTo = checksumAddress(offer.payTo);
  } else {
    if (!isSolanaAddress(extra.feePayer)) return { skipped: 'extra.feePayer is missing or not a Solana address' };
    offer.feePayer = extra.feePayer;
    if (extra.memo !== undefined) {
      if (typeof extra.memo !== 'string' || Buffer.byteLength(extra.memo, 'utf8') > MAX_MEMO_BYTES) {
        return { skipped: `extra.memo must be text of at most ${MAX_MEMO_BYTES} bytes` };
      }
      offer.memo = extra.memo;
    }
  }
  return { offer };
}

export function parsePaymentRequired(raw: unknown): PaymentRequired {
  const pr = decodeRequired(raw);
  const version = pr.x402Version;
  if (version !== 1 && version !== 2) throw new Error('payment_required has no supported x402Version (1 or 2)');
  if (!Array.isArray(pr.accepts) || pr.accepts.length === 0) throw new Error('payment_required lists no offers (accepts)');
  if (pr.accepts.length > 32) throw new Error('payment_required lists too many offers');
  const offers = pr.accepts.map((r, i) => ({ index: i, ...checkOffer(i, r, version) }));
  let resourceUrl = '';
  if (version === 2) {
    // v2 echoes the resource back in the payment; a 402 without one cannot be answered with
    // the payload the spec defines (round 1, F4).
    const res = pr.resource as Record<string, unknown> | undefined;
    if (!res || typeof res !== 'object' || Array.isArray(res) || typeof res.url !== 'string' || !res.url) {
      throw new Error('payment_required (x402 v2) has no resource');
    }
    resourceUrl = res.url;
  } else {
    const first = pr.accepts[0] as Record<string, unknown> | undefined;
    resourceUrl = typeof first?.resource === 'string' ? first.resource : '';
  }
  // Kept whole: it keys pending approvals, and two URLs that differ after character 512 are
  // two purchases (round 2, F3). It is cut only where it is shown.
  return { version, resource: pr.resource, resourceUrl, offers };
}

/**
 * The offer to pay. With one supported offer, that one. With several, the caller must say
 * which — choosing "the first" or "the cheapest" on the owner's behalf would sign an offer
 * nobody picked. An index that names an unsupported offer is refused, not replaced.
 */
export function selectOffer(pr: PaymentRequired, acceptIndex?: number): Offer {
  const supported = pr.offers.filter((o) => o.offer).map((o) => o.offer!);
  const describe = () => pr.offers.map((o) => o.offer
    ? `  [${o.index}] ${formatUnits(o.offer.amount)} USDC on ${o.offer.network.label} to ${o.offer.payTo}`
    : `  [${o.index}] not supported: ${o.skipped}`).join('\n');
  if (acceptIndex !== undefined && acceptIndex !== null) {
    if (!Number.isInteger(acceptIndex) || acceptIndex < 0 || acceptIndex >= pr.offers.length) {
      throw new Error(`accept_index ${acceptIndex} is out of range. The offers are:\n${describe()}`);
    }
    const chosen = pr.offers[acceptIndex];
    if (!chosen.offer) throw new Error(`offer ${acceptIndex} is not supported (${chosen.skipped}). The offers are:\n${describe()}`);
    return chosen.offer;
  }
  if (supported.length === 0) throw new Error(`None of the merchant's offers can be paid from a vaulted wallet:\n${describe()}`);
  if (supported.length > 1) {
    throw new Error(`The merchant makes more than one offer this wallet could pay. Say which with accept_index:\n${describe()}`);
  }
  return supported[0];
}

/** The header the agent retries with, for the version the merchant spoke. */
export function paymentHeader(pr: PaymentRequired, offer: Offer, payload: Record<string, unknown>): { header: string; value: string } {
  const body = pr.version === 2
    ? { x402Version: 2, resource: pr.resource, accepted: offer.raw, payload }
    : { x402Version: 1, scheme: 'exact', network: offer.network.name, payload };
  return {
    header: pr.version === 2 ? 'PAYMENT-SIGNATURE' : 'X-PAYMENT',
    value: Buffer.from(JSON.stringify(body), 'utf8').toString('base64'),
  };
}
