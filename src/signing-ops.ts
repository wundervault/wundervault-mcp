/**
 * BUILD 2 operations: pay (x402), sign (signing keys), and the stamp approval for vault_call.
 *
 * They share one shape, and the order inside it is the security argument:
 *
 *   1. fetch the entry (ciphertext and the owner's encrypted rules) — nothing decrypted yet;
 *   2. check the mode, the request, and the rules;
 *   3. if the owner must approve: ask, wait, then OPEN THE OWNER'S SEAL and compare its
 *      commitment with the operation about to happen — the server's "approved" alone is
 *      worth nothing here (spec R5);
 *   4. only then decrypt the key, sign, record, and return.
 *
 * Runs inside the broker's account, like everything reached through the socket.
 */
import { createHash } from 'node:crypto';
import type { AgentVaultAPI } from './api-client.js';
import { decryptSecretContent } from './crypto.js';
import { modeAllowsWallet, modeAllowsSign, wrongModeMessage } from './ssh-agent.js';
import {
  parsePaymentRequired, selectOffer, paymentHeader, formatUnits, sameAddress, NETWORKS, type Chain, type Offer, type PaymentRequired,
} from './x402.js';
import { parseEvmPrivateKey, evmAddressOf, transferDigest, signDigest, randomNonce } from './evm.js';
import {
  parseSolanaSecretKey, buildTransferMessage, signTransfer, randomMemo, fetchLatestBlockhash, type BlockhashFetcher,
} from './solana.js';
import {
  readPolicy, commitment, openOwnerToken, SigningState, LedgerUnreadable, type ApprovalKind, type Policy,
} from './wallet.js';
import { parseSigningKey, signBytes, decodeData } from './signing.js';
import type { SecretResponse } from './types.js';

export interface OpError { error: string; code?: string }
const err = (error: string, code?: string): OpError => (code ? { error, code } : { error });

export const MAX_SIGN_BYTES = 256 * 1024;
const MAX_TEXT_PREVIEW = 64 * 1024;

function coerceCfg(raw: unknown): Record<string, unknown> {
  try {
    const v = typeof raw === 'string' ? JSON.parse(raw) : (raw ?? {});
    return (v && typeof v === 'object' && !Array.isArray(v)) ? v as Record<string, unknown> : {};
  } catch { return {}; }
}

export interface Deps {
  api: AgentVaultAPI;
  state: SigningState;
  fetchBlockhash?: BlockhashFetcher;
  /** How long one call waits for the owner before telling the agent to call again. */
  approvalWaitMs?: number;
  now?: () => number;
  /** Told which entry was fetched, so the activity log can name the key (2026-10-13). */
  onSecret?: (s: SecretResponse) => void;
}

/**
 * Ask the owner (or keep waiting on an earlier ask for the same operation), and return only
 * once their sealed approval for EXACTLY this operation is in hand and burned.
 */
async function ownerApproval(d: Deps, a: {
  entryId: string; kind: ApprovalKind; commit: string; detail: Record<string, unknown>;
  purpose: string; vaultKey: Uint8Array;
  /**
   * What makes two asks "the same ask" for reuse. Defaults to the commitment; a payment adds
   * the resource, so a second purchase from the same payee for the same amount is asked
   * about on its own rather than riding on the first one's approval (round 1, F1).
   */
  pendingKey?: string;
}): Promise<{ ok: true; addPayee: boolean } | OpError> {
  const pendingKey = a.pendingKey ?? a.commit;
  let requestId = d.state.pendingFor(pendingKey);
  if (requestId) {
    // An earlier call already asked. Waiting on it, rather than asking again, is what stops
    // an agent that retries in a loop from mailing the owner once per retry.
  } else {
    // The agent's reason travels INSIDE the detail, which the server erases on decision —
    // never in the request's purpose field, which outlived it (round 1, server F1).
    const v = await d.api.checkOperation({ entry_id: a.entryId, kind: a.kind, detail: a.detail, purpose: '' });
    if (v.allowed) {
      // The server may never allow one of these without an approval. A server that does is
      // not one this broker will follow.
      return err('Refused: the server allowed this without the owner\'s approval, which it never may. Nothing was signed.', 'BAD_SERVER');
    }
    if (!v.request_id) return err(`${v.message ?? 'The owner could not be asked.'} Nothing was signed.`, 'NOT_APPROVED');
    requestId = v.request_id;
    d.state.setPending(pendingKey, requestId);
  }
  const res = await d.api.waitForOwnerApproval(requestId, d.approvalWaitMs ?? 90_000);
  if (res.status === 'pending') {
    return err('The owner has been asked and has not answered yet. Nothing was signed. Call again with '
      + 'the same request to keep waiting — it will not ask the owner a second time.', 'WAITING');
  }
  if (res.status !== 'approved') {
    d.state.setPending(pendingKey, null);
    return err(`The owner did not approve this (${res.status}). Nothing was signed.`, 'NOT_APPROVED');
  }
  const opened = openOwnerToken(res.owner_token, a.vaultKey, {
    requestId, entryId: a.entryId, kind: a.kind, commitment: a.commit,
  });
  if (!opened.ok) return err(`Refused: ${opened.reason}. Nothing was signed.`, 'BAD_APPROVAL');
  if (d.state.isUsed(requestId)) return err('Refused: that approval has already been used. Nothing was signed.', 'BAD_APPROVAL');
  // Burn it locally first: if the server's burn then fails, the approval is spent rather
  // than spendable twice.
  d.state.markUsed(requestId);
  d.state.setPending(pendingKey, null);
  const second = await d.api.checkOperation({ entry_id: a.entryId, kind: a.kind, approval_id: requestId, purpose: '' });
  if (!second.allowed) return err(`${second.message ?? 'The approval could not be used.'} Nothing was signed.`, 'NOT_APPROVED');
  return { ok: true, addPayee: opened.token.addPayee };
}

/** Turn a thrown LedgerUnreadable (or anything) into a refusal, never a half-done payment. */
async function guarded<T>(fn: () => Promise<T | OpError>): Promise<T | OpError> {
  try { return await fn(); } catch (e) {
    if (e instanceof LedgerUnreadable) return err(e.message, 'LEDGER');
    throw e;
  }
}

// ── vault_pay ──────────────────────────────────────────────────────────────

export interface PayResult {
  header: string; value: string; network: string; payee: string; amount_usdc: string; inside_rules: boolean;
}

export async function pay(d: Deps, args: {
  entryId: string; purpose: string; paymentRequired: unknown; acceptIndex?: number;
}): Promise<PayResult | OpError> {
  const s: SecretResponse = await d.api.getSecret(args.entryId);
  d.onSecret?.(s);
  if (!modeAllowsWallet(s.entry_mode)) return err(wrongModeMessage(s.entry_mode, 'wallet'), 'WRONG_MODE');
  const cfg = coerceCfg(s.exec_config);
  const chain = cfg.delivery === 'wallet' && (cfg.chain === 'evm' || cfg.chain === 'solana') ? cfg.chain as Chain : null;
  if (!chain) return err('Refused: this wallet does not say which chain it is on. The owner can fix it in the dashboard.', 'BAD_CONFIG');

  let offer: Offer;
  let pr: PaymentRequired;
  try {
    pr = parsePaymentRequired(args.paymentRequired);
    offer = selectOffer(pr, args.acceptIndex);
  } catch (e) { return err(`Refused: ${(e as Error).message}`, 'BAD_REQUEST'); }
  if (offer.network.chain !== chain) {
    return err(`Refused: this wallet is on ${chain === 'evm' ? 'Base' : 'Solana'}, and the offer is on ${offer.network.label}.`, 'BAD_REQUEST');
  }

  const vaultKey = await d.api.ensureVaultKey();
  const pol = readPolicy({ ciphertext: s.policy_ciphertext, nonce: s.policy_nonce, vaultKey, entryId: args.entryId, kind: 'wallet', chain });
  if (!pol.ok) return err(`Refused: this wallet's settings could not be used (${pol.reason}). Nothing was signed. The owner can save them again in the dashboard.`, 'BAD_POLICY');
  const policy: Policy | null = pol.policy;
  const rules = policy?.wallet ?? null;

  return guarded(async () => {
    if (policy) {
      const bad = d.state.acceptPolicy(policy);
      if (bad) return err(`Refused: ${bad}. Nothing was signed.`, 'BAD_POLICY');
    }
    // One lock per wallet: without it two payments that each fit the cap could both be
    // checked before either is recorded, and together pass it. It is NOT held while the
    // owner is being asked: an unanswered approval would otherwise stall every payment from
    // this wallet, inside the rules or not, for the whole wait (round 1, B1). An approved
    // payment takes the lock again to sign and record.
    const lockKey = `${chain}:${(rules?.address ?? `entry:${args.entryId}`).toLowerCase()}`;
    const fields = {
      entry_id: args.entryId, network: offer.network.name, asset: offer.network.asset,
      payee: offer.payTo, amount: offer.amount.toString(),
    };
    const commit = commitment(fields);
    type Outside = { outside: string; spent: bigint };
    const first: PayResult | OpError | Outside = await d.state.exclusive(lockKey, async () => {
      const tier2 = String(s.access_tier ?? '1') === '2';
      const spent = rules ? d.state.spentLastDay(chain, rules.address) : 0n;
      let reason: string | null = null;
      if (tier2) reason = 'tier2';
      else if (!rules || !rules.payees.some((p) => sameAddress(chain, p.address, offer.payTo))) reason = 'payee';
      else if (!rules.networks.includes(offer.network.name)) reason = 'network';
      else if (spent + offer.amount > rules.dailyCap) reason = 'cap';
      if (reason !== null) return { outside: reason, spent };
      const v = await d.api.checkOperation({ entry_id: args.entryId, kind: 'payment', within_rules: true, purpose: '' });
      if (!v.allowed) return err(`${v.message ?? 'The server refused this payment.'} Nothing was signed.`, 'NOT_APPROVED');
      return signAndRecord('inside');
    });
    if (!('outside' in first)) return first;
    const approval = await ownerApproval(d, {
      entryId: args.entryId, kind: 'payment', commit, vaultKey, purpose: args.purpose,
      pendingKey: commitment({ ...fields, resource_url: pr.resourceUrl }),
      detail: {
        ...fields, reason: first.outside, spent_24h: first.spent.toString(), daily_cap: (rules?.dailyCap ?? 0n).toString(),
        payee_listed: !!rules?.payees.some((p) => sameAddress(chain, p.address, offer.payTo)),
        resource_url: pr.resourceUrl.slice(0, 512), purpose: args.purpose.slice(0, 200),
      },
    });
    if ('error' in approval) return approval;
    return d.state.exclusive(lockKey, () => signAndRecord('approved'));

    async function signAndRecord(how: 'inside' | 'approved'): Promise<PayResult | OpError> {
      // The same fetch the rules were checked against — not a second one.
      const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
      try {
        const raw = new TextDecoder().decode(bytes);
        let header: { header: string; value: string };
        let address: string;
        if (chain === 'evm') {
          let key: Uint8Array;
          try { key = parseEvmPrivateKey(raw); } catch (e) { return err(`Refused: ${(e as Error).message}.`, 'WRONG_KIND'); }
          try {
            address = evmAddressOf(key);
            if (rules && !sameAddress(chain, rules.address, address)) {
              return err(`Refused: the wallet address in the settings (${rules.address}) is not the one this key controls. Nothing was signed.`, 'ADDRESS_MISMATCH');
            }
            if (sameAddress(chain, address, offer.payTo)) return err('Refused: the wallet would be paying itself.', 'BAD_REQUEST');
            const now = Math.floor((d.now ?? Date.now)() / 1000);
            const authorization = {
              from: address, to: offer.payTo, value: offer.amount.toString(),
              validAfter: String(now - 600), validBefore: String(now + Math.min(offer.maxTimeoutSeconds, 300)),
              nonce: randomNonce(),
            };
            const n = NETWORKS[offer.network.name];
            const signature = signDigest(transferDigest({ ...n.domain!, verifyingContract: n.asset }, authorization), key);
            header = paymentHeader(pr, offer, { signature, authorization });
          } finally { key.fill(0); }
        } else {
          let key;
          try { key = parseSolanaSecretKey(raw); } catch (e) { return err(`Refused: ${(e as Error).message}.`, 'WRONG_KIND'); }
          try {
            address = key.address;
            if (rules && rules.address !== address) {
              return err(`Refused: the wallet address in the settings (${rules.address}) is not the one this key controls. Nothing was signed.`, 'ADDRESS_MISMATCH');
            }
            if (offer.payTo === address) return err('Refused: the wallet would be paying itself.', 'BAD_REQUEST');
            if (offer.feePayer === address) return err('Refused: the merchant asked this wallet to pay the network fee as well. Nothing was signed.', 'BAD_REQUEST');
            const rpc = rules?.solanaRpc ?? offer.network.rpc!;
            let blockhash: string;
            try { blockhash = await (d.fetchBlockhash ?? fetchLatestBlockhash)(rpc); } catch (e) {
              return err(`Could not reach the Solana network to build the payment: ${(e as Error).message}. Nothing was signed.`, 'NETWORK');
            }
            const message = buildTransferMessage({
              wallet: address, payTo: offer.payTo, mint: offer.network.asset, amount: offer.amount,
              decimals: offer.network.decimals, feePayer: offer.feePayer!, recentBlockhash: blockhash,
              memo: offer.memo !== undefined ? new TextEncoder().encode(offer.memo) : randomMemo(),
            });
            header = paymentHeader(pr, offer, { transaction: signTransfer(message, key) });
          } catch (e) {
            return err(`Refused: ${(e as Error).message}. Nothing was signed.`, 'BAD_REQUEST');
          } finally { key.seed.fill(0); }
        }
        // Recorded BEFORE the header leaves: a payment this machine cannot remember is one
        // the cap cannot count. If this throws, the agent gets an error and no header.
        d.state.record({
          entry_id: args.entryId, address, network: offer.network.name, payee: offer.payTo,
          amount: offer.amount.toString(), how, purpose: args.purpose.slice(0, 200),
        });
        return {
          header: header.header, value: header.value, network: offer.network.label, payee: offer.payTo,
          amount_usdc: formatUnits(offer.amount), inside_rules: how === 'inside',
        };
      } finally { bytes.fill(0); }
    }
  });
}

// ── vault_sign ─────────────────────────────────────────────────────────────

export async function sign(d: Deps, args: {
  entryId: string; purpose: string; data: unknown; encoding?: unknown;
}): Promise<{ signature: string; public_key: string; algorithm: string } | OpError> {
  const s = await d.api.getSecret(args.entryId);
  d.onSecret?.(s);
  if (!modeAllowsSign(s.entry_mode)) return err(wrongModeMessage(s.entry_mode, 'sign'), 'WRONG_MODE');
  if (coerceCfg(s.exec_config).delivery !== 'sign') {
    return err('Refused: this signing key\'s settings are not ones the broker accepts. The owner can fix it in the dashboard.', 'BAD_CONFIG');
  }
  let data: Buffer;
  try { data = decodeData(args.data, args.encoding); } catch (e) { return err(`Refused: ${(e as Error).message}.`, 'BAD_REQUEST'); }
  if (data.length === 0) return err('Refused: there is nothing to sign.', 'BAD_REQUEST');
  if (data.length > MAX_SIGN_BYTES) return err(`Refused: at most ${MAX_SIGN_BYTES} bytes can be signed at once.`, 'BAD_REQUEST');

  const dataSha = createHash('sha256').update(data).digest('hex');
  const fields = { entry_id: args.entryId, data_sha256: dataSha, length: String(data.length) };
  // The whole text when it is text and small enough to read; the owner cannot judge bytes
  // they are shown 200 characters of (spec review S13).
  let text: string | undefined;
  if (data.length <= MAX_TEXT_PREVIEW) {
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(data); } catch { text = undefined; }
    if (text !== undefined && /[\x00-\x08\x0e-\x1f]/.test(text)) text = undefined;
    // Measured as it travels — escaped — not as it is: 64 KiB of quotation marks is 128 KiB
    // of JSON, and the server would refuse the ask the owner needs to see (round 2, F2).
    if (text !== undefined && Buffer.byteLength(JSON.stringify(text)) > MAX_TEXT_PREVIEW) text = undefined;
  }
  const vaultKey = await d.api.ensureVaultKey();
  return guarded(async () => {
    const approval = await ownerApproval(d, {
      entryId: args.entryId, kind: 'signature', commit: commitment(fields), vaultKey, purpose: args.purpose,
      detail: { ...fields, ...(text !== undefined ? { text } : {}), purpose: args.purpose.slice(0, 200) },
    });
    if ('error' in approval) return approval;
    // Decrypted only now: a denied or forged approval never reaches the key.
    const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
    try {
      let key;
      try { key = parseSigningKey(new TextDecoder().decode(bytes)); } catch (e) {
        return err(`Refused: ${(e as Error).message}`, 'WRONG_KIND');
      }
      return { signature: signBytes(key, data), public_key: key.publicKey, algorithm: key.algorithm };
    } finally { bytes.fill(0); }
  });
}

// ── stamp recipe approval (used by vault_call) ─────────────────────────────

/**
 * Is this (recipe, origin) approved for this stamped entry — or, if not, get the owner's
 * approval now. Returns null when the call may proceed.
 */
export async function approveStamp(d: Deps, args: {
  entryId: string; s: SecretResponse; vaultKey: Uint8Array; origin: string; recipe: unknown;
  recipeSha: string; summary: string; purpose: string;
}): Promise<OpError | null> {
  const pol = readPolicy({ ciphertext: args.s.policy_ciphertext, nonce: args.s.policy_nonce, vaultKey: args.vaultKey, entryId: args.entryId, kind: 'stamped' });
  if (!pol.ok) return err(`Refused: this key's settings could not be used (${pol.reason}). Nothing was sent.`, 'BAD_POLICY');
  const r = await guarded(async () => {
    if (pol.policy) {
      const bad = d.state.acceptPolicy(pol.policy);
      if (bad) return err(`Refused: ${bad}. Nothing was sent.`, 'BAD_POLICY');
      if (pol.policy.stamped!.approved.some((a) => a.recipe_sha256 === args.recipeSha && a.origin === args.origin)) {
        return { ok: true as const };
      }
    }
    const fields = { entry_id: args.entryId, origin: args.origin, recipe_sha256: args.recipeSha };
    const approval = await ownerApproval(d, {
      entryId: args.entryId, kind: 'recipe', commit: commitment(fields), vaultKey: args.vaultKey, purpose: args.purpose,
      detail: { ...fields, recipe: args.recipe, summary: args.summary, purpose: args.purpose.slice(0, 200) },
    });
    if ('error' in approval) return approval;
    return { ok: true as const };
  });
  return 'error' in r ? r : null;
}
