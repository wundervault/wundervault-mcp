import { createHash } from 'node:crypto';
import { checkValueCommitment, openSetup } from './setup-seal.js';
import { setupProblem } from './parts.js';
import type { SetupPins } from './setup-seal.js';
import type { SecretResponse, SecretsResponse, VaultEntry } from './types.js';

export interface EntryContext {
  requestedId: string | null;
  vaultKey: () => Promise<Uint8Array>;
  pins: SetupPins;
  account: string;
  withValue: boolean;
  /** Batch B A1: the full use view (setup, config) of an entry fetched WITHOUT its value, so the
   * call can be approved before the value is fetched. The value commitment is checked on the
   * value fetch that follows. Ignored when withValue is true. */
  metaView?: boolean;
}

type EntryResponse = Omit<Partial<SecretResponse>, 'operations'> & {
  secret_name?: string;
  operations?: string | string[];
};

type EntryResult<T> =
  | { ok: true; entry: T }
  | { ok: false; code: 'WRONG_ENTRY' | 'MALFORMED' | 'SETUP_REFUSED'; message: string };

const modes = {
  http: 'BROKER_HTTP',
  ssh: 'BROKER_SSH_AGENT',
  wallet: 'BROKER_WALLET',
  sign: 'BROKER_SIGN',
};

const responseFields = [
  'encrypted_content', 'content_nonce', 'access_tier', 'alert_email', 'directive',
  'directive_signature', 'id', 'agent_id', 'rev', 'vault_locked',
  // The owner's sealed rules (wallet limits and payees, approved stamp recipes). Sealed by the
  // owner's browser with this agent's vault key and bound to the entry id, and refused when
  // older than a version this machine has seen (SigningState.acceptPolicy), so the server can
  // withhold them but not forge or roll them back. Dropping them made every payment and every
  // stamped call ask the owner again once a setup was sealed (found by broker-stamp-parts).
  'policy_ciphertext', 'policy_nonce',
] as const;

function refused(reason: string): EntryResult<never> {
  return {
    ok: false,
    code: 'SETUP_REFUSED',
    message: `Sealed setup refused: ${reason}. Nothing was sent.`,
  };
}

function nonEmptyObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.keys(value).length > 0;
}

export function pinAccountFor(apiKey: string): string {
  return createHash('sha256').update(apiKey, 'utf8').digest('hex');
}

/** The only place server entry fields become a locally opened, broker-facing view. */
export async function resolveEntry<T extends EntryResponse>(
  resp: T, ctx: EntryContext,
): Promise<EntryResult<T>> {
  if (ctx.requestedId !== null && resp.id !== undefined && resp.id !== ctx.requestedId) {
    return {
      ok: false,
      code: 'WRONG_ENTRY',
      message: 'The server returned a different entry. Nothing was sent.',
    };
  }
  const entryId = ctx.requestedId ?? resp.id;
  if (typeof entryId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(entryId)) {
    return {
      ok: false,
      code: 'MALFORMED',
      message: 'The server returned no usable entry id. Nothing was sent.',
    };
  }

  // An empty blob is a broken seal, not permission to fall back to plaintext.
  const hasSetup = resp.setup_ciphertext !== undefined && resp.setup_ciphertext !== null;
  try {
    await ctx.pins.load();
    const decision = ctx.pins.decide(ctx.account, entryId, hasSetup, resp.rev, resp.vault_locked);
    if (decision !== 'ok') return refused(decision);
  } catch {
    return refused('pins unreadable');
  }

  if (!hasSetup) {
    if (resp.vault_locked === true) {
      return refused('this account is locked but the server sent no sealed setup');
    }
    return { ok: true, entry: resp };
  }

  try {
    const opened = openSetup(
      await ctx.vaultKey(), resp.agent_id ?? '', entryId, resp.rev ?? -1,
      resp.setup_ciphertext!, resp.setup_nonce ?? '',
    );
    if (!opened.ok) return refused(opened.reason);
    const setup = opened.setup;

    // The same rules the vault page saves by (review cl5 broker F1): a sealed setup that breaks
    // them is refused here, so nothing downstream ever sees an impossible combination.
    const problem = setupProblem(setup, ctx.withValue || ctx.metaView === true);
    if (problem) return refused(problem);
    if (ctx.withValue && !checkValueCommitment(setup, resp.encrypted_content ?? '')) {
      return refused("the key and its setup don't match");
    }

    // Deliberate allowlist: never merge server policy or descriptions into this view.
    const view: Record<string, unknown> = {};
    for (const field of responseFields) {
      if (resp[field] !== undefined) view[field] = resp[field];
    }
    view.name = setup.name;
    view.secret_name = setup.name;
    view.entry_mode = modes[setup.delivery];

    const config: Record<string, unknown> = { delivery: setup.delivery };
    // Today's binding check refuses unknown fields, and the vault page marks a v1 binding
    // {v:1}; the marker is the setup's business, not the legacy exec_config's.
    let binding: unknown = setup.binding;
    if (binding && typeof binding === 'object' && !Array.isArray(binding)
        && (binding as { v?: unknown }).v === 1) {
      const { v: _v, ...rest } = binding as Record<string, unknown>;
      binding = rest;
    }
    for (const [field, value] of [
      ['credential_binding', binding],
      ['ssh_hosts', setup.ssh_hosts],
      ['chain', setup.chain],
    ] as const) {
      if (value !== undefined && value !== null) config[field] = value;
    }
    view.exec_config = JSON.stringify(config);
    if (nonEmptyObject(setup.operations)) view.operations = JSON.stringify(setup.operations);
    if (Array.isArray(setup.private_origins) && setup.private_origins.length > 0) {
      view.allowed_private_origins = JSON.stringify(setup.private_origins);
    }
    view.setup = setup;

    // Persist before returning anything usable. Errors must not expose an unpinned view.
    await ctx.pins.record(ctx.account, entryId, setup.rev, resp.vault_locked === true);
    if (!ctx.withValue && ctx.metaView !== true) {
      // A list entry keeps the exact shape the server listed before L — an older agent app
      // reads `operations` as an array of ids (server.ts list rendering) — and carries no setup.
      const listed: Record<string, unknown> = {
        id: entryId, secret_name: setup.name, access_tier: resp.access_tier, entry_mode: view.entry_mode,
      };
      if (nonEmptyObject(setup.operations)) listed.operations = Object.keys(setup.operations);
      return { ok: true, entry: listed as unknown as T };
    }
    return { ok: true, entry: view as unknown as T };
  } catch {
    // Neither crypto errors nor filesystem errors may disclose names, keys or setups.
    return refused('could not open the setup or persist its revision pin');
  }
}

export async function resolveList(
  resp: SecretsResponse, ctx: Omit<EntryContext, 'requestedId' | 'withValue'>,
): Promise<{ entries: VaultEntry[]; refused: number }> {
  const entries: VaultEntry[] = [];
  let refusedCount = 0;
  for (const entry of resp.entries) {
    const result = await resolveEntry(entry, { ...ctx, requestedId: null, withValue: false });
    if (result.ok) entries.push(result.entry);
    else refusedCount++;
  }
  return { entries, refused: refusedCount };
}
