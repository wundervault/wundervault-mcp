/**
 * What the broker does on an agent's behalf, now that it does not hand over the key.
 *
 * Phase 4 moved the credentials into an account the agent cannot read. It did not stop
 * the broker giving them back: the per-agent socket answered a valid token with
 * `{api_key, enc_key, vault_url}`, and the MCP server — which runs as the AGENT's uid —
 * used `enc_key` to unwrap `vault_key_for_agent` and decrypt the whole vault in its own
 * memory. The boundary held for the disk and for the broker's memory, and the front door
 * handed out the key.
 *
 * So the socket stops serving credentials and starts serving OPERATIONS. Everything in
 * this file runs inside the broker's uid. `vault_key` is derived here, used here, and
 * never crosses the socket.
 *
 * THE RULE THAT SHAPES EVERY OPERATION BELOW
 *
 * The broker never runs a command the agent chose. `ProtectHome=yes` already means it
 * could not reach the agent's files, but the real reason is worse than inconvenience: a
 * broker that executes an agent-supplied command hands that agent code execution as the
 * uid that owns /var/lib/wundervault, which is every credential on the machine. So the
 * operations here are exactly two shapes, and no more:
 *
 *   - perform an HTTP request with the key attached and return the scrubbed response;
 *   - answer ssh-agent signature requests on a socket, holding the private key.
 *
 * There used to be a third — hand back a plaintext, for an entry in the hand-over mode
 * (`get_entry`, behind `vault_exec`, `vault_entry_inject_env` and `vault_rsync`). 1.0 is
 * brokered only: that mode is retired on the server and the operation is gone here, so
 * no path through this socket returns a key's value. `vault_ssh_exec` still runs in the
 * agent's process — it is the agent's own command — and gets signatures, not the key.
 *
 * WEB CALLS ASK BEFORE FETCHING THE VALUE
 *
 * A web call first reads metadata, builds the destination check, and only then fetches
 * the value with the allowed check's single-use fetch grant. Other operations keep their
 * existing fetch gate, and an old server falls back to it.
 *
 * None of them sends the agent's `purpose` with that fetch. The reason stays in the local
 * destination log; the server hears it only for a tier-2 web call, on the approval the
 * owner is being asked to make (see `call`).
 */
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { AgentVaultAPI, approvalNotGivenMessage, ADMIN_ACCESS_REQUIRED, adminAccessRequiredMessage } from './api-client.js';
import { adminCertificate } from './ssh-cert.js';
import { signerFromIdentity, type BrokerSigner } from './broker-sign.js';
import { decryptSecretContent, loadEncryptionKey } from './crypto.js';
import {
  modeAllowsSshBroker, modeAllowsHttpBroker, wrongModeMessage,
  loadOpenSshEd25519, startAgent, checkSshDestination, runSshWithAgent, type AgentHandle, type BrokeredOp,
} from './ssh-agent.js';
import {
  normalizeSshTarget, scanHostKey, isSshHostKey, sshHostRecipe, sshHostSha,
  describeSshHost, fingerprint as hostFingerprint, knownHostsLine,
} from './ssh-pin.js';
import { parseGitSshUrl } from './git-op.js';
import {
  performOperation, definitionFromAgentRequest, originString, isApprovedPrivateOrigin,
  probeCertificate, type AgentRequest,
} from './http-broker.js';
import {
  validateSignInRecipe, signInRecipeSha, describeSignIn, renderLoginBody, extractSession,
  secretFormsFor, SessionCache, sessionKey, type SignInRecipe,
} from './signin.js';
import type { CredentialBinding } from './opdef.js';

/**
 * Sessions the broker got by signing in (spec 1.2 §3). Memory only — never written to disk,
 * never returned — so a broker restart signs in again. Module-level because an agent's ops
 * object is not guaranteed to live between calls; keys carry the agent, entry, origin,
 * approved recipe, value and pin, so a change to any of them is a different session.
 */
const SIGN_IN_SESSIONS = new SessionCache();
import { verifyOperationDefinition, validateArguments } from './opdef.js';
import { recordDestination, newDestinationNotice, emitToStderr } from './network-store.js';
import { runtimeDir, systemRoot } from './paths.js';
import type { VaultEntry } from './types.js';
import { BEARER, bindingFromExecConfig, looksLikePrivateKey, secretForms, validateAgentHeaders, pathBindingProblem } from './delivery.js';
import { checkAgentHeaders, oauth1FromParts, readValue, scrub as scrubParts, secretFormsAll, validateBindingV2, type BindingV2, type Shape } from './parts.js';
import { SetupPins, sealT2Detail, t2MatchMac, t2OriginMac, newRequestId, sealIncoming, incomingNameMac } from './setup-seal.js';
import { NewKeyRecipes, NewKeyOutbox, readNewKey, newKeyForms, carriesKey, type NewKeyRecipe } from './new-key.js';
import { renderDetail } from './render.js';
import { SigningState, readPolicy } from './wallet.js';
import { normalizeOrigin, validateSendAs, placementRecipe, placementSha, describePlacement, isAskBinding, type SendAs } from './placement.js';
import { validateRecipe, recipeSha256, describeRecipe, computeStamp, parseStampedValue, looksLikeOAuth1Value, type Recipe, type StampedValue } from './stamp.js';
import { pay as payOp, sign as signOp, twoFactorCode as twoFactorOp, approveStamp, type Deps, type PayResult } from './signing-ops.js';
import type { ActivityRecord } from './activity-log.js';
import type { AnchorClient } from './activity-anchor.js';
import { scrubSecret } from './http-broker.js';

/** Where an operation's line in the activity log goes. The daemon supplies one. */
export interface ActivitySink { record(r: ActivityRecord): void }

/** The first line of a message, bounded: a log line is one line. */
function firstLine(s: string): string {
  return String(s ?? '').split('\n')[0].slice(0, 300);
}

/** Turn an operation's reply into the line's outcome. `sending` means the request went out. */
function finish(rec: ActivityRecord, r: unknown): void {
  const e = r as { error?: string; code?: string } | null;
  if (e && typeof e === 'object' && typeof e.error === 'string') {
    rec.outcome = rec.outcome === 'sending' ? 'failed' : 'refused';
    rec.detail = `${e.code ? `${e.code}: ` : ''}${firstLine(e.error)}`;
  } else if (rec.outcome === 'sending' || rec.outcome === 'refused') {
    rec.outcome = rec.kind === 'call' ? 'sent' : rec.outcome;
  }
}

export interface OpError { error: string; code?: string }

const NEW_KEY_POINTER = (service: string) =>
  `Refused: this address makes a new key at ${service}, and its answer would hand that key to you. `
  + 'Nothing was sent. Use vault_new_key with the same entry and request: the helper makes the key, puts it '
  + "straight into the owner's vault, and tells you its id.";

function err(message: string, code?: string): OpError {
  return code ? { error: message, code } : { error: message };
}

/** Parse exec_config, which the backend sends as a JSON string on some paths. */
function coerceCfg(raw: unknown): Record<string, unknown> {
  try {
    const v = typeof raw === 'string' ? JSON.parse(raw) : (raw ?? {});
    return (v && typeof v === 'object') ? v as Record<string, unknown> : {};
  } catch { return {}; }
}

/**
 * One agent's operations. Holds the credentials; never returns them.
 *
 * `api` is built once per profile and kept, because `AgentVaultAPI` caches the unwrapped
 * vault key after the first `ensureVaultKey()`. That cache lives in the broker's memory,
 * which is the whole point of the phase — but it also means a repair (which retires the
 * vault key) must invalidate it, so `reset()` exists and `registerProfile` calls it.
 */
export class BrokerOps {
  private api: AgentVaultAPI;
  private readonly recipes: NewKeyRecipes;
  private readonly outbox: NewKeyOutbox;
  /** BUILD 2: this machine's payment record, policy versions and used approvals. */
  private state: SigningState;
  private readonly keyscan: (t: NonNullable<ReturnType<typeof normalizeSshTarget>>) => Promise<string | null>;
  private ssh = new Map<string, { handle: AgentHandle; timer: NodeJS.Timeout; entryId: string; key?: string; host: string; reason: string; tier: string; adminPoll?: NodeJS.Timeout; adminUntil?: string; endedBy?: string; endRemote?: () => Promise<number> }>();

  /**
   * A server's identity, scanned at most once per two minutes per address. Each scan is a
   * connection that never signs in, and OpenSSH 9.8+ (PerSourcePenalties) blocks an address
   * that makes many: guided setup's seven sessions in a row were dropped by the server. Safe
   * to reuse: the connection itself is still checked against the pinned identity
   * (StrictHostKeyChecking=yes), so a stale answer can only fail, never let another server in.
   */
  private scanCache = new Map<string, { at: number; key: string }>();
  private async scanCached(target: NonNullable<ReturnType<typeof normalizeSshTarget>>): Promise<string | null> {
    const id = `${target.host}:${target.port}`;
    const hit = this.scanCache.get(id);
    if (hit && Date.now() - hit.at < 120_000) return hit.key;
    const key = await this.keyscan(target);
    if (key) this.scanCache.set(id, { at: Date.now(), key });
    else this.scanCache.delete(id);
    return key;
  }

  /** How often an admin session asks whether its admin access is still on (End now, done). */
  static ADMIN_POLL_MS = 3_000;
  /**
   * The activity log (activity-log.ts). Set by the daemon; null in a test that does not
   * care. Writing a line never changes what an operation returns, and never throws into it.
   */
  activity: ActivitySink | null = null;

  private record(rec: ActivityRecord): void {
    try { this.activity?.record(rec); } catch { /* bookkeeping never fails a vault call */ }
  }

  /** This agent's route to the server's copy of the log's chain. */
  /** Update now: this agent's route for the owner's update orders, and the key that opens them. */
  orderRoute(): {
    get(brokerVersion: string): ReturnType<AgentVaultAPI['getBrokerOrders']>;
    post(id: string, state: string, detail: string): Promise<void>;
    key(): Promise<Uint8Array>;
    /** Guided setup + change check (SPEC-admin-access §13). */
    result(id: string, ciphertext: string, nonce: string): Promise<void>;
    due(entries: string[]): ReturnType<AgentVaultAPI['getServerChecksDue']>;
    check(requestId: string, changed: boolean, ciphertext: string, nonce: string): Promise<void>;
    ops: BrokerOps;
  } {
    return {
      get: (v) => this.api.getBrokerOrders(v),
      post: (id, state, detail) => this.api.postBrokerOrderState(id, state, detail),
      key: () => this.api.ensureVaultKey(),
      result: (id, c, n) => this.api.postBrokerOrderResult(id, c, n),
      due: (entries) => this.api.getServerChecksDue(entries),
      check: (r, ch, c, n) => this.api.postServerCheck(r, ch, c, n),
      ops: this,
    };
  }

  anchorClient(): AnchorClient {
    const api = this.api;
    return {
      label: this.agentName,
      getActivityAnchor: () => api.getActivityAnchor(),
      postActivityAnchor: (b) => api.postActivityAnchor(b),
      reportActivityMismatch: (b) => api.reportActivityMismatch(b),
    };
  }

  constructor(
    public readonly agentName: string,
    apiKey: string,
    encKeyB64: string,
    vaultUrl: string,
    /**
     * PHASE 6. Injectable so a test can drive a signed call without a key in
     * /var/lib/wundervault — and so the default path is the real one, read from this
     * machine's broker identity rather than passed in by whoever constructs this.
     */
    signer: BrokerSigner | null = signerFromIdentity(),
    state: SigningState = new SigningState(),
    private readonly depsOverride: Partial<Deps> = {},
    opts: {
      pinsPath?: string;
      keyscan?: (t: NonNullable<ReturnType<typeof normalizeSshTarget>>) => Promise<string | null>;
      /** Tests only: recipes for a local stand-in service. The real list is compiled in (new-key.ts). */
      newKeyRecipes?: NewKeyRecipes;
      /** Where a made-but-undelivered key waits, already locked. Default: the helper's own folder. */
      outboxDir?: string;
    } = {},
  ) {
    this.recipes = opts.newKeyRecipes ?? new NewKeyRecipes();
    this.outbox = new NewKeyOutbox(opts.outboxDir ?? path.join(systemRoot(), 'new-key-outbox'));
    const pins = SetupPins.shared(opts.pinsPath ?? path.join(systemRoot(), 'setup-pins.json'));
    this.api = new AgentVaultAPI(apiKey, loadEncryptionKey(encKeyB64), vaultUrl, signer, pins);
    this.state = state;
    this.keyscan = opts.keyscan ?? scanHostKey;
  }

  private deps(): Deps {
    return { api: this.api, state: this.state, ...this.depsOverride };
  }

  /** The same, with the fetched entry's name and tier copied onto the log line. */
  private depsNaming(rec: ActivityRecord): Deps {
    return {
      ...this.deps(),
      onSecret: (s) => { rec.key = s.name; rec.tier = String(s.access_tier ?? '1'); },
    };
  }

  // ── pay / sign (build 2) ───────────────────────────────────────────────────
  async pay(args: { entryId: string; purpose: string; paymentRequired: unknown; acceptIndex?: number }): Promise<PayResult | OpError> {
    const rec: ActivityRecord = { kind: 'pay', outcome: 'refused', agent: this.agentName, entry_id: args.entryId, reason: args.purpose };
    try {
      const r = await payOp(this.depsNaming(rec), args);
      finish(rec, r);
      if (!('error' in r)) {
        rec.outcome = 'signed';
        rec.approval = r.inside_rules ? 'none' : 'approved';
        rec.extra = { network: r.network, payee: r.payee, amount_usdc: r.amount_usdc, inside_rules: r.inside_rules };
      }
      return r;
    } catch (e) {
      rec.outcome = 'error'; rec.detail = firstLine((e as Error).message);
      throw e;
    } finally { this.record(rec); }
  }

  async sign(args: { entryId: string; purpose: string; data: unknown; encoding?: unknown }) {
    const rec: ActivityRecord = {
      kind: 'sign', outcome: 'refused', agent: this.agentName, entry_id: args.entryId, reason: args.purpose,
      extra: {
        data_sha256: createHash('sha256').update(String(args.data ?? '')).digest('hex'),
        encoding: typeof args.encoding === 'string' ? args.encoding : 'utf8',
      },
    };
    try {
      const r = await signOp(this.depsNaming(rec), args);
      finish(rec, r);
      const ok = r as { signature?: string; algorithm?: string };
      if (ok && typeof ok.signature === 'string') {
        rec.outcome = 'signed';
        rec.approval = 'approved';
        if (ok.algorithm) rec.extra = { ...rec.extra, algorithm: ok.algorithm };
      }
      return r;
    } catch (e) {
      rec.outcome = 'error'; rec.detail = firstLine((e as Error).message);
      throw e;
    } finally { this.record(rec); }
  }

  // ── 2fa_code ─────────────────────────────────────────────────────────────
  async twoFactorCode(args: { entryId: string; purpose: string }) {
    const rec: ActivityRecord = { kind: '2fa', outcome: 'refused', agent: this.agentName, entry_id: args.entryId, reason: args.purpose };
    try {
      const r = await twoFactorOp(this.depsNaming(rec), args);
      finish(rec, r);
      // The code itself is never logged: it is short-lived, but the log is readable by agents.
      if (!('error' in r)) { rec.outcome = 'sent'; if (rec.tier === '2') rec.approval = 'approved'; }
      return r;
    } catch (e) {
      rec.outcome = 'error'; rec.detail = firstLine((e as Error).message);
      throw e;
    } finally { this.record(rec); }
  }

  /**
   * How many signing sessions one agent may hold at once.
   *
   * Each open session is a listener, a timer, a directory under /run and a private key
   * held in memory, and the caller chooses when to close them. Without a ceiling an
   * authenticated agent can call `ssh_agent_open` in a loop and leave every session alive
   * for its full lifetime. Small, because a legitimate caller runs one command at a time.
   */
  private static readonly MAX_SSH_SESSIONS = 4;

  /** Close every ssh session this agent holds. Called on re-enrolment and on shutdown. */
  reset(): void {
    for (const id of [...this.ssh.keys()]) this.closeSsh(id);
  }

  // ── list_entries ───────────────────────────────────────────────────────────
  async listEntries(): Promise<{ entries: VaultEntry[] } | OpError> {
    const data = await this.api.listSecrets();
    return { entries: data.entries ?? [] };
  }

  async done(): Promise<{ ended: number; setting: 'end' | 'keep'; ssh_closed?: number } | OpError> {
    try {
      const r = await this.api.agentDone();
      if (r.setting !== 'end') return r;
      // D6: "end" also closes this agent's signing sessions here, not only its approvals on
      // the server. "keep" leaves both running.
      let closed = 0;
      for (const id of [...this.ssh.keys()]) { if (this.closeSsh(id, 'done').closed) closed++; }
      return { ...r, ssh_closed: closed };
    } catch (e) {
      return err((e as Error).message, (e as { code?: string }).code);
    }
  }

  // ── call ───────────────────────────────────────────────────────────────────
  /**
   * Perform a typed HTTP request with the credential, and return the response.
   *
   * Moved here whole from the MCP server. `SPEC-tiered-broker.md` said of tier 1 that
   * "the key never reaches the agent" — which was written about this code and was not
   * true of it, because `performOperation` was imported into the agent's own process.
   * It is true now.
   */
  async call(args: {
    entryId: string; purpose: string; operationId?: string;
    callArgs?: Record<string, unknown>; request?: AgentRequest & { send_as?: unknown };
    /** vault_new_key: the answer holds a new key; it goes to the vault, never to the agent. */
    newKey?: { saveAs: string };
  }): Promise<{ status: number; body: unknown; tier: string; label: string; notice?: string } | OpError> {
    // One line in the activity log for every call, whatever happens to it. The inner body
    // fills in what it learns (the key's name, the address, the approval, the status) as
    // it learns it, so a refusal at any point still says how far the call got.
    const rec: ActivityRecord = {
      kind: 'call', outcome: 'refused', agent: this.agentName, entry_id: args.entryId,
      reason: args.purpose, approval: 'none',
    };
    // What the agent ASKED for, recorded before anything can refuse it (round 1, F4). The
    // agent never has the key, so this cannot contain it; once the key is decrypted the
    // address is rewritten from the definition, scrubbed.
    const ask = args.request;
    if (ask?.origin?.host && ask.origin.scheme) {
      rec.method = String(ask.method || 'GET').toUpperCase();
      rec.address = `${ask.origin.scheme}://${ask.origin.host}:${ask.origin.port ?? ''}${ask.path || '/'}`;
      if (ask.body !== undefined) rec.body_sha256 = createHash('sha256').update(JSON.stringify(ask.body)).digest('hex');
    } else if (args.operationId) {
      rec.extra = { operation: args.operationId };
    }
    if (args.newKey) rec.extra = { ...(rec.extra ?? {}), new_key: true };
    try {
      const r = await this.callInner(args, rec);
      finish(rec, r);
      return r;
    } catch (e) {
      rec.outcome = rec.outcome === 'sending' ? 'failed' : 'error';
      rec.detail = firstLine((e as Error).message);
      throw e;
    } finally {
      this.record(rec);
    }
  }

  private async callInner(args: {
    entryId: string; purpose: string; operationId?: string;
    callArgs?: Record<string, unknown>; request?: AgentRequest & { send_as?: unknown };
    /** vault_new_key: the answer holds a new key; it goes to the vault, never to the agent. */
    newKey?: { saveAs: string };
  }, rec: ActivityRecord): Promise<{ status: number; body: unknown; tier: string; label: string; notice?: string } | OpError> {
    const { entryId, purpose } = args;
    const operationId = args.operationId || '';
    const callArgs = args.callArgs ?? {};
    let agentReq = args.request;

    // ── KEY-MAKING ADDRESSES (SPEC-helper-fetch-and-save F1, F2, F4). Decided from what the
    // agent asked, before the entry is fetched, anything is approved or anything is sent.
    const newKey = args.newKey;
    let recipe: NewKeyRecipe | null = null;
    let saveAs = '';
    if (newKey) {
      saveAs = typeof newKey.saveAs === 'string' ? newKey.saveAs.trim() : '';
      if (!saveAs || saveAs.length > 80 || /[\u0000-\u001f\u007f]/.test(saveAs)) {
        return err('Refused: save_as is the name for the new secret, 1 to 80 characters. Nothing was sent.', 'BAD_REQUEST');
      }
      if (operationId || !agentReq) {
        return err('Refused: vault_new_key takes a request, not a signed operation. Nothing was sent.', 'BAD_REQUEST');
      }
      const extras = agentReq as { sign_in?: unknown; send_as?: unknown; trust_certificate?: unknown };
      if (extras.sign_in !== undefined || extras.send_as !== undefined || extras.trust_certificate !== undefined) {
        return err('Refused: vault_new_key does not take sign_in, send_as or trust_certificate. Nothing was sent.', 'BAD_REQUEST');
      }
      recipe = this.recipes.exact(agentReq.origin, agentReq.method, String(agentReq.path ?? ''));
      if (!recipe) {
        return err('Refused: the helper has no recipe for making a key at this address, so it cannot tell '
          + 'which part of the answer is the new key. Nothing was sent. vault_new_key works only at the exact '
          + 'key-making addresses it knows (see its description).', 'NO_RECIPE');
      }
      rec.extra = { ...(rec.extra ?? {}), recipe: recipe.id };
    } else if (agentReq?.origin) {
      const hit = this.recipes.loose(agentReq.origin, agentReq.method || 'GET', String(agentReq.path ?? ''));
      if (hit) return err(NEW_KEY_POINTER(hit.service_name), 'USE_NEW_KEY');
    }

    let haveValue = false;
    let grant: string | undefined;
    let s: Awaited<ReturnType<AgentVaultAPI['getSecretMeta']>>;
    try {
      s = await this.api.getSecretMeta(entryId);
    } catch (e) {
      if ((e as { code?: string })?.code !== 'META_UNSUPPORTED') throw e;
      s = await this.api.getSecret(entryId);
      haveValue = true;
    }
    rec.key = s.name;
    rec.tier = String(s.access_tier ?? '1');
    if (!modeAllowsHttpBroker(s.entry_mode)) {
      return err(wrongModeMessage(s.entry_mode, 'http'), 'WRONG_MODE');
    }

    const askBinding = (s.setup?.shape === 'api_key' && isAskBinding(s.setup.binding))
      || isAskBinding(coerceCfg(s.exec_config).credential_binding);
    if (!askBinding && agentReq?.send_as !== undefined) {
      return err('Refused: request.send_as is only for keys set to ask on first use. Nothing was sent.', 'BAD_REQUEST');
    }
    if (askBinding && operationId) {
      return err('Refused: a key set to ask on first use is used with request, not a signed operation. Nothing was sent.', 'BAD_REQUEST');
    }

    // The credential binding always comes from the ENTRY. An agent may choose where a
    // request goes; it never chooses how the secret is framed on the way out, except for
    // an ask-entry's owner-approved proposal. Checked before the key is decrypted.
    // ── SIGN-IN (spec 1.2 §3): a stored login the broker signs in with, keeping the session.
    // Checked and approved BEFORE anything is decrypted, like a stamp recipe.
    const signInRaw = (agentReq as { sign_in?: unknown } | undefined)?.sign_in;
    let signIn: {
      recipe: SignInRecipe; origin: string; recipeSha: string;
      pin?: { sha256: string; pem: string }; approvedOrigins: string[];
    } | null = null;
    if (signInRaw !== undefined) {
      if (askBinding) return err('Refused: request.sign_in is not used with a key set to ask on first use. Nothing was sent.', 'BAD_REQUEST');
      if (operationId) return err('Refused: a sign-in is used with request, not a signed operation. Nothing was sent.', 'BAD_REQUEST');
      const shape = s.setup?.shape;
      if ((shape !== 'password' && shape !== 'website_login') || s.setup?.value_format !== 'parts-1' || s.setup?.binding != null) {
        return err('Refused: request.sign_in works with a stored login (a username and password the broker '
          + 'signs in with). This secret is not one. Nothing was sent.', 'WRONG_KIND');
      }
      if ((agentReq as { stamp?: unknown }).stamp !== undefined) {
        return err('Refused: a request cannot carry both sign_in and stamp. Nothing was sent.', 'BAD_REQUEST');
      }
      const rc = validateSignInRecipe(signInRaw);
      if (!rc.ok) return err(`Refused: request.sign_in: ${rc.reason}. Nothing was sent.`, 'BAD_REQUEST');
      const o = agentReq!.origin;
      if (!o?.host || o.scheme !== 'https' || !o.port) return err('request.origin needs scheme https, host and port.');
      const origin = originString({ scheme: 'https', host: o.host.toLowerCase(), port: o.port });
      let approvedOrigins: string[] = [];
      try {
        const raw = s.allowed_private_origins as unknown;
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (Array.isArray(parsed)) approvedOrigins = parsed.filter((x): x is string => typeof x === 'string');
      } catch { approvedOrigins = []; }
      let pin: { sha256: string; pem: string } | undefined;
      if ((agentReq as { trust_certificate?: unknown }).trust_certificate === true) {
        try {
          pin = await probeCertificate({ host: o.host.toLowerCase(), port: o.port }, approvedOrigins);
        } catch (e) {
          return err(`Refused: this address's own certificate could not be trusted (${firstLine((e as Error).message)}). Nothing was sent.`, 'BAD_REQUEST');
        }
      }
      // The fingerprint is part of what the owner approves: a different certificate is a
      // different approval, never a silent change.
      // Folded into the HASH, not the approved address (which stays a plain origin).
      const hashOrigin = pin ? `${origin}#cert-sha256=${pin.sha256}` : origin;
      const recipeSha = signInRecipeSha(rc.recipe, hashOrigin);
      const approvedAs = origin;
      // What the owner's page hashes: it recomputes sha256(canonicalJson(detail.recipe)) from
      // what it shows and never takes our hash, so detail.recipe must be EXACTLY the object
      // signInRecipeSha hashes (signin.ts).
      const shownRecipe = { type: 'sign_in', v: 1, origin: hashOrigin, recipe: rc.recipe };
      const vk = await this.api.ensureVaultKey();
      const refused = await approveStamp(this.deps(), {
        entryId, s, vaultKey: vk, recipe: shownRecipe,
        recipeSha, origin: approvedAs,
        summary: describeSignIn(rc.recipe, origin, '')
          + (pin ? ` This address uses its own certificate; trust only this one (fingerprint ${pin.sha256.slice(0, 16)}…).` : ''),
        purpose,
      });
      if (refused) {
        // Not approved (or approval revoked): no session for this address survives it, so a
        // later re-approval signs in afresh (round 2, F4).
        const gone = `${this.agentName}\u0001${entryId}\u0000${origin}\u0000`;
        SIGN_IN_SESSIONS.deleteWhere((k) => k.startsWith(gone));
        return refused;
      }
      signIn = { recipe: rc.recipe, origin, recipeSha, pin, approvedOrigins };
    } else if ((agentReq as { trust_certificate?: unknown } | undefined)?.trust_certificate !== undefined) {
      return err('Refused: trust_certificate is for a sign-in (request.sign_in). Nothing was sent.', 'BAD_REQUEST');
    }

    // Stored-only entries (a login, a password with no binding, a 2FA seed) are never sent
    // as they are. Without request.sign_in nothing here may use them.
    const storedOnlyShape = s.setup?.shape === 'website_login' || s.setup?.shape === 'two_factor'
      || (s.setup?.shape === 'password' && s.setup?.binding == null);
    if (storedOnlyShape && !signIn && !askBinding) {
      return err('Refused: this secret is stored only and is not sent by the broker. A login can be used with '
        + 'request.sign_in (the broker signs in for you), and a 2FA seed with vault_2fa_code. Nothing was sent.', 'STORED_ONLY');
    }

    // Recognise {ask:true} before either binding validator sees it. The approved list is
    // owner-sealed, and its version is checked even when no new approval is needed.
    let approvedPlacement: SendAs | undefined;
    if (askBinding) {
      const origin = agentReq?.origin ? normalizeOrigin(agentReq.origin) : null;
      if (!origin) return err('Refused: request.origin needs an https host and a valid port, without credentials, a path or an IPv6 literal. Nothing was sent.', 'BAD_REQUEST');
      if ((agentReq as { stamp?: unknown }).stamp !== undefined) {
        return err('Refused: request.stamp is for stamped keys, and this one is not. Nothing was sent.', 'BAD_REQUEST');
      }
      if (agentReq!.send_as !== undefined) {
        const checked = validateSendAs(agentReq!.send_as);
        if (!checked.ok) return err(`Refused: request.send_as: ${checked.reason}. Nothing was sent.`, 'BAD_REQUEST');
        approvedPlacement = checked.sendAs;
        // A conflicting agent header is refused BEFORE asking the owner.
        const headers = validateAgentHeaders(agentReq!.headers, approvedPlacement);
        if (!headers.ok) return err(`Refused: ${headers.field}: ${headers.reason}. Nothing was sent.`, 'BAD_REQUEST');
      }
      const vaultKey = await this.api.ensureVaultKey();
      const sealed = s as unknown as { policy_ciphertext?: string | null; policy_nonce?: string | null };
      const checked = readPolicy({
        ciphertext: sealed.policy_ciphertext, nonce: sealed.policy_nonce,
        vaultKey, entryId, kind: 'stamped',
      });
      if (!checked.ok) return err(`Refused: this key's settings could not be read (${checked.reason}). Nothing was sent.`, 'BAD_POLICY');
      if (checked.policy) {
        const problem = this.deps().state.acceptPolicy(checked.policy);
        if (problem) return err(`Refused: this key's settings could not be accepted (${problem}). Nothing was sent.`, 'BAD_POLICY');
      }
      if (approvedPlacement) {
        const refused = await approveStamp(this.deps(), {
          entryId, s, vaultKey, origin,
          recipe: placementRecipe(origin, approvedPlacement),
          recipeSha: placementSha(origin, approvedPlacement),
          summary: describePlacement(origin, approvedPlacement), purpose,
        });
        if (refused) return refused;
      } else {
        const approved = checked.policy?.stamped?.approved.filter((item) => item.origin === origin && item.placement) ?? [];
        const distinct = [...new Map(approved.map((item) => [item.recipe_sha256, item])).values()];
        if (distinct.length === 0) {
          return err(`Refused: this key has no approved way to be sent to ${origin} yet. Propose one with request.send_as {in:"header"|"query", name, template:"... {secret} ..."} — the owner approves it once. Nothing was sent.`, 'NEEDS_PLACEMENT');
        }
        if (distinct.length !== 1) {
          return err(`Refused: this key has several approved ways to be sent to ${origin}. Name one with request.send_as {in:"header"|"query", name, template:"... {secret} ..."}. Nothing was sent.`, 'NEEDS_PLACEMENT');
        }
        approvedPlacement = distinct[0].placement!;
      }
      // Use the same normalised address for execution as for approval, including 443.
      const address = new URL(origin);
      agentReq = {
        ...agentReq!, origin: {
          scheme: 'https', host: address.hostname, port: Number(address.port || '443'),
        },
      };
    }

    const hasV2Binding = !signIn && !askBinding && (s.setup?.binding as { v?: unknown } | undefined)?.v === 2;
    const partsPath = !signIn && !!s.setup && (hasV2Binding || s.setup.value_format === 'parts-1');
    const legacySinglePart = partsPath && !hasV2Binding && s.setup!.shape === 'api_key';
    let partsBinding: BindingV2 | undefined;
    if (partsPath && !legacySinglePart && !askBinding) {
      // validateBindingV2 reads a v1 binding as well (a signed set's {in:'stamp'} included).
      const checked = validateBindingV2(s.setup!.binding, s.setup!.shape as Shape, 'http');
      if (!checked.ok) {
        return err(`Refused: this entry's delivery setting is not one the broker accepts `
          + `(${checked.field}: ${checked.message}). Nothing was sent. The owner can set how the secret `
          + `is sent in the dashboard.`, 'BAD_BINDING');
      }
      // Only a v2 binding is a placement list; a v1 stamp (a signed set) stays on the stamp path.
      if (checked.binding.v === 2) partsBinding = checked.binding;
    }

    // The legacy definition builder needs a single binding. For v2 it only builds the
    // request image: performOperation receives the real placements separately and owns
    // all credential placement. A stamp still uses the existing stamp definition.
    // A sign-in sends the SESSION, placed as the approved recipe says; the password only
    // ever goes in the login request.
    const sessionBinding: CredentialBinding | null = signIn
      ? ('cookie' in signIn.recipe.send_session_as
        ? { in: 'header', name: 'Cookie', template: `${signIn.recipe.send_session_as.cookie}={secret}` }
        : { in: 'header', name: signIn.recipe.send_session_as.header,
          template: signIn.recipe.send_session_as.template.replace('{{session}}', '{secret}') })
      : null;
    const chosenBinding = approvedPlacement ?? sessionBinding;
    const bound = chosenBinding ? { ok: true as const, binding: chosenBinding } : bindingFromExecConfig(hasV2Binding && partsBinding
      ? {
        credential_binding: partsBinding.placements.length === 1 && partsBinding.placements[0].in === 'stamp'
          ? { in: 'stamp' }
          : { in: 'header', name: 'Authorization', template: 'Bearer {secret}' },
      }
      : coerceCfg(s.exec_config));
    if (!bound.ok) {
      return err(`Refused: this entry's delivery setting is not one the broker accepts `
        + `(${bound.field}: ${bound.reason}). Nothing was sent. The owner can set how the secret `
        + `is sent in the dashboard.`, 'BAD_BINDING');
    }
    const binding = bound.binding;

    // BUILD 2: a stamped key. The recipe is checked, and the owner's approval of this
    // (recipe, address) pair obtained, BEFORE the key is decrypted (spec §F29).
    let stampRecipe: Recipe | null = null;
    if (binding.in === 'stamp') {
      if (operationId) return err('Refused: a stamped key is used with request and request.stamp, not a signed operation.', 'BAD_REQUEST');
      const raw = (agentReq as { stamp?: unknown } | undefined)?.stamp;
      if (raw === undefined) {
        return err('Refused: this secret is stamped — it never travels, and each request carries a code computed from it. '
          + 'Describe how the service wants it in request.stamp (see the vault_call description). Nothing was sent.', 'BAD_REQUEST');
      }
      const rc = validateRecipe(raw);
      if (!rc.ok) return err(`Refused: request.stamp: ${rc.reason}. Nothing was sent.`, 'BAD_REQUEST');
      const o = agentReq!.origin;
      if (!o?.host || !o.scheme || !o.port) return err('request.origin needs scheme, host and port.');
      const vk = await this.api.ensureVaultKey();
      const refused = await approveStamp(this.deps(), {
        entryId, s, vaultKey: vk, recipe: rc.recipe, recipeSha: recipeSha256(rc.recipe),
        origin: originString({ scheme: o.scheme, host: o.host.toLowerCase(), port: o.port }),
        summary: describeRecipe(rc.recipe), purpose,
      });
      if (refused) return refused;
      stampRecipe = rc.recipe;
    } else if ((agentReq as { stamp?: unknown } | undefined)?.stamp !== undefined) {
      return err('Refused: request.stamp is for stamped keys, and this one is not. Nothing was sent.', 'BAD_REQUEST');
    }

    // The agent's own headers and body, checked before the key is decrypted. A refused
    // header refuses the call; it is never dropped and the rest sent, because the agent
    // would then be reading a reply to a request it did not make.
    let agentHeaders: Record<string, string> = {};
    if (agentReq) {
      const h = partsBinding
        ? checkAgentHeaders(agentReq.headers, partsBinding)
        : validateAgentHeaders(agentReq.headers, binding);
      if (!h.ok) return err(`Refused: ${h.field}: ${h.reason}. Nothing was sent.`, 'BAD_REQUEST');
      agentHeaders = h.headers;
    }

    const vaultKey = await this.api.ensureVaultKey();
    let def: NonNullable<ReturnType<typeof verifyOperationDefinition>["definition"]>;
    let label: string;
    let operationSlot: { definition: unknown; signature?: string } | undefined;
    if (operationId) {
      let catalogue: Record<string, { definition: unknown; signature?: string }> = {};
      try {
        const raw = s.operations as unknown;
        catalogue = (typeof raw === 'string' ? JSON.parse(raw) : (raw ?? {})) as typeof catalogue;
      } catch { return err("This entry's operation catalogue is not readable."); }
      operationSlot = catalogue?.[operationId];
      if (!operationSlot) {
        const known = Object.keys(catalogue || {});
        return err(`Entry has no operation "${operationId}".`
          + (known.length ? ` Available: ${known.join(', ')}.` : ' It defines none.'));
      }
      // Read only the proposed destination here. The signature needs the value, so it
      // is verified after approval and before execution; its destination must not change.
      def = operationSlot.definition as NonNullable<ReturnType<typeof verifyOperationDefinition>['definition']>;
      if (!def?.origin || typeof def.origin.host !== 'string' || !def.origin.host
          || typeof def.origin.scheme !== 'string' || !def.origin.scheme
          || typeof def.origin.port !== 'number' || !def.origin.port
          || !def.route || typeof def.route.method !== 'string' || !def.route.method
          || typeof def.route.path !== 'string') {
        return err("Refused: this entry's operation definition is not readable.");
      }
      label = operationId;
    } else {
      const r = agentReq!;
      if (!r?.origin?.host || !r.origin.scheme || !r.origin.port) {
        return err('request.origin needs scheme, host and port.');
      }
      def = definitionFromAgentRequest({ ...r, headers: agentHeaders }, binding);
      label = `${def.route.method} ${originString(r.origin)}${r.path || '/'}`;
    }

    // The same question again on the request AS IT WILL BE SENT: a signed operation names its
    // own address, and the query the agent gave is part of the path by now.
    if (!recipe) {
      const hit = this.recipes.loose(def.origin, def.route.method, def.route.path);
      if (hit) return err(NEW_KEY_POINTER(hit.service_name), 'USE_NEW_KEY');
    } else if (this.recipes.exact(def.origin, def.route.method, def.route.path) !== recipe) {
      return err('Refused: this request no longer matches the key-making address. Nothing was sent.', 'NO_RECIPE');
    }

    const bodyHash = agentReq?.body !== undefined
      ? createHash('sha256').update(JSON.stringify(agentReq.body)).digest('hex')
      : undefined;
    const originStr = originString(def.origin);
    const { isNew } = recordDestination(entryId, originStr, undefined, purpose);
    const known = Array.isArray(s.setup?.known_addresses) ? s.setup.known_addresses : [];
    const firstSighting = isNew && !known.includes(originStr);

    const isTier2 = String(s.access_tier ?? '1') === '2';
    const destination = isTier2
      ? { origin: originStr, method: def.route.method, path: def.route.path, body_sha256: bodyHash }
      : {};
    let lockedCheck: {
      entry_id: string; first_sighting: boolean; request_id?: string;
      detail_ciphertext?: string; detail_nonce?: string; match_mac?: string; origin_mac?: string;
    } | undefined;
    if (s.vault_locked === true) {
      lockedCheck = { entry_id: entryId, first_sighting: firstSighting };
      if (isTier2) {
        const requestId = newRequestId();
        try {
          const detail = sealT2Detail(vaultKey, s.agent_id ?? '', requestId, {
            name: s.name ?? '', kind: 'web', origin: originStr,
            method: def.route.method, path: def.route.path, reason: purpose.slice(0, 200),
          });
          if (!detail.ok) {
            return err('Refused: this approval request could not be sealed. Nothing was sent.', 'BAD_REQUEST');
          }
          lockedCheck = {
            ...lockedCheck, request_id: requestId,
            detail_ciphertext: detail.ciphertext, detail_nonce: detail.nonce,
            match_mac: t2MatchMac(vaultKey, {
              kind: 'web', origin: originStr, method: def.route.method,
              path: def.route.path, entry_id: entryId,
            }, 2),
            origin_mac: t2OriginMac(vaultKey, { origin: originStr, entry_id: entryId }),
          };
        } catch {
          return err('Refused: this approval request could not be sealed. Nothing was sent.', 'BAD_REQUEST');
        }
      }
    }

    // The purpose goes with the destination: tier 2 only, where the owner is approving
    // this one call and needs to read why. Tier 1 sends neither (network-shape decision).
    const verdict = await this.api.checkOperation((lockedCheck ?? {
      entry_id: entryId, purpose: isTier2 ? purpose.slice(0, 200) : '', first_sighting: firstSighting,
      ...destination,
    }) as never);

    if (!verdict.allowed) {
      rec.approval = 'asked';
      const outcome = verdict.request_id
        ? await this.api.waitForTier2Outcome(verdict.request_id)
        : null;
      if (outcome !== 'approved') {
        rec.approval = 'not_approved';
        const why = outcome ? approvalNotGivenMessage(outcome, `"${s.name}"`)
          : `${verdict.message ?? 'This call needs owner approval.'} Nothing was sent.`;
        // The address as the agent (or the signed definition) gave it, before any part is
        // placed in it: the value has not been fetched, so there is nothing in it to scrub.
        return err(`${why}\n\nThe owner sees exactly: ${def.route.method} ${originStr}${def.route.path}`);
      }
      const second = await this.api.checkOperation((lockedCheck ?? {
        entry_id: entryId, purpose: purpose.slice(0, 200), origin: originStr,
        method: def.route.method, path: def.route.path, body_sha256: bodyHash,
      }) as never);
      if (!second.allowed) {
        rec.approval = 'not_approved';
        return err(`${second.message ?? 'This call needs owner approval.'}\n\n`
          + `Nothing was sent. The owner sees exactly: ${def.route.method} ${originStr}${def.route.path}`);
      }
      grant = second.fetch_grant;
      verdict.tier = second.tier;
      rec.approval = 'approved';
    } else {
      grant = verdict.fetch_grant;
    }

    if (!haveValue) {
      const full = await this.api.getSecret(entryId, grant);
      if (String(full.rev) !== String(s.rev)) {
        return err('Refused: this secret changed while the call was being approved. Nothing was sent. Try again.', 'CHANGED');
      }
      s = full;
      haveValue = true;
    }
    const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
    try {
      let secret = new TextDecoder().decode(bytes);
      let parts: Record<string, string> | undefined;
      let login: { username?: string; password: string; valueSha: string } | null = null;
      if (signIn) {
        const value = readValue(secret, 'parts-1', 'http', s.setup!.shape as Shape);
        if (!value.ok || !value.parts.password) {
          return err('Refused: this login could not be read (it needs a password). Nothing was sent.', 'BAD_VALUE');
        }
        login = { username: value.parts.username || undefined, password: value.parts.password,
          valueSha: createHash('sha256').update(secret).digest('hex') };
        // Scrubbed from everything shown, like any part; the session is added once known.
        parts = { password: value.parts.password };
        secret = '';
      }
      if (partsPath) {
        const value = readValue(secret, s.setup!.value_format, 'http', s.setup!.shape as Shape);
        if (!value.ok) {
          return err(`Refused: this key could not be read (${value.reason}). Nothing was sent.`, 'BAD_VALUE');
        }
        parts = value.parts;
        if (askBinding && Object.keys(parts).length !== 1) {
          return err('Refused: a key set to ask on first use must have a single part. Nothing was sent.', 'BAD_VALUE');
        }
        if (operationId && Object.keys(parts).length !== 1) {
          return err('Refused: signed operations work with single-part keys only. Nothing was sent.', 'BAD_REQUEST');
        }
        // What the stamp code reads: X's four values, or {"id","secret"} (AWS SigV4, HMAC recipes).
        secret = stampRecipe && s.setup!.shape === 'signed_set'
          ? JSON.stringify(oauth1FromParts(parts))
          : stampRecipe && s.setup!.shape === 'key_id'
            ? JSON.stringify({ id: parts.id, secret: parts.secret })
            : Object.values(parts)[0];
      }
      const values = parts ? Object.values(parts) : [secret];
      if (values.some((value) => looksLikePrivateKey(value))) {
        return err('Refused: this entry holds a private key, which is never sent to a web service. '
          + 'Nothing was sent. If it is an SSH key, the owner can set it to SSH (with the servers '
          + 'it may sign in to) in the dashboard, and then use vault_ssh_exec.', 'WRONG_KIND');
      }
      if (!stampRecipe && values.some((value) => looksLikeOAuth1Value(value))) {
        return err('Refused: this entry holds OAuth 1.0a keys (X and others: an API key and secret, an access '
          + 'token and secret), which are never sent as they are: the service would refuse them, and both '
          + 'secrets would go with them. Nothing was sent. The owner can set this entry to "Signed requests" '
          + 'in the dashboard; then call again with request.stamp {"builtin": "oauth1"}.', 'WRONG_KIND');
      }

      if (operationSlot) {
        const operationKey = parts ? new TextEncoder().encode(secret) : bytes;
        let verified: ReturnType<typeof verifyOperationDefinition>;
        try {
          verified = verifyOperationDefinition(entryId, operationSlot.definition, operationSlot.signature, operationKey, operationId);
        } finally {
          if (operationKey !== bytes) operationKey.fill(0);
        }
        if (!verified.ok || !verified.definition) return err(`Refused: ${verified.reason}`);
        if (originString(verified.definition.origin) !== originStr
            || verified.definition.route.method !== def.route.method
            || verified.definition.route.path !== def.route.path) {
          return err('Refused: this secret changed while the call was being approved. Nothing was sent. Try again.', 'CHANGED');
        }
        const argCheck = validateArguments(verified.definition, callArgs);
        if (!argCheck.ok) return err(`Refused: ${argCheck.reason}`);
        def = verified.definition;
      } else {
        // These checks need the value. Approval now precedes them, but a refusal still
        // sends nothing, and the credential placement rules are unchanged.
        if (!partsBinding) {
          const problem = pathBindingProblem(binding, secret, def.route.path);
          if (problem) return err(`Refused: ${problem} Nothing was sent.`, 'BAD_REQUEST');
        } else {
          for (const placement of partsBinding.placements) {
            if (placement.in !== 'path') continue;
            const match = /\{part:([a-z][a-z0-9_]{0,31})\}/.exec(placement.template);
            if (!match) continue;
            const pathBinding = { ...placement, template: placement.template.replace(match[0], '{secret}') };
            const pathBound = bindingFromExecConfig({ credential_binding: pathBinding });
            if (!pathBound.ok) {
              return err(`Refused: this entry's delivery setting is not one the broker accepts `
                + `(${pathBound.field}: ${pathBound.reason}). Nothing was sent. The owner can set how the secret `
                + `is sent in the dashboard.`, 'BAD_BINDING');
            }
            const problem = pathBindingProblem(pathBound.binding, parts![match[1]], def.route.path);
            if (problem) return err(`Refused: ${problem} Nothing was sent.`, 'BAD_REQUEST');
          }
        }
      }

      // The address the agent asked for, before the key is added — scrubbed anyway, so a
      // key that somehow reached the path never reaches the log.
      rec.method = def.route.method;
      // Every part, longest first: an agent may know a key's non-secret half (an id, a
      // username) and put it in its own path; nothing the broker shows repeats a part.
      const shownForms = parts
        ? (partsBinding ? secretFormsAll(partsBinding, parts)
          : Object.values(parts).flatMap((value) => secretForms(BEARER, value)))
        : [];
      const scrubShown = (text: string): string => parts
        ? scrubParts(text, shownForms)
        : String(scrubSecret(text, secret));
      rec.address = scrubShown(`${originString(def.origin)}${def.route.path}`);
      rec.body_sha256 = bodyHash;

      let approvedOrigins: string[] = [];
      try {
        const raw = s.allowed_private_origins as unknown;
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (Array.isArray(parsed)) approvedOrigins = parsed.filter((x): x is string => typeof x === 'string');
      } catch { approvedOrigins = []; }

      let noticeForAgent = '';
      if (firstSighting) {
        const notice = newDestinationNotice(
          s.name ?? entryId, originStr, def.route.method, scrubShown(def.route.path), verdict.tier,
          !operationId, verdict.emailed === true,
        );
        emitToStderr(notice);
        noticeForAgent = notice.toolNote;
      }

      // A legacy stamped entry may hold {"id", "secret"}, or OAuth 1.0a's four values;
      // only the secrets are MAC keys. Parts-format entries also scrub the ids below.
      let stamped: StampedValue | null = null;
      if (stampRecipe) {
        try { stamped = parseStampedValue(secret, stampRecipe); } catch (e) {
          return err(`Refused: ${(e as Error).message}. Nothing was sent. The owner can fix it in the dashboard.`, 'WRONG_KIND');
        }
      }
      rec.outcome = 'sending';
      if (signIn && login) {
        const si = signIn; const lg = login;
        const key = sessionKey({ entryId: `${this.agentName}\u0001${entryId}`, origin: si.origin,
          recipeSha: si.recipeSha, valueSha: lg.valueSha, pin: si.pin?.sha256 });
        // Same agent, entry AND address: another address's session is not stale (round 1, F5).
        const prefix = `${this.agentName}\u0001${entryId}\u0000${si.origin}\u0000`;
        // A changed password, recipe or certificate is a different key: drop the old session
        // now, on this call, not at the next restart.
        SIGN_IN_SESSIONS.deleteWhere((k) => k.startsWith(prefix) && k !== key);
        const internal = si.pin ? { certPin: si.pin } : undefined;
        const doLogin = (): Promise<string> => SIGN_IN_SESSIONS.exclusive(prefix, async () => {
          const s2 = await doLoginOnce();
          SIGN_IN_SESSIONS.remember(prefix, s2);
          return s2;
        });
        const doLoginOnce = async (): Promise<string> => {
          let replyHeaders: Record<string, string | string[] | undefined> = {};
          const rendered = renderLoginBody(si.recipe, lg);
          const loginDef = {
            op: 'agent.sign_in', origin: def.origin,
            route: { method: si.recipe.login.method, path: si.recipe.login.path },
            credential_binding: { in: 'stamp', name: '', template: '' },
            static_headers: { 'content-type': rendered.contentType },
            response: undefined, redirects: 'deny', limits: def.limits,
          } as unknown as typeof def;
          // The password is already in the body; the "stamp" adds nothing and names the
          // password (and its spellings) for scrubbing.
          const r = await performOperation(loginDef, rendered.body, lg.password, si.approvedOrigins,
            () => ({ headers: {}, query: [], stamp: lg.password, scrub: [] }), undefined,
            { ...(internal ?? {}), onResponseHeaders: (h) => { replyHeaders = h; } });
          if (!r.ok || !r.status || r.status < 200 || r.status >= 300) {
            throw new Error(`the service refused the sign-in${r.status ? ` (HTTP ${r.status})` : ''}`
              + (r.error && !r.status ? `: ${r.error}` : ''));
          }
          const body = typeof r.body === 'string' ? r.body : JSON.stringify(r.body ?? '');
          const session = extractSession(si.recipe, { headers: replyHeaders, body });
          if (!session) throw new Error('the sign-in answered, but not with a session where the approved sign-in says to look');
          return session;
        };
        const agentBody = typeof agentReq?.body === 'string' ? agentReq.body
          : ((agentReq?.body ?? {}) as Record<string, unknown>);
        let session: string;
        const signInFailed = (e: unknown) => err(scrubParts(`Signing in to ${si.origin} failed: ${firstLine((e as Error).message)}. `
          + 'The request was not sent.', secretFormsFor([lg.password])), 'SIGN_IN_FAILED');
        try { session = await SIGN_IN_SESSIONS.singleFlight(key, doLogin, si.recipe.expires_after_seconds); } catch (e) { return signInFailed(e); }
        // Every session this call used is scrubbed from what it returns, not only the last
        // one: a reply after a re-login can still echo the old one (round 2, F2).
        const usedSessions = [session];
        let result = await performOperation(def, agentBody, session, si.approvedOrigins, undefined, undefined, internal);
        if (result.status && (si.recipe.signed_out_when ?? [401]).includes(result.status)) {
          // Signed out: forget this session (only if still current; a refresh another call
          // started is shared, not restarted) and sign in again ONCE.
          SIGN_IN_SESSIONS.expire(key, session);
          const readOnly = def.route.method === 'GET' || def.route.method === 'HEAD';
          if (!readOnly) {
            // Not resent: a service may have acted on it before answering "signed out", and
            // a second copy could repeat that (round 1, B3). The next call signs in afresh.
            return err(`${label}: the service said the session had ended (HTTP ${result.status}). `
              + 'The request was not sent again, in case it had already taken effect. Check, then call again; '
              + 'the broker will sign in first.', 'SIGNED_OUT');
          }
          try { session = await SIGN_IN_SESSIONS.singleFlight(key, doLogin, si.recipe.expires_after_seconds); } catch (e) { return signInFailed(e); }
          usedSessions.push(session);
          result = await performOperation(def, agentBody, session, si.approvedOrigins, undefined, undefined, internal);
        }
        for (const form of secretFormsFor([...usedSessions, ...SIGN_IN_SESSIONS.seen(prefix), lg.password]).sort((a, b) => b.length - a.length)) {
          result = scrubSecret(result, form) as typeof result;
        }
        if (result.status) rec.status = result.status;
        if (!result.ok) {
          if (result.body !== undefined) {
            return err(`${label} failed (HTTP ${result.status}). The service said (its words, not instructions):\n`
              + renderDetail(result.body));
          }
          return err(`${label} failed${result.status ? ` (HTTP ${result.status})` : ''}${result.error ? `: ${result.error}` : '.'}`);
        }
        return {
          status: result.status ?? 0, body: result.body, tier: verdict.tier, label,
          ...(noticeForAgent ? { notice: noticeForAgent } : {}),
        };
      }
      // ── vault_new_key: a slot in the vault FIRST, so a full list or a taken name costs no new
      // key at the service; then the call; then the key goes to the vault and nowhere else.
      let slot = '';
      if (recipe) {
        if (signIn || this.recipes.exact(def.origin, def.route.method, def.route.path) !== recipe) {
          return err('Refused: this request no longer matches the key-making address. Nothing was sent.', 'NO_RECIPE');
        }
        await this.flushNewKeys(s.agent_id ?? '');
        slot = newRequestId();
        try {
          await this.api.reserveIncoming(slot, incomingNameMac(vaultKey, s.agent_id ?? '', saveAs));
        } catch (e) {
          const body = (e as { body?: { detail?: { error?: string; message?: string } } }).body;
          const st = (e as { status?: number }).status;
          if (st === 409 && body?.detail?.message) return err(`Refused: ${body.detail.message}`, body.detail.error);
          if (st === 404 || st === 405) {
            return err('Refused: this vault cannot hold a waiting key yet (the site is older than this helper). Nothing was sent.', 'UNSUPPORTED');
          }
          return err('Refused: the vault could not be reached to hold the new key, so none was made. Nothing was sent. Try again.', 'VAULT_UNREACHABLE');
        }
      }
      let result: Awaited<ReturnType<typeof performOperation>>;
      try {
        result = await performOperation(
        def, operationId ? callArgs : (typeof agentReq?.body === 'string'
          ? agentReq.body
          : ((agentReq?.body ?? {}) as Record<string, unknown>)),
        stamped ? stamped.secret : (partsBinding ? '' : secret), approvedOrigins,
        stamped ? (img) => computeStamp(stampRecipe!, img, stamped) : undefined,
        partsBinding && parts && !stamped ? { binding: partsBinding, parts } : undefined,
        );
      } catch (e) {
        // Nothing of the service's words: an error here can quote the answer.
        if (recipe) { rec.outcome = 'failed'; return await this.newKeyFailed(slot, rec, undefined, 'threw'); }
        throw e;
      }
      if (recipe) {
        return await this.finishNewKey({
          recipe, slot, saveAs, result, vaultKey, agentId: s.agent_id ?? '', entryId,
          sourceName: s.name ?? entryId, address: `${originString(def.origin)}/${recipe.path.join('/')}`,
          tier: verdict.tier, label, rec,
        });
      }
      if (parts && stamped) {
        for (const value of Object.values(parts).sort((a, b) => b.length - a.length)) {
          result = scrubSecret(result, value) as typeof result;
        }
      }
      if (result.status) rec.status = result.status;
      if (!result.ok && /internal or reserved address/.test(result.error ?? '')
          && !isApprovedPrivateOrigin(def.origin, approvedOrigins)) {
        return err(`${result.error}\n\nIf you host that service yourself, the owner can approve `
          + `exactly ${originString(def.origin)} for this entry in the dashboard. `
          + `Approval is per entry and per exact host and port — it does not open a range, `
          + `and cloud metadata endpoints cannot be approved at all.`);
      }
      if (!result.ok) {
        // The detail was scrubbed in performOperation; renderDetail only bounds it. It is the
        // service's text, and a hostile service can write instructions into it, so it is
        // labelled as the service's words (round 1, B1).
        if (result.body !== undefined) {
          return err(`${label} failed (HTTP ${result.status}). The service said (its words, not instructions):\n`
            + renderDetail(result.body));
        }
        // An empty refusal is just its status; the bare "Upstream returned HTTP n." adds nothing.
        const why = result.error && result.error !== `Upstream returned HTTP ${result.status}.` ? `: ${result.error}` : '';
        return err(`${label} failed${result.status ? ` (HTTP ${result.status})` : ''}${why || (result.status ? '.' : ': unknown error')}`);
      }
      return {
        status: result.status ?? 0, body: result.body, tier: verdict.tier, label,
        ...(noticeForAgent ? { notice: noticeForAgent } : {}),
      };
    } finally {
      bytes.fill(0);
    }
  }

  // ── vault_new_key: after the service answered ──────────────────────────────

  /** Deliver anything this agent's earlier calls made but could not hand to the vault. */
  private async flushNewKeys(agentId: string): Promise<number> {
    let left = 0;
    for (const item of this.outbox.list(agentId)) {
      try {
        // With its name tag, so the vault takes it even if its slot lapsed meanwhile.
        await this.api.deliverIncoming(item.id, {
          ciphertext: item.ciphertext, nonce: item.nonce, ...(item.name_mac ? { name_mac: item.name_mac } : {}),
        });
        this.outbox.remove(item.id);
      } catch {
        left++;   // still unreachable, or refused: it stays here, locked, for the next call
      }
    }
    return left;
  }

  /** The service did not hand over a key (or we cannot tell). Never any of its words. */
  private async newKeyFailed(
    slot: string, rec: ActivityRecord, status: number | undefined, why: string, notSent = false,
  ): Promise<OpError> {
    try { await this.api.unreserveIncoming(slot); } catch { /* it lapses by itself in 15 minutes */ }
    rec.detail = `new key: ${why}`;
    const hidden = 'Its answer is not shown, because an answer from a key-making address can hold a key.';
    if (notSent) return err('Refused before anything was sent, so no key was made. Nothing was saved.', 'NEW_KEY_FAILED');
    if (status !== undefined && status >= 200 && status < 300) {
      return err(`The service answered HTTP ${status}, but no new key could be read from its answer. Nothing was saved. `
        + 'If a key was made there, nobody holds it: tell the owner to delete it at the service.', 'NEW_KEY_FAILED');
    }
    if (status !== undefined && status >= 400 && status < 500) {
      return err(`No key was made: the service refused (HTTP ${status}). Nothing was saved. ${hidden}`, 'NEW_KEY_FAILED');
    }
    // No answer at all (the connection dropped, a timeout), a redirect, or a 5xx: the request
    // may have been carried out before the answer was lost. Never "no key was made" (review r1 F3).
    return err(`${status ? `The service answered HTTP ${status}` : 'No answer came back from the service'}, so it is NOT KNOWN `
      + 'whether a key was made. Nothing was saved, and if one was made nobody holds it. Do not simply try again: '
      + "first look at the service's list of keys (a GET with vault_call is allowed) and tell the owner about any key "
      + `with the name you asked for, so they can delete it there. ${hidden}`, 'NEW_KEY_UNKNOWN');
  }

  private async finishNewKey(a: {
    recipe: NewKeyRecipe; slot: string; saveAs: string; result: { ok: boolean; status?: number; body?: unknown };
    vaultKey: Uint8Array; agentId: string; entryId: string; sourceName: string; address: string;
    tier: string; label: string; rec: ActivityRecord;
  }): Promise<{ status: number; body: unknown; tier: string; label: string; notice?: string } | OpError> {
    const { recipe, slot, result, rec } = a;
    if (result.status) rec.status = result.status;
    if (!result.ok || !result.status || result.status < 200 || result.status > 299) {
      // performOperation's own refusals (a blocked address, a bad placement) say so and send nothing.
      const notSent = !result.status && /^Refused\b|Nothing was sent/.test(String((result as { error?: string }).error ?? ''));
      return this.newKeyFailed(slot, rec, result.status, result.status ? 'service refused' : 'no answer', notSent);
    }
    let body = result.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = undefined; } }
    const got = readNewKey(recipe, body);
    if (!got.ok) return this.newKeyFailed(slot, rec, result.status, 'no key in the answer');

    const forms = newKeyForms(got.value);
    const sealed = sealIncoming(a.vaultKey, a.agentId, slot, {
      name: a.saveAs, service: recipe.service, service_name: recipe.service_name, recipe: recipe.id,
      value: got.value, info: got.info, source_entry: a.entryId, source_name: a.sourceName,
      address: a.address, made_at: new Date().toISOString(),
    });
    if (!sealed.ok) return this.newKeyFailed(slot, rec, result.status, 'could not be locked');
    const blob = { ciphertext: sealed.ciphertext, nonce: sealed.nonce };
    const nameMac = incomingNameMac(a.vaultKey, a.agentId, a.saveAs);

    // On disk (locked) BEFORE the first try, so a crash between the service's answer and the
    // vault's cannot lose the only copy.
    let kept = true;
    try { this.outbox.put({ id: slot, agent_id: a.agentId, name_mac: nameMac, ...blob, made_at: new Date().toISOString() }); }
    catch { kept = false; }
    let delivered = false;
    for (const wait of [0, 500, 1500]) {
      if (wait) await new Promise((r) => setTimeout(r, wait));
      try { await this.api.deliverIncoming(slot, blob); delivered = true; break; } catch { /* again */ }
    }
    if (delivered && kept) this.outbox.remove(slot);

    // readNewKey already dropped any field that carries the key; checked once more, value by
    // value (never by rewriting JSON text, which a digits-only key could break: review r1 F2).
    const info: Record<string, string | number | boolean> = {};
    for (const [k, v] of Object.entries(got.info)) {
      if (!carriesKey(String(v), got.value, forms) && !carriesKey(k, got.value, forms)) info[k] = v;
    }
    rec.extra = { ...(rec.extra ?? {}), saved: delivered };
    const where = `${recipe.service_name} made a new key`;
    const notice = delivered
      ? `${where}. It went straight into the owner's vault as "${carriesKey(a.saveAs, got.value, forms) ? 'the name you gave' : a.saveAs}" and is WAITING FOR THE OWNER: `
        + 'no agent can use it until the owner saves it (passkey) and sets it up. You were not given the key and no tool will return it. '
        + 'Tell the owner a new key is waiting in the vault under Needs you.'
      : kept
        ? `${where}, but it is NOT in the vault yet: the vault could not be reached. The helper is holding it, locked, `
          + 'and will hand it over on your next vault call. You were not given the key. Do not make another one.'
        : `${where}, but it could not be saved and the helper could not keep it. Nobody holds it: delete it at the service `
          + '(its id is below) and try again.';
    return {
      status: result.status, body: { new_key: delivered ? 'waiting for the owner' : kept ? 'made, not saved yet' : 'lost', ...info },
      tier: a.tier, label: a.label, notice,
    };
  }

  // ── ssh_agent_open / ssh_agent_close ───────────────────────────────────────
  /**
   * Hold the private key and answer signature requests on a socket.
   *
   * This is the shape that lets a brokered key be USED without being handed over, and it
   * is the only reason `vault_ssh_exec` can keep running in the agent's process: ssh
   * itself never sees a private key, it asks an agent to sign.
   *
   * THE SOCKET CANNOT LIVE IN /tmp. `startAgent`'s default is `mkdtempSync(os.tmpdir())`,
   * and the unit sets `PrivateTmp=yes`, so that directory exists only inside the broker's
   * mount namespace — the agent would not find the socket at all. It goes under the
   * RuntimeDirectory instead, in a per-session directory with a random name.
   *
   * Legacy sessions still allow any same-uid process that learns the socket path to ask
   * for signatures. Pinned sessions additionally require a verified session-bind from
   * the approved server; knowing their socket path is not enough to sign in elsewhere.
   */
  async sshAgentOpen(args: {
    entryId: string; purpose: string; op: BrokeredOp; ttlSeconds?: number;
    /** Guided setup only (never from an agent): which half of an admin key to offer. */
    offer?: 'cert' | 'plain';
  }): Promise<{
    session_id: string; socket_path: string; public_key_path: string; fingerprint: string;
    audited_host: string; known_hosts_path?: string; pinned_host_key?: string;
  } | OpError> {
    const rec: ActivityRecord = {
      kind: args.op?.kind === 'git' ? 'git' : 'ssh', outcome: 'refused', agent: this.agentName, entry_id: args.entryId,
      reason: args.purpose, address: `ssh://${String(args.op?.destination ?? '')}`,
      extra: {
        op: String(args.op?.kind ?? ''),
        // push / fetch / … for a git session, so the owner's log tells them apart (round 1, F6).
        ...(args.op?.kind === 'git' && typeof (args.op as { subcommand?: unknown }).subcommand === 'string'
          && ['push', 'pull', 'fetch', 'clone', 'ls-remote'].includes((args.op as { subcommand: string }).subcommand)
          ? { git: (args.op as { subcommand: string }).subcommand } : {}),
      },
    };
    try {
      const r = await this.sshAgentOpenInner(args, rec);
      finish(rec, r);
      if (!('error' in r)) rec.outcome = 'opened';
      return r;
    } catch (e) {
      rec.outcome = 'error'; rec.detail = firstLine((e as Error).message);
      throw e;
    } finally { this.record(rec); }
  }

  private async sshAgentOpenInner(args: {
    entryId: string; purpose: string; op: BrokeredOp; ttlSeconds?: number; offer?: 'cert' | 'plain';
  }, rec: ActivityRecord): Promise<{
    session_id: string; socket_path: string; public_key_path: string; fingerprint: string;
    audited_host: string; known_hosts_path?: string; pinned_host_key?: string;
  } | OpError> {
    const { entryId, purpose, op } = args;
    const ttlSeconds = args.ttlSeconds ?? 300;

    // Checked BEFORE the entry is fetched, so hitting the ceiling does not spend an
    // access-log row or a tier-2 gate on a request that was never going to open.
    if (this.ssh.size >= BrokerOps.MAX_SSH_SESSIONS) {
      return err(
        `This agent already has ${this.ssh.size} signing sessions open, which is the limit. `
        + `Close one with ssh_agent_close, or wait for it to expire.`,
        'TOO_MANY_SESSIONS',
      );
    }

    let s;
    try {
      s = await this.api.getSecret(entryId);
    } catch (e) {
      if ((e as { code?: string }).code === ADMIN_ACCESS_REQUIRED) {
        rec.approval = 'not_approved';
        return err((e as Error).message, ADMIN_ACCESS_REQUIRED);
      }
      throw e;
    }
    rec.key = s.name;
    rec.tier = String(s.access_tier ?? '1');
    if (!modeAllowsSshBroker(s.entry_mode)) {
      return err(wrongModeMessage(s.entry_mode, 'ssh'), 'WRONG_MODE');
    }
    // Admin access (D7): the session may not outlive the owner's approval. No end time from a
    // server that says this is an admin key = no session.
    let adminUntilMs: number | undefined;
    if (s.admin_access === true) {
      adminUntilMs = Date.parse(String(s.admin_until ?? ''));
      if (!Number.isFinite(adminUntilMs) || adminUntilMs <= Date.now()) {
        return err(adminAccessRequiredMessage(s.name ? `"${s.name}"` : undefined), ADMIN_ACCESS_REQUIRED);
      }
    }

    let auditedHost: string;
    let vaultKey: Uint8Array | undefined;
    let pin: { target: NonNullable<ReturnType<typeof normalizeSshTarget>>; hostKey: string } | undefined;
    const setup = s.setup as unknown as { ask?: unknown; delivery?: unknown } | undefined;
    // This must precede the legacy allowlist check, which refuses an empty ssh_hosts.
    // Only the sealed setup can opt an entry into first-use approval.
    if (setup?.ask === true && setup.delivery === 'ssh') {
      if (op?.kind !== 'ssh' && op?.kind !== 'git') {
        return err('Refused: SSH keys set to ask on first use support SSH and git, not rsync.', 'BAD_REQUEST');
      }
      const target = normalizeSshTarget(op.destination);
      if (!target) return err('Refused: give an SSH destination as user@host[:port].', 'BAD_REQUEST');
      // The command runs op.destination as written, so it must already be the approved form:
      // 'u@Host.', 'u@h:000022' would be approved as one thing and run as another (review 13 r2 F1).
      const canonical = `${target.user}@${target.host}${target.port === 22 ? '' : ':' + target.port}`;
      if (op.destination !== canonical && op.destination !== `${target.user}@${target.host}:${target.port}`) {
        return err(`Refused: write the SSH destination as ${canonical}.`, 'BAD_REQUEST');
      }
      if (op.kind === 'git') {
        const urls = (op as unknown as { urls?: unknown }).urls;
        if (!Array.isArray(urls) || urls.length === 0) {
          return err('Refused: git needs SSH URLs for the approved user, host and port.', 'HOST_NOT_ALLOWED');
        }
        for (const url of urls) {
          if (typeof url !== 'string') return err('Refused: every git URL must use the approved SSH target.', 'HOST_NOT_ALLOWED');
          const parsed = parseGitSshUrl(url);
          const gitTarget = parsed.ok && parsed.user
            ? normalizeSshTarget(`${parsed.user}@${parsed.host}`, parsed.port ?? 22)
            : null;
          if (!gitTarget || gitTarget.user !== target.user || gitTarget.host !== target.host || gitTarget.port !== target.port) {
            return err('Refused: every git URL must use the same user, host and port as the SSH destination.', 'HOST_NOT_ALLOWED');
          }
        }
      }
      auditedHost = `${target.user}@${target.host}:${target.port}`;
      rec.address = `ssh://${auditedHost}`;
      vaultKey = await this.api.ensureVaultKey();
      const sealed = s as unknown as { policy_ciphertext?: string | null; policy_nonce?: string | null };
      const checked = readPolicy({
        ciphertext: sealed.policy_ciphertext, nonce: sealed.policy_nonce,
        vaultKey, entryId, kind: 'stamped',
      });
      if (!checked.ok) return err(`Refused: this key's settings could not be read (${checked.reason}).`, 'BAD_POLICY');
      if (checked.policy) {
        const problem = this.deps().state.acceptPolicy(checked.policy);
        if (problem) return err(`Refused: this key's settings could not be accepted (${problem}).`, 'BAD_POLICY');
      }
      const matching = checked.policy?.stamped?.approved.filter((item) =>
        item.ssh?.user === target.user && item.ssh.host === target.host && item.ssh.port === target.port) ?? [];
      let scanned: string | null;
      try { scanned = await this.scanCached(target); } catch { scanned = null; }
      if (!scanned || !isSshHostKey(scanned)) {
        return err('Refused: could not read this server\'s identity. No signing session was opened.', 'HOST_KEY_UNREADABLE');
      }
      scanned = sshHostRecipe(target, scanned).host_key;
      // Conflicting pins fail closed: an unpinned address cannot override a pinned one.
      const changed = matching.find((item) => item.ssh?.host_key && item.ssh.host_key !== scanned);
      if (changed?.ssh?.host_key) {
        return err(`Refused: this server's identity changed since you approved it. `
          + `Approved identity ${hostFingerprint(changed.ssh.host_key)}; current identity ${hostFingerprint(scanned)}. `
          + 'The owner can remove this server on the secret\'s page in the vault; the next connection then asks to approve the new identity. No signing session was opened.', 'HOST_KEY_CHANGED');
      }
      const recipeSha = sshHostSha(target, scanned);
      const approved = matching.some((item) => item.ssh?.host_key === scanned && item.recipe_sha256 === recipeSha);
      if (!approved) {
        rec.approval = 'asked';
        // approveStamp's existing lookup is origin-based. SSH approvals are checked above;
        // call it only to ask, with the exact recipe the owner's page hashes.
        const refused = await approveStamp(this.deps(), {
          entryId, s, vaultKey, origin: `ssh://${auditedHost}`,
          recipe: sshHostRecipe(target, scanned), recipeSha,
          summary: describeSshHost(target, scanned), purpose,
        });
        if (refused) {
          rec.approval = 'not_approved';
          return refused;
        }
        rec.approval = 'approved';
      } else {
        rec.approval = 'none';
      }
      pin = { target, hostKey: scanned };
    } else {
      // Legacy entries keep their existing allowlist behaviour, without a key scan or pin.
      let allowedHosts: string[] = [];
      const execCfg = coerceCfg(s.exec_config);
      if (Array.isArray((execCfg as { ssh_hosts?: unknown }).ssh_hosts)) {
        allowedHosts = ((execCfg as { ssh_hosts: unknown[] }).ssh_hosts).map(String);
      }
      const check = checkSshDestination(op, allowedHosts);
      if (!check.ok) return err(check.error, 'HOST_NOT_ALLOWED');
      auditedHost = check.auditedHost;
      rec.address = `ssh://${auditedHost}`;
    }

    // The agent's reason is no longer sent with the fetch, so it is kept HERE — in the
    // same local store as the web calls' destinations, on the owner's machine, written by
    // the broker's account. Without this an SSH call's purpose would exist nowhere, and
    // the owner's answer to "what was my agent doing on that server" would be a count.
    recordDestination(entryId, `ssh://${auditedHost}`, undefined, purpose);
    vaultKey ??= await this.api.ensureVaultKey();
    const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
    let identity;
    // Names this session's server-side sessions, so an EARLY end (End now, done, a revoke) can
    // end them on the server too, not only at the certificate's end (whole-build review F1).
    let certTag: string | undefined;
    try {
      identity = loadOpenSshEd25519(new TextDecoder().decode(bytes));
      if (adminUntilMs !== undefined && args.offer !== 'plain') {
        // D13: a certificate for this key, valid until admin access ends, whose forced
        // command makes the server end the session then too.
        certTag = randomBytes(8).toString('hex');
        identity.certBlob = adminCertificate(identity, { end: Math.floor(adminUntilMs / 1000), tag: certTag });
        if (args.offer === 'cert') identity.certOnly = true;
      } else if (args.offer === 'cert') {
        throw new Error('only an admin key in admin access has a certificate');
      }
    } catch (e) {
      return err(`That entry is not an unencrypted OpenSSH ed25519 private key: ${(e as Error).message}`);
    } finally {
      bytes.fill(0);
    }

    const sessionId = randomId();
    // The PARENT too, every time. A recursive mkdir creates `ssh/` with its mode masked by
    // umask, and only the leaf is chmodded below: under the macOS LaunchDaemon's Umask 0077
    // `ssh/` came out 0700, so the agent could reach neither the socket nor id.pub ("SSH
    // couldn't read the broker's id.pub file: Permission denied", the owner's Mac,
    // 2026-10-21). The same trap start() documents for the runtime directory. chmod on an
    // existing directory also repairs a Mac that already has a 0700 `ssh/`.
    //
    // 0711, not 0755: other uids may pass through to a session they were told the id of, but
    // may not LIST the live session ids. At 0755 any local account could read the ids and
    // connect to those 0666 signing sockets, so "the path is the unguessable part" below was
    // only true of this directory once it stopped being readable (review round 1, B1).
    const sshRoot = path.join(runtimeDir(), 'ssh');
    fs.mkdirSync(sshRoot, { recursive: true, mode: 0o711 });
    fs.chmodSync(sshRoot, 0o711);
    const dir = path.join(sshRoot, sessionId);
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    // 0755 on the directory and 0666 on the socket, for the same reason every broker
    // socket is world-connectable: the broker is a different uid from the agent, so a
    // mode that excluded other local users would exclude the agent too. The path is the
    // unguessable part.
    fs.chmodSync(dir, 0o755);

    let knownHostsPath: string | undefined;
    let handle: AgentHandle;
    try {
      if (pin) {
        knownHostsPath = path.join(dir, 'known_hosts');
        fs.writeFileSync(knownHostsPath, knownHostsLine(pin.target, pin.hostKey), { mode: 0o644, flag: 'wx' });
        fs.chmodSync(knownHostsPath, 0o644);
      }
      handle = startAgent(identity, undefined, auditedHost, {
        dir, socketMode: 0o666, publicKeyMode: 0o644,
        ...(pin ? { pinnedHostKey: pin.hostKey, pinnedUser: pin.target.user } : {}),
      });
    } catch (e) {
      fs.rmSync(dir, { recursive: true, force: true });
      throw e;
    }

    const lifeMs = adminUntilMs === undefined
      ? ttlSeconds * 1000
      : Math.max(1, Math.min(ttlSeconds * 1000, adminUntilMs - Date.now()));
    const timer = setTimeout(() => this.closeSsh(sessionId, adminUntilMs === undefined ? undefined : 'admin_access_ended'), lifeMs);
    (timer as unknown as { unref?: () => void }).unref?.();
    let adminPoll: NodeJS.Timeout | undefined;
    if (adminUntilMs !== undefined) {
      // End now / done / a revoke on the server closes the session within one poll. A failed
      // poll is not "still on": two in a row close it (fail closed, but not on one blip).
      let misses = 0;
      adminPoll = setInterval(() => {
        this.api.adminAccessStatus(entryId).then((st) => {
          misses = 0;
          if (!st.open) this.closeSsh(sessionId, 'admin_access_ended');
        }, () => {
          if (++misses >= 2) this.closeSsh(sessionId, 'admin_access_unconfirmed');
        });
      }, BrokerOps.ADMIN_POLL_MS);
      (adminPoll as unknown as { unref?: () => void }).unref?.();
    }
    let endRemote: (() => Promise<number>) | undefined;
    if (certTag !== undefined && (op?.kind === 'ssh' || op?.kind === 'git') && typeof op.destination === 'string') {
      // One last sign-in whose certificate can do one thing: end this session's server sessions
      // now. It carries the same pin, so it signs only for the same server.
      const tag = certTag, base = identity, destination = op.destination;
      const pinned = pin ? { hostKey: pin.hostKey, user: pin.target.user, line: knownHostsLine(pin.target, pin.hostKey) } : undefined;
      endRemote = async () => {
        const d = fs.mkdtempSync(path.join(sshRoot, 'end-'));
        let h: AgentHandle | undefined;
        try {
          const kh = pinned ? path.join(d, 'known_hosts') : undefined;
          if (kh) fs.writeFileSync(kh, pinned!.line, { mode: 0o600 });
          const id2 = { ...base, certOnly: true,
            certBlob: adminCertificate(base, { end: Math.floor(Date.now() / 1000) + 120, tag, endNow: true }) };
          h = startAgent(id2, undefined, auditedHost, {
            dir: d, socketMode: 0o600, publicKeyMode: 0o600,
            ...(pinned ? { pinnedHostKey: pinned.hostKey, pinnedUser: pinned.user } : {}),
          });
          const r = await runSshWithAgent({
            op: { kind: 'ssh', destination, remoteArgv: ['true'] } as BrokeredOp,
            socketPath: h.socketPath, publicKeyPath: h.publicKeyPath,
            ...(kh ? { knownHostsPath: kh } : {}), timeoutMs: 20_000,
          });
          return r.exitCode;
        } finally {
          try { h?.close(); } catch { /* gone */ }
          fs.rmSync(d, { recursive: true, force: true });
        }
      };
    }
    this.ssh.set(sessionId, {
      handle, timer, entryId, key: s.name, host: auditedHost, reason: purpose, tier: String(s.access_tier ?? '1'),
      ...(adminPoll ? { adminPoll, adminUntil: new Date(adminUntilMs!).toISOString() } : {}),
      ...(endRemote ? { endRemote } : {}),
    });
    // Pairs this line with its close. A hash, not the id: the id names the signing socket's
    // directory, and a copy of the log (the viewer page) is readable by agents (round 3, B1).
    rec.extra = { ...(rec.extra ?? {}), session: sessionRef(sessionId) };

    return {
      session_id: sessionId,
      socket_path: handle.socketPath,
      public_key_path: handle.publicKeyPath,
      fingerprint: identity.fingerprint,
      audited_host: auditedHost,
      ...(pin ? { known_hosts_path: knownHostsPath!, pinned_host_key: pin.hostKey } : {}),
      ...(adminUntilMs !== undefined ? { admin_until: new Date(adminUntilMs).toISOString() } : {}),
    };
  }

  /**
   * Guided setup and the change check (SPEC-admin-access §13): open a session through the SAME
   * path an agent's command takes (host pin, admin-access gate, certificate, activity line),
   * run ONE fixed command from this broker, close. `argv` gets the key's public line, which
   * setup needs (the admin key is trusted as a certificate authority). Never reachable from an
   * agent's request: the callers are the owner's sealed orders and the server's due list.
   */
  async serverRun(args: {
    entryId: string; destination: string; purpose: string;
    argv: (publicKey: string) => string[]; input?: string; offer?: 'cert' | 'plain'; timeoutMs?: number;
  }): Promise<{ exitCode: number; stdout: string; stderr: string } | OpError> {
    const op = { kind: 'ssh', destination: args.destination, remoteArgv: ['true'] } as BrokeredOp;
    const opened = await this.sshAgentOpen({
      entryId: args.entryId, purpose: args.purpose, op, ttlSeconds: 600, ...(args.offer ? { offer: args.offer } : {}),
    });
    if ('error' in opened) return opened;
    const stop = new AbortController();
    const watch = setInterval(() => {
      if (!this.ssh.has(opened.session_id)) stop.abort(this.endedSessions.get(opened.session_id) ?? 'session closed');
    }, 1000);
    (watch as unknown as { unref?: () => void }).unref?.();
    try {
      const pub = fs.readFileSync(opened.public_key_path, 'utf8').trim().split(/\s+/).slice(0, 2).join(' ');
      return await runSshWithAgent({
        op: { ...op, remoteArgv: args.argv(pub) } as BrokeredOp,
        socketPath: opened.socket_path, publicKeyPath: opened.public_key_path,
        ...(opened.known_hosts_path ? { knownHostsPath: opened.known_hosts_path } : {}),
        ...(args.input !== undefined ? { input: args.input } : {}),
        timeoutMs: args.timeoutMs ?? 180_000, signal: stop.signal,
      });
    } finally {
      clearInterval(watch);
      this.closeSsh(opened.session_id);
    }
  }

  /** Is this signing session still open? The agent's process asks, to stop its command when not. */
  sshSessionOpen(sessionId: string): { open: boolean; ended_by?: string } {
    if (this.ssh.has(sessionId)) return { open: true };
    const ended = this.endedSessions.get(sessionId);
    return ended ? { open: false, ended_by: ended } : { open: false };
  }

  /** Waits between early-end attempts (tests shorten them). */
  static END_RETRY_MS = [3_000, 10_000, 30_000, 60_000];

  /** Sessions whose early server-side end was started (tests read this). */
  readonly endingRemote = new Set<string>();

  /** Why recent sessions ended, so the agent can be told "admin access ended" (bounded). */
  private endedSessions = new Map<string, string>();

  closeSsh(sessionId: string, endedBy?: string): { closed: boolean; signs: number } {
    const rec = this.ssh.get(sessionId);
    if (!rec) return { closed: false, signs: 0 };
    const signs = rec.handle.signCount();
    clearTimeout(rec.timer);
    if (rec.adminPoll) clearInterval(rec.adminPoll);
    if (endedBy) {
      this.endedSessions.set(sessionId, endedBy);
      if (this.endedSessions.size > 64) this.endedSessions.delete(this.endedSessions.keys().next().value as string);
    }
    try { rec.handle.close(); } catch { /* already gone */ }
    this.ssh.delete(sessionId);
    // Ended EARLY by the owner (End now, done, a revoke) or unconfirmed: the server would keep
    // a session the agent opened with its own ssh until the certificate's end, so end it there
    // now (whole-build review F1). At the natural end the server's own timer does it.
    if (endedBy && rec.endRemote && rec.adminUntil && Date.now() < Date.parse(rec.adminUntil) - 2000) {
      const ref = sessionRef(sessionId);
      const until = Date.parse(rec.adminUntil);
      const endRemote = rec.endRemote;
      const note = (ok: boolean, detail: string) => this.record({
        kind: 'ssh_closed', outcome: ok ? 'closed' : 'refused', agent: this.agentName, entry_id: rec.entryId,
        key: rec.key, address: `ssh://${rec.host}`, reason: 'Ended the server sessions early', tier: rec.tier,
        extra: { session: ref, server_end: detail },
      });
      // Tried again until it works or the certificate's own end makes it moot (whole-build
      // review r2 F3: a busy server refusing one sign-in must not leave the session running).
      const attempt = (n: number): void => {
        endRemote().then((code) => ({ code }), () => ({ code: -1 })).then(({ code }) => {
          if (code === 0) { note(true, n ? `done (try ${n + 1})` : 'done'); return; }
          const wait = BrokerOps.END_RETRY_MS[Math.min(n, BrokerOps.END_RETRY_MS.length - 1)]!;
          if (Date.now() + wait >= until) { note(false, `failed (${code}); the server ends it at the certificate's end`); return; }
          const t = setTimeout(() => attempt(n + 1), wait);
          (t as unknown as { unref?: () => void }).unref?.();
        });
      };
      attempt(0);
      this.endingRemote.add(ref);
      if (this.endingRemote.size > 64) this.endingRemote.delete(this.endingRemote.values().next().value as string);
    }
    this.record({
      kind: 'ssh_closed', outcome: 'closed', agent: this.agentName, entry_id: rec.entryId,
      key: rec.key, address: `ssh://${rec.host}`, reason: rec.reason, tier: rec.tier,
      extra: { signs, session: sessionRef(sessionId), ...(endedBy ? { ended_by: endedBy } : {}) },
    });
    return { closed: true, signs };
  }
}

function sessionRef(sessionId: string): string {
  return createHash('sha256').update(sessionId).digest('hex').slice(0, 12);
}

function randomId(): string {
  return randomBytes(16).toString('hex');
}
