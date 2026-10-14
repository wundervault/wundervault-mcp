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
 * ONE getSecret PER OPERATION, DELIBERATELY
 *
 * Each operation makes exactly one `getSecret` call, the same one the agent used to make.
 * That keeps the server's access log and the tier-2 gate seeing precisely what they saw
 * before. A separate "just the metadata" probe would have been convenient here and would
 * have added an access-log row per call and a second chance to trip tier 2.
 *
 * None of them sends the agent's `purpose` with that fetch. The reason stays in the local
 * destination log; the server hears it only for a tier-2 web call, on the approval the
 * owner is being asked to make (see `call`).
 */
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { AgentVaultAPI } from './api-client.js';
import { signerFromIdentity, type BrokerSigner } from './broker-sign.js';
import { decryptSecretContent, loadEncryptionKey } from './crypto.js';
import {
  modeAllowsSshBroker, modeAllowsHttpBroker, wrongModeMessage,
  loadOpenSshEd25519, startAgent, checkSshDestination, type AgentHandle, type BrokeredOp,
} from './ssh-agent.js';
import {
  performOperation, definitionFromAgentRequest, originString, isApprovedPrivateOrigin,
  type AgentRequest,
} from './http-broker.js';
import { verifyOperationDefinition, validateArguments } from './opdef.js';
import { recordDestination, newDestinationNotice, emitToStderr } from './network-store.js';
import { runtimeDir } from './paths.js';
import type { VaultEntry } from './types.js';
import { bindingFromExecConfig, looksLikePrivateKey, validateAgentHeaders, pathBindingProblem } from './delivery.js';
import { renderDetail } from './render.js';
import { SigningState } from './wallet.js';
import { validateRecipe, recipeSha256, describeRecipe, computeStamp, parseStampedValue, type Recipe } from './stamp.js';
import { pay as payOp, sign as signOp, approveStamp, type Deps, type PayResult } from './signing-ops.js';
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
  /** BUILD 2: this machine's payment record, policy versions and used approvals. */
  private state: SigningState;
  private ssh = new Map<string, { handle: AgentHandle; timer: NodeJS.Timeout; entryId: string; key?: string; host: string; reason: string; tier: string }>();
  /**
   * The activity log (activity-log.ts). Set by the daemon; null in a test that does not
   * care. Writing a line never changes what an operation returns, and never throws into it.
   */
  activity: ActivitySink | null = null;

  private record(rec: ActivityRecord): void {
    try { this.activity?.record(rec); } catch { /* bookkeeping never fails a vault call */ }
  }

  /** This agent's route to the server's copy of the log's chain. */
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
  ) {
    this.api = new AgentVaultAPI(apiKey, loadEncryptionKey(encKeyB64), vaultUrl, signer);
    this.state = state;
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
    callArgs?: Record<string, unknown>; request?: AgentRequest;
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
    callArgs?: Record<string, unknown>; request?: AgentRequest;
  }, rec: ActivityRecord): Promise<{ status: number; body: unknown; tier: string; label: string; notice?: string } | OpError> {
    const { entryId, purpose } = args;
    const operationId = args.operationId || '';
    const callArgs = args.callArgs ?? {};
    const agentReq = args.request;

    const s = await this.api.getSecret(entryId);
    rec.key = s.name;
    rec.tier = String(s.access_tier ?? '1');
    if (!modeAllowsHttpBroker(s.entry_mode)) {
      return err(wrongModeMessage(s.entry_mode, 'http'), 'WRONG_MODE');
    }

    // The credential binding always comes from the ENTRY. An agent may choose where a
    // request goes; it never chooses how the secret is framed on the way out. Checked
    // before the key is decrypted: a binding the server sent that this broker would not
    // have accepted from the owner refuses the call. It is not repaired and it does not
    // fall back to a bearer token — see delivery.ts.
    const bound = bindingFromExecConfig(coerceCfg(s.exec_config));
    if (!bound.ok) {
      return err(`Refused: this entry's delivery setting is not one the broker accepts `
        + `(${bound.field}: ${bound.reason}). Nothing was sent. The owner can set how the key `
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
        return err('Refused: this key is stamped — it never travels, and each request carries a code computed from it. '
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
      const h = validateAgentHeaders(agentReq.headers, binding);
      if (!h.ok) return err(`Refused: ${h.field}: ${h.reason}. Nothing was sent.`, 'BAD_REQUEST');
      agentHeaders = h.headers;
    }

    const vaultKey = await this.api.ensureVaultKey();
    const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
    try {
      const secret = new TextDecoder().decode(bytes);
      if (looksLikePrivateKey(secret)) {
        return err('Refused: this entry holds a private key, which is never sent to a web service. '
          + 'Nothing was sent. If it is an SSH key, the owner can set it to SSH (with the servers '
          + 'it may sign in to) in the dashboard, and then use vault_ssh_exec.', 'WRONG_KIND');
      }

      let def;
      let label: string;
      if (operationId) {
        let catalogue: Record<string, { definition: unknown; signature?: string }> = {};
        try {
          const raw = s.operations as unknown;
          catalogue = (typeof raw === 'string' ? JSON.parse(raw) : (raw ?? {})) as typeof catalogue;
        } catch { return err("This entry's operation catalogue is not readable."); }
        const slot = catalogue?.[operationId];
        if (!slot) {
          const known = Object.keys(catalogue || {});
          return err(`Entry has no operation "${operationId}".`
            + (known.length ? ` Available: ${known.join(', ')}.` : ' It defines none.'));
        }
        const verified = verifyOperationDefinition(entryId, slot.definition, slot.signature, bytes, operationId);
        if (!verified.ok || !verified.definition) return err(`Refused: ${verified.reason}`);
        const argCheck = validateArguments(verified.definition, callArgs);
        if (!argCheck.ok) return err(`Refused: ${argCheck.reason}`);
        def = verified.definition;
        label = operationId;
      } else {
        const r = agentReq!;
        if (!r?.origin?.host || !r.origin.scheme || !r.origin.port) {
          return err('request.origin needs scheme, host and port.');
        }
        def = definitionFromAgentRequest({ ...r, headers: agentHeaders }, binding);
        label = `${def.route.method} ${originString(r.origin)}${r.path || '/'}`;
        // Before anything is recorded or approved: a key that cannot go in the address
        // would otherwise spend a tier-2 approval on a call that was never going to be sent.
        const problem = pathBindingProblem(binding, secret, def.route.path);
        if (problem) return err(`Refused: ${problem} Nothing was sent.`, 'BAD_REQUEST');
      }

      const bodyHash = agentReq?.body !== undefined
        ? createHash('sha256').update(JSON.stringify(agentReq.body)).digest('hex')
        : undefined;
      // The address the agent asked for, before the key is added — scrubbed anyway, so a
      // key that somehow reached the path never reaches the log.
      rec.method = def.route.method;
      rec.address = String(scrubSecret(`${originString(def.origin)}${def.route.path}`, secret));
      rec.body_sha256 = bodyHash;

      // Recorded here, in the broker, which is the first time this has actually worked.
      // The call site used to be in the MCP server — the agent's uid — writing to
      // /var/lib/wundervault/network.json, a directory that uid cannot open. D3 of the
      // uid-split spec calls this store an integrity control because the audited party
      // no longer owns the evidence; until now the audited party was still the writer.
      const originStr = originString(def.origin);
      const { isNew } = recordDestination(entryId, originStr, undefined, purpose);

      const isTier2 = String(s.access_tier ?? '1') === '2';
      const destination = isTier2
        ? { origin: originStr, method: def.route.method, path: def.route.path, body_sha256: bodyHash }
        : {};

      // The purpose goes with the destination: tier 2 only, where the owner is approving
      // this one call and needs to read why. Tier 1 sends neither (network-shape decision).
      const verdict = await this.api.checkOperation({
        entry_id: entryId, purpose: isTier2 ? purpose.slice(0, 200) : '', first_sighting: isNew,
        ...destination,
      });

      if (!verdict.allowed) {
        rec.approval = 'asked';
        const approved = verdict.request_id
          ? await this.api.waitForTier2Approval(verdict.request_id)
          : false;
        if (!approved) {
          rec.approval = 'not_approved';
          return err(`${verdict.message ?? 'This call needs owner approval.'}\n\n`
            + `Nothing was sent. The owner sees exactly: ${def.route.method} `
            + `${originString(def.origin)}${def.route.path}`);
        }
        const second = await this.api.checkOperation({
          entry_id: entryId, purpose: purpose.slice(0, 200), origin: originStr,
          method: def.route.method, path: def.route.path, body_sha256: bodyHash,
        });
        if (!second.allowed) {
          rec.approval = 'not_approved';
          return err(`${second.message ?? 'This call needs owner approval.'}\n\n`
            + `Nothing was sent. The owner sees exactly: ${def.route.method} `
            + `${originString(def.origin)}${def.route.path}`);
        }
        verdict.tier = second.tier;
        rec.approval = 'approved';
      }

      let approvedOrigins: string[] = [];
      try {
        const raw = s.allowed_private_origins as unknown;
        const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
        if (Array.isArray(parsed)) approvedOrigins = parsed.filter((x): x is string => typeof x === 'string');
      } catch { approvedOrigins = []; }

      let noticeForAgent = '';
      if (isNew) {
        const notice = newDestinationNotice(
          s.name ?? entryId, originStr, def.route.method, def.route.path, verdict.tier,
          !operationId, verdict.emailed === true,
        );
        emitToStderr(notice);
        noticeForAgent = notice.toolNote;
      }

      // A stamped entry may hold {"id", "secret"}; only the secret is a MAC key, and only
      // the secret is scrubbed (the id is sent in the clear by design).
      let stamped: { id?: string; secret: string } | null = null;
      if (stampRecipe) {
        try { stamped = parseStampedValue(secret); } catch (e) {
          return err(`Refused: ${(e as Error).message}. Nothing was sent. The owner can fix it in the dashboard.`, 'WRONG_KIND');
        }
      }
      rec.outcome = 'sending';
      const result = await performOperation(
        def, operationId ? callArgs : (typeof agentReq?.body === 'string'
          ? agentReq.body
          : ((agentReq?.body ?? {}) as Record<string, unknown>)),
        stamped ? stamped.secret : secret, approvedOrigins,
        stamped ? (img) => computeStamp(stampRecipe!, img, stamped) : undefined,
      );
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
   * WHAT THIS DOES NOT FIX. The socket has to be connectable by the agent's uid, and all
   * seven agents share that uid, so any agent that learns the path can ask for a
   * signature while the session is open. The random path and the short life bound that;
   * they do not close it. It is still strictly better than the status quo, where the
   * agent holds the private key itself and can sign with it for ever.
   */
  async sshAgentOpen(args: {
    entryId: string; purpose: string; op: BrokeredOp; ttlSeconds?: number;
  }): Promise<{
    session_id: string; socket_path: string; public_key_path: string; fingerprint: string;
    audited_host: string;
  } | OpError> {
    const rec: ActivityRecord = {
      kind: 'ssh', outcome: 'refused', agent: this.agentName, entry_id: args.entryId,
      reason: args.purpose, address: `ssh://${String(args.op?.destination ?? '')}`,
      extra: { op: String(args.op?.kind ?? '') },
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
    entryId: string; purpose: string; op: BrokeredOp; ttlSeconds?: number;
  }, rec: ActivityRecord): Promise<{
    session_id: string; socket_path: string; public_key_path: string; fingerprint: string;
    audited_host: string;
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

    const s = await this.api.getSecret(entryId);
    rec.key = s.name;
    rec.tier = String(s.access_tier ?? '1');
    if (!modeAllowsSshBroker(s.entry_mode)) {
      return err(wrongModeMessage(s.entry_mode, 'ssh'), 'WRONG_MODE');
    }

    // THE ALLOWLIST IS CHECKED HERE, BEFORE A SESSION EXISTS.
    //
    // It used to be checked in the MCP server, which is the agent's own process — so the
    // entry's list of permitted hosts was advice the caller gave itself, and an agent
    // that skipped the check had the private key in hand anyway. The broker refuses to
    // OPEN a signing session for a destination the entry does not authorise, which is
    // the first time this list has been a control rather than a convention.
    //
    // The honest limit is unchanged and stated in the class header: once a session is
    // open, any same-uid process that learns the socket path can ask it to sign for some
    // other host. Closing that needs OpenSSH's session-bind extension.
    let allowedHosts: string[] = [];
    const execCfg = coerceCfg(s.exec_config);
    if (Array.isArray((execCfg as { ssh_hosts?: unknown }).ssh_hosts)) {
      allowedHosts = ((execCfg as { ssh_hosts: unknown[] }).ssh_hosts).map(String);
    }
    const check = checkSshDestination(op, allowedHosts);
    if (!check.ok) return err(check.error, 'HOST_NOT_ALLOWED');
    rec.address = `ssh://${check.auditedHost}`;

    // The agent's reason is no longer sent with the fetch, so it is kept HERE — in the
    // same local store as the web calls' destinations, on the owner's machine, written by
    // the broker's account. Without this an SSH call's purpose would exist nowhere, and
    // the owner's answer to "what was my agent doing on that server" would be a count.
    recordDestination(entryId, `ssh://${check.auditedHost}`, undefined, purpose);
    const vaultKey = await this.api.ensureVaultKey();
    const bytes = decryptSecretContent(vaultKey, s.encrypted_content, s.content_nonce);
    let identity;
    try {
      identity = loadOpenSshEd25519(new TextDecoder().decode(bytes));
    } catch (e) {
      return err(`That entry is not an unencrypted OpenSSH ed25519 private key: ${(e as Error).message}`);
    } finally {
      bytes.fill(0);
    }

    const sessionId = randomId();
    const dir = path.join(runtimeDir(), 'ssh', sessionId);
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    // 0755 on the directory and 0666 on the socket, for the same reason every broker
    // socket is world-connectable: the broker is a different uid from the agent, so a
    // mode that excluded other local users would exclude the agent too. The path is the
    // unguessable part.
    fs.chmodSync(dir, 0o755);

    const handle = startAgent(identity, undefined, check.auditedHost, {
      dir, socketMode: 0o666, publicKeyMode: 0o644,
    });

    const timer = setTimeout(() => this.closeSsh(sessionId), ttlSeconds * 1000);
    (timer as unknown as { unref?: () => void }).unref?.();
    this.ssh.set(sessionId, { handle, timer, entryId, key: s.name, host: check.auditedHost, reason: purpose, tier: String(s.access_tier ?? '1') });
    // Pairs this line with its close. A hash, not the id: the id names the signing socket's
    // directory, and a copy of the log (the viewer page) is readable by agents (round 3, B1).
    rec.extra = { ...(rec.extra ?? {}), session: sessionRef(sessionId) };

    return {
      session_id: sessionId,
      socket_path: handle.socketPath,
      public_key_path: handle.publicKeyPath,
      fingerprint: identity.fingerprint,
      audited_host: check.auditedHost,
    };
  }

  closeSsh(sessionId: string): { closed: boolean; signs: number } {
    const rec = this.ssh.get(sessionId);
    if (!rec) return { closed: false, signs: 0 };
    const signs = rec.handle.signCount();
    clearTimeout(rec.timer);
    try { rec.handle.close(); } catch { /* already gone */ }
    this.ssh.delete(sessionId);
    this.record({
      kind: 'ssh_closed', outcome: 'closed', agent: this.agentName, entry_id: rec.entryId,
      key: rec.key, address: `ssh://${rec.host}`, reason: rec.reason, tier: rec.tier,
      extra: { signs, session: sessionRef(sessionId) },
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
