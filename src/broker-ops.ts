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
import { bindingFromExecConfig, looksLikePrivateKey, validateAgentHeaders } from './delivery.js';

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
  private ssh = new Map<string, { handle: AgentHandle; timer: NodeJS.Timeout; entryId: string }>();

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
  ) {
    this.api = new AgentVaultAPI(apiKey, loadEncryptionKey(encKeyB64), vaultUrl, signer);
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
    const { entryId, purpose } = args;
    const operationId = args.operationId || '';
    const callArgs = args.callArgs ?? {};
    const agentReq = args.request;

    const s = await this.api.getSecret(entryId);
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
      }

      const bodyHash = agentReq?.body !== undefined
        ? createHash('sha256').update(JSON.stringify(agentReq.body)).digest('hex')
        : undefined;

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
        const approved = verdict.request_id
          ? await this.api.waitForTier2Approval(verdict.request_id)
          : false;
        if (!approved) {
          return err(`${verdict.message ?? 'This call needs owner approval.'}\n\n`
            + `Nothing was sent. The owner sees exactly: ${def.route.method} `
            + `${originString(def.origin)}${def.route.path}`);
        }
        const second = await this.api.checkOperation({
          entry_id: entryId, purpose: purpose.slice(0, 200), origin: originStr,
          method: def.route.method, path: def.route.path, body_sha256: bodyHash,
        });
        if (!second.allowed) {
          return err(`${second.message ?? 'This call needs owner approval.'}\n\n`
            + `Nothing was sent. The owner sees exactly: ${def.route.method} `
            + `${originString(def.origin)}${def.route.path}`);
        }
        verdict.tier = second.tier;
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

      const result = await performOperation(
        def, operationId ? callArgs : (typeof agentReq?.body === 'string'
          ? agentReq.body
          : ((agentReq?.body ?? {}) as Record<string, unknown>)),
        secret, approvedOrigins,
      );
      if (!result.ok && /internal or reserved address/.test(result.error ?? '')
          && !isApprovedPrivateOrigin(def.origin, approvedOrigins)) {
        return err(`${result.error}\n\nIf you host that service yourself, the owner can approve `
          + `exactly ${originString(def.origin)} for this entry in the dashboard. `
          + `Approval is per entry and per exact host and port — it does not open a range, `
          + `and cloud metadata endpoints cannot be approved at all.`);
      }
      if (!result.ok) {
        return err(`${label} failed${result.status ? ` (HTTP ${result.status})` : ''}: ${result.error ?? 'unknown error'}`);
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
    this.ssh.set(sessionId, { handle, timer, entryId });

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
    return { closed: true, signs };
  }
}

function randomId(): string {
  return randomBytes(16).toString('hex');
}
