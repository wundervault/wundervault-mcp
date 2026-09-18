import crypto from 'node:crypto';
import { hmacForApiKey, decryptVaultKey } from './crypto.js';
import type { BrokerSigner } from './broker-sign.js';
import type { VaultEntry, ProfileResponse, SecretsResponse, SecretResponse } from './types.js';
import { VERSION } from './version.js';

const TIMEOUT = 30_000;

export class AgentVaultAPI {
  private hmacB64: string;
  private vaultKey: Uint8Array | null = null;
  private allowEnvInject: boolean = false;

  constructor(
    private apiKey: string,
    private encKey: Uint8Array,
    private baseUrl: string = 'https://wundervault.com',
    /**
     * PHASE 6. The broker's signer, or null on a machine that has never paired.
     *
     * Null is not a way to opt out of the check: the SERVER decides which agents may go
     * unsigned, from a column the owner's repair writes. A signer that is null against a
     * broker-held agent produces a refusal naming the upgrade, which is the correct
     * outcome — not a quiet downgrade to the weaker path.
     */
    private signer: BrokerSigner | null = null,
  ) {
    this.hmacB64 = hmacForApiKey(apiKey, encKey);
  }

  private headers(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
      'X-Api-Key-Hmac': this.hmacB64,
      'X-Via-MCP': 'wundervault-mcp',
      'X-Wundervault-MCP-Version': VERSION,
    };
  }

  /**
   * The headers for one request, signed when this machine has a broker identity.
   *
   * Every call goes through here, so a method added later is signed without anyone having
   * to remember — the same reason the server puts its check in one place.
   */
  private signedHeaders(
    method: string, url: string, body?: string,
  ): Record<string, string> {
    const base = this.headers();
    if (!this.signer) return base;
    // Signed from the PARSED url, not from the path string that was passed in. The
    // server verifies against the raw path it received, and `new URL()` applies the same
    // encoding `fetch` will put on the wire — so signing the unparsed string would be
    // signing something merely equivalent to what is sent. No current path needs
    // encoding, which is why this would have failed the first time one did.
    const u = new URL(url);
    return { ...base, ...this.signer.sign(method, u.pathname, u.search.replace(/^\?/, ''), body) };
  }

  private async fetchJson<T>(path: string, params?: Record<string, string>): Promise<T> {
    let url = `${this.baseUrl}${path}`;
    // Built once and signed as built. Re-serialising the params for the signature would
    // mean signing a string that is merely equivalent to the one sent, and the server
    // compares bytes.
    const query = params ? new URLSearchParams(params).toString() : '';
    if (query) url += `?${query}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: this.signedHeaders('GET', url),
      signal: AbortSignal.timeout(TIMEOUT),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      const err: any = new Error(`HTTP ${resp.status}: ${text}`);
      err.status = resp.status;
      throw err;
    }
    return resp.json() as Promise<T>;
  }

  /**
   * Ask the server whether this brokered call may proceed.
   *
   * Deliberately asked BEFORE anything is sent upstream: a tier-2 call that needs
   * consent must never reach the network, and the tier and the approvals live on the
   * server, so the decision does too.
   */
  async checkOperation(body: {
    entry_id: string;
    purpose: string;
    /**
     * The destination — sent for TIER 2 ONLY.
     *
     * Where an owner's agents send their keys is a behavioural profile: which services,
     * how often, at what hour, and for a self-hosted destination the shape of an internal
     * network. None of it helps anyone read a secret and all of it is what a breach or a
     * subpoena reaches, so it stays in the local store rather than being accumulated
     * server-side one routine call at a time.
     *
     * Tier 2 is the exception because tier 2 IS a human reviewing one specific request,
     * and nobody can approve what they cannot see. That is consented disclosure for a
     * single call. The server enforces this: it refuses a tier-2 check that omits them,
     * so a client that lied about the tier to withhold the destination gets a 422 rather
     * than a quiet downgrade.
     */
    origin?: string; method?: string; path?: string;
    body_sha256?: string;
    /**
     * One bit, computed locally: has this entry been used against this origin before?
     *
     * This is what replaced the server answering the same question from its access log —
     * which required it to hold every destination for ever in order to send one email.
     * The server learns that a first sighting happened, never which destination caused
     * it.
     */
    first_sighting?: boolean;
  }): Promise<{ allowed: boolean; tier: string; request_id?: string; message?: string;
                emailed?: boolean }> {
    // Serialised once. The bytes that are hashed for the signature must be the bytes
    // that are sent, and JSON.stringify called twice is two chances to differ.
    const payload = JSON.stringify(body);
    const resp = await fetch(`${this.baseUrl}/agent/vault/operation-check`, {
      method: 'POST',
      headers: {
        ...this.signedHeaders('POST', `${this.baseUrl}/agent/vault/operation-check`, payload),
        'content-type': 'application/json',
      },
      body: payload,
      signal: AbortSignal.timeout(TIMEOUT),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      const err: any = new Error(`HTTP ${resp.status}: ${text}`);
      err.status = resp.status;
      throw err;
    }
    return resp.json() as Promise<{ allowed: boolean; tier: string; request_id?: string;
                                    message?: string; emailed?: boolean }>;
  }

  async getProfile(): Promise<ProfileResponse> {
    return this.fetchJson<ProfileResponse>('/agent/profile');
  }

  async listSecrets(): Promise<SecretsResponse> {
    return this.fetchJson<SecretsResponse>('/agent/vault/secrets');
  }

  async getSecret(id: string, purpose: string): Promise<SecretResponse> {
    try {
      return await this.fetchJson<SecretResponse>(`/agent/vault/secrets/${id}`, {
        purpose: purpose.slice(0, 200),
      });
    } catch (err: any) {
      // Tier-2 gate: the 403 detail carries a pending approval-request id.
      // Park here and poll it so the human's approval resolves this same
      // tool call instead of forcing a blind retry later.
      const requestId = err?.status === 403
        ? String(err.message).match(/tier2-requests\/([A-Za-z0-9_-]+)/)?.[1]
        : undefined;
      if (!requestId) throw err;
      const approved = await this.waitForTier2Approval(requestId);
      if (!approved) throw err;
      return await this.fetchJson<SecretResponse>(`/agent/vault/secrets/${id}`, {
        purpose: purpose.slice(0, 200),
      });
    }
  }

  /**
   * Poll a tier-2 approval request for up to ~90s. True once approved.
   *
   * Running out of patience is not the same as being refused, and the difference is
   * worth reporting. A denial means somebody looked and said no. A timeout means nobody
   * looked at all — which is the only signal this system ever gets that the terminal had
   * no one reading it. So the deadline expiring reports itself, and the server turns that
   * into the second, louder notice.
   *
   * Only the expiry reports. A denial and an explicit expiry both mean a human was
   * involved or the request is already dead, and mailing about either would make the
   * escalation routine — at which point it stops being read, which is the failure mode
   * that matters for a channel whose entire job is to work at 3am.
   */
  async waitForTier2Approval(requestId: string): Promise<boolean> {
    const deadline = Date.now() + 90_000;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 5_000));
      try {
        const res = await this.fetchJson<{ status: string }>(
          `/agent/vault/tier2-requests/${requestId}`,
        );
        if (res.status === 'approved') return true;
        if (res.status === 'denied' || res.status === 'expired') return false;
      } catch {
        // transient poll error — keep waiting until the deadline
      }
    }
    await this.reportUnanswered(requestId);
    return false;
  }

  /**
   * Tell the server nobody answered, so the owner hears about it a second time.
   *
   * Best effort by design. This runs at the end of a call that has already failed, and
   * the caller is about to report that failure; turning a broken notification into a
   * different error would replace an accurate message ("approval never came") with a
   * misleading one ("could not reach Wundervault"). The server is idempotent on its side,
   * so a retried call cannot multiply the mail.
   */
  private async reportUnanswered(requestId: string): Promise<void> {
    try {
      const path = `/agent/vault/tier2-requests/${requestId}/unanswered`;
      await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: this.signedHeaders('POST', `${this.baseUrl}${path}`),
        signal: AbortSignal.timeout(TIMEOUT),
      });
    } catch { /* the call already failed; do not fail it differently */ }
  }

  async getMcpSettings(): Promise<{
    session_lock_minutes: number;
    session_lock_uses: number;
    require_approval: boolean;
    approval_scope: string;
    audit_log_enabled: boolean;
    audit_log_retention_days: number;
    audit_log_detail: string;
    allow_arbitrary_commands: boolean;
  }> {
    try {
      return await this.fetchJson('/api/v1/mcp-settings');
    } catch {
      return {
        session_lock_minutes: 5,
        session_lock_uses: 3,
        require_approval: false,
        approval_scope: 'high_impact',
        audit_log_enabled: true,
        audit_log_retention_days: 90,
        audit_log_detail: 'label',
        allow_arbitrary_commands: false,
      };
    }
  }

  /**
   * Decrypt vault_key_for_agent blob: AES-256-GCM.
   * Blob format: 60 raw bytes = 12B nonce + 32B ciphertext + 16B GCM tag.
   * Cached after first call.
   */
  async ensureVaultKey(): Promise<Uint8Array> {
    if (this.vaultKey !== null) return this.vaultKey;
    const data = await this.getProfile();
    this.vaultKey = decryptVaultKey(this.encKey, data.vault_key_for_agent);
    this.allowEnvInject = data.allow_env_inject ?? false;
    return this.vaultKey;
  }

  /** Returns whether env inject is enabled for this account (from cached profile). */
  async getAllowEnvInject(): Promise<boolean> {
    return this.allowEnvInject;
  }
}
