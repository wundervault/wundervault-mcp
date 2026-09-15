import crypto from 'node:crypto';
import { hmacForApiKey, decryptVaultKey } from './crypto.js';
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

  private async fetchJson<T>(path: string, params?: Record<string, string>): Promise<T> {
    let url = `${this.baseUrl}${path}`;
    if (params) {
      const searchParams = new URLSearchParams(params);
      url += `?${searchParams.toString()}`;
    }
    const resp = await fetch(url, {
      method: 'GET',
      headers: this.headers(),
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
    entry_id: string; origin: string; method: string; path: string;
    purpose: string; body_sha256?: string;
  }): Promise<{ allowed: boolean; tier: string; request_id?: string; message?: string }> {
    const resp = await fetch(`${this.baseUrl}/agent/vault/operation-check`, {
      method: 'POST',
      headers: { ...this.headers(), 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      const err: any = new Error(`HTTP ${resp.status}: ${text}`);
      err.status = resp.status;
      throw err;
    }
    return resp.json() as Promise<{ allowed: boolean; tier: string; request_id?: string; message?: string }>;
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
      await fetch(`${this.baseUrl}/agent/vault/tier2-requests/${requestId}/unanswered`, {
        method: 'POST',
        headers: this.headers(),
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
