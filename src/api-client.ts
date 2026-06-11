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

  async getProfile(): Promise<ProfileResponse> {
    return this.fetchJson<ProfileResponse>('/agent/profile');
  }

  async listSecrets(): Promise<SecretsResponse> {
    return this.fetchJson<SecretsResponse>('/agent/vault/secrets');
  }

  async getSecret(id: string, purpose: string): Promise<SecretResponse> {
    return this.fetchJson<SecretResponse>(`/agent/vault/secrets/${id}`, {
      purpose: purpose.slice(0, 200),
    });
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
