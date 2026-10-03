export interface VaultEntry {
  id: string;
  secret_name: string;
  access_tier: string;
  /** BROKER_HTTP or BROKER_SSH_AGENT. Absent from a server older than 1.0. */
  entry_mode?: string;
  /** Ids of the signed operations the entry offers. */
  operations?: string[];
}

export interface Credentials {
  agent_vault_url: string;
  agent_vault_api_key: string;
  agent_encryption_key: string;
}

export interface ProfileResponse {
  vault_key_for_agent: string;
}

export interface SecretsResponse {
  entries: VaultEntry[];
}

export interface SecretResponse {
  /**
   * BROKER_HTTP | BROKER_SSH_AGENT — set server-side. (LEGACY_EXEC, hand-over, is retired.)
   *
   * Enforced in the BROKER, and since phase 6 also on the server: a broker mode is served
   * only to a caller that signed with the broker key this agent is bonded to. An agent on
   * a machine with no paired broker cannot fetch one at all.
   */
  entry_mode?: string;
  /** Signed operation catalogue, JSON. */
  operations?: string;
  /** Exact private origins the owner approved for this entry. */
  allowed_private_origins?: string;
  /** "on" | "off" — does a first sighting on this entry also go out by email? */
  alert_email?: string;
  name?: string;
  encrypted_content: string;
  content_nonce: string;
  directive?: string;
  directive_signature?: string;
  access_tier?: string;
  /**
   * How the key is used, as JSON: {delivery:"http", credential_binding:{…}} or
   * {delivery:"ssh", ssh_hosts:[…]}. The broker re-validates it (delivery.ts); it is
   * never trusted as given.
   */
  exec_config?: Record<string, unknown> | string;
}
