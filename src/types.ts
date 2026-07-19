export interface VaultEntry {
  id: string;
  secret_name: string;
  access_tier: string;
}

export interface Credentials {
  agent_vault_url: string;
  agent_vault_api_key: string;
  agent_encryption_key: string;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface ProfileResponse {
  vault_key_for_agent: string;
  allow_env_inject?: boolean;
}

export interface SecretsResponse {
  entries: VaultEntry[];
}

export interface ExecConfig {
  /** env var name for the `env`/generic mechanism (optional once a recipe drives delivery) */
  env_key?: string;
  pre_command?: string;
  post_command?: string;
  /** CIP-025: recipe id (sudo | ssh-passphrase | git | generic). Drives the delivery mechanism. */
  credential_type?: string;
  /** Advanced escape hatch — force a channel directly instead of a recipe. */
  mechanism?: 'env' | 'stdin' | 'askpass';
  /** Advanced escape hatch — askpass env var, used with mechanism: 'askpass'. */
  askpass_var?: string;
}

export interface RemoteHost {
  host: string;
  user: string;
  ssh_key?: string;
  ssh_key_entry_id?: string;
}

export interface SecretResponse {
  name?: string;
  encrypted_content: string;
  content_nonce: string;
  directive?: string;
  directive_signature?: string;
  access_tier?: string;
  exec_config?: ExecConfig | string; // CIP-017 — backend forwards a JSON string; coerce before use
}

export interface VaultHttpPostCredential {
  entry_id: string;
  header: string;
  format: string;
}

export interface VaultHttpPostParams {
  url: string;
  body: Record<string, unknown> | string;
  method?: string;
  credentials: VaultHttpPostCredential[];
  purpose: string;
  timeout?: number;
}