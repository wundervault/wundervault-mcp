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
  env_key: string;
  pre_command?: string;
  post_command?: string;
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
  exec_config?: ExecConfig; // CIP-017
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