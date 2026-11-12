# Key-making recipes: where each one was checked

Each recipe in `src/new-key.ts` was read against the service's own API reference on 2026-11-11.
A recipe we cannot confirm this way stays out. Re-check when a service changes its API version.

| Recipe | Address (POST) | New key in | Source |
|---|---|---|---|
| resend.api-key | https://api.resend.com/api-keys | `token` | resend.com/docs/api-reference/api-keys/create-api-key |
| cloudflare.user-token | https://api.cloudflare.com/client/v4/user/tokens | `result.value` | developers.cloudflare.com/api (User > Tokens > Create) |
| cloudflare.account-token | https://api.cloudflare.com/client/v4/accounts/{account_id}/tokens | `result.value` | developers.cloudflare.com/api (Accounts > Tokens > Create) |
| sendgrid.api-key | https://api.sendgrid.com/v3/api_keys | `api_key` | twilio.com/docs/sendgrid/api-reference/api-keys/create-api-keys |
| openai.admin-key | https://api.openai.com/v1/organization/admin_api_keys | `value` | github.com/openai/openai-openapi (openapi.yaml, AdminApiKey) |
| openai.service-account | https://api.openai.com/v1/organization/projects/{project_id}/service_accounts | `api_key.value` | same file, ProjectServiceAccountCreateResponse |
| twilio.api-key | https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Keys.json | `secret` | twilio.com/docs/iam/api-keys/key-resource-v2010 |
| openrouter.key | https://openrouter.ai/api/v1/keys | `key` | openrouter.ai/docs/api-reference/api-keys/create-api-key |

Not checked against a live account: only Resend is planned for the real run (spec check 16).
Known gaps: Cloudflare "roll token" (PUT .../tokens/{id}/value) also returns a new value and is NOT
covered; it belongs to rotation (item 2).
