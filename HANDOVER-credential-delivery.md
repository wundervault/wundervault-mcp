# CIP-025 — Credential delivery recipes (handover)

Intent-based secret delivery for `vault_exec`: a vault entry declares a
`credential_type` (recipe) and the vault picks the safe channel — **stdin** and
**askpass** as the hidden engine, **env** as the backward-compatible default.
PTY was deliberately left out.

## Status
- **MCP server** (`wundervault-mcp`, branch `feat/credential-delivery-recipes`):
  recipes.ts + stdin/askpass mechanisms + dispatch + `coerceExecConfig` (parses
  the exec_config JSON string the backend forwards — also fixes a latent bug in
  the env_key path). 14 tests pass; real `sudo -S` + askpass smoked.
- **Dashboard** (`burnbox`, branch `feat/credential-type-picker`): send-to-agent
  modal reframed to a **Credential type** picker; writes `credential_type` into
  exec_config. Directive text updated (no more hand-rolled `sudo -S <<<`).
- Backend: **no change** — exec_config is an opaque JSON string it forwards.

## ⚠ DOCS — UPDATE ALL OF THESE ONCE SHIPPED (user-requested)
The old model (env_key / manual injection recipe / "pipe to sudo -S") is now
inaccurate. Update to describe credential types + safe delivery:
- MCP repo: `README.md`, `README-AGENTS.md`, `llms-install.md`
- Site templates (burnbox `app/templates/`): `for-agents.html`, `security.html`,
  `mcp.html`, `secrets-for-ai-agents.html`, `quickstart.html`, `setup_agent.html`,
  `whitepaper.html`, `index.html`, `dashboard.html`
- CIP docs (burnbox root): update `CIP-017-vault-exec-v2.md`, `SECURITY-WHITEPAPER.md`;
  **author `CIP-025-credential-delivery.md`** (this feature — note: "CIP-018" in
  early commit messages was a mislabel; 018 is strawberry-autopipeline)

## Open decisions before/at deploy
- **env-inject disabling policy**: `allow_env_inject` today gates only
  `vault_entry_inject_env` (writing secrets to disk files); `vault_exec` never
  checked it. Gating the exec `env` mechanism behind it would BREAK npm/template
  flows (flag defaults false). Decision pending: leave as-is, or add a separate
  opt-in "disable env delivery in vault_exec (force stdin/askpass)" flag.
- Deploy: MCP npm publish (topology/Hermes check first) + burnbox dashboard.
- Remote `vault_exec` recipes: env-only for now (Phase 2+ to extend).
- Optional: show `credential_type` on the entry-list badge (cosmetic).
