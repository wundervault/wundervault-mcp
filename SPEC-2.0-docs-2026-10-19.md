# SPEC — the version 2 docs say what version 2 does (2026-10-19)

At the 1.0 / MCP 2.0 cutover, the npm page, GitHub, Glama, Smithery and the agents that install
the server read these files. Until today they described version 1: six tools that hand the key to
a command (`vault_exec`, `vault_entry_get`, `vault_entry_inject_env`, `vault_rsync`), "Windows
does not yet" have a broker, `onboard.py` with a setup link, `--url` as an override. The site's
own MCP reference said "Three tools" though there are five, and llms.txt said keys are always sent
as a bearer token.

Files: `README.md`, `llms-install.md`, `README-AGENTS.md`, `RELEASE-HIGHLIGHTS.md` (one line),
`src/index.ts` (`--help` text only); on the site, `app/templates/mcp.html`, `app/static/llms.txt`,
one line of `LIMITATIONS.md`; and the OpenClaw skill staged in `burnbox/cutover/clawhub-skill-2.0/`
(published at the cutover, not before: local agents load the live copy and still run 1.x).

## Checks

- D1. Every tool named exists in `src/server.ts` (vault_entries_list, vault_call, vault_ssh_exec,
  vault_pay, vault_sign), every argument named exists in its schema, and none of the retired tools
  is described as available.
- D2. No claim is stronger than the code. In particular: for a web call the key DOES go to the
  service (only SSH and stamped keys never leave the broker); "ask me first" approves a
  destination + method + path, once or for a window, not an intention; Windows and macOS are beta;
  macOS and Windows lack Linux's sandboxing; Windows elevated administrators are inside the
  boundary; a store key without a TPM is not sealed against a disk copy plus root.
- D3. The install steps are the ones the site gives (`/quickstart`, `/install`): npm install @2,
  the per-OS broker installer, `sudo wundervault-agent --pair`, a claim code from the vault entered
  at `wundervault-agent --enrol`, the MCP config with only `WUNDERVAULT_AGENT_NAME`.
- D4. Error texts quoted for agents are the real ones the code prints.
- D5. Nothing tells an agent to accept a key, claim code or setup link in chat or on a command line.
- D6. Plain English up front, technical detail lower down (the site's voice rule); no jargon in the
  opening paragraph.
