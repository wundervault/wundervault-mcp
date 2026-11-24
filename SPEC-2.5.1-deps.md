# Helper 2.5.1 — security update (2026-11-14; server-script fix added 2026-11-23)

Scope: dependency update + (added 2026-11-23, owner's choice) a fix to the server scripts the helper
sends for server setup (packaging/server/wv-setup.sh, wv-check). No source (src/) change. Cut from
tag v2.5.0.

The server-script hole (found by the vault-jobs phase 1 review, 2026-11-23): setup, finalize,
remove-key and the change check read account key files AS ROOT, following links, and wrote
root-made temp files inside account .ssh folders. An account on a set-up server could (a) link its
key file to /etc/shadow and get pieces of it into the change check's report, (b) swap a root-made
temp file for a link and have root write to, chown and chmod any file. Only reachable by someone
who already has an account on that server, and only when the owner runs setup / remove-key or a
change check runs.

## Acceptance checks
1. `npm audit --omit=dev` reports 0 vulnerabilities (was 10: 1 critical, 6 high, 3 moderate).
2. package.json requires `@modelcontextprotocol/sdk` >= 1.32.2 (the version that clears every SDK advisory), so `npm install -g` users also get the fixed SDK.
3. The lockfile pins the fixed versions; the release package (scripts/pack-app.mjs: `npm ci --omit=dev` from the lockfile) contains SDK 1.32.2 and zod >= 4.6.6, and the closure check passes.
4. No src/ file changed; `tsc` builds clean.
5. Full test suite passes.
6. MCP protocol output (initialize, tools/list including every tool's input schema, a tools/call, an unknown method) is byte-identical to 2.5.0.
7. Version is 2.5.1 in package.json, package-lock.json, server.json; CHANGELOG has a 2.5.1 entry that states accurately what changed and why.
9. Every read and write of an account's authorized_keys by the server scripts runs AS THAT ACCOUNT
   (runuser, else setpriv); root never opens, creates, chowns or chmods a file in an account's folder;
   root's working copies are in /var/lib/wundervault (root 700).
10. Real sshd (packaging/server/test-setup.sh): a key file linked to /etc/shadow and a root-only file at
   the key path show nothing in the report (the root-only one is reported unreadable); a FIFO does not
   hang the report; remove-key removes a key as the account and still refuses the emergency line;
   remove-key refuses a linked key file and leaves its target unchanged.
11. CHANGELOG says plainly that the change check on a server is fixed only after setup is re-run there.
8. Dev-only advisories (vitest/esbuild/tinypool, not shipped) are out of scope and stated as such.
