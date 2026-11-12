import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  CallToolResultSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { BrokerClient, brokerClient } from './broker-client.js';
import { runSshWithAgent, type BrokeredOp } from './ssh-agent.js';
import {
  validateGitRequest, resolveGitUrls, runGit, gitEnv, sshCommandFor, buildGitArgv, parseGitSshUrl,
} from './git-op.js';
import type { AgentRequest } from './http-broker.js';
import type { VaultEntry } from './types.js';
import { VERSION } from './version.js';
import { renderBody } from './render.js';
export { renderBody } from './render.js';

export { DIRECTIVE } from './directive.js';

// ── Three tools, and none of them returns a key ──────────────────────────────
//
// 1.0 is brokered only. vault_exec, vault_entry_get, vault_entry_inject_env, vault_rsync
// and vault_entry_forget handed the agent a key's value — in a command's environment, a
// file, or the tool result — and are retired with the hand-over mode on the server. What
// is left: list the entries, make a web call with a key (vault_call), or run ssh/rsync
// with a key the broker signs for (vault_ssh_exec). A removed name is "Unknown tool".

// ── Talking to the broker ─────────────────────────────────────────────────────
//
// There is no credential loading here any more, and that is the point of the phase.
//
// This process runs as the AGENT's uid. It used to open the per-agent socket, receive
// `{api_key, enc_key, vault_url}`, and derive `vault_key` in its own memory — so the uid
// split protected the store on disk and the broker's memory while the socket handed the
// key straight back. Every `entry_mode` check in this file ran here too, in the agent's
// own process, which is why `types.ts` described them as "enforced client-side".
//
// Now the socket serves operations. The checks that matter run in the broker; the ones
// left here are a faster, friendlier error and nothing more. Deleting every one of them
// must not change what an agent can obtain — that is acceptance check 3.5, and there is
// a test for it.

// ── Sandbox / demo mode ─────────────────────────────────────────────────────
// When WUNDERVAULT_MOCK=1, tool calls return representative DEMO responses
// instead of contacting the local wundervault-agent daemon. This exists so
// automated directory scanners / CI (e.g. Glama) can start the server with no
// daemon or credentials, exercise every tool, and validate the build. It is OFF
// by default and is never enabled in production, so the real vault path is
// untouched. Every response is explicitly labelled — no real secret is ever
// involved.
const MOCK_MODE = process.env.WUNDERVAULT_MOCK === '1' || process.env.WUNDERVAULT_MOCK === 'true';
const MOCK_NOTE = '\n\n[DEMO MODE — WUNDERVAULT_MOCK is set; no real vault was contacted and no real secret was used.]';

/** An admin session's command may run only until its admin access ends (site SPEC-admin-access D7). */
export function adminTimeoutMs(opened: Record<string, unknown>, timeoutMs: number): number {
  const until = Date.parse(String(opened.admin_until ?? ''));
  if (!Number.isFinite(until)) return timeoutMs;
  return Math.max(1, Math.min(timeoutMs, until - Date.now()));
}

export const ADMIN_ENDED = 'Admin access ended, so the connection was closed. Ask your owner to allow admin access again if you need more time.';

/**
 * While an admin command runs, ask the helper app every 3 s whether its signing session is
 * still open; when it is not (End now, done, the time is up), abort, which kills the command
 * and its connection. A plain session gets a no-op watcher.
 */
export const SESSION_CLOSED = 'The helper app closed this connection (you said you were done, or the owner ended it).';

/**
 * While an SSH/git command runs, ask the helper app every 3 s whether its signing session is
 * still open, and stop the command when it is not (vault_done with "end", End now, the time is
 * up). An admin session also stops at admin_until even if the helper can't be reached.
 * Every session is watched, not only admin ones: vault_done closes them all, and a command left
 * running would make "closed" untrue (helper review round 1, F2). The helper is local, so a
 * poll is cheap.
 */
export function watchAdminSession(
  broker: { send(op: string, payload?: Record<string, unknown>): Promise<Record<string, unknown>> },
  opened: Record<string, unknown>, sessionId: string, everyMs = 3_000,
): { signal: AbortSignal; stop(): void } {
  const ac = new AbortController();
  const admin = typeof opened.admin_until === 'string';
  const until = admin ? Date.parse(opened.admin_until as string) : NaN;
  const end = Number.isFinite(until) ? setTimeout(() => ac.abort(ADMIN_ENDED), Math.max(1, until - Date.now())) : undefined;
  const poll = setInterval(() => {
    broker.send('ssh_agent_status', { session_id: sessionId }).then((st) => {
      if (st && st.open === false) ac.abort(admin ? ADMIN_ENDED : SESSION_CLOSED);
    }, () => { /* an admin session is still bounded by its end timer */ });
  }, everyMs);
  (poll as unknown as { unref?: () => void }).unref?.();
  return { signal: ac.signal, stop() { if (end) clearTimeout(end); clearInterval(poll); } };
}

function mockToolResult(name: string, args: Record<string, any>) {
  switch (name) {
    case 'vault_entries_list':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `Vault entries (4):\n  [demo-0001]  DEMO_API_KEY  (tier: 1, web service)\n  [demo-0002]  DEMO_SSH_KEY  (tier: 1, SSH)\n`
        + `  [demo-0003]  DEMO_WALLET  (tier: 1, wallet)\n  [demo-0004]  DEMO_SIGNING_KEY  (tier: 2, signing key)${MOCK_NOTE}` }] });
    case 'vault_ssh_exec':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ Ran on ${args.destination ?? 'demo-host'} (exit 0). 1 signature, key never left the server.${MOCK_NOTE}` }] });
    case 'vault_call':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ ${args.operation_id ?? args.request?.method ?? 'demo.op'} returned 200. Credential was used, not disclosed.${MOCK_NOTE}` }] });
    case 'vault_new_key':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `Demo made a new key. It went straight into the owner's vault as "${args.save_as ?? 'new key'}" and is waiting for the owner. You were not given the key.${MOCK_NOTE}` }] });
    case 'vault_pay':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ Paid 0.01 USDC on base-sepolia inside the owner's rules. Send this header when you retry: `
        + `PAYMENT-SIGNATURE: demo-payment-header. The wallet key never left the broker.${MOCK_NOTE}` }] });
    case 'vault_done':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `Done. The owner's approvals for this agent were ended.${MOCK_NOTE}` }] });
    case 'vault_sign':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ Signed after the owner approved. signature: ZGVtby1zaWduYXR1cmU=  public_key: ZGVtby1wdWJsaWMta2V5  `
        + `algorithm: ed25519. The signing key never left the broker.${MOCK_NOTE}` }] });
    case 'vault_git':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ git ${args.subcommand ?? 'push'} completed (exit 0). 1 signature; the key never left the broker.${MOCK_NOTE}` }] });
    case 'vault_2fa_code':
      return CallToolResultSchema.parse({ content: [{ type: 'text', text:
        `✅ Authenticator code: 123456 (valid for 25 more seconds). The setup key never left the broker.${MOCK_NOTE}` }] });
    default:
      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `Unknown tool: ${name}${MOCK_NOTE}` }], isError: true });
  }
}

// ── Server Factory ─────────────────────────────────────────────────────────────

export function createServer(args: { url?: string } = {}) {
  // `--url` no longer decides where the vault is, and that is deliberate rather than an
  // oversight. The vault URL is part of the credential the broker holds; letting this
  // process override it would let an agent point its own broker-fetched identity at a
  // server the agent chose — which is the same attack the enrolment origin allowlist
  // exists to stop, one layer down. It is ignored loudly rather than silently, because a
  // flag that appears to work and does nothing is worse than one that is refused.
  if (args.url) {
    process.stderr.write(
      `[wundervault] --url is ignored: the vault URL comes from the broker, with the\n`
      + `[wundervault] credential it belongs to. Set WUNDERVAULT_SETUP_ORIGIN on the broker\n`
      + `[wundervault] for a self-hosted install.\n`);
  }

  const server = new Server(
    { name: 'wundervault-mcp', version: VERSION },
    { capabilities: { tools: {} } },
  );

  // ── Tool Definitions ──────────────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'vault_done',
        description: (
          'Call this when you have finished the task your owner gave you. It tells the vault you are done, '
          + 'which (by your owner\'s setting) ends the time-limited approvals they gave you, so nothing stays '
          + 'open after the work, including admin access and any SSH connection it opened. It can only end '
          + 'approvals, never extend them. Takes no arguments.'
        ),
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'vault_entries_list',
        description: (
          'List the vault entries this agent may use. For each: its ID, name, tier, what kind of secret '
          + 'it is — web-service (vault_call), SSH (vault_ssh_exec), wallet (vault_pay) or signing '
          + 'key (vault_sign) — and any signed operations it offers. Never a secret\'s value — no tool returns one.'
        ),
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'vault_call',
        description: (
          'Call a web service with a vaulted secret that is never returned to you: the broker '
          + 'attaches the secret, sends the request and gives you the answer with the secret removed.\n\n'
          + 'Two ways to call. Describe the request yourself with `request` (origin, method, path, '
          + 'and optional query, body and your own headers). Or run a named operation the owner '
          + 'defined, with `operation_id` and typed `args`: the operation fixes the origin and '
          + 'route, returns only the fields it permits, and is signed with a key derived from the '
          + 'secret itself, so a definition altered in transit is refused. vault_entries_list '
          + 'shows which operations an entry offers.\n\n'
          + 'Either way the entry decides how the secret is attached (a header, a query parameter, a '
          + 'username and password, or part of the web address), and you never see the secret. '
          + 'A key the owner saved without saying how it is sent is refused with NEEDS_PLACEMENT the first '
          + 'time at an address: follow the service\'s own docs and propose it with request.send_as '
          + '{in:"header"|"query", name, template:"... {secret} ..."} ({secret} exactly once). The owner '
          + 'approves it once for that address; later calls there go straight through.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the credential.' },
            operation_id: { type: 'string', description: 'A signed operation on the entry. Use this OR request, not both.' },
            args: { type: 'object', description: 'Typed arguments for operation_id, checked against its schema.' },
            request: {
              type: 'object',
              description: 'Describe the call yourself: {origin:{scheme,host,port}, method, path, body?, query?, headers?}. '
                + 'body: an object or array is sent as JSON; a string is sent as written (set content-type in '
                + 'headers, e.g. application/x-www-form-urlencoded). headers: your own, such as user-agent or an '
                + 'API version; the header that carries the secret, and framing headers, are refused. '
                + 'If the entry keeps its secret in the web address (Telegram, webhooks), path is only what comes '
                + 'AFTER the secret, e.g. /sendMessage, or / for the stored address as is. '
                + 'Tier 1 secrets proceed and are logged. Tier 2 secrets are refused until the owner approves '
                + 'this exact origin, method and path; the approval covers whatever headers and body it carries. '
                + 'STAMPED keys (AWS, X, SnapTrade, exchanges) never travel: add request.stamp describing how the '
                + 'service signs requests, either {builtin:"aws-sigv4", region, service}, '
                + '{builtin:"oauth1"} for OAuth 1.0a (X, Tumblr, Flickr; optional signature_method:"HMAC-SHA256" and '
                + 'realm for NetSuite; nonce, timestamp and the Authorization header are written for you; the owner '
                + 'stores the four values as {"api_key","api_secret","access_token","access_token_secret"}), or '
                + '{mac:"hmac-sha256"|"hmac-sha384"|"hmac-sha512", key:"utf8"|"base64"|"hex", message:[parts], '
                + 'encoding:"hex"|"base64"|"base64url", place:[{in:"header"|"query", name, value:"…{stamp}…"}]}. '
                + 'Parts: {text}, {var: method|path|query|path_and_query|body|host|key_id|body_json}, {header: name}, '
                + '{body_field: name}, {sha256:[parts]}, {sha512:[parts]}, {sha256_hex:[parts]}, {json:{name: part}} '
                + '(sorted keys, no spaces). Parts read the request before the stamp is placed; put timestamps and '
                + 'nonces in the request yourself. place values may use {stamp} and {key_id}. The owner approves '
                + 'each recipe once per address; the first call waits for that. '
                + 'STORED LOGINS (a username and password, e.g. a router or a self-hosted app whose API wants you to '
                + 'sign in first): add request.sign_in = {login:{method:"POST"|"PUT", path, body_format:"json"|"form", '
                + 'body (use "{{username}}" and "{{password}}" where they go)}, session_from:{cookie:name}|{json:"a.b"}|'
                + '{header:name}, send_session_as:{cookie:name}|{header:name, template:"Bearer {{session}}"}, '
                + 'signed_out_when?:[401], expires_after_seconds?}. The broker signs in, keeps the session, and sends '
                + 'it on this and later calls; you never see the password or the session. The owner approves each '
                + 'sign-in once per address. A device on the owner\'s own network with its own (self-signed) '
                + 'certificate: add request.trust_certificate:true; the owner approves that exact certificate.',
            },
            purpose: { type: 'string', description: 'Why this is needed (audit log).' },
          },
          required: ['entry_id', 'purpose'],
        },
      },
      {
        name: 'vault_new_key',
        description: (
          'Make a NEW key at a service (for example a new API key at Resend or Cloudflare), using a vaulted key that is '
          + 'allowed to create keys there. The helper sends your request, takes the new key out of the answer and puts it '
          + "straight into the owner's vault, where it waits for the owner. You never see the new key: you get its id and "
          + 'name at the service. No agent can use it until the owner saves it with their passkey and sets it up, so tell '
          + 'the owner it is waiting under Needs you.\n\n'
          + 'Works only at these exact addresses (POST): '
          + 'Resend https://api.resend.com/api-keys; '
          + 'Cloudflare https://api.cloudflare.com/client/v4/user/tokens and /client/v4/accounts/{account_id}/tokens; '
          + 'SendGrid https://api.sendgrid.com/v3/api_keys; '
          + 'OpenAI https://api.openai.com/v1/organization/admin_api_keys and /v1/organization/projects/{project_id}/service_accounts; '
          + 'Twilio https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Keys.json; '
          + 'OpenRouter https://openrouter.ai/api/v1/keys. '
          + 'vault_call refuses these addresses. Anywhere else, the owner makes the key and adds it to the vault by hand.\n\n'
          + 'ROTATING a key: pass replaces_entry_id (the secret the new key replaces). The order is: (0) list the keys at the '
          + 'service and note the id of the OLD key, the one in use now; (1) vault_new_key, giving the new key the same permissions; '
          + '(2) tell the owner and wait until they press Replace; (3) make a harmless call with that secret to prove the new '
          + 'value works; (4) only then delete the OLD key at the service with vault_call (DELETE, by the OLD id you noted, never '
          + 'the id vault_new_key returned); (5) tell the owner. Never delete the old key before the new one has worked. '
          + 'Rolling a token in place (Cloudflare PUT .../tokens/{token_id}/value) is refused: it ends the old value at once.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the key that is allowed to create keys at the service.' },
            request: {
              type: 'object',
              description: 'As for vault_call: {origin:{scheme:"https",host,port:443}, method:"POST", path, body?, headers?}. '
                + 'The body is what the service wants for a new key (its name, permissions).',
            },
            save_as: { type: 'string', description: 'Name for the new secret in the vault, 1 to 80 characters.' },
            replaces_entry_id: { type: 'string', description: 'Optional. The entry id of the secret this new key replaces (one you have). The owner can then replace its value in one step; its name, rules and agents stay as they are.' },
            purpose: { type: 'string', description: 'Why this is needed (audit log, and shown to the owner).' },
          },
          required: ['entry_id', 'request', 'save_as', 'purpose'],
        },
      },
      {
        name: 'vault_pay',
        description: (
          'Pay an x402 "402 Payment Required" from a vaulted wallet whose key is never returned to you. '
          + 'Pass the 402 reply\'s PAYMENT-REQUIRED header (or the decoded JSON, or a v1 402 body) as '
          + 'payment_required; you get back the header to send when you retry the same request. USDC only, '
          + 'on Base, Base Sepolia, Solana and Solana devnet. Payments inside the owner\'s rules (allowed '
          + 'payees, a daily limit) are signed at once; anything else waits for the owner to approve, and '
          + 'if they have not answered yet, call again with the same payment to keep waiting.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the wallet.' },
            payment_required: { description: 'The PAYMENT-REQUIRED header value (base64), or the decoded object.' },
            accept_index: { type: 'number', description: 'Which offer in accepts[] to pay, when the merchant makes more than one.' },
            purpose: { type: 'string', description: 'Why this payment is needed. The owner sees it if they are asked.' },
          },
          required: ['entry_id', 'payment_required', 'purpose'],
        },
      },
      {
        name: 'vault_git',
        description: (
          'Run git push, pull, fetch, clone or ls-remote over SSH with a vaulted SSH key that never '
          + 'leaves the broker. Every address git would connect to (including a separate push address '
          + 'and any rewrite in git config) must be a server approved for the entry, or nothing '
          + 'connects; for a key saved without servers, the first use of a new server asks the owner. '
          + 'Only SSH remotes; no submodules, no hooks during the run. Linux and macOS only.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the SSH key.' },
            purpose: { type: 'string', description: 'Why (activity log).' },
            subcommand: { type: 'string', enum: ['push', 'pull', 'fetch', 'clone', 'ls-remote'] },
            repo_dir: { type: 'string', description: 'The local repository (for clone: the folder to clone into).' },
            remote: { type: 'string', description: 'Named remote, e.g. origin. Required except for clone.' },
            url: { type: 'string', description: 'clone only: the SSH address, e.g. git@github.com:owner/repo.git.' },
            target_dir: { type: 'string', description: 'clone only: folder name to create inside repo_dir.' },
            refspecs: { type: 'array', items: { type: 'string' }, description: 'push/pull/fetch: branches or refspecs, e.g. ["main"].' },
            flags: { type: 'array', items: { type: 'string' }, description: 'Allowed: push --force-with-lease --tags --set-upstream --dry-run --delete --follow-tags; pull --ff-only --rebase --no-rebase; fetch --tags --prune --dry-run --depth=N; clone --depth=N --branch=NAME --single-branch --no-checkout; ls-remote --heads --tags.' },
            timeout_seconds: { type: 'number', description: 'Default 120, at most 870.' },
          },
          required: ['entry_id', 'purpose', 'subcommand', 'repo_dir'],
        },
      },
      {
        name: 'vault_2fa_code',
        description: (
          'Get the current authenticator-app code (the 6-digit 2FA code) for a vaulted login or Authenticator code secret, to type into a '
          + 'sign-in that asks for one. You get the 6- or 8-digit code and how many seconds it stays '
          + 'valid; the seed that makes the codes never leaves the broker. If the code was about to '
          + 'expire, this waits up to 5 seconds and returns the next one.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the authenticator setup key (an Authenticator code secret, or a login with its Authenticator setup key filled). Only authenticator-app codes: not text-message or email codes, not passkeys.' },
            purpose: { type: 'string', description: 'What you are signing in to, and why. The owner sees it.' },
          },
          required: ['entry_id', 'purpose'],
        },
      },
      {
        name: 'vault_sign',
        description: (
          'Sign data with a vaulted signing key whose value is never returned to you. Every signature '
          + 'is approved by the owner, who is shown the data (in full when it is text up to 64 KiB) and '
          + 'its sha256. Returns the signature (base64), the public key and the algorithm. At most 256 KiB.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the signing key.' },
            data: { type: 'string', description: 'The bytes to sign, as text or encoded.' },
            encoding: { type: 'string', enum: ['utf8', 'base64', 'hex'], description: 'How data is written. Default utf8.' },
            purpose: { type: 'string', description: 'What this signature is for. The owner sees it.' },
          },
          required: ['entry_id', 'data', 'purpose'],
        },
      },
      {
        name: 'vault_ssh_exec',
        description: (
          'Run a command on a remote host, or rsync files to it, using a vaulted SSH key '
          + 'that is never written to disk and never returned to you.\n\n'
          + 'Admin keys: a server can have an everyday key (use it by default: reading code, health, logs) '
          + 'and an admin key (for changes: deploys, settings, containers). The admin key works only while '
          + 'your owner has allowed admin access (5, 15 or 60 minutes); without it you get '
          + 'ADMIN_ACCESS_REQUIRED and your owner is asked. The connection is closed when admin access ends. '
          + 'Call vault_done when you have finished.\n\n'
          + 'The key stays inside the broker, which answers signature requests over a private '
          + 'ssh-agent socket that exists only for the duration of this call. You choose the '
          + 'remote command; you do not get the key.\n\n'
          + 'The destination is checked against the servers approved for the entry, and the '
          + 'ssh command line is constructed here — naming a different host inside remote_argv '
          + 'does not change where it connects. A key the owner saved without servers asks the owner '
          + 'the first time it connects to a new user@host[:port] (write it exactly that way; the call '
          + 'waits for the answer), and that server\'s identity is remembered: a different machine at the '
          + 'same address is refused.\n\n'
          + 'Every signature is audited with the key fingerprint and the authorised host.\n\n'
          + 'ADMIN (sudo) work on a computer: use the owner\'s admin key (an SSH key made on that computer '
          + 'with its admin-key script) with destination root@localhost and run the command '
          + 'directly — no sudo, no password. You never get the sudo password; it is not in the vault for you.'
        ),
        inputSchema: {
          type: 'object',
          properties: {
            entry_id: { type: 'string', description: 'Vault entry holding the SSH private key (ed25519, unencrypted).' },
            destination: { type: 'string', description: 'Remote destination, [user@]host. The host part must be in the entry\'s ssh_hosts.' },
            purpose: { type: 'string', description: 'Why this is needed (audit log).' },
            remote_argv: {
              type: 'array', items: { type: 'string' },
              description: 'Command and arguments to run on the remote host. An array, run without a shell. Omit when using rsync_args.',
            },
            rsync_args: {
              type: 'array', items: { type: 'string' },
              description: 'rsync arguments instead of a remote command. Every [user@]host:path argument is checked against the same allowlist.',
            },
            timeout_seconds: { type: 'number', description: 'Default 120.' },
            working_dir: { type: 'string', description: 'Local working directory for rsync source paths.' },
          },
          required: ['entry_id', 'destination', 'purpose'],
        },
      },
    ],
  }));

  // ── Tool Call Handler ─────────────────────────────────────────────────────

  server.setRequestHandler(CallToolRequestSchema, async (
    request,
    _extra: RequestHandlerExtra<any, any>,
  ) => {
    if (MOCK_MODE) {
      return mockToolResult(request.params.name, (request.params.arguments ?? {}) as Record<string, any>);
    }
    let broker: BrokerClient;
    try {
      broker = brokerClient();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `❌ Vault unavailable: ${msg}` }] });
    }

    try {
      if (request.params.name === 'vault_done') {
        const data = await broker.sendOrThrow('done');
        const n = Number(data.ended ?? 0);
        const text = data.setting === 'keep'
          ? 'Noted. Your owner keeps approvals until their timers run out, so nothing was ended.'
          : `Done. ${n} approval${n === 1 ? '' : 's'} the owner gave you ${n === 1 ? 'was' : 'were'} ended; `
            + 'the next use of an "ask me first" secret will ask again.'
            + (Number(data.ssh_closed ?? 0) > 0 ? ` ${Number(data.ssh_closed)} open SSH connection(s) were closed.` : '');
        return CallToolResultSchema.parse({ content: [{ type: 'text', text }] });
      }

      if (request.params.name === 'vault_entries_list') {
        const data = await broker.sendOrThrow('list_entries');
        const entries: VaultEntry[] = (data.entries as VaultEntry[]) ?? [];
        if (!entries.length) {
          return CallToolResultSchema.parse({ content: [{ type: 'text', text: 'Vault is empty — no entries available.' }] });
        }
        const lines = [`Vault entries (${entries.length}):\n`];
        for (const e of entries) {
          const use = e.entry_mode === 'BROKER_SSH_AGENT' ? 'SSH key → vault_ssh_exec'
            : e.entry_mode === 'BROKER_HTTP' ? 'web-service secret → vault_call'
            : e.entry_mode === 'BROKER_WALLET' ? 'wallet → vault_pay'
            : e.entry_mode === 'BROKER_SIGN' ? 'signing key → vault_sign'
            : 'not usable until the owner sets how it is used';
          const ops = e.operations?.length ? `; operations: ${e.operations.join(', ')}` : '';
          const admin = (e as { admin_access?: boolean }).admin_access === true
            ? '; ADMIN key: needs admin access, which your owner allows for 5-60 minutes; use an everyday key for anything that only reads' : '';
          lines.push(`  [${e.id}]  ${e.secret_name}  (tier: ${e.access_tier ?? 'read'}; ${use}${ops}${admin})`);
        }
        return CallToolResultSchema.parse({ content: [{ type: 'text', text: lines.join('\n') }] });
      }

      if (request.params.name === 'vault_call') {
        const a = request.params.arguments as Record<string, unknown>;
        const entry_id = String(a?.entry_id ?? '');
        const operation_id = String(a?.operation_id ?? '');
        const purpose = String(a?.purpose ?? '');
        const callArgs = (a?.args ?? {}) as Record<string, unknown>;
        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
        const agentReq = a?.request as AgentRequest | undefined;
        if (!entry_id || !purpose) return fail('vault_call needs entry_id and purpose.');
        if (!operation_id && !agentReq) return fail('vault_call needs either operation_id or request.');
        if (operation_id && agentReq) return fail('Give either operation_id or request, not both.');

        // THE WHOLE OPERATION HAPPENS IN THE BROKER.
        //
        // Everything that used to be here — fetching the entry, unwrapping the vault key,
        // decrypting the credential, verifying the signed operation definition, the tier
        // gate, the tier-2 wait, the destination record, the SSRF guard and the outbound
        // request — ran in this process, as the agent's uid, holding the plaintext.
        // `SPEC-tiered-broker.md` said of tier 1 that "the key never reaches the agent"; it
        // was describing this code, and it was not true of it.
        //
        // What comes back is a status, a body and a tier. No credential crosses the
        // socket in either direction.
        const r = await broker.send('call', {
          entry_id,
          purpose: purpose.slice(0, 200),
          ...(operation_id ? { operation_id } : {}),
          ...(operation_id ? { args: callArgs } : {}),
          ...(agentReq ? { request: agentReq } : {}),
        });
        if (r.error) return fail(String(r.error));

        return CallToolResultSchema.parse({
          content: [{ type: 'text', text:
            `✅ ${r.label} → HTTP ${r.status} (tier ${r.tier}). The credential was used here, not returned to you.\n`
            + `${renderBody(r.body)}${r.notice ? `\n\n${r.notice}` : ''}` }],
        });
      }

      if (request.params.name === 'vault_new_key') {
        const a = (request.params.arguments ?? {}) as Record<string, unknown>;
        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
        const entry_id = String(a.entry_id ?? '');
        const purpose = String(a.purpose ?? '');
        const save_as = typeof a.save_as === 'string' ? a.save_as : '';
        if (!entry_id || !purpose || !save_as || !a.request || typeof a.request !== 'object') {
          return fail('vault_new_key needs entry_id, request, save_as and purpose.');
        }
        const r = await broker.send('new_key', {
          entry_id, purpose: purpose.slice(0, 200), request: a.request, save_as,
          ...(typeof a.replaces_entry_id === 'string' && a.replaces_entry_id ? { replaces_entry_id: a.replaces_entry_id } : {}),
        });
        if (r.error) return fail(String(r.error));
        return CallToolResultSchema.parse({
          content: [{ type: 'text', text: `${r.notice ?? ''}\n${renderBody(r.body)}`.trim() }],
        });
      }

      if (request.params.name === 'vault_pay' || request.params.name === 'vault_sign') {
        const a = (request.params.arguments ?? {}) as Record<string, unknown>;
        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
        const entry_id = String(a.entry_id ?? '');
        const purpose = String(a.purpose ?? '');
        if (!entry_id || !purpose) return fail(`${request.params.name} needs entry_id and purpose.`);
        if (request.params.name === 'vault_pay') {
          if (a.payment_required === undefined) return fail('vault_pay needs payment_required.');
          const r = await broker.send('pay', {
            entry_id, purpose: purpose.slice(0, 200), payment_required: a.payment_required,
            ...(a.accept_index !== undefined ? { accept_index: a.accept_index } : {}),
          });
          if (r.error) return fail(String(r.error));
          return CallToolResultSchema.parse({ content: [{ type: 'text', text:
            `✅ Signed a payment of ${r.amount_usdc} USDC on ${r.network} to ${r.payee}`
            + `${r.inside_rules ? ' (inside the owner\'s rules)' : ' (approved by the owner)'}. `
            + `Retry your request with this header:\n${r.header}: ${r.value}` }] });
        }
        if (typeof a.data !== 'string') return fail('vault_sign needs data as a string.');
        const r = await broker.send('sign', {
          entry_id, purpose: purpose.slice(0, 200), data: a.data, ...(a.encoding ? { encoding: a.encoding } : {}),
        });
        if (r.error) return fail(String(r.error));
        return CallToolResultSchema.parse({ content: [{ type: 'text', text:
          `✅ Signed (${r.algorithm}). The key was used in the broker, not returned to you.\n`
          + `signature: ${r.signature}\npublic key: ${r.public_key}` }] });
      }

      if (request.params.name === 'vault_git') {
        const a = (request.params.arguments ?? {}) as Record<string, unknown>;
        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
        const entry_id = String(a.entry_id ?? '');
        const purpose = String(a.purpose ?? '');
        const repoDir = typeof a.repo_dir === 'string' ? a.repo_dir : '';
        if (!entry_id || !purpose || !repoDir) return fail('vault_git needs entry_id, purpose, subcommand and repo_dir.');
        const { entry_id: _e, purpose: _p, repo_dir: _r, timeout_seconds: _t, ...reqRaw } = a;
        const v = validateGitRequest(reqRaw);
        if (!v.ok) return fail(`Refused: ${v.reason}. Nothing connected.`);
        // 870, not 900: the signing session lives timeout + 30 s and the broker caps it at 900,
        // so git can never outlast the session that signs for it (round 1, B4).
        const timeoutSeconds = Math.max(1, Math.min(Number(a.timeout_seconds ?? 120) || 120, 870));
        // Resolved with git's own rules (pushurl, insteadOf) and with ssh disabled, so
        // working out WHERE git would go cannot itself connect anywhere.
        const resolved = await resolveGitUrls(v.req, repoDir, runGit, gitEnv(process.env, 'false'));
        if (!resolved.ok) return fail(`Refused: ${resolved.reason}. Nothing connected.`);
        const first = parseGitSshUrl(resolved.urls[0]);
        const destination = first.ok ? (first.user ? `${first.user}@${first.host}` : first.host) : '';
        const op: BrokeredOp = { kind: 'git', destination, urls: resolved.urls, subcommand: v.req.subcommand };
        const opened = await broker.send('ssh_agent_open', {
          entry_id, purpose: purpose.slice(0, 200), op_spec: op, ttl_seconds: timeoutSeconds + 30,
        });
        if (opened.error) return fail(String(opened.error));
        const sessionId = String(opened.session_id ?? '');
        const watch = watchAdminSession(broker, opened, sessionId);
        let r: { code: number; stdout: string; stderr: string };
        let signs = 0;
        try {
          r = await runGit(
            buildGitArgv(v.req), repoDir,
            gitEnv(process.env, sshCommandFor(String(opened.socket_path ?? ''), String(opened.public_key_path ?? ''),
              typeof opened.known_hosts_path === 'string' ? opened.known_hosts_path : undefined)),
            adminTimeoutMs(opened, timeoutSeconds * 1000),
            watch.signal,
          );
        } finally {
          watch.stop();
          const closed = await broker.send('ssh_agent_close', { session_id: sessionId }).catch(() => ({ signs: 0 }));
          signs = Number((closed as { signs?: unknown }).signs ?? 0);
        }
        const head = r.code === 0
          ? `✅ git ${v.req.subcommand} completed (exit 0).`
          : `❌ git ${v.req.subcommand} failed (exit ${r.code}).`;
        return CallToolResultSchema.parse({
          content: [{ type: 'text', text:
            `${head}\n${signs} signature(s) for ${String(opened.audited_host ?? destination)}; the key never left the broker.\n`
            + `--- stdout ---\n${r.stdout || '(empty)'}\n--- stderr ---\n${r.stderr || '(empty)'}` }],
          isError: r.code !== 0,
        });
      }

      if (request.params.name === 'vault_2fa_code') {
        const a = (request.params.arguments ?? {}) as Record<string, unknown>;
        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
        const entry_id = String(a.entry_id ?? '');
        const purpose = String(a.purpose ?? '');
        if (!entry_id || !purpose) return fail('vault_2fa_code needs entry_id and purpose.');
        const r = await broker.send('2fa_code', { entry_id, purpose: purpose.slice(0, 200) });
        if (r.error) return fail(String(r.error));
        return CallToolResultSchema.parse({ content: [{ type: 'text', text:
          `✅ Authenticator code: ${r.code} (valid for ${r.expires_in_seconds} more seconds). The setup key never left the broker.` }] });
      }

      if (request.params.name === 'vault_ssh_exec') {
        const entry_id = String((request.params.arguments as Record<string, unknown>)?.entry_id ?? '');
        const destination = String((request.params.arguments as Record<string, unknown>)?.destination ?? '');
        const purpose = String((request.params.arguments as Record<string, unknown>)?.purpose ?? '');
        const remoteArgvRaw = (request.params.arguments as Record<string, unknown>)?.remote_argv;
        const rsyncArgsRaw = (request.params.arguments as Record<string, unknown>)?.rsync_args;
        const timeoutSeconds = Number((request.params.arguments as Record<string, unknown>)?.timeout_seconds ?? 120);
        const workingDir = (request.params.arguments as Record<string, unknown>)?.working_dir as string | undefined;

        const fail = (text: string) => CallToolResultSchema.parse({ content: [{ type: 'text', text }], isError: true });
        if (!entry_id || !destination || !purpose) {
          return fail('vault_ssh_exec needs entry_id, destination and purpose.');
        }

        const remoteArgv = Array.isArray(remoteArgvRaw) ? remoteArgvRaw.map(String) : undefined;
        const rsyncArgs = Array.isArray(rsyncArgsRaw) ? rsyncArgsRaw.map(String) : undefined;
        if ((remoteArgv && rsyncArgs) || (!remoteArgv && !rsyncArgs)) {
          return fail('Give exactly one of remote_argv or rsync_args.');
        }

        const op: BrokeredOp = remoteArgv
          ? { kind: 'ssh', destination, remoteArgv }
          : { kind: 'rsync', destination, rsyncArgs: rsyncArgs as string[] };

        // THE KEY STAYS WITH THE BROKER AND THE COMMAND STAYS HERE.
        //
        // This used to fetch the entry, decrypt the private key into this process, and
        // run a signing agent on its own socket — so "the key never left this server" was
        // true of the network and false of the machine: the agent held the key.
        //
        // Now the broker loads the key, checks the destination against the entry's
        // ssh_hosts allowlist (which used to be checked HERE, by the caller, about
        // itself), and serves the ssh-agent protocol on a socket of its own. `ssh` runs
        // in this process, as this uid, and authenticates by asking the broker to sign.
        //
        // The command deliberately does NOT move to the broker. A broker that runs a
        // caller-supplied command hands that caller code execution as the uid that owns
        // /var/lib/wundervault, which is every credential on this machine.
        const opened = await broker.send('ssh_agent_open', {
          entry_id,
          purpose: purpose.slice(0, 200),
          op_spec: op,
          ttl_seconds: Math.max(1, Math.min(timeoutSeconds, 900)) + 30,
        });
        if (opened.error) return fail(String(opened.error));

        const sessionId = String(opened.session_id ?? '');
        const watch = watchAdminSession(broker, opened, sessionId);
        let r: { exitCode: number; stdout: string; stderr: string };
        let signs = 0;
        let endedNote = '';
        try {
          r = await runSshWithAgent({
            signal: watch.signal,
            op,
            socketPath: String(opened.socket_path ?? ''),
            publicKeyPath: String(opened.public_key_path ?? ''),
            ...(typeof opened.known_hosts_path === 'string' ? { knownHostsPath: opened.known_hosts_path } : {}),
            cwd: workingDir,
            timeoutMs: adminTimeoutMs(opened, Math.max(1, Math.min(timeoutSeconds, 900)) * 1000),
          });
        } finally {
          watch.stop();
          // iamwyse real run: End now cuts the server side first, so ssh exits 255 before the
          // watch's next poll and the agent saw only "exit 255". Ask once, before closing, so a
          // session the owner ended says so.
          if (typeof opened.admin_until === 'string' && !watch.signal.aborted) {
            const st = await broker.send('ssh_agent_status', { session_id: sessionId }).catch(() => null);
            if (st && st.open === false && st.ended_by) endedNote = `\n${ADMIN_ENDED}`;
          }
          // Always closed, including on a throw and on a timeout. The broker also expires
          // the session on its own timer, because a client that dies between opening and
          // closing must not leave an ambient signing socket behind — a close that only
          // happens when the caller remembers is not a close.
          const closed = await broker.send('ssh_agent_close', { session_id: sessionId })
            .catch(() => ({ signs: 0 }));
          signs = Number((closed as { signs?: unknown }).signs ?? 0);
        }

        const head = r.exitCode === 0
          ? `✅ ${op.kind} on ${destination} completed (exit 0).`
          : `❌ ${op.kind} on ${destination} failed (exit ${r.exitCode}).${r.exitCode !== 0 ? endedNote : ''}`;
        return CallToolResultSchema.parse({
          content: [{ type: 'text', text:
            `${head}\n${signs} signature(s); the key never left the broker.\n`
            + `--- stdout ---\n${r.stdout || '(empty)'}\n--- stderr ---\n${r.stderr || '(empty)'}` }],
          isError: r.exitCode !== 0,
        });
      }


      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `Unknown tool: ${request.params.name}` }] });

    } catch (err: unknown) {
      const status = (err as any)?.status;
      if (status === 401) {
        return CallToolResultSchema.parse({ content: [{ type: 'text', text: '❌ Unauthorized — agent credentials invalid or revoked.' }] });
      }
      if (status === 404) {
        return CallToolResultSchema.parse({ content: [{ type: 'text', text: '❌ Vault entry not found or not accessible.' }] });
      }
      const msg = err instanceof Error ? err.message : String(err);
      return CallToolResultSchema.parse({ content: [{ type: 'text', text: `❌ Error: ${msg}` }] });
    }
  });

  return server;
}
