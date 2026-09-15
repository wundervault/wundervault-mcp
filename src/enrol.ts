/**
 * Enrolment, done by the daemon instead of by the agent's own process.
 *
 * This is the piece that lets the uid split mean anything. Before it, the management
 * socket accepted `register_profile` from anyone who could reach it — and since agents run
 * as the same user as the person who owns them, "anyone who could reach it" included every
 * agent on the machine. An agent could register a name with a token it chose and then
 * collect that agent's credentials from its own socket. The boundary held for files and
 * memory and leaked at the front door.
 *
 * The fix is not a tighter local permission. There isn't one: the kernel cannot tell the
 * owner's shell from an agent running as the owner, so any lock the owner can open, an
 * agent can open. What the owner has that an agent does not is something from OUTSIDE the
 * machine — a setup link, issued by the server, to a person logged into the website.
 *
 * So the setup link is the authorisation, and the daemon redeems it itself:
 *
 *   https://wundervault.com/setup/agent/<token>#<passphrase>
 *                                        ^path          ^fragment, never sent to a server
 *
 *   1. GET  /api/setup/agent/<token>   -> the encrypted blob
 *   2. PBKDF2(passphrase) -> AES-256-GCM -> api_key + encryption_key
 *   3. POST /api/setup/agent/<token>/burn
 *
 * The client hands over a URL and gets back a name. The credentials exist only inside the
 * daemon and the file it owns — they are never in the address space of the process that
 * asked, which is an improvement on the pre-split world too, where onboard.py held them in
 * plaintext as the user.
 *
 * The parameters below are fixed by what the server already does (see onboard.py, which
 * this deliberately mirrors rather than reinvents). They are not ours to choose.
 */
import crypto from 'node:crypto';

const DEFAULT_ORIGIN = 'https://wundervault.com';

/**
 * Where a setup link is allowed to come from.
 *
 * Read from the daemon's environment, which after the uid split is set by the unit file.
 * That is the point: the caller hands over a URL, but it does not get to say which server
 * is trusted. `WUNDERVAULT_SETUP_ORIGIN` exists for self-hosted installs and for tests,
 * and in both cases it is set by whoever starts the daemon, never by whoever calls it.
 */
export function allowedOrigins(): string[] {
  const configured = process.env.WUNDERVAULT_SETUP_ORIGIN;
  if (!configured) return [DEFAULT_ORIGIN];
  return configured.split(',').map(o => o.trim()).filter(Boolean);
}

const PBKDF2_SALT = 'wv-agent-setup-v1';
const PBKDF2_ROUNDS = 100_000;
const UA = 'WunderVault-Agent-Daemon/1.0';
/** A credential blob is a couple of hundred bytes. This is three orders of magnitude of slack. */
const MAX_RESPONSE_BYTES = 256 * 1024;

export interface EnrolledCredentials {
  agent_name: string;
  agent_id: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
}

interface ParsedLink { baseUrl: string; token: string; passphrase: string; }

/**
 * Pull the three parts out of a setup link.
 *
 * The passphrase lives in the URL fragment precisely because browsers never transmit it,
 * so the server stores a blob it cannot itself read. That property is worth preserving on
 * this side of the wire too: it is why the passphrase is never put in a query string, a
 * header, or a log line here.
 */
export function parseSetupUrl(raw: string): ParsedLink {
  let u: URL;
  try { u = new URL(String(raw ?? '').trim()); }
  catch { throw new Error('That does not look like a setup link. Paste the whole URL, including the # at the end.'); }

  // THE ORIGIN IS THE WHOLE SECURITY PROPERTY, so it is checked against an allowlist the
  // caller cannot influence.
  //
  // The first version of this accepted any https origin, plus http on loopback so a test
  // could run a real server. That defeated the entire design in one line: a malicious
  // agent could start its own listener on 127.0.0.1, serve a blob it had encrypted with a
  // passphrase it chose, and hand the daemon `http://127.0.0.1:9999/setup/agent/x#p`. The
  // daemon would decrypt it perfectly, believe it, and register whatever profile the agent
  // named — including overwriting a real one. The "setup link an agent cannot obtain"
  // becomes a setup link an agent can simply mint.
  //
  // So: exactly one origin, from the DAEMON's own environment, which systemd sets and no
  // agent controls. The test override lives there too and is therefore unreachable by a
  // caller — an agent cannot set the daemon's environment any more than it can set its uid.
  // https everywhere except loopback, ON TOP of the allowlist. The allowlist replaced the
  // old protocol check outright, which quietly meant a configured origin could be plain
  // http to any host on the network — the token is a bearer credential in the URL path, so
  // that hands it to anything on the wire. Loopback stays permitted because a local
  // rehearsal against a development server is a real need and never leaves the machine.
  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(u.hostname);
  if (u.protocol !== 'https:' && !loopback) {
    throw new Error(`A setup link must be https. Got ${u.protocol.replace(':', '')}.`);
  }

  const allowed = allowedOrigins();
  if (!allowed.includes(u.origin)) {
    throw new Error(
      `A setup link must come from ${allowed.join(' or ')}. Got ${u.origin}.\n` +
      `A link from anywhere else is not a Wundervault setup link, whatever it looks like.`,
    );
  }

  const m = u.pathname.match(/\/setup\/agent\/([^/]+)\/?$/);
  if (!m) throw new Error('That URL has no setup token in it. Copy the link from the dashboard again.');

  const passphrase = decodeURIComponent(u.hash.replace(/^#/, ''));
  if (!passphrase) {
    throw new Error(
      'That link is missing the part after the #. It is the only thing that can decrypt ' +
      'your credentials, and it is never sent to the server — so a link without it is ' +
      'useless. Copy the whole URL.',
    );
  }
  return { baseUrl: u.origin, token: decodeURIComponent(m[1]), passphrase };
}

async function httpJson(url: string, method: 'GET' | 'POST'): Promise<any> {
  // `redirect: 'error'` rather than the default 'follow'. The setup token is a bearer
  // credential sitting in the URL PATH, so a 302 would hand it to whatever host the
  // response named — and this runs inside the process that holds every agent's
  // credentials. There is no legitimate reason for the setup endpoints to redirect, so
  // refusing is free, and the failure is visible rather than silent.
  // Bounded on both axes. This runs inside the process holding every agent's credentials,
  // so a server that never answers must not park a request there for ever, and one that
  // answers for ever must not be read into memory without limit.
  const res = await fetch(url, {
    method,
    headers: { 'User-Agent': UA },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) {
    const known: Record<number, string> = {
      404: 'That setup link is not valid. Check you copied all of it.',
      410: 'That setup link has already been used, or it has expired. ' +
           'Repair the agent in the dashboard to get a fresh one — it keeps the agent\'s ' +
           'existing vault access.',
    };
    throw new Error(known[res.status] ?? `The server answered ${res.status} for the setup link.`);
  }
  // `includes('json')` was not a media-type test: it accepted `text/notjson` and rejected
  // `Application/JSON`, which is the same string with different case and perfectly valid.
  // Parse the type properly — drop parameters, lowercase, then match exactly or on the
  // structured `+json` suffix.
  const ctype = String(res.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
  if (ctype !== 'application/json' && !ctype.endsWith('+json')) {
    // A captive portal or a proxy answering 200 with an HTML login page would otherwise
    // reach JSON.parse and surface as a confusing syntax error.
    throw new Error(`The setup link did not return JSON (content-type: ${ctype || 'none'}).`);
  }

  // A response with no declared length, or an absurd one, is refused before it is read.
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_RESPONSE_BYTES) {
    throw new Error(`The setup endpoint returned ${declared} bytes; refusing to read it.`);
  }
  const text = await res.text();
  if (text.length > MAX_RESPONSE_BYTES) {
    throw new Error('The setup endpoint returned more data than a credential blob can be.');
  }
  return JSON.parse(text);
}

/**
 * Ask the server which agent a link belongs to, redeeming nothing.
 *
 * The GET endpoint deliberately does not burn the token — the server's own comment says so,
 * because a link may be previewed. That lets enrolment learn the agent's name BEFORE it
 * commits to anything, which is what removes the two-step dance this used to require: mint
 * a token, enrol, discover the name from the reply, then swap the token back. That dance
 * had a window where a dropped connection left an agent registered under a token the
 * caller had not saved, and no way to recover it.
 */
export async function peekAgentName(rawUrl: string): Promise<string> {
  const { baseUrl, token } = parseSetupUrl(rawUrl);
  const server = await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}`, 'GET');
  return String(server?.agent_name ?? '');
}

/**
 * Redeem a setup link.
 *
 * The burn is a separate call AFTER the credentials are decrypted, and that order matters:
 * burning first would mean a wrong passphrase or a network blip consumed a single-use link
 * and left the agent with nothing, forcing another trip to the dashboard. Burning last
 * means the only way to lose the link is to have already succeeded with it.
 */
export async function redeemSetupLink(
  rawUrl: string,
): Promise<{ creds: EnrolledCredentials; burn: () => Promise<boolean> }> {
  const { baseUrl, token, passphrase } = parseSetupUrl(rawUrl);

  const server = await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}`, 'GET');
  if (!server?.encrypted_blob) throw new Error('The server returned no credentials for that link.');

  // base64url -> base64, then pad. The server emits the URL-safe alphabet.
  let b64 = String(server.encrypted_blob).replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  const blob = Buffer.from(b64, 'base64');
  if (blob.length < 29) throw new Error('The credential blob is too short to be valid.');

  const key = crypto.pbkdf2Sync(passphrase, PBKDF2_SALT, PBKDF2_ROUNDS, 32, 'sha256');
  let plain: Buffer;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    // GCM in this format carries its tag at the END of the ciphertext, the way the Python
    // AESGCM.decrypt() on the other side expects to find it.
    const ct = blob.subarray(12, blob.length - 16);
    decipher.setAuthTag(blob.subarray(blob.length - 16));
    plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error(
      'Could not decrypt those credentials — the part of the link after the # is wrong, ' +
      'or the link was mangled in transit. Nothing has been changed and the link is unused.',
    );
  }

  const raw = JSON.parse(plain.toString('utf8'));
  const creds: EnrolledCredentials = {
    agent_name: server.agent_name ?? 'unknown',
    agent_id: server.agent_id,
    api_key: raw.api_key ?? raw.agent_vault_api_key ?? '',
    enc_key: raw.encryption_key ?? raw.agent_encryption_key ?? '',
    vault_url: baseUrl,
  };
  if (!creds.api_key || !creds.enc_key) {
    throw new Error('The decrypted credentials are missing a key. Repair the agent and try again.');
  }

  // The burn is HANDED BACK rather than done here, so the caller can do it only after the
  // profile is actually stored. Burning at this point consumed the link on any later
  // failure — a missing socket token, a disk error — leaving the owner with a spent link
  // and no agent.
  //
  // It stays non-fatal once called: the credentials are already in hand and filed, and
  // failing an enrolment that has already succeeded because the "mark as used" call timed
  // out would be the worse outcome. A link that stays live for the rest of its fifteen
  // minutes is the smaller problem, and it is logged.
  const burn = async (): Promise<boolean> => {
    try {
      await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}/burn`, 'POST');
      return true;
    } catch {
      console.error(
        '[wundervault-agent] Enrolled, but could not mark the setup link as used. ' +
        'It stays valid until it expires — repair the agent again if that worries you.',
      );
      return false;
    }
  };

  return { creds, burn };
}
