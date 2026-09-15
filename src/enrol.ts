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

const PBKDF2_SALT = 'wv-agent-setup-v1';
const PBKDF2_ROUNDS = 100_000;
const UA = 'WunderVault-Agent-Daemon/1.0';

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

  // The blob is encrypted, but the setup token is a bearer credential and plaintext HTTP
  // would hand it to anything on the path. The one exception is loopback: a connection
  // that never leaves the machine cannot be intercepted on the way, and without it there
  // is no way to exercise this against a real server in a test — which would mean the
  // protocol was only ever checked against a mock of our own making.
  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) {
    throw new Error(`A setup link must be https. Got ${u.protocol.replace(':', '')}.`);
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
  const res = await fetch(url, {
    method,
    headers: { 'User-Agent': UA },
    redirect: 'error',
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
  const ctype = String(res.headers.get('content-type') ?? '');
  if (!ctype.includes('json')) {
    // A captive portal or a proxy answering 200 with an HTML login page would otherwise
    // reach JSON.parse and surface as a confusing syntax error.
    throw new Error(`The setup link did not return JSON (content-type: ${ctype || 'none'}).`);
  }
  return res.json();
}

/**
 * Redeem a setup link.
 *
 * The burn is a separate call AFTER the credentials are decrypted, and that order matters:
 * burning first would mean a wrong passphrase or a network blip consumed a single-use link
 * and left the agent with nothing, forcing another trip to the dashboard. Burning last
 * means the only way to lose the link is to have already succeeded with it.
 */
export async function redeemSetupLink(rawUrl: string): Promise<EnrolledCredentials> {
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

  // Best effort, and deliberately non-fatal: the credentials are already in hand, and
  // failing the whole enrolment because the "mark as used" call timed out would be a
  // worse outcome than a link that stays live for its remaining fifteen minutes.
  try {
    await httpJson(`${baseUrl}/api/setup/agent/${encodeURIComponent(token)}/burn`, 'POST');
  } catch {
    console.error('[wundervault-agent] Enrolled, but could not mark the setup link as used.');
  }

  return creds;
}
