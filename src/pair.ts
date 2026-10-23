/**
 * Pairing this machine's broker with an account, and claiming credentials afterwards.
 *
 * Pairing happens ONCE PER MACHINE and moves nothing secret. The broker uploads its
 * public key and gets back a short code; the owner types that code into the dashboard,
 * compares the fingerprint the page computes against the one the terminal printed, and
 * confirms. After that a repair can wrap credentials to this broker's public key, and the
 * thing the owner carries from browser to terminal is a claim code that decrypts nothing.
 *
 * WHAT AN OBSERVER GETS. An agent reading the terminal, the command line, the screen and
 * the network sees: a public key, a fingerprint, and a claim code. None of it opens a
 * blob. Compare that with the link flow, where a single string read once within fifteen
 * minutes yields the vault key.
 *
 * WHAT PAIRING STILL TRUSTS. The fingerprint is compared by a person between two screens.
 * An agent driving the terminal could print a fingerprint for a key it controls, so
 * pairing is the owner's job in a session no agent is driving. That is the same trust the
 * `sudo` install already assumes, once per machine instead of once per repair.
 */
import fs from 'node:fs';
import path from 'node:path';
import { loadOrCreateIdentity, fingerprintOf, type BrokerIdentity } from './broker-key.js';
import { allowedOrigins } from './enrol.js';
import { systemRoot, ensureSystemRoot } from './paths.js';
import { VERSION } from './version.js';

const UA = `WunderVault-Agent-Daemon/${VERSION}`;
const TIMEOUT = 20_000;
const MAX_RESPONSE_BYTES = 256 * 1024;

export function pairedMarkerPath(): string {
  return process.env.WUNDERVAULT_PAIRED_MARKER || path.join(systemRoot(), 'paired.json');
}

export interface PairedRecord {
  origin: string;
  fingerprint: string;
  account_label?: string;
  /** The account that confirmed, for the owner to eyeball. Shown, never verified. */
  account_hint?: string;
  paired_at: string;
}

/**
 * Forget the local pairing.
 *
 * NEEDED BECAUSE UNPAIRING HAS TWO HALVES. The dashboard revokes the server row, which
 * stops new credentials being sealed to this broker. It cannot reach into this machine,
 * so `paired.json` survives — and the setup-link refusal is keyed to that file. Without
 * this command, an owner who unpaired would be shown a setup link by the dashboard and
 * have it refused by their own broker, with nothing explaining why.
 */
export function forgetPairing(): boolean {
  try {
    fs.unlinkSync(pairedMarkerPath());
    return true;
  } catch {
    return false;
  }
}

export function readPaired(): PairedRecord | null {
  try {
    const raw = fs.readFileSync(pairedMarkerPath(), 'utf8');
    const v = JSON.parse(raw) as PairedRecord;
    return v && typeof v.fingerprint === 'string' ? v : null;
  } catch { return null; }
}

function writePaired(rec: PairedRecord): void {
  ensureSystemRoot();
  const p = pairedMarkerPath();
  fs.writeFileSync(p, JSON.stringify(rec, null, 2), { mode: 0o600 });
  fs.chmodSync(p, 0o600);
}

/** The one origin this broker will talk to. Set by the unit; never by a caller. */
function origin(): string {
  return allowedOrigins()[0];
}

async function postJson(url: string, body: unknown): Promise<any> {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': UA },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT),
  });
  const text = (await resp.text()).slice(0, MAX_RESPONSE_BYTES);
  let parsed: any = null;
  try { parsed = JSON.parse(text); } catch { /* reported below */ }
  if (!resp.ok) {
    throw new Error(parsed?.detail ?? `HTTP ${resp.status} from ${url}`);
  }
  if (!parsed) throw new Error(`${url} returned a response this build could not parse.`);
  return parsed;
}

async function getJson(url: string): Promise<any> {
  const resp = await fetch(url, {
    headers: { 'user-agent': UA },
    signal: AbortSignal.timeout(TIMEOUT),
  });
  const text = (await resp.text()).slice(0, MAX_RESPONSE_BYTES);
  let parsed: any = null;
  try { parsed = JSON.parse(text); } catch { /* reported below */ }
  if (!resp.ok) throw new Error(parsed?.detail ?? `HTTP ${resp.status} from ${url}`);
  if (!parsed) throw new Error(`${url} returned a response this build could not parse.`);
  return parsed;
}

/**
 * What `--pair` prints after the code and fingerprint: where in the vault to enter it, in the 1.0
 * vault's own words (Your computers, then Pair a computer). Kept here so a test can read it without
 * running the CLI.
 */
export function pairInstructions(): string[] {
  return [
    '  In your vault: Your computers, then Pair a computer. Enter the code above, and check',
    '  that the fingerprint it shows matches this one EXACTLY before you confirm. That',
    '  comparison is the whole ceremony: everything after it is sealed to the key you approved.',
  ];
}

/** What `--pair` prints once the vault has confirmed: how an agent on this machine gets set up. */
export function pairedNextSteps(): string[] {
  return [
    '  Setup links are no longer accepted on this machine. To set up an agent here, use Add an',
    '  agent (or Repair, for one you have) in your vault, choose this computer, and give the',
    '  agent the message the vault shows.',
  ];
}

export interface PairStart { code: string; identity: BrokerIdentity; expiresInMinutes: number }

/** Upload the public half and get the code the owner will type. */
export async function startPairing(): Promise<PairStart> {
  const identity = loadOrCreateIdentity();
  const res = await postJson(`${origin()}/api/broker/pair-request`, {
    public_key: identity.publicKeyB64,
    hostname: process.env.HOSTNAME || '',
  });
  const code = String(res.code ?? '');
  if (!code) throw new Error('The server did not return a pairing code.');
  return { code, identity, expiresInMinutes: Number(res.expires_in_minutes ?? 15) };
}

/**
 * Wait for the owner to confirm in the dashboard.
 *
 * Polling rather than pushing, because the broker has no inbound port and should not
 * have one. The wait is what gives this command a definite end: without it the broker
 * would never learn whether pairing succeeded, and could not refuse the weaker link path
 * on a paired machine, because it would not know it was paired.
 */
export async function awaitConfirmation(
  start: PairStart,
  opts: {
    timeoutMs?: number;
    intervalMs?: number;
    onTick?: (waitedMs: number) => void;
    /**
     * Ask the person at the terminal whether the confirming account is theirs.
     *
     * Required in practice — the default of "yes" exists only so a test can drive the
     * happy path without a TTY, and the CLI always supplies a real prompt.
     */
    confirmAccount?: (accountHint: string) => Promise<boolean>;
  } = {},
): Promise<PairedRecord> {
  const timeoutMs = opts.timeoutMs ?? start.expiresInMinutes * 60_000;
  const intervalMs = opts.intervalMs ?? 3_000;
  const began = Date.now();
  for (;;) {
    const waited = Date.now() - began;
    if (waited > timeoutMs) {
      throw new Error(
        `The pairing code expired after ${Math.round(timeoutMs / 60_000)} minutes without being `
        + `confirmed. Run --pair again; nothing was changed.`);
    }
    let res: any;
    try {
      res = await getJson(`${origin()}/api/broker/pair-request/${encodeURIComponent(start.code)}`);
    } catch {
      // A transient failure is not a refusal, and treating it as one would abandon a
      // pairing the owner may be halfway through confirming.
      res = null;
    }
    if (res?.status === 'confirmed') {
      // The fingerprint is recomputed from the key the SERVER now holds, and compared
      // with ours. If they differ, something else was confirmed under this code and the
      // owner approved a key that is not this machine's — which is the one failure this
      // whole ceremony exists to make visible.
      const serverFp = fingerprintOf(String(res.public_key ?? ''));
      if (serverFp !== start.identity.fingerprint) {
        throw new Error(
          `The confirmed key is not this machine's.\n`
          + `  this broker : ${start.identity.fingerprint}\n`
          + `  confirmed   : ${serverFp}\n`
          + `Nothing was paired. Run --pair again and check the fingerprint before confirming.`);
      }

      // AND THE OWNER CONFIRMS WHOSE ACCOUNT IT WENT TO.
      //
      // The pairing code is not a secret — it is printed on this terminal and typed into
      // a browser — so anyone who reads it can look it up and confirm it under THEIR
      // account. Claiming the code for the first account that touches it makes an
      // attacker have to be first; it does not stop them being first. This machine then
      // believes it is paired, while the key is bound to a stranger's vault.
      //
      // The key check above cannot catch that: the key IS this machine's, which is
      // exactly what makes the attack work. So the last step is a human reading an
      // account name and saying whether it is theirs. It is the same shape as the
      // fingerprint comparison — the ceremony's whole security is a person looking at two
      // things — and it costs one keystroke on a step taken once per machine.
      const hint = res.account_hint ? String(res.account_hint) : '';
      if (!(await opts.confirmAccount?.(hint) ?? true)) {
        throw new Error(
          `Not paired. The confirmation came from ${hint || 'an account this broker cannot name'}, `
          + `and you said that is not yours.\n`
          + `Whoever confirmed it now has a pairing request for this machine's public key under `
          + `their account — that gives them nothing on this machine, but run --pair again and `
          + `do not share the code.`);
      }
      const rec: PairedRecord = {
        origin: origin(),
        fingerprint: start.identity.fingerprint,
        account_label: res.label ? String(res.label) : undefined,
        // Which account claimed this pairing, so `--pair` can print it and the owner can
        // see at a glance that it is theirs. The broker cannot VERIFY whose account it
        // is — it has no account credential of its own at this point, which is the whole
        // reason the ceremony exists — so this is shown, never checked. The server's
        // claim-on-lookup is what makes a stranger have to win a race to appear here.
        account_hint: res.account_hint ? String(res.account_hint) : undefined,
        paired_at: new Date().toISOString(),
      };
      writePaired(rec);
      return rec;
    }
    if (res?.status === 'rejected') {
      throw new Error('The pairing was rejected in the dashboard. Nothing was changed.');
    }
    opts.onTick?.(waited);
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

export interface ClaimResult {
  agent_name: string;
  agent_id: string;
  api_key: string;
  api_key_hmac?: string;
  enc_key: string;
  vault_url: string;
}

/** A claim code names a blob. It is not a credential and opens nothing. */
export function looksLikeClaimCode(s: string): boolean {
  return /^WV-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/i.test(s.trim());
}

/**
 * Fetch and open the blob this claim code names.
 *
 * The fetch is deliberately unauthenticated: there is nothing to protect. Only the
 * holder of this machine's private key can open what comes back, so an attacker who
 * steals the claim code gets ciphertext. That is the whole reason the claim code can
 * travel through an agent, a chat log or a command line without mattering.
 */
export async function claim(code: string): Promise<ClaimResult> {
  const { openBrokerBlob } = await import('./broker-key.js');
  const identity = loadOrCreateIdentity();
  const res = await getJson(
    `${origin()}/api/setup/agent/claim/${encodeURIComponent(code.trim().toUpperCase())}`);

  const blobB64 = String(res.broker_blob ?? '');
  if (!blobB64) {
    throw new Error(
      'That claim has no blob for this broker. It was probably created before this machine '
      + 'was paired, or for a different machine. Repair the agent again and pick this broker.');
  }
  const fpWanted = String(res.broker_fingerprint ?? '');
  if (fpWanted && fpWanted !== identity.fingerprint) {
    throw new Error(
      `That claim was sealed for a different broker.\n`
      + `  this broker : ${identity.fingerprint}\n`
      + `  sealed for  : ${fpWanted}`);
  }

  let opened: Record<string, unknown>;
  try {
    opened = JSON.parse(openBrokerBlob(identity.privateKeyPem, blobB64).toString('utf8'));
  } catch (e) {
    throw new Error(
      `This broker could not open that claim: ${(e as Error).message}\n`
      + `It is sealed to a public key; if this machine was re-paired since the repair, the `
      + `key it was sealed to is gone. Repair the agent again.`);
  }

  const api_key = String(opened.api_key ?? '');
  const enc_key = String(opened.encryption_key ?? opened.enc_key ?? '');
  if (!api_key || !enc_key) throw new Error('The claim opened but did not contain a credential.');

  return {
    agent_name: String(res.agent_name ?? ''),
    agent_id: String(res.agent_id ?? ''),
    api_key,
    api_key_hmac: opened.api_key_hmac ? String(opened.api_key_hmac) : undefined,
    enc_key,
    // The CONFIGURED origin, not the one the response offered.
    //
    // The claim endpoint is unauthenticated, so `res.vault_url` is a value supplied by
    // whatever answered — and the credential is about to be used against whatever URL we
    // write here. Taking it from the response would let a server that can answer this
    // endpoint redirect every future vault call, which is the same hole the enrolment
    // origin allowlist exists to close. It comes from the daemon's own environment,
    // which systemd sets and no caller controls.
    vault_url: origin(),
  };
}

/**
 * Who is this claim for, without opening it.
 *
 * The claim endpoint does not burn on read, so asking costs nothing and buys the same
 * property the link path's `whose_link` buys: the caller can reuse an agent's EXISTING
 * socket token instead of replacing it, and a running agent is not locked out of the
 * broker that just re-enrolled it.
 */
export async function whoseClaim(code: string): Promise<{ agent_name: string; broker_fingerprint: string }> {
  const res = await getJson(
    `${origin()}/api/setup/agent/claim/${encodeURIComponent(code.trim().toUpperCase())}`);
  return {
    agent_name: String(res.agent_name ?? ''),
    broker_fingerprint: String(res.broker_fingerprint ?? ''),
  };
}

/**
 * Tell the server the claim was used, so it cannot be replayed.
 *
 * Carries `api_key_hmac` FROM INSIDE THE SEALED BLOB as proof. A claim code is
 * deliberately not a secret, which made an unauthenticated burn a denial of service:
 * anyone who read the code could spend the claim before this broker reached it, and the
 * owner would repair the agent again with no idea why. Only a broker that opened the blob
 * has this value.
 */
export async function burnClaim(code: string, apiKeyHmac: string): Promise<boolean> {
  try {
    await postJson(
      `${origin()}/api/setup/agent/claim/${encodeURIComponent(code.trim().toUpperCase())}/burn`,
      { api_key_hmac: apiKeyHmac });
    return true;
  } catch {
    return false;
  }
}
