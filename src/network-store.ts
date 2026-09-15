/**
 * Where an agent's secrets go — held on the customer's machine, not on the server.
 *
 * Destinations are a behavioural profile: which services you call, how often, when, and
 * (for approved private origins) your internal network addresses. None of that helps
 * anyone read a secret, but it is competitive intelligence on its own and it is the kind
 * of thing a breach or a subpoena reaches. "We cannot read your secrets" was always
 * true; keeping this local makes "we do not know what you do with them" true as well.
 *
 * The split that makes this coherent:
 *
 *   Tier 1 — the destination NEVER leaves this machine. The server learns that a call
 *            happened, not where it went.
 *   Tier 2 — the destination IS sent, because the whole point of tier 2 is that a human
 *            reviews the request, and they cannot review what they cannot see. That is
 *            consented disclosure for one specific call, not a standing profile.
 *
 * HONEST LIMIT: this file lives in the agent's own home directory and is writable by the
 * agent's uid. A compromised agent can edit its own record of where it sent things — the
 * party being audited controls the evidence. So OBSERVATIONS live here (privacy, no
 * integrity claim), and it becomes an integrity control only after the uid split moves it
 * to a daemon-owned path.
 *
 * WHAT DOES NOT LIVE HERE, and why: owner APPROVALS. An earlier version stored approved
 * private origins in this file, which was a straight security regression — the agent
 * could write its own approval and walk through the SSRF filter it was meant to be
 * constrained by. An observation being forgeable costs you a missed notice; a CONTROL
 * being forgeable costs you the control. Approvals therefore stay server-side, where the
 * owner authenticates and the agent cannot write, until a daemon-owned path exists.
 *
 * The line: this file records what happened. It never decides what is allowed.
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync,
  openSync, closeSync, unlinkSync, statSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface SeenDestination {
  entryId: string;
  origin: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
}

export interface NetworkShape {
  version: 1;
  seen: SeenDestination[];
}

const EMPTY: NetworkShape = { version: 1, seen: [] };

/** Bounded, so a long-lived install cannot grow this without limit. */
const MAX_SEEN = 2000;

/**
 * Recording can be turned off. The metadata IS the control, so opting out of the record
 * opts out of first-sighting notices too — there is no honest way to have the second
 * without the first, and pretending otherwise would leave someone believing they were
 * being warned.
 */
export function recordingEnabled(): boolean {
  const v = (process.env.WUNDERVAULT_RECORD_DESTINATIONS ?? '').trim().toLowerCase();
  return !(v === '0' || v === 'false' || v === 'off' || v === 'no');
}

export function defaultStorePath(): string {
  // After the uid split this becomes /var/lib/wundervault/network.json, owned by the
  // daemon account. Same shape, same code — only the path and the owner change.
  return process.env.WUNDERVAULT_NETWORK_STORE
    || path.join(os.homedir(), '.wundervault', 'network.json');
}

export function load(storePath = defaultStorePath()): NetworkShape {
  try {
    if (!existsSync(storePath)) return { version: 1, seen: [] };
    const parsed = JSON.parse(readFileSync(storePath, 'utf8')) as NetworkShape;
    if (!parsed || parsed.version !== 1) return { version: 1, seen: [] };
    return { version: 1, seen: Array.isArray(parsed.seen) ? parsed.seen : [] };
  } catch {
    // A corrupt store must not break every vault call. Start clean rather than throw —
    // the worst case is one spurious "new destination" notice.
    return { version: 1, seen: [] };
  }
}

export function save(shape: NetworkShape, storePath = defaultStorePath()): void {
  const dir = path.dirname(storePath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // Write-then-rename: a half-written store read by the next call would look like a
  // cleared history, and every destination would alert again.
  const tmp = `${storePath}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(shape, null, 2), { mode: 0o600 });
  renameSync(tmp, storePath);
  try { chmodSync(storePath, 0o600); } catch { /* best effort */ }
}

/**
 * Record a destination and say whether it had been seen before.
 *
 * Returns true the FIRST time an (entry, origin) pair appears. The caller uses that to
 * raise a notice exactly once, rather than on every call to a familiar service.
 */
export function recordDestination(
  entryId: string, origin: string, storePath = defaultStorePath(),
): { isNew: boolean; recorded: boolean } {
  // Opted out: touch nothing, say nothing. Returning isNew:false here is deliberate —
  // a notice without a record would fire on every single call.
  if (!recordingEnabled()) return { isNew: false, recorded: false };

  return withStoreLock(storePath, () => {
  const shape = load(storePath);
  const now = new Date().toISOString();
  const key = origin.trim().toLowerCase();

  const existing = shape.seen.find((s) => s.entryId === entryId && s.origin === key);
  if (existing) {
    existing.count += 1;
    existing.lastSeen = now;
    save(shape, storePath);
    return { isNew: false, recorded: true };
  }

  shape.seen.push({ entryId, origin: key, firstSeen: now, lastSeen: now, count: 1 });
  // Oldest-first eviction. Evicting a record makes that destination read as new again,
  // which raises one extra notice — the safe direction for a detective signal.
  if (shape.seen.length > MAX_SEEN) {
    shape.seen.sort((a, b) => a.lastSeen.localeCompare(b.lastSeen));
    shape.seen = shape.seen.slice(shape.seen.length - MAX_SEEN);
  }
  save(shape, storePath);
  return { isNew: true, recorded: true };
  });
}

/**
 * Serialise read-modify-write across processes.
 *
 * Several agents run under one user here — seven on this machine — so two MCP processes
 * writing at once is the normal case, not a corner. Without this, both load the same
 * store, both write, and the later rename silently discards the other's destination,
 * which then reports as new again. An exclusive lock file with a stale-lock timeout is
 * enough: contention is brief and the failure mode of waiting is better than the failure
 * mode of losing a record.
 */
function withStoreLock<T>(storePath: string, fn: () => T): T {
  const lockPath = `${storePath}.lock`;
  const deadline = Date.now() + 5000;
  let fd: number | undefined;
  for (;;) {
    try {
      fd = openSync(lockPath, 'wx');
      break;
    } catch {
      // A lock left by a crashed process must not block every later call for ever.
      try {
        const age = Date.now() - statSync(lockPath).mtimeMs;
        if (age > 30_000) { unlinkSync(lockPath); continue; }
      } catch { /* vanished under us: retry */ }
      if (Date.now() > deadline) {
        // Proceed unlocked rather than fail a vault call over bookkeeping. Worst case is
        // the lost-update this guards against, which costs one spurious notice.
        return fn();
      }
      const wait = Date.now() + 25;
      while (Date.now() < wait) { /* brief spin; this is a millisecond-scale section */ }
    }
  }
  try {
    return fn();
  } finally {
    try { closeSync(fd!); } catch { /* ignore */ }
    try { unlinkSync(lockPath); } catch { /* ignore */ }
  }
}

export function destinationsFor(entryId: string, storePath = defaultStorePath()): SeenDestination[] {
  return load(storePath).seen.filter((s) => s.entryId === entryId);
}

// Approvals deliberately absent — see the header. They are a control, and a control in
// an agent-writable file is not a control.

// ── telling the owner, without telling the server ──────────────────────────────

export interface DestinationNotice {
  /** For stderr — the model cannot suppress this. */
  stderrLine: string;
  /** For the tool result — the model reads this and can explain it in context. */
  toolNote: string;
}

/**
 * Compose the first-sighting notice.
 *
 * Two channels, deliberately, and the split matters:
 *
 *  - **stderr** goes from this process straight to the MCP client and never passes
 *    through the model. A compromised agent can decide not to mention a tool result; it
 *    cannot strip a line already written to stderr. That makes this the channel of
 *    record.
 *  - **the tool result** is how the agent explains it to you in the conversation, which
 *    is where you are actually looking.
 *
 * Neither reaches the server. The destination stays on this machine, so the default
 * install leaves the server knowing nothing about where a secret goes — no relay, no
 * transient handling, nothing to store.
 *
 * The case this does NOT cover is an unattended run: a scheduled agent at 3am with
 * nobody watching the terminal. Email covers that and is therefore opt-in, labelled as
 * the choice that sends the destination to the server in order to deliver it.
 */
export function newDestinationNotice(
  secretName: string, origin: string, method: string, path: string,
  /** Which tier authorised this call. The notice must not describe the wrong one. */
  tier: string = '1',
): DestinationNotice {
  const at = new Date().toISOString();
  const isTier2 = String(tier) === '2';

  // Tier 2 already required the owner to see and approve this exact operation, so
  // telling them "this was not gated" and "the destination stayed on this machine"
  // would both be false — the approval is precisely where it was disclosed.
  const explanation = isTier2
    ? `   You approved this operation, so it was gated. The destination was sent to the `
      + `server as part of that approval; it is also recorded here.`
    : `   Tier 1 does not gate destinations, so this is a notice rather than a block. `
      + `If you did not expect it, revoke this agent and rotate the secret at the provider. `
      + `Moving the secret to Tier 2 makes each new request wait for approval.\n`
      + `   Recorded on this machine only — the destination was not sent to the server.`;

  return {
    stderrLine:
      `[wundervault] NEW DESTINATION ${at} tier=${tier} secret="${secretName}" ${method} ${origin}${path}\n`,
    toolNote: `⚠ First use of "${secretName}" against ${origin}.\n   ${method} ${origin}${path}\n${explanation}`,
  };
}

/** Write the notice where the model cannot interfere with it. */
export function emitToStderr(notice: DestinationNotice): void {
  try { process.stderr.write(notice.stderrLine); } catch { /* never break a call over a log line */ }
}
