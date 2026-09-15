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
 * HONEST LIMIT, and it is the important one: this file lives in the agent's own home
 * directory and is writable by the agent's uid. A compromised agent can therefore edit
 * its own record of where it sent things — the party being audited controls the
 * evidence. That makes this a privacy improvement today and NOT an integrity control.
 * It becomes one after the uid split, when the file moves to /var/lib/wundervault owned
 * by a daemon account the agent cannot write to. The interface here does not change when
 * that happens.
 */
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
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
  /** entryId -> exact "scheme://host:port" strings the owner approved locally. */
  approvedPrivateOrigins: Record<string, string[]>;
}

const EMPTY: NetworkShape = { version: 1, seen: [], approvedPrivateOrigins: {} };

/** Bounded, so a long-lived install cannot grow this without limit. */
const MAX_SEEN = 2000;
const MAX_APPROVED_PER_ENTRY = 10;

export function defaultStorePath(): string {
  // After the uid split this becomes /var/lib/wundervault/network.json, owned by the
  // daemon account. Same shape, same code — only the path and the owner change.
  return process.env.WUNDERVAULT_NETWORK_STORE
    || path.join(os.homedir(), '.wundervault', 'network.json');
}

export function load(storePath = defaultStorePath()): NetworkShape {
  try {
    if (!existsSync(storePath)) return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
    const parsed = JSON.parse(readFileSync(storePath, 'utf8')) as NetworkShape;
    if (!parsed || parsed.version !== 1) return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
    return {
      version: 1,
      seen: Array.isArray(parsed.seen) ? parsed.seen : [],
      approvedPrivateOrigins: (parsed.approvedPrivateOrigins && typeof parsed.approvedPrivateOrigins === 'object')
        ? parsed.approvedPrivateOrigins : {},
    };
  } catch {
    // A corrupt store must not break every vault call. Start clean rather than throw —
    // the worst case is one spurious "new destination" notice.
    return { ...EMPTY, seen: [], approvedPrivateOrigins: {} };
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
): { isNew: boolean } {
  const shape = load(storePath);
  const now = new Date().toISOString();
  const key = origin.trim().toLowerCase();

  const existing = shape.seen.find((s) => s.entryId === entryId && s.origin === key);
  if (existing) {
    existing.count += 1;
    existing.lastSeen = now;
    save(shape, storePath);
    return { isNew: false };
  }

  shape.seen.push({ entryId, origin: key, firstSeen: now, lastSeen: now, count: 1 });
  // Oldest-first eviction. Evicting a record makes that destination read as new again,
  // which raises one extra notice — the safe direction for a detective signal.
  if (shape.seen.length > MAX_SEEN) {
    shape.seen.sort((a, b) => a.lastSeen.localeCompare(b.lastSeen));
    shape.seen = shape.seen.slice(shape.seen.length - MAX_SEEN);
  }
  save(shape, storePath);
  return { isNew: true };
}

export function destinationsFor(entryId: string, storePath = defaultStorePath()): SeenDestination[] {
  return load(storePath).seen.filter((s) => s.entryId === entryId);
}

// ── owner-approved private origins, held locally ───────────────────────────────

/**
 * Cloud metadata endpoints hand out instance credentials. No approval unlocks one,
 * because it is not a decision anyone can meaningfully make on an agent's behalf.
 */
const NEVER_APPROVABLE = new Set(['169.254.169.254', 'fd00:ec2::254', '100.100.100.200', 'metadata.google.internal']);

export function approvedPrivateOrigins(entryId: string, storePath = defaultStorePath()): string[] {
  const list = load(storePath).approvedPrivateOrigins[entryId];
  return Array.isArray(list) ? list.filter((s) => typeof s === 'string') : [];
}

export function approvePrivateOrigin(
  entryId: string, origin: string, storePath = defaultStorePath(),
): { ok: boolean; reason?: string; origins?: string[] } {
  const m = /^(https?):\/\/([a-z0-9._\-[\]:]+?):(\d{1,5})$/i.exec(origin.trim());
  if (!m) {
    return { ok: false, reason: 'Origin must be exactly "scheme://host:port", for example https://10.0.0.5:9000. No ranges and no wildcards — a range is not something you can realistically evaluate.' };
  }
  const host = m[2].toLowerCase().replace(/^\[|\]$/g, '');
  const port = Number(m[3]);
  if (port < 1 || port > 65535) return { ok: false, reason: 'Port out of range.' };
  if (NEVER_APPROVABLE.has(host)) {
    return { ok: false, reason: `${host} is a cloud metadata endpoint. It hands out instance credentials, so it cannot be approved.` };
  }

  const shape = load(storePath);
  const current = shape.approvedPrivateOrigins[entryId] ?? [];
  const canonical = `${m[1].toLowerCase()}://${host}:${port}`;
  if (current.includes(canonical)) return { ok: true, origins: current };
  if (current.length >= MAX_APPROVED_PER_ENTRY) {
    return { ok: false, reason: `This entry already approves ${MAX_APPROVED_PER_ENTRY} private origins.` };
  }
  shape.approvedPrivateOrigins[entryId] = [...current, canonical];
  save(shape, storePath);
  return { ok: true, origins: shape.approvedPrivateOrigins[entryId] };
}

export function revokePrivateOrigin(
  entryId: string, origin: string, storePath = defaultStorePath(),
): string[] {
  const shape = load(storePath);
  const canonical = origin.trim().toLowerCase();
  const next = (shape.approvedPrivateOrigins[entryId] ?? []).filter((o) => o.toLowerCase() !== canonical);
  if (next.length === 0) delete shape.approvedPrivateOrigins[entryId];
  else shape.approvedPrivateOrigins[entryId] = next;
  save(shape, storePath);
  return next;
}


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
): DestinationNotice {
  const at = new Date().toISOString();
  return {
    stderrLine:
      `[wundervault] NEW DESTINATION ${at} secret="${secretName}" ${method} ${origin}${path}\n`,
    toolNote:
      `⚠ First use of "${secretName}" against ${origin}.\n`
      + `   ${method} ${origin}${path}\n`
      + `   Tier 1 does not gate destinations, so this is a notice rather than a block. `
      + `If you did not expect it, revoke this agent and rotate the secret at the provider. `
      + `Moving the secret to Tier 2 makes each new request wait for approval.\n`
      + `   Recorded on this machine only — the destination was not sent to the server.`,
  };
}

/** Write the notice where the model cannot interfere with it. */
export function emitToStderr(notice: DestinationNotice): void {
  try { process.stderr.write(notice.stderrLine); } catch { /* never break a call over a log line */ }
}
