/**
 * Hand existing agents over to the system daemon.
 *
 * Run by the user, without sudo, after the one privileged install step. It reads the
 * pre-split store from the user's own home — which only the user can do, and which is
 * exactly why the daemon must not do it: reaching into a user's home directory is the
 * access phase 4 removes, and a daemon that kept the habit would have kept the hole.
 *
 * So the direction is inward: the user pushes profiles in over the management socket, the
 * daemon writes them somewhere the user cannot read, and the user's copy is deleted.
 *
 * THE DELETION IS THE POINT. Migration that copies and leaves the original behind has
 * moved nothing: a readable file holding every credential still sits in a directory the
 * agent can read. Someone reading the release notes would believe otherwise.
 */
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { legacy, mgmtSocketPath, agentTokenPath, safeName } from './paths.js';

interface LegacyProfile {
  agent_name: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
  socket_token?: string;
}

/** One request/response over the management socket. */
function ask(payload: unknown, sockPath = mgmtSocketPath(), timeoutMs = 5_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(sockPath);
    let buf = '';
    const done = (fn: () => void) => { clearTimeout(timer); sock.destroy(); fn(); };
    const timer = setTimeout(
      () => done(() => reject(new Error(`timed out talking to the daemon at ${sockPath}`))),
      timeoutMs,
    );
    sock.on('connect', () => sock.write(JSON.stringify(payload) + '\n'));
    sock.on('data', (d) => {
      buf += d.toString();
      if (!buf.includes('\n')) return;
      try { done(() => resolve(JSON.parse(buf.trim()))); }
      catch { done(() => reject(new Error('unparseable reply from the daemon'))); }
    });
    sock.on('error', (e) => done(() => reject(e)));
  });
}

/**
 * Decrypt the pre-split store.
 *
 * The key derivation is duplicated here rather than imported, deliberately: the daemon's
 * version now derives against the DAEMON's uid and the new salt path, and this has to
 * derive against the USER's uid and the old one. Sharing the function would have silently
 * produced the wrong key and read as a corrupt store.
 */
function readLegacyProfiles(): LegacyProfile[] {
  const profilesPath = legacy.profiles();
  if (!fs.existsSync(profilesPath)) return [];

  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();
  const salt = fs.readFileSync(legacy.salt());
  const key = crypto.hkdfSync('sha256', ikm, salt, Buffer.from('wundervault-agent-v1'), 32) as unknown as Buffer;

  const buf = fs.readFileSync(profilesPath);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  const plain = Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
  return (JSON.parse(plain).profiles ?? []) as LegacyProfile[];
}

export interface MigrationResult {
  migrated: string[];
  skipped: { name: string; why: string }[];
  deletedLegacyStore: boolean;
  alreadyDone: boolean;
}

export async function migrate(opts: { dryRun?: boolean } = {}): Promise<MigrationResult> {
  const result: MigrationResult = {
    migrated: [], skipped: [], deletedLegacyStore: false, alreadyDone: false,
  };

  // Say out loud which file is about to be deleted, before deleting it.
  //
  // This function shreds a credential store. A test once pointed it at a real home
  // directory believing it had redirected it, and the only warning anybody got was the
  // absence of the file afterwards. One line of output costs nothing and turns a silent
  // destructive path into one somebody can notice going wrong.
  if (!opts.dryRun) {
    console.error(`[migrate] source store: ${legacy.profiles()} (will be deleted once every agent is across)`);
  }

  // Fail loudly if the daemon is absent. Writing the old file as a fallback would
  // recreate the pre-split world beside a daemon that never reads it, and everything
  // would appear to work.
  const ping = await ask({ action: 'ping' }).catch((e) => {
    throw new Error(
      `Could not reach the daemon at ${mgmtSocketPath()}: ${(e as Error).message}\n` +
      `Install it first:  sudo sh packaging/install-daemon.sh\n` +
      `Then check:        systemctl status wundervault-agent`,
    );
  });
  if (!ping?.ok) throw new Error('The daemon answered, but not with ok. Check its logs.');

  if (!fs.existsSync(legacy.profiles())) {
    result.alreadyDone = true;
    return result;
  }

  let profiles: LegacyProfile[];
  try {
    profiles = readLegacyProfiles();
  } catch (e) {
    throw new Error(
      `Could not read the old store at ${legacy.profiles()}: ${(e as Error).message}\n` +
      `It is encrypted against your machine id and uid, so this usually means it belongs ` +
      `to a different user or a different machine. Nothing has been changed.`,
    );
  }

  const already = new Set<string>(ping.agents ?? []);

  for (const p of profiles) {
    let name: string;
    try { name = safeName(p.agent_name); }
    catch (e) { result.skipped.push({ name: String(p.agent_name), why: (e as Error).message }); continue; }

    if (already.has(name)) { result.skipped.push({ name, why: 'already known to the daemon' }); continue; }

    // A profile with no socket token cannot be served: the per-agent socket is
    // world-connectable now, so the token is the only thing identifying the caller.
    // Minting one here keeps the migration unattended instead of sending someone back
    // through onboarding.
    //
    // The TOKEN FILE is checked separately from the token, and that distinction matters.
    // A profile can carry a token whose file has been lost — a restored home directory, a
    // half-finished uninstall — and migrating it would produce an agent the daemon knows
    // about and the client cannot authenticate as. It would look migrated and be locked
    // out, which is the worst of both. So the file is written whenever it is missing,
    // whether the token is new or inherited.
    const tp = agentTokenPath(name);
    let token = p.socket_token;
    const fileMissing = !fs.existsSync(tp);
    if (!token) token = crypto.randomBytes(32).toString('hex');

    if (!opts.dryRun && (fileMissing || !p.socket_token)) {
      fs.mkdirSync(path.dirname(tp), { recursive: true, mode: 0o700 });
      fs.writeFileSync(tp, token, { mode: 0o600 });
    }

    if (opts.dryRun) { result.migrated.push(name); continue; }

    const reply = await ask({
      action: 'register_profile',
      profile: { ...p, agent_name: name, socket_token: token },
    });
    if (reply?.ok) result.migrated.push(name);
    else result.skipped.push({ name, why: reply?.error ?? 'the daemon refused it' });
  }

  // Only delete once every profile is in. A partial migration that deleted the source
  // would lose the credentials it failed to move.
  const allIn = result.skipped.every(s => s.why === 'already known to the daemon');
  if (!opts.dryRun && allIn && result.skipped.length + result.migrated.length === profiles.length) {
    for (const f of [legacy.profiles(), legacy.salt()]) {
      try { shred(f); result.deletedLegacyStore = true; } catch { /* best effort */ }
    }
  }

  return result;
}

/**
 * Overwrite before unlinking.
 *
 * Not a guarantee — a journalling or copy-on-write filesystem, or an SSD's wear
 * levelling, can keep the old blocks regardless. It is worth doing because it costs
 * nothing and removes the easy case, and it is worth saying plainly that it does not make
 * the data unrecoverable.
 */
function shred(file: string): void {
  if (!fs.existsSync(file)) return;
  const size = fs.statSync(file).size;
  if (size > 0) fs.writeFileSync(file, crypto.randomBytes(size));
  fs.unlinkSync(file);
}

export function describe(r: MigrationResult, dryRun = false): string {
  if (r.alreadyDone) {
    return 'Nothing to migrate — there is no pre-split store in your home directory.';
  }
  const lines: string[] = [];
  if (r.migrated.length) {
    lines.push(dryRun
      ? `Would hand ${r.migrated.length} agent(s) to the daemon: ${r.migrated.join(', ')}`
      : `Handed ${r.migrated.length} agent(s) to the daemon: ${r.migrated.join(', ')}`);
  }
  for (const s of r.skipped) lines.push(`  ${dryRun ? 'would skip' : 'skipped'} ${s.name}: ${s.why}`);

  if (dryRun) {
    // A dry run reporting "LEFT the old store in place" reads as a failure rather than as
    // the absence of any action, which is what it actually is.
    lines.push('Dry run — nothing was changed. Re-run without --dry-run to do it.');
    return lines.join('\n');
  }
  lines.push(r.deletedLegacyStore
    ? 'Deleted the old store from your home directory. Credentials now live where your '
      + 'agents cannot read them.'
    : 'LEFT the old store in place, because not every agent made it across. Re-run this '
      + 'once the skipped ones are resolved — until then a readable copy of your '
      + 'credentials is still in your home directory.');
  return lines.join('\n');
}
