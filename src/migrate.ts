/**
 * Move agents enrolled before the uid split onto the system daemon.
 *
 * The first version of this carried credentials. It decrypted the pre-split store, pushed
 * each profile in over the management socket, and shredded the original — which meant the
 * management socket had to accept a profile from whoever asked, and that turned out to be
 * the hole the whole phase existed to close: agents run as the owner, so "whoever asked"
 * included every agent on the machine, and any of them could register a name with a token
 * of its choosing and then read that agent's credentials from its own socket.
 *
 * The product already had the answer. REPAIR, in the dashboard, rotates an agent's
 * credentials and issues a fresh setup link while keeping its identity and every one of
 * its vault grants. So migration is not a data move at all — it is the owner repairing
 * each agent and handing the daemon the link. Nothing here touches a credential.
 *
 * Three things fall out of that, all good:
 *   - No unauthenticated path into the daemon, and no special case carved for migration.
 *   - Repair invalidates the old credentials server-side, so the copy in the pre-split
 *     store is worthless the moment an agent is repaired. Deleting it becomes tidiness
 *     rather than the thing standing between the user and a leak.
 *   - The pre-split daemon, if it is still running, is serving credentials the server no
 *     longer accepts. It should still be turned off, but it is no longer a boundary hole.
 *
 * The old store is read ONLY for the list of names, so the owner can be told which agents
 * still need doing. That read is something the owner could always do; it moves no secret.
 */
import fs from 'node:fs';
import net from 'node:net';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { legacy, mgmtSocketPath, splitAvailable } from './paths.js';

/** One request/response over a socket. */
export function ask(payload: unknown, sockPath = mgmtSocketPath(), timeoutMs = 30_000): Promise<any> {
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
 * The names in the pre-split store.
 *
 * Decrypted with the key the OLD daemon used — the user's uid, the old salt path — which
 * is why this cannot be shared with the daemon's own derivation and is not imported from
 * it. Only the names are returned. The credentials in there are about to be made
 * worthless by repair, and reading them into this process would recreate, for no benefit,
 * exactly the exposure the split removes.
 */
export function legacyAgentNames(): string[] {
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
  return ((JSON.parse(plain).profiles ?? []) as { agent_name?: string }[])
    .map(p => String(p.agent_name ?? ''))
    .filter(Boolean);
}

type OldUnit = 'gone' | 'still-running';

/**
 * The unit this stops, and why it is a variable.
 *
 * A test for this called it with the real name and systemctl did exactly as asked: it
 * stopped and disabled the developer's own live daemon. Anything that reaches outside the
 * process has to be redirectable, or a test cannot be written for it without doing the
 * thing for real.
 */
const OLD_UNIT = () => process.env.WUNDERVAULT_OLD_UNIT || 'wundervault-agent.service';

export function stopOldUserUnit(): Promise<OldUnit> {
  return new Promise((resolve) => {
    execFile('systemctl', ['--user', 'disable', '--now', OLD_UNIT()], { timeout: 10_000 }, () => {
      // The exit code is not consulted: `disable` fails on a unit that was never there,
      // which is the good case, and can succeed while the process lives on. Only the
      // liveness check decides, and anything that is not a clear "not active" counts as
      // still running — if we cannot reach the user bus we do not know, and not knowing
      // must not read as success.
      execFile('systemctl', ['--user', 'is-active', OLD_UNIT()], { timeout: 5_000 },
        (_e, stdout) => {
          const state = String(stdout).trim();
          resolve(state === 'active' || state === '' ? 'still-running' : 'gone');
        });
    });
  });
}

/**
 * Delete the pre-split unit file.
 *
 * Disabling stops it now; the file is what starts it again. Leaving it means a reboot
 * brings up a second daemon that binds a socket the client still falls back to, and by
 * then the store it wants is gone — so it comes up serving nothing, loudly, for reasons
 * nobody will connect to a migration run weeks earlier.
 */
function removeOldUnitFile(): void {
  const home = process.env.HOME || '';
  if (!home) return;
  const unit = `${home}/.config/systemd/user/${OLD_UNIT()}`;
  try { if (fs.existsSync(unit)) fs.unlinkSync(unit); } catch { /* best effort */ }
}

export interface MigrationStatus {
  pending: string[];
  across: string[];
  alreadyDone: boolean;
  oldStorePath: string;
}

/** What still needs doing. Reads; changes nothing. */
/**
 * Migration is a Linux-only operation, and saying so prevents data loss.
 *
 * Off Linux there is no split to migrate TO: systemRoot() returns the user's own directory,
 * which means `profilesPath()` and `legacy.profiles()` are THE SAME FILE. Every agent the
 * daemon knows about therefore appears "already across", nothing is pending, and
 * `--migrate --finish` shreds the store the running daemon is actually using. A cleanup
 * step that deletes the live credential file because it mistook it for a leftover is about
 * the worst outcome available here, and it would have looked like a successful migration.
 */
function refuseOffLinux(): void {
  if (splitAvailable()) return;
  throw new Error(
    `Migration is Linux-only. On ${process.platform} the daemon already stores credentials ` +
    `in your own directory and there is nothing to move — the source and destination are ` +
    `the same file, so continuing would delete the store this machine is using.`,
  );
}

export async function status(): Promise<MigrationStatus> {
  refuseOffLinux();
  const oldStorePath = legacy.profiles();
  const ping = await ask({ action: 'ping' }).catch((e) => {
    throw new Error(
      `Could not reach the secret broker at ${mgmtSocketPath()}: ${(e as Error).message}\n` +
      `Install it first:  sudo sh packaging/install-daemon.sh\n` +
      `Then check:        systemctl status wundervault-agent`,
    );
  });
  if (!ping?.ok) throw new Error('The broker answered, but not with ok. Check its logs.');

  if (!fs.existsSync(oldStorePath)) {
    return { pending: [], across: [], alreadyDone: true, oldStorePath };
  }

  const roster = await ask({ action: 'known_agents' }).catch(() => ({ agents: [] }));
  const known = new Set<string>(roster.agents ?? []);
  const names = legacyAgentNames();
  return {
    pending: names.filter(n => !known.has(n)),
    across: names.filter(n => known.has(n)),
    alreadyDone: false,
    oldStorePath,
  };
}

export interface EnrolResult { agent_name: string; agent_id: string; }

/**
 * Hand one setup link to the daemon.
 *
 * The socket token is minted HERE and written to the user's own home, not by the daemon.
 * The daemon must not write into a user's home directory — that access is precisely what
 * this phase removes — and the token is the agent's identity rather than a vault
 * credential, so there is nothing to protect by having the daemon generate it.
 */
export async function enrol(setupUrl: string): Promise<EnrolResult & { linkBurned: boolean }> {
  const { agentTokenPath } = await import('./paths.js');
  const path = await import('node:path');

  // Ask WHOSE link this is before committing to anything. The GET endpoint does not burn
  // the token — the server says so explicitly — so this costs one round trip and removes a
  // race that the previous shape could not avoid: it had to mint a token, enrol, learn the
  // name from the reply, then swap the token back. If the connection dropped in the middle
  // of that, the agent was registered under a token nobody had saved, the link was spent,
  // and there was no way back except another repair.
  const who = await ask({ action: 'whose_link', setup_url: setupUrl });
  if (who?.error) throw new Error(who.error);
  const agentName = String(who?.agent_name ?? '');
  if (!agentName) throw new Error('The server did not say which agent that link is for.');

  // Reuse the agent's existing token when it has one. Repair rotates the VAULT
  // credentials; the socket token is a separate local identity, read once at startup by
  // any already-running agent process. Replacing it would have that agent refused by the
  // daemon that just enrolled it, with 'unauthorized' as the only clue.
  const tp = agentTokenPath(agentName);
  let socketToken = '';
  if (fs.existsSync(tp)) {
    try {
      const existing = fs.readFileSync(tp, 'utf8').trim();
      if (existing.length >= 32) socketToken = existing;
    } catch { /* unreadable: mint a new one below */ }
  }
  const reusedToken = Boolean(socketToken);
  if (!socketToken) socketToken = crypto.randomBytes(32).toString('hex');

  const reply = await ask({ action: 'enrol', setup_url: setupUrl, socket_token: socketToken });
  if (reply?.error) throw new Error(reply.error);
  if (!reply?.ok || !reply.agent_name) throw new Error('The broker did not confirm the enrolment.');

  // Written only after the daemon has confirmed, and skipped entirely when the value did
  // not change. Writing first would leave a token file for an agent that does not exist,
  // which reads as a working setup and is not.
  if (!reusedToken) {
    const dir = path.dirname(tp);
    // chmod unconditionally: mkdir's mode is masked by umask and ignored on a directory
    // that already exists, and writeFileSync's mode applies only when it creates the file.
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    fs.writeFileSync(tp, socketToken, { mode: 0o600 });
  }
  fs.chmodSync(tp, 0o600);

  return {
    agent_name: reply.agent_name,
    agent_id: reply.agent_id,
    linkBurned: reply.link_burned !== false,
  };
}

/**
 * Enrol from a CLAIM CODE rather than a setup link.
 *
 * The difference is what the owner carries. A setup link is a bearer credential: read it
 * within fifteen minutes and you hold the agent's vault key. A claim code names a blob
 * sealed to this machine's broker key, so reading it gets you ciphertext.
 *
 * The flow is otherwise identical to `enrol`, including reusing an existing socket token,
 * because a repair rotates the VAULT credentials and the socket token is a separate local
 * identity — replacing it would have a running agent refused by the broker that just
 * enrolled it, with 'unauthorized' as the only clue.
 */
export async function enrolClaim(claimCode: string): Promise<EnrolResult & { linkBurned: boolean }> {
  const { agentTokenPath } = await import('./paths.js');
  const path = await import('node:path');
  const code = claimCode.trim().toUpperCase();

  // Ask WHOSE claim this is first. Reading a claim does not spend it, so this costs one
  // round trip and removes the same race the link path removes: without it the caller
  // must mint a token, enrol, learn the name from the reply, and reconcile the file
  // afterwards — and a running agent whose token was replaced is refused by the broker
  // that just re-enrolled it, with 'unauthorized' as the only clue.
  const who = await ask({ action: 'whose_claim', claim_code: code });
  if (who?.error) throw new Error(who.error);
  const agentName = String(who?.agent_name ?? '');
  if (!agentName) throw new Error('The server did not say which agent that claim is for.');

  // Reuse the existing token when there is one. A repair rotates the VAULT credentials;
  // the socket token is a separate local identity read once at startup by any agent
  // already running.
  const tp = agentTokenPath(agentName);
  let socketToken = '';
  if (fs.existsSync(tp)) {
    try {
      const existing = fs.readFileSync(tp, 'utf8').trim();
      if (existing.length >= 32) socketToken = existing;
    } catch { /* unreadable: mint a new one below */ }
  }
  const reusedToken = Boolean(socketToken);
  if (!socketToken) socketToken = crypto.randomBytes(32).toString('hex');

  const reply = await ask({ action: 'enrol_claim', claim_code: code, socket_token: socketToken });
  if (reply?.error) throw new Error(reply.error);
  if (!reply?.ok || !reply.agent_name) throw new Error('The broker did not confirm the enrolment.');

  // Written only after the broker has confirmed, and skipped entirely when the value did
  // not change. Writing first would leave a token file for an agent that does not exist,
  // which reads as a working setup and is not.
  if (!reusedToken) {
    const dir = path.dirname(tp);
    // chmod unconditionally: mkdir's mode is masked by umask and ignored on a directory
    // that already exists, and writeFileSync's mode applies only when it creates the file.
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
    fs.writeFileSync(tp, socketToken, { mode: 0o600 });
  }
  fs.chmodSync(tp, 0o600);

  return {
    agent_name: String(reply.agent_name),
    agent_id: String(reply.agent_id ?? ''),
    linkBurned: reply.link_burned !== false,
  };
}

/** Ask the broker whether this machine is paired, so a caller can pick the right path. */
export async function pairedStatus(): Promise<{ paired: boolean; fingerprint?: string; account_label?: string }> {
  const reply = await ask({ action: 'paired' });
  if (reply?.error) throw new Error(reply.error);
  return {
    paired: Boolean(reply?.paired),
    fingerprint: reply?.fingerprint ? String(reply.fingerprint) : undefined,
    account_label: reply?.account_label ? String(reply.account_label) : undefined,
  };
}

export interface CleanupResult { deleted: boolean; oldUnitStopped: boolean; pending: string[]; }

/**
 * Remove the pre-split store, once every agent is across.
 *
 * Still refused while anything is pending. The old credentials for an un-repaired agent
 * are the only ones it has, and deleting them would take that agent off the air with no
 * way back except creating a new one.
 */
export async function cleanup(): Promise<CleanupResult> {
  refuseOffLinux();
  const st = await status();
  if (st.alreadyDone) {
    // The store is already gone, but the old unit may not be — an earlier --finish could
    // have shredded the store and failed to reach the user bus. Returning early here meant
    // that state could never be repaired by rerunning: no store, so nothing to do, while a
    // disabled-but-present unit file waited to start a second daemon at the next boot.
    const unit = await stopOldUserUnit();
    if (unit === 'gone') removeOldUnitFile();
    return { deleted: false, oldUnitStopped: unit === 'gone', pending: [] };
  }
  if (st.pending.length) return { deleted: false, oldUnitStopped: false, pending: st.pending };

  console.error(`[migrate] deleting the pre-split store: ${st.oldStorePath}`);

  // The store is shredded even if the old unit is still up, and that is safe HERE and only
  // here: reaching this point means every agent is across, which means every one of them
  // was repaired, which means the server has already rotated the credentials in that file
  // to dead ones. It is stale ciphertext, not a live secret.
  //
  // The unit is a different matter. It is reported, and its unit FILE is removed so a
  // reboot does not quietly start a second daemon — the thing a rerun could not fix once
  // the store was gone.
  const oldUnit = await stopOldUserUnit();
  for (const f of [legacy.profiles(), legacy.salt()]) {
    try { shred(f); } catch { /* best effort */ }
  }
  if (oldUnit === 'gone') removeOldUnitFile();
  return { deleted: !fs.existsSync(legacy.profiles()), oldUnitStopped: oldUnit === 'gone', pending: [] };
}

/**
 * Overwrite before unlinking.
 *
 * Not a guarantee — a journalling or copy-on-write filesystem, or an SSD's wear
 * levelling, can keep the old blocks regardless. Worth doing because it costs nothing and
 * removes the easy case, and worth saying plainly that it does not make the data
 * unrecoverable. After repair these credentials are already rejected by the server, so
 * this is tidiness rather than the thing keeping anyone safe.
 */
function shred(file: string): void {
  if (!fs.existsSync(file)) return;
  const size = fs.statSync(file).size;
  if (size > 0) fs.writeFileSync(file, crypto.randomBytes(size));
  fs.unlinkSync(file);
}

export function describeStatus(st: MigrationStatus, dashboardUrl = 'https://wundervault.com/dashboard'): string {
  if (st.alreadyDone) {
    return 'Nothing to migrate — there is no old store in your home directory.';
  }
  const lines: string[] = [];
  if (st.across.length) lines.push(`Already across: ${st.across.join(', ')}`);
  if (!st.pending.length) {
    lines.push('');
    lines.push('Every agent is across. Remove the old store:');
    lines.push('  wundervault-agent --migrate --finish');
    return lines.join('\n');
  }
  lines.push(`Still to do (${st.pending.length}): ${st.pending.join(', ')}`);
  lines.push('');
  lines.push('These agents were set up before the broker had its own account, so their');
  lines.push('credentials are in a file your agents can read. Repair moves each one across');
  lines.push('and KEEPS its vault access — same agent, same permissions, new credentials.');
  lines.push('');
  lines.push(`  1. Open ${dashboardUrl}`);
  lines.push('  2. Press REPAIR on the agent, and copy the setup link it gives you');
  lines.push('  3. Run:  wundervault-agent --enrol');
  lines.push('     …and paste the link when it asks. Do NOT put it on the command line:');
  lines.push('     every process you run can read another\'s command line, so the link');
  lines.push('     would be visible to the very agents it is meant to keep out.');
  lines.push('');
  lines.push('The link is good for 15 minutes and works once. Repeat for each agent, then');
  lines.push('run  wundervault-agent --migrate --finish  to delete the old file.');
  return lines.join('\n');
}
