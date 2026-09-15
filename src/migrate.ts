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
import { legacy, mgmtSocketPath } from './paths.js';

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

export interface MigrationStatus {
  pending: string[];
  across: string[];
  alreadyDone: boolean;
  oldStorePath: string;
}

/** What still needs doing. Reads; changes nothing. */
export async function status(): Promise<MigrationStatus> {
  const oldStorePath = legacy.profiles();
  const ping = await ask({ action: 'ping' }).catch((e) => {
    throw new Error(
      `Could not reach the daemon at ${mgmtSocketPath()}: ${(e as Error).message}\n` +
      `Install it first:  sudo sh packaging/install-daemon.sh\n` +
      `Then check:        systemctl status wundervault-agent`,
    );
  });
  if (!ping?.ok) throw new Error('The daemon answered, but not with ok. Check its logs.');

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
export async function enrol(setupUrl: string): Promise<EnrolResult> {
  const socketToken = crypto.randomBytes(32).toString('hex');
  const reply = await ask({ action: 'enrol', setup_url: setupUrl, socket_token: socketToken });
  if (reply?.error) throw new Error(reply.error);
  if (!reply?.ok || !reply.agent_name) throw new Error('The daemon did not confirm the enrolment.');

  // Written only after the daemon has confirmed. Writing first would leave a token file
  // for an agent that does not exist, which reads as a working setup and is not.
  const { agentTokenPath } = await import('./paths.js');
  const tp = agentTokenPath(reply.agent_name);
  const path = await import('node:path');
  const dir = path.dirname(tp);
  // chmod unconditionally: mkdir's mode is masked by umask and ignored on an existing
  // directory, and writeFileSync's mode applies only when it creates the file. This token
  // is the agent's identity in front of a world-connectable socket.
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  fs.writeFileSync(tp, socketToken, { mode: 0o600 });
  fs.chmodSync(tp, 0o600);

  return { agent_name: reply.agent_name, agent_id: reply.agent_id };
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
  const st = await status();
  if (st.alreadyDone) return { deleted: false, oldUnitStopped: false, pending: [] };
  if (st.pending.length) return { deleted: false, oldUnitStopped: false, pending: st.pending };

  console.error(`[migrate] deleting the pre-split store: ${st.oldStorePath}`);

  const oldUnit = await stopOldUserUnit();
  for (const f of [legacy.profiles(), legacy.salt()]) {
    try { shred(f); } catch { /* best effort */ }
  }
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
    return 'Nothing to migrate — there is no pre-split store in your home directory.';
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
  lines.push('These agents were set up before the daemon had its own account, so their');
  lines.push('credentials are in a file your agents can read. Repair moves each one across');
  lines.push('and KEEPS its vault access — same agent, same permissions, new credentials.');
  lines.push('');
  lines.push(`  1. Open ${dashboardUrl}`);
  lines.push('  2. Press REPAIR on the agent, and copy the setup link it gives you');
  lines.push('  3. Run:  wundervault-agent --enrol "<the whole link, including the #part>"');
  lines.push('');
  lines.push('The link is good for 15 minutes and works once. Repeat for each agent, then');
  lines.push('run  wundervault-agent --migrate --finish  to delete the old file.');
  return lines.join('\n');
}
