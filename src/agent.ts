#!/usr/bin/env node
/**
 * The credential daemon, running as its own user.
 *
 * Before phase 4 this process shared a uid with the agents it served, so its key file, its
 * memory and its sockets were all readable by the party it was protecting them from.
 * Everything the vault claimed was true only against an agent that did not try.
 *
 * It now runs as the `wundervault` system account with its state in /var/lib/wundervault,
 * mode 0700. That directory mode is the boundary. The at-rest encryption is defence in
 * depth and is described as such — its key derives from the machine id, the uid and a salt
 * file kept beside the ciphertext, so anyone who can read the directory can recompute it.
 *
 * WHAT CHANGED IN THE THREAT MODEL, AND WHY THE SOCKETS LOOK WEAKER
 *
 * The per-agent sockets used to be 0600. They cannot be any more: the daemon is now a
 * different uid from every agent, and a 0600 socket it owns is one no agent could reach.
 * So the sockets are world-connectable and the TOKEN is the identity — a file in the
 * agent's own home at 0600, which only that uid can read.
 *
 * That makes the token check load-bearing in a way it never was. It used to be a second
 * lock behind a file mode; it is now the only lock. Two consequences the previous version
 * got wrong and this one must not:
 *
 *   1. A profile with no token used to be served to anyone who connected, because the
 *      check was inside `if (profile.socket_token)`. Behind a 0600 socket that was
 *      merely sloppy. In front of a world-connectable one it hands credentials to any
 *      local user. A profile without a token is now refused outright.
 *   2. Anyone may knock, so bad attempts are rate-limited per agent.
 */
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { VERSION } from './version.js';
import { redeemSetupLink, peekAgentName } from './enrol.js';
import {
  systemRoot, profilesPath, saltPath, mgmtSocketPath, agentSocketPath,
  runtimeDir, ensureSystemRoot, safeName, SYSTEM_ACCOUNT, mgmtDir, networkStorePath,
  splitAvailable, systemdCredential, sealKind, boundaryIsReal, principalId, platformShape,
  expectedAccount,
  type SealKind,
} from './paths.js';
import {
  agentEndpoint, mgmtEndpoint, listenOn, withHello, releaseEndpoint, publishBrokerPublicKey,
  helloSignerFrom, usesPortFiles, anotherBrokerIsServing, endpointLabel,
  type Endpoint, type HelloSigner,
} from './endpoint.js';
import { loadOrCreateIdentity, logSignerFromIdentity, brokerPublicKeyObject } from './broker-key.js';
import { load as loadNetworkShape } from './network-store.js';
import { BrokerOps, type ActivitySink } from './broker-ops.js';
import { ActivityLog } from './activity-log.js';
import { Anchorer } from './activity-anchor.js';
import type { BrokeredOp } from './ssh-agent.js';

/**
 * The per-agent socket request cap.
 *
 * Enforced before parsing, on the raw buffer, so it bounds an unauthenticated caller.
 */
const MAX_REQUEST_BYTES = 1024 * 1024;

/**
 * The largest reply the broker will serialise.
 *
 * Generous — an upstream JSON body is the big case — and still a bound. The MCP client
 * caps its side at the same figure; bounding only one end leaves the other holding
 * whatever the first will produce.
 */
const MAX_REPLY_BYTES = 8 * 1024 * 1024;

/** Everything a caller may ask the per-agent socket for. */
interface SocketRequest {
  token?: string;
  op?: string;
  entry_id?: string;
  purpose?: string;
  operation_id?: string;
  args?: Record<string, unknown>;
  request?: unknown;
  session_id?: string;
  include_plaintext?: boolean;
  op_spec?: unknown;
  ttl_seconds?: number;
  /** BUILD 2: pay */
  payment_required?: unknown;
  accept_index?: unknown;
  /** BUILD 2: sign */
  data?: unknown;
  encoding?: unknown;
}

interface AgentProfile {
  agent_name: string;
  api_key: string;
  enc_key: string;
  vault_url: string;
  socket_token?: string;
}

interface ProfileStore {
  profiles: AgentProfile[];
}

/**
 * Refuse to be root.
 *
 * The unit says `User=wundervault`, but a unit is a file someone can edit, and a daemon
 * that silently keeps root because of a typo in /etc is worse than one that never had it:
 * every protection below would still appear to be working. Failing here makes the mistake
 * loud at the only moment anyone is watching.
 */
/**
 * Say which world this daemon is actually running in.
 *
 * On Linux after the install it holds a real boundary: a different uid, a directory the
 * agent cannot open, memory the agent cannot read. Everywhere else it is the same uid as
 * the agents it serves, which is careful handling and nothing more. Printing that at
 * startup is the difference between a limitation and a false claim — the release notes say
 * "the key never reaches the agent", and on macOS today that is true only of an agent that
 * does not try.
 */
/**
 * The Windows console does not render what we write.
 *
 * Node writes UTF-8; `cmd.exe` and the default PowerShell host read the machine's OEM code
 * page, so the em-dash in the startup warning came out as `?"` on Windows 10 — observed.
 * A boundary warning that looks like a mis-decoded string is a boundary warning people
 * stop reading.
 *
 * Transliteration rather than `chcp 65001`, because changing the console's code page is a
 * side effect on the user's terminal that outlives the process, and this is six characters.
 */
export function consoleSafe(text: string): string {
  if (process.platform !== 'win32') return text;
  const pretty = text
    .replace(/[\u2014\u2013]/g, '-')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/\u2026/g, '...')
    .replace(/\u00a0/g, ' ');

  // AND THEN EVERYTHING ELSE, because the promise is "no non-ASCII reaches the Windows
  // console", not "the punctuation I happened to type is handled". Our own prose is not the
  // only thing that gets printed here: agent names, file paths, and upstream error messages
  // all flow through, and an agent called `José` put a raw non-ASCII byte straight back on
  // the console the transliteration list was written to keep clear.
  //
  // Escaped rather than replaced with '?', so a name that needed mangling is still
  // identifiable in the log rather than turned into a different name.
  // eslint-disable-next-line no-control-regex
  return pretty.replace(/[^\x00-\x7f]/g, (c) =>
    `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** Every daemon message goes through here, so the transliteration cannot be forgotten. */
function say(text: string): void { console.error(consoleSafe(text)); }

/**
 * Apply it to EVERYTHING, once, at the stream.
 *
 * Routing each console.error through consoleSafe() by hand is the version of this fix that
 * decays: there are twenty of them, new ones get added, and the one that matters is
 * whichever message a person is reading when something has gone wrong. Wrapping the two
 * streams catches those, the ones thrown from inside errors, and the ones written by code
 * that has not been born yet.
 *
 * Windows only, and a no-op that returns false everywhere else — the streams on Linux and
 * macOS are not touched at all.
 */
export function installConsoleTransliteration(): boolean {
  if (process.platform !== 'win32') return false;
  for (const stream of [process.stdout, process.stderr]) {
    const original = stream.write.bind(stream);
    (stream as unknown as { write: (...a: unknown[]) => boolean }).write =
      (chunk: unknown, ...rest: unknown[]): boolean => {
        if (typeof chunk === 'string') {
          return (original as (...a: unknown[]) => boolean)(consoleSafe(chunk), ...rest);
        }
        return (original as (...a: unknown[]) => boolean)(chunk, ...rest);
      };
  }
  return true;
}

/** The privileged install command for this platform. */
export function installerCommand(platform: string = process.platform): string {
  if (platform === 'darwin') return 'sudo sh packaging/install-daemon-macos.sh';
  if (platform === 'win32') {
    return 'powershell -ExecutionPolicy Bypass -File packaging\\install-daemon-windows.ps1'
      + '   (in an Administrator prompt)';
  }
  return 'sudo sh packaging/install-daemon.sh';
}

function announceBoundary(): void {
  if (boundaryIsReal()) return;

  // Two different situations, and telling them apart is the whole value of the message.
  if (!splitAvailable()) {
    say(
      `[wundervault-agent] Running on ${process.platform}, where the secret broker cannot\n` +
      `[wundervault-agent] have its own account. State is in your own directory and it runs as\n` +
      `[wundervault-agent] YOU — so its key material and memory are readable by anything you\n` +
      `[wundervault-agent] run, including your agents. That is the pre-split threat model.`,
    );
    return;
  }

  // The platform CAN do this and the install has not been done — or has been undone. Said
  // separately because the fix is a command, not a wait for a future release.
  //
  // The Windows sentence says ACL rather than 0700, because 0700 is meaningless there:
  // chmod is a no-op and stat reports 666 for every file on the volume. Telling a Windows
  // user to look for a mode would send them hunting something that cannot exist.
  const shape = platformShape();
  const what = shape === 'windows'
    ? `is not a directory whose ACL is limited to the broker's own account`
    : `is not a 0700 directory\n[wundervault-agent] owned by a separate account`;

  // TWO DIFFERENT FAILURES, AND ONE SENTENCE WAS BEING USED FOR BOTH.
  //
  // "this daemon is running as the same user as the agents it serves" is the uninstalled
  // case. On a machine where the install DID take and someone then widened the ACL, the
  // daemon is still its own account -- the directory is simply open -- and saying it runs
  // as you is false. This file's whole discipline is that a warning must not be the wrong
  // warning, and a reader who is told the wrong thing goes looking in the wrong place.
  let sameUser = true;
  try { sameUser = os.userInfo().username.toLowerCase() !== expectedAccount().toLowerCase(); }
  catch { sameUser = true; }

  const consequence = sameUser
    ? `[wundervault-agent] so this daemon is running as the same user as the agents it\n` +
      `[wundervault-agent] serves. Its key material and memory are readable by anything you run.\n` +
      `[wundervault-agent]   ${installerCommand()}`
    : `[wundervault-agent] This daemon IS running as its own account (${expectedAccount()}),\n` +
      `[wundervault-agent] but that directory is open to more than that account -- so the\n` +
      `[wundervault-agent] separation is not doing anything. Its contents are readable by\n` +
      `[wundervault-agent] whoever the directory lets in. Re-run the installer to reset it:\n` +
      `[wundervault-agent]   ${installerCommand()}`;

  say(`[wundervault-agent] No privilege boundary: ${systemRoot()} ${what}.\n${consequence}`);
}

/**
 * A refusal that RESTARTING CANNOT FIX.
 *
 * launchd has no equivalent of systemd's `Restart=on-failure` with a give-up count: a
 * KeepAlive job that exits non-zero is restarted, immediately, for ever. So a daemon that
 * correctly refuses to start — no store key and no machine identity, a socket directory
 * the agents cannot traverse, running as the wrong account — would respawn every couple of
 * seconds and append its explanation to a log inside a 0700 directory nobody is watching,
 * until the disk filled.
 *
 * The launchd idiom for "do not bring me back" is a CLEAN exit, paired with
 * `KeepAlive: {SuccessfulExit: false}` in the plist. So these refusals exit 0. That is not
 * a claim that everything is fine — the message says plainly that it is not — it is the
 * only way to tell launchd that coming back will not help. A genuine crash still exits
 * non-zero and is still restarted, which is what KeepAlive is for.
 *
 * The two halves must stay in step: if the plist ever goes back to a bare `KeepAlive`,
 * this becomes a silent stop instead of a loud one.
 */
export class ConfigurationRefusal extends Error {
  readonly configurationRefusal = true;
}

function refuseRoot(): void {
  const uid = (process as unknown as { getuid?: () => number }).getuid?.();
  if (uid === 0) {
    console.error(
      `[wundervault-agent] Refusing to run as root.\n` +
      `  The secret broker holds credentials and must run as its own unprivileged account.\n` +
      `  Expected User=${SYSTEM_ACCOUNT} in the unit file.\n` +
      `  If you installed by hand, re-run packaging/install-daemon.sh.`,
    );
    process.exit(1);
  }
}

/**
 * The key the profile store is encrypted with.
 *
 * TWO MODES, AND THE DIFFERENCE IS THE WHOLE POINT.
 *
 * SEALED (preferred). systemd unseals a random 32-byte key for us — sealed to this
 * machine's TPM where there is one, to the root-only host key otherwise — and drops it in a
 * private tmpfs only this service can read. The key is not derived from anything; it is a
 * secret. Copy the disk to another machine and the store does not open, because the TPM
 * that sealed it is not there.
 *
 * DERIVED (fallback, and what this used to be exclusively). HKDF over
 * sha256(machine-id : uid) with a salt stored beside the ciphertext. Every input to that is
 * readable by anyone who can read the directory, so the key is RECOMPUTABLE: it is not a
 * secret, it is an obfuscation, and the directory mode was doing all the real work. That is
 * fine as defence in depth and was always described as such — it is not fine as the only
 * thing standing between a stolen disk and every credential on it.
 *
 * Both are supported because the fallback has to exist: no TPM, an older systemd, a
 * container, a hand-started broker. What must not happen is a machine silently sitting in
 * the weaker mode while the release notes describe the stronger one, so the mode in force is
 * reported at startup and by `ping`.
 */
type KeyMode = 'sealed-tpm' | 'sealed-host' | 'local-file' | 'derived' | 'derived-shared';

/**
 * This machine's identity, or null when it has none we can read.
 *
 * `/etc/machine-id` is a Linux file. On macOS the read fails, and the ORIGINAL code
 * swallowed that and carried on with the literal string `unknown` — so the derived store
 * key on a Mac was HKDF over sha256("unknown:501"), and 501 is the first account macOS
 * creates. Every Mac in the world running this daemon derived the SAME store key. The
 * fallback was documented as "recomputable by anyone who can read the directory"; on macOS
 * it was computable by anyone who could read this source file.
 *
 * The macOS equivalent is the hardware UUID from the IOKit registry. It is not a secret
 * either — nothing about the derived mode is — but it is per-machine, which is the entire
 * property the derivation was supposed to have.
 */
export function machineIdentity(): string | null {
  const override = process.env.WUNDERVAULT_MACHINE_ID;
  if (override && override.trim()) return override.trim();

  // DARWIN FIRST, and the order is deliberate. /etc/machine-id is not a macOS file, but
  // nothing stops a third-party package or an administrator creating one — and a file that
  // can be copied between machines with the disk image is exactly the property this
  // derivation must not have. The hardware UUID cannot be copied, so on a Mac it wins.
  if (process.platform === 'darwin') {
    try {
      const out = execFileSync('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], {
        encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'],
      });
      const uuid = parseIOPlatformUUID(out);
      if (uuid) return uuid;
    } catch { /* no ioreg, or it failed */ }
  }

  // WINDOWS HAS NEITHER OF THE OTHER TWO, AND SAYING SO IS THE WHOLE POINT.
  //
  // Before this branch existed machineIdentity() returned null on every Windows machine,
  // and phase 7's keyModeFor() turns a null identity with no existing store into `refuse`.
  // So the daemon did not start at all on a fresh Windows box — observed on Windows 10
  // 22H2, 2026-09-18. The comment above keyModeFor called that branch "unreachable on any
  // machine that has /etc/machine-id or ioreg, which is all of them". Windows is not.
  if (process.platform === 'win32') return windowsMachineIdentity();

  try {
    const id = fs.readFileSync('/etc/machine-id', 'utf8').trim();
    if (id) return id;
  } catch { /* not linux, or a container without one */ }

  return null;
}

/**
 * TWO SOURCES, COMBINED, BECAUSE EACH ONE FAILS IN A DIFFERENT WAY.
 *
 * `MachineGuid` (HKLM\SOFTWARE\Microsoft\Cryptography) is generated when Windows is
 * installed. It is the exact shape of thing the macOS bug was about: it travels with a
 * disk image, so two machines cloned from one image share it.
 *
 * The SMBIOS UUID (`Win32_ComputerSystemProduct.UUID`) is hardware and does not travel —
 * but on real boards it is often junk. win199, a Supermicro machine, reports
 * `00000000-0000-0000-0000-AC1F6B1C4252`: twelve zero bytes and the NIC's MAC address.
 * That one is still unique; all-zeros and all-FFs, which other vendors ship, are not, and
 * trusting them blindly puts every such machine on one derived key. That IS the macOS bug.
 *
 * So: drop a source that is absent or degenerate, hash what is left, and return null only
 * when NOTHING usable remains — at which point `refuse` is the correct answer rather than
 * an accident.
 *
 * Pure, and separated from the two subprocesses that collect the values, because the part
 * that can silently return the wrong thing is the part that has to be testable off
 * Windows.
 */
export function machineIdentityFromSources(
  smbiosUuid: string | null,
  machineGuid: string | null,
): string | null {
  const parts: string[] = [];
  const s = usableWindowsId(smbiosUuid);
  const g = usableWindowsId(machineGuid);
  if (s) parts.push(`smbios=${s}`);
  if (g) parts.push(`machineguid=${g}`);
  if (parts.length === 0) return null;
  return crypto.createHash('sha256').update(`wv-win:${parts.join(':')}`).digest('hex');
}

/**
 * Is this value actually per-machine?
 *
 * Rejects what is not a UUID at all, and the placeholder values that many machines share.
 * Deliberately does NOT reject win199's mostly-zero UUID: it is ugly and it is unique,
 * and a rule tight enough to exclude it would exclude a large slice of real hardware for
 * no gain. The test is "could another machine produce this", not "does it look tidy".
 */
function usableWindowsId(raw: string | null): string | null {
  const v = String(raw ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v)) return null;
  const hex = v.replace(/-/g, '');
  if (/^0+$/.test(hex)) return null;                 // all zeros: the commonest placeholder
  if (/^f+$/.test(hex)) return null;                 // all FFs: an unprogrammed field
  // Known vendor placeholders, shipped identically on every unit of a model.
  if (hex === '03000200040005000006000700080009') return null;
  return v;
}

/**
 * Collect the two Windows sources. Subprocesses, so kept away from the pure part above.
 *
 * `reg query` for MachineGuid because it is fast and always present. PowerShell for the
 * SMBIOS UUID because `wmic` is deprecated and unreliable on current builds. Both are
 * bounded by a timeout and both failures are survivable — losing one source is exactly the
 * case machineIdentityFromSources is built for.
 */
function windowsMachineIdentity(): string | null {
  let smbios: string | null = null;
  let guid: string | null = null;

  try {
    const out = execFileSync('powershell', [
      '-NoProfile', '-NonInteractive', '-Command',
      '(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID',
    ], { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] });
    smbios = out.trim() || null;
  } catch { /* no PowerShell, or CIM is unwell */ }

  try {
    const out = execFileSync('reg', [
      'query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid',
    ], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    const m = out.match(/MachineGuid\s+REG_SZ\s+(\S+)/i);
    guid = m ? m[1] : null;
  } catch { /* registry read failed */ }

  return machineIdentityFromSources(smbios, guid);
}

/**
 * Pull the hardware UUID out of ioreg's output.
 *
 * Separated from the exec so the parsing — the part that can silently return the wrong
 * thing — is testable somewhere other than a Mac. A regex that quietly fails to match
 * lands us straight back on the shared key, which is the bug this replaced.
 */
export function parseIOPlatformUUID(ioregOutput: string): string | null {
  const m = ioregOutput.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/);
  if (!m || !m[1]) return null;
  // ioreg prints a canonical UUID. Anything else means the format moved and we should say
  // we have no identity rather than derive a key from a surprise.
  const v = m[1].trim();
  return /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/.test(v)
    ? v
    : null;
}

/**
 * The OLD derived key, kept for ONE purpose: opening a store THIS DAEMON ACCOUNT wrote
 * under the previous derivation.
 *
 * It contains the `unknown` constant deliberately — removing it would leave such a store
 * unopenable, turning an upgrade into silent data loss. New stores are never written
 * under it.
 *
 * WHAT IT DOES NOT DO, because an earlier comment here implied otherwise: it does not
 * carry a PRE-SPLIT macOS store across. That store lives in the owner's home and was
 * encrypted with the OWNER's uid in the derivation; this runs as the daemon account, with
 * a different uid, so the key does not match and could not. Nor should it — migration
 * deliberately carries no credentials. `--migrate` runs as the owner, reads only the
 * agent NAMES out of that store (see legacyAgentNames in migrate.ts, which derives with
 * the owner's uid and is correct as written), and the credentials themselves are replaced
 * by REPAIR, in the dashboard. Do not "fix" this to reach across the uid boundary.
 */
export function legacyDerivedKey(): Buffer {
  let machineId = 'unknown';
  try { machineId = fs.readFileSync('/etc/machine-id', 'utf8').trim(); } catch { /* not linux */ }
  const uid = (process as unknown as { getuid?: () => number }).getuid?.() ?? 0;
  const ikm = crypto.createHash('sha256').update(`${machineId}:${uid}`).digest();

  // Buffer.from, not a cast: hkdfSync returns an ArrayBuffer, and the `as unknown as
  // Buffer` this replaced made `.length` read undefined on a value the rest of the file
  // treats as a Buffer. It happened to work because nothing asked.
  return Buffer.from(crypto.hkdfSync(
    'sha256', ikm, readOrCreateSalt(), Buffer.from('wundervault-agent-v1'), 32,
  ));
}

function readOrCreateSalt(): Buffer {
  const sp = saltPath();
  if (fs.existsSync(sp)) return fs.readFileSync(sp);
  const salt = crypto.randomBytes(32);
  ensureSystemRoot();
  fs.writeFileSync(sp, salt, { mode: 0o600 });
  return salt;
}

/**
 * The derived key for a machine that HAS an identity. Same construction, real input.
 *
 * Shares the salt file with the legacy key deliberately: the salt is not the secret and a
 * second salt would mean a second file to lose.
 */
export function derivedKeyFor(identity: string): Buffer {
  // principalId(), not `getuid() ?? 0`. On POSIX it returns the uid as a string, so this
  // is bit-for-bit what it always was and no existing store moves. On Windows getuid is
  // undefined and the old fallback made every account on the box principal 0 — one derived
  // key shared by every user of the machine, which is the macOS bug in a second costume.
  const ikm = crypto.createHash('sha256').update(`${identity}:${principalId()}`).digest();
  // Buffer.from, not a cast: hkdfSync returns an ArrayBuffer, and the `as unknown as
  // Buffer` this replaced made `.length` read undefined on a value the rest of the file
  // treats as a Buffer. It happened to work because nothing asked.
  return Buffer.from(crypto.hkdfSync(
    'sha256', ikm, readOrCreateSalt(), Buffer.from('wundervault-agent-v1'), 32,
  ));
}

function sealedKey(): Buffer | null {
  const raw = systemdCredential();
  if (!raw) return null;
  // Expanded rather than used raw, so the stored secret is never the working key and can be
  // re-purposed later (a second context string gives a second independent key).
  return Buffer.from(crypto.hkdfSync(
    'sha256', raw, Buffer.alloc(0), Buffer.from('wundervault-store-v2'), 32,
  ));
}

/**
 * WHICH mode applies, separated from the key material so the decision can be asserted.
 *
 * The inputs are the three facts that decide it, supplied rather than read: whether a key
 * was unsealed, what kind, whether this machine has an identity, and whether there is
 * already a store on disk. Every one of those is awkward to arrange in a test and trivial
 * to pass — and the no-identity branch in particular is unreachable on any machine that
 * has /etc/machine-id or ioreg, which is all of them.
 */
export function keyModeFor(
  sealed: boolean,
  kind: SealKind,
  hasIdentity: boolean,
  storeExists: boolean,
): KeyMode | 'refuse' {
  if (sealed) {
    return kind === 'tpm' ? 'sealed-tpm' : kind === 'local-file' ? 'local-file' : 'sealed-host';
  }
  if (hasIdentity) return 'derived';
  // No key and no identity. Refusing is right only when nothing is lost by it.
  return storeExists ? 'derived-shared' : 'refuse';
}

function deriveMachineKey(): { key: Buffer; mode: KeyMode } {
  const sealed = sealedKey();
  const identity = machineIdentity();
  const mode = keyModeFor(!!sealed, sealKind(), identity !== null, fs.existsSync(profilesPath()));

  if (mode === 'refuse') {
    throw new ConfigurationRefusal(
      `Refusing to start: there is no store key and this machine has no identity to ` +
      `derive one from, so the only key available is identical on every machine with ` +
      `this uid. There is no existing store here, so nothing is lost by stopping.\n` +
      `  Install the broker, which writes a random store key, or set ` +
      `WUNDERVAULT_MACHINE_ID to a per-machine value.`,
    );
  }
  if (sealed) return { key: sealed, mode };
  if (identity) return { key: derivedKeyFor(identity), mode };

  // No sealed key and no machine identity. The legacy derivation still works here, and it
  // is the same value on every machine with this uid — so the store is readable by anyone
  // holding a copy of the ciphertext and this source file.
  //
  // WHETHER TO REFUSE DEPENDS ENTIRELY ON WHETHER THERE IS ANYTHING TO LOSE.
  //
  // With NO store on disk, refusing is right and there is no cost: nothing is stranded,
  // and starting would mean writing a NEW store under a key that is not a secret. Refuse.
  //
  // With a store already there, refusing to start is how an existing install becomes
  // unrecoverable — the same failure the unit file refuses elsewhere, where a cleared TPM
  // must not mean a broker that never reaches ExecStart. The store is already encrypted
  // under this key; declining to open it protects nothing and strands everything. Serve
  // it, say so at every start, and refuse ENROLMENT so no new secret joins it.
  return { key: legacyDerivedKey(), mode };
}

function encryptProfiles(store: ProfileStore, key: Buffer): Buffer {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(store), 'utf8'), cipher.final()]);
  return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
}

function decryptProfiles(buf: Buffer, key: Buffer): ProfileStore {
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8'));
}

/** Constant-time comparison of two hex tokens, safe against malformed input. */
export function tokenMatches(provided: string | undefined, expected: string | undefined): boolean {
  if (!expected) return false;          // no token configured: never a match
  if (!provided) return false;
  let a: Buffer, b: Buffer;
  try {
    a = Buffer.from(provided, 'hex');
    b = Buffer.from(expected, 'hex');
  } catch { return false; }
  // Length is compared first and separately on purpose: timingSafeEqual throws on a
  // length mismatch, and a thrown exception is a louder timing signal than the
  // comparison it was meant to protect.
  if (a.length === 0 || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Bad attempts, per agent name.
 *
 * The socket is world-connectable now, so any local process may knock. Guessing a 32-byte
 * token is not a real threat; an unbounded loop of connections is, and the log it would
 * produce is its own denial of service. A short lockout costs a legitimate agent one
 * retry after a genuine misconfiguration.
 */
/**
 * Make guessing expensive without letting a guesser deny the real agent.
 *
 * The first shape of this was a lockout: ten bad tokens for an agent name and that name
 * was refused for sixty seconds. Behind a 0600 socket that was defensible. It is not
 * defensible now — this phase made the per-agent sockets world-connectable, because the
 * daemon is a different uid and a 0600 socket it owns is one no agent could reach. So any
 * local process could send ten wrong tokens and take the LEGITIMATE agent off the air,
 * repeatedly, for as long as it liked. The mechanism meant to slow an attacker down had
 * become the cheapest attack available, and this phase is what introduced it.
 *
 * The rule now: a correct token is ALWAYS served. Nothing an attacker sends can change
 * what the holder of the real token gets back. The cost falls on the failing caller
 * instead, as a delay that doubles per consecutive failure — which is what actually
 * throttles guessing, since it is the attacker's own connection that has to wait.
 *
 * The delay is per agent name, and that is a deliberate, stated limit: a unix socket
 * carries no address to attribute failures to, and Node exposes no SO_PEERCRED to
 * identify the caller. So a persistent guesser does slow down a legitimate client that
 * is ALSO failing — but a legitimate client that is failing has the wrong token, and
 * telling it so a second later costs nothing.
 */
class Knocks {
  private fails = new Map<string, { n: number; until: number }>();
  private readonly WINDOW_MS = 60_000;
  // Overridable so the tests can exercise the growth curve without sitting through it.
  // Production values are the defaults; nothing in the shipped path sets these.
  private readonly BASE_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_BASE_MS) || 50;
  private readonly MAX_DELAY_MS = Number(process.env.WUNDERVAULT_KNOCK_MAX_MS) || 2_000;

  /**
   * How long to make a FAILING caller wait. Never consulted before a token is checked:
   * a valid token must not be delayed or refused because somebody else guessed wrong.
   */
  penaltyMs(name: string): number {
    const f = this.fails.get(name);
    if (!f || Date.now() >= f.until) return 0;
    return Math.min(this.BASE_DELAY_MS * 2 ** Math.min(f.n, 16), this.MAX_DELAY_MS);
  }

  record(name: string): void {
    const now = Date.now();
    const f = this.fails.get(name);
    if (!f || now >= f.until) { this.fails.set(name, { n: 1, until: now + this.WINDOW_MS }); return; }
    f.n += 1;
    // Sliding, not fixed: a guesser that keeps knocking keeps paying, rather than
    // getting a clean slate sixty seconds after its first attempt.
    f.until = now + this.WINDOW_MS;
  }

  clear(name: string): void { this.fails.delete(name); }
}

class AgentDaemon {
  private key: Buffer;
  private profiles: AgentProfile[] = [];
  private agentServers: Map<string, net.Server> = new Map();
  private mgmtServer: net.Server | null = null;
  /**
   * How this daemon proves it is this daemon, on a platform reached by a port.
   *
   * Null everywhere else, and null is the honest value: the unix-socket platforms do not
   * need it, because a socket path lives in a directory only the daemon can write and
   * nobody else can put something there for an agent to find.
   */
  private helloSigner: HelloSigner | null = null;
  private knocks = new Knocks();
  /**
   * One operations object per agent, built on first use and kept.
   *
   * Kept rather than rebuilt per connection because `AgentVaultAPI` caches the unwrapped
   * vault key after the first call, and that cache is exactly what we want: it lives in
   * the broker's memory and nowhere else. The consequence is that a repair — which
   * retires the vault key — must drop it, so `registerProfile` and `removeProfile` both
   * discard the entry rather than leaving a stale key to fail every subsequent call.
   */
  private ops: Map<string, BrokerOps> = new Map();

  /**
   * The full, signed activity log (activity-log.ts), and the job that keeps the server's
   * copy of its chain current and checks the file against it (activity-anchor.ts). Owner,
   * 2026-10-13: a full log on the computer, signed, checked by us, kept for a year.
   */
  private activity = new ActivityLog(undefined, logSignerFromIdentity);
  private anchorer = new Anchorer(this.activity, () => this.anchorClients(),
    { minIntervalMs: 60_000, delayMs: 2_000, publicKey: brokerPublicKeyObject });
  private activitySink: ActivitySink = {
    record: (r) => { if (this.activity.append(r)) this.anchorer.notify(); },
  };
  private dailyTimer: NodeJS.Timeout | null = null;

  /** Every servable agent's route to the server, so each account's chain has one. */
  private anchorClients() {
    return this.profiles
      .filter((p) => !!p.socket_token)
      .map((p) => { try { return this.opsFor(p).anchorClient(); } catch { return null; } })
      .filter((c): c is NonNullable<typeof c> => c !== null);
  }

  constructor() {
    ensureSystemRoot();
    const { key, mode } = deriveMachineKey();
    this.key = key;
    this.keyMode = mode;
    this.loadProfiles();
  }

  /** 'sealed' when the key came from the TPM via systemd; 'derived' when it is recomputable. */
  keyMode: KeyMode = 'derived';

  /**
   * A store we could not read is NOT an empty store.
   *
   * This used to log the failure and carry on with `this.profiles` still `[]`. The daemon
   * would come up serving nobody, which looks like a bad day — and then the first
   * enrolment called saveProfiles(), which wrote a store containing ONLY that profile,
   * over the ciphertext holding every other agent's credentials. A recoverable problem
   * (a changed /etc/machine-id, a recreated wundervault account, a damaged file — all of
   * which leave the plaintext retrievable) became permanent loss, silently.
   *
   * So a decrypt failure is now a refusal: the daemon will not serve and will not save
   * until a person has looked at it. Refusing to start is a visible, reversible failure.
   * Overwriting is neither.
   */
  private unreadableStore: string | null = null;

  loadProfiles(): void {
    const pp = profilesPath();
    if (!fs.existsSync(pp)) { this.unreadableStore = null; return; }
    try {
      this.profiles = decryptProfiles(fs.readFileSync(pp), this.key).profiles;
      this.unreadableStore = null;
      return;
    } catch (err) {
      // Before giving up: a store written under the OLD derived key is not corrupt, it is
      // just addressed to a key we have stopped using. Try that key, and if it opens,
      // rewrite the store under the sealed one immediately. Migration has to be automatic —
      // an upgrade that leaves every existing install unable to start is not an upgrade, and
      // one that needs a manual step is one most people will not take.
      if (this.keyMode !== 'derived') {
        try {
          const viaLegacy = decryptProfiles(fs.readFileSync(pp), legacyDerivedKey()).profiles;
          this.profiles = viaLegacy;
          this.unreadableStore = null;
          this.saveProfiles();
          console.error(
            '[wundervault-agent] Re-sealed the profile store: it was encrypted with a key ' +
            'derived from public inputs, and is now sealed to this machine.',
          );
          // The old salt is no longer an input to anything. Leaving it implies otherwise.
          try { fs.unlinkSync(saltPath()); } catch { /* already gone */ }
          return;
        } catch { /* genuinely unreadable; fall through to the refusal below */ }
      }
      this.unreadableStore = (err as Error).message;
      this.profiles = [];
      console.error(
        `[wundervault-agent] Could not read the profile store at ${pp}: ${this.unreadableStore}\n` +
        `[wundervault-agent] It is encrypted against this machine's id and the daemon's uid.\n` +
        `[wundervault-agent] REFUSING to serve or to overwrite it. The credentials are still\n` +
        `[wundervault-agent] in that file; starting fresh would destroy them. Restore the file,\n` +
        `[wundervault-agent] or move it aside deliberately if you mean to start over.`,
      );
    }
  }

  /** True when the store exists but could not be read. Nothing may be written in this state. */
  get storeUnreadable(): boolean { return this.unreadableStore !== null; }

  saveProfiles(): void {
    if (this.unreadableStore) {
      throw new Error(
        `Refusing to write the profile store: it exists but could not be decrypted ` +
        `(${this.unreadableStore}). Writing now would replace every credential in it ` +
        `with only what is in memory.`,
      );
    }
    const pp = profilesPath();
    // Write-then-rename. A half-written store read after a crash decrypts to nothing and
    // every agent on the machine loses its credentials at once.
    const tmp = `${pp}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, encryptProfiles({ profiles: this.profiles }, this.key), { mode: 0o600 });
    fs.renameSync(tmp, pp);
    try { fs.chmodSync(pp, 0o600); } catch { /* best effort */ }
  }

  registerProfile(profile: AgentProfile): void {
    // The name becomes a path segment. It arrives over a socket any local process can
    // connect to, so "../../etc/cron.d/x" would otherwise have this daemon place a file
    // wherever it liked — which for the process holding the boundary is the whole game.
    profile.agent_name = safeName(profile.agent_name);

    // Refuse before touching anything. Saving first was not enough on its own: by the time
    // saveProfiles() threw, the in-memory list had already been rewritten and the previous
    // agent's socket closed, so a rejected enrolment still took a working agent off the
    // air. The state a failure leaves behind has to be the state it started from.
    if (this.storeUnreadable) {
      throw new Error(
        `Refusing to enrol while the profile store cannot be read. Writing now would ` +
        `replace every credential in it with only what is in memory.`,
      );
    }

    // A key that is identical on every machine with this uid is not a key. Existing agents
    // keep working — pulling them off the air would be a worse answer than the one this
    // refuses — but a NEW credential must not be committed to it.
    if (this.keyMode === 'derived-shared') {
      throw new Error(
        `Refusing to enrol: this machine has no identity to derive a store key from, so ` +
        `the key protecting the store is the same on every machine with this uid. ` +
        `Install the broker, or set WUNDERVAULT_MACHINE_ID to a per-machine value.`,
      );
    }

    if (!profile.socket_token) {
      throw new Error(
        'A profile must carry a socket_token. The per-agent socket is world-connectable ' +
        'now that the daemon runs as a different user, so the token is the only thing ' +
        'identifying the caller.',
      );
    }

    const idx = this.profiles.findIndex(p => p.agent_name === profile.agent_name);
    if (idx >= 0) {
      this.profiles[idx] = profile;
      // A re-enrolment follows a repair, and a repair retires the vault key. The cached
      // operations object holds the OLD one; keeping it would make every call after a
      // repair fail to decrypt, which reads as a broken vault rather than a stale cache.
      this.dropOps(profile.agent_name);
      const old = this.agentServers.get(profile.agent_name);
      if (old) {
        // Not unlinked in the close callback: startAgentSocket unlinks and rebinds
        // immediately, and the async callback would race it.
        old.close();
        this.agentServers.delete(profile.agent_name);
      }
    } else {
      this.profiles.push(profile);
    }
    this.knocks.clear(profile.agent_name);
    // Saved BEFORE the socket is published. The other order started serving credentials
    // and then threw on save, so a daemon that had just declared it would not write to an
    // unreadable store was nonetheless handing out a profile it had not committed —
    // refusing the caller while serving the agent. Commit first; publish only if it stuck.
    this.saveProfiles();
    this.startAgentSocket(profile);
  }

  removeProfile(name: string): boolean {
    const safe = safeName(name);
    const before = this.profiles.length;
    this.profiles = this.profiles.filter(p => p.agent_name !== safe);
    if (this.profiles.length === before) return false;
    const srv = this.agentServers.get(safe);
    if (srv) { try { srv.close(); } catch { /* already gone */ } }
    this.agentServers.delete(safe);
    this.dropOps(safe);
    releaseEndpoint(agentEndpoint(safe));
    this.saveProfiles();
    return true;
  }

  /**
   * Answer one operation for one agent.
   *
   * The token has already been checked by the caller. Everything here runs as the
   * broker's uid, and NOTHING here may return `api_key` or `enc_key` — that is the
   * property the whole phase rests on, and it is asserted by a test that inspects the
   * bytes written to the socket for every operation, including the failures.
   */
  private async serve(profile: AgentProfile, msg: SocketRequest): Promise<Record<string, unknown>> {
    const op = typeof msg.op === 'string' ? msg.op : '';

    // No `op` at all is the pre-custody client asking for credentials. Answering it with
    // a generic "unknown operation" would send someone hunting through their config; say
    // what actually happened and what fixes it.
    if (!op) {
      return {
        error:
          'This broker no longer hands out vault credentials. The MCP server on this '
          + `machine is older than the broker (broker ${VERSION}). Update it: `
          + 'npm install -g @wundervault/mcp-server, then reload your MCP connection.',
        code: 'UPGRADE_REQUIRED',
        upgrade: true,
        broker_version: VERSION,
      };
    }

    // `ping` is answered BEFORE any credential is touched. Building the operations
    // object parses the encryption key, so a profile with an unusable one would make the
    // liveness check fail in the same way a dead broker does — and "is the broker there"
    // is exactly the question you ask when something is already wrong.
    if (op === 'ping') {
      // Deliberately says nothing about the vault. It exists so a client can tell a
      // broker that is running from one that is not, before it has an entry to ask for.
      return { ok: true, agent: profile.agent_name, broker_version: VERSION };
    }

    const ops = this.opsFor(profile);
    const entry = () => String(msg.entry_id ?? '');
    const purpose = () => String(msg.purpose ?? '');

    switch (op) {
      case 'list_entries':
        return await ops.listEntries() as unknown as Record<string, unknown>;

      // `get_entry` (a key's value, for the hand-over tools) and `profile_flags` (whether
      // the account let agents write keys into files) were answered here until 1.0. Both
      // served hand-over, which is retired; they now fall through to "unknown operation",
      // so no request on this socket returns a plaintext.

      case 'call': {
        if (!entry() || !purpose()) return { error: 'call needs entry_id and purpose.' };
        return await ops.call({
          entryId: entry(),
          purpose: purpose(),
          operationId: typeof msg.operation_id === 'string' ? msg.operation_id : undefined,
          callArgs: (msg.args ?? {}) as Record<string, unknown>,
          request: msg.request as never,
        }) as unknown as Record<string, unknown>;
      }

      case 'ssh_agent_open': {
        if (!entry() || !purpose()) return { error: 'ssh_agent_open needs entry_id and purpose.' };
        const ttl = Number.isFinite(msg.ttl_seconds) ? Number(msg.ttl_seconds) : 300;
        const op = msg.op_spec as BrokeredOp | undefined;
        if (!op || (op.kind !== 'ssh' && op.kind !== 'rsync') || typeof op.destination !== 'string') {
          return { error: 'ssh_agent_open needs op_spec {kind, destination, remoteArgv|rsyncArgs}.' };
        }
        return await ops.sshAgentOpen({
          entryId: entry(),
          purpose: purpose(),
          op,
          // Clamped rather than trusted: the caller is the party the session is a
          // capability for, so an unbounded ttl from it would be a request to leave the
          // signing socket open for ever.
          ttlSeconds: Math.max(10, Math.min(900, ttl)),
        }) as unknown as Record<string, unknown>;
      }

      // BUILD 2. Both answer with a signature or a refusal, never with the key.
      case 'pay': {
        if (!entry() || !purpose()) return { error: 'pay needs entry_id and purpose.' };
        if (msg.payment_required === undefined) return { error: 'pay needs payment_required.' };
        const idx = msg.accept_index;
        // A whole number or nothing. `true` must not become offer 1 (round 2, F1).
        if (idx !== undefined && idx !== null && !(typeof idx === 'number' && Number.isInteger(idx))) {
          return { error: 'Refused: accept_index must be a whole number. Nothing was signed.', code: 'BAD_REQUEST' };
        }
        return await ops.pay({
          entryId: entry(), purpose: purpose(), paymentRequired: msg.payment_required,
          ...(typeof idx === 'number' ? { acceptIndex: idx } : {}),
        }) as unknown as Record<string, unknown>;
      }

      case 'sign': {
        if (!entry() || !purpose()) return { error: 'sign needs entry_id and purpose.' };
        return await ops.sign({
          entryId: entry(), purpose: purpose(), data: msg.data, encoding: msg.encoding,
        }) as unknown as Record<string, unknown>;
      }

      case 'ssh_agent_close':
        return ops.closeSsh(String(msg.session_id ?? '')) as unknown as Record<string, unknown>;

      default:
        return { error: `Unknown operation "${op}".`, code: 'UNKNOWN_OP' };
    }
  }

  /** The operations object for one agent, built on first use. */
  private opsFor(profile: AgentProfile): BrokerOps {
    const existing = this.ops.get(profile.agent_name);
    if (existing) return existing;
    const fresh = new BrokerOps(
      profile.agent_name, profile.api_key, profile.enc_key, profile.vault_url,
    );
    fresh.activity = this.activitySink;
    this.ops.set(profile.agent_name, fresh);
    return fresh;
  }

  /** Drop an agent's cached operations — and its cached vault key — and close its sessions. */
  private dropOps(name: string): void {
    const existing = this.ops.get(name);
    if (!existing) return;
    try { existing.reset(); } catch { /* closing a dead session is not an event */ }
    this.ops.delete(name);
  }

  startAgentSocket(profile: AgentProfile): void {
    const ep = agentEndpoint(profile.agent_name);
    releaseEndpoint(ep);

    const srv: net.Server = net.createServer(withHello((socket) => {
      // BUFFERS, not a string, and the reasons are two separate bugs.
      //
      // 1. `buf.length` on a string counts UTF-16 code units, not bytes. A request of
      //    700,000 three-byte UTF-8 characters is over 2 MiB on the wire and about
      //    700,000 "long" as a string, so a byte cap enforced on a string is not a byte
      //    cap. It was harmless when the only payload was `{"token":"<hex>"}`; a `call`
      //    carries an arbitrary HTTP body.
      // 2. `chunk.toString()` decodes each chunk independently, so a multi-byte character
      //    split across two TCP reads becomes two replacement characters. The broker would
      //    then forward a body that is not the one the caller sent — silently, and only
      //    for non-ASCII content.
      //
      // Concatenating Buffers and decoding once, at the end, fixes both.
      let chunks: Buffer[] = [];
      let size = 0;
      let consumed = false;

      // TWO TIMERS, WITH DIFFERENT JOBS.
      //
      // The inactivity timer bounds a caller who never finishes sending — the slow-loris
      // shape the original 5s timeout was written for. The absolute deadline bounds the
      // connection whatever it does.
      //
      // The inactivity timer is DISARMED the moment a complete request has been read,
      // because from then on there is legitimately no traffic: the broker is fetching an
      // entry, waiting on a 30s upstream call, or parked on a tier-2 approval for up to
      // 90s. Leaving it armed destroyed the socket mid-operation and returned nothing,
      // while the broker carried on working for a caller that was no longer there.
      socket.setTimeout(30_000, () => socket.destroy());
      // 180s, not 120s: a tier-2 call waits up to 90s for a human, then re-asks the
      // server and performs a request with its own 30s timeout. A 120s ceiling would cut
      // off the one path that exists to survive a human taking their time.
      const deadline = setTimeout(() => socket.destroy(), 180_000);
      (deadline as unknown as { unref?: () => void }).unref?.();
      socket.on('close', () => clearTimeout(deadline));
      socket.on('data', (d) => {
        if (consumed) return;
        chunks.push(d);
        size += d.length;
        // Enforced on RAW BYTES, before parsing, which is what stops an unauthenticated
        // caller growing this buffer. 4096 was right for a token lookup; a `call`
        // operation carries an HTTP body, so the cap is 1 MiB.
        if (size > MAX_REQUEST_BYTES) { socket.destroy(); return; }

        // Search the CHUNK, not the accumulation. `Buffer.concat` on every data event
        // copies everything received so far, so a caller sending a sub-1-MiB line in
        // thousands of small paced writes made the broker do quadratic work BEFORE
        // authenticating — the byte cap and the deadline both eventually apply, and
        // neither stops it burning CPU in front of a legitimate agent in the meantime.
        if (d.indexOf(0x0a) < 0) return;
        const joined = Buffer.concat(chunks);
        const nl = joined.indexOf(0x0a);
        if (nl < 0) return;
        consumed = true;
        // Decoded ONCE, over the whole line, so a multi-byte character spanning chunks
        // survives.
        const line = joined.subarray(0, nl).toString('utf8').trim();

        // The request has arrived in full; the inactivity timer has done its job and
        // would now be measuring the broker's own work.
        socket.setTimeout(0);

        let msg: SocketRequest | null = null;
        try {
          const parsed = JSON.parse(line) as unknown;
          // `JSON.parse("null")` returns null, and `null.token` throws — synchronously,
          // inside a socket data callback, which takes the whole broker down. Any local
          // process could send `null\n` to a world-connectable socket and kill the
          // process holding every credential on the machine. A scalar (`5`, `"x"`) does
          // not throw but is not a request either, so the shape is checked rather than
          // the failure mode patched.
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            msg = parsed as SocketRequest;
          }
        } catch { /* treated as no token, exactly as an unparseable body always was */ }
        if (msg === null) msg = {};

        // The token is checked FIRST, before any penalty is consulted. The previous order
        // let a stranger's wrong guesses decide what the real agent got back.
        if (!tokenMatches(msg.token, profile.socket_token)) {
          const wait = this.knocks.penaltyMs(profile.agent_name);
          this.knocks.record(profile.agent_name);
          console.error(`[wundervault-agent] Auth failure on ${profile.agent_name} socket`);
          // The same answer for a bad token and a missing one. Anything more specific
          // tells a local prober which agent names exist on this machine.
          const refuse = () => {
            try {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
              socket.end();
            } catch { /* the prober hung up while waiting, which is fine */ }
          };
          if (wait > 0) {
            const t = setTimeout(refuse, wait);
            // Do not hold the event loop open on behalf of someone guessing tokens.
            (t as unknown as { unref?: () => void }).unref?.();
            socket.on('close', () => clearTimeout(t));
          } else {
            refuse();
          }
          return;
        }

        this.knocks.clear(profile.agent_name);

        // ── THE CHANGE THIS PHASE EXISTS FOR ────────────────────────────────
        //
        // This used to be:
        //
        //     socket.write(JSON.stringify({ api_key, enc_key, vault_url }))
        //
        // A valid token got the credentials, and the MCP server — which runs as the
        // AGENT's uid — used `enc_key` to unwrap `vault_key_for_agent` and decrypt the
        // whole vault in its own memory. The uid split protected the store on disk and
        // the broker's memory, and then the socket handed the key over anyway. The token
        // that authorises this lives in the agent's own home at 0600, readable by the
        // agent because that is how the MCP server authenticates, so obtaining the whole
        // vault needed no exploit at all.
        //
        // The socket now serves OPERATIONS. Nothing below can return api_key or enc_key,
        // and there is no flag, env var or legacy mode that brings the old reply back:
        // an old client gets an upgrade error, because a deprecation path here is a
        // downgrade path for an attacker.
        this.serve(profile, msg as SocketRequest)
          .then((reply) => {
            try {
              const body = JSON.stringify(reply);
              // A reply the broker cannot serialise within a bound is REFUSED rather than
              // sent. Not a confidentiality control — it is what stops an authenticated
              // caller turning one legitimate operation (a huge upstream body, a vault
              // with thousands of entries) into memory this process has to hold and the
              // client has to buffer. The client caps its side too; both ends bounding it
              // is deliberate, because either one alone leaves the other exposed.
              if (body.length > MAX_REPLY_BYTES) {
                socket.write(JSON.stringify({
                  error: `That operation produced a reply larger than `
                    + `${Math.round(MAX_REPLY_BYTES / (1024 * 1024))} MiB, so it was not sent. `
                    + `Narrow the request.`,
                  code: 'REPLY_TOO_LARGE',
                }) + '\n');
                socket.end();
                return;
              }
              socket.write(body + '\n');
              socket.end();
            } catch { /* the caller hung up while we worked */ }
          })
          .catch((e: Error) => {
            try { socket.write(JSON.stringify({ error: e.message }) + '\n'); socket.end(); }
            catch { /* as above */ }
          });
      });
      socket.on('error', () => { /* a client that hangs up is not an event */ });
    }, this.helloSigner, () => {
      const a = srv.address();
      return a && typeof a !== 'string' ? a.port : 0;
    }));

    // NO maxConnections here, deliberately — the second version of this code had one, and
    // it recreated the denial of service it was meant to prevent one layer down. A ceiling
    // of 64 means 64 held connections exclude everyone else, and the legitimate agent's
    // connection is dropped by the kernel BEFORE its token is ever read. Holding them was
    // easy: setTimeout() is an INACTIVITY timeout, so a byte every few seconds reset it
    // indefinitely, and the 4096-byte ceiling took hours to reach at that rate.
    //
    // What bounds the resource is the absolute deadline below instead: a connection dies a
    // fixed time after it was accepted, whatever it sends. Slots cannot be held, so they
    // do not need to be rationed, and nothing an attacker does can make the daemon refuse
    // a connection it has not yet authenticated.
    listenOn(
      srv, ep, this.helloSigner,
      () => { /* the per-agent endpoint is not announced; the mgmt line covers the start */ },
      (message) => {
        // A per-agent endpoint that cannot be published is an agent nobody can reach. It
        // is reported and the server is dropped, rather than left bound to a port no
        // discovery file names — which reads as "running" and serves nobody.
        console.error(`[wundervault-agent] ${profile.agent_name}: ${message}`);
        try { srv.close(); } catch { /* already gone */ }
        this.agentServers.delete(profile.agent_name);
      },
    );
    srv.on('error', (err) => {
      console.error(`[wundervault-agent] Socket error for ${profile.agent_name}:`, err.message);
    });
    this.agentServers.set(profile.agent_name, srv);
  }

  /**
   * Refuse to become the second broker on a machine that already has one.
   *
   * Awaited before start(), because on a port-addressed platform there is no EADDRINUSE to
   * stop us: two daemons run happily and the second overwrites the first's discovery
   * files, taking every agent with it. Observed during phase 8's own testing.
   */
  static async refuseIfAlreadyServing(): Promise<void> {
    if (!usesPortFiles()) return;
    const ep = mgmtEndpoint();
    if (await anotherBrokerIsServing(ep)) {
      throw new ConfigurationRefusal(
        `Another secret broker is already serving on this machine.\n` +
        `  ${endpointLabel(ep)} names a port that is answering, so starting a second\n` +
        `  broker would overwrite the address every agent here is using and point them\n` +
        `  at this process instead.\n` +
        `  Stop the running one first, or let the scheduled task manage it:\n` +
        `    schtasks /end /tn wundervault-agent`,
      );
    }
  }

  startMgmtSocket(): void {
    const ep = mgmtEndpoint();
    // The directory is the control, and it exists before the socket does. chmod-after-
    // listen leaves a window in which the socket is bound at the default mode and a
    // process watching for it can connect; a 0770 directory has no such window.
    const md = mgmtDir();
    fs.mkdirSync(md, { recursive: true, mode: 0o755 });
    // chmod is a no-op on Windows — measured, it reports 666 whatever is asked — so it is
    // skipped rather than run for the look of it. The Windows equivalent is the ACL the
    // installer puts on the run directory, and it is the installer's job.
    if (!usesPortFiles()) fs.chmodSync(md, 0o755);
    releaseEndpoint(ep);

    const mgmt: net.Server = net.createServer(withHello((socket) => {
      let buf = '';
      // An ABSOLUTE deadline as well as the inactivity one. setTimeout() below is reset by
      // any traffic, so a byte every nine seconds held a management connection for days —
      // no newline, so never consumed, and the 64KiB ceiling never reached. Enough of
      // those and the daemon runs out of file descriptors and no agent can connect.
      //
      // It is generous because enrolment legitimately waits on two network round trips,
      // and the previous 10s inactivity timeout could destroy the socket mid-enrolment:
      // the profile still got registered and the link still got burned, but the caller
      // never learned the name, so it never wrote the token file. An agent existed that
      // nothing could authenticate as.
      const hardDeadline = setTimeout(() => socket.destroy(), 60_000);
      (hardDeadline as unknown as { unref?: () => void }).unref?.();
      socket.on('close', () => clearTimeout(hardDeadline));

      // Writing to a destroyed socket throws; every reply goes through here so a client
      // that hung up cannot turn into an unhandled error inside an async handler.
      const reply = (obj: unknown) => {
        try {
          if (socket.destroyed) return;
          socket.write(JSON.stringify(obj) + '\n');
          socket.end();
        } catch { /* the caller is gone */ }
      };
      // One request per connection. The handler fires on every 'data' event and reparses
      // whatever is in the buffer, so before this flag a caller could write one valid
      // enrol line and then dribble single bytes: each one re-ran the same request, and
      // each enrol is a 100,000-round PBKDF2 plus a network fetch. A thousand of those
      // stall the event loop that every agent's credential socket shares.
      let consumed = false;
      socket.setTimeout(10_000, () => socket.destroy());
      socket.on('data', (d) => {
        buf += d.toString();
        // Enrolment carries a profile, so this ceiling is higher than the agent socket's —
        // but it is still a ceiling.
        if (buf.length > 64 * 1024) { socket.destroy(); return; }
        const nl = buf.indexOf('\n');
        if (nl < 0) return;
        if (consumed) return;
        consumed = true;

        try {
          const msg = JSON.parse(buf.slice(0, nl));
          if (msg.action === 'enrol_claim' && msg.claim_code) {
            // The claim path. What the caller hands over here is NOT a credential: it
            // names a blob sealed to this broker's public key, and only this broker's
            // private key opens it. So the code can cross a terminal, a chat log or a
            // command line without mattering — which is the whole difference from the
            // setup link, where the same journey hands over the vault key.
            void (async () => {
              try {
                if (!msg.socket_token || String(msg.socket_token).length < 32) {
                  throw new Error('An enrolment must carry a socket_token of at least 32 characters.');
                }
                const { claim, burnClaim } = await import('./pair.js');
                const c = await claim(String(msg.claim_code));
                this.registerProfile({
                  agent_name: c.agent_name,
                  api_key: c.api_key,
                  enc_key: c.enc_key,
                  vault_url: c.vault_url,
                  socket_token: String(msg.socket_token),
                } as AgentProfile);
                // Burned only after the profile is stored, for the same reason the link
                // path defers its burn: a disk error must not consume a single-use claim.
                // The burn carries api_key_hmac from inside the blob as proof — without
                // it, anyone who read the claim code could spend it first.
                const burned = await burnClaim(String(msg.claim_code), c.api_key_hmac ?? '');
                reply({ ok: true, agent_name: c.agent_name, agent_id: c.agent_id, link_burned: burned });
              } catch (e) {
                reply({ error: (e as Error).message });
              } finally {
                socket.end();
              }
            })();
            return;
          }

          if (msg.action === 'whose_claim' && msg.claim_code) {
            // Reading a claim does not spend it, so this costs one round trip and lets
            // the caller reuse an existing socket token rather than locking out a running
            // agent. The blob is not opened here and nothing from it is returned.
            void (async () => {
              try {
                const { whoseClaim } = await import('./pair.js');
                reply(await whoseClaim(String(msg.claim_code)));
              } catch (e) {
                reply({ error: (e as Error).message });
              } finally {
                socket.end();
              }
            })();
            return;
          }

          if (msg.action === 'paired') {
            // So a client can find out whether this machine has a broker identity bound
            // to an account, and refuse the weaker path itself with a useful message
            // rather than discovering it two round trips later.
            void (async () => {
              try {
                const { readPaired } = await import('./pair.js');
                const rec = readPaired();
                reply(rec
                  ? { paired: true, fingerprint: rec.fingerprint, origin: rec.origin,
                      account_label: rec.account_label ?? null, paired_at: rec.paired_at }
                  : { paired: false });
              } catch (e) {
                reply({ error: (e as Error).message });
              } finally {
                socket.end();
              }
            })();
            return;
          }

          if (msg.action === 'enrol' && msg.setup_url) {
            // The ONLY way a profile gets in. `register_profile` used to live here and
            // took whatever it was handed: any local process — every agent on this
            // machine included, since they run as the owner — could register a name with
            // a token of its choosing and then read that agent's credentials off its own
            // socket. No local permission could fix that, because the kernel cannot tell
            // the owner's shell from an agent running as the owner.
            //
            // A setup link can. It is issued by the server to someone logged in to the
            // website, it is single-use, and it expires in fifteen minutes. An agent
            // cannot obtain one. So the daemon redeems it ITSELF: the caller hands over a
            // URL and learns a name, and the credentials never exist in the asking
            // process at all.
            void (async () => {
              try {
                // Checked BEFORE anything is redeemed. Redeeming first meant a missing
                // socket_token burned a single-use link and produced no usable agent —
                // the link spent, the agent absent, and another trip to the dashboard.
                if (!msg.socket_token || String(msg.socket_token).length < 32) {
                  throw new Error('An enrolment must carry a socket_token of at least 32 characters.');
                }
                // ACCEPTANCE CHECK 14. On a paired machine the link path is refused.
                //
                // Leaving it available would make every hardening above optional: an
                // attacker who wanted the credential in bearer form would simply ask for
                // the path that still produces one. A downgrade that remains reachable is
                // not a fallback, it is the attack.
                //
                // Refused BEFORE redeeming, so a link offered to a paired broker is not
                // spent on its way to being rejected.
                const { readPaired: _paired } = await import('./pair.js');
                const pairedRec = _paired();
                if (pairedRec) {
                  throw new Error(
                    `This machine is paired with a broker (${pairedRec.fingerprint}), so setup `
                    + `links are not accepted here — they are bearer credentials and the pairing `
                    + `exists to stop one being carried.\n`
                    + `Use Repair on the agent in your vault, choose this computer, and give the agent `
                    + `the message it shows instead. Nothing was redeemed, so the link you have is still valid.`);
                }
                // The burn is deferred: the link is marked used only once the profile is
                // actually stored, so a disk error cannot consume it either.
                const { creds, burn } = await redeemSetupLink(String(msg.setup_url));
                this.registerProfile({
                  agent_name: creds.agent_name,
                  api_key: creds.api_key,
                  enc_key: creds.enc_key,
                  vault_url: creds.vault_url,
                  socket_token: String(msg.socket_token),
                } as AgentProfile);
                const burned = await burn();
                // Reported, not swallowed. An unburned link stays usable for the rest of
                // its fifteen minutes and could be replayed to overwrite this profile with
                // a different token, so the caller is told rather than reassured.
                reply({
                  ok: true, agent_name: creds.agent_name, agent_id: creds.agent_id,
                  link_burned: burned,
                });
              } catch (e) {
                reply({ error: (e as Error).message });
              }
            })();
            return;   // the async path owns this socket from here
          } else if (msg.action === 'whose_link' && msg.setup_url) {
            // The agent's NAME, redeeming nothing — the GET endpoint does not burn. This
            // exists so enrolment can find out whether that agent already has a socket
            // token BEFORE committing, which replaced a two-step register-then-swap that
            // left an agent registered under a token the caller had not saved if the
            // connection dropped in between.
            void (async () => {
              try {
                const name = await peekAgentName(String(msg.setup_url));
                reply({ ok: true, agent_name: name });
              } catch (e) {
                reply({ error: (e as Error).message });
              }
            })();
            return;
          } else if (msg.action === 'remove_profile' && msg.agent_name) {
            // Gated on the agent's own token. The socket is world-connectable now, so
            // without this any local user could delete another user's agents. It does NOT
            // distinguish one agent from another under the same uid — nothing can, and
            // the spec says so in C5 — but it does stop everyone else.
            const name = String(msg.agent_name);
            const target = this.profiles.find(p => p.agent_name === name);
            if (!target || !tokenMatches(msg.token, target.socket_token)) {
              socket.write(JSON.stringify({ error: 'unauthorized' }) + '\n');
              socket.end();
              return;
            }
            const gone = this.removeProfile(name);
            socket.write(JSON.stringify({ ok: true, removed: gone }) + '\n');
          } else if (msg.action === 'reload') {
            this.loadProfiles();
            socket.write(JSON.stringify({ ok: true, count: this.profiles.length }) + '\n');
          } else if (msg.action === 'destinations') {
            // Deliberately gone. It was served here while the socket sat behind a locked
            // directory; that lock is off, because the owner and their agents are the same
            // uid and any door the owner can open an agent can open too. Serving this now
            // would hand every agent the record of where all the others sent secrets.
            socket.write(JSON.stringify({
              error: 'destinations are not served over this socket. Run: ' +
                     'sudo wundervault-agent --destinations',
            }) + '\n');
          } else if (msg.action === 'ping') {
            // Liveness only. This used to return every agent name on the machine, which
            // is a roster of what holds credentials here, handed to anyone who could
            // reach the socket. Migration is the only caller that needs the names, and it
            // asks for them explicitly below.
            socket.write(JSON.stringify({
              ok: true, version: VERSION, store_unreadable: this.storeUnreadable,
              key_mode: this.keyMode,
              // Whether there is ACTUALLY a boundary here, from the daemon's own mouth.
              // The startup warning says this too, but a warning is a line in a log that
              // nothing can assert on; an installer's verifier needs an answer it can
              // read. Observed rather than inferred -- boundaryIsReal() looks at the
              // directory, not at process.platform.
              boundary: boundaryIsReal(),
              account: (() => { try { return os.userInfo().username; } catch { return null; } })(),
            }) + '\n');
          } else if (msg.action === 'known_agents') {
            // Names only, never credentials. This is what lets migration tell you which of
            // your agents still need a repair link, and it is the reason the destination
            // store is NOT served here any more: a roster of names is a much smaller thing
            // to give away than the record of where every agent sent its secrets.
            socket.write(JSON.stringify({
              ok: true, agents: this.profiles.map(p => p.agent_name),
            }) + '\n');
          } else {
            socket.write(JSON.stringify({ error: 'unknown action' }) + '\n');
          }
        } catch (err) {
          // The message is reported because an agent-name rejection is actionable and
          // silence here reads as a hang.
          socket.write(JSON.stringify({ error: (err as Error).message || 'parse error' }) + '\n');
        }
        socket.end();
      });
      socket.on('error', () => { /* hang-ups are not events */ });
    }, this.helloSigner, () => {
      const a = mgmt.address();
      return a && typeof a !== 'string' ? a.port : 0;
    }));

    listenOn(
      mgmt, ep, this.helloSigner,
      (label) => { console.log(`[wundervault-agent] Listening. Management: ${label}`); },
      (message) => {
        // The management endpoint is how an agent is enrolled and removed. A daemon that
        // cannot publish it has nothing to offer, and saying so is better than a process
        // that looks alive.
        throw new ConfigurationRefusal(message);
      },
    );
    mgmt.on('error', (err) => {
      console.error('[wundervault-agent] Mgmt socket error:', err.message);
    });
    this.mgmtServer = mgmt;
  }

  start(): void {
    const rt = runtimeDir();
    fs.mkdirSync(rt, { recursive: true, mode: 0o755 });
    // chmod, not just mkdir's mode. mkdir masks its mode by umask and ignores it outright
    // when the directory already exists — the same trap ensureSystemRoot() documents, and
    // it bites harder here. The macOS LaunchDaemon sets Umask 0077 so that files this
    // process writes are private, which silently turns this 0755 into 0700; the agents run
    // as the OWNER, so a 0700 socket directory means every single one of them gets EACCES
    // connecting to its own socket, on a machine where nothing else is wrong.
    //
    // The directory being traversable costs nothing. The sockets inside it are
    // world-connectable by design and each carries its own token — nothing here is
    // protected by being hard to reach.
    // WINDOWS HAS NO MODE TO CHECK. chmod there is a no-op and stat() reports 666 for
    // everything, measured — so running this check would either pass vacuously or, worse,
    // refuse to start on a correct install. The Windows equivalent is the run directory's
    // ACL, which the installer sets and verify-windows.ps1 proves from a second account.
    if (!usesPortFiles()) {
      fs.chmodSync(rt, 0o755);
      const rtMode = fs.statSync(rt).mode & 0o777;
      if ((rtMode & 0o011) !== 0o011) {
        throw new ConfigurationRefusal(
          `${rt} is mode ${rtMode.toString(8)}. Agents run as the machine's owner and need ` +
          `search permission on this directory to reach their sockets; at this mode every ` +
          `connection would fail with EACCES.`,
        );
      }
    }
    // Clear endpoints left by a crash. A stale socket makes listen() fail; a stale PORT
    // FILE is worse than that, because it does not fail — it names a port this daemon no
    // longer holds, which anything local may now have bound. Both go.
    try {
      for (const f of fs.readdirSync(rt)) {
        if (f.endsWith('.sock') || f.endsWith('.port') || f.endsWith('.port.tmp')) {
          try { fs.unlinkSync(path.join(rt, f)); } catch { /* ignore */ }
        }
      }
    } catch { /* first run */ }

    // The identity, and the half of it agents verify against. Only where the transport
    // needs it: on the unix-socket platforms nothing reads broker.pub and publishing it
    // would be a file with no reader and a question for whoever found it.
    if (usesPortFiles()) {
      const identity = loadOrCreateIdentity();
      this.helloSigner = helloSignerFrom(identity.privateKeyPem);
      publishBrokerPublicKey(identity.publicKeyB64);
    }

    for (const profile of this.profiles) {
      if (!profile.socket_token) {
        // Pre-split profiles may have none. Serving them now would hand credentials to
        // any local process, so they are skipped loudly rather than served quietly.
        console.error(
          `[wundervault-agent] Agent "${profile.agent_name}" has no socket token and will ` +
          `NOT be served. Re-run onboarding for it.`,
        );
        continue;
      }
      this.startAgentSocket(profile);
    }
    this.startMgmtSocket();
    console.log(
      `[wundervault-agent] Started with ${this.agentServers.size} agent(s). State: ${systemRoot()}`,
    );
    // A year of the activity log, then a check against Wundervault's copy: now (shortly
    // after start, once the network is up) and daily. Both unref'd: bookkeeping must never
    // be what keeps a stopping broker alive.
    // The prune asks our server first how far it may go: no line is removed before every
    // account's copy has held it for a year, and nothing is pruned while we can't ask.
    const dailyCare = async () => {
      try { this.activity.prune(undefined, await this.anchorer.pruneLimit()); } catch { /* next time */ }
      await this.anchorer.flush({ verifyLocal: true });
    };
    const firstCheck = setTimeout(() => { void dailyCare(); }, 30_000);
    (firstCheck as unknown as { unref?: () => void }).unref?.();
    this.dailyTimer = setInterval(() => { void dailyCare(); }, 24 * 60 * 60 * 1000);
    (this.dailyTimer as unknown as { unref?: () => void }).unref?.();
    // Said out loud, every start. A machine quietly running in the weaker mode while the
    // documentation describes the stronger one is the failure this line exists to prevent.
    if (this.keyMode === 'sealed-tpm') {
      console.log(
        '[wundervault-agent] Store key: SEALED TO THIS MACHINE\'S TPM. ' +
        'A copy of the disk does not open it.',
      );
    } else if (this.keyMode === 'sealed-host') {
      // Deliberately NOT the sentence above. systemd's host key lives at
      // /var/lib/systemd/credential.secret — on the same disk as the sealed store — so a copy
      // of that disk plus root does open this. Better than a key derived from public inputs,
      // and not the same claim.
      console.log(
        '[wundervault-agent] Store key: sealed to systemd\'s HOST KEY (no TPM found).\n' +
        '[wundervault-agent] That key is on this same disk, so an offline copy plus root\n' +
        '[wundervault-agent] WOULD open the store. It stops a casual file read, not a\n' +
        '[wundervault-agent] stolen disk. A TPM is what makes the disk copy useless.',
      );
    } else if (this.keyMode === 'local-file') {
      // macOS. Not sealed to anything, and deliberately NOT given the TPM sentence. What it
      // is: a random key, so it cannot be recomputed. What it is not: protected against
      // someone holding the disk. FileVault covers that and FileVault is not ours to claim.
      console.log(
        '[wundervault-agent] Store key: a random key in a 0600 file owned by this account.\n' +
        '[wundervault-agent] It is NOT sealed to hardware — a copy of the disk plus root\n' +
        '[wundervault-agent] WOULD open the store. It is not recomputable, which the old\n' +
        '[wundervault-agent] derived key was. FileVault is what covers a stolen disk.',
      );
    } else if (this.keyMode === 'derived-shared') {
      console.error(
        '[wundervault-agent] Store key: DERIVED, and this machine has no identity to derive\n' +
        '[wundervault-agent] from — so the key is THE SAME on every machine with this uid.\n' +
        '[wundervault-agent] Anyone holding a copy of the store can open it without this\n' +
        '[wundervault-agent] machine. Enrolment is refused until that is fixed: install the\n' +
        '[wundervault-agent] broker, or set WUNDERVAULT_MACHINE_ID to something per-machine.',
      );
    } else {
      // THREE PLATFORMS, THREE TRUE SENTENCES, and the third one was being told the first
      // one's. On Windows there is no machine-id, no uid, and no directory mode — chmod is
      // a no-op there and stat reports 666 whatever is asked. Printing "the directory mode
      // is what protects the store" on a Windows box names a control that does not exist
      // and points the reader away from the one that does, which is the ACL.
      const source = process.platform === 'win32'
        ? 'this machine\'s hardware id and your account SID'
        : process.platform === 'darwin'
          ? 'the hardware UUID and uid'
          : 'machine-id and uid';
      const control = platformShape() === 'windows'
        ? 'the directory\'s ACL is what protects the store'
        : 'the directory mode is what protects the store';
      say(
        `[wundervault-agent] Store key: DERIVED from ${source}, which are not secret.\n` +
        `[wundervault-agent] Anyone who can read this directory can recompute it, so\n` +
        `[wundervault-agent] ${control} — not the encryption.`,
      );
    }
  }

  shutdown(): void {
    this.anchorer.stop();
    if (this.dailyTimer) { clearInterval(this.dailyTimer); this.dailyTimer = null; }
    // The discovery file goes with the server. A port file that outlives its daemon names
    // an address anything local may now bind, and an agent that read it would be talking
    // to a stranger — which the hello handshake catches, but only because this also
    // happens on the paths where it can.
    for (const [name, srv] of this.agentServers) {
      try { srv.close(); } catch { /* already closing */ }
      releaseEndpoint(agentEndpoint(name));
    }
    if (this.mgmtServer) { try { this.mgmtServer.close(); } catch { /* already closing */ } }
    releaseEndpoint(mgmtEndpoint());
  }
}

export { AgentDaemon, deriveMachineKey, encryptProfiles, decryptProfiles, refuseRoot };
export type { AgentProfile, ProfileStore };

/**
 * Read the setup link from stdin.
 *
 * Deliberately not an argument. `/proc/<pid>/cmdline` is world-readable on Linux, so a
 * link passed on the command line is visible to every process running as the owner — which
 * is every agent — for as long as the command runs. That link is the one credential this
 * whole design assumes an agent cannot obtain, and fetching and burning are separate steps,
 * so an agent that copied it would have had time to redeem it first. Piping still works, so
 * this stays scriptable; nothing that reaches here lands in argv.
 */
/**
 * A yes/no question on the terminal.
 *
 * Defaults to NO. The two questions this asks — "is that fingerprint right" and "is that
 * your account" — are the whole of the pairing ceremony's security, and a default of yes
 * would turn either into a keystroke somebody taps through.
 */
function askYesNo(prompt: string): Promise<boolean> {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      // Non-interactive: refuse rather than assume. A pairing confirmed by a script is a
      // pairing nobody looked at, which is the thing being defended against.
      process.stderr.write(
        '\nRefusing to confirm a pairing without a terminal — this step exists to be read by a person.\n');
      resolve(false);
      return;
    }
    process.stdout.write(prompt);
    let answered = false;
    const onData = (d: Buffer | string) => {
      if (answered) return;
      answered = true;
      process.stdin.removeListener('data', onData);
      process.stdin.pause();
      resolve(/^\s*y(es)?\s*$/i.test(String(d)));
    };
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

function readLinkFromStdin(): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      process.stderr.write('Paste the claim code, or the setup link, from the dashboard: ');
    }
    let buf = '';
    process.stdin.setEncoding('utf8');
    const finish = (v: string) => { process.stdin.pause(); resolve(v.trim()); };
    process.stdin.on('data', (d) => {
      buf += d;
      // A terminal sends no EOF until ctrl-D, so the first newline ends the read.
      if (process.stdin.isTTY && buf.includes('\n')) finish(buf.split('\n')[0]);
    });
    process.stdin.on('end', () => finish(buf));
  });
}

// Only run when invoked as the binary, so the class can be imported by tests and by the
// migration command without starting a daemon as a side effect.
const invokedDirectly = process.argv[1] && /wundervault-agent|agent\.(js|ts)$/.test(process.argv[1]);
if (invokedDirectly && !process.env.WUNDERVAULT_AGENT_NO_AUTOSTART) {
  // Before anything writes a byte. A warning nobody can read is a warning nobody reads.
  installConsoleTransliteration();
  const argv = process.argv.slice(2);

  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`
Wundervault secret broker ${VERSION}

Usage: wundervault-agent [--pair] [--unpair] [--enrol] [--migrate [--finish]] [--destinations]

With no arguments it runs as the secret broker: the process that holds your agents'
credentials so the agents cannot read them. It is normally started by systemd as the
'${SYSTEM_ACCOUNT}' account, not by hand.

  --pair        Bind this machine's broker to your account, once. Needs sudo: it writes
                the broker's private key. Prints a code and a fingerprint, neither of
                which is a secret, and waits for you to confirm in the dashboard.
  --unpair      Forget this machine's pairing, so setup links are accepted here again.
                Revokes no agent and does not delete the broker's key. Unpair in the
                dashboard too — that is the half this cannot reach.
  --enrol       Add an agent. Prompts for a CLAIM CODE (on a paired machine) or a setup
                link (on an unpaired one), rather than taking either as an argument: a
                command line is readable by every process on this machine. The broker
                fetches and decrypts the credentials itself, so they never pass through
                this process. A claim code is not a credential; a setup link is.
  --migrate     Show which agents still need moving to the broker, and how.
  --finish      With --migrate: delete the old store, once every agent is across.
  --destinations  Show the broker's log: every use of a key, where it went, why, and
                what happened, with whether the log checks out (signed, linked, and
                matching Wundervault's copy). Needs sudo: the log belongs to the broker
                so your agents cannot read it. The page is opened and then DELETED,
                because it is a copy your agents could otherwise read.
  --keep        With --destinations: leave the page on disk instead.

State lives in ${systemRoot()} and is readable only by ${SYSTEM_ACCOUNT}.
`);
    process.exit(0);
  }

  if (argv.includes('--destinations')) {
    // Dispatched here as well as in the MCP binary, because every message that mentions
    // this names THIS command — `sudo wundervault-agent --destinations`. It was only wired
    // into wundervault-mcp, so the advice printed by the daemon and the log viewer led
    // straight into refuseRoot and a message about not running as root.
    //
    // refuseRoot is deliberately NOT called on this path: reading the store is the one
    // thing that requires being root, because the file belongs to the daemon's account and
    // that is what stops the agents reading it.
    const { writeViewer, collectShape, collectActivity, resolveSudoUser, dropToSudoUser,
            shredViewer, openInBrowser } = await import('./log-viewer.js');
    const { activityLogPath } = await import('./activity-log.js');
    const { readCheck } = await import('./activity-anchor.js');
    const { defaultStorePath } = await import('./network-store.js');
    const pathMod = await import('node:path');
    const store = defaultStorePath();
    // Read as root — that is the only reason this needs privilege — then give it up before
    // writing anything into a home directory. Root must not follow paths an agent can
    // rearrange under it; doing so was a working escalation to a root cron job.
    // resolveSudoUser throws when SUDO_USER is set but cannot be resolved — refusing to
    // carry on as root is correct, but it has to read as a message rather than a stack
    // trace, and it happens before the promise chain that handles everything else.
    let sudoUser: { uid: number; gid: number; home: string } | null = null;
    try {
      sudoUser = resolveSudoUser();
    } catch (e) {
      console.error((e as Error).message);
      process.exit(1);
    }
    collectShape(store)
      .then(async ({ shape }) => {
        // The full log, verified here while still root: the file and the key that checks its
        // signatures both belong to the broker's account.
        const activity = collectActivity(activityLogPath(), brokerPublicKeyObject(), readCheck());
        let target: string | undefined;
        if (sudoUser) {
          target = pathMod.join(sudoUser.home, '.wundervault', 'destinations.html');
          dropToSudoUser(sudoUser);
        }
        const out = writeViewer(store, target, shape, activity);
        const keep = argv.includes('--keep');
        const { verdictOf } = await import('./log-viewer.js');
        const verdict = verdictOf(activity);

        console.log(
          `\nYour broker's log — ${activity.total} line(s)\n` +
          `  log:    ${activity.logPath}\n  viewer: ${out}\n\n` +
          verdict.lines.map((l) => `  ${l}`).join('\n') + '\n');

        if (keep) {
          // Deliberate, and said plainly. Someone may want the page to keep or to send.
          console.log(
            `Kept on disk at your request. It is a full copy of the record above, and your\n` +
            `agents run as you — so anything you run can read it until you delete it.\n`);
          process.exit(0);
        }

        // Removed on the way out however we leave: a clean exit, a ctrl-C, or the timeout.
        // Leaving the copy behind is the thing being avoided, so it must not depend on the
        // user choosing the tidy path.
        // The inode, captured now, so cleanup can tell OUR page from one another
        // invocation wrote to the same path — including one deliberately kept with --keep.
        let stamp: { ino: number; mtimeMs: number } | undefined;
        try {
          const st = fs.statSync(out);
          stamp = { ino: st.ino, mtimeMs: st.mtimeMs };
        } catch { /* gone already; cleanup will no-op */ }

        let gone = false;
        const cleanup = () => { if (!gone) { gone = true; shredViewer(out, stamp); } };
        process.on('exit', cleanup);
        for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
          process.on(sig, () => { cleanup(); process.exit(0); });
        }

        const opened = openInBrowser(out);
        console.log(opened
          ? `Opened in your browser. The copy is removed when you close this command —\n` +
            `press ctrl-C when you are done, or it clears itself in 10 minutes.\n` +
            `(--keep leaves it on disk instead.)\n`
          : `Could not open a browser. Open the file above, then press ctrl-C here to\n` +
            `remove it. It clears itself in 10 minutes. (--keep leaves it on disk.)\n`);
        console.log(
          `It is deleted because it is a COPY of a record your agents cannot otherwise\n` +
          `read: they run as you, so a file in your home is a file they can open.\n`);

        setTimeout(() => { cleanup(); process.exit(0); }, 10 * 60 * 1000);
      })
      .catch((e: Error) => { console.error(e.message); process.exit(1); });
  } else if (argv.includes('--pair')) {
    // Runs as ROOT (via sudo), because it writes the broker's private key into
    // /var/lib/wundervault. Nothing secret leaves this command: it uploads a PUBLIC key
    // and prints a fingerprint and a code, both of which an onlooker may read.
    void (async () => {
      const { startPairing, awaitConfirmation, pairInstructions, pairedNextSteps } = await import('./pair.js');
      try {
        const start = await startPairing();
        console.log('');
        console.log('  Pairing code : ' + start.code);
        console.log('  Fingerprint  : ' + start.identity.fingerprint);
        console.log('');
        for (const line of pairInstructions()) console.log(line);
        console.log('');
        console.log('  Neither of those two values is a secret. Anyone reading this screen learns');
        console.log('  a public key and a code that opens nothing.');
        console.log('');
        process.stdout.write('  Waiting for you to confirm...');
        let dots = 0;
        const rec = await awaitConfirmation(start, {
          onTick: () => { dots += 1; if (dots % 4 === 0) process.stdout.write('.'); },
          // The second half of the ceremony. The fingerprint check proves the key is
          // this machine's; it cannot prove the ACCOUNT is yours, because a pairing code
          // is printed here and typed into a browser and anyone who reads it can confirm
          // it under their own account. So the person at the terminal reads the account
          // back and says whether it is theirs.
          confirmAccount: async (hint) => {
            console.log('');
            console.log('');
            console.log(`  Confirmed by: ${hint || '(the server did not name an account)'}`);
            console.log('');
            return askYesNo('  Is that your account? [y/N] ');
          },
        });
        console.log('');
        console.log('');
        console.log(`  Paired. This broker is ${rec.fingerprint}`
          + (rec.account_label ? ` (${rec.account_label})` : ''));
        console.log('');
        for (const line of pairedNextSteps()) console.log(line);
        process.exit(0);
      } catch (e) {
        console.log('');
        console.error((e as Error).message);
        process.exit(1);
      }
    })();
  } else if (argv.includes('--unpair')) {
    // The local half of unpairing. The dashboard revokes the server row; this forgets
    // the marker here. Both are needed: the setup-link refusal is keyed to the local
    // file, so without this an owner who unpaired in the browser would be offered a link
    // and have it refused by their own broker with nothing explaining why.
    void (async () => {
      const { readPaired, forgetPairing } = await import('./pair.js');
      const rec = readPaired();
      if (!rec) {
        console.log('This machine is not paired. Nothing to do.');
        process.exit(0);
      }
      const gone = forgetPairing();
      console.log(gone
        ? `Forgot the pairing with ${rec.fingerprint}. Setup links are accepted here again.\n`
          + `The broker's KEY is untouched and no agent was revoked — anything already enrolled\n`
          + `keeps working. Unpair it in the dashboard too, or it will still be offered as a\n`
          + `delivery target there.`
        : `Could not remove ${''}the pairing marker. Check permissions on the state directory.`);
      process.exit(gone ? 0 : 1);
    })();
  } else if (argv.includes('--enrol')) {
    // Runs as the USER. It hands over a URL and gets back a name — the credentials are
    // fetched, decrypted and filed by the daemon, and never enter this process.
    //
    // The link is READ FROM STDIN, never taken from argv. A command line is world-readable
    // through /proc/<pid>/cmdline, so `--enrol "https://...#passphrase"` published the one
    // credential this design assumes an agent cannot get, to every agent on the machine,
    // for as long as the command ran. And because fetching and burning are separate steps,
    // an agent that copied it had time to redeem it first. Prompting costs one paste and
    // keeps the link out of argv and out of shell history.
    const input = await readLinkFromStdin();
    if (!input) {
      console.error('Nothing given. Paste a claim code, or a setup link on an unpaired machine.');
      process.exit(2);
    }
    void (async () => {
      const { enrol, enrolClaim } = await import('./migrate.js');
      const { looksLikeClaimCode } = await import('./pair.js');
      try {
        // A claim code and a setup link are told apart by SHAPE, not by asking the user
        // which they have. They look nothing alike, and a wrong guess here would send a
        // bearer credential down the path that does not expect one.
        const isClaim = looksLikeClaimCode(input);
        const r = isClaim ? await enrolClaim(input) : await enrol(input);
        console.log(`Enrolled ${r.agent_name}. Its credentials are held by the broker in ${systemRoot()}, `
                    + `which your agents cannot read.`);
        if (!r.linkBurned) {
          console.log('');
          console.log(isClaim
            ? 'WARNING: the server did not confirm the claim as used, so it stays valid until it'
            : 'WARNING: the server did not confirm the setup link as used, so it stays');
          console.log(isClaim
            ? 'expires. It opens nothing without this broker\u2019s key, but repair the agent again'
            : 'valid until it expires and could be replayed to re-point this agent.');
          console.log(isClaim
            ? 'if you would rather it were dead.'
            : 'Repair the agent again in the dashboard if that matters to you.');
        }
        process.exit(0);
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    })();
  } else if (argv.includes('--migrate')) {
    // Runs as the USER, not the daemon: it reads the old store from a home directory the
    // daemon deliberately cannot reach.
    const { status, describeStatus, cleanup } = await import('./migrate.js');
    if (argv.includes('--finish')) {
      cleanup()
        .then((r) => {
          if (r.pending.length) {
            console.error(`Not yet — these are still on the old credentials: ${r.pending.join(', ')}`);
            console.error('Deleting the store now would take them off the air for good.');
            process.exit(1);
          }
          console.log(r.deleted
            ? 'Deleted the pre-split store. Credentials now live where your agents cannot read them.'
            : 'There was no pre-split store to delete.');
          if (!r.oldUnitStopped) {
            console.log('');
            console.log('The pre-split daemon may still be running. It is serving credentials the');
            console.log('server no longer accepts, but it should not be left behind:');
            console.log('  systemctl --user disable --now wundervault-agent.service');
          }
          process.exit(0);
        })
        .catch((e: Error) => { console.error(e.message); process.exit(1); });
    } else {
      status()
        .then((st) => { console.log(describeStatus(st)); process.exit(0); })
        .catch((e: Error) => { console.error(e.message); process.exit(1); });
    }
  } else {
    // AN UNRECOGNISED FLAG MUST NOT START A BROKER.
    //
    // Everything that is not a known subcommand fell through to here and launched a
    // daemon in the foreground. So `wundervault-agent --ping` -- a flag that does not
    // exist, and which this project's own verifier script asked for -- started a SECOND
    // broker, as the wrong user, which then sat there for ever. On Windows that second
    // broker overwrites the discovery files the real one published, so a typo silently
    // repoints every agent on the machine at a daemon running as the person who typed it.
    //
    // Found by running the verifier on Windows. It is not a Windows bug: a typo has
    // started a stray broker on every platform since phase 4.
    const unknown = argv.filter(a => a.startsWith('-'));
    if (unknown.length > 0) {
      console.error(
        `[wundervault-agent] Unrecognised option${unknown.length > 1 ? 's' : ''}: ` +
        `${unknown.join(', ')}\n` +
        `  Refusing to start a broker, because that is almost certainly not what you meant.\n` +
        `  Run with --help to see what this command accepts.`,
      );
      process.exit(2);
    }
    refuseRoot();
    announceBoundary();
    let daemon: AgentDaemon;
    try {
      // Before anything is constructed or published. A second broker that has already
      // written its discovery files has already stolen the agents.
      await AgentDaemon.refuseIfAlreadyServing();
      daemon = new AgentDaemon();
      daemon.start();
    } catch (err) {
      const e = err as Error & { configurationRefusal?: boolean };
      console.error(`[wundervault-agent] ${e.message}`);
      // Exit 0 ONLY for a refusal a restart cannot fix — see ConfigurationRefusal. Any
      // other failure keeps its non-zero code so launchd and systemd both retry it.
      process.exit(e.configurationRefusal ? 0 : 1);
    }
    process.on('SIGTERM', () => { daemon.shutdown(); process.exit(0); });
    process.on('SIGINT', () => { daemon.shutdown(); process.exit(0); });
  }
}
