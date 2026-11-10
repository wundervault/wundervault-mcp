/**
 * Guided server setup and the change check (site SPEC-admin-access §5a, D13, D14, §13).
 *
 * The owner's browser seals an order with an agent's vault key (the Update now channel). This
 * broker opens it, and runs the FIXED script packaging/server/wv-setup.bundled.sh on the server
 * over SSH, through BrokerOps.serverRun — the same path an agent's admin command takes (host
 * pin, admin-access gate, short-lived certificate). Every value that reaches the server is
 * checked here against a strict pattern and checked again by the script; nothing is evaluated.
 *
 * Results go back SEALED with the same agent vault key, so PASS/FAIL lines, account names and
 * key comments never reach our server in the clear; the plain detail is only a count.
 */
import { createCipheriv, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeSshTarget } from './ssh-pin.js';

export const SERVER_ORDER_TYPES = ['setup', 'remove-key', 'accept'] as const;
export type ServerOrderType = typeof SERVER_ORDER_TYPES[number];

interface Base { order_id: string; entry_id: string; destination: string }
export type ServerOrder =
  | Base & { type: 'setup'; everyday_user: string; everyday_entry_id: string;
      everyday_pub: string; emergency_pub: string; logs: boolean }
  | Base & { type: 'remove-key'; user: string; fp: string }
  | Base & { type: 'accept' };

const ID = /^[A-Za-z0-9_-]{8,64}$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;
const PUB = /^ssh-ed25519 [A-Za-z0-9+/]{68}$/;
const FP = /^[0-9a-f]{16}$/;
const SESSION_CHECK = '/usr/local/lib/wundervault/wv-check';

const FIELDS: Record<ServerOrderType, string[]> = {
  setup: ['everyday_user', 'everyday_entry_id', 'everyday_pub', 'emergency_pub', 'logs'],
  'remove-key': ['user', 'fp'],
  accept: [],
};

function isoMs(v: unknown): number {
  return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/.test(v)
    ? Date.parse(v) : NaN;
}

/** The canonical `user@host[:port]` of a destination, or null. */
export function canonicalDestination(d: unknown): { user: string; host: string; port: number; text: string } | null {
  if (typeof d !== 'string' || d.length > 300) return null;
  const t = normalizeSshTarget(d);
  if (!t || !USER.test(t.user)) return null;
  const text = `${t.user}@${t.host}${t.port === 22 ? '' : ':' + t.port}`;
  if (d !== text && d !== `${t.user}@${t.host}:${t.port}`) return null;
  return { user: t.user, host: t.host, port: t.port, text };
}

/** Check an opened order. Exact key set per type; anything else is refused, never guessed. */
export function validateServerOrder(
  o: Record<string, unknown>, fingerprint: string, nowMs: number,
): { ok: true; order: ServerOrder } | { ok: false; reason: string } {
  const type = o.type as ServerOrderType;
  if (!SERVER_ORDER_TYPES.includes(type)) return { ok: false, reason: 'malformed' };
  const keys = ['v', 'type', 'broker', 'order_id', 'issued_at', 'expires_at', 'entry_id', 'destination', ...FIELDS[type]];
  if (Object.keys(o).length !== keys.length || !keys.every((k) => Object.hasOwn(o, k)) || o.v !== 1) {
    return { ok: false, reason: 'malformed' };
  }
  if (o.broker !== fingerprint) return { ok: false, reason: 'wrong broker' };
  const issued = isoMs(o.issued_at);
  const expires = isoMs(o.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > 16 * 60_000) {
    return { ok: false, reason: 'malformed' };
  }
  if (issued > nowMs + 2 * 60_000 || expires <= nowMs) return { ok: false, reason: 'expired' };
  if (typeof o.order_id !== 'string' || !ID.test(o.order_id) ||
      typeof o.entry_id !== 'string' || !ID.test(o.entry_id)) return { ok: false, reason: 'malformed' };
  const dest = canonicalDestination(o.destination);
  if (!dest) return { ok: false, reason: 'bad destination' };
  const base = { order_id: o.order_id, entry_id: o.entry_id, destination: dest.text };
  if (type === 'setup') {
    if (typeof o.everyday_user !== 'string' || !USER.test(o.everyday_user) || o.everyday_user === dest.user ||
        typeof o.everyday_entry_id !== 'string' || !ID.test(o.everyday_entry_id) || o.everyday_entry_id === o.entry_id ||
        typeof o.everyday_pub !== 'string' || !PUB.test(o.everyday_pub) ||
        typeof o.emergency_pub !== 'string' || !PUB.test(o.emergency_pub) || o.emergency_pub === o.everyday_pub ||
        typeof o.logs !== 'boolean') {
      return { ok: false, reason: 'malformed' };
    }
    return { ok: true, order: { ...base, type, everyday_user: o.everyday_user, everyday_entry_id: o.everyday_entry_id,
      everyday_pub: o.everyday_pub, emergency_pub: o.emergency_pub, logs: o.logs } };
  }
  if (type === 'remove-key') {
    if (typeof o.user !== 'string' || !USER.test(o.user) || typeof o.fp !== 'string' || !FP.test(o.fp)) {
      return { ok: false, reason: 'malformed' };
    }
    return { ok: true, order: { ...base, type, user: o.user, fp: o.fp } };
  }
  return { ok: true, order: { ...base, type } };
}

/** AES-256-GCM with the agent's vault key; the browser opens it with the same key and AAD. */
export function sealForOwner(vaultKey: Uint8Array, aad: string, value: unknown): { ciphertext: string; nonce: string } {
  const nonce = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', vaultKey, nonce);
  c.setAAD(Buffer.from(aad, 'utf8'));
  const body = Buffer.concat([c.update(JSON.stringify(value), 'utf8'), c.final(), c.getAuthTag()]);
  return { ciphertext: body.toString('base64'), nonce: nonce.toString('base64') };
}

export const resultAad = (fingerprint: string, orderId: string) => `wv-broker-result-v1|${fingerprint}|${orderId}`;
export const checkAad = (requestId: string) => `wv-server-check-v1|${requestId}`;

/** What a setup record keeps: enough to run the change check later. No secrets. */
export interface SetupRecord { everyday_entry_id: string; everyday_destination: string; admin_user: string; at: string }

export class SetupRecords {
  constructor(private file: string) {}
  read(): Record<string, SetupRecord> {
    try {
      const v = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, SetupRecord> : {};
    } catch { return {}; }
  }
  /** Admin entries this computer can check (F5: the server offers only these as due). */
  entries(): string[] { return Object.keys(this.read()).filter((id) => this.get(id) !== undefined); }
  get(adminEntryId: string): SetupRecord | undefined {
    const r = this.read()[adminEntryId];
    return r && typeof r.everyday_entry_id === 'string' && canonicalDestination(r.everyday_destination) ? r : undefined;
  }
  put(adminEntryId: string, rec: SetupRecord): void {
    const all = this.read();
    all[adminEntryId] = rec;
    const tmp = `${this.file}.${randomBytes(6).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(all), { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, this.file);
  }
}

/** The fixed script, shipped in the package next to dist/. */
export function bundledScript(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return fs.readFileSync(path.join(here, '..', 'packaging', 'server', 'wv-setup.bundled.sh'), 'utf8');
}

type Run = { exitCode: number; stdout: string; stderr: string } | { error: string; code?: string };
export interface ServerRunner {
  serverRun(args: {
    entryId: string; destination: string; purpose: string;
    argv: (publicKey: string) => string[]; input?: string; offer?: 'cert' | 'plain'; timeoutMs?: number;
  }): Promise<Run>;
}

/** PASS/FAIL/NOTE lines a script printed, bounded; anything else is dropped. */
function verdictLines(out: string): string[] {
  return out.split('\n').map((l) => l.replace(/[^\x20-\x7e]/g, '').trim())
    .filter((l) => /^(PASS|FAIL|NOTE) /.test(l)).slice(0, 40).map((l) => l.slice(0, 160));
}

function failOf(r: Run, what: string): string {
  if ('error' in r) return `FAIL ${what}: ${r.error.split('\n')[0]!.slice(0, 160)}`;
  const tail = (r.stderr.trim().split('\n').pop() ?? '').replace(/[^\x20-\x7e]/g, '').slice(0, 120);
  return `FAIL ${what} (exit ${r.exitCode}${tail ? ': ' + tail : ''})`;
}

/**
 * Setup, in the order that can never lock the owner out: prepare (adds, removes nothing) ->
 * certificate-only sign-in proven -> finalize (drops the plain admin line) -> status ->
 * plain key refused -> everyday self-test. A failure stops the run where it is.
 */
export async function runSetup(ops: ServerRunner, o: Extract<ServerOrder, { type: 'setup' }>, script: string,
  records?: SetupRecords): Promise<{ ok: boolean; lines: string[] }> {
  const dest = canonicalDestination(o.destination)!;
  const admin = dest.user;
  const sudo = admin === 'root' ? [] : ['sudo', '-n'];
  const lines: string[] = [];
  const purpose = 'Wundervault guided setup';
  let ca = '';
  const step = async (what: string, argv: (pub: string) => string[], extra: { offer?: 'cert' | 'plain'; input?: string; entryId?: string; destination?: string } = {}) => {
    const r = await ops.serverRun({ entryId: extra.entryId ?? o.entry_id, destination: extra.destination ?? o.destination,
      purpose, argv, ...(extra.offer ? { offer: extra.offer } : {}), ...(extra.input !== undefined ? { input: extra.input } : {}) });
    return r;
  };

  const prep = await step('prepare', (pub) => {
    ca = pub;
    if (!PUB.test(pub)) throw new Error('the admin key is not ed25519');
    return [...sudo, 'sh', '-s', '--', 'prepare', admin, o.everyday_user, pub, o.everyday_pub, o.emergency_pub, o.logs ? 'logs' : ''];
  }, { input: script });
  if ('error' in prep || prep.exitCode !== 0) {
    lines.push(...('error' in prep ? [] : verdictLines(prep.stdout)), failOf(prep, 'prepare'));
    return { ok: false, lines };
  }
  lines.push(...verdictLines(prep.stdout));

  const proof = await step('certificate', () => ['echo', 'wv-cert-ok'], { offer: 'cert' });
  if ('error' in proof || proof.exitCode !== 0 || !proof.stdout.includes('wv-cert-ok')) {
    lines.push(failOf(proof, 'admin sign-in with a short-lived certificate'),
      'NOTE nothing was removed: the admin key still signs in as before');
    return { ok: false, lines };
  }
  lines.push('PASS admin signs in with a short-lived certificate');

  const fin = await step('finalize', () => [...sudo, 'sh', '-s', '--', 'finalize', admin, ca], { offer: 'cert', input: script });
  if ('error' in fin || fin.exitCode !== 0) {
    lines.push(...('error' in fin ? [] : verdictLines(fin.stdout)), failOf(fin, 'finalize'));
    return { ok: false, lines };
  }
  lines.push(...verdictLines(fin.stdout));

  const status = await step('status', () => [...sudo, 'sh', '-s', '--', 'status', admin, o.everyday_user], { offer: 'cert', input: script });
  if ('error' in status) lines.push(failOf(status, 'status'));
  else lines.push(...verdictLines(status.stdout));

  const plain = await step('plain', () => ['true'], { offer: 'plain' });
  const refused = !('error' in plain) && plain.exitCode === 255 && /Permission denied \(publickey/.test(plain.stderr);
  lines.push(refused
    ? 'PASS the admin key alone is refused (it works only inside admin access)'
    : !('error' in plain) && plain.exitCode === 0
      ? 'FAIL the admin key still signs in without admin access'
      : failOf(plain, 'could not confirm the admin key alone is refused'));

  const everyday = `${o.everyday_user}@${dest.host}${dest.port === 22 ? '' : ':' + dest.port}`;
  const selftest = [
    'a=$1; h=$(getent passwd "$a" | cut -d: -f6)',
    'echo "PASS everyday key signs in"',
    'if sudo -n true 2>/dev/null; then echo "FAIL the everyday account can use sudo"; else echo "PASS the everyday account cannot use sudo"; fi',
    'if [ -n "$h" ] && ls "$h" >/dev/null 2>&1; then echo "FAIL the everyday account can read the admin home"; else echo "PASS the admin home is closed to the everyday account"; fi',
    `if sudo -n ${SESSION_CHECK} health >/dev/null 2>&1; then echo "PASS health check works"; else echo "FAIL health check"; fi`,
    `if sudo -n ${SESSION_CHECK} report | grep -q '^END$'; then echo "PASS change check works"; else echo "FAIL change check"; fi`,
  ].join('\n');
  const day = await step('everyday', () => ['sh', '-c', selftest, 'wv-selftest', admin],
    { entryId: o.everyday_entry_id, destination: everyday });
  if ('error' in day || day.exitCode !== 0) lines.push(...('error' in day ? [] : verdictLines(day.stdout)), failOf(day, 'everyday key'));
  else lines.push(...verdictLines(day.stdout));

  const ok = !lines.some((l) => l.startsWith('FAIL '));
  if (records) {
    try {
      records.put(o.entry_id, { everyday_entry_id: o.everyday_entry_id, everyday_destination: everyday,
        admin_user: admin, at: new Date().toISOString() });
    } catch {
      lines.push('FAIL this computer could not save the setup record, so the change check would not run; run the setup again');
      return { ok: false, lines };
    }
  }
  return { ok, lines };
}

export async function runRemoveOrAccept(ops: ServerRunner, o: Exclude<ServerOrder, { type: 'setup' }>, script: string):
  Promise<{ ok: boolean; lines: string[] }> {
  const admin = canonicalDestination(o.destination)!.user;
  const sudo = admin === 'root' ? [] : ['sudo', '-n'];
  const argv = o.type === 'remove-key' ? ['remove-key', o.user, o.fp] : ['accept'];
  const r = await ops.serverRun({ entryId: o.entry_id, destination: o.destination,
    purpose: o.type === 'remove-key' ? 'Remove a key the change check found' : 'Accept the server as it is now',
    argv: () => [...sudo, 'sh', '-s', '--', ...argv], input: script });
  if ('error' in r || r.exitCode !== 0) return { ok: false, lines: [...('error' in r ? [] : verdictLines(r.stdout)), failOf(r, o.type)] };
  return { ok: true, lines: verdictLines(r.stdout) };
}

/**
 * Keep a sealed answer under the server's 16 KB ciphertext limit: at most `budget` bytes of
 * lines (JSON-escaped), then one line saying how many more there were.
 */
export function fitLines(lines: string[], budget = 9_000): string[] {
  const out: string[] = [];
  let used = 0;
  for (let i = 0; i < lines.length; i++) {
    const n = JSON.stringify(lines[i]).length + 1;
    if (used + n > budget) { out.push(`NOTE and ${lines.length - i} more not shown; the server's own report has them all`); break; }
    out.push(lines[i]!); used += n;
  }
  return out;
}

/** NEW/GONE lines of `wv-check report`, or null when the report did not finish (no END). */
export function parseReport(out: string): string[] | null {
  const lines = out.split('\n').map((l) => l.replace(/[^\x09\x20-\x7e]/g, '').trimEnd());
  if (!lines.includes('END') && !lines.some((l) => l.startsWith('NO-BASELINE'))) return null;
  return fitLines(lines.filter((l) => /^(NEW|GONE)\t/.test(l) || l.startsWith('NO-BASELINE')).map((l) => l.slice(0, 200)));
}

/** D14: run the read-only report with the everyday key. */
export async function runChangeCheck(ops: ServerRunner, rec: SetupRecord):
  Promise<{ ok: true; changed: boolean; lines: string[] } | { ok: false; error: string }> {
  const r = await ops.serverRun({ entryId: rec.everyday_entry_id, destination: rec.everyday_destination,
    purpose: 'Wundervault change check after admin access', argv: () => ['sudo', '-n', SESSION_CHECK, 'report'] });
  if ('error' in r) return { ok: false, error: r.error.split('\n')[0]!.slice(0, 160) };
  const lines = r.exitCode === 0 ? parseReport(r.stdout) : null;
  if (!lines) return { ok: false, error: `the report did not finish (exit ${r.exitCode})` };
  return { ok: true, changed: lines.length > 0, lines };
}
