import {
  createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { open, readFile, rename, unlink } from 'node:fs/promises';

const zeroSalt = Buffer.alloc(32);
const buckets = [256, 1024, 4096, 16384, 65536, 131072, 262144, 524288];
const maxSealedBytes = 524288 + 16;
// The server accepts a signature detail up to 72 KiB (agent.py MAX_SIGNATURE_DETAIL_BYTES).
const maxT2OpJsonBytes = 80 * 1024;
const setupKeys = new Set([
  'v', 'rev', 'value_sha256', 'value_format', 'name', 'shape', 'service', 'delivery',
  'binding', 'ssh_hosts', 'private_origins', 'known_addresses', 'approval', 'operations', 'chain',
  // Spec 1.3: an SSH key whose servers are approved on first use (ssh_hosts may then be empty).
  'ask',
]);

export interface Setup extends Record<string, unknown> {
  v: 1;
  rev: number;
  value_sha256: string;
  value_format?: 'raw' | 'parts-1';
  delivery: 'http' | 'ssh' | 'wallet' | 'sign';
}

export interface T2Detail {
  name: string;
  kind: string;
  origin: string;
  method: string;
  path: string;
  reason: string;
}

export interface T2OpDetail {
  name: string;
  kind: 'payment' | 'signature' | 'recipe' | '2fa';
  detail: Record<string, unknown>;
}

export interface T2MatchFields {
  kind: string;
  origin: string;
  method: string;
  path: string;
  entry_id: string;
}

type Failure = { ok: false; reason: 'bad seal' | 'malformed' };

export type SealResult =
  | { ok: true; ciphertext: string; nonce: string }
  | Failure;

export type OpenSetupResult =
  | { ok: true; setup: Setup }
  | Failure;

export type OpenT2DetailResult =
  | { ok: true; detail: T2Detail & { v: 1 } }
  | Failure;

export type OpenT2OpDetailResult =
  | { ok: true; detail: T2OpDetail & { v: 1 } }
  | Failure;

export function hkdfKey(ikm: Uint8Array, salt: Uint8Array, info: string): Buffer {
  return Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from(info, 'utf8'), 32));
}

export function pad(json: string): Buffer {
  const bytes = Buffer.from(json, 'utf8');
  const bucket = buckets.find(size => size >= bytes.length);
  if (bucket === undefined) throw new Error('Plaintext exceeds 524288 bytes');
  const padded = Buffer.alloc(bucket, 0x20);
  bytes.copy(padded);
  return padded;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validRev(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function validId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
}

function validRequestId(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
}

function validSetup(value: unknown, rev: number): value is Setup {
  return isObject(value) &&
    Object.keys(value).every(key => setupKeys.has(key)) &&
    value.v === 1 && validRev(value.rev) && value.rev === rev &&
    typeof value.value_sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.value_sha256) &&
    (value.value_format === undefined ||
      value.value_format === 'raw' || value.value_format === 'parts-1') &&
    (value.delivery === 'http' || value.delivery === 'ssh' ||
      value.delivery === 'wallet' || value.delivery === 'sign');
}

function validDetail(value: unknown): value is T2Detail & { v: 1 } {
  const keys = ['v', 'name', 'kind', 'origin', 'method', 'path', 'reason'];
  return isObject(value) && Object.keys(value).length === keys.length &&
    keys.every(key => Object.hasOwn(value, key)) && value.v === 1 &&
    keys.slice(1).every(key => typeof value[key] === 'string') &&
    ['kind', 'origin', 'method', 'path'].every(key => !(value[key] as string).includes('\n'));
}

function validOpDetail(value: unknown): value is T2OpDetail & { v: 1 } {
  const keys = ['v', 'name', 'kind', 'detail'];
  return isObject(value) && Object.keys(value).length === keys.length &&
    keys.every(key => Object.hasOwn(value, key)) && value.v === 1 &&
    // Characters, as the vault page counts a name (review cl5 browser F3), not UTF-16 units.
    typeof value.name === 'string' && Array.from(value.name).length <= 256 &&
    (value.kind === 'payment' || value.kind === 'signature' || value.kind === 'recipe' || value.kind === '2fa') &&
    isObject(value.detail);
}

function decodeBase64(value: string): Buffer {
  if (typeof value !== 'string' || value.length > Math.ceil(maxSealedBytes / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('base64');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw new Error('base64');
  return bytes;
}

function seal(
  vaultKey: Uint8Array, info: string, aad: string, json: string, nonce?: Buffer,
): SealResult {
  let plaintext: Buffer;
  try {
    plaintext = pad(json);
  } catch {
    return { ok: false, reason: 'malformed' };
  }

  try {
    const iv = nonce === undefined ? randomBytes(12) : Buffer.from(nonce);
    if (vaultKey.length !== 32 || iv.length !== 12) return { ok: false, reason: 'bad seal' };
    const key = hkdfKey(vaultKey, zeroSalt, info);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const ciphertext = Buffer.concat([
      cipher.update(plaintext), cipher.final(), cipher.getAuthTag(),
    ]);
    return { ok: true, ciphertext: ciphertext.toString('base64'), nonce: iv.toString('base64') };
  } catch {
    return { ok: false, reason: 'bad seal' };
  }
}

function openBlob(
  vaultKey: Uint8Array, info: string, aad: string, ciphertextB64: string, nonceB64: string,
  maxJsonBytes?: number,
): { ok: true; value: unknown } | Failure {
  let plaintext: Buffer;
  try {
    const ciphertext = decodeBase64(ciphertextB64);
    const nonce = decodeBase64(nonceB64);
    if (vaultKey.length !== 32 || nonce.length !== 12 ||
        ciphertext.length < 16 || ciphertext.length > maxSealedBytes) {
      return { ok: false, reason: 'bad seal' };
    }
    const key = hkdfKey(vaultKey, zeroSalt, info);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(ciphertext.subarray(-16));
    plaintext = Buffer.concat([
      decipher.update(ciphertext.subarray(0, -16)), decipher.final(),
    ]);
  } catch {
    return { ok: false, reason: 'bad seal' };
  }

  try {
    const text = plaintext.toString('utf8');
    if (!buckets.includes(plaintext.length) || !Buffer.from(text, 'utf8').equals(plaintext)) {
      return { ok: false, reason: 'malformed' };
    }
    const json = text.trim();
    if (maxJsonBytes !== undefined && Buffer.byteLength(json, 'utf8') > maxJsonBytes) {
      return { ok: false, reason: 'malformed' };
    }
    return { ok: true, value: JSON.parse(json) as unknown };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

export function sealSetup(
  vaultKey: Uint8Array, agentId: string, entryId: string, rev: number,
  setup: object, nonce?: Buffer,
): SealResult {
  let json: string;
  try {
    if (!validId(agentId) || !validId(entryId) || !validRev(rev)) {
      return { ok: false, reason: 'malformed' };
    }
    json = JSON.stringify(setup);
    if (!validSetup(JSON.parse(json) as unknown, rev)) {
      return { ok: false, reason: 'malformed' };
    }
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  return seal(vaultKey, 'wv-setup-1', `wv-setup-1|${agentId}|${entryId}|${rev}`, json, nonce);
}

export function openSetup(
  vaultKey: Uint8Array, agentId: string, entryId: string, rev: number,
  ciphertextB64: string, nonceB64: string,
): OpenSetupResult {
  if (!validId(agentId) || !validId(entryId) || !validRev(rev)) {
    return { ok: false, reason: 'malformed' };
  }
  const opened = openBlob(
    vaultKey, 'wv-setup-1', `wv-setup-1|${agentId}|${entryId}|${rev}`, ciphertextB64, nonceB64,
  );
  if (!opened.ok) return opened;
  if (!validSetup(opened.value, rev)) return { ok: false, reason: 'malformed' };
  return { ok: true, setup: opened.value };
}

export function checkValueCommitment(setup: Setup, encryptedContentB64: string): boolean {
  try {
    if (!/^[0-9a-f]{64}$/.test(setup.value_sha256)) return false;
    const ciphertext = decodeBase64(encryptedContentB64);
    if (ciphertext.length < 16) return false;
    const expected = Buffer.from(setup.value_sha256, 'hex');
    const actual = createHash('sha256').update(ciphertext).digest();
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

export function sealT2Detail(
  vaultKey: Uint8Array, agentId: string, requestId: string, detail: T2Detail, nonce?: Buffer,
): SealResult {
  let json: string;
  try {
    if (!validId(agentId) || !validRequestId(requestId) || !isObject(detail) ||
        Object.keys(detail).length !== 6 || Object.hasOwn(detail, 'v')) {
      return { ok: false, reason: 'malformed' };
    }
    json = JSON.stringify({ v: 1, ...detail });
    if (!validDetail(JSON.parse(json) as unknown)) return { ok: false, reason: 'malformed' };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  return seal(vaultKey, 'wv-t2-1', `wv-t2-1|${agentId}|${requestId}`, json, nonce);
}

export function openT2Detail(
  vaultKey: Uint8Array, agentId: string, requestId: string,
  ciphertextB64: string, nonceB64: string,
): OpenT2DetailResult {
  if (!validId(agentId) || !validRequestId(requestId)) {
    return { ok: false, reason: 'malformed' };
  }
  const opened = openBlob(
    vaultKey, 'wv-t2-1', `wv-t2-1|${agentId}|${requestId}`, ciphertextB64, nonceB64,
  );
  if (!opened.ok) return opened;
  if (!validDetail(opened.value)) return { ok: false, reason: 'malformed' };
  return { ok: true, detail: opened.value };
}

export function sealT2OpDetail(
  vaultKey: Uint8Array, agentId: string, requestId: string, detail: T2OpDetail, nonce?: Buffer,
): SealResult {
  let json: string;
  try {
    if (!validId(agentId) || !validRequestId(requestId) || !isObject(detail) ||
        Object.keys(detail).length !== 3 || Object.hasOwn(detail, 'v')) {
      return { ok: false, reason: 'malformed' };
    }
    json = JSON.stringify({ v: 1, ...detail });
    if (Buffer.byteLength(json, 'utf8') > maxT2OpJsonBytes ||
        !validOpDetail(JSON.parse(json) as unknown)) {
      return { ok: false, reason: 'malformed' };
    }
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  return seal(vaultKey, 'wv-t2op-1', `wv-t2op-1|${agentId}|${requestId}`, json, nonce);
}

export function openT2OpDetail(
  vaultKey: Uint8Array, agentId: string, requestId: string,
  ciphertextB64: string, nonceB64: string,
): OpenT2OpDetailResult {
  if (!validId(agentId) || !validRequestId(requestId)) {
    return { ok: false, reason: 'malformed' };
  }
  const opened = openBlob(
    vaultKey, 'wv-t2op-1', `wv-t2op-1|${agentId}|${requestId}`,
    ciphertextB64, nonceB64, maxT2OpJsonBytes,
  );
  if (!opened.ok) return opened;
  if (!validOpDetail(opened.value)) return { ok: false, reason: 'malformed' };
  return { ok: true, detail: opened.value };
}

export function t2MatchMac(vaultKey: Uint8Array, fields: T2MatchFields): string {
  const values = [fields.kind, fields.origin, fields.method, fields.path, fields.entry_id];
  if (values.some(value => typeof value !== 'string' || value.includes('\n'))) {
    throw new Error('Invalid tier-2 match field');
  }
  if (vaultKey.length !== 32) throw new Error('Invalid vault key');
  const key = hkdfKey(vaultKey, zeroSalt, 'wv-t2-match-1');
  return createHmac('sha256', key).update(values.join('\n'), 'utf8').digest('hex');
}

/**
 * Batch B A2: what a 15/60-minute window covers on a locked account — this key, this agent's
 * copy, this service (origin), any method and path. The owner's browser recomputes it from the
 * sealed detail before offering a window, so the server cannot widen what was approved.
 */
export function t2OriginMac(vaultKey: Uint8Array, fields: { origin: string; entry_id: string }): string {
  const values = ['web', fields.origin, fields.entry_id];
  if (values.some(value => typeof value !== 'string' || value.includes('\n'))) {
    throw new Error('Invalid tier-2 match field');
  }
  if (vaultKey.length !== 32) throw new Error('Invalid vault key');
  const key = hkdfKey(vaultKey, zeroSalt, 'wv-t2-origin-1');
  return createHmac('sha256', key).update(values.join('\n'), 'utf8').digest('hex');
}

export function newRequestId(): string {
  return randomBytes(16).toString('hex');
}

export interface SetupPinsFile {
  writeFile(data: string): Promise<void>;
  chmod(mode: number): Promise<void>;
  sync(): Promise<void>;
  close(): Promise<void>;
}

export interface SetupPinsFs {
  readFile(path: string, encoding: 'utf8'): Promise<string>;
  open(path: string, flags: 'wx', mode: number): Promise<SetupPinsFile>;
  rename(from: string, to: string): Promise<void>;
  unlink(path: string): Promise<void>;
}

export type PinDecision =
  | 'ok'
  | 'refuse: plaintext after sealed'
  | 'refuse: older revision'
  | 'refuse: unlocked after locked'
  | 'refuse: pins unreadable';

interface PinState {
  /** Per account: it has opened a sealed setup; `locked` = it has seen the account locked. */
  accounts: Map<string, { locked: boolean }>;
  entries: Map<string, number>;
}

function parsePins(text: string): PinState {
  const value: unknown = JSON.parse(text);
  if (!isObject(value) || value.v !== 1 || Object.keys(value).length !== 3 ||
      !isObject(value.accounts) || !isObject(value.entries)) {
    throw new Error('Invalid pins');
  }
  const accounts = new Map<string, { locked: boolean }>();
  const entries = new Map<string, number>();
  for (const [id, account] of Object.entries(value.accounts)) {
    if (!id || !isObject(account) || account.sealed_seen !== true ||
        Object.keys(account).some(key => key !== 'sealed_seen' && key !== 'locked_seen') ||
        (Object.hasOwn(account, 'locked_seen') && account.locked_seen !== true)) {
      throw new Error('Invalid pins');
    }
    accounts.set(id, { locked: account.locked_seen === true });
  }
  for (const [id, rev] of Object.entries(value.entries)) {
    if (!id || !validRev(rev)) throw new Error('Invalid pins');
    entries.set(id, rev);
  }
  return { accounts, entries };
}

export class SetupPins {
  private static readonly byPath = new Map<string, SetupPins>();

  /**
   * One instance per pins file in this process. Each instance caches the file and rewrites it
   * whole, so two instances on one path could undo each other's pins (review cl5 broker B1).
   */
  static shared(path: string): SetupPins {
    let pins = SetupPins.byPath.get(path);
    if (!pins) {
      pins = new SetupPins(path);
      SetupPins.byPath.set(path, pins);
    }
    return pins;
  }

  /** Tests only: forget the shared instances (a test that deletes the pins file is a new machine). */
  static resetSharedForTests(): void {
    SetupPins.byPath.clear();
  }

  private state: PinState | null = null;
  private loaded = false;
  private unreadable = false;
  private pending: Promise<void> = Promise.resolve();

  constructor(
    private readonly path: string,
    private readonly fs: SetupPinsFs = { readFile, open, rename, unlink },
  ) {}

  private enqueue(action: () => Promise<void>): Promise<void> {
    const next = this.pending.then(action);
    this.pending = next.catch(() => {});
    return next;
  }

  load(): Promise<void> {
    return this.enqueue(async () => {
      if (this.loaded) return;
      this.loaded = true;
      try {
        this.state = parsePins(await this.fs.readFile(this.path, 'utf8'));
      } catch (error) {
        if ((error as NodeJS.ErrnoException | null)?.code === 'ENOENT') {
          this.state = { accounts: new Map(), entries: new Map() };
        } else {
          this.unreadable = true;
        }
      }
    });
  }

  decide(
    accountId: string, entryId: string, hasCiphertext: boolean, rev: number | undefined,
    locked?: unknown,
  ): PinDecision {
    if (!this.loaded || this.unreadable || !this.state) return 'refuse: pins unreadable';
    // Locking is one-way (spec L4.6). The flag is not sealed, so a server that once said
    // "locked" and now says otherwise is asking for plaintext approval traffic (review cl5 F2).
    if (this.state.accounts.get(accountId)?.locked && locked !== true) {
      return 'refuse: unlocked after locked';
    }
    if (!hasCiphertext && this.state.accounts.has(accountId)) {
      return 'refuse: plaintext after sealed';
    }
    const highest = this.state.entries.get(entryId);
    if ((hasCiphertext && !validRev(rev)) ||
        (highest !== undefined && (!validRev(rev) || rev < highest))) {
      return 'refuse: older revision';
    }
    return 'ok';
  }

  async record(accountId: string, entryId: string, rev: number, locked = false): Promise<void> {
    await this.load();
    return this.enqueue(async () => {
      if (this.unreadable || !this.state) throw new Error('refuse: pins unreadable');
      if (!accountId || !entryId || !validRev(rev)) throw new Error('Invalid pin');
      // Merge with the file as it is NOW: another broker process may have pinned higher since
      // this one loaded it, and a whole-file rewrite from a stale copy would undo that (review
      // cl5 r2 broker F2). Highest revision wins; locked is never un-set.
      let onDisk: PinState | null = null;
      try {
        onDisk = parsePins(await this.fs.readFile(this.path, 'utf8'));
      } catch (error) {
        if ((error as NodeJS.ErrnoException | null)?.code !== 'ENOENT') {
          this.unreadable = true;
          throw new Error('refuse: pins unreadable');
        }
      }
      if (onDisk) {
        const merged: PinState = {
          accounts: new Map(this.state.accounts),
          entries: new Map(this.state.entries),
        };
        for (const [id, a] of onDisk.accounts) {
          merged.accounts.set(id, { locked: a.locked || (merged.accounts.get(id)?.locked ?? false) });
        }
        for (const [id, r] of onDisk.entries) merged.entries.set(id, Math.max(r, merged.entries.get(id) ?? r));
        this.state = merged;
      }
      const current = this.state.entries.get(entryId);
      // A newer revision was pinned while this one was being opened: never hand back the older
      // setup (review cl5 F3).
      if (current !== undefined && current > rev) throw new Error('refuse: older revision');
      const account = this.state.accounts.get(accountId);
      const wasLocked = account?.locked === true;
      if (wasLocked && !locked) throw new Error('refuse: unlocked after locked');
      // Listing pins every entry on every call; write only when a pin actually moves.
      if (account && current === rev && (wasLocked || !locked)) return;
      const next: PinState = {
        accounts: new Map(this.state.accounts),
        entries: new Map(this.state.entries),
      };
      next.accounts.set(accountId, { locked: wasLocked || locked });
      next.entries.set(entryId, Math.max(rev, next.entries.get(entryId) ?? rev));
      const json = JSON.stringify({
        v: 1,
        accounts: Object.fromEntries(
          [...next.accounts.entries()].map(([id, a]) =>
            [id, a.locked ? { sealed_seen: true, locked_seen: true } : { sealed_seen: true }]),
        ),
        entries: Object.fromEntries(next.entries),
      });
      const temporary = `${this.path}.${randomBytes(16).toString('hex')}.tmp`;
      let created = false;
      try {
        const handle = await this.fs.open(temporary, 'wx', 0o600);
        created = true;
        try {
          await handle.chmod(0o600);
          await handle.writeFile(json);
          await handle.sync();
        } finally {
          await handle.close();
        }
        await this.fs.rename(temporary, this.path);
        created = false;
        this.state = next;
      } catch (error) {
        // WHY: a caller must not continue using unpersisted anti-downgrade state.
        this.unreadable = true;
        throw error;
      } finally {
        if (created) await this.fs.unlink(temporary).catch(() => {});
      }
    });
  }
}
