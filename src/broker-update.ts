import { createDecipheriv, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export type OrderState = 'received' | 'refused' | 'working' | 'installed' |
  'rolled back' | 'rollback failed' | 'failed';

export interface OrderClient {
  getOrders(brokerVersion: string): Promise<{
    orders: { id: string; agent_id: string; ciphertext: string; nonce: string }[];
  }>;
  postState(id: string, state: OrderState, detail: string): Promise<void>;
}

export interface BrokerUpdateDeps {
  fingerprint: string;
  version: string;
  client: OrderClient;
  vaultKeyFor(agentId: string): Promise<Uint8Array | null>;
  seenPath: string;
  requestPath: string;
  statusPath: string;
  now(): number;
  log(msg: string): void;
}

type OpenResult =
  | { ok: true; order: { version: string; order_id: string } }
  | { ok: false; reason: string };

function versionParts(value: unknown): bigint[] | null {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)) {
    return null;
  }
  return value.split('.').map(part => BigInt(part));
}

function newer(version: bigint[], own: bigint[]): boolean {
  for (let i = 0; i < 3; i++) {
    if (version[i] !== own[i]) return version[i]! > own[i]!;
  }
  return false;
}

function decodeBase64(value: string): Buffer {
  if (typeof value !== 'string' || value.length > 16_384 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('base64');
  }
  return Buffer.from(value, 'base64');
}

function isoTime(value: unknown): number {
  if (typeof value !== 'string') return NaN;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) return NaN;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]! ||
      Number(match[4]) > 23 || Number(match[5]) > 59 || Number(match[6]) > 59) return NaN;
  const zone = match[7]!;
  if (zone !== 'Z' && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59)) return NaN;
  return Date.parse(value);
}

export function openOrder(
  ciphertextB64: string,
  nonceB64: string,
  key: Uint8Array,
  fingerprint: string,
  nowMs: number,
  ownVersion: string,
): OpenResult {
  let plaintext: string;
  try {
    const sealed = decodeBase64(ciphertextB64);
    const nonce = decodeBase64(nonceB64);
    if (key.length !== 32 || nonce.length !== 12 || sealed.length < 16) {
      return { ok: false, reason: 'bad seal' };
    }
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(Buffer.from(`wv-broker-order-v1|${fingerprint}`, 'utf8'));
    decipher.setAuthTag(sealed.subarray(-16));
    plaintext = Buffer.concat([
      decipher.update(sealed.subarray(0, -16)),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return { ok: false, reason: 'bad seal' };
  }

  try {
    const order = JSON.parse(plaintext) as Record<string, unknown>;
    const keys = ['v', 'type', 'broker', 'version', 'order_id', 'issued_at', 'expires_at'];
    if (!order || typeof order !== 'object' || Array.isArray(order) ||
        Object.keys(order).length !== keys.length ||
        !keys.every(key => Object.hasOwn(order, key)) ||
        order.v !== 1 || order.type !== 'update' || typeof order.broker !== 'string' ||
        typeof order.order_id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(order.order_id)) {
      return { ok: false, reason: 'malformed' };
    }
    const version = versionParts(order.version);
    const own = versionParts(ownVersion);
    const issued = isoTime(order.issued_at);
    const expires = isoTime(order.expires_at);
    if (!version || !own || !Number.isFinite(issued) || !Number.isFinite(expires) ||
        !Number.isFinite(nowMs) || expires <= issued || expires - issued > 24 * 60 * 60_000) {
      return { ok: false, reason: 'malformed' };
    }
    if (order.broker !== fingerprint) return { ok: false, reason: 'wrong broker' };
    if (issued > nowMs + 2 * 60_000 || expires <= nowMs - 2 * 60_000) {
      return { ok: false, reason: 'expired' };
    }
    if (!newer(version, own)) return { ok: false, reason: 'not newer' };
    return { ok: true, order: { version: order.version as string, order_id: order.order_id } };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

interface PollState {
  running: boolean;
  seen: string[] | null;
  handedOver: Map<string, string>;
  relayed: Map<string, string>;
}

const states = new WeakMap<BrokerUpdateDeps, PollState>();

function stateFor(d: BrokerUpdateDeps): PollState {
  let state = states.get(d);
  if (!state) {
    state = { running: false, seen: null, handedOver: new Map(), relayed: new Map() };
    states.set(d, state);
  }
  return state;
}

function log(d: BrokerUpdateDeps, message: string): void {
  try {
    d.log(message);
  } catch {
    // WHY: a logging failure must not turn a timer callback into an unhandled rejection.
  }
}

async function post(
  d: BrokerUpdateDeps, id: string, state: OrderState, detail: string,
): Promise<boolean> {
  try {
    await d.client.postState(id, state, detail);
    return true;
  } catch {
    log(d, 'Update state relay failed');
    return false;
  }
}

async function loadSeen(d: BrokerUpdateDeps, state: PollState): Promise<void> {
  if (state.seen) return;
  try {
    const value: unknown = JSON.parse(await readFile(d.seenPath, 'utf8'));
    if (!Array.isArray(value) || !value.every(id => typeof id === 'string')) {
      throw new Error('invalid seen list');
    }
    state.seen = [...new Set(value as string[])].slice(-100);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    state.seen = [];
    await remember(d, state, []);
  }
}

async function remember(d: BrokerUpdateDeps, state: PollState, ids: string[]): Promise<void> {
  const next = [...new Set([...(state.seen ?? []), ...ids])].slice(-100);
  const temporary = `${d.seenPath}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, JSON.stringify(next), { flag: 'wx', mode: 0o600 });
    await rename(temporary, d.seenPath);
    state.seen = next;
  } finally {
    await unlink(temporary).catch(() => {});
  }
}

async function writeRequest(d: BrokerUpdateDeps, order: { version: string; order_id: string }): Promise<void> {
  // WHY: root owns the directory entry. Never create, replace, or follow it.
  const handle = await open(d.requestPath, constants.O_WRONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1) throw new Error('invalid spool');
    await handle.truncate(0);
    await handle.writeFile(JSON.stringify({ version: order.version, order_id: order.order_id }));
    await handle.sync();
  } finally {
    await handle.close();
  }
}

const relayStates = new Set<string>([
  'refused', 'working', 'installed', 'rolled back', 'rollback failed', 'failed',
]);

async function relay(d: BrokerUpdateDeps, state: PollState): Promise<void> {
  let value: unknown;
  try {
    const handle = await open(d.statusPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      if (!(await handle.stat()).isFile()) return;
      const buffer = Buffer.alloc(4097);
      let size = 0;
      while (size < buffer.length) {
        const result = await handle.read(buffer, size, buffer.length - size, null);
        if (result.bytesRead === 0) break;
        size += result.bytesRead;
      }
      if (size > 4096) return;
      value = JSON.parse(buffer.subarray(0, size).toString('utf8'));
    } finally {
      await handle.close();
    }
  } catch {
    return;
  }
  if (!value || typeof value !== 'object') return;
  const status = value as Record<string, unknown>;
  if (typeof status.order_id !== 'string' || typeof status.state !== 'string' ||
      !relayStates.has(status.state) || typeof status.detail !== 'string') return;
  // After a restart (an update restarts the broker on purpose) the in-memory map is empty; an
  // order this broker accepted is still in the persisted seen list, under the server's own id.
  const id = state.handedOver.get(status.order_id) ??
    (state.seen?.includes(status.order_id) ? status.order_id : undefined);
  if (id === undefined) return;
  const detail = status.detail.slice(0, 200);
  const pair = JSON.stringify([status.state, detail]);
  if (state.relayed.get(status.order_id) === pair) return;
  if (await post(d, id, status.state as OrderState, detail)) {
    state.relayed.set(status.order_id, pair);
  }
}

export async function pollOnce(d: BrokerUpdateDeps): Promise<void> {
  const state = stateFor(d);
  if (state.running) return;
  state.running = true;
  try {
    await loadSeen(d, state);
    try {
      const response = await d.client.getOrders(d.version);
      for (const envelope of response.orders) {
        if (state.seen!.includes(envelope.id)) continue;
        try {
          const key = await d.vaultKeyFor(envelope.agent_id);
          const opened = key
            ? openOrder(envelope.ciphertext, envelope.nonce, key, d.fingerprint, d.now(), d.version)
            : { ok: false as const, reason: 'no key' };
          if (!opened.ok) {
            if (await post(d, envelope.id, 'refused', opened.reason)) {
              await remember(d, state, [envelope.id]);
            }
            continue;
          }
          if (state.seen!.includes(opened.order.order_id)) {
            if (await post(d, envelope.id, 'refused', 'replay')) {
              await remember(d, state, [envelope.id]);
            }
            continue;
          }
          // The browser names the order and the server files it under that same name, so the
          // root updater's status file can be relayed by any later broker process — including the
          // new version that the update itself started, which remembers nothing of this one.
          if (opened.order.order_id !== envelope.id) {
            if (await post(d, envelope.id, 'refused', 'id mismatch')) {
              await remember(d, state, [envelope.id]);
            }
            continue;
          }
          try {
            await writeRequest(d, opened.order);
          } catch {
            if (await post(d, envelope.id, 'failed', 'no spool')) {
              await remember(d, state, [envelope.id]);
            }
            continue;
          }
          await remember(d, state, [envelope.id, opened.order.order_id]);
          state.handedOver.set(opened.order.order_id, envelope.id);
          await post(d, envelope.id, 'received', '');
        } catch {
          log(d, 'Update order processing failed');
        }
      }
    } catch {
      log(d, 'Update order poll failed');
    }
    await relay(d, state);
  } catch {
    log(d, 'Update polling failed');
  } finally {
    state.running = false;
  }
}

/** Where the root updater's spool lives (SPEC-update-now U1). Fixed: never read from the environment. */
export function updateSpoolDir(platform: NodeJS.Platform = process.platform): string | null {
  if (platform === 'linux' || platform === 'darwin') return '/var/lib/wundervault-update';
  if (platform === 'win32') return join(process.env.ProgramData ?? 'C:\\ProgramData', 'wundervault-update');
  return null;
}

export function startPolling(
  d: BrokerUpdateDeps, intervalMs = 5 * 60_000, firstMs = 30_000,
): { stop(): void } {
  let stopped = false;
  let interval: ReturnType<typeof setInterval> | undefined;
  const first = setTimeout(() => {
    if (stopped) return;
    void pollOnce(d);
    interval = setInterval(() => { void pollOnce(d); }, intervalMs);
    interval.unref();
  }, firstMs);
  first.unref();
  return {
    stop(): void {
      stopped = true;
      clearTimeout(first);
      if (interval) clearInterval(interval);
    },
  };
}
