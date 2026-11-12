/**
 * Read a secret as the agent's own user, before handing its value to the broker.
 * Nothing from a file or a command belongs in an error, including stderr.
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { TextDecoder } from 'node:util';

export type SaveSource = { from_file?: unknown; from_command?: unknown; value?: unknown; pick?: unknown };
export type ReadOk = { ok: true; value: string; type: 'file' | 'command' | 'given'; label: string; chars: number };
export type ReadFail = { ok: false; error: string; code: string };

type Pick = { ok: true; kind: 'env' | 'json'; name: string };
type ReadBytes = { ok: true; bytes: Buffer } | ReadFail;

function fail(code: string, error: string): ReadFail {
  return { ok: false, error, code };
}

function checkPick(pick: unknown): Pick | ReadFail {
  if (!pick || typeof pick !== 'object' || Array.isArray(pick) || Object.keys(pick).length !== 1) {
    return fail('BAD_REQUEST', 'pick must contain exactly one env name or JSON path');
  }
  const p = pick as Record<string, unknown>;
  if (Object.hasOwn(p, 'env') && typeof p.env === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(p.env)) {
    return { ok: true, kind: 'env', name: p.env };
  }
  if (Object.hasOwn(p, 'json') && typeof p.json === 'string') {
    const segments = p.json.split('.');
    if (segments.length <= 20 && segments.every((s) => s.length > 0)) {
      return { ok: true, kind: 'json', name: p.json };
    }
  }
  return fail('BAD_REQUEST', 'pick must contain exactly one env name or JSON path');
}

/** One pair of quotes, or an unquoted comment; never evaluate shell syntax. */
function envValue(raw: string): string {
  let value = raw.trim();
  let quote = '';
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (quote) {
      if (c === quote) quote = '';
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '#' && i > 0 && value[i - 1] === ' ') {
      value = value.slice(0, i).trim();
      break;
    }
  }
  if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0]) {
    return value.slice(1, -1);
  }
  return value.trim();
}

export function pickValue(text: string, pick: unknown): { ok: true; value: string } | ReadFail {
  const p = checkPick(pick);
  if (!p.ok) return p;
  if (p.kind === 'env') {
    const re = new RegExp(`^\\s*(?:export\\s+)?${p.name}\\s*=\\s*(.*)$`);
    let found: string | undefined;
    for (const line of text.split(/\r?\n/)) {
      if (/^\s*#/.test(line)) continue;
      const match = re.exec(line);
      if (!match) continue;
      if (found !== undefined) return fail('AMBIGUOUS', 'the name given is set more than once in it');
      found = envValue(match[1]);
    }
    return found === undefined
      ? fail('NOT_FOUND', 'the name given is not set in it')
      : { ok: true, value: found };
  }

  let at: unknown;
  try { at = JSON.parse(text); } catch { return fail('NOT_JSON', 'it is not JSON'); }
  for (const segment of p.name.split('.')) {
    if (at === null || typeof at !== 'object') {
      return fail('NOT_FOUND', 'there is no text at the path given');
    }
    let key = segment;
    if (Array.isArray(at)) {
      if (!/^\d+$/.test(segment) || !Number.isSafeInteger(Number(segment))) {
        return fail('NOT_FOUND', 'there is no text at the path given');
      }
      key = String(Number(segment));
    }
    if (!Object.hasOwn(at, key)) return fail('NOT_FOUND', 'there is no text at the path given');
    at = (at as Record<string, unknown>)[key];
  }
  return typeof at === 'string' && at.length > 0
    ? { ok: true, value: at }
    : fail('NOT_FOUND', 'there is no text at the path given');
}

async function readFile(p: string, maxBytes: number): Promise<ReadBytes> {
  let handle: Awaited<ReturnType<typeof fs.promises.open>> | undefined;
  try {
    // Nonblocking open makes a FIFO safe to inspect. Symlinks are allowed.
    handle = await fs.promises.open(p, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
    const stat = await handle.stat();
    if (!stat.isFile()) return fail('NOT_A_FILE', `not a regular file: ${p}`);
    if (stat.size > maxBytes) return fail('TOO_BIG', `the file is too big: ${p}`);

    const chunks: Buffer[] = [];
    let total = 0;
    while (total <= maxBytes) {
      // The open file may have grown since fstat; read only one byte past the limit.
      const chunk = Buffer.alloc(Math.min(8192, maxBytes + 1 - total));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) return fail('TOO_BIG', `the file is too big: ${p}`);
      chunks.push(chunk.subarray(0, bytesRead));
    }
    return { ok: true, bytes: Buffer.concat(chunks, total) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'EISDIR') {
      return fail('NOT_A_FILE', `not a regular file: ${p}`);
    }
    return fail('UNREADABLE', `cannot read the file: ${p}`);
  } finally {
    if (handle) {
      try { await handle.close(); } catch { /* already closed or unreadable */ }
    }
  }
}

function readCommand(argv: string[], maxBytes: number, timeoutMs: number): Promise<ReadBytes> {
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(argv[0], argv.slice(1), {
        shell: false, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true,
        // Its own process group on Unix, so a timeout ends what it started too (review r1 B1).
        detached: process.platform !== 'win32',
      });
    } catch {
      resolve(fail('NO_PROGRAM', `cannot run the program: ${path.basename(argv[0])}`));
      return;
    }

    let settled = false;
    let total = 0;
    const chunks: Buffer[] = [];
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: ReadBytes) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (!result.ok) child.stdout?.destroy();
      resolve(result);
    };
    const stop = (result: ReadFail) => {
      if (settled) return;
      if (process.platform !== 'win32' && child.pid) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
      } else {
        child.kill('SIGKILL');
      }
      finish(result);
    };

    child.once('error', () => {
      finish(fail('NO_PROGRAM', `cannot run the program: ${path.basename(argv[0])}`));
    });
    child.stdout?.on('data', (chunk: Buffer) => {
      if (settled) return;
      if (chunk.length > maxBytes - total) {
        stop(fail('TOO_BIG', 'the command output is too big'));
        return;
      }
      total += chunk.length;
      chunks.push(chunk);
    });
    child.stdout?.once('error', () => {
      stop(fail('UNREADABLE', 'the command output could not be read'));
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      if (signal) {
        finish(fail('EXIT_CODE', `the command ended with signal ${signal}; its output is not shown`));
      } else if (code !== 0) {
        finish(fail('EXIT_CODE', `the command ended with exit code ${code}; its output is not shown`));
      } else {
        finish({ ok: true, bytes: Buffer.concat(chunks, total) });
      }
    });
    timer = setTimeout(() => {
      stop(fail('TIMEOUT', 'the command did not finish in 30 seconds'));
    }, timeoutMs);
  });
}

export async function readSaveSource(
  src: SaveSource,
  opts?: { timeoutMs?: number; maxBytes?: number },
): Promise<ReadOk | ReadFail> {
  if (!src || typeof src !== 'object' || Array.isArray(src)) {
    return fail('BAD_REQUEST', 'give exactly one of from_file, from_command or value');
  }
  // A key present but undefined is not given (the tool passes every field it has, set or not).
  const given = (k: string) => Object.hasOwn(src, k) && (src as Record<string, unknown>)[k] !== undefined;
  const sources = ['from_file', 'from_command', 'value'].filter(given);
  if (sources.length !== 1) {
    return fail('BAD_REQUEST', 'give exactly one of from_file, from_command or value');
  }
  const hasPick = given('pick');
  if (sources[0] === 'value' && hasPick) return fail('BAD_REQUEST', 'pick is not allowed with value');
  if (hasPick) {
    const checked = checkPick(src.pick);
    if (!checked.ok) return checked;
  }

  const maxBytes = opts?.maxBytes ?? 65536;
  const timeoutMs = opts?.timeoutMs ?? 30000;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || !Number.isSafeInteger(maxBytes + 1)
      || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2147483647) {
    return fail('BAD_REQUEST', 'the read limits are not valid');
  }

  let type: ReadOk['type'];
  let label: string;
  let bytes: Buffer;
  if (sources[0] === 'from_file') {
    if (typeof src.from_file !== 'string' || !path.isAbsolute(src.from_file) || src.from_file.includes('\0')) {
      return fail('BAD_REQUEST', 'from_file must be an absolute path without NUL');
    }
    type = 'file';
    label = src.from_file;
    const read = await readFile(src.from_file, maxBytes);
    if (!read.ok) return read;
    bytes = read.bytes;
  } else if (sources[0] === 'from_command') {
    const argv = src.from_command;
    if (!Array.isArray(argv) || argv.length === 0 || argv.length > 64
        || !argv.every((arg) => typeof arg === 'string' && arg.length <= 4096 && !arg.includes('\0'))
        || argv[0].length === 0) {
      return fail('BAD_REQUEST', 'from_command is a list: the program, then its arguments; no shell');
    }
    type = 'command';
    const n = argv.length - 1;
    label = `the command ${path.basename(argv[0])}${n > 0 ? ` (with ${n} arguments)` : ''}`;
    const read = await readCommand(argv, maxBytes, timeoutMs);
    if (!read.ok) return read;
    bytes = read.bytes;
  } else {
    if (typeof src.value !== 'string') return fail('BAD_REQUEST', 'value must be text');
    type = 'given';
    label = 'given in the chat';
    bytes = Buffer.from(src.value, 'utf8');
  }

  let text: string;
  try {
    // Keep a BOM: silently discarding it would change the value.
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return fail('NOT_TEXT', 'the value is not valid UTF-8 text without NUL');
  }
  if (type === 'given' && text !== src.value) {
    return fail('NOT_TEXT', 'the value is not valid UTF-8 text without NUL');
  }

  let value: string;
  if (hasPick) {
    const picked = pickValue(text, src.pick);
    if (!picked.ok) return picked;
    value = picked.value;
  } else {
    value = text.endsWith('\r\n') ? text.slice(0, -2) : text.endsWith('\n') ? text.slice(0, -1) : text;
  }
  // JSON strings can introduce a lone surrogate even when the source bytes were valid.
  if (value.includes('\0') || Buffer.from(value, 'utf8').toString('utf8') !== value) {
    return fail('NOT_TEXT', 'the value is not valid UTF-8 text without NUL');
  }
  const size = Buffer.byteLength(value, 'utf8');
  if (size < 8) return fail('TOO_SHORT', 'the value must be at least 8 bytes');
  if (size > 16384) return fail('TOO_BIG', 'the value must be no more than 16 KB');
  if (value !== value.trim()) return fail('SPACES', 'the value starts or ends with spaces');
  return { ok: true, value, type, label, chars: [...value].length };
}
