import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { newKeyForms } from '../src/new-key.js';
import { pickValue, readSaveSource } from '../src/save-source.js';
import type { ReadFail } from '../src/save-source.js';

const SECRET = 'PLANTED_s3cr3t_A9-xY7+/%end';
const unix = process.platform !== 'win32';

function refused(result: { ok: true } | ReadFail, code: string): ReadFail {
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('expected refusal');
  expect(result.code).toBe(code);
  for (const form of newKeyForms(SECRET)) expect(result.error).not.toContain(form);
  expect(result.error).not.toContain(SECRET.slice(0, 8));
  expect(result.error).not.toContain(SECRET.slice(-8));
  return result;
}

describe('save source', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-save-source-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function file(contents: string | Buffer, name = 'source'): string {
    const p = path.join(dir, name);
    fs.writeFileSync(p, contents);
    return p;
  }

  it('reads a regular file, removing one trailing newline', async () => {
    const p = file(`${SECRET}\r\n`);
    const open = vi.spyOn(fs.promises, 'open');
    expect(await readSaveSource({ from_file: p })).toEqual({
      ok: true, value: SECRET, type: 'file', label: p, chars: SECRET.length,
    });
    expect(open).toHaveBeenCalledWith(p, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
  });

  it.skipIf(!unix)('allows a symlink to a regular file', async () => {
    const p = file(SECRET);
    const link = path.join(dir, 'link');
    fs.symlinkSync(p, link);
    expect(await readSaveSource({ from_file: link })).toEqual({
      ok: true, value: SECRET, type: 'file', label: link, chars: SECRET.length,
    });
  });

  it('requires exactly one source before opening or running anything', async () => {
    const p = file(SECRET);
    const open = vi.spyOn(fs.promises, 'open');
    const marker = path.join(dir, 'must-not-exist');
    const command = [process.execPath, '-e', 'require("node:fs").writeFileSync(process.argv[1], "ran")', marker];
    refused(await readSaveSource({}), 'BAD_REQUEST');
    refused(await readSaveSource({ from_file: p, value: SECRET }), 'BAD_REQUEST');
    refused(await readSaveSource({ from_file: p, from_command: command }), 'BAD_REQUEST');
    refused(await readSaveSource({ from_command: command, value: SECRET }), 'BAD_REQUEST');
    refused(await readSaveSource({ from_file: undefined, value: undefined }), 'BAD_REQUEST');
    expect(open).not.toHaveBeenCalled();
    // A field present but undefined is not a second source (the tool passes every field it has).
    expect(await readSaveSource({ from_file: p, value: undefined, from_command: undefined, pick: undefined })).toMatchObject({ ok: true, value: SECRET });
    expect(fs.existsSync(marker)).toBe(false);
  });

  it('validates pick before opening a file', async () => {
    const open = vi.spyOn(fs.promises, 'open');
    refused(await readSaveSource({ from_file: path.join(dir, 'missing'), pick: {} }), 'BAD_REQUEST');
    expect(open).not.toHaveBeenCalled();
  });

  it('refuses a relative path and non-string paths', async () => {
    refused(await readSaveSource({ from_file: 'relative.env' }), 'BAD_REQUEST');
    refused(await readSaveSource({ from_file: 1 }), 'BAD_REQUEST');
    refused(await readSaveSource({ from_file: `${dir}\0` }), 'BAD_REQUEST');
  });

  it('refuses an unreadable path without exposing native errors', async () => {
    const p = path.join(dir, 'missing');
    const result = refused(await readSaveSource({ from_file: p }), 'UNREADABLE');
    expect(result.error).toBe(`cannot read the file: ${p}`);
  });

  it('refuses a directory', async () => {
    refused(await readSaveSource({ from_file: dir }), 'NOT_A_FILE');
  });

  it.skipIf(!unix)('refuses a FIFO without waiting for a writer', async () => {
    const p = path.join(dir, 'fifo');
    execFileSync('mkfifo', [p]);
    refused(await readSaveSource({ from_file: p }), 'NOT_A_FILE');
  }, 2000);

  it.skipIf(!unix)('refuses /dev/zero without reading it', async () => {
    refused(await readSaveSource({ from_file: '/dev/zero' }), 'NOT_A_FILE');
  }, 2000);

  it('refuses a 70 KB file and honors a smaller read cap', async () => {
    refused(await readSaveSource({ from_file: file(SECRET + 'x'.repeat(70 * 1024)) }), 'TOO_BIG');
    refused(await readSaveSource({ from_file: file(SECRET) }, { maxBytes: 8 }), 'TOO_BIG');
  });

  it('caps a file that grows after fstat at maxBytes plus one', async () => {
    const p = file(SECRET + 'x'.repeat(100));
    const handle = await fs.promises.open(p, 'r');
    const stat = await handle.stat();
    stat.size = 0;
    vi.spyOn(handle, 'stat').mockImplementation(async () => stat);
    const read = vi.spyOn(handle, 'read');
    vi.spyOn(fs.promises, 'open').mockResolvedValue(handle);
    refused(await readSaveSource({ from_file: p }, { maxBytes: 32 }), 'TOO_BIG');
    expect(read).toHaveBeenCalledTimes(1);
    expect(read.mock.calls[0][2]).toBe(33);
  });

  it('extracts env assignments with export, quotes, whitespace and comments', async () => {
    const variants = [
      `#NAME=ignored\nexport NAME="${SECRET}"\nOTHER=ignored\n`,
      `NAME=${SECRET}\n`,
      `  NAME = '${SECRET}'  \r\n`,
      `NAME=  ${SECRET}   # comment\n`,
      `NAME="${SECRET}" # comment\n`,
    ];
    for (const contents of variants) {
      const p = file(contents);
      expect(await readSaveSource({ from_file: p, pick: { env: 'NAME' } })).toEqual({
        ok: true, value: SECRET, type: 'file', label: p, chars: SECRET.length,
      });
    }
    expect(pickValue('NAME="text # inside quotes"', { env: 'NAME' })).toEqual({
      ok: true, value: 'text # inside quotes',
    });
    expect(pickValue('NAME=one=two', { env: 'NAME' })).toEqual({ ok: true, value: 'one=two' });
  });

  it('refuses duplicate env assignments, including an empty first value', async () => {
    for (const contents of [
      `#NAME=ignored\nNAME=${SECRET}\nexport NAME='second-value'\n`,
      `NAME=\nNAME=${SECRET}\n`,
    ]) {
      const result = refused(await readSaveSource({ from_file: file(contents), pick: { env: 'NAME' } }), 'AMBIGUOUS');
      expect(result.error).toBe('the name given is set more than once in it');
    }
  });

  it('refuses a missing env name without including any line', async () => {
    const result = refused(await readSaveSource({
      from_file: file(`#NAME=${SECRET}\nOTHER=${SECRET}\n`), pick: { env: 'NAME' },
    }), 'NOT_FOUND');
    expect(result.error).toBe('the name given is not set in it');
  });

  it('extracts a nested JSON string, including an array index', async () => {
    const p = file(JSON.stringify({ a: { b: [{ c: SECRET }] } }));
    expect(await readSaveSource({ from_file: p, pick: { json: 'a.b.0.c' } })).toEqual({
      ok: true, value: SECRET, type: 'file', label: p, chars: SECRET.length,
    });
  });

  it('refuses invalid JSON, missing paths and non-text JSON values', async () => {
    refused(await readSaveSource({ from_file: file(`not JSON ${SECRET}`), pick: { json: 'a.b' } }), 'NOT_JSON');
    for (const b of [123, {}, [], '', null]) {
      const result = refused(await readSaveSource({
        from_file: file(JSON.stringify({ a: { b }, secret: SECRET })), pick: { json: 'a.b' },
      }), 'NOT_FOUND');
      expect(result.error).toBe('there is no text at the path given');
    }
    refused(pickValue(`{"secret":"${SECRET}"}`, { json: 'missing' }), 'NOT_FOUND');
    refused(pickValue('{}', { json: 'constructor.name' }), 'NOT_FOUND');
    refused(pickValue('[]', { json: 'length' }), 'NOT_FOUND');
  });

  it('r2 F1: a refusal after reading never repeats the name or path given (it could be the value)', async () => {
    const f = path.join(dir, 'echo.json');
    fs.writeFileSync(f, JSON.stringify({ token: 'there is no text at missing' }));
    const r = await readSaveSource({ from_file: f, pick: { json: 'missing' } });
    expect(r).toMatchObject({ ok: false, code: 'NOT_FOUND' });
    expect((r as { error: string }).error).not.toContain('missing');
  });

  it('validates the complete pick shape', () => {
    for (const pick of [
      null, [], {}, 'NAME', { env: 'NAME', json: 'a' }, { env: 'NAME', extra: true },
      { env: 'A.*' }, { env: '1NAME' }, { env: '' }, { env: 1 },
      { json: '' }, { json: 'a..b' }, { json: '.a' }, { json: 'a.' },
      { json: Array(21).fill('a').join('.') }, { json: 1 },
    ]) {
      refused(pickValue(SECRET, pick), 'BAD_REQUEST');
    }
  });

  it.skipIf(!unix)('runs printf without including arguments in its label', async () => {
    expect(await readSaveSource({ from_command: ['printf', '%s', SECRET] })).toEqual({
      ok: true, value: SECRET, type: 'command', label: 'the command printf (with 2 arguments)', chars: SECRET.length,
    });
  });

  it('uses only the program basename in a command label', async () => {
    const result = await readSaveSource({
      from_command: [process.execPath, '-e', 'process.stdout.write(process.argv[1])', SECRET],
    });
    expect(result).toEqual({
      ok: true, value: SECRET, type: 'command',
      label: `the command ${path.basename(process.execPath)} (with 3 arguments)`, chars: SECRET.length,
    });
  });

  it('closes command stdin', async () => {
    const result = await readSaveSource({
      from_command: [
        process.execPath, '-e',
        'process.stdin.resume(); process.stdin.on("end", () => process.stdout.write(process.argv[1]))',
        SECRET,
      ],
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe(SECRET);
  });

  it('validates argv without accepting shell command strings', async () => {
    for (const argv of [
      'a | b', [], [''], ['printf', 1], ['printf', 'x\0y'],
      ['printf', 'x'.repeat(4097)], Array(65).fill('printf'),
    ]) {
      const result = refused(await readSaveSource({ from_command: argv }), 'BAD_REQUEST');
      expect(result.error).toBe('from_command is a list: the program, then its arguments; no shell');
    }
  });

  it('does not interpret shell metacharacters in arguments', async () => {
    const text = `${SECRET} | echo not-a-pipeline`;
    const result = await readSaveSource({
      from_command: [process.execPath, '-e', 'process.stdout.write(process.argv[1])', text],
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe(text);
  });

  it.skipIf(!unix)('discards stdout and stderr on exit code 3', async () => {
    const result = refused(await readSaveSource({
      from_command: ['sh', '-c', `printf '%s' '${SECRET}'; echo '${SECRET}' >&2; exit 3`],
    }), 'EXIT_CODE');
    expect(result.error).toBe('the command ended with exit code 3; its output is not shown');
    const empty = refused(await readSaveSource({ from_command: ['sh', '-c', 'exit 3'] }), 'EXIT_CODE');
    expect(empty.error).toContain('exit code 3');
  });

  it.skipIf(!unix)('never reads stderr, even on a successful exit', async () => {
    const result = refused(await readSaveSource({
      from_command: ['sh', '-c', `echo '${SECRET}' >&2; exit 0`],
    }), 'TOO_SHORT');
    expect(result.error).toBe('the value must be at least 8 bytes');
  });

  it.skipIf(!unix)('kills a sleeping program at the test timeout', async () => {
    const started = Date.now();
    const result = refused(await readSaveSource({
      from_command: ['sleep', '40'],
    }, { timeoutMs: 500 }), 'TIMEOUT');
    expect(result.error).toBe('the command did not finish in 30 seconds');
    expect(Date.now() - started).toBeLessThan(4000);
  }, 5000);

  it.skipIf(!unix)('r1 B1: a timeout also ends what the command started', async () => {
    const late = path.join(dir, 'late-write');
    const r = await readSaveSource({ from_command: ['/bin/sh', '-c', `(sleep 1; touch ${late}) & wait`] }, { timeoutMs: 300 });
    expect(r).toMatchObject({ ok: false, code: 'TIMEOUT' });
    await new Promise((res) => setTimeout(res, 1500));
    expect(fs.existsSync(late)).toBe(false);
  });

  it('kills a command whose stdout exceeds the source cap', async () => {
    refused(await readSaveSource({
      from_command: [
        process.execPath, '-e',
        'process.stdout.write(process.argv[1].repeat(10000)); setInterval(() => {}, 1000)',
        SECRET,
      ],
    }, { maxBytes: 128 }), 'TOO_BIG');
  });

  it.skipIf(!unix)('reports a signal without the output', async () => {
    const result = refused(await readSaveSource({
      from_command: [
        process.execPath, '-e',
        'process.stdout.write(process.argv[1], () => process.kill(process.pid, "SIGTERM"))', SECRET,
      ],
    }), 'EXIT_CODE');
    expect(result.error).toBe('the command ended with signal SIGTERM; its output is not shown');
  });

  it('names only the program basename on a spawn error', async () => {
    const result = refused(await readSaveSource({
      from_command: [path.join(dir, 'missing-program'), SECRET],
    }), 'NO_PROGRAM');
    expect(result.error).toBe('cannot run the program: missing-program');
  });

  it('applies pick to command output too', async () => {
    const result = await readSaveSource({
      from_command: [process.execPath, '-e', 'process.stdout.write(process.argv[1])', `NAME="${SECRET}"\n`],
      pick: { env: 'NAME' },
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe(SECRET);
  });

  it('accepts a given value but never pick with it', async () => {
    expect(await readSaveSource({ value: SECRET })).toEqual({
      ok: true, value: SECRET, type: 'given', label: 'given in the chat', chars: SECRET.length,
    });
    refused(await readSaveSource({ value: SECRET, pick: { env: 'NAME' } }), 'BAD_REQUEST');
    refused(await readSaveSource({ value: 123 }), 'BAD_REQUEST');
  });

  it('removes exactly one newline, not arbitrary surrounding whitespace', async () => {
    for (const ending of ['\n', '\r\n']) {
      const result = await readSaveSource({ value: SECRET + ending });
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.value).toBe(SECRET);
    }
    for (const value of [` ${SECRET}`, `${SECRET} `, `${SECRET}\t`, `${SECRET}\n\n`, `${SECRET}\r\n\n`]) {
      refused(await readSaveSource({ value }), 'SPACES');
    }
    refused(await readSaveSource({ from_file: file(`NAME="${SECRET} "\n`), pick: { env: 'NAME' } }), 'SPACES');
  });

  it('uses byte limits but counts Unicode characters', async () => {
    const value = '🔑🔑';
    expect(await readSaveSource({ value })).toEqual({
      ok: true, value, type: 'given', label: 'given in the chat', chars: 2,
    });
    refused(await readSaveSource({ value: 'ééé' }), 'TOO_SHORT');
    expect((await readSaveSource({ value: 'x'.repeat(8) })).ok).toBe(true);
    expect((await readSaveSource({ value: 'é'.repeat(8192) })).ok).toBe(true);
    refused(await readSaveSource({ value: SECRET + 'x'.repeat(16384) }), 'TOO_BIG');
    refused(await readSaveSource({ from_file: file(SECRET + 'x'.repeat(16384)) }), 'TOO_BIG');
    refused(await readSaveSource({ value: 'short' }), 'TOO_SHORT');
  });

  it('refuses invalid UTF-8, NUL and lone surrogates without quoting the text', async () => {
    refused(await readSaveSource({
      from_file: file(Buffer.concat([Buffer.from(SECRET), Buffer.from([0xc3, 0x28])])),
    }), 'NOT_TEXT');
    refused(await readSaveSource({ from_file: file(`${SECRET}\0`) }), 'NOT_TEXT');
    refused(await readSaveSource({ value: `${SECRET}\0` }), 'NOT_TEXT');
    refused(await readSaveSource({ value: `${SECRET}\ud800` }), 'NOT_TEXT');
    refused(await readSaveSource({
      from_file: file(JSON.stringify({ key: `${SECRET}\ud800` })), pick: { json: 'key' },
    }), 'NOT_TEXT');
    refused(await readSaveSource({
      from_command: [process.execPath, '-e', 'process.stdout.write(Buffer.from([255]))'],
    }), 'NOT_TEXT');
  });

  it('does not silently discard a leading UTF-8 BOM', async () => {
    refused(await readSaveSource({ from_file: file(`\ufeff${SECRET}`) }), 'SPACES');
  });

  it('validates read limits before opening anything', async () => {
    const open = vi.spyOn(fs.promises, 'open');
    for (const opts of [{ maxBytes: 0 }, { maxBytes: NaN }, { timeoutMs: 0 }, { timeoutMs: Infinity }]) {
      refused(await readSaveSource({ from_file: path.join(dir, 'missing') }, opts), 'BAD_REQUEST');
    }
    expect(open).not.toHaveBeenCalled();
  });
});
