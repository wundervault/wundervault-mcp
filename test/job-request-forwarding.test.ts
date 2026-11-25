/**
 * 2.7.0 shipped with vault_job_request's `file` dropped on the way to the broker: the MCP server and
 * the broker's socket handler each copy the tool's fields BY NAME, and neither copied the new one,
 * so every file job became a text job. Every field the tool accepts must be passed on by both.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

const src = (f: string) => fs.readFileSync(path.join(__dirname, '..', 'src', f), 'utf8');
// Comments removed: a field named only in a comment is not forwarded (review r1 F1).
const code = (text: string) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
// The field passed on as a property: `name: a.name` or `{ file: a.file }`.
const forwards = (block: string, f: string) => new RegExp(`(^|[\\s{,])${f}:\\s*(a|msg)\\.${f}\\b`, 'm').test(code(block));

/** The fields the tool really accepts: its schema as the built server lists it (review r2 F1: not by
 *  parsing source indentation). */
function toolFields(): Promise<string[]> {
  const entry = path.join(__dirname, '..', 'dist', 'index.js');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-fields-'));
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [entry, '--url', 'http://127.0.0.1:9'],
      { env: { PATH: process.env.PATH, HOME: home, WUNDERVAULT_MOCK: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
    const timer = setTimeout(() => { p.kill(); reject(new Error('no tools/list reply')); }, 15_000);
    let buf = '';
    p.stdout.on('data', (d) => {
      buf += d.toString();
      const lines = buf.split('\n'); buf = lines.pop()!;
      for (const line of lines) {
        try {
          const m = JSON.parse(line);
          if (m.id === 2) {
            clearTimeout(timer); p.stdin.end(); fs.rmSync(home, { recursive: true, force: true });
            const tool = m.result.tools.find((t: { name: string }) => t.name === 'vault_job_request');
            resolve(Object.keys(tool.inputSchema.properties));
          }
        } catch { /* partial line */ }
      }
    });
    p.on('error', reject);
    const send = (o: unknown) => p.stdin.write(JSON.stringify(o) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'fields', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  });
}

describe('vault_job_request passes every field it accepts to the broker', () => {
  const server = src('server.ts');
  let fields: string[] = [];
  beforeAll(async () => { fields = await toolFields(); }, 30_000);

  it('the tool still takes the fields we expect (guards the parser)', () => {
    expect(fields).toEqual(expect.arrayContaining(['name', 'entry_id', 'destination', 'argv', 'schedule',
      'timeout_s', 'grace_minutes', 'why', 'file']));
  });

  it('the MCP server forwards each of them', () => {
    const at = server.indexOf("broker.send('job_request', {");
    const block = server.slice(at, server.indexOf('});', at));
    for (const f of fields) expect(forwards(block, f), f).toBe(true);
  });

  it("the broker's socket handler forwards each of them", () => {
    const agent = src('agent.ts');
    const at = agent.indexOf("case 'job_request': {");
    const block = agent.slice(at, agent.indexOf('}) as unknown as Record<string, unknown>;', at));
    for (const f of fields) expect(forwards(block, f), f).toBe(true);
  });
});
