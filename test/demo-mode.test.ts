/**
 * Demo mode as a directory scanner meets it: several copies started at once, no agent name.
 * Runs the BUILT server (dist/index.js), as Glama does, over real stdio.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ENTRY = path.join(__dirname, '..', 'dist', 'index.js');
let home: string;
beforeAll(() => { home = mkdtempSync(path.join(os.tmpdir(), 'wv-demo-')); });
afterAll(() => { rmSync(home, { recursive: true, force: true }); });

/** Start one copy, send `calls` after the handshake, collect the replies by id, close it. */
function session(calls: { id: number; method: string; params: unknown }[]): Promise<Record<number, any>> {
  return new Promise((resolve, reject) => {
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: home, WUNDERVAULT_MOCK: '1' };
    const p = spawn(process.execPath, [ENTRY, '--url', 'http://127.0.0.1:9'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let buf = ''; const got: Record<number, any> = {};
    const timer = setTimeout(() => { p.kill(); reject(new Error('replies missing after 15 s')); }, 15_000);
    p.stdout.on('data', (d) => {
      buf += d;
      const lines = buf.split('\n'); buf = lines.pop()!;
      for (const line of lines) {
        try { const m = JSON.parse(line); if (m.id !== undefined) got[m.id] = m; } catch { /* not JSON */ }
      }
      if (calls.every((c) => got[c.id])) { clearTimeout(timer); p.stdin.end(); resolve(got); }
    });
    p.on('error', reject);
    const send = (o: unknown) => p.stdin.write(JSON.stringify(o) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'scan', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    for (const c of calls) send({ jsonrpc: '2.0', ...c });
  });
}

/** Start one copy, list its tools, close it. */
function listTools(): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: home, WUNDERVAULT_MOCK: '1' };
    const p = spawn(process.execPath, [ENTRY, '--url', 'http://127.0.0.1:9'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let buf = '';
    const timer = setTimeout(() => { p.kill(); reject(new Error('no tools/list reply in 15 s')); }, 15_000);
    p.stdout.on('data', (d) => {
      buf += d;
      for (const line of buf.split('\n')) {
        try {
          const m = JSON.parse(line);
          if (m.id === 2) { clearTimeout(timer); p.stdin.end(); resolve(m.result.tools.map((t: { name: string }) => t.name)); }
        } catch { /* partial line */ }
      }
    });
    p.on('error', reject);
    const send = (o: unknown) => p.stdin.write(JSON.stringify(o) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'scan', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  });
}

describe('demo mode holds no lock (2.0.2: Glama listed one tool)', () => {
  it('three copies started at once, with no agent name, each list the five vault tools', async () => {
    expect(existsSync(ENTRY)).toBe(true);
    const all = await Promise.all([listTools(), listTools(), listTools()]);
    for (const tools of all) {
      expect(tools.sort()).toEqual(['vault_call', 'vault_entries_list', 'vault_pay', 'vault_sign', 'vault_ssh_exec']);
    }
  }, 60_000);

  it('every tool answers in demo mode with a demo reply, and none tries to reach a broker', async () => {
    const tools = ['vault_entries_list', 'vault_call', 'vault_ssh_exec', 'vault_pay', 'vault_sign'];
    const got = await session(tools.map((name, i) => ({
      id: 10 + i, method: 'tools/call', params: { name, arguments: { entry_id: 'demo-0001', purpose: 'scan',
        destination: 'demo-host', command: 'true', request: { method: 'GET' } } },
    })));
    for (let i = 0; i < tools.length; i++) {
      const text = got[10 + i].result.content.map((c: { text: string }) => c.text).join('');
      expect(text, tools[i]).toMatch(/DEMO MODE/);
      // Demo replies may say a key "never left the broker"; a real attempt says "Vault unavailable".
      expect(text, tools[i]).not.toMatch(/Vault unavailable|ECONNREFUSED/);
      expect(got[10 + i].result.isError ?? false, tools[i]).toBe(false);
    }
  }, 60_000);

  it('leaves no file behind: demo mode takes no lock and writes no state', async () => {
    await Promise.all([listTools(), listTools()]);
    const left: string[] = [];
    const walk = (d: string) => { for (const e of readdirSync(d, { withFileTypes: true })) {
      const f = path.join(d, e.name); left.push(f); if (e.isDirectory()) walk(f); } };
    walk(home);
    expect(left).toEqual([]);
  }, 60_000);
});
