import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AgentDaemon } from '../src/agent.js';

/**
 * A long-running vault tool picks up a re-enrolled token (SPEC-2.0-shared-agent, round 2, B2).
 *
 * BrokerClient read the agent's token once. After a Repair the owner enrols again and the
 * broker and the token file both get a new token; every chat already open then kept sending the
 * old one and got 'unauthorized'. Sharing means more such chats. Real broker, real socket.
 */

const T1 = 'a1'.repeat(32);
const T2 = 'b2'.repeat(32);
let dir: string;
let daemon: AgentDaemon | undefined;
const KEYS = ['WUNDERVAULT_SYSTEM_ROOT', 'WUNDERVAULT_USER_ROOT', 'WUNDERVAULT_RUNTIME_DIR', 'WUNDERVAULT_AGENT_NO_AUTOSTART',
              'WUNDERVAULT_OLD_UNIT', 'WUNDERVAULT_KNOCK_BASE_MS', 'WUNDERVAULT_KNOCK_MAX_MS', 'WUNDERVAULT_AGENT_NAME',
              'WUNDERVAULT_AGENT_TOKEN'];
const saved: Record<string, string | undefined> = {};

function profile(token: string) {
  return { agent_name: 'R', api_key: 'wv_agent_R|k', enc_key: Buffer.alloc(32, 7).toString('base64url'),
           vault_url: 'http://127.0.0.1:1', socket_token: token };
}

beforeEach(async () => {
  for (const k of KEYS) saved[k] = process.env[k];
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wv-tokreload-'));
  process.env.WUNDERVAULT_SYSTEM_ROOT = path.join(dir, 'state');
  process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'home', '.wundervault');
  process.env.WUNDERVAULT_RUNTIME_DIR = path.join(dir, 'run');
  process.env.WUNDERVAULT_AGENT_NO_AUTOSTART = '1';
  process.env.WUNDERVAULT_OLD_UNIT = 'wundervault-test-not-a-real-unit.service';
  process.env.WUNDERVAULT_KNOCK_BASE_MS = '2';
  process.env.WUNDERVAULT_KNOCK_MAX_MS = '20';
  process.env.WUNDERVAULT_AGENT_NAME = 'R';
  delete process.env.WUNDERVAULT_AGENT_TOKEN;
  daemon = new AgentDaemon();
  daemon.registerProfile(profile(T1));
  daemon.start();
});

afterEach(() => {
  try { daemon?.shutdown(); } catch { /* down */ }
  daemon = undefined;
  for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  fs.rmSync(dir, { recursive: true, force: true });
});

async function writeToken(t: string) {
  const { agentTokenPath } = await import('../src/paths.js');
  fs.mkdirSync(path.dirname(agentTokenPath('R')), { recursive: true });
  fs.writeFileSync(agentTokenPath('R'), t + '\n', { mode: 0o600 });
}

describe('a re-enrolled token reaches a vault tool that is already running', () => {
  it('retries once with the new token from the file, and only when it changed', async () => {
    await writeToken(T1);
    const { BrokerClient } = await import('../src/broker-client.js');
    const c = new BrokerClient('R');
    const first = await c.send('ping');
    expect(first.error).toBeUndefined();

    // The Repair: the broker now knows T2, and enrol wrote T2 to the file.
    daemon!.registerProfile(profile(T2));
    await writeToken(T2);
    const after = await c.send('ping');
    expect(after.error).toBeUndefined();
  });

  it('recovers every call in flight when the token changes under them (round 3, F1)', async () => {
    await writeToken(T1);
    const { BrokerClient } = await import('../src/broker-client.js');
    const c = new BrokerClient('R');
    expect((await c.send('ping')).error).toBeUndefined();
    daemon!.registerProfile(profile(T2));
    await writeToken(T2);
    // All three carry T1 before any refusal comes back; the first to be refused reloads the
    // shared token, and the others must still retry because THEY sent T1.
    const replies = await Promise.all([c.send('ping'), c.send('ping'), c.send('ping')]);
    expect(replies.map((r) => r.error ?? 'ok')).toEqual(['ok', 'ok', 'ok']);
  });

  it('sends a wrong token once, not twice (round 3, B2)', async () => {
    await writeToken('c3'.repeat(32));
    const { BrokerClient } = await import('../src/broker-client.js');
    const spy = vi.spyOn(console, 'error');
    try {
      const r = await new BrokerClient('R').send('ping');
      expect(r.error).toBe('unauthorized');
      const fails = spy.mock.calls.filter((a) => String(a[0]).includes('Auth failure on R socket'));
      expect(fails.length).toBe(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('names WUNDERVAULT_AGENT_TOKEN when that is where a refused token came from (round 3, B3)', async () => {
    await writeToken(T1);
    process.env.WUNDERVAULT_AGENT_TOKEN = 'd4'.repeat(32);
    const { BrokerClient } = await import('../src/broker-client.js');
    const r = await new BrokerClient('R').send('ping');
    expect(String(r.error)).toMatch(/WUNDERVAULT_AGENT_TOKEN/);
  });
});
