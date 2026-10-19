/**
 * WUNDERVAULT_MOCK=1: directory scanners (Glama) and CI start the server with no broker and call
 * every tool it lists. Until 2026-10-19 vault_pay and vault_sign answered "Unknown tool" there,
 * because the demo cases were written when there were three tools. This lists the tools and calls
 * each one, so a sixth tool without a demo answer fails here.
 */
import { describe, it, expect } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const ARGS: Record<string, Record<string, unknown>> = {
  vault_entries_list: {},
  vault_call: { entry_id: 'demo-0001', purpose: 'demo', request: { origin: { scheme: 'https', host: 'api.example.com', port: 443 }, method: 'GET', path: '/' } },
  vault_ssh_exec: { entry_id: 'demo-0002', destination: 'demo@host', purpose: 'demo', remote_argv: ['true'] },
  vault_pay: { entry_id: 'demo-0003', payment_required: 'e30=', purpose: 'demo' },
  vault_sign: { entry_id: 'demo-0004', data: 'hello', purpose: 'demo' },
};

describe('demo mode', () => {
  it('answers every listed tool with a labelled demo result', async () => {
    process.env.WUNDERVAULT_MOCK = '1';
    const { createServer } = await import('../src/server.js');
    const server = createServer();
    const [serverSide, clientSide] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'mock-test', version: '0' });
    await Promise.all([server.connect(serverSide), client.connect(clientSide)]);

    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(Object.keys(ARGS).sort());
    for (const t of tools) {
      const r = await client.callTool({ name: t.name, arguments: ARGS[t.name] });
      const text = (r.content as Array<{ text: string }>)[0].text;
      expect(r.isError, `${t.name}: ${text}`).toBeFalsy();
      expect(text).toContain('[DEMO MODE');
    }
    await client.close();
  });
});
