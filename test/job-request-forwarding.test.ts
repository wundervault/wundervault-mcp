/**
 * 2.7.0 shipped with vault_job_request's `file` dropped on the way to the broker: the MCP server and
 * the broker's socket handler each copy the tool's fields BY NAME, and neither copied the new one,
 * so every file job became a text job. Every field the tool accepts must be passed on by both.
 */
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const src = (f: string) => fs.readFileSync(path.join(__dirname, '..', 'src', f), 'utf8');

function toolFields(server: string): string[] {
  const at = server.indexOf("name: 'vault_job_request'");
  const props = server.indexOf('properties: {', at);
  const end = server.indexOf("required: ['name', 'entry_id', 'destination', 'argv', 'schedule', 'why']", props);
  expect(at > 0 && props > at && end > props).toBe(true);
  const block = server.slice(props, end);
  // Top-level properties are the keys indented 12 spaces.
  return [...block.matchAll(/^ {12}([a-z_]+): \{/gm)].map(m => m[1]!);
}

describe('vault_job_request passes every field it accepts to the broker', () => {
  const server = src('server.ts');
  const fields = toolFields(server);

  it('the tool still takes the fields we expect (guards the parser)', () => {
    expect(fields).toEqual(expect.arrayContaining(['name', 'entry_id', 'destination', 'argv', 'schedule',
      'timeout_s', 'grace_minutes', 'why', 'file']));
  });

  it('the MCP server forwards each of them', () => {
    const at = server.indexOf("broker.send('job_request', {");
    const block = server.slice(at, server.indexOf('});', at));
    for (const f of fields) expect(block, f).toMatch(new RegExp(`\\b${f}\\b`));
  });

  it("the broker's socket handler forwards each of them", () => {
    const agent = src('agent.ts');
    const at = agent.indexOf("case 'job_request': {");
    const block = agent.slice(at, agent.indexOf('}) as unknown as Record<string, unknown>;', at));
    for (const f of fields) expect(block, f).toMatch(new RegExp(`\\b${f}\\b`));
  });
});
