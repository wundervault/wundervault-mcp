/**
 * The words a copy that stands down uses (2.0.1, B3). On cutover day the owner switched Claude
 * Code to 2.0, the app's old 1.7.2 child kept the agent's place, and the 2.0.0 message ("already
 * checked out by another MCP instance … maps to the same address") sent them hunting for a PID.
 */
import { describe, it, expect } from 'vitest';
import { heldNoticeText, type Holder } from '../src/lock.js';

// Noon UTC: October 20 in every time zone from UTC-11 to UTC+11, wherever the suite runs (round 2, F2).
const older: Holder = { pid: 579028, since: '2026-10-20T12:00:00.000Z', agent: 'Claude 0512', source: 'holder', shares: false };

describe('the stand-down message', () => {
  it('names the agent and the process, and says to quit and reopen the app first', () => {
    const t = heldNoticeText('Claude 0512', older);
    expect(t).toContain('"Claude 0512"');
    expect(t).toContain('process 579028');
    expect(t).toContain('an older copy of Wundervault for this agent is still running');
    expect(t).toMatch(/quit and reopen your agent app/);
    expect(t).toContain('/mcp');
    expect(t).toMatch(/running since Oct 20, \d{1,2}:\d\d\s[AP]M/);
  });

  it('drops the jargon of 2.0.0', () => {
    for (const h of [older, { ...older, agent: null, since: null, pid: null, source: 'lock-file' as const }]) {
      const t = heldNoticeText('Claude 0512', h);
      expect(t).not.toMatch(/checked out|MCP instance|maps to the same address|credential/);
    }
  });

  it('a holder with no banner (an old lock file) still reads as an older copy', () => {
    const t = heldNoticeText('Byte', { pid: 1508, since: null, agent: null, source: 'lock-file', shares: false });
    expect(t).toContain('an older copy of Wundervault for this agent is still running (process 1508)');
  });

  it('a different agent on the same place says rename one, not quit the app', () => {
    const t = heldNoticeText('Byte', { ...older, agent: 'Byte?' });
    expect(t).toContain('another agent, "Byte?", already holds the same place');
    expect(t).toContain('WUNDERVAULT_AGENT_NAME');
    expect(t).not.toMatch(/quit and reopen/);
  });

  it('a current copy under another user account is not called an older copy (round 1, B3)', () => {
    const t = heldNoticeText('Byte', { ...older, agent: 'Byte', otherAccount: true });
    expect(t).toContain('another user account on this computer runs an agent with the same name');
    expect(t).not.toMatch(/older copy|quit and reopen/);
  });
});
