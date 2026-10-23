import { describe, it, expect } from 'vitest';
import { pairInstructions, pairedNextSteps } from '../src/pair.js';

// SPEC-1.0-polish F4: --pair names the place in the 1.0 vault, not the 1.x settings page.
describe('--pair text', () => {
  it('names Your computers and Pair a computer, and never the old Settings > Agents path', () => {
    const t = pairInstructions().join('\n');
    expect(t).toContain('Pair a computer');
    expect(t).toContain('Your computers');
    expect(t).not.toMatch(/Settings > Agents|Pair a broker|dashboard/);
  });
  it('after pairing, points at Add an agent / Repair, not the claim-code-by-hand step', () => {
    const t = pairedNextSteps().join('\n');
    expect(t).toMatch(/Add an\s+agent/);
    expect(t).not.toMatch(/CLAIM CODE|dashboard/);
  });
});
