import { describe, it, expect } from 'vitest';
import { nodeFloorProblem, NODE_FLOORS } from '../src/node-floor.js';

describe('the Node.js the broker runs on (October 21, 2026 security release)', () => {
  const ok = ['v22.23.4', 'v22.24.0', 'v22.30.1', 'v24.22.1', 'v24.23.0', 'v26.12.1', 'v26.13.0', 'v27.0.0', 'v30.1.2',
              'v22.23.5-rc.1', 'v24.23.0-nightly20261101abc', 'v27.0.0-pre'];
  // A pre-release OF a floor version comes before that release (review round 1, F3).
  const refused = ['v22.23.3', 'v22.9.0', 'v23.11.0', 'v24.22.0', 'v24.3.9', 'v25.9.9', 'v26.12.0', 'v20.19.5', 'v18.20.0', 'v21.7.3', '',
                   'v22.23.4-rc.1', 'v24.22.1-nightly20261020abc', 'v26.12.1-pre'];
  for (const v of ok) it(`accepts ${v}`, () => expect(nodeFloorProblem(v)).toBeNull());
  for (const v of refused) {
    it(`refuses ${v || '(none)'}`, () => {
      const why = nodeFloorProblem(v);
      expect(why).toMatch(/October 21, 2026/);
      expect(why).toMatch(/nodejs\.org/);
    });
  }
  it('names the version to install for a line that has a fix', () => {
    expect(nodeFloorProblem('v24.22.0')).toContain('24.22.1');
    expect(nodeFloorProblem('v22.23.3')).toContain('22.23.4');
  });
  it('keeps step with the installers', async () => {
    const fs = await import('node:fs');
    for (const f of ['packaging/install-daemon.sh', 'packaging/install-daemon-macos.sh', 'packaging/install-daemon-windows.ps1']) {
      const src = fs.readFileSync(f, 'utf8');
      for (const floor of Object.values(NODE_FLOORS)) expect(src, f).toContain(floor);
    }
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    for (const floor of Object.values(NODE_FLOORS)) expect(pkg.engines?.node).toContain(floor);
  });
});
