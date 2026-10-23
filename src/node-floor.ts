/**
 * The oldest Node.js the broker runs on, per release line.
 *
 * WHY IT IS ENFORCED, NOT ADVISED. Node's October 21, 2026 security release fixed an
 * out-of-bounds write in its bundled Brotli decoder (CVE-2026-111497) and two TLS hostname
 * checks that could be bypassed (CVE-2026-105483, CVE-2026-106069). The broker decompresses
 * Brotli replies from services an AGENT chooses (http-broker.ts), and checks certificates for
 * hosts an agent names. On an unpatched Node an agent could point the broker at a server of
 * its own and corrupt the memory of the one process that holds the keys. That is the attack
 * the broker exists to stop, so it does not start on such a Node.
 *
 * Lines with no fix (23.x, 25.x, and anything below 22) are refused outright. A line newer
 * than the newest listed here shipped after the fix and is accepted. A pre-release or nightly
 * OF a floor version (22.23.4-rc.1, 22.23.4-nightly…) comes before that release and may predate
 * the fix, so it is refused; one of a later version is accepted (review round 1, F3).
 */
import { parseSemver } from './version.js';

/** The first patched release of each supported line. Kept in step with the installers. */
export const NODE_FLOORS: Record<number, string> = { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' };
const NEWEST_LINE = 26;

export const NODE_REQUIREMENT = 'Node.js 22.23.4, 24.22.1 or 26.12.1 or newer (the October 21, 2026 security release)';

/** Null when this Node is new enough; otherwise why not, in words a person can act on. */
export function nodeFloorProblem(version: string = process.version): string | null {
  const [major, minor, patch] = parseSemver(version);
  const prerelease = /^v?\d+\.\d+\.\d+-/.test(String(version).trim());
  if (major > NEWEST_LINE) return null;
  const floor = NODE_FLOORS[major];
  if (floor) {
    const [, fm, fp] = parseSemver(floor);
    if (minor > fm || (minor === fm && patch > fp) || (minor === fm && patch === fp && !prerelease)) return null;
    return `This computer has Node.js ${version.replace(/^v/, '')}, which lacks the October 21, 2026 ` +
           `security fix. Install Node.js ${floor} or newer from nodejs.org, then start the broker again.`;
  }
  return `This computer has Node.js ${version.replace(/^v/, '') || '(unknown)'}, which lacks the October 21, 2026 ` +
         `security fix (no update for it has one). Install ${NODE_REQUIREMENT} from nodejs.org, then start the broker again.`;
}
