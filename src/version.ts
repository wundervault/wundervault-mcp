import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };
export const VERSION: string = pkg.version;

/** Lenient semver: garbage/empty -> [0,0,0]. */
export function parseSemver(v: string | undefined | null): [number, number, number] {
  if (!v) return [0, 0, 0];
  const p = String(v).trim().replace(/^v/, '').split('-')[0].split('.');
  const n = (i: number) => { const x = parseInt(p[i] ?? '0', 10); return Number.isFinite(x) ? x : 0; };
  return [n(0), n(1), n(2)];
}
export function semverLt(a: string, b: string): boolean {
  const x = parseSemver(a), y = parseSemver(b);
  for (let i = 0; i < 3; i++) { if (x[i] !== y[i]) return x[i] < y[i]; }
  return false;
}