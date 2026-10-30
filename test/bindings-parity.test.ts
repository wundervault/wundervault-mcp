/**
 * The vault page checks a setup before sealing it (app/static/js/vault-setup.js); the broker
 * checks it again on use. Both run this same file of cases, so neither can accept what the
 * other refuses.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { validateBindingV2, type Delivery, type Shape } from '../src/parts.js';

interface Case { name: string; shape: Shape; delivery: Delivery; binding: unknown; ok: boolean; field?: string }
const cases = JSON.parse(readFileSync(new URL('./vectors/bindings-v2.json', import.meta.url), 'utf8')) as Case[];

describe('binding cases shared with the vault page', () => {
  it('has cases', () => { expect(cases.length).toBeGreaterThanOrEqual(40); });
  for (const c of cases) {
    it(c.name, () => {
      const result = validateBindingV2(c.binding, c.shape, c.delivery);
      expect(result.ok).toBe(c.ok);
    });
  }
});
