import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * The store key's derived fallback, and the identity it derives from.
 *
 * The bug this covers: `legacyDerivedKey` read `/etc/machine-id`, swallowed the failure,
 * and carried on with the literal string `unknown`. On macOS that file does not exist, so
 * the derived store key on every Mac was HKDF over sha256("unknown:501") — and 501 is the
 * uid macOS gives the first account it creates. The fallback was documented as
 * "recomputable by anyone who can read the directory". On a Mac it was computable by
 * anyone who could read this repository.
 */

let agent: typeof import('../src/agent.js');
let root: string;
const saved: Record<string, string | undefined> = {};

function setEnv(k: string, v: string | undefined) {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
}

beforeEach(async () => {
  root = mkdtempSync(path.join(os.tmpdir(), 'wv-ident-'));
  setEnv('WUNDERVAULT_AGENT_NO_AUTOSTART', '1');
  setEnv('WUNDERVAULT_SYSTEM_ROOT', root);
  setEnv('WUNDERVAULT_MACHINE_ID', undefined);
  agent = await import('../src/agent.js');
});

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const k of Object.keys(saved)) delete saved[k];
  rmSync(root, { recursive: true, force: true });
});

describe('parsing the hardware UUID out of ioreg', () => {
  // Real output, trimmed. Kept verbatim so a change in ioreg's format shows up here
  // rather than as a silently shared key on every Mac.
  const REAL = `+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000253, registered>
    {
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
      "IOPlatformUUID" = "4C4C4544-0051-4610-8051-B4C04F4D3332"
      "IOPlatformSerialNumber" = "C02XY0ABJGH5"
      "platform-name" = <"t8103">
    }`;

  it('finds the UUID', () => {
    expect(agent.parseIOPlatformUUID(REAL)).toBe('4C4C4544-0051-4610-8051-B4C04F4D3332');
  });

  it('returns null rather than a surprise when the format moves', () => {
    // Failing to match must mean "no identity", which is loud, rather than falling through
    // to a constant, which is silent and shared.
    expect(agent.parseIOPlatformUUID('nothing here')).toBeNull();
    expect(agent.parseIOPlatformUUID('"IOPlatformUUID" = ""')).toBeNull();
    expect(agent.parseIOPlatformUUID('"IOPlatformUUID" = "not-a-uuid"')).toBeNull();
    expect(agent.parseIOPlatformUUID('"IOPlatformSerialNumber" = "C02XY0ABJGH5"')).toBeNull();
  });
});

describe('the derived key is per-machine', () => {
  it('differs for two different machine identities', () => {
    // The property the old derivation was supposed to have and did not have on macOS.
    const a = agent.derivedKeyFor('4C4C4544-0051-4610-8051-B4C04F4D3332');
    const b = agent.derivedKeyFor('11111111-2222-3333-4444-555555555555');
    expect(a.length).toBe(32);
    expect(a.equals(b)).toBe(false);
  });

  it('is stable for one identity', () => {
    const a = agent.derivedKeyFor('4C4C4544-0051-4610-8051-B4C04F4D3332');
    const b = agent.derivedKeyFor('4C4C4544-0051-4610-8051-B4C04F4D3332');
    expect(a.equals(b)).toBe(true);
  });

  it('is not the key the old code would have used on a Mac', () => {
    // If these ever match, the identity is not reaching the derivation and every Mac is
    // back on one key.
    const real = agent.derivedKeyFor('4C4C4544-0051-4610-8051-B4C04F4D3332');
    const shared = agent.legacyDerivedKey();
    expect(real.equals(shared)).toBe(false);
  });
});

describe('machineIdentity', () => {
  it('honours an explicit per-machine value', () => {
    setEnv('WUNDERVAULT_MACHINE_ID', 'a-specific-machine');
    expect(agent.machineIdentity()).toBe('a-specific-machine');
  });

  it('ignores a blank override rather than deriving from empty', () => {
    setEnv('WUNDERVAULT_MACHINE_ID', '   ');
    expect(agent.machineIdentity()).not.toBe('   ');
  });

  it('never returns the string the old code fell back to', () => {
    expect(agent.machineIdentity()).not.toBe('unknown');
  });
});

describe('what happens when the machine has no identity at all', () => {
  // Unreachable on any machine with /etc/machine-id or ioreg, which is all of them — so
  // the decision is a pure function and is asserted directly rather than by contriving a
  // machine that cannot identify itself.

  it('REFUSES to start when there is no store to lose', () => {
    // Nothing is stranded by stopping, and starting would write a NEW store under a key
    // that is identical on every machine with this uid. Refuse.
    expect(agent.keyModeFor(false, null, false, false)).toBe('refuse');
  });

  it('serves an EXISTING store rather than stranding it', () => {
    // The store is already encrypted under that key. Declining to open it protects
    // nothing and loses everything — the same failure the unit file refuses elsewhere,
    // where a cleared TPM must not mean a broker that never starts. Serve it, say so
    // loudly, and refuse enrolment so no new secret joins it.
    expect(agent.keyModeFor(false, null, false, true)).toBe('derived-shared');
  });

  it('prefers a real identity over both', () => {
    expect(agent.keyModeFor(false, null, true, false)).toBe('derived');
    expect(agent.keyModeFor(false, null, true, true)).toBe('derived');
  });

  it('maps each sealing mechanism to its own mode, never to a neighbour', () => {
    // Three mechanisms, three different promises. Collapsing any two is how a machine
    // ends up described as sealed when it is not.
    expect(agent.keyModeFor(true, 'tpm', true, true)).toBe('sealed-tpm');
    expect(agent.keyModeFor(true, 'host', true, true)).toBe('sealed-host');
    expect(agent.keyModeFor(true, 'local-file', true, true)).toBe('local-file');
    // A sealed key with no declared kind is the HOST tier, never the TPM one: the weaker
    // claim is the safe default.
    expect(agent.keyModeFor(true, null, true, true)).toBe('sealed-host');
  });
});
