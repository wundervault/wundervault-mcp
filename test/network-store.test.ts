/**
 * Acceptance checks for the local network store (PLAN part A).
 *
 * Every test uses a temp store path, because the real one is the developer's own
 * ~/.wundervault and a test must never touch it.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, statSync, writeFileSync, readFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  load, save, recordDestination, destinationsFor,
  newDestinationNotice, defaultStorePath, recordingEnabled,
} from '../src/network-store.js';

let dir: string;
let store: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), 'wv-net-'));
  store = path.join(dir, 'network.json');
});
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('first-sighting detection', () => {
  it('reports a destination as new exactly once', () => {
    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(true);
    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
  });

  it('separates entries, so one secret does not vouch for another', () => {
    recordDestination('e1', 'https://api.cloudflare.com:443', store);
    expect(recordDestination('e2', 'https://api.cloudflare.com:443', store).isNew).toBe(true);
  });

  it('separates origins', () => {
    recordDestination('e1', 'https://api.cloudflare.com:443', store);
    expect(recordDestination('e1', 'https://api.openai.com:443', store).isNew).toBe(true);
  });

  it('treats a port change as a different destination', () => {
    recordDestination('e1', 'https://h.example:443', store);
    expect(recordDestination('e1', 'https://h.example:8443', store).isNew).toBe(true);
  });

  it('is case-insensitive on the origin', () => {
    recordDestination('e1', 'https://API.Cloudflare.com:443', store);
    expect(recordDestination('e1', 'https://api.cloudflare.com:443', store).isNew).toBe(false);
  });

  it('counts repeat use', () => {
    for (let i = 0; i < 4; i += 1) recordDestination('e1', 'https://h.example:443', store);
    expect(destinationsFor('e1', store)[0].count).toBe(4);
  });
});

describe('durability', () => {
  it('writes 0600 and survives a reload', () => {
    recordDestination('e1', 'https://h.example:443', store);
    expect(statSync(store).mode & 0o777).toBe(0o600);
    expect(load(store).seen).toHaveLength(1);
  });

  it('leaves no temp file behind', () => {
    recordDestination('e1', 'https://h.example:443', store);
    const leftovers = require('node:fs').readdirSync(dir).filter((f: string) => f.includes('.tmp-'));
    expect(leftovers).toEqual([]);
  });

  it('starts clean on a corrupt store rather than breaking every call', () => {
    writeFileSync(store, '{{{not json');
    expect(load(store).seen).toEqual([]);
    // and can still be written afterwards
    expect(recordDestination('e1', 'https://h.example:443', store).isNew).toBe(true);
  });

  it('ignores a store written by a future version', () => {
    writeFileSync(store, JSON.stringify({ version: 99, seen: [{ entryId: 'x' }] }));
    expect(load(store).seen).toEqual([]);
  });
});

describe('approvals are NOT stored here', () => {
  it('exposes no way to record an approval locally', async () => {
    // A control in an agent-writable file is not a control: the agent could approve its
    // own internal destination and walk through the SSRF filter it is constrained by.
    const mod = await import('../src/network-store.js');
    expect('approvePrivateOrigin' in mod).toBe(false);
    expect('approvedPrivateOrigins' in mod).toBe(false);
    expect('revokePrivateOrigin' in mod).toBe(false);
  });

  it('keeps no approval field in the persisted shape', () => {
    recordDestination('e1', 'https://h.example:443', store);
    const raw = JSON.parse(readFileSync(store, 'utf8'));
    expect(Object.keys(raw).sort()).toEqual(['seen', 'version']);
  });
});

describe('the notice, and where it goes', () => {
  const n = () => newDestinationNotice('Cloudflare', 'https://api.cloudflare.com:443', 'GET', '/client/v4/zones');

  it('names the secret and the destination on both channels', () => {
    const notice = n();
    expect(notice.stderrLine).toContain('Cloudflare');
    expect(notice.stderrLine).toContain('api.cloudflare.com');
    expect(notice.toolNote).toContain('api.cloudflare.com');
  });

  it('says the destination stayed local, which is now true, and which channels carried it', () => {
    // This assertion has been through both states, and the history is the point.
    //
    // It originally claimed "not sent to Wundervault" while checkOperation was sending
    // origin, method and path on every call — a test defending a false security claim,
    // which is worse than no test because it defends the claim against correction. It was
    // then rewritten to assert the truth: terminal-only, no claim about locality.
    //
    // The code has since been changed to match what the notice always wanted to say. The
    // destination genuinely does not leave the machine at tier 1 now; one boolean does.
    // So the claim comes back — earned this time rather than asserted.
    expect(n().toolNote).toMatch(/not sent to Wundervault/i);
    expect(n().toolNote).toMatch(/Terminal only/i);
    expect(n().toolNote).toMatch(/nobody is emailed/i);
  });

  it('does not put the destination in the sentence about email', () => {
    // The mail is a doorbell. If the notice implied otherwise, an owner would reasonably
    // conclude their inbox holds a record of where their keys go, and act on that.
    const on = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '1', true, true);
    expect(on.toolNote).toMatch(/does not say where/i);
  });

  it('describes itself as a notice, not a block', () => {
    expect(n().toolNote).toMatch(/notice rather than a block/i);
  });

  it('tells the reader what to do if it was unexpected', () => {
    expect(n().toolNote).toMatch(/revoke/i);
    expect(n().toolNote).toMatch(/Tier 2/i);
  });

  it('carries a timestamp on the stderr line, which is the channel of record', () => {
    // stderr never passes through the model, so this is the line that cannot be suppressed.
    expect(n().stderrLine).toMatch(/\d{4}-\d{2}-\d{2}T/);
    expect(n().stderrLine.endsWith('\n')).toBe(true);
  });
});

describe('store location', () => {
  it('honours an explicit override', () => {
    const prev = process.env.WUNDERVAULT_NETWORK_STORE;
    process.env.WUNDERVAULT_NETWORK_STORE = '/tmp/elsewhere.json';
    try { expect(defaultStorePath()).toBe('/tmp/elsewhere.json'); }
    finally {
      if (prev === undefined) delete process.env.WUNDERVAULT_NETWORK_STORE;
      else process.env.WUNDERVAULT_NETWORK_STORE = prev;
    }
  });
});

describe('round 1 fixes', () => {
  it('records nothing and notices nothing when recording is off', () => {
    // The metadata IS the control, so opting out of the record opts out of the notice.
    // A notice without a record would fire on every single call.
    const prev = process.env.WUNDERVAULT_RECORD_DESTINATIONS;
    process.env.WUNDERVAULT_RECORD_DESTINATIONS = '0';
    try {
      const r = recordDestination('e1', 'https://h.example:443', store);
      expect(r.recorded).toBe(false);
      expect(r.isNew).toBe(false);
      expect(existsSync(store)).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.WUNDERVAULT_RECORD_DESTINATIONS;
      else process.env.WUNDERVAULT_RECORD_DESTINATIONS = prev;
    }
  });

  it.each(['0', 'false', 'off', 'no', 'OFF'])('treats %s as off', (v) => {
    const prev = process.env.WUNDERVAULT_RECORD_DESTINATIONS;
    process.env.WUNDERVAULT_RECORD_DESTINATIONS = v;
    try { expect(recordingEnabled()).toBe(false); }
    finally {
      if (prev === undefined) delete process.env.WUNDERVAULT_RECORD_DESTINATIONS;
      else process.env.WUNDERVAULT_RECORD_DESTINATIONS = prev;
    }
  });

  it('records by default', () => {
    expect(recordingEnabled()).toBe(true);
  });

  it('does not tell a Tier 2 caller the destination stayed local', () => {
    // Tier 2 approval is exactly where the destination WAS disclosed, so the Tier 1
    // wording would be false — and false reassurance is worse than none.
    const t2 = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '2');
    expect(t2.toolNote).not.toMatch(/not sent to Wundervault/i);
    expect(t2.toolNote).toMatch(/approved this operation/i);
    expect(t2.stderrLine).toContain('tier=2');
  });

  it('tells a Tier 1 caller it is a notice, and whether anyone was emailed', () => {
    const off = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '1');
    expect(off.toolNote).toMatch(/notice rather than a block/i);
    expect(off.toolNote).toMatch(/Terminal only/i);

    const on = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '1', true, true);
    expect(on.toolNote).toMatch(/Emailed to you/i);
    expect(on.toolNote).not.toMatch(/Terminal only/i);
  });

  it('never claims mail went out when it did not', () => {
    // The asymmetry that matters: believing you are covered at 3am and not being is
    // strictly worse than knowing you are not covered.
    const off = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '1', true, false);
    expect(off.toolNote).not.toMatch(/[Ee]mailed to you/);
    expect(off.stderrLine).toContain('api.cf.com');
  });

  it('does not lose a record when two writers interleave', () => {
    // Seven agents run under one uid on this machine, so concurrent writers are the
    // normal case. Last-write-wins would silently drop a destination, which then reports
    // as new again.
    const a = load(store);
    a.seen.push({ entryId: 'eA', origin: 'https://a.example:443', firstSeen: 'x', lastSeen: 'x', count: 1 });
    save(a, store);
    recordDestination('eB', 'https://b.example:443', store);
    const after = load(store);
    expect(after.seen.map((s) => s.entryId).sort()).toEqual(['eA', 'eB']);
  });

  it('leaves no lock file behind', () => {
    recordDestination('e1', 'https://h.example:443', store);
    expect(existsSync(`${store}.lock`)).toBe(false);
  });
});

describe('round 2 fixes', () => {
  it('keeps a signed operation\'s destination out of the tool result', () => {
    // The tool result is read by the model, and for a hosted model that reaches the
    // model provider. With a signed operation the agent supplied only an operation id —
    // the origin and path came from the definition, so putting them in the note would
    // disclose a destination the model never had.
    const n = newDestinationNotice('Payroll', 'https://payroll.internal:8443', 'GET', '/employees', '1', false);
    expect(n.toolNote).not.toContain('payroll.internal');
    expect(n.toolNote).not.toContain('/employees');
    // stderr still carries it: that channel never passes through the model.
    expect(n.stderrLine).toContain('payroll.internal');
    expect(n.stderrLine).toContain('/employees');
  });

  it('includes the destination when the caller chose it', () => {
    // Already in the agent's context, so repeating it discloses nothing new.
    const n = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/zones', '1', true);
    expect(n.toolNote).toContain('api.cf.com');
  });

  it('warns where the note travels', () => {
    // The tool result reaches the model provider. That warning survives; the neighbouring
    // "not sent to Wundervault" claim did not, because it was not true.
    const n = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/zones', '1', true);
    expect(n.toolNote).toMatch(/reaches whoever runs your model/);
  });

  it('drops malformed rows instead of throwing on the next read', () => {
    // {"seen":[null]} is valid JSON and a valid shape, and used to throw when a find
    // callback touched .entryId.
    writeFileSync(store, JSON.stringify({ version: 1, seen: [null, 'x', { entryId: 'e', origin: 'o', firstSeen: 'a', lastSeen: 'a', count: 1 }] }));
    expect(load(store).seen).toHaveLength(1);
    expect(() => recordDestination('e2', 'https://h.example:443', store)).not.toThrow();
  });

  it('does not spin when the store directory does not exist yet', () => {
    // openSync on the lock returned ENOENT, which the loop could not tell from
    // contention, so the first call on a fresh install burned the whole timeout.
    const fresh = path.join(dir, 'nested', 'deeper', 'network.json');
    const started = Date.now();
    expect(recordDestination('e1', 'https://h.example:443', fresh).isNew).toBe(true);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

describe('the purpose lives here, not on the server', () => {
  const CF = 'https://api.cloudflare.com:443';

  it('keeps the agent-written purpose beside the destination', () => {
    // It used to go into the hosted audit log, where it was a WORSE disclosure than the
    // origin: an origin is mostly externally discoverable and only dangerous in
    // aggregate, whereas a purpose is intent — one row naming an incident or a customer
    // is enough to hurt.
    recordDestination('e1', CF, store, 'rotate the prod key after the incident');
    const [rec] = destinationsFor('e1', store);
    expect(rec.purposes?.[0]).toMatch(/rotate the prod key after the incident/);
  });

  it('keeps enough history to reconstruct what an agent did', () => {
    // The point of keeping it at all. Dropping both the destination and the intention
    // leaves the owner's own forensic answer at "this key was used four hundred times",
    // which protects them from us at the cost of protecting them from their agent.
    for (let i = 0; i < 5; i++) recordDestination('e1', CF, store, `call ${i}`);
    const [rec] = destinationsFor('e1', store);
    expect(rec.count).toBe(5);
    expect(rec.purposes).toHaveLength(5);
    expect(rec.purposes?.at(-1)).toMatch(/call 4/);
  });

  it('is bounded, and evicts the oldest', () => {
    // A long-lived install must not grow this file without limit. An owner reconstructing
    // an incident reads backwards from the most recent call, so the newest end is the one
    // worth keeping.
    for (let i = 0; i < 60; i++) recordDestination('e1', CF, store, `call ${i}`);
    const [rec] = destinationsFor('e1', store);
    expect(rec.purposes!.length).toBeLessThanOrEqual(20);
    expect(rec.purposes?.at(-1)).toMatch(/call 59/);
    expect(rec.purposes?.some(p => p.includes('call 0 '))).toBe(false);
  });

  it('truncates a very long purpose rather than storing it whole', () => {
    recordDestination('e1', CF, store, 'x'.repeat(5000));
    const [rec] = destinationsFor('e1', store);
    expect(rec.purposes![0].length).toBeLessThan(400);
  });

  it('records the destination even when no purpose was given', () => {
    expect(recordDestination('e1', CF, store).isNew).toBe(true);
    const [rec] = destinationsFor('e1', store);
    expect(rec.origin).toBe(CF);
    expect(rec.purposes).toBeUndefined();
  });

  it('survives a reload, because it is the owners only copy', () => {
    recordDestination('e1', CF, store, 'deploy the site');
    const reloaded = load(store).seen.find(s => s.entryId === 'e1');
    expect(reloaded?.purposes?.[0]).toMatch(/deploy the site/);
  });
});
