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

  it('says plainly that the destination did not go to the server', () => {
    // The whole point of the local store; if the notice does not say so, nobody knows.
    expect(n().toolNote).toMatch(/not sent to the server/i);
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
    expect(t2.toolNote).not.toMatch(/not sent to the server/i);
    expect(t2.toolNote).toMatch(/approved this operation/i);
    expect(t2.stderrLine).toContain('tier=2');
  });

  it('still tells a Tier 1 caller the destination stayed local', () => {
    const t1 = newDestinationNotice('CF', 'https://api.cf.com:443', 'GET', '/x', '1');
    expect(t1.toolNote).toMatch(/not sent to the server/i);
    expect(t1.toolNote).toMatch(/notice rather than a block/i);
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
