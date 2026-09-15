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
  approvePrivateOrigin, approvedPrivateOrigins, revokePrivateOrigin,
  newDestinationNotice, defaultStorePath,
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

describe('locally approved private origins', () => {
  it('accepts an exact scheme://host:port', () => {
    const r = approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    expect(r.ok).toBe(true);
    expect(approvedPrivateOrigins('e1', store)).toEqual(['https://10.0.0.5:9000']);
  });

  it('refuses a range or wildcard', () => {
    // A range is not something an owner can realistically evaluate.
    expect(approvePrivateOrigin('e1', 'https://10.0.0.0/24', store).ok).toBe(false);
    expect(approvePrivateOrigin('e1', 'https://*.local:9000', store).ok).toBe(false);
  });

  it('refuses an origin with no port', () => {
    expect(approvePrivateOrigin('e1', 'https://10.0.0.5', store).ok).toBe(false);
  });

  it('refuses cloud metadata endpoints outright', () => {
    for (const h of ['169.254.169.254', 'metadata.google.internal', '100.100.100.200']) {
      const r = approvePrivateOrigin('e1', `https://${h}:80`, store);
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/metadata/i);
    }
  });

  it('does not leak approvals between entries', () => {
    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    expect(approvedPrivateOrigins('e2', store)).toEqual([]);
  });

  it('caps how many an entry may approve', () => {
    for (let i = 1; i <= 10; i += 1) approvePrivateOrigin('e1', `https://10.0.0.${i}:9000`, store);
    expect(approvePrivateOrigin('e1', 'https://10.0.0.99:9000', store).ok).toBe(false);
  });

  it('is idempotent', () => {
    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    expect(approvedPrivateOrigins('e1', store)).toHaveLength(1);
  });

  it('revokes one without disturbing the others', () => {
    approvePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    approvePrivateOrigin('e1', 'https://10.0.0.6:9000', store);
    revokePrivateOrigin('e1', 'https://10.0.0.5:9000', store);
    expect(approvedPrivateOrigins('e1', store)).toEqual(['https://10.0.0.6:9000']);
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
