/**
 * The destination viewer, rendered and driven — not just inspected as a string.
 *
 * This file exists because of the mistake this project has already made twice: a feature
 * that looked right in source and did nothing on contact with a real system. A viewer is
 * exactly that shape. Every assertion here is made against a parsed DOM with the page's
 * own script executed, so "it renders the rows" means the rows are in the document, and
 * "search filters" means the handler ran.
 *
 * The other half of the job is that this page holds a behavioural profile and displays
 * agent-written text. So it is also tested as a hostile document: the injection attempt
 * has to arrive as characters on screen rather than as markup, and the page must carry a
 * policy that makes exfiltration impossible rather than merely absent.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { JSDOM } from 'jsdom';
import { mkdtempSync, rmSync, writeFileSync, statSync, readFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { renderViewer, writeViewer } from '../src/log-viewer.js';
import type { NetworkShape } from '../src/network-store.js';

const SHAPE: NetworkShape = {
  version: 1,
  seen: [
    { entryId: 'e-oracle', origin: 'https://api.cloudflare.com:443',
      firstSeen: '2026-09-01T10:00:00.000Z', lastSeen: '2026-09-15T03:02:00.000Z', count: 138,
      purposes: ['2026-09-01T10:00:00.000Z purge the cache',
                 '2026-09-15T03:02:00.000Z rotate the prod key after the incident'] },
    { entryId: 'e-anthropic', origin: 'https://api.anthropic.com:443',
      firstSeen: '2026-09-10T08:00:00.000Z', lastSeen: '2026-09-14T22:00:00.000Z', count: 12,
      purposes: ['2026-09-14T22:00:00.000Z summarise the weekly numbers'] },
    { entryId: 'e-plain', origin: 'https://plain.example:443',
      firstSeen: '2026-09-11T08:00:00.000Z', lastSeen: '2026-09-11T08:00:00.000Z', count: 1 },
  ],
};

let dir: string;
beforeEach(() => { dir = mkdtempSync(path.join(os.tmpdir(), 'wv-view-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

/** Parse and RUN the page, the way a browser would. */
function open(shape: NetworkShape = SHAPE) {
  const dom = new JSDOM(renderViewer(shape, '/home/someone/.wundervault/network.json'), {
    runScripts: 'dangerously',
  });
  return dom.window.document;
}

describe('the page actually renders', () => {
  it('puts every destination in the document', () => {
    const doc = open();
    const rows = doc.querySelectorAll('#rows tr');
    expect(rows).toHaveLength(3);
    expect(doc.body.textContent).toContain('api.cloudflare.com');
    expect(doc.body.textContent).toContain('api.anthropic.com');
  });

  it('shows the reasons the agent gave', () => {
    // The half that was nearly lost: without it the owner can see that a key was used and
    // not what for.
    expect(open().body.textContent).toContain('rotate the prod key after the incident');
  });

  it('counts destinations and calls', () => {
    expect(open().getElementById('count')!.textContent).toMatch(/3 of 3 destinations.*151 calls/);
  });

  it('handles a record with no purposes without breaking the row', () => {
    const doc = open();
    expect(doc.body.textContent).toContain('plain.example');
    expect(doc.querySelectorAll('#rows tr')).toHaveLength(3);
  });

  it('renders an empty store as a page rather than a crash', () => {
    const doc = open({ version: 1, seen: [] });
    expect(doc.querySelectorAll('#rows tr')).toHaveLength(0);
    expect(doc.getElementById('empty')!.hasAttribute('hidden')).toBe(false);
  });
});

describe('search', () => {
  function search(doc: Document, q: string) {
    const input = doc.getElementById('q') as HTMLInputElement;
    input.value = q;
    input.dispatchEvent(new (doc.defaultView as any).Event('input'));
    return doc.querySelectorAll('#rows tr');
  }

  it('filters by destination', () => {
    const doc = open();
    expect(search(doc, 'cloudflare')).toHaveLength(1);
  });

  it('filters by the reason, not only the destination', () => {
    // "what was my agent doing when it touched this key" is the question someone actually
    // arrives with, and it is answered by the purpose text.
    const doc = open();
    const rows = search(doc, 'incident');
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain('cloudflare');
  });

  it('filters by entry id', () => {
    expect(search(open(), 'e-anthropic')).toHaveLength(1);
  });

  it('says so when nothing matches, instead of showing an empty table', () => {
    const doc = open();
    expect(search(doc, 'nothing-matches-this')).toHaveLength(0);
    expect(doc.getElementById('empty')!.hasAttribute('hidden')).toBe(false);
  });

  it('highlights the match', () => {
    const doc = open();
    search(doc, 'cloudflare');
    expect(doc.querySelector('#rows mark')?.textContent).toBe('cloudflare');
  });
});

describe('sorting', () => {
  it('sorts a numeric column high-to-low first, then toggles', () => {
    const doc = open();
    const first = () => doc.querySelector('#rows tr')!.textContent!;
    const th = doc.querySelector('th[data-k="count"]') as HTMLElement;
    const click = () => th.dispatchEvent(
      new (doc.defaultView as any).Event('click', { bubbles: true }));

    // Busiest first, because "what has this key been hammering" is the question.
    click();
    expect(first()).toContain('cloudflare');   // 138
    // Same header again reverses rather than re-sorting the same way.
    click();
    expect(first()).toContain('plain.example'); // 1
  });

  it('defaults to most recently used', () => {
    // What someone wants on opening it: what happened last.
    expect(open().querySelector('#rows tr')!.textContent).toContain('cloudflare');
  });
});

describe('it is a viewer, not a payload', () => {
  const HOSTILE: NetworkShape = {
    version: 1,
    seen: [{
      entryId: 'e-x', origin: 'https://x.example:443',
      firstSeen: '2026-09-15T04:00:00.000Z', lastSeen: '2026-09-15T04:00:00.000Z', count: 1,
      purposes: ['2026-09-15T04:00:00.000Z </script><img src=x onerror=PWNED><script>'],
    }],
  };

  it('does not let a purpose close the script block', () => {
    // The purpose is agent-written, and this page is opened by someone who may already
    // suspect that agent. A literal </script> would end the block early and the rest would
    // parse as markup — script injection into the tool you reach for during an incident.
    const html = renderViewer(HOSTILE, '/tmp/x.json');
    const body = html.slice(html.indexOf('const DATA'));
    expect(body.slice(0, body.indexOf('\n'))).not.toContain('</script>');
    expect(html).toContain('\\u003c/script');
  });

  it('shows the injection attempt as text, and injects nothing', () => {
    const doc = open(HOSTILE);
    expect(doc.querySelector('#rows img')).toBeNull();
    expect(doc.body.textContent).toContain('onerror=PWNED');
  });

  it('carries a policy that forbids every network request', () => {
    // Not "does not use the network" — cannot. A page holding a behavioural profile should
    // be structurally incapable of sending one, including after someone edits it.
    const csp = open().querySelector('meta[http-equiv="Content-Security-Policy"]')!
      .getAttribute('content')!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toContain('connect-src');
    expect(csp).not.toContain('img-src');
    expect(csp).toContain("form-action 'none'");
  });

  it('loads nothing from anywhere', () => {
    const doc = open();
    expect(doc.querySelectorAll('script[src]')).toHaveLength(0);
    expect(doc.querySelectorAll('link[rel=stylesheet]')).toHaveLength(0);
    expect(doc.querySelectorAll('img, iframe, video, object, embed')).toHaveLength(0);
  });

  it('has no outbound links', () => {
    const hrefs = [...open().querySelectorAll('a[href]')]
      .map(a => a.getAttribute('href')!)
      .filter(h => /^https?:/.test(h));
    expect(hrefs).toHaveLength(0);
  });
});

describe('the file it writes', () => {
  it('lands beside the store, readable only by its owner', () => {
    // Beside the store rather than in /tmp: the page holds the same profile the store
    // does, and a world-readable temp directory is the wrong home for it.
    const store = path.join(dir, 'network.json');
    writeFileSync(store, JSON.stringify(SHAPE));
    const out = writeViewer(store);
    expect(path.dirname(out)).toBe(dir);
    expect(statSync(out).mode & 0o777).toBe(0o600);
    expect(readFileSync(out, 'utf8')).toContain('api.cloudflare.com');
  });

  it('leaves the store untouched', () => {
    const store = path.join(dir, 'network.json');
    const original = JSON.stringify(SHAPE);
    writeFileSync(store, original);
    writeViewer(store);
    expect(readFileSync(store, 'utf8')).toBe(original);
  });

  it('writes a usable page even when the store does not exist', () => {
    const out = writeViewer(path.join(dir, 'missing.json'));
    const doc = new JSDOM(readFileSync(out, 'utf8'), { runScripts: 'dangerously' }).window.document;
    expect(doc.getElementById('empty')!.hasAttribute('hidden')).toBe(false);
  });
});
