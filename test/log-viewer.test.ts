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
import fs, { mkdtempSync, rmSync, writeFileSync, statSync, readFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { renderViewer, writeViewer, resolveSudoUser, dropToSudoUser, type ActivityView, type SudoLookup, type ProcessIds } from '../src/log-viewer.js';
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
  it('lands in the USER directory, readable only by its owner', () => {
    // It used to land beside the store. After the uid split the store belongs to the
    // daemon and the person running this cannot write there — so the page goes to their
    // own directory. Still not /tmp: it holds the same profile the store does, and a
    // world-readable temp directory is the wrong home for it.
    const store = path.join(dir, 'state', 'network.json');
    fs.mkdirSync(path.dirname(store), { recursive: true });
    writeFileSync(store, JSON.stringify(SHAPE));
    const userRoot = path.join(dir, 'home');
    process.env.WUNDERVAULT_USER_ROOT = userRoot;
    try {
      const out = writeViewer(store);
      expect(path.dirname(out)).toBe(userRoot);
      expect(statSync(out).mode & 0o777).toBe(0o600);
      expect(readFileSync(out, 'utf8')).toContain('api.cloudflare.com');
    } finally { delete process.env.WUNDERVAULT_USER_ROOT; }
  });

  it('leaves the store untouched', () => {
    const store = path.join(dir, 'network.json');
    const original = JSON.stringify(SHAPE);
    writeFileSync(store, original);
    process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'home2');
    try { writeViewer(store); } finally { delete process.env.WUNDERVAULT_USER_ROOT; }
    expect(readFileSync(store, 'utf8')).toBe(original);
  });

  it('writes a usable page even when the store does not exist', () => {
    process.env.WUNDERVAULT_USER_ROOT = path.join(dir, 'home3');
    const out = writeViewer(path.join(dir, 'missing.json'));
    delete process.env.WUNDERVAULT_USER_ROOT;
    const doc = new JSDOM(readFileSync(out, 'utf8'), { runScripts: 'dangerously' }).window.document;
    expect(doc.getElementById('empty')!.hasAttribute('hidden')).toBe(false);
  });
});

describe('it looks like Wundervault (SPEC-branded-log-page-2026-10-28)', () => {
  /** A log view at a chosen verdict, with one refused and one sent use. */
  function view(level: 'ok' | 'bad' | 'unknown'): ActivityView {
    const line = (seq: number, outcome: string) => ({
      v: 1, seq, ts: '2026-10-27T14:12:00.000Z', prev: 'p', hash: 'h' + seq, sig: 's', kind: 'call',
      agent: 'Claude 0512', key: 'Cloudflare', method: 'GET', address: 'https://api.cloudflare.com/x',
      reason: 'list records', outcome,
    });
    return {
      logPath: '/var/lib/wundervault/state/activity.log',
      lines: [line(1, 'sent'), line(2, 'refused')] as unknown as ActivityView['lines'],
      total: 2, problems: level === 'bad' ? [{ seq: 2, lineNo: 2, what: 'bad signature' }] as unknown as ActivityView['problems'] : [],
      problemCount: level === 'bad' ? 1 : 0, signed: 2, unsigned: 0, keyAvailable: true,
      check: level === 'ok' ? { ok: true, checked_at: '2026-10-27T15:00:00.000Z',
        streams: [{ matched: true, server_seq: 2, server_head: 'h2' }] } as unknown as ActivityView['check'] : null,
      lastSeq: 2, checkpointsMatch: true,
    };
  }
  const page = (v?: ActivityView, opts: ConstructorParameters<typeof JSDOM>[1] = {}) =>
    new JSDOM(renderViewer(SHAPE, '/home/someone/.wundervault/network.json', v), { runScripts: 'dangerously', ...opts });

  it('carries the wordmark as an inline outline in the header, not an image or a font', () => {
    const doc = open();
    const marks = doc.querySelectorAll('header svg[role="img"][aria-label="Wundervault"]');
    expect(marks).toHaveLength(1);
    const d = marks[0].querySelector('path')!.getAttribute('d')!;
    expect(d).toMatch(/^M/);
    expect(d.length).toBeGreaterThan(500);
    expect(doc.querySelectorAll('img')).toHaveLength(0);
  });

  it('loads nothing through CSS either: no url() anywhere, no @font-face, no @import', () => {
    const html = renderViewer(SHAPE, 'x', view('ok'));
    expect(html).not.toMatch(/url\s*\(/i);
    expect(html).not.toMatch(/@font-face|@import/i);
  });

  it('keeps the 2.0.1 content-security policy byte for byte', () => {
    const csp = open().querySelector('meta[http-equiv="Content-Security-Policy"]')!.getAttribute('content');
    expect(csp).toBe("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'");
  });

  it('offers Light / Dark / Auto as three peers, Auto first pressed, and each click does what it says', () => {
    const doc = open();     // jsdom's default opaque origin: localStorage THROWS on every call
    const btn = (m: string) => doc.querySelector(`.theme button[data-mode="${m}"]`) as HTMLButtonElement;
    expect([...doc.querySelectorAll('.theme button')].map(b => b.textContent)).toEqual(['Light', 'Dark', 'Auto']);
    const pressed = () => [...doc.querySelectorAll('.theme button[aria-pressed="true"]')].map(b => (b as HTMLElement).dataset.mode);
    expect(pressed()).toEqual(['auto']);
    expect(doc.documentElement.hasAttribute('data-theme')).toBe(false);
    btn('light').click();
    expect(doc.documentElement.getAttribute('data-theme')).toBe('light');
    expect(pressed()).toEqual(['light']);
    btn('dark').click();
    expect(doc.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(pressed()).toEqual(['dark']);
    btn('auto').click();
    expect(doc.documentElement.hasAttribute('data-theme')).toBe(false);
    expect(pressed()).toEqual(['auto']);
  });

  it('remembers the choice where the browser allows storage, and applies it before the page renders', () => {
    const first = page(undefined, { url: 'https://viewer.test/' });
    (first.window.document.querySelector('.theme button[data-mode="light"]') as HTMLButtonElement).click();
    expect(first.window.localStorage.getItem('wv-log-theme')).toBe('light');
    const second = page(undefined, {
      url: 'https://viewer.test/',
      beforeParse(w) { w.localStorage.setItem('wv-log-theme', 'dark'); },
    });
    const doc = second.window.document;
    expect(doc.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(doc.querySelector('.theme button[aria-pressed="true"]')!.getAttribute('data-mode')).toBe('dark');
  });

  it('ignores a stored value that is not a mode', () => {
    const doc = page(undefined, {
      url: 'https://viewer.test/',
      beforeParse(w) { w.localStorage.setItem('wv-log-theme', '"><script>x</script>'); },
    }).window.document;
    expect(doc.documentElement.hasAttribute('data-theme')).toBe(false);
    expect(doc.querySelector('.theme button[aria-pressed="true"]')!.getAttribute('data-mode')).toBe('auto');
  });

  it('says the check result in words: Checks out / Problem found / Not confirmed', () => {
    const label = (lvl: 'ok' | 'bad' | 'unknown') =>
      page(view(lvl)).window.document.querySelector('#verdict .state')!.textContent;
    expect(label('ok')).toBe('Checks out');
    expect(label('bad')).toBe('Problem found');
    expect(label('unknown')).toBe('Not confirmed');
  });

  it('marks a refused use in the danger style and leaves a sent one plain, with the words unchanged', () => {
    const doc = page(view('ok')).window.document;
    const res = [...doc.querySelectorAll('#uses td:nth-child(4) .res')] as HTMLElement[];
    const byText = Object.fromEntries(res.map(r => [r.textContent, r.className]));
    expect(byText['Refused']).toBe('res bad');
    expect(byText['Sent']).toBe('res');
  });
});

describe('who ran sudo (2.0.2: --destinations refused on every Mac)', () => {
  // Real output of `/usr/bin/dscacheutil -q user -a name zackaryprag` on macOS, 2026-10-28.
  const MAC = 'name: zackaryprag\npassword: ********\nuid: 501\ngid: 20\ndir: /Users/zackaryprag\nshell: /bin/zsh\ngecos: Zackary Prag\n\n';
  function lookup(over: Partial<SudoLookup>, answers: Record<string, string>) {
    const calls: string[] = [];
    const l: SudoLookup = {
      platform: 'darwin', uid: 0, env: { SUDO_USER: 'zackaryprag', SUDO_UID: '501' },
      run: (cmd, args) => {
        calls.push(cmd + ' ' + args.join(' '));
        if (!(cmd in answers)) { const e = new Error(`spawnSync ${cmd} ENOENT`); throw e; }
        return answers[cmd];
      },
      ...over,
    };
    return { l, calls };
  }

  it('resolves the Mac user through dscacheutil, by its full path, and never asks for getent', () => {
    const { l, calls } = lookup({}, { '/usr/bin/dscacheutil': MAC });
    expect(resolveSudoUser(l)).toEqual({ uid: 501, gid: 20, home: '/Users/zackaryprag' });
    expect(calls).toEqual(['/usr/bin/dscacheutil -q user -a name zackaryprag']);
  });

  it('still resolves a Linux user through getent', () => {
    const { l, calls } = lookup({ platform: 'linux', env: { SUDO_USER: 'zee', SUDO_UID: '1000' } },
      { getent: 'zee:x:1000:1000:Zee,,,:/home/zee:/bin/bash\n' });
    expect(resolveSudoUser(l)).toEqual({ uid: 1000, gid: 1000, home: '/home/zee' });
    expect(calls).toEqual(['getent passwd zee']);
  });

  it('refuses, rather than staying root, when the Mac has no such account (dscacheutil prints nothing)', () => {
    const { l } = lookup({}, { '/usr/bin/dscacheutil': '' });
    expect(() => resolveSudoUser(l)).toThrow(/Refusing to continue as root/);
  });

  it('refuses when the lookup tool itself is missing', () => {
    const { l } = lookup({}, {});
    expect(() => resolveSudoUser(l)).toThrow(/could not be resolved.*ENOENT[\s\S]*Refusing to continue as root/);
  });

  it('refuses to become uid 0, and refuses a name that resolves to a different uid than sudo recorded', () => {
    const root = 'name: zackaryprag\nuid: 0\ngid: 0\ndir: /var/root\n';
    expect(() => resolveSudoUser(lookup({}, { '/usr/bin/dscacheutil': root }).l)).toThrow(/unusable/);
    const other = lookup({ env: { SUDO_USER: 'zackaryprag', SUDO_UID: '502' } }, { '/usr/bin/dscacheutil': MAC }).l;
    expect(() => resolveSudoUser(other)).toThrow(/resolves to uid 501/);
  });

  it('refuses an empty or non-numeric uid or gid, and group 0 — an empty field is not root', () => {
    for (const rec of ['name: zackaryprag\nuid: 501\ngid: \ndir: /Users/zackaryprag\n',
                       'name: zackaryprag\nuid: 501\ngid: 20x\ndir: /Users/zackaryprag\n',
                       'name: zackaryprag\nuid: 501\ngid: 0\ndir: /Users/zackaryprag\n',
                       // Number('0x14') is 20 and Number(' ') is 0: only plain digits are a number here.
                       'name: zackaryprag\nuid: 501\ngid: 0x14\ndir: /Users/zackaryprag\n']) {
      expect(() => resolveSudoUser(lookup({}, { '/usr/bin/dscacheutil': rec }).l)).toThrow(/unusable/);
    }
    const linux = lookup({ platform: 'linux', env: { SUDO_USER: 'zee', SUDO_UID: '1000' } },
      { getent: 'zee:x:1000::Zee:/home/zee:/bin/bash\n' }).l;
    expect(() => resolveSudoUser(linux)).toThrow(/unusable/);
  });

  it('only reads the first record, and only one whose name is the one asked for', () => {
    const two = 'name: someone\nuid: 777\ngid: 20\ndir: /Users/someone\n\n' + MAC;
    expect(() => resolveSudoUser(lookup({}, { '/usr/bin/dscacheutil': two }).l)).toThrow(/unusable/);
  });

  it('is not a sudo run when not root, or when SUDO_USER is missing or root', () => {
    expect(resolveSudoUser(lookup({ uid: 501 }, {}).l)).toBeNull();
    expect(resolveSudoUser(lookup({ env: {} }, {}).l)).toBeNull();
    expect(resolveSudoUser(lookup({ env: { SUDO_USER: 'root' } }, {}).l)).toBeNull();
  });
});

describe('what an agent wrote is shown as written (2.0.2)', () => {
  const RLO = '‮';
  const shape: NetworkShape = { version: 1, seen: [
    { entryId: 'e-x', origin: `https://pay.example${RLO}moc.knab:443`, firstSeen: '2026-09-01T10:00:00.000Z',
      lastSeen: '2026-09-02T10:00:00.000Z', count: 1, purposes: [`2026-09-02T10:00:00.000Z refund ${RLO}0001$ to me`] },
  ] };
  it('shows a direction override as a visible code, in the destination and in the reason', () => {
    const doc = new JSDOM(renderViewer(shape, 'x'), { runScripts: 'dangerously' }).window.document;
    const body = doc.querySelector('#rows')!.textContent!;
    expect(body).toContain('pay.example⟨U+202E⟩moc.knab');
    expect(body).toContain('refund ⟨U+202E⟩0001$ to me');
    expect(doc.body.textContent).not.toContain(RLO);
  });
  it('shows them in server-written text too (the log path)', () => {
    const html = renderViewer(shape, `/tmp/a${RLO}b`);
    expect(html).toContain('/tmp/a⟨U+202E⟩b');
    expect(html).not.toContain(RLO);
  });
  it('finds a row by the code it shows: searching "U+202E" matches the destination that carries one', () => {
    const onlyInOrigin: NetworkShape = { version: 1, seen: [
      { ...shape.seen[0], purposes: ['2026-09-02T10:00:00.000Z a plain reason'] },
      { entryId: 'e-y', origin: 'https://plain.example:443', firstSeen: '2026-09-01T10:00:00.000Z',
        lastSeen: '2026-09-02T10:00:00.000Z', count: 1, purposes: [] },
    ] };
    const doc = new JSDOM(renderViewer(onlyInOrigin, 'x'), { runScripts: 'dangerously' }).window.document;
    const q = doc.getElementById('q') as HTMLInputElement;
    q.value = 'u+202e';
    q.dispatchEvent(new doc.defaultView!.Event('input'));
    expect(doc.querySelectorAll('#rows tr')).toHaveLength(1);
    expect(doc.querySelector('#rows mark')!.textContent!.toLowerCase()).toBe('u+202e');
  });

  it('lets a keyboard user reach each scrolling table', () => {
    const doc = open();
    const regions = [...doc.querySelectorAll('.tablewrap')];
    expect(regions.length).toBeGreaterThan(0);
    for (const r of regions) {
      expect(r.getAttribute('tabindex')).toBe('0');
      expect(r.getAttribute('role')).toBe('region');
      expect(r.getAttribute('aria-label')).toBeTruthy();
    }
  });
});

describe('dropping root (2.0.2 review: supplementary groups)', () => {
  function proc(over: Partial<ProcessIds> = {}) {
    const st = { uid: 0, gid: 0, groups: [0, 80] };
    const p: ProcessIds = {
      setgroups: (g) => { st.groups = g; }, setgid: (g) => { st.gid = g; }, setuid: (u) => { st.uid = u; },
      getuid: () => st.uid, getgid: () => st.gid, getgroups: () => st.groups, ...over,
    };
    return { p, st };
  }
  it('drops groups, gid and uid, in that order, and checks each', () => {
    const { p, st } = proc();
    dropToSudoUser({ uid: 501, gid: 20 }, p);
    expect(st).toEqual({ uid: 501, gid: 20, groups: [20] });
  });
  it('refuses when root\'s supplementary groups cannot be dropped, before changing uid', () => {
    const { p, st } = proc({ setgroups: () => { throw new Error('EPERM'); } });
    expect(() => dropToSudoUser({ uid: 501, gid: 20 }, p)).toThrow(/setgroups: EPERM/);
    expect(st.uid).toBe(0);
  });
  it('refuses when group 0 is still there afterwards, or the gid did not change', () => {
    expect(() => dropToSudoUser({ uid: 501, gid: 20 }, proc({ setgroups: () => {} }).p)).toThrow(/group 0/);
    expect(() => dropToSudoUser({ uid: 501, gid: 20 }, proc({ setgid: () => {} }).p)).toThrow(/\(gid\)/);
  });
});

describe('a damaged destination record does not break the page (2.0.2 review)', () => {
  const damaged = { version: 1, seen: [
    { entryId: 'e-bad', origin: 'https://x.example:443', firstSeen: '2026-09-01T10:00:00.000Z',
      lastSeen: '2026-09-02T10:00:00.000Z', count: '1‮', purposes: [null, 42, '2026-09-02T10:00:00.000Z ok'] },
    { entryId: 'e-good', origin: 'https://y.example:443', firstSeen: '2026-09-01T10:00:00.000Z',
      lastSeen: '2026-09-02T10:00:00.000Z', count: 3, purposes: [] },
  ] } as unknown as NetworkShape;
  it('a record that is not an object at all is shown as damaged, and the page still renders', () => {
    const doc = new JSDOM(renderViewer({ version: 1, seen: [null, 7, damaged.seen[1]] } as unknown as NetworkShape, 'x'),
      { runScripts: 'dangerously' }).window.document;
    expect(doc.querySelectorAll('#rows tr')).toHaveLength(3);
    expect(doc.querySelector('#rows')!.textContent).toContain('(damaged record)');
  });

  it('a date that carries a direction control is shown with it, never parsed away', () => {
    const odd = { version: 1, seen: [{ ...damaged.seen[1], firstSeen: 'Wed, 02 Sep 2026 10:00:00 GMT (\u202E)' }] } as unknown as NetworkShape;
    const doc = new JSDOM(renderViewer(odd, 'x'), { runScripts: 'dangerously' }).window.document;
    expect(doc.querySelector('#rows')!.textContent).toContain('GMT (⟨U+202E⟩)');
  });

  it('renders both rows, sums counts as numbers, and shows no raw control in the summary', () => {
    const doc = new JSDOM(renderViewer(damaged, 'x'), { runScripts: 'dangerously' }).window.document;
    expect(doc.querySelectorAll('#rows tr')).toHaveLength(2);
    expect(doc.getElementById('count')!.textContent).toMatch(/2 of 2 destinations · 3 calls/);
    expect(doc.getElementById('count')!.textContent).not.toContain('‮');
    expect(doc.querySelector('#rows')!.textContent).toContain('ok');
  });
});
