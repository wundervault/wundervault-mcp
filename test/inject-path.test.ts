import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, linkSync, rmSync, readFileSync, statSync, chmodSync, realpathSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { resolveInjectTarget, isAllowedInjectPath } from '../src/templates.js';

// resolveInjectTarget is the gate in front of vault_entry_inject_env. The tool exists
// to be the SAFE way to put a secret in a config file — the alternative to letting a
// command write files — so any way to steer it at another file defeats its purpose.

let root: string;

beforeEach(() => {
  // Not under os.tmpdir(): the resolver refuses the temp tree on purpose, so these
  // tests need a project-shaped directory somewhere it will actually consider.
  root = mkdtempSync(path.join(os.homedir(), '.wv-injecttest-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('resolveInjectTarget — accepts legitimate targets', () => {
  it('accepts a real project .env', () => {
    const target = path.join(root, '.env');
    const r = resolveInjectTarget(target);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.target.path).toBe(target);
  });

  it('accepts a project .env that does not exist yet', () => {
    expect(resolveInjectTarget(path.join(root, '.env.local')).ok).toBe(true);
  });

  it('reports the existing mode so a rewrite cannot widen permissions', () => {
    const target = path.join(root, '.env');
    writeFileSync(target, 'A=1\n');
    chmodSync(target, 0o640);
    const r = resolveInjectTarget(target);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.target.existingMode).toBe(0o640);
  });
});

describe('resolveInjectTarget — rejects redirected writes', () => {
  it('rejects a symlink named .env that points elsewhere', () => {
    const decoy = path.join(root, 'elsewhere.txt');
    writeFileSync(decoy, 'original\n');
    const link = path.join(root, '.env');
    symlinkSync(decoy, link);

    const r = resolveInjectTarget(link);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('symlink');
    expect(readFileSync(decoy, 'utf8')).toBe('original\n');
  });

  it('rejects a .env reached through a symlinked parent directory', () => {
    const real = path.join(root, 'real');
    mkdirSync(real);
    symlinkSync(real, path.join(root, 'link'));

    const r = resolveInjectTarget(path.join(root, 'link', '.env'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('symlinked directory');
  });

  it('rejects a .env reached through a symlinked GRANDparent', () => {
    const real = path.join(root, 'real');
    mkdirSync(path.join(real, 'project'), { recursive: true });
    symlinkSync(real, path.join(root, 'link'));

    const r = resolveInjectTarget(path.join(root, 'link', 'project', '.env'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('symlinked directory');
  });
});

describe('resolveInjectTarget — rejects non-regular targets', () => {
  // A FIFO here is not a curiosity: every fs call on this path is synchronous, so
  // opening a named pipe with no writer blocks the entire daemon, not one request.
  it('rejects a FIFO named .env instead of blocking on it', () => {
    const fifo = path.join(root, '.env');
    try {
      execFileSync('mkfifo', [fifo]);
    } catch {
      return; // no mkfifo on this platform; nothing to assert
    }
    const r = resolveInjectTarget(fifo);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('not a regular file');
  });

  it('rejects a directory named .env', () => {
    mkdirSync(path.join(root, '.env'));
    const r = resolveInjectTarget(path.join(root, '.env'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('not a regular file');
  });
});

describe('resolveInjectTarget — hardlinks', () => {
  // lstat cannot tell a hardlink from an ordinary file and O_NOFOLLOW does not help.
  // The path layer genuinely cannot see this; writeInjectedLine fstats the open file
  // and refuses on nlink > 1. This test pins where the blindness actually is.
  it('cannot distinguish a hardlinked target at the path layer', () => {
    const victim = path.join(root, 'victim.txt');
    writeFileSync(victim, 'do not touch\n');
    const target = path.join(root, '.env');
    linkSync(victim, target);

    const r = resolveInjectTarget(target);
    expect(r.ok).toBe(true);                 // indistinguishable here
    expect(statSync(target).nlink).toBe(2);  // which is why the WRITE has to check
  });
});

describe('resolveInjectTarget — path policy', () => {
  it('rejects a relative path rather than resolving it against the daemon cwd', () => {
    const r = resolveInjectTarget('.env');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('absolute');
  });

  it('rejects system directories even with an allowed name', () => {
    for (const p of ['/etc/.env', '/usr/.env', '/root/.env', '/proc/.env']) {
      const r = resolveInjectTarget(p);
      expect(r.ok, p).toBe(false);
      if (!r.ok) expect(r.error).toContain('system directory');
    }
  });

  it('rejects the world-writable temp tree even with an allowed name', () => {
    const tmpProject = mkdtempSync(path.join(os.tmpdir(), 'wv-tmp-'));
    try {
      const r = resolveInjectTarget(path.join(tmpProject, '.env'));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain('temp directory');
    } finally {
      rmSync(tmpProject, { recursive: true, force: true });
    }
  });

  it('rejects a filename that is not on the allowlist', () => {
    const r = resolveInjectTarget(path.join(root, 'secrets.txt'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('not an allowed config file path');
  });

  it('judges the name AFTER normalising traversal', () => {
    // Ends in "/.env" as a string; resolves to a sibling that is not allowed.
    mkdirSync(path.join(root, 'sub'));
    const r = resolveInjectTarget(path.join(root, 'sub', '..', 'notenv', '.env', '..', 'x.txt'));
    expect(r.ok).toBe(false);
  });

  it('lets traversal through to an allowed location it genuinely resolves to', () => {
    mkdirSync(path.join(root, 'sub'));
    const r = resolveInjectTarget(path.join(root, 'sub', '..', '.env'));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.target.path).toBe(path.join(root, '.env'));
  });

  it('rejects a path whose directory does not exist', () => {
    const r = resolveInjectTarget(path.join(root, 'nope', '.env'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('does not exist');
  });

  it('rejects empty input', () => {
    expect(resolveInjectTarget('').ok).toBe(false);
    expect(resolveInjectTarget('   ').ok).toBe(false);
  });
});

describe('isAllowedInjectPath', () => {
  it('accepts ~/.npmrc by its canonical spelling', () => {
    expect(isAllowedInjectPath(path.join(realpathSync(os.homedir()), '.npmrc'))).toBe(true);
  });

  // .netrc and docker config.json used to be accepted and then corrupted: this writer
  // emits KEY=value, which is not .netrc grammar and is not valid JSON.
  it('no longer accepts files this writer would corrupt', () => {
    const home = realpathSync(os.homedir());
    expect(isAllowedInjectPath(path.join(home, '.netrc'))).toBe(false);
    expect(isAllowedInjectPath(path.join(home, '.docker', 'config.json'))).toBe(false);
  });

  it('does not accept a lookalike name', () => {
    expect(isAllowedInjectPath('/srv/app/.environment')).toBe(false);
    expect(isAllowedInjectPath('/srv/app/env')).toBe(false);
    expect(isAllowedInjectPath('/srv/app/env.local')).toBe(false);
  });
});
