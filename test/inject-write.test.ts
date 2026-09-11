import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, linkSync, rmSync, statSync, chmodSync, readdirSync, mkdirSync, renameSync, symlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { resolveInjectTarget, writeInjectedLine } from '../src/templates.js';


// Unix modes, symlinks, mkfifo and /bin/sh. Secret delivery is POSIX-only by
// construction, so these assert semantics Windows does not have.
const POSIX_ONLY = process.platform === 'win32' ? describe.skip : describe;

// These exercise the actual write, not just the path helper. The path helper cannot
// see a hardlink and does not try to — the write is what has to survive one.

let root: string;

beforeEach(() => { root = mkdtempSync(path.join(os.homedir(), '.wv-writetest-')); });
afterEach(() => { rmSync(root, { recursive: true, force: true }); });

function resolved(p: string) {
  const r = resolveInjectTarget(p);
  if (!r.ok) throw new Error(`expected a resolvable target, got: ${r.error}`);
  return r.target;
}

POSIX_ONLY('writeInjectedLine', () => {
  it('creates the file and writes the pair', () => {
    const target = path.join(root, '.env');
    expect(writeInjectedLine(resolved(target), 'TOKEN', 's3cret').ok).toBe(true);
    expect(readFileSync(target, 'utf8')).toContain('TOKEN=s3cret');
  });

  it('replaces an existing key without disturbing the others', () => {
    const target = path.join(root, '.env');
    writeFileSync(target, 'KEEP=yes\nTOKEN=old\nALSO=fine\n');
    expect(writeInjectedLine(resolved(target), 'TOKEN', 'new').ok).toBe(true);
    const out = readFileSync(target, 'utf8');
    expect(out).toContain('KEEP=yes');
    expect(out).toContain('TOKEN=new');
    expect(out).toContain('ALSO=fine');
    expect(out).not.toContain('TOKEN=old');
  });

  // THE one that matters. `ln ~/.bashrc project/.env` then inject. Truncating in place
  // writes the secret into the victim's inode (verified: the pre-fix code did exactly
  // that). The write now fstats the OPEN file and refuses a target with other names,
  // which also stops the victim's contents being copied into the new .env.
  it('refuses to write to a target that is hardlinked to another file', () => {
    const victim = path.join(root, 'victim.txt');
    writeFileSync(victim, 'original contents\n');
    const target = path.join(root, '.env');
    linkSync(victim, target);
    expect(statSync(target).nlink).toBe(2);

    const r = writeInjectedLine(resolved(target), 'TOKEN', 'leaked-secret');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('hard links');

    // victim untouched, and nothing of it copied anywhere
    expect(readFileSync(victim, 'utf8')).toBe('original contents\n');
    expect(readFileSync(target, 'utf8')).not.toContain('leaked-secret');
    expect(readdirSync(root).filter((f) => f.startsWith('.wv-inject-'))).toHaveLength(0);
  });

  // A hardlink planted AFTER the path check still has to be caught, because every
  // check made against a path is stale the moment it returns.
  it('refuses a hardlink swapped in after resolution', () => {
    const target = path.join(root, '.env');
    writeFileSync(target, 'A=1\n');
    const t = resolved(target);

    const victim = path.join(root, 'victim.txt');
    writeFileSync(victim, 'original\n');
    rmSync(target);
    linkSync(victim, target);

    const r = writeInjectedLine(t, 'TOKEN', 'leaked-secret');
    expect(r.ok).toBe(false);
    expect(readFileSync(victim, 'utf8')).toBe('original\n');
  });

  // A FIFO planted after resolution used to park the open forever and, since every
  // call here is synchronous, take the whole daemon with it.
  it('does not block on a FIFO swapped in after resolution', () => {
    const target = path.join(root, '.env');
    const t = resolved(target);
    try {
      execFileSync('mkfifo', [target]);
    } catch {
      return;
    }
    const r = writeInjectedLine(t, 'TOKEN', 'x');   // must return, not hang
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/not a regular file|Cannot read/);
  });

  it('aborts if the parent directory is swapped after resolution', () => {
    const project = path.join(root, 'project');
    mkdirSync(project);
    const target = resolved(path.join(project, '.env'));

    // the classic race: rename the approved directory away, put a symlink in its place
    const elsewhere = path.join(root, 'elsewhere');
    mkdirSync(elsewhere);
    renameSync(project, path.join(root, 'project.old'));
    symlinkSync(elsewhere, project);

    const r = writeInjectedLine(target, 'TOKEN', 'leaked-secret');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('changed identity');
    expect(readdirSync(elsewhere)).toHaveLength(0);
  });

  it('preserves the existing file mode rather than widening it', () => {
    const target = path.join(root, '.env');
    writeFileSync(target, 'A=1\n');
    chmodSync(target, 0o600);
    expect(writeInjectedLine(resolved(target), 'TOKEN', 'x').ok).toBe(true);
    expect(statSync(target).mode & 0o777).toBe(0o600);
  });

  it('creates a new file 0600, not world-readable', () => {
    const target = path.join(root, '.env');
    expect(writeInjectedLine(resolved(target), 'TOKEN', 'x').ok).toBe(true);
    expect(statSync(target).mode & 0o777).toBe(0o600);
  });

  it('leaves no temp file behind on success', () => {
    const target = path.join(root, '.env');
    writeInjectedLine(resolved(target), 'TOKEN', 'x');
    expect(readdirSync(root).filter((f) => f.startsWith('.wv-inject-'))).toHaveLength(0);
  });

  it('refuses to truncate a file it could not read', () => {
    const target = path.join(root, '.env');
    writeFileSync(target, 'IMPORTANT=keep\n');
    const t = resolved(target);
    chmodSync(target, 0o000); // unreadable, but still present
    try {
      const r = writeInjectedLine(t, 'TOKEN', 'x');
      if (process.getuid?.() === 0) return; // root reads anything; nothing to assert
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain('Refusing to overwrite');
      chmodSync(target, 0o600);
      expect(readFileSync(target, 'utf8')).toBe('IMPORTANT=keep\n');
    } finally {
      try { chmodSync(target, 0o600); } catch { /* gone */ }
    }
  });
});

POSIX_ONLY('writeInjectedLine — key validation', () => {
  it('refuses a key carrying a newline instead of writing extra lines', () => {
    const target = path.join(root, '.env');
    writeFileSync(target, 'KEEP=yes\n');
    const r = writeInjectedLine(resolved(target), 'A\nNODE_OPTIONS', 'x');
    expect(r.ok).toBe(false);
    expect(readFileSync(target, 'utf8')).toBe('KEEP=yes\n');
  });

  it('replaces every duplicate of a key, not just the first', () => {
    const target = path.join(root, '.env');
    writeFileSync(target, 'TOKEN=one\nOTHER=x\nTOKEN=two\n');
    expect(writeInjectedLine(resolved(target), 'TOKEN', 'new').ok).toBe(true);
    const out = readFileSync(target, 'utf8');
    expect(out).not.toContain('TOKEN=one');
    expect(out).not.toContain('TOKEN=two');
    expect(out.match(/TOKEN=new/g)).toHaveLength(2);
  });
});
