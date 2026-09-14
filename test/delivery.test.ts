import { describe, it, expect } from 'vitest';
import { readdirSync } from 'node:fs';
import os from 'node:os';
import { runWithSecret, runWithSecretStdin, runWithSecretAskpass, coerceExecConfig, commandInvokesSudo } from '../src/exec.js';
import { getRecipe, recipeIds, RECIPES } from '../src/recipes.js';


// Unix modes, symlinks, mkfifo and /bin/sh. Secret delivery is POSIX-only by
// construction, so these assert semantics Windows does not have.
const POSIX_ONLY = process.platform === 'win32' ? describe.skip : describe;

const SECRET = 'hunter2';

POSIX_ONLY('recipes', () => {
  it('maps credential types to safe mechanisms', () => {
    expect(getRecipe('generic')?.mechanism).toBe('env');
    expect(getRecipe('sudo')?.mechanism).toBe('stdin');
    expect(getRecipe('git')?.mechanism).toBe('askpass');
    expect(getRecipe('git')?.askpassVar).toBe('GIT_ASKPASS');
    expect(getRecipe('ssh-passphrase')?.askpassVar).toBe('SSH_ASKPASS');
    expect(getRecipe('ssh-passphrase')?.wrap).toBe('setsid');
  });

  it('sudo terminates the secret with a newline', () => {
    expect(getRecipe('sudo')?.appendNewline).toBe(true);
  });

  it('rejects unknown types', () => {
    expect(getRecipe('nope')).toBeUndefined();
    expect(recipeIds()).toEqual(Object.keys(RECIPES));
  });

  it('every recipe carries a non-empty delivery note', () => {
    for (const r of Object.values(RECIPES)) expect(r.delivery.length).toBeGreaterThan(0);
  });
});

POSIX_ONLY('coerceExecConfig', () => {
  it('parses the JSON string the backend forwards', () => {
    expect(coerceExecConfig('{"credential_type":"sudo"}')).toEqual({ credential_type: 'sudo' });
    expect(coerceExecConfig('{"env_key":"NPM_TOKEN","pre_command":"x"}')).toEqual({ env_key: 'NPM_TOKEN', pre_command: 'x' });
  });
  it('passes through an already-parsed object', () => {
    expect(coerceExecConfig({ credential_type: 'git' })).toEqual({ credential_type: 'git' });
  });
  it('returns undefined for empty / garbage / non-object', () => {
    expect(coerceExecConfig(undefined)).toBeUndefined();
    expect(coerceExecConfig('')).toBeUndefined();
    expect(coerceExecConfig('   ')).toBeUndefined();
    expect(coerceExecConfig('not json')).toBeUndefined();
    expect(coerceExecConfig('"a string"')).toBeUndefined();
    expect(coerceExecConfig('42')).toBeUndefined();
  });
});

POSIX_ONLY('env mechanism (generic)', () => {
  it('injects the secret as the named env var', () => {
    const r = runWithSecret(SECRET, 'printenv THEKEY', 'THEKEY');
    expect(r.exitCode).toBe(0);
    // scrubbed on the way out, so the literal never reaches the agent
    expect(r.stdout).toContain('[SECRET_REDACTED]');
    expect(r.stdout).not.toContain(SECRET);
  });
});

POSIX_ONLY('stdin mechanism (sudo)', () => {
  it('delivers the secret on stdin (byte count proves arrival)', () => {
    const r = runWithSecretStdin(SECRET, 'wc -c', { appendNewline: true });
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toBe(String(SECRET.length + 1)); // + newline
  });

  it('does NOT place the secret in the environment', () => {
    const r = runWithSecretStdin(SECRET, `if env | grep -q ${SECRET}; then echo LEAK; else echo CLEAN; fi`);
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toBe('CLEAN');
  });

  it('still rejects a redirect to disk', () => {
    const r = runWithSecretStdin(SECRET, 'cat > /tmp/wv-should-not-write');
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain('Exec rejected');
  });
});

POSIX_ONLY('askpass mechanism (git / ssh)', () => {
  it('the askpass helper hands the secret to the tool', () => {
    // A stand-in "tool": invoke the askpass var and count the bytes it prints.
    const r = runWithSecretAskpass(SECRET, '"$TEST_ASKPASS" | wc -c', { askpassVar: 'TEST_ASKPASS' });
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toBe(String(SECRET.length + 1)); // helper prints secret + newline
  });

  it('does NOT place the secret in the environment', () => {
    const r = runWithSecretAskpass(
      SECRET,
      `if env | grep -q ${SECRET}; then echo LEAK; else echo CLEAN; fi`,
      { askpassVar: 'TEST_ASKPASS' },
    );
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toBe('CLEAN');
  });

  it('does not leak its temp dir after a run', () => {
    const count = () => readdirSync(os.tmpdir()).filter((n) => n.startsWith('wv-ap-')).length;
    const before = count();
    runWithSecretAskpass(SECRET, '"$TEST_ASKPASS" | wc -c', { askpassVar: 'TEST_ASKPASS' });
    expect(count()).toBeLessThanOrEqual(before);
  });
});

describe('commandInvokesSudo — the stdin route into root', () => {
  // Gating only credential_type "sudo" would be a gate in name only: an entry with no
  // server-side exec_config lets the caller pick mechanism "stdin" freely, and 49 of 50
  // entries have none. This matches the sudo INVOCATION so that route is closed too.
  it('matches sudo at the start of a command', () => {
    expect(commandInvokesSudo('sudo -S apt-get update')).toBe(true);
  });

  it('matches an absolute path to sudo', () => {
    expect(commandInvokesSudo('/usr/bin/sudo -S id')).toBe(true);
    expect(commandInvokesSudo('/bin/sudo id')).toBe(true);
  });

  it('matches sudo after a shell separator, not just at position zero', () => {
    expect(commandInvokesSudo('echo hi; sudo -S id')).toBe(true);
    expect(commandInvokesSudo('true && sudo id')).toBe(true);
    expect(commandInvokesSudo('cat x | sudo tee y')).toBe(true);
    expect(commandInvokesSudo('( sudo id )')).toBe(true);
  });

  it('does not match a file merely named like sudo', () => {
    expect(commandInvokesSudo('cat /etc/sudoers')).toBe(false);
    expect(commandInvokesSudo('grep pseudo-tty config')).toBe(false);
  });

  it('does not match sudo quoted inside an argument', () => {
    // rsync's remote-side sudo is a different mechanism and blocking it would break
    // legitimate transfers; the local process is not being handed the password here.
    expect(commandInvokesSudo('rsync --rsync-path="sudo rsync" a b')).toBe(false);
  });

  it('leaves ordinary commands alone', () => {
    expect(commandInvokesSudo('npm login')).toBe(false);
    expect(commandInvokesSudo('docker login -u me --password-stdin')).toBe(false);
  });
});
