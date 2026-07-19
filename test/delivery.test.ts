import { describe, it, expect } from 'vitest';
import { readdirSync } from 'node:fs';
import os from 'node:os';
import { runWithSecret, runWithSecretStdin, runWithSecretAskpass, coerceExecConfig } from '../src/exec.js';
import { getRecipe, recipeIds, RECIPES } from '../src/recipes.js';

const SECRET = 'hunter2';

describe('recipes', () => {
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

describe('coerceExecConfig', () => {
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

describe('env mechanism (generic)', () => {
  it('injects the secret as the named env var', () => {
    const r = runWithSecret(SECRET, 'printenv THEKEY', 'THEKEY');
    expect(r.exitCode).toBe(0);
    // scrubbed on the way out, so the literal never reaches the agent
    expect(r.stdout).toContain('[SECRET_REDACTED]');
    expect(r.stdout).not.toContain(SECRET);
  });
});

describe('stdin mechanism (sudo)', () => {
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

describe('askpass mechanism (git / ssh)', () => {
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
