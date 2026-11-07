/** vault_git: the broker checks EVERY address git will use (spec 1.2 §2, checks 6). */
import { describe, it, expect } from 'vitest';
import { checkSshDestination, buildSshArgv } from '../src/ssh-agent.js';

const allowed = ['github.com'];
const git = (urls: string[]) => ({ kind: 'git' as const, destination: 'git@github.com', urls });

describe('checkSshDestination for git', () => {
  it('allows when every URL is on a permitted host', () => {
    expect(checkSshDestination(git(['git@github.com:me/r.git', 'ssh://git@github.com/me/r2.git']), allowed))
      .toEqual({ ok: true, auditedHost: 'github.com' });
  });
  it('refuses when ANY URL (e.g. a separate push address) is elsewhere', () => {
    const r = checkSshDestination(git(['git@github.com:me/r.git', 'git@evil.example:x.git']), allowed);
    expect(r).toMatchObject({ ok: false });
    expect((r as { error: string }).error).toContain('evil.example');
  });
  it('refuses a non-SSH address, an option-looking host, no URLs, and an empty allowlist', () => {
    for (const urls of [['https://github.com/me/r.git'], ['ext::sh -c x'], ['-oProxyCommand=x:y'], []]) {
      expect(checkSshDestination(git(urls), allowed).ok).toBe(false);
    }
    expect(checkSshDestination(git(['git@github.com:me/r.git']), []).ok).toBe(false);
  });
  it('a git op can never be turned into an ssh command line', () => {
    expect(() => buildSshArgv(git(['git@github.com:me/r.git']), '/s', '/p')).toThrow();
  });
});
