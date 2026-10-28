import { existsSync, lstatSync, readlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

/**
 * True when an access control list may let someone other than root change `q`. Read the way the
 * installers read it: macOS lists entries under `ls -lde` (only an ALLOW of a change counts);
 * Linux has no -e and marks any list with a + after the mode. If ls cannot answer, the answer is
 * "may" — this decides whether a command is offered to sudo, so doubt means no.
 */
export function aclMayAllowChange(q: string, platform: NodeJS.Platform = process.platform,
                                  run: (args: string[]) => string = (args) =>
                                    execFileSync('/bin/ls', args, { encoding: 'utf8', timeout: 5000 })): boolean {
  try {
    if (platform === 'darwin') {
      return run(['-lde', q]).split('\n').slice(1)
        .some((l) => /allow.*(write|add_file|add_subdirectory|delete|append|chown|security)/.test(l));
    }
    return run(['-ld', q]).charAt(10) === '+';
  } catch { return true; }
}

/**
 * True when `p` can be changed only by root: every folder from `/` down, every symbolic link on the
 * way (followed where it leads; the folder it sits in is what counts), and the file itself are
 * owned by root, writable by no one else, and carry no access control list that lets anyone else
 * change them. The same walk as the installers' root_only_chain.
 */
export function rootOnly(p: string,
                         lstat: (q: string) => { uid: number; mode: number; isSymbolicLink(): boolean } = lstatSync,
                         readlink: (q: string) => string = (q) => readlinkSync(q, 'utf8'),
                         aclAllows: (q: string) => boolean = (q) => aclMayAllowChange(q)): boolean {
  if (!path.isAbsolute(p)) return false;
  const safe = (st: { uid: number; mode: number }) => st.uid === 0 && (st.mode & 0o022) === 0;
  try {
    if (!safe(lstat('/')) || aclAllows('/')) return false;
    let cur = '/';
    const rest = p.split('/').filter(Boolean);
    let hops = 0;
    while (rest.length) {
      const c = rest.shift()!;
      if (c === '.') continue;
      if (c === '..') { cur = path.dirname(cur); continue; }
      const next = path.join(cur, c);
      const st = lstat(next);
      if (st.isSymbolicLink()) {
        if (++hops > 40) return false;
        const t = readlink(next);
        if (path.isAbsolute(t)) cur = '/';
        rest.unshift(...t.split('/').filter(Boolean));
        continue;
      }
      if (!safe(st) || aclAllows(next)) return false;
      cur = next;
    }
    return true;
  } catch { return false; }
}

/** Where a node only root can change is usually found, after the one running now. */
const NODE_CANDIDATES = ['/usr/local/bin/node', '/usr/bin/node', '/opt/wundervault/bin/node'];

/**
 * The command to put after `sudo` in a message, or null when there is no safe one.
 *
 * Two lookups could otherwise run someone else's program as root (SPEC-2.0.3): a bare
 * `wundervault-agent` is found on a PATH sudo may keep from the user — on a Mac usually starting
 * with /opt/homebrew/bin, which the user and every agent can write — and even a full path starts
 * `#!/usr/bin/env node`, so node is looked up the same way. So both are named, and both must be
 * changeable only by root: a node that qualifies (the one running this process, or a usual
 * location), then the launcher. A launcher the user's account can change (a copy in a home folder)
 * is never offered to sudo: that would hand root to whatever an agent puts there (review round 3).
 *
 * The broker names the launcher it was started as (an installer run with --exec may have given it
 * another name); the MCP server names the wundervault-agent beside it. process.argv[1] keeps the
 * launcher's own path; it is not resolved to dist/.
 */
export function agentCommand(argv1: string | undefined = process.argv[1],
                             exists: (p: string) => boolean = existsSync,
                             runningNode: string = process.execPath,
                             isRootOnly: (p: string) => boolean = rootOnly): string | null {
  const quote = (p: string) => (/^[A-Za-z0-9_./@+-]+$/.test(p) ? p : `'${p.replace(/'/g, `'\\''`)}'`);
  if (!argv1 || !path.isAbsolute(argv1)) return null;
  let launcher = argv1;
  if (/^wundervault-mcp/.test(path.basename(argv1))) {
    launcher = path.join(path.dirname(argv1), 'wundervault-agent');
    if (!exists(launcher)) return null;
  }
  if (!isRootOnly(launcher)) return null;
  const node = [runningNode, ...NODE_CANDIDATES].find((n) => !!n && path.isAbsolute(n) && isRootOnly(n));
  return node ? `${quote(node)} ${quote(launcher)}` : null;
}

/** "sudo <node> <broker> <args>", or where to find that command when there is no safe one to print. */
export function sudoHint(args: string, cmd: string | null = agentCommand()): string {
  return cmd ? `sudo ${cmd} ${args}`
    : `sudo <node> <wundervault-agent> ${args}, with the full paths of node and of the broker your ` +
      `installer set up (it printed them, in its pairing step)`;
}
