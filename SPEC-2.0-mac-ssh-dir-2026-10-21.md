# SSH sessions work on a Mac (broker 2.0, 2026-10-21)

## What happened

The owner's Telegram onboarding test on their Mac: agent Bearclaw called `vault_ssh_exec` with an
ed25519 key and got "SSH couldn't read the broker's id.pub file: Permission denied". Nothing was
sent to the server.

`BrokerOps.sshAgentOpenInner` makes `<runtime>/ssh/<sessionId>/` with one recursive `mkdirSync`
and chmods only the leaf to 0755. The macOS LaunchDaemon sets `Umask 63` (0077), so the parent
`<runtime>/ssh/` was created 0700, owned by `_wundervault`. The agent runs as the owner, a
different uid, so it could traverse neither to `id.pub` (0644) nor to `agent.sock` (0666). On the
Mac as found: `drwx------ _wundervault /var/lib/wundervault/run/ssh`. Linux never showed it: the
systemd unit has no UMask, so `ssh/` came out 0755. `AgentDaemon.start()` already documents and
fixes the same trap for the runtime directory itself; this parent was missed.

## Requirements

- **R1** Every directory the broker creates between the runtime directory and an SSH session's
  files is traversable by other uids, whatever the process umask. `<runtime>/ssh/` is exactly
  0711: passable, but the live session ids are not listable (round 1, B1).
- **R2** A `<runtime>/ssh/` that a broken version already left at 0700 is repaired by the next
  SSH session, with no reinstall and no manual step.
- **R3** Nothing else about the session changes: the leaf directory, socket mode (0666), id.pub
  mode (0644), random session id, removal on close, and the 0700 state directory are as before.
- **R4** `packaging/verify-macos.sh` reports the mode of `<runtime>/ssh/`: PASS at 711, WARN at
  755/775/777 (works, but listable) and at any other mode other accounts can still pass through
  (an odd last digit: SSH works, the next call sets 711), FAIL when they cannot (every SSH call
  fails) with what breaks, and SKIP (not applicable) when no SSH call has made it yet.
  (Wording matched to the script in polish review round 1, broker F3: the script was right.)

## Acceptance checks

1. Under umask 0077, opening a session leaves `<runtime>/ssh/` at exactly 0711, the session
   directory other-traversable, and id.pub other-readable; the socket sits beside id.pub.
2. With `<runtime>/ssh/` pre-created at 0700, opening a session leaves it at 0711.
3. Both checks fail when the fix is removed (proved by mutation, not assumed).
4. The broker's full test suite passes apart from failures that also occur without the change.
5. On the owner's Mac, after the fixed broker is installed and one SSH call is made, verify-macos.sh
   prints `PASS ssh session dir is 711` and Bearclaw's SSH call works (the real cross-uid check).
6. The leaf, socket and id.pub modes, and close-time removal, are unchanged (R3), by reading the
   diff: the change only adds the parent's mkdir+chmod.
