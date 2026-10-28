# SPEC — 2.0.3: nothing the user's account can change runs as root (2026-10-28)

## The hole (found in the 2.0.2 review, round 3)
The installers are the one step that runs as root. They used bare command names (`id`, `uname`,
`launchctl`, `stat`, `awk`, `rm`, `dscl`, `systemctl`, …) resolved on the PATH of whoever ran
`sudo`. macOS's sudo keeps that PATH, and on Apple Silicon it usually begins with
`/opt/homebrew/bin`, which the user owns (verified on the owner's Mac: `drwxrwxr-x zackaryprag admin`).
Everything the user runs — every agent — can write there, so a planted `launchctl` or `id` would
run as root the next time anyone installs, upgrades or uninstalls. Agents getting root defeats the
whole design (the broker exists so agents cannot reach credentials).

Related, same class:
- Only the broker FILE and node FILE are checked for root ownership (macOS); their FOLDERS are not.
  A root-owned file in a user-writable folder can be renamed away and replaced, and launchd/systemd
  start the broker by that path. Intel Homebrew makes /usr/local/bin user-owned.
- The Linux installer checks neither file nor folder, and runs the service's `node` as root
  (`node -p process.version`) before any check.
- The broker's own messages tell people to type `sudo wundervault-agent …` by bare name, which sudo
  may resolve on the same user PATH.

## Requirements
R1. Both installers save the caller's PATH as `USER_PATH` and then set `PATH` to system directories,
    as their first two statements after `set -eu` (nothing runs in between: the save is an assignment)
    (macOS `/usr/bin:/bin:/usr/sbin:/sbin`; Linux `/usr/sbin:/usr/bin:/sbin:/bin`) and export it. The
    caller's PATH is kept in `USER_PATH` and used ONLY to look up where `node` and `wundervault-agent`
    are (`command -v` in a subshell); nothing found there is executed before R2 passes.
R2. Before anything found that way runs, and before it is written into the plist/unit, the file AND
    every directory from `/` down to it must be owned by root and not writable by group or others —
    walking the path one component at a time and following EVERY symbolic link where it leads (the
    folder each link sits in is checked; a link's own mode is not), so no intermediate hop escapes. One
    shared function `root_only_chain` in each installer, between markers so tests run it alone; it
    works with GNU stat (`-c '%U %a'`) and BSD stat (`-f '%Su %Lp'`), taking the last three mode
    digits. The refusal names the offending path, why, and a way out (install under a root-only
    prefix, or copy node there, and pass --node / --exec).
R3. Linux: the service's node (found on systemd's PATH, unchanged) passes R2 before it is run.
R4. The broker's messages that tell someone to run a sudo command print the launcher's absolute
    path (the path this process was started as, if absolute), falling back to the bare name.
R4b. The installers clear NODE_OPTIONS, NODE_PATH and the LD_/DYLD_ loader variables before running
    anything (review round 1, B1); refuse an access control list that grants a change (B2); and
    refuse any non-root or group/other-writable file inside the broker's package (B3).
R4c. (owner, after round 3) The restart (`env -i`) carries SUDO_UID/SUDO_GID/SUDO_USER; its
    `--clean-env` marker is accepted only when the environment is already exactly what the restart
    produces; the package scans follow links into folders (`find -L`); agent hints offer sudo only a
    broker AND a node that are root-only, else say where to find the installer's printed command.
R6. (owner, after round 3) When run through sudo, the installers check sudo's own PATH (USER_PATH):
    if any entry is not root-only, they warn — early and again beside the next steps — naming it and
    printing `Defaults secure_path="<the usual root-only folders on this machine>"`. A warning, not
    a refusal: the installer itself is not exposed.
R7. (owner approved a round 4; its findings) R1 as built: the first command after `set -eu` is the
    restart itself, `exec /usr/bin/env -i …` by full path, so nothing the caller set reaches any tool;
    the USER_PATH save and PATH pin are the first statements after it, and the `--clean-env` check
    runs on the pinned PATH. The service template (PLIST_SRC / UNIT_SRC) passes root_only_chain before
    it is read. The package scan walks every link found in the package AND in each folder a link
    leads to (a worklist, capped at 500 folders). Every find/ls in the scan that fails is a refusal.
    agentCommand's rootOnly reads access lists the way the installers do (doubt means no). An empty
    or trailing entry in sudo's PATH is the current folder and is checked as `.`.
R8. (owner approved a round 5; its findings) Until the clean-environment check passes, nothing is
    run by a bare name — macOS's sh (bash 3.2) imports BASH_FUNC_x%% functions, `[` included
    (measured on the owner's Mac): the first command is `case` + `exec /usr/bin/env -i`; the check
    runs /usr/bin/env and /usr/bin/sed by full path (a name with a slash is never imported); the
    refusal is printed by a fresh `env -i` shell. A wholly empty sudo PATH is one empty entry.
R5. No environment variable or option weakens R1/R2 (a test seam must not be an attack seam):
    tests transform a COPY of the script, the shipped script has no override.

## Acceptance checks
A1. Each installer's first non-comment lines after `set -eu` are the `env -i` restart by full path,
    then the USER_PATH save and the PATH pin (static check, R7), and the
    unmodified macOS and Linux installers, run with a planted `id`, `uname`, `stat`, `launchctl`,
    `systemctl` first on PATH, never execute any planted tool (each would leave a marker).
A2. root_only_chain passes a root-owned file in root-owned folders (e.g. /usr/bin/env), and refuses:
    a file owned by the test user; a root-owned-looking chain containing a user-owned folder; a
    group-writable and an other-writable file/folder (via a stat stand-in in a transformed copy);
    sticky world-writable /tmp is refused too.
A3. The uninstall tests still pass against a transformed copy whose PATH line points at stand-ins.
A4. Messages: `--destinations` hints and the broker-key message print an absolute launcher path when
    the process was started by one.
A6. (R7) A user-owned template is refused before it is read; a link nested inside a linked folder,
    into a user-owned folder, is refused; each of the scan's find/ls steps failing alone is a refusal
    (each guard mutation-checked, both installers); an ACL that allows a change makes rootOnly false;
    `/usr/bin::/bin` and a trailing `:` are flagged.
A7. (R8) With BASH_FUNC_ functions for `[`, env, sed, echo, printf and test in the environment, a
    bash-as-sh run of either installer's prologue — normal, and with a hand-typed --clean-env —
    runs none of them (forged: refused). Real root install of the Linux installer (systemd container,
    a normal user's sudo without secure_path, planted tools first on PATH): installs, warns, prints
    full-path commands, runs no planted tool; refuses a user-owned broker, folder, package file and
    template; reinstalls; uninstalls.
A5. Full suite green on Node 22 and 24; CI green; publish as 2.0.3.
