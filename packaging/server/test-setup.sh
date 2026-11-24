#!/bin/bash
# Drive guided setup, the server cut-off and the change check against a throwaway sshd
# container (podman). Never points at a real server.
#   packaging/server/test-setup.sh            # builds localhost/wv-admin-test:1 if missing
#   WV_TEST_OS=ol9 packaging/server/test-setup.sh   # the same on Oracle Linux 9 (port 2399, wheel,
#                                                   # /var/spool/cron); its PAM account step is
#                                                   # bypassed (pam_unix refuses in rootless podman)
#   WV_TEST_NO_RUNUSER=1 ...                        # hide runuser: drives the setpriv path
# Leaves the container running on 127.0.0.1:2299 for test/admin-cert-sshd.test.ts;
# remove it with: podman rm -f wv-admin-test
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
FAILS=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
expect() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

sh "$HERE/bundle.sh" >/dev/null
B=$HERE/wv-setup.bundled.sh
if [ "${WV_TEST_OS:-debian}" = ol9 ]; then
  IMG=localhost/wv-admin-test-ol9:1 CT=wv-admin-test-ol9 PORT=2399 ADMG=wheel CRONF=/var/spool/cron/opc
else
  IMG=localhost/wv-admin-test:1 CT=wv-admin-test PORT=2299 ADMG=sudo CRONF=crontabs/opc
fi
PORT=${WV_TEST_PORT:-$PORT}
if ! podman image exists "$IMG"; then
  if [ "$CT" = wv-admin-test-ol9 ]; then
    cat > "$W/Containerfile" <<'EOF'
FROM docker.io/library/oraclelinux:9
RUN dnf -y -q install openssh-server sudo procps-ng cronie util-linux shadow-utils >/dev/null && dnf clean all >/dev/null && ssh-keygen -A \
 && sed -i "s/^account *required *pam_unix.so/account sufficient pam_permit.so\naccount required pam_unix.so/" /etc/pam.d/password-auth /etc/pam.d/system-auth \
 && useradd -m -s /bin/bash opc && echo 'opc ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/opc && chmod 440 /etc/sudoers.d/opc \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd","-D","-e"]
EOF
  else
    cat > "$W/Containerfile" <<'EOF'
FROM docker.io/library/debian:stable-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server sudo procps cron >/dev/null && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd && useradd -m -s /bin/bash opc && echo 'opc ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/opc && chmod 440 /etc/sudoers.d/opc \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd","-D","-e"]
EOF
  fi
  podman build -q -t "$IMG" -f "$W/Containerfile" "$W" >/dev/null
fi
podman rm -f "$CT" >/dev/null 2>&1
podman run -d --name "$CT" -p 127.0.0.1:$PORT:22 "$IMG" >/dev/null; sleep 1
# WV_TEST_NO_RUNUSER=1: hide runuser so the scripts take their setpriv path (fixtures keep a copy).
RU=runuser
if [ "${WV_TEST_NO_RUNUSER:-}" = 1 ]; then
  podman exec "$CT" sh -c 'mv "$(command -v runuser)" /root/runuser-hidden'; RU=/root/runuser-hidden
fi
for k in admin daily emerg sneaky; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$W/$k"; done
cp "$W/admin" "${WV_ADMIN_KEY_OUT:-/dev/null}" 2>/dev/null || true
podman exec "$CT" sh -c 'install -d -o opc -g opc -m 700 /home/opc/.ssh; echo secret=1 > /home/opc/.env; chown opc /home/opc/.env; chmod 755 /home/opc'
cp "$W/admin.pub" "$W/ak"; podman cp "$W/ak" "$CT":/home/opc/.ssh/authorized_keys
podman exec "$CT" sh -c 'chown opc:opc /home/opc/.ssh/authorized_keys; chmod 600 /home/opc/.ssh/authorized_keys'
CA=$(cut -d' ' -f1,2 "$W/admin.pub"); D=$(cut -d' ' -f1,2 "$W/daily.pub"); E=$(cut -d' ' -f1,2 "$W/emerg.pub")
O=(-F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o IdentitiesOnly=yes -o BatchMode=yes -p "$PORT")
cert() { end=$(( $(date +%s) + $1 )); ssh-keygen -q -s "$W/admin" -I t -n wv-admin -V "-1m:$(date -u -d @$end +%Y%m%d%H%M%S)Z" \
  -O clear -O permit-pty -O force-command="/usr/local/lib/wundervault/wv-admin-session $end" "$W/admin.pub"; }
plain() { ssh "${O[@]}" -i "$W/admin" -o CertificateFile=/dev/null opc@127.0.0.1 "$@"; }
admin() { ssh "${O[@]}" -i "$W/admin" -o CertificateFile="$W/admin-cert.pub" opc@127.0.0.1 "$@"; }
daily() { ssh "${O[@]}" -i "$W/daily" wv-agent@127.0.0.1 "$@"; }

out=$(plain "sudo sh -s -- prepare opc wv-agent '$CA' '$D' '$E' logs" < "$B")
expect "prepare" '[[ $out == *"PASS prepared"* ]]'
out=$(plain "sudo sh -s -- status opc wv-agent" < "$B"); expect "status all PASS" '[[ $out != *FAIL* && $(grep -c PASS <<<"$out") == 5 ]]'
expect "plain admin key still works after prepare (nothing removed yet)" '[[ $(plain "echo ok") == ok ]]'
expect "everyday key signs in" '[[ $(daily "id -un") == wv-agent ]]'
expect "everyday cannot read the admin .env" '! daily "cat /home/opc/.env" >/dev/null 2>&1'
expect "everyday has no sudo" '! daily "sudo -n true" >/dev/null 2>&1'
expect "everyday may run the health check" '[[ $(daily "sudo -n /usr/local/lib/wundervault/wv-check health") == *disk* ]]'
expect "everyday cannot rewrite the baseline" '! daily "sudo -n /usr/local/lib/wundervault/wv-check baseline" >/dev/null 2>&1'
cert 300
expect "certificate login works before finalize" '[[ $(admin "echo ok") == ok ]]'
out=$(admin "sudo sh -s -- finalize opc '$CA'" < "$B"); expect "finalize" '[[ $out == *"PASS finalized"* ]]'
expect "plain admin key refused after finalize" '! plain "true" >/dev/null 2>&1'
expect "certificate login works after finalize" '[[ $(admin "echo ok") == ok ]]'
expect "emergency key works" '[[ $(ssh "${O[@]}" -i "$W/emerg" opc@127.0.0.1 "echo ok") == ok ]]'
out=$(admin "sudo sh -s -- prepare opc wv-agent '$CA' '$D' '$E' logs && sudo sh -s -- finalize opc '$CA'" < "$B" 2>&1)
expect "setup again is safe (idempotent)" '[[ $out != *FAIL* ]] && [[ $(admin "echo ok") == ok ]] && [[ $(podman exec "$CT" grep -c . /home/opc/.ssh/authorized_keys) == 2 ]]'
for _ in 1 2 3; do admin true; done; sleep 2
expect "finished sessions leave no timer behind" '[[ -z $(podman exec "$CT" ps -u opc -o comm= | grep -v sshd) ]]'
expect "nothing changed -> empty report" '[[ $(daily "sudo -n /usr/local/lib/wundervault/wv-check report") == END ]]'
admin "echo '$(cat "$W/sneaky.pub")' >> ~/.ssh/authorized_keys; sudo useradd -m helper2; sudo usermod -aG $ADMG helper2; echo '* * * * * true' | crontab -; setsid nohup sleep 900 >/dev/null 2>&1 </dev/null & true"
sleep 2; rep=$(daily "sudo -n /usr/local/lib/wundervault/wv-check report")
expect "report: new key with its comment" '[[ $rep == *"NEW	key	opc	"*"sneaky"* ]]'
expect "report: new sudo member" '[[ $rep == *"NEW	group	$ADMG	helper2"* ]]'
expect "report: new cron job" '[[ $rep == *"$CRONF"* ]]'
expect "report: process left running" '[[ $rep == *"NEW	process	opc	sleep"* ]]'
expect "report: /etc/passwd changed" '[[ $rep == *"NEW	file	/etc/passwd"* ]]'
expect "report never prints a whole key" '[[ $rep != *AAAAC3Nza* ]]'
keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
expect "everyday may list keys; list ends with END" '[[ $(tail -n1 <<<"$keys") == END ]]'
expect "keys lists all four sign-in lines across both accounts" '[[ $(grep -c "^KEY	" <<<"$keys") == 4 && $keys == *"KEY	wv-agent	"*"wundervault-everyday	no"* ]]'
expect "keys never prints a whole key" '[[ $keys != *AAAAC3Nza* ]]'
expect "admin CA and emergency keys are protected" '[[ $keys == *"wundervault-admin-ca	yes"* && $keys == *"wundervault-emergency	yes"* && $(grep -c "	yes$" <<<"$keys") == 2 ]]'
fp=$(awk -F '\t' '$1 == "KEY" && $2 == "opc" && $4 == "sneaky" && $5 == "no" { print $3 }' <<<"$keys")
report_fp=$(awk -F '\t' '$1 == "NEW" && $2 == "key" && $3 == "opc" && $5 == "sneaky" { print $4 }' <<<"$rep")
line=$(cat "$W/sneaky.pub"); want=$(printf '%s' "$line" | sha256sum | cut -c1-16)
expect "keys fingerprint equals the change-check and remove-key hash" '[[ -n $fp && $fp == "$report_fp" && $fp == "$want" ]]'
for comment in wundervault-admin-ca wundervault-emergency; do
  protected_fp=$(awk -F '\t' -v comment="$comment" '$1 == "KEY" && $2 == "opc" && $4 == comment { print $3 }' <<<"$keys")
  out=$(admin "sudo sh -s -- remove-key opc '$protected_fp'" < "$B")
  expect "remove-key refuses $comment by its listed fingerprint" '[[ $out == *"emergency key line; refusing"* ]]'
done
out=$(admin "sudo sh -s -- remove-key opc '$fp'" < "$B")
expect "remove-key accepts the fingerprint printed by keys" '[[ $out == "PASS removed 1 key line(s) from opc" ]]'
keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
expect "removed key is gone; everyday and protected keys remain" '[[ $keys != *sneaky* && $(grep -c "^KEY	" <<<"$keys") == 3 && $(grep -c "	yes$" <<<"$keys") == 2 && $keys == *"wundervault-everyday	no"* ]]'
expect "removed key is absent from authorized_keys" '! podman exec "$CT" grep -Fq -- "$(cut -d" " -f2 "$W/sneaky.pub")" /home/opc/.ssh/authorized_keys'
# Review r1 B2: an account that points its key file at /etc/shadow must not get pieces of it listed.
# r1 F1: a key line with no comment lists an empty comment, never part of the key body.
# r1 F3: an account name with a dot is listed.
podman exec "$CT" sh -c 'useradd -m snoop; install -d -o snoop -m 700 /home/snoop/.ssh; ln -s /etc/shadow /home/snoop/.ssh/authorized_keys' >/dev/null 2>&1
podman exec "$CT" sh -c "useradd -m al.ice; install -d -o al.ice -m 700 /home/al.ice/.ssh; echo '$(cut -d' ' -f1-2 "$W/sneaky.pub")' > /home/al.ice/.ssh/authorized_keys; chown al.ice /home/al.ice/.ssh/authorized_keys" >/dev/null 2>&1
keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
body=$(cut -d' ' -f2 "$W/sneaky.pub")
expect "a symlinked key file is skipped and named, not read" '[[ $keys == *"NOTE	skipped-link	snoop"* && $keys != *"KEY	snoop"* && $keys != *root* ]]'
expect "a comment-less key lists an empty comment, not its body (dotted account listed)" '[[ $keys == *"KEY	al.ice	"*"		no"* && $keys != *"${body:0:20}"* && $keys != *"${body:20:20}"* ]]'
rep=$(daily "sudo -n /usr/local/lib/wundervault/wv-check report")
expect "the change check skips the symlinked key file too" '[[ $rep != *"key	snoop"* && $rep != *root* ]]'
podman exec "$CT" sh -c 'userdel -r snoop; userdel -r al.ice; /usr/local/lib/wundervault/wv-check baseline' >/dev/null 2>&1
# Review r2 F1: key files are read AS THE ACCOUNT. A root-only file at the key-file path (what a
# swapped-in link would reach) is not readable by its account, so nothing from it is listed.
podman exec "$CT" sh -c "useradd -m snoop2; install -d -o snoop2 -m 700 /home/snoop2/.ssh; echo '$(cut -d' ' -f1-2 "$W/sneaky.pub") ROOTONLY' > /home/snoop2/.ssh/authorized_keys; chown root:root /home/snoop2/.ssh/authorized_keys; chmod 600 /home/snoop2/.ssh/authorized_keys" >/dev/null 2>&1
keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
rep=$(daily "sudo -n /usr/local/lib/wundervault/wv-check report")
expect "key files are read as their account: a root-only one lists nothing" '[[ $keys != *ROOTONLY* && $rep != *ROOTONLY* && $(tail -n1 <<<"$keys") == END ]]'
# Review r2 F2: a key-type word inside a quoted option is not taken for the key.
admin "echo 'command=\"echo ssh-ed25519 marker\" $(cut -d' ' -f1-2 "$W/sneaky.pub") quoted-owner' >> ~/.ssh/authorized_keys"
keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
expect "a key-type word in a quoted option: comment is the real one, no body" '[[ $keys == *"KEY	opc	"*"	quoted-owner	no"* && $keys != *"${body:0:20}"* ]]'
# Review r2 B1: a key that only CALLS itself the emergency key is not protected, and can be removed.
admin "echo '$(cut -d' ' -f1-2 "$W/sneaky.pub") wundervault-emergency' >> ~/.ssh/authorized_keys"
keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
fake=$(awk -F '\t' '$1 == "KEY" && $2 == "opc" && $4 == "wundervault-emergency" && $5 == "no" { print $3 }' <<<"$keys")
expect "a key named like the emergency key is not protected; the real two still are" '[[ -n $fake && $(grep -c "	yes$" <<<"$keys") == 2 ]]'
out=$(admin "sudo sh -s -- remove-key opc '$fake'" < "$B")
expect "remove-key removes the look-alike" '[[ $out == "PASS removed 1 key line(s) from opc" ]]'
qfp=$(awk -F '\t' '$1 == "KEY" && $2 == "opc" && $4 == "quoted-owner" { print $3 }' <<<"$keys")
admin "sudo sh -s -- remove-key opc '$qfp'" < "$B" >/dev/null
podman exec "$CT" sh -c 'userdel -r snoop2; /usr/local/lib/wundervault/wv-check baseline' >/dev/null 2>&1
# Review r3: the root-only file above is now NOTED as unreadable, never treated as an empty list (B1).
# (snoop2 is gone by now; make the case again for the note.)
podman exec "$CT" sh -c "useradd -m snoop3; install -d -o snoop3 -m 700 /home/snoop3/.ssh; echo x > /home/snoop3/.ssh/authorized_keys; chown root:root /home/snoop3/.ssh/authorized_keys; chmod 600 /home/snoop3/.ssh/authorized_keys" >/dev/null 2>&1
keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
expect "an unreadable key file is named, not listed as empty (r3 B1)" '[[ $keys == *"NOTE	unreadable	snoop3"* ]]'
# r3 F2: a FIFO at the key path cannot hang the list or the change check.
podman exec -e RU="$RU" "$CT" sh -c 'useradd -m fifo1; install -d -o fifo1 -m 700 /home/fifo1/.ssh; $RU -u fifo1 -- mkfifo /home/fifo1/.ssh/authorized_keys' >/dev/null 2>&1
t0=$SECONDS; keys=$(timeout 60 ssh "${O[@]}" -i "$W/daily" wv-agent@127.0.0.1 "sudo -n /usr/local/lib/wundervault/wv-check keys"); t1=$SECONDS
rep=$(timeout 60 ssh "${O[@]}" -i "$W/daily" wv-agent@127.0.0.1 "sudo -n /usr/local/lib/wundervault/wv-check report"); t2=$SECONDS
expect "a FIFO key file does not hang the list or the report (r3 F2)" '[[ $(tail -n1 <<<"$keys") == END && $(tail -n1 <<<"$rep") == END && $((t2 - t0)) -lt 50 ]]'
# r3 F3: the emergency line with a changed spacing and comment is STILL protected (by its key).
podman exec "$CT" sh -c "sed -i 's/ wundervault-emergency\$/   renamed-by-a-tool  /' /home/opc/.ssh/authorized_keys"
keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
efp=$(awk -F '\t' '$1 == "KEY" && $2 == "opc" && $4 == "renamed-by-a-tool" { print $3 "|" $5 }' <<<"$keys")
expect "an edited emergency line stays protected (r3 F3)" '[[ ${efp#*|} == yes ]]'
out=$(admin "sudo sh -s -- remove-key opc '${efp%|*}'" < "$B")
expect "...and remove-key still refuses it" '[[ $out == *"emergency key line; refusing"* ]]'
podman exec "$CT" sh -c "sed -i 's/   renamed-by-a-tool  \$/ wundervault-emergency/' /home/opc/.ssh/authorized_keys"
# r3 F1: key files are written by their account (owner stays the account; no root-made file left).
expect "key files are written as their account (r3 F1)" '[[ $(podman exec "$CT" stat -c %U /home/opc/.ssh/authorized_keys) == opc && -z $(podman exec "$CT" sh -c "ls -A /home/opc/.ssh | grep wv-ak") ]]'
podman exec "$CT" sh -c 'userdel -r snoop3; userdel -r fifo1; /usr/local/lib/wundervault/wv-check baseline' >/dev/null 2>&1
podman exec "$CT" sh -c 'useradd -m -s /bin/bash maint1; /usr/local/lib/wundervault/wv-check baseline >/dev/null; usermod -o -u 0 maint1' >/dev/null 2>&1
rep=$(daily "sudo -n /usr/local/lib/wundervault/wv-check report")
expect "report: an account moved to uid 0" '[[ $rep == *"NEW	account	maint1	0:"* ]]'
cert 8; t0=$(date +%s); admin "sleep 120" >/dev/null 2>&1; took=$(( $(date +%s) - t0 ))
expect "server ends a running admin command at the end ($took s for 8 s)" '[[ $took -le 10 ]]'
expect "certificate refused after its end" '! admin true >/dev/null 2>&1'
podman exec "$CT" sh -c 'groupadd -f docker; useradd -m -G docker wv-bad' >/dev/null 2>&1; cert 120
out=$(admin "sudo sh -s -- prepare opc wv-bad '$CA' '$D' '$E'" < "$B"); expect "refuses an everyday account in docker" '[[ $out == *"FAIL wv-bad is in group docker"* ]]'
out=$(admin "sudo sh -s -- prepare 'opc;id' wv-agent x y z" < "$B"); expect "refuses a bad name before using it" '[[ $out == "FAIL admin account name" ]]'
podman exec "$CT" sh -c "useradd -m adm2; install -d -o adm2 -m 700 /home/adm2/.ssh; echo 'cert-authority,principals=\"wv-admin\" $CA' > /home/adm2/.ssh/authorized_keys"
out=$(admin "sudo sh -s -- finalize adm2 '$CA'" < "$B"); expect "finalize refuses without the emergency key" '[[ $out == *"emergency key is missing"* ]]'
end=$(( $(date +%s) + 60 ))
out=$(podman exec -u opc -e TMPDIR=/nonexistent -e SSH_ORIGINAL_COMMAND="echo SHOULD-NOT" "$CT" sh /usr/local/lib/wundervault/wv-admin-session $end 2>&1)
expect "session check timer cannot start -> refused (fails closed)" '[[ $out != *SHOULD-NOT* && $out == *refused* ]]'
podman exec "$CT" mv /usr/local/lib/wundervault/wv-admin-session /tmp/x; cert 60
expect "session check missing -> admin refused (fails closed)" '! admin "echo SHOULD-NOT" 2>/dev/null | grep -q SHOULD-NOT'
expect "...while the everyday key still works" '[[ $(daily "id -un") == wv-agent ]]'
expect "...and the emergency key still works" '[[ $(ssh "${O[@]}" -i "$W/emerg" opc@127.0.0.1 "echo ok") == ok ]]'
podman exec "$CT" mv /tmp/x /usr/local/lib/wundervault/wv-admin-session
# From 2.5.1 (review r27/r28): re-running setup first SAYS and SAVES what changed since the last check;
# an oversized key file is reported; remove-key refuses a linked key file and leaves its target alone.
podman exec "$CT" sh -c 'useradd -m drift1' >/dev/null 2>&1
cert 300
out=$(admin "sudo sh -s -- prepare opc wv-agent '$CA' '$D' '$E' logs && sudo sh -s -- finalize opc '$CA'" < "$B" 2>&1)
expect "setup again lists changes since the last check before recording them" '[[ $out == *"change(s) since the last check"* && $out == *"NOTE changed: NEW account drift1"* && $out != *FAIL* ]]'
expect "the full list of changes before setup is kept on the server, root only" '[[ $(podman exec "$CT" sh -c "cat /var/lib/wundervault/changes-before-setup-*.txt") == *"NEW account drift1"* && $(podman exec "$CT" sh -c "stat -c %U%a /var/lib/wundervault/changes-before-setup-*.txt | sort -u") == root600 ]]'
podman exec -e RU="$RU" "$CT" sh -c 'useradd -m big1; install -d -o big1 -m 700 /home/big1/.ssh; $RU -u big1 -- sh -c "seq 1 3000 | sed s/^/x/ > /home/big1/.ssh/authorized_keys"' >/dev/null 2>&1
rep=$(daily "sudo -n /usr/local/lib/wundervault/wv-check report"); keys=$(daily "sudo -n /usr/local/lib/wundervault/wv-check keys")
expect "an oversized key file is reported as too large (report and key list)" '[[ $rep == *"key	big1	too-large"* && $keys == *"NOTE	too-large	big1"* && $(tail -n1 <<<"$rep") == END ]]'
podman exec "$CT" sh -c 'useradd -m linky; install -d -o linky -m 700 /home/linky/.ssh; ln -s /etc/passwd /home/linky/.ssh/authorized_keys' >/dev/null 2>&1
before=$(podman exec "$CT" sha256sum /etc/passwd)
out=$(admin "sudo sh -s -- remove-key linky 0123456789abcdef" < "$B")
expect "remove-key refuses a linked key file and leaves its target alone" '[[ $out == *"is a link; refusing"* && $(podman exec "$CT" sha256sum /etc/passwd) == "$before" && $(podman exec "$CT" stat -c %U /etc/passwd) == root ]]'
podman exec "$CT" sh -c 'userdel -r drift1; userdel -r big1; userdel -r linky' >/dev/null 2>&1
echo; [ "$FAILS" = 0 ] && echo "ALL PASS" || echo "$FAILS FAILED"
exit "$FAILS"
