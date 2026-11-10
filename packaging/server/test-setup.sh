#!/bin/bash
# Drive guided setup, the server cut-off and the change check against a throwaway sshd
# container (podman). Never points at a real server.
#   packaging/server/test-setup.sh            # builds localhost/wv-admin-test:1 if missing
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
if ! podman image exists localhost/wv-admin-test:1; then
  cat > "$W/Containerfile" <<'EOF'
FROM docker.io/library/debian:stable-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server sudo procps cron >/dev/null && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd && useradd -m -s /bin/bash opc && echo 'opc ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/opc && chmod 440 /etc/sudoers.d/opc \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd","-D","-e"]
EOF
  podman build -q -t localhost/wv-admin-test:1 -f "$W/Containerfile" "$W" >/dev/null
fi
podman rm -f wv-admin-test >/dev/null 2>&1
podman run -d --name wv-admin-test -p 127.0.0.1:2299:22 localhost/wv-admin-test:1 >/dev/null; sleep 1
for k in admin daily emerg sneaky; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$W/$k"; done
cp "$W/admin" "${WV_ADMIN_KEY_OUT:-/dev/null}" 2>/dev/null || true
podman exec wv-admin-test sh -c 'install -d -o opc -g opc -m 700 /home/opc/.ssh; echo secret=1 > /home/opc/.env; chown opc /home/opc/.env; chmod 755 /home/opc'
cp "$W/admin.pub" "$W/ak"; podman cp "$W/ak" wv-admin-test:/home/opc/.ssh/authorized_keys
podman exec wv-admin-test sh -c 'chown opc:opc /home/opc/.ssh/authorized_keys; chmod 600 /home/opc/.ssh/authorized_keys'
CA=$(cut -d' ' -f1,2 "$W/admin.pub"); D=$(cut -d' ' -f1,2 "$W/daily.pub"); E=$(cut -d' ' -f1,2 "$W/emerg.pub")
O=(-F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o IdentitiesOnly=yes -o BatchMode=yes -p 2299)
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
expect "setup again is safe (idempotent)" '[[ $out != *FAIL* ]] && [[ $(admin "echo ok") == ok ]] && [[ $(podman exec wv-admin-test grep -c . /home/opc/.ssh/authorized_keys) == 2 ]]'
for _ in 1 2 3; do admin true; done; sleep 2
expect "finished sessions leave no timer behind" '[[ -z $(podman exec wv-admin-test ps -u opc -o comm= | grep -v sshd) ]]'
expect "nothing changed -> empty report" '[[ $(daily "sudo -n /usr/local/lib/wundervault/wv-check report") == END ]]'
admin "echo '$(cat "$W/sneaky.pub")' >> ~/.ssh/authorized_keys; sudo useradd -m helper2; sudo usermod -aG sudo helper2; echo '* * * * * true' | crontab -; setsid nohup sleep 900 >/dev/null 2>&1 </dev/null & true"
sleep 2; rep=$(daily "sudo -n /usr/local/lib/wundervault/wv-check report")
expect "report: new key with its comment" '[[ $rep == *"NEW	key	opc	"*"sneaky"* ]]'
expect "report: new sudo member" '[[ $rep == *"NEW	group	sudo	helper2"* ]]'
expect "report: new cron job" '[[ $rep == *"crontabs/opc"* ]]'
expect "report: process left running" '[[ $rep == *"NEW	process	opc	sleep"* ]]'
expect "report: /etc/passwd changed" '[[ $rep == *"NEW	file	/etc/passwd"* ]]'
expect "report never prints a whole key" '[[ $rep != *AAAAC3Nza* ]]'
podman exec wv-admin-test sh -c 'useradd -m -s /bin/bash maint1; /usr/local/lib/wundervault/wv-check baseline >/dev/null; usermod -o -u 0 maint1' >/dev/null 2>&1
rep=$(daily "sudo -n /usr/local/lib/wundervault/wv-check report")
expect "report: an account moved to uid 0" '[[ $rep == *"NEW	account	maint1	0:"* ]]'
cert 8; t0=$(date +%s); admin "sleep 120" >/dev/null 2>&1; took=$(( $(date +%s) - t0 ))
expect "server ends a running admin command at the end ($took s for 8 s)" '[[ $took -le 10 ]]'
expect "certificate refused after its end" '! admin true >/dev/null 2>&1'
podman exec wv-admin-test sh -c 'groupadd -f docker; useradd -m -G docker wv-bad' >/dev/null 2>&1; cert 120
out=$(admin "sudo sh -s -- prepare opc wv-bad '$CA' '$D' '$E'" < "$B"); expect "refuses an everyday account in docker" '[[ $out == *"FAIL wv-bad is in group docker"* ]]'
out=$(admin "sudo sh -s -- prepare 'opc;id' wv-agent x y z" < "$B"); expect "refuses a bad name before using it" '[[ $out == "FAIL admin account name" ]]'
podman exec wv-admin-test sh -c "useradd -m adm2; install -d -o adm2 -m 700 /home/adm2/.ssh; echo 'cert-authority,principals=\"wv-admin\" $CA' > /home/adm2/.ssh/authorized_keys"
out=$(admin "sudo sh -s -- finalize adm2 '$CA'" < "$B"); expect "finalize refuses without the emergency key" '[[ $out == *"emergency key is missing"* ]]'
end=$(( $(date +%s) + 60 ))
out=$(podman exec -u opc -e TMPDIR=/nonexistent -e SSH_ORIGINAL_COMMAND="echo SHOULD-NOT" wv-admin-test sh /usr/local/lib/wundervault/wv-admin-session $end 2>&1)
expect "session check timer cannot start -> refused (fails closed)" '[[ $out != *SHOULD-NOT* && $out == *refused* ]]'
podman exec wv-admin-test mv /usr/local/lib/wundervault/wv-admin-session /tmp/x; cert 60
expect "session check missing -> admin refused (fails closed)" '! admin "echo SHOULD-NOT" 2>/dev/null | grep -q SHOULD-NOT'
expect "...while the everyday key still works" '[[ $(daily "id -un") == wv-agent ]]'
expect "...and the emergency key still works" '[[ $(ssh "${O[@]}" -i "$W/emerg" opc@127.0.0.1 "echo ok") == ok ]]'
podman exec wv-admin-test mv /tmp/x /usr/local/lib/wundervault/wv-admin-session
echo; [ "$FAILS" = 0 ] && echo "ALL PASS" || echo "$FAILS FAILED"
exit "$FAILS"
