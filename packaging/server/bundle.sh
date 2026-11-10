#!/bin/sh
# Build wv-setup.bundled.sh: wv-setup.sh with wv-admin-session and wv-check embedded, so the
# helper app sends one fixed file to the server.
set -eu
cd "$(dirname "$0")"
python3 - <<'PY'
s = open('wv-setup.sh').read()
for tag, f in (('@@WV_ADMIN_SESSION@@', 'wv-admin-session'), ('@@WV_CHECK@@', 'wv-check')):
    body = open(f).read().rstrip('\n')
    assert 'WVSESSION' not in body and 'WVCHECK' not in body
    assert s.count(tag) == 1
    s = s.replace(tag, body)
open('wv-setup.bundled.sh', 'w').write(s)
PY
sh -n wv-setup.bundled.sh
echo "wv-setup.bundled.sh $(sha256sum wv-setup.bundled.sh | cut -c1-16)"
