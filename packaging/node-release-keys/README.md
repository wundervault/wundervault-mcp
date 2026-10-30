# Pinned Node.js release keys

Put the Node.js release team's public OpenPGP keys in this directory, one
ASCII-armored `.asc` file per key. The authoritative list of release keys is:

https://github.com/nodejs/node#release-keys

Check each fingerprint against that list through a trusted channel before
committing the key. Changes to this directory change which Node distributions
the owner can approve, so review them as trust-root changes. Do not put private
keys here.

`scripts/release-record.mjs` refuses to run if this directory contains no `.asc`
files. It imports only these pinned keys into a temporary, isolated GPG keyring
and verifies `SHASUMS256.txt.sig` before reading any Node distribution hashes.
It does not obtain keys from a keyserver or use the operator's normal keyring.

No key material is supplied here: verified Node release public keys must be
added before producing a release record.
