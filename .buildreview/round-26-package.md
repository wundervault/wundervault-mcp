# Review package — round 26
generated 2026-11-14T05:28:16+00:00

## Spec — judge the build against THIS

# Helper 2.5.1 — dependency security update (2026-11-14)

Scope: dependency update only. No source (src/) change. Cut from tag v2.5.0.

## Acceptance checks
1. `npm audit --omit=dev` reports 0 vulnerabilities (was 10: 1 critical, 6 high, 3 moderate).
2. package.json requires `@modelcontextprotocol/sdk` >= 1.32.2 (the version that clears every SDK advisory), so `npm install -g` users also get the fixed SDK.
3. The lockfile pins the fixed versions; the release package (scripts/pack-app.mjs: `npm ci --omit=dev` from the lockfile) contains SDK 1.32.2 and zod >= 4.6.6, and the closure check passes.
4. No src/ file changed; `tsc` builds clean.
5. Full test suite passes.
6. MCP protocol output (initialize, tools/list including every tool's input schema, a tools/call, an unknown method) is byte-identical to 2.5.0.
7. Version is 2.5.1 in package.json, package-lock.json, server.json; CHANGELOG has a 2.5.1 entry that states accurately what changed and why.
8. Dev-only advisories (vitest/esbuild/tinypool, not shipped) are out of scope and stated as such.


## What was built this round, and how it was tested

Round 2 of this build (previous round = round-25, triage attached). Flaky test now identified: test/lock.test.ts 'reports the credential as taken while held, and free once released' — fails identically on unchanged v2.5.0 (old deps) under load, so pre-existing. 2.5.1: that file 10/10 passes; full suite run2 + run3 both 2519/2519. Everything else unchanged from the previous round's notes: audit --omit=dev 0; tsc clean; stdio protocol output byte-identical to 2.5.0; pack-app closure check passed, archive has sdk 1.32.2 / zod 4.6.7 and answers initialize + tools/list. Helper uses only Server + StdioServerTransport + types from the SDK.

## Diff

```diff
diff --git a/CHANGELOG.md b/CHANGELOG.md
index caa0f04..9f283fb 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -4,6 +4,18 @@ Changes to `@wundervault/mcp-server`: the MCP server, the broker (`wundervault-a
 installers. The full history, with the website's changes beside it, is at
 <https://wundervault.com/changelog>.
 
+## [2.5.1] — 2026-11-14
+
+Update from the vault: Computers › Update now. No change to what the helper app does.
+
+### Security
+
+- Updated the MCP library (`@modelcontextprotocol/sdk` 1.29.0 → 1.32.2) and the parts it brings in
+  (`zod`, `proxy-addr`, `body-parser`, `qs`, `ip-address`, `fast-uri`, `@hono/node-server` and others).
+  `npm audit --omit=dev` went from 10 advisories (1 critical, 6 high) to none. The fixed problems are in the
+  library's web-server and sign-in parts, which the helper app does not use (it talks to agents over
+  stdin/stdout only), so no known attack reached it; this keeps it that way.
+
 ## [2.5.0] — 2026-11-13
 
 Update from the vault: Computers › Update now. Needs wundervault.com 1.5.0 (live with this release).
diff --git a/SPEC-2.5.1-deps.md b/SPEC-2.5.1-deps.md
new file mode 100644
index 0000000..0b9fd55
--- /dev/null
+++ b/SPEC-2.5.1-deps.md
@@ -0,0 +1,13 @@
+# Helper 2.5.1 — dependency security update (2026-11-14)
+
+Scope: dependency update only. No source (src/) change. Cut from tag v2.5.0.
+
+## Acceptance checks
+1. `npm audit --omit=dev` reports 0 vulnerabilities (was 10: 1 critical, 6 high, 3 moderate).
+2. package.json requires `@modelcontextprotocol/sdk` >= 1.32.2 (the version that clears every SDK advisory), so `npm install -g` users also get the fixed SDK.
+3. The lockfile pins the fixed versions; the release package (scripts/pack-app.mjs: `npm ci --omit=dev` from the lockfile) contains SDK 1.32.2 and zod >= 4.6.6, and the closure check passes.
+4. No src/ file changed; `tsc` builds clean.
+5. Full test suite passes.
+6. MCP protocol output (initialize, tools/list including every tool's input schema, a tools/call, an unknown method) is byte-identical to 2.5.0.
+7. Version is 2.5.1 in package.json, package-lock.json, server.json; CHANGELOG has a 2.5.1 entry that states accurately what changed and why.
+8. Dev-only advisories (vitest/esbuild/tinypool, not shipped) are out of scope and stated as such.
diff --git a/package-lock.json b/package-lock.json
index f61d170..0d358c8 100644
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,15 +1,15 @@
 {
   "name": "@wundervault/mcp-server",
-  "version": "2.5.0",
+  "version": "2.5.1",
   "lockfileVersion": 3,
   "requires": true,
   "packages": {
     "": {
       "name": "@wundervault/mcp-server",
-      "version": "2.5.0",
+      "version": "2.5.1",
       "license": "AGPL-3.0-or-later",
       "dependencies": {
-        "@modelcontextprotocol/sdk": "^1.29.0",
+        "@modelcontextprotocol/sdk": "^1.32.2",
         "@noble/curves": "^2.4.0",
         "@noble/hashes": "^2.4.0"
       },
@@ -623,15 +623,15 @@
       }
     },
     "node_modules/@hono/node-server": {
-      "version": "1.19.14",
-      "resolved": "https://registry.npmjs.org/@hono/node-server/-/node-server-1.19.14.tgz",
-      "integrity": "sha512-GwtvgtXxnWsucXvbQXkRgqksiH2Qed37H9xHZocE5sA3N8O8O8/8FA3uclQXxXVzc9XBZuEOMK7+r02FmSpHtw==",
+      "version": "2.1.8",
+      "resolved": "https://registry.npmjs.org/@hono/node-server/-/node-server-2.1.8.tgz",
+      "integrity": "sha512-jdf7FHh6A1lzjpHHQUgxsg2GeER2vMetnAOfeActzcoli6jamlK+NAwL6Dsr5Fl3BS3tYUQzCdtZjU8Qxv7bEA==",
       "license": "MIT",
       "engines": {
-        "node": ">=18.14.1"
+        "node": ">=20"
       },
       "peerDependencies": {
-        "hono": "^4"
+        "hono": "^4 || ^5.0.0-0"
       }
     },
     "node_modules/@jest/schemas": {
@@ -655,12 +655,12 @@
       "license": "MIT"
     },
     "node_modules/@modelcontextprotocol/sdk": {
-      "version": "1.29.0",
-      "resolved": "https://registry.npmjs.org/@modelcontextprotocol/sdk/-/sdk-1.29.0.tgz",
-      "integrity": "sha512-zo37mZA9hJWpULgkRpowewez1y6ML5GsXJPY8FI0tBBCd77HEvza4jDqRKOXgHNn867PVGCyTdzqpz0izu5ZjQ==",
+      "version": "1.32.2",
+      "resolved": "https://registry.npmjs.org/@modelcontextprotocol/sdk/-/sdk-1.32.2.tgz",
+      "integrity": "sha512-SWsVtH/0vULSQStoZ6xxH2K09Li8fXYTMC64ZeogCdpZ3XSi1eCPOByV1OpuJxuI3OcmHhosDWYyii07tpPsLw==",
       "license": "MIT",
       "dependencies": {
-        "@hono/node-server": "^1.19.9",
+        "@hono/node-server": "^1.19.9 || ^2.0.5",
         "ajv": "^8.17.1",
         "ajv-formats": "^3.0.1",
         "content-type": "^1.0.5",
@@ -1275,20 +1275,20 @@
       }
     },
     "node_modules/body-parser": {
-      "version": "2.2.2",
-      "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-2.2.2.tgz",
-      "integrity": "sha512-oP5VkATKlNwcgvxi0vM0p/D3n2C3EReYVX+DNYs5TjZFn/oQt2j+4sVJtSMr18pdRr8wjTcBl6LoV+FUwzPmNA==",
+      "version": "2.4.0",
+      "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-2.4.0.tgz",
+      "integrity": "sha512-Ifk1KcLrxaGt1occQagQNFNNOqRt1LFuehEnHHzB8Z6cRgIxRU1TBaiIsUiCdA+gy5PL7Y1IX31DNKkRmxtXjQ==",
       "license": "MIT",
       "dependencies": {
         "bytes": "^3.1.2",
-        "content-type": "^1.0.5",
+        "content-type": "^2.1.0",
         "debug": "^4.4.3",
-        "http-errors": "^2.0.0",
-        "iconv-lite": "^0.7.0",
+        "http-errors": "^2.0.1",
+        "iconv-lite": "^0.7.3",
         "on-finished": "^2.4.1",
-        "qs": "^6.14.1",
-        "raw-body": "^3.0.1",
-        "type-is": "^2.0.1"
+        "qs": "^6.16.1",
+        "raw-body": "^3.0.2",
+        "type-is": "^2.1.0"
       },
       "engines": {
         "node": ">=18"
@@ -1298,6 +1298,19 @@
         "url": "https://opencollective.com/express"
       }
     },
+    "node_modules/body-parser/node_modules/content-type": {
+      "version": "2.1.0",
+      "resolved": "https://registry.npmjs.org/content-type/-/content-type-2.1.0.tgz",
+      "integrity": "sha512-mj7UPXE0jaqaOsukNZRUEfEi2AcL7C/vwmwcHV0O97eO1E1pxBZuyjlZrx5seTaNBg1U6+o35wpa35Qfcc+7ag==",
+      "license": "MIT",
+      "engines": {
+        "node": ">=18"
+      },
+      "funding": {
+        "type": "opencollective",
+        "url": "https://opencollective.com/express"
+      }
+    },
     "node_modules/bytes": {
       "version": "3.1.2",
       "resolved": "https://registry.npmjs.org/bytes/-/bytes-3.1.2.tgz",
@@ -1616,9 +1629,9 @@
       }
     },
     "node_modules/es-object-atoms": {
-      "version": "1.1.1",
-      "resolved": "https://registry.npmjs.org/es-object-atoms/-/es-object-atoms-1.1.1.tgz",
-      "integrity": "sha512-FGgH2h8zKNim9ljj7dankFPcICIK9Cp5bm+c2gQSYePhpaG5+esrLODihIorn+Pe6FGJzWhXQotPv73jTaldXA==",
+      "version": "1.1.2",
+      "resolved": "https://registry.npmjs.org/es-object-atoms/-/es-object-atoms-1.1.2.tgz",
+      "integrity": "sha512-HWcBoN6NileqtSydK2FqHbS/LoDd2pqrnQHLyJzBj4kOp/ky2MWMN694xOfkK8/SnUsW2DH7EfyVlydKCsm1Zw==",
       "license": "MIT",
       "dependencies": {
         "es-errors": "^1.3.0"
@@ -1780,12 +1793,13 @@
       }
     },
     "node_modules/express-rate-limit": {
-      "version": "8.3.2",
-      "resolved": "https://registry.npmjs.org/express-rate-limit/-/express-rate-limit-8.3.2.tgz",
-      "integrity": "sha512-77VmFeJkO0/rvimEDuUC5H30oqUC4EyOhyGccfqoLebB0oiEYfM7nwPrsDsBL1gsTpwfzX8SFy2MT3TDyRq+bg==",
+      "version": "8.7.4",
+      "resolved": "https://registry.npmjs.org/express-rate-limit/-/express-rate-limit-8.7.4.tgz",
+      "integrity": "sha512-LKBXzX700wz3zAGNNmVnjRI5mEbYkLv7UbMI4+9Xa+JPcg2UZh6AgY/2CZh9RrJjFM5ttC/N1lD+KzyFoZITCw==",
       "license": "MIT",
       "dependencies": {
-        "ip-address": "10.1.0"
+        "debug": "^4.4.3",
+        "ip-address": "^10.2.0"
       },
       "engines": {
         "node": ">= 16"
@@ -1804,9 +1818,9 @@
       "license": "MIT"
     },
     "node_modules/fast-uri": {
-      "version": "3.1.0",
-      "resolved": "https://registry.npmjs.org/fast-uri/-/fast-uri-3.1.0.tgz",
-      "integrity": "sha512-iPeeDKJSWf4IEOasVVrknXpaBV0IApz/gp7S2bb7Z4Lljbl2MGJRqInZiUrQwV16cpzw/D3S5j5Julj/gT52AA==",
+      "version": "3.1.9",
+      "resolved": "https://registry.npmjs.org/fast-uri/-/fast-uri-3.1.9.tgz",
+      "integrity": "sha512-hS/0Wt3Ya043oKXs0sIxrMpKQITXhMLIrVAKKXi4gozGC9v7YRWVnXIZzjNPTO02M9BdxLCWqK1yRXgNziVyJQ==",
       "funding": [
         {
           "type": "github",
@@ -1967,9 +1981,9 @@
       }
     },
     "node_modules/hasown": {
-      "version": "2.0.2",
-      "resolved": "https://registry.npmjs.org/hasown/-/hasown-2.0.2.tgz",
-      "integrity": "sha512-0hJU9SCPvmMzIBdZFqNPXWa6dqh7WdH0cII9y+CyS8rG3nL48Bclra9HmKhVVUHyPWNH5Y7xDwAB7bfgSjkUMQ==",
+      "version": "2.0.4",
+      "resolved": "https://registry.npmjs.org/hasown/-/hasown-2.0.4.tgz",
+      "integrity": "sha512-T2UbfbBEF32wiepXIsMlTW9+dDYC6wMh/t/vYA4tuOMKqWz/n3vr1NFSxQiyP+zk2mXsoMA/i/7qV6LKut1t1A==",
       "license": "MIT",
       "dependencies": {
         "function-bind": "^1.1.2"
@@ -1979,9 +1993,9 @@
       }
     },
     "node_modules/hono": {
-      "version": "4.12.12",
-      "resolved": "https://registry.npmjs.org/hono/-/hono-4.12.12.tgz",
-      "integrity": "sha512-p1JfQMKaceuCbpJKAPKVqyqviZdS0eUxH9v82oWo1kb9xjQ5wA6iP3FNVAPDFlz5/p7d45lO+BpSk1tuSZMF4Q==",
+      "version": "4.13.18",
+      "resolved": "https://registry.npmjs.org/hono/-/hono-4.13.18.tgz",
+      "integrity": "sha512-H9q/E1XizaWstJxUW881dmLxEj+t/TrGGnyxINkm4+sK0qUwsMtFdo2BWI9Vs3cIS19MU6b6iCijoUoEf4f3DA==",
       "license": "MIT",
       "engines": {
         "node": ">=16.9.0"
@@ -2031,9 +2045,9 @@
       }
     },
     "node_modules/iconv-lite": {
-      "version": "0.7.2",
-      "resolved": "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.7.2.tgz",
-      "integrity": "sha512-im9DjEDQ55s9fL4EYzOAv0yMqmMBSZp6G0VvFyTMPKWxiSBHUj9NW/qqLmXUwXrrM7AvqSlTCfvqRb0cM8yYqw==",
+      "version": "0.7.3",
+      "resolved": "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.7.3.tgz",
+      "integrity": "sha512-IKXpvIzjnC9XTAUbVBcMfGS0EPaIXtW6v+zr+RRp+hqULEpo0owZax6wyRwPOJbWbzjYspQwusTsfVr0ifh4uQ==",
       "license": "MIT",
       "dependencies": {
         "safer-buffer": ">= 2.1.2 < 3.0.0"
@@ -2053,9 +2067,9 @@
       "license": "ISC"
     },
     "node_modules/ip-address": {
-      "version": "10.1.0",
-      "resolved": "https://registry.npmjs.org/ip-address/-/ip-address-10.1.0.tgz",
-      "integrity": "sha512-XXADHxXmvT9+CRxhXg56LJovE+bmWnEWB78LB83VZTprKTmaC5QfruXocxzTZ2Kl0DNwKuBdlIhjL8LeY8Sf8Q==",
+      "version": "10.7.6",
+      "resolved": "https://registry.npmjs.org/ip-address/-/ip-address-10.7.6.tgz",
+      "integrity": "sha512-00LYkM6byILa9eQIx6qoaXCM40xTLd56AZ4vyaPW3YTyb49VZYPo5xsiAq4tuQ54GH4R7gVdYScJ1B7B77PuTg==",
       "license": "MIT",
       "engines": {
         "node": ">= 12"
@@ -2327,9 +2341,9 @@
       "license": "MIT"
     },
     "node_modules/nanoid": {
-      "version": "3.3.11",
-      "resolved": "https://registry.npmjs.org/nanoid/-/nanoid-3.3.11.tgz",
-      "integrity": "sha512-N8SpfPUnUp1bK+PMYW8qSWdl9U+wwNWI4QKxOYDy9JAro3WMX7p2OeVRF9v+347pnakNevPmiHhNmZ2HbFA76w==",
+      "version": "3.3.20",
+      "resolved": "https://registry.npmjs.org/nanoid/-/nanoid-3.3.20.tgz",
+      "integrity": "sha512-uKdg2G3GNCKQn9byYOpxbGqrT2fGO5KRt5J/8b3pok8rT6qxGWF6hxMyJiEYtAf+FVyYuD9hRaDqX5uPFYJ4ZQ==",
       "dev": true,
       "funding": [
         {
@@ -2551,9 +2565,9 @@
       "license": "MIT"
     },
     "node_modules/postcss": {
-      "version": "8.5.9",
-      "resolved": "https://registry.npmjs.org/postcss/-/postcss-8.5.9.tgz",
-      "integrity": "sha512-7a70Nsot+EMX9fFU3064K/kdHWZqGVY+BADLyXc8Dfv+mTLLVl6JzJpPaCZ2kQL9gIJvKXSLMHhqdRRjwQeFtw==",
+      "version": "8.5.33",
+      "resolved": "https://registry.npmjs.org/postcss/-/postcss-8.5.33.tgz",
+      "integrity": "sha512-RVHEU9/Pp1Fnjr/MpAJsZoADukCKhfIi15OunEYiGktIkYLkPVvC1sioWolGDS7XByMTx9m/IGbro0Js13zhnQ==",
       "dev": true,
       "funding": [
         {
@@ -2571,9 +2585,9 @@
       ],
       "license": "MIT",
       "dependencies": {
-        "nanoid": "^3.3.11",
+        "nanoid": "^3.3.20",
         "picocolors": "^1.1.1",
-        "source-map-js": "^1.2.1"
+        "source-map-js": "^1.2.2"
       },
       "engines": {
         "node": "^10 || ^12 || >=14"
@@ -2595,9 +2609,9 @@
       }
     },
     "node_modules/proxy-addr": {
-      "version": "2.0.7",
-      "resolved": "https://registry.npmjs.org/proxy-addr/-/proxy-addr-2.0.7.tgz",
-      "integrity": "sha512-llQsMLSUDUPT44jdrU/O37qlnifitDP+ZwrmmZcoSKyLKvtZxpyV0n2/bD/N4tBAAZ/gJEdZU7KMraoK1+XYAg==",
+      "version": "2.0.8",
+      "resolved": "https://registry.npmjs.org/proxy-addr/-/proxy-addr-2.0.8.tgz",
+      "integrity": "sha512-5nnx0yGyVUcY6t9RnWcARWtwT9F1D8O9rt08htPvnd49W1IgZtmLkhu9WfMzQj1cFxjHIO6connUNVW5k7AVyQ==",
       "license": "MIT",
       "dependencies": {
         "forwarded": "0.2.0",
@@ -2605,6 +2619,10 @@
       },
       "engines": {
         "node": ">= 0.10"
+      },
+      "funding": {
+        "type": "opencollective",
+        "url": "https://opencollective.com/express"
       }
     },
     "node_modules/punycode": {
@@ -2618,12 +2636,13 @@
       }
     },
     "node_modules/qs": {
-      "version": "6.15.1",
-      "resolved": "https://registry.npmjs.org/qs/-/qs-6.15.1.tgz",
-      "integrity": "sha512-6YHEFRL9mfgcAvql/XhwTvf5jKcOiiupt2FiJxHkiX1z4j7WL8J/jRHYLluORvc1XxB5rV20KoeK00gVJamspg==",
+      "version": "6.17.1",
+      "resolved": "https://registry.npmjs.org/qs/-/qs-6.17.1.tgz",
+      "integrity": "sha512-jd3COkaKVgGUW+ZHyEHCG9bH7RoaaiWuMgzsIBjUMVjLAaWGWpoUAVwljVvBHxRu/2qEHnadLGZrkutYUBPQJA==",
       "license": "BSD-3-Clause",
       "dependencies": {
-        "side-channel": "^1.1.0"
+        "es-define-property": "^1.0.1",
+        "side-channel": "^1.1.1"
       },
       "engines": {
         "node": ">=0.6"
@@ -2825,14 +2844,14 @@
       }
     },
     "node_modules/side-channel": {
-      "version": "1.1.0",
-      "resolved": "https://registry.npmjs.org/side-channel/-/side-channel-1.1.0.tgz",
-      "integrity": "sha512-ZX99e6tRweoUXqR+VBrslhda51Nh5MTQwou5tnUDgbtyM0dBgmhEDtWGP/xbKn6hqfPRHujUNwz5fy/wbbhnpw==",
+      "version": "1.1.1",
+      "resolved": "https://registry.npmjs.org/side-channel/-/side-channel-1.1.1.tgz",
+      "integrity": "sha512-6x6dK6zJdpTzF4sQeNYxwtvBzf6Eg4GtlesS94HOvTudUeyK2WXAaIfmDgsyslYrRBeFIlsi54AYsFGUuhmvrQ==",
       "license": "MIT",
       "dependencies": {
         "es-errors": "^1.3.0",
-        "object-inspect": "^1.13.3",
-        "side-channel-list": "^1.0.0",
+        "object-inspect": "^1.13.4",
+        "side-channel-list": "^1.0.1",
         "side-channel-map": "^1.0.1",
         "side-channel-weakmap": "^1.0.2"
       },
@@ -2917,9 +2936,9 @@
       }
     },
     "node_modules/source-map-js": {
-      "version": "1.2.1",
-      "resolved": "https://registry.npmjs.org/source-map-js/-/source-map-js-1.2.1.tgz",
-      "integrity": "sha512-UXWMKhLOwVKb728IUtQPXxfYU+usdybtUrK/8uGE8CQMvrhOpwvzDBwj0QhSL7MQc7vIsISBG8VQ8+IDQxpfQA==",
+      "version": "1.2.2",
+      "resolved": "https://registry.npmjs.org/source-map-js/-/source-map-js-1.2.2.tgz",
+      "integrity": "sha512-KGj/8Y43x35aZVDtt+J4mK1hoLGHULMYfSkODJNQjNDC3oW1PqPoxMwo0pLUsWM/UEGzON/NxeHywEfNXNP3Vw==",
       "dev": true,
       "license": "BSD-3-Clause",
       "engines": {
@@ -3075,17 +3094,34 @@
       }
     },
     "node_modules/type-is": {
-      "version": "2.0.1",
-      "resolved": "https://registry.npmjs.org/type-is/-/type-is-2.0.1.tgz",
-      "integrity": "sha512-OZs6gsjF4vMp32qrCbiVSkrFmXtG/AZhY3t0iAMrMBiAZyV9oALtXO8hsrHbMXF9x6L3grlFuwW2oAz7cav+Gw==",
+      "version": "2.1.0",
+      "resolved": "https://registry.npmjs.org/type-is/-/type-is-2.1.0.tgz",
+      "integrity": "sha512-faYHw0anBbc/kWF3zFTEnxSFOAGUX9GFbOBthvDdLsIlEoWOFOtS0zgCiQYwIskL9iGXZL3kAXD8OoZ4GmMATA==",
       "license": "MIT",
       "dependencies": {
-        "content-type": "^1.0.5",
+        "content-type": "^2.0.0",
         "media-typer": "^1.1.0",
         "mime-types": "^3.0.0"
       },
       "engines": {
-        "node": ">= 0.6"
+        "node": ">= 18"
+      },
+      "funding": {
+        "type": "opencollective",
+        "url": "https://opencollective.com/express"
+      }
+    },
+    "node_modules/type-is/node_modules/content-type": {
+      "version": "2.1.0",
+      "resolved": "https://registry.npmjs.org/content-type/-/content-type-2.1.0.tgz",
+      "integrity": "sha512-mj7UPXE0jaqaOsukNZRUEfEi2AcL7C/vwmwcHV0O97eO1E1pxBZuyjlZrx5seTaNBg1U6+o35wpa35Qfcc+7ag==",
+      "license": "MIT",
+      "engines": {
+        "node": ">=18"
+      },
+      "funding": {
+        "type": "opencollective",
+        "url": "https://opencollective.com/express"
       }
     },
     "node_modules/typescript": {
@@ -3110,9 +3146,9 @@
       "license": "MIT"
     },
     "node_modules/undici": {
-      "version": "8.10.2",
-      "resolved": "https://registry.npmjs.org/undici/-/undici-8.10.2.tgz",
-      "integrity": "sha512-/y4/bH9YNU5hi9NIrpOuvGXFcxrj3CMrV+/AYpowAYTpHn8gX/XPFjNy766FPoYY0miQhdW977JFWKGNhBdwyQ==",
+      "version": "8.12.4",
+      "resolved": "https://registry.npmjs.org/undici/-/undici-8.12.4.tgz",
+      "integrity": "sha512-8Mx+uNKKER2bA4AdtedkqRbwUCIJFr2nJckXRe5yrDqzePqwLP7VNcctN8/XdmDSbF7mS+jJKIszlL+vbam1VA==",
       "dev": true,
       "license": "MIT",
       "engines": {
@@ -3410,9 +3446,9 @@
       }
     },
     "node_modules/zod": {
-      "version": "4.3.6",
-      "resolved": "https://registry.npmjs.org/zod/-/zod-4.3.6.tgz",
-      "integrity": "sha512-rftlrkhHZOcjDwkGlnUtZZkvaPHCsDATp4pGpuOOMDaTdDDXF91wuVDJoWoPsKX/3YPQ5fHuF3STjcYyKr+Qhg==",
+      "version": "4.6.7",
+      "resolved": "https://registry.npmjs.org/zod/-/zod-4.6.7.tgz",
+      "integrity": "sha512-g8W2D2kU6a8untc053fX1uVBKzM7yqAxW/3zwk83+6RyF2+SKOuV+c0wBDhUwzV1PaGapmZH+rmcUzPf+3CGwg==",
       "license": "MIT",
       "funding": {
         "url": "https://github.com/sponsors/colinhacks"
diff --git a/package.json b/package.json
index b54ccc0..2588f9a 100644
--- a/package.json
+++ b/package.json
@@ -1,7 +1,7 @@
 {
   "name": "@wundervault/mcp-server",
   "mcpName": "io.github.wundervault/wundervault-mcp",
-  "version": "2.5.0",
+  "version": "2.5.1",
   "description": "AI agents use your API keys, SSH keys and wallets through a local broker, never holding them",
   "files": [
     "dist",
@@ -43,7 +43,7 @@
     "wundervault-agent": "bin/wundervault-agent"
   },
   "dependencies": {
-    "@modelcontextprotocol/sdk": "^1.29.0",
+    "@modelcontextprotocol/sdk": "^1.32.2",
     "@noble/curves": "^2.4.0",
     "@noble/hashes": "^2.4.0"
   },
diff --git a/server.json b/server.json
index e1be4a6..86e470d 100644
--- a/server.json
+++ b/server.json
@@ -7,12 +7,12 @@
     "source": "github"
   },
   "websiteUrl": "https://wundervault.com",
-  "version": "2.5.0",
+  "version": "2.5.1",
   "packages": [
     {
       "registryType": "npm",
       "identifier": "@wundervault/mcp-server",
-      "version": "2.5.0",
+      "version": "2.5.1",
       "transport": {
         "type": "stdio"
       },

```

## File: package.json

```
{
  "name": "@wundervault/mcp-server",
  "mcpName": "io.github.wundervault/wundervault-mcp",
  "version": "2.5.1",
  "description": "AI agents use your API keys, SSH keys and wallets through a local broker, never holding them",
  "files": [
    "dist",
    "bin",
    "README.md",
    "README-AGENTS.md",
    "CHANGELOG.md",
    "packaging"
  ],
  "scripts": {
    "build": "tsc",
    "test": "vitest run",
    "prepublishOnly": "npm run build && npm test"
  },
  "keywords": [
    "mcp",
    "model-context-protocol",
    "secrets",
    "vault",
    "zero-knowledge",
    "ai-agents"
  ],
  "author": "Wundervault",
  "license": "AGPL-3.0-or-later",
  "homepage": "https://wundervault.com",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/wundervault/wundervault-mcp.git"
  },
  "bugs": {
    "url": "https://github.com/wundervault/wundervault-mcp/issues"
  },
  "type": "module",
  "engines": {
    "node": "^22.23.4 || ^24.22.1 || ^26.12.1 || >=27"
  },
  "bin": {
    "wundervault-mcp": "bin/wundervault-mcp",
    "wundervault-agent": "bin/wundervault-agent"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.32.2",
    "@noble/curves": "^2.4.0",
    "@noble/hashes": "^2.4.0"
  },
  "devDependencies": {
    "@types/node": "^20.19.39",
    "jsdom": "^30.0.1",
    "typescript": "^5.9.3",
    "vitest": "^1.6.1"
  }
}

```

## File: scripts/pack-app.mjs

```
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { args, required, main } from './lib/release-cli.mjs';
import { collectTree, buildArchive } from './lib/ustar.mjs';
import { checkClosure } from './lib/closure-check.mjs';

main(() => {
  const values = args({ out: { type: 'string' } });
  required(values, ['out']);
  const root = process.cwd();
  const out = path.resolve(values.out);
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(pkg.version)) {
    throw new Error('package.json must have an X.Y.Z version');
  }
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'wundervault-pack-'));
  try {
    for (const name of ['package.json', 'package-lock.json']) {
      const source = path.join(root, name);
      if (!fs.lstatSync(source).isFile()) throw new Error(`Regular file required: ${source}`);
      fs.copyFileSync(source, path.join(temp, name));
    }
    execFileSync('npm', ['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'], {
      cwd: temp,
      stdio: 'inherit',
    });
    const modules = path.join(temp, 'node_modules');
    fs.mkdirSync(modules, { recursive: true });
    fs.rmSync(path.join(modules, '.bin'), { recursive: true, force: true });
    checkClosure(modules);

    const entries = [{ path: 'app', directory: true }];
    for (const name of ['package.json', 'README.md', 'CHANGELOG.md', 'bin', 'dist', 'packaging']) {
      entries.push(...collectTree(path.join(root, name), `app/${name}`, (name, directory) =>
        directory || !name.startsWith('app/dist/') ||
        (!name.endsWith('.d.ts') && !name.endsWith('.d.ts.map'))));
    }
    entries.push(...collectTree(modules, 'app/node_modules'));
    const result = buildArchive(entries);
    fs.mkdirSync(out, { recursive: true });
    const archivePath = path.join(out, `wundervault-app-${pkg.version}.tar.gz`);
    const filesPath = path.join(out, 'app-files.json');
    fs.writeFileSync(archivePath, result.archive);
    fs.writeFileSync(filesPath, JSON.stringify({
      version: pkg.version,
      sha256: result.sha256,
      files: result.files,
    }));
    console.log(archivePath);
    console.log(filesPath);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

```

## Already ruled on in earlier rounds

Do not raise these again unless you have new evidence, and name the evidence if you do.

- [round 1 F2] deferred: Delete the lock file, start a frozen OLDER copy of the package, and it starts alongside a live holder because it has no process scan.
  reason: True and unfixable from inside this repo — an old build cannot be taught to scan. Explicitly out of scope per the spec (frozen copies are not being rebuilt), but it means the invariant is only restored box-wide once Byte's copy in ~/.openclaw/workspace/node_modules is updated. Raised to the user as a real remaining gap, not closed.
- [round 1 B2] rejected: Agent names 'Team A' and 'Team?A' both slug to mcp-Team_A.lock and can clobber each other's lock.
  reason: Real but not fixable under this spec's compatibility constraint: changing the filename breaks every older copy on the box that reads mcp-<slug>.lock, which is a strictly worse failure. Impact is now small because arbitration is by process and the scan compares the RAW agent name from environ, not the slug. Documented, not changed.
- [round 1 B1] deferred: Containers with disjoint /proc views sharing one home directory cannot be disambiguated by a host-local (pid, start) pair.
  reason: Correct, and out of scope — no such deployment exists here. Worth recording as a known boundary of the design rather than pretending the lock is namespace-safe.
- [round 1 B3] deferred: On non-Linux there is no incarnation evidence, so a stale lock naming a reused PID refuses forever and points at the wrong process.
  reason: Accurate. Mitigated in practice by fix 2 of this build: the refusal is now legible and names the PID, so an operator can see it is wrong and delete the lock, instead of staring at CONNECTION_CLOSED. A real fix needs a non-/proc incarnation source; noted, not built.
- [round 2 F4] rejected: A reparented (PPID 1) holder yields no parent hint, so the blocked user gets no way to identify the owning session.
  reason: Accurate but not a defect. PID and connection time are still reported and are enough to find the process; naming init would identify nothing. Deliberately not falling back to the parent's argv, which is where a useful-looking hint would have to come from and which can contain tokens — that was blocker F4 in round 1.
- [round 3 B1] deferred: Any local process can bind the predictable address and impersonate occupancy without being an MCP server.
  reason: True and inherent to any same-UID lock — a process that can bind your address can also read your lock file, your socket and your home directory. It denies service rather than granting it, which is the safe direction, and the identity banner now makes an impostor visible (it cannot produce the protocol line, so the refusal reports the holder as unknown rather than pretending). Not fixable without an authenticated channel, which is out of proportion here.
- [round 3 B3] deferred: The suite covers the lock module and cross-process behaviour but not full MCP initialization, tool listing, tool rejection, or holder turnover.
  reason: Fair. Those paths ARE exercised, but by hand against the live daemon rather than in the suite — handshake, vault_status only, vault-tool rejection, and standing down for this machine's older-build holder. Worth turning into a spawned-server integration test; noted rather than done, and called out to the owner as the weakest part of the coverage.
- [round 4 F1] deferred: A rebuilt instance and a frozen pre-socket instance can both serve if they interleave around the old build's non-atomic pid-file check and write.
  reason: Confirmed, and NOT FIXABLE FROM THIS REPOSITORY. The race lives in code already installed elsewhere: an older build does existsSync, then readFile, then writeFile with no atomicity, and nothing a new build does can make another process's check-then-write atomic. Binding first and honouring the pid file narrows the window but cannot close it. The actual remedy is to stop having two versions — which is what publishing this and updating the frozen copies achieves. Raised to the owner explicitly rather than closed, because it means the invariant is not fully restored box-wide until every copy is updated.
- [round 6 F3] rejected: the tool API does not match the spec's vault_ssh_exec(entry_id, host, argv[], purpose)
  reason: the spec is stale, not the code. That exact signature IS round 1's F2 bug — an argv carrying its own destination alongside an advisory host field. Changing the API was the fix. Updating SPEC.md to match rather than reintroducing the vulnerability.
- [round 9 F3] rejected: a server-approved private origin is refused because the local store is empty after upgrade
  reason: already fixed before this review landed. Approvals were moved back server-side after the plan review found that a local approvals file let the agent forge its own. server.ts reads them from the entry again.
- [round 9 F5] rejected: bracketed IPv6 approvals do not round-trip through revoke
  reason: the approval API no longer exists in this module — it was deleted, not deprecated, after the plan review. The bracket bug is real in principle and will apply when approvals are rebuilt on a daemon-owned path; noted for that build.
- [round 9 F6] deferred: the token scheme has no verifier and conflicts with ProtectHome
  reason: correct, and my own plan contradicted itself here. Part B is not built. It is recorded as unresolved rather than papered over: SO_PEERCRED also reports PID and GID, not just uid as I claimed, so it is strictly stronger than a copyable bearer token.
- [round 9 F7] deferred: opt-in email for unattended runs is described but not built
  reason: true. The package describes a capability that does not exist yet. Recorded as not-built rather than claimed; the terminal channels are what works today, and an unattended run genuinely has no notice until this lands.
- [round 11 F1] deferred: On a real install the owner cannot traverse the 0770 mgmt directory, so --migrate and --destinations fail
  reason: CONFIRMED, and proved the mechanism locally against /var/cache/cups (root:lp 0770) -> Permission denied. Deferred to the same change as F2, not because it is minor but because the obvious fix (usermod -aG wundervault) hands F2's re-key attack to every agent: agents run as the owner's uid, so any permission the owner has the agent has. Needs the owner's decision on the read side; see the question put to the user.
- [round 11 F2] deferred: register_profile accepts no setup token; B2/B3/check 7 unimplemented
  reason: CONFIRMED. registerProfile (agent.ts:200) overwrites an existing profile by name INCLUDING socket_token, so whoever reaches the mgmt socket can re-key an agent and read its credentials off the per-agent socket. Fix is an auth redesign spanning onboard.py in the burnbox repo; putting the shape to the owner before building it rather than guessing.
- [round 11 B2] deferred: No test runs the installed unit with two real uids under the real systemd sandbox
  reason: Correct, and it is the reason every one of these blockers survived 366 passing tests. A real two-uid install test is the next piece of work, but it needs the install to be performed on this machine first - which is the owner's call, not mine.
- [round 11 B5] deferred: Agent names and sockets are machine-global across multiple human users
  reason: Real, but out of scope for this spec: the product targets one human per machine today and the spec's C5 already states one uid is one principal. Noted for the owner.
- [round 12 F1] rejected: Telling the user to sudo npm install into /usr/local contradicts G1's single privileged step
  reason: REJECTED on the security merits. The reviewer's implied alternative - accept the home path and bind-mount it back past ProtectHome - is worse than the problem: a directory under the user's home is writable by everything running as that user, agents included, so the daemon would execute code its own agents can replace. That hands over the process guarding the credentials, not just the credentials. G1 scopes what the INSTALLER does; where the package itself lives is a separate, pre-existing choice. Kept the refusal and added the reasoning to the message so nobody 'fixes' it later.
- [round 14 B1] deferred: The link is out of argv but still in the enrolment client's memory, under the same uid as the agents
  reason: True and irreducible at this layer: the owner has to paste the link into SOME process running as them. What the fix bought is real - argv is world-readable to every process continuously, process memory needs ptrace of a short-lived process at the right moment. Worth stating in the docs rather than pretending it is closed.
- [round 14 B2] deferred: Profile-store writes are not fsynced before rename
  reason: Real durability gap - a crash between rename and writeback can leave a truncated store. Out of scope for this phase, which is about who can read the file, not whether it survives power loss. Noted for the owner.
- [round 14 B3] deferred: Concurrent enrolments for the same link are not serialised
  reason: Real but now much narrower: the server enforces single-use, and the local window is one round trip. The remaining case needs a burn failure AND a concurrent caller, and F4 now surfaces the burn failure. Not worth a lock in this phase.
- [round 15 B1] deferred: The generated destinations HTML is a full copy of the protected audit store, written into a directory the agents can read
  reason: Real and worth stating: the page is 0600 and owned by the human, but every agent runs as that human, so any agent can read it. The store itself stays protected; what leaks is a snapshot the owner deliberately asked for. Not silently acceptable - it belongs in the docs and possibly behind a --output flag defaulting somewhere else. Raising with the owner rather than deciding alone.
- [round 15 B2] deferred: The installer refuses a home-directory ExecStart but never checks the package tree is not writable by the agent uid
  reason: Real gap with the same shape as the /home rule: a globally-installed tree that happens to be group- or world-writable lets an agent replace the daemon's own code. Worth a check in the installer. Out of scope for this round; noted.
- [round 15 B3] deferred: The rehearsal covers one systemd and kernel version
  reason: True, and MemoryDenyWriteExecute is proof the risk is not theoretical - it was in the list for two commits. The remaining directives now run verified on Ubuntu 24.04 / systemd 255. Broader coverage needs more images than this session should spend; noted for the owner.
- [round 16 B1] deferred: The privilege drop discards the invoking user's supplementary groups rather than restoring their normal set
  reason: True. setgroups([gid]) is deliberately narrow - it drops root's groups, which is the safety property - but it is not the user's real group set either. For writing one file into their own home that is sufficient and arguably safer. Worth initgroups() if this path ever does more; noted rather than changed.
- [round 16 B2] deferred: A low-uid non-login wundervault account may belong to an unrelated service
  reason: Real, and not distinguishable from the outside - an existing nologin account named wundervault could be another vendor's. The installer now says which account it is adopting and its uid. A --account flag would be the proper answer; noted for the owner.
- [round 16 B3] deferred: getent is a synchronous unbounded NSS call on the viewer path
  reason: True but confined to the short-lived CLI, never the daemon. A hung NSS lookup delays one interactive command the user can ctrl-C. Not worth async plumbing here.
- [round 16 B4] deferred: Store validation checks version and that seen is an array, not the field types the generated JS consumes
  reason: Fair - a store with the right shape and wrong field types renders a broken page rather than an error. The page is generated from our own daemon's writes, so this is corruption-only, and the honest-vs-empty distinction that mattered is fixed. Deeper schema validation noted.
- [round 18 B1] deferred: No end-to-end test with a credential materialised by a working TPM
  reason: True and unavoidable here: the rehearsal container has no TPM firmware and could not materialise credentials at all under LoadCredentialEncrypted. The ExecStartPre path IS now verified in-container with host-key sealing, which exercises the same delivery and fallback logic; only the TPM branch is untested. Flagged for the owner's own machine, which does have a TPM.
- [round 18 B2] deferred: Backup and restore semantics for the sealed store are undefined
  reason: Real and worth a runbook entry: a backup of /var/lib/wundervault restored onto different hardware will not decrypt under a TPM-sealed key. The recovery path exists - repair each agent and re-enrol - but it is not written down. Belongs in RESTORE.md; noted for the owner rather than invented now.
- [round 18 B3] deferred: No procedure to rotate or reseal the store key before TPM maintenance
  reason: Same family as B2. The mechanism supports it (delete the blob, re-run the installer, let the store migrate) but there is no documented drill. Worth writing alongside B2.
- [round 19 B1] deferred: listEntries and settings forward API response objects with no output-field allowlist
  reason: Real and worth doing, but it is a change to what the server may send rather than to what this build introduced — the same fields crossed the same boundary before, in the agent's own process. Recorded for the user as an open item rather than changed under this spec.
- [round 19 B2] deferred: No cancellation propagation or per-agent operation queue after a client disconnects
  reason: Real. An authenticated caller can start expensive work and hang up. Out of scope for this spec, which is about key custody rather than resource control, and the caller is already authenticated — so this is a cost question, not a boundary one. Recorded as an open item.
- [round 19 B3] rejected: recordDestination runs before tier approval and the SSRF check, so a refused request is still recorded as a destination
  reason: Correct about the ordering and wrong about it being a defect — it is deliberate and documented at the call site. A first sighting recorded only on success would alert again on every retry of a tier-2 request the owner had not yet answered. The store records ATTEMPTS, which is what an exposure review needs; recording only deliveries would hide precisely the attempts worth looking at. The reviewer's underlying point — that the store's meaning should be stated — is fair, and the comment already says so.
- [round 19 B4] deferred: Decrypted credentials become immutable JS strings; only the byte buffers are wiped
  reason: True and unfixable in this language. Already recorded as a known limit in the phase-5 handoff for the browser side; the same applies in the broker. Wiping the buffers is worth doing anyway and is done. Noted for the user rather than pretended away.
- [round 20 F2] rejected: server.ts still sends the old {token} request, so every agent breaks against the new broker
  reason: Wrong in fact, and correctly hedged by the reviewer ('if src/server.ts remains as described'). server.ts WAS rewritten: getCredentials and tryDaemonConnect are gone, every tool handler calls src/broker-client.ts, which sends {token, op, ...}. Evidence: grep shows zero occurrences of decryptVaultKey/decryptSecretContent/loadEncryptionKey and zero of AgentVaultAPI in server.ts, and test/key-custody.test.ts asserts the whole tool surface over the new protocol. The diff was withheld from this package for the payload cap and the notes said so — this is the blind-spot-shaped finding that arrives when you withhold a file, which is why the notes ask for exactly that flagging.
- [round 21 F3] rejected: The legacy fallback cannot open a pre-phase-7 macOS store after the uid split, because the old store was keyed on the owner uid and the daemon now runs as another
  reason: The arithmetic is right and the conclusion does not follow, because nothing ever asks the daemon to open that store. Migration deliberately carries no credentials: `--migrate` runs as the OWNER, and legacyAgentNames() in migrate.ts derives with the owner's uid to read only the agent NAMES; the credentials are replaced by REPAIR in the dashboard, which is the phase-4 design. The daemon's loadProfiles fallback exists for a store THIS ACCOUNT wrote under the previous derivation, not for the pre-split user store. Reviewer was not shown migrate.ts. What it did catch is a comment of mine that implied the fallback carried a macOS store across — that overclaim is now corrected in the source, with an explicit note not to 'fix' it into reaching across the uid boundary.
- [round 21 F7] rejected: The Windows pre-split warning changed, though the spec requires it byte-for-byte unchanged
  reason: The text did change and it had to. The removed sentence was 'The boundary is Linux-only for now.', which this phase makes FALSE — keeping it byte-for-byte would ship a statement the release contradicts. The spec's 'byte for byte' was about Windows BEHAVIOUR being untouched, which it is: shape 'none', splitAvailable() false, pre-split layout, warning printed. Spec amended to say behaviour rather than bytes, so the next round is not told the same thing.
- [round 22 F2] rejected: Umask 63 makes Node create the unix sockets at 0700, so agents get EACCES connecting
  reason: The code explicitly chmods every socket to 0666 in its listen callback — src/agent.ts:941 for the per-agent sockets, :1215 for the management socket — and chmod is absolute, so umask does not apply to it. The reviewer was not shown agent.ts this round, which is exactly the case I asked it to flag rather than assume, and it was right to raise it. What is real and smaller: between listen() and the chmod there is a brief window at the umask-masked mode, which fails CLOSED (an agent connecting in that window is refused and retries), so it is not worth a startup-ordering change. The same reviewer reflex found the genuine version of this bug in the DIRECTORIES, which is fixed.
- [round 24 B1] deferred: blind spot: the combined machine identity is unstable if one source is transiently unavailable
  reason: Real. A PowerShell hiccup drops the SMBIOS source, the identity changes, and the store will not decrypt. It fails SAFE -- the daemon refuses to serve or overwrite and says the store is unreadable -- so it is confusing rather than destructive, and the supported install path uses store.key rather than a derived key at all. Recorded as an open item: the fix is to record which sources produced the identity and refuse with an accurate message when the set changes, rather than silently deriving a different key.
- [round 24 B2] deferred: blind spot: the installer resets an existing account password before the ACL and task work is known to succeed
  reason: True and low: a failure leaves an account whose password nobody knows, which the next run of the installer fixes, because that is the first thing it does. Noted.
- [round 24 B3] deferred: blind spot: SeDenyBatchLogonRight inherited through group membership or a later GPO is not detected
  reason: Real but niche. Its effect is caught downstream -- the installer now FAILS when the task registers and the broker is not running (F3), which is what a denied logon right produces. Noted rather than checked directly.
- [round 25 B1] deferred: npm install -g can resolve newer deps than the lockfile
  reason: true of every release; the signed archive (what Update now installs) uses the lockfile. Range floor ^1.32.2 guarantees the fixed SDK. Not in scope.
