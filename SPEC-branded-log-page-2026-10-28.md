# SPEC — the broker's log page looks like Wundervault (2026-10-28)

Owner, first time seeing `wundervault-agent --destinations`: "we need to add wundervault branding … It just
looks like a generic document." The page is the one place an owner reads what their agents did with their
secrets on this computer; it should be recognisably the same product as wundervault.com and the vault.

## What stays exactly as it is (the page's security contract)
- The Content-Security-Policy string is byte-identical: `default-src 'none'; style-src 'unsafe-inline';
  script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'`. No font-src, img-src or connect-src.
- Nothing is loaded: no `<img>`, `<link>`, `script[src]`, iframe/object/embed, no `url(...)` in CSS, no
  http(s) links. Every agent-written string still reaches the page through `textContent` / `embedJson`.
- Data, columns, search, sorting, "Show 2,000 more", the verdict sentences, file writing/shredding: unchanged.

## What changes
1. **Header bar** like the site's: the WUNDERVAULT wordmark on the left, the theme control on the right,
   a bottom rule. The wordmark is the site's logo face (JetBrains Mono Bold, 0.16em tracking, from
   burnbox `app/static/fonts/530d036ba64a.woff2` at wght 700) **drawn as an inline SVG path** — so it
   needs no font file and no CSP change. `role="img"`, `aria-label="Wundervault"`. Green (#3ce078) with
   the site's glow in dark; ink (#0e1410), no glow, in light — as the site does.
2. **Colours are the site's tokens** (burnbox `app/static/css/site.css`, 1.0): dark is the default
   (`--bg #060a08`, `--panel #0b1014`, `--panel2 #0d141a`, `--fg #d8efe2`, `--muted #a2b9ac`,
   `--border #19261f`, `--brand #3ce078`, `--warn #ff9a3a`, `--danger #ff5a5a`); light uses the site's
   light set. Green is text only in dark; in light it is fills and rules, text is ink (site rule:
   green on white is 1.7:1). The site's faint green grid sits behind the page.
3. **Type**: headings, labels, table heads and buttons in the site's mono stack
   (`"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`); prose in the reading
   stack (`"IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif`). Local fonts only.
4. **Theme control: Light / Dark / Auto**, three peer buttons with `aria-pressed`. Auto is the default and
   follows the OS live (pure CSS, no listener needed). The choice is remembered in localStorage when the
   browser allows it on a file page; if storage throws, the control still works for the visit.
5. **The check result gets a label in words** above its sentences: "Checks out" (ok), "Problem found"
   (bad), "Not confirmed" (unknown). Colour reinforces, never carries it alone.
6. **Result words** keep their text; Refused / Failed / Error are drawn in the danger colour.
7. An eyebrow line "BROKER LOG · THIS COMPUTER" above the heading, in the site's label style.

## Acceptance checks
A1. The document contains one inline `<svg role="img" aria-label="Wundervault">` with a path, inside the
    header; no `<img>`, no font file, no `url(` anywhere in the page.
A2. The CSP meta content is byte-identical to 2.0.1's; every existing "viewer, not payload" test passes
    unchanged.
A3. Theme buttons: three, labelled Light / Dark / Auto; clicking Light sets `data-theme="light"`, Dark
    sets `"dark"`, Auto removes the attribute; exactly one has `aria-pressed="true"`; with localStorage
    throwing on every call the clicks still work and the page renders.
A4. The verdict shows "Checks out" / "Problem found" / "Not confirmed" for ok / bad / unknown.
A5. No horizontal page scroll at 320, 360, 390 and 1280 px wide, dark and light (measured in Chromium).
A6. Text contrast ≥ 4.5:1 for body, muted, table-head and minor text on their backgrounds, both themes
    (computed from the tokens).
A7. All existing tests pass; no new dependency; the page grows by less than 12 KB.
