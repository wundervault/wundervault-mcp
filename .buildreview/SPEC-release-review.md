# Release review: last changes before the jobs release (2026-11-23)

The jobs release (site feat/vault-jobs, helper feat/vault-jobs = 2.6.0 incl. held 2.5.1) was reviewed
in rounds 1-9. This review covers ONLY what came after round 9:

Site
- A. Newsletter embed (60e55bc, merged): /static/newsletter/embed/* is served sandboxed so the
  issue 31 page can frame an interactive 3D model; /newsletter/issue/* may frame 'self'.
- B. 9807b63: owner's "Test run now" inside the helper's 10-minute limit is refused with
  "Try again in N minutes" instead of waiting silently.
Helper
- C. 3bedaa5: agent-facing text points at the Jobs page; demo-mode test lists the 4 job tools.
- D. c38236f: a signed local activity-log line when a job is saved / not saved / paused / resumed /
  deleted on this machine (real-machine run: pause + resume lines appeared within one poll).

## Acceptance checks
1. An embed page's scripts can never read wundervault.com cookies, localStorage or call the API as
   the signed-in user: every response under the embed prefix carries `sandbox allow-scripts`
   (never allow-same-origin), including when opened directly as a top-level page.
2. No other path gets the embed's looser headers (frame-ancestors 'self', XFO SAMEORIGIN, CORP
   cross-origin) — including encoded / dot-segment / case variants of the prefix.
3. Only /newsletter/issue/* gains frame-src 'self'; nowhere gains a wider frame-src.
4. The embed loads nothing from other hosts and cannot send data out (default-src 'none').
5. B: the refusal is computed from the same 10-minute limit the helper enforces; no run is queued
   when refused; a run allowed after the limit still queues.
6. D: a log write failure never stops an order or a job run; each change logs at most once per real
   state change; no secret, argv or command output goes into the line.
7. C: no tool, schema or behaviour change beyond text and the test.
